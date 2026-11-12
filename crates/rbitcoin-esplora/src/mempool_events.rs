//! `GET /mempool/events`: a long-poll over the hub's numbered pool changes.
//!
//! A client reads `epoch` from a probe, takes `getrawmempool false true`
//! (txids and sequence S), then polls with `from=S` and passes each answer's
//! `next` as the next `from`. A `410`, or an `epoch` that differs from the
//! first one seen, means take a new snapshot.

use crate::server::{block_hash_hex, json_reply_here, AppState};
use axum::extract::{Extension, Query as AxumQuery, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use bitcoin::hashes::Hash;
use rbitcoin_net::mempool_events::{
    EventRead, EventsFrom, MempoolEvent, PoolChange, RemovalReason,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

/// Default and cap for `limit`.
pub const EVENTS_LIMIT: usize = 5_000;
/// Cap for `wait`, before the half-request-timeout cap.
pub const EVENTS_MAX_WAIT: Duration = Duration::from_secs(25);

#[derive(Deserialize)]
pub struct EventsQuery {
    pub from: Option<u64>,
    /// Milliseconds to park when no event is ready. Default 0.
    pub wait: Option<u64>,
    pub limit: Option<usize>,
}

/// Parked polls. A parked poll holds a listener slot, so at most half the
/// listener's in-flight limit (rounded down) may park. A one-slot listener
/// parks none.
#[doc(hidden)]
pub struct EventPark {
    cap: usize,
    max_wait: Duration,
    parked: AtomicUsize,
    wake: Notify,
}

struct Parked(Arc<EventPark>);

impl Drop for Parked {
    fn drop(&mut self) {
        self.0.parked.fetch_sub(1, Ordering::SeqCst);
        self.0.wake.notify_waiters();
    }
}

impl EventPark {
    /// `wait` stays under half the request timeout, so a parked poll answers
    /// before the listener's timeout does.
    pub(crate) fn new(max_conn: usize, request_timeout: Duration) -> Arc<Self> {
        Arc::new(Self {
            cap: max_conn / 2,
            max_wait: EVENTS_MAX_WAIT.min(request_timeout / 2),
            parked: AtomicUsize::new(0),
            wake: Notify::new(),
        })
    }

    #[doc(hidden)]
    pub fn parked(&self) -> usize {
        self.parked.load(Ordering::SeqCst)
    }

    #[doc(hidden)]
    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }

    fn try_park(self: &Arc<Self>) -> Option<Parked> {
        self.parked
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.cap).then_some(n + 1)
            })
            .ok()?;
        self.wake.notify_waiters();
        Some(Parked(Arc::clone(self)))
    }
}

pub async fn mempool_events(
    State(st): State<AppState>,
    Extension(park): Extension<Arc<EventPark>>,
    AxumQuery(q): AxumQuery<EventsQuery>,
) -> Response {
    let Some(mp) = st.mempool.as_ref() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "mempool not available").into_response();
    };
    let log = mp.events();
    let Some(from) = q.from else {
        return json_reply_here(json!({
            "epoch": epoch_hex(log.epoch()),
            "next": log.next(),
            "events": [],
        }));
    };
    let limit = q.limit.unwrap_or(EVENTS_LIMIT).clamp(1, EVENTS_LIMIT);
    let wait = Duration::from_millis(q.wait.unwrap_or(0)).min(park.max_wait);
    // Subscribed before the read, so an event recorded after it still wakes.
    let mut woke = log.subscribe();
    let read = log.read(from, limit);
    let nothing_yet = matches!(&read.from, EventsFrom::Events(e) if e.is_empty());
    if !nothing_yet || wait.is_zero() {
        return events_reply(from, read);
    }
    let Some(_parked) = park.try_park() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "1")],
            "too many parked polls",
        )
            .into_response();
    };
    let _ = tokio::time::timeout(wait, woke.changed()).await;
    events_reply(from, log.read(from, limit))
}

fn epoch_hex(epoch: u64) -> String {
    format!("{epoch:016x}")
}

fn txid_hex(txid: &bitcoin::Txid) -> String {
    block_hash_hex(&txid.to_byte_array())
}

fn events_reply(from: u64, read: EventRead) -> Response {
    let epoch = epoch_hex(read.epoch);
    let EventsFrom::Events(events) = read.from else {
        let gone = json!({"epoch": epoch, "oldest": read.oldest, "next": read.next});
        return (StatusCode::GONE, axum::Json(gone)).into_response();
    };
    let next = events.last().map_or(from, |e| e.seq + 1);
    let rows: Vec<Value> = events.iter().map(event_json).collect();
    json_reply_here(json!({"epoch": epoch, "next": next, "events": rows}))
}

fn event_json(e: &MempoolEvent) -> Value {
    match e.change {
        PoolChange::Added {
            txid,
            fee_sat,
            weight,
            vsize,
            time,
        } => json!({
            "seq": e.seq,
            "type": "added",
            "txid": txid_hex(&txid),
            "fee": fee_sat,
            "weight": weight,
            "vsize": vsize,
            "time": time,
        }),
        PoolChange::Removed { txid, reason } => {
            let mut row = json!({
                "seq": e.seq,
                "type": "removed",
                "txid": txid_hex(&txid),
                "reason": reason.as_str(),
            });
            if let RemovalReason::Replaced { by } = reason {
                row["by"] = json!(txid_hex(&by));
            }
            row
        }
    }
}
