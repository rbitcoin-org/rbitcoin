//! Numbered mempool changes for a client that follows the pool.
//!
//! Every pool write drains the pool's journal into this log before the
//! write lock is released, so sequence order is commit order. A sequence is
//! Core's `mempool_sequence`: it starts at 1 and `next` is the value the next
//! change will take. The ring keeps the newest [`EVENT_RING_CAP`] changes.
//! `epoch` is random per process, so a client can tell a restart from a gap.
//!
//! The ring mutex is a leaf. It is taken under the pool write lock and never
//! held while taking the pool lock.

pub use rbitcoin_mempool::{PoolChange, RemovalReason};
use std::collections::VecDeque;
use std::sync::Mutex;

/// Changes the ring keeps. Older ones fall off.
pub const EVENT_RING_CAP: usize = 65_536;

/// One numbered pool change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MempoolEvent {
    pub seq: u64,
    pub change: PoolChange,
}

/// What a read from `from` found.
#[derive(Debug, PartialEq, Eq)]
pub enum EventsFrom {
    /// Up to `limit` events with `seq >= from`, in order. Empty when `from`
    /// is `next`.
    Events(Vec<MempoolEvent>),
    /// `from` fell off the ring.
    TooOld,
    /// `from` is past `next`: a cursor from another process.
    Ahead,
}

/// A read with the log's position.
#[derive(Debug, PartialEq, Eq)]
pub struct EventRead {
    pub epoch: u64,
    /// Oldest sequence still in the ring (`next` when it is empty).
    pub oldest: u64,
    pub next: u64,
    pub from: EventsFrom,
}

struct Ring {
    events: VecDeque<MempoolEvent>,
    next: u64,
}

pub struct MempoolEventLog {
    epoch: u64,
    ring: Mutex<Ring>,
    /// Carries `next`. A waiter that subscribes before it reads cannot miss
    /// a change.
    wake: tokio::sync::watch::Sender<u64>,
}

impl Default for MempoolEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl MempoolEventLog {
    pub fn new() -> Self {
        let mut epoch = [0u8; 8];
        getrandom::fill(&mut epoch).expect("CSPRNG for mempool event epoch");
        Self {
            epoch: u64::from_le_bytes(epoch),
            ring: Mutex::new(Ring {
                events: VecDeque::new(),
                next: 1,
            }),
            wake: tokio::sync::watch::channel(1).0,
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The sequence the next change will take.
    pub fn next(&self) -> u64 {
        self.ring.lock().unwrap().next
    }

    /// Number `changes` in order, drop what falls off the ring, then wake
    /// waiters. No IO.
    pub fn record(&self, changes: impl IntoIterator<Item = PoolChange>) {
        let next = {
            let mut ring = self.ring.lock().unwrap();
            let start = ring.next;
            for change in changes {
                let seq = ring.next;
                ring.next += 1;
                if ring.events.len() == EVENT_RING_CAP {
                    ring.events.pop_front();
                }
                ring.events.push_back(MempoolEvent { seq, change });
            }
            if ring.next == start {
                return;
            }
            ring.next
        };
        self.wake.send_replace(next);
    }

    /// Events with `seq >= from`, at most `limit`.
    pub fn read(&self, from: u64, limit: usize) -> EventRead {
        let ring = self.ring.lock().unwrap();
        let oldest = ring.next - ring.events.len() as u64;
        let from_events = if from > ring.next {
            EventsFrom::Ahead
        } else if from < oldest {
            EventsFrom::TooOld
        } else {
            let skip = (from - oldest) as usize;
            EventsFrom::Events(ring.events.range(skip..).take(limit).copied().collect())
        };
        EventRead {
            epoch: self.epoch,
            oldest,
            next: ring.next,
            from: from_events,
        }
    }

    /// Wakes with the new `next` after each [`Self::record`] that numbered
    /// at least one change.
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.wake.subscribe()
    }
}
