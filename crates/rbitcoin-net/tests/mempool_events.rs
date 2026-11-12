use super::tx_relay::{copy_maturity_pad, pad_cbs, spend_true, tmp};
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use rbitcoin_mempool::{PoolChange, RemovalReason};
use rbitcoin_net::mempool_events::{
    EventRead, EventsFrom, MempoolEvent, MempoolEventLog, EVENT_RING_CAP,
};
use rbitcoin_net::tx_relay::MempoolHub;
use std::collections::BTreeSet;
use std::sync::Arc;

fn op_true() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

fn spend(cb: Txid, fee: u64) -> Transaction {
    spend_true(cb, fee, op_true())
}

fn child_of(parent: &Transaction, fee: u64) -> Transaction {
    let mut tx = spend(parent.compute_txid(), 0);
    tx.output[0].value = parent.output[0].value - bitcoin::Amount::from_sat(fee);
    tx
}

fn all_events(hub: &MempoolHub) -> Vec<MempoolEvent> {
    match hub.events().read(1, usize::MAX).from {
        EventsFrom::Events(e) => e,
        other => panic!("read from 1: {other:?}"),
    }
}

fn removed(txid: Txid, reason: RemovalReason) -> PoolChange {
    PoolChange::Removed { txid, reason }
}

fn changes(events: &[MempoolEvent]) -> Vec<PoolChange> {
    events.iter().map(|e| e.change).collect()
}

fn live_set(hub: &MempoolHub) -> BTreeSet<Txid> {
    hub.live_txids_at_event_seq().0.into_iter().collect()
}

/// A snapshot at `seq` plus every event from `seq` on.
fn replay(snapshot: &(Vec<Txid>, u64), events: &[MempoolEvent]) -> BTreeSet<Txid> {
    let mut set: BTreeSet<Txid> = snapshot.0.iter().copied().collect();
    for e in events.iter().filter(|e| e.seq >= snapshot.1) {
        match e.change {
            PoolChange::Added { txid, .. } => assert!(set.insert(txid), "added twice: {e:?}"),
            PoolChange::Removed { txid, .. } => assert!(set.remove(&txid), "not live: {e:?}"),
        }
    }
    set
}

fn assert_consecutive_from_one(events: &[MempoolEvent]) {
    for (i, e) in events.iter().enumerate() {
        assert_eq!(e.seq, i as u64 + 1, "sequence gap at {i}: {events:?}");
    }
}

#[test]
fn a_fresh_hub_starts_at_one_and_numbers_each_admit() {
    let (_store, q, cbs) = pad_cbs(12);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, q).unwrap();
    hub.set_relay_enabled(true);
    assert_eq!(hub.live_txids_at_event_seq(), (Vec::new(), 1));
    let tx = spend(cbs[0], 1_000);
    let r = hub.accept_tx(&tx).expect("admit");
    let read = hub.events().read(1, 10);
    assert_eq!(read.next, 2);
    assert_eq!(read.oldest, 1);
    let EventsFrom::Events(events) = read.from else {
        panic!("{read:?}");
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].seq, 1);
    assert!(
        matches!(events[0].change, PoolChange::Added { txid, fee_sat: 1_000, .. } if txid == r.txid)
    );
    assert_eq!(hub.live_txids_at_event_seq(), (vec![r.txid], 2));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hub_removals_carry_their_reason() {
    let (_store, q, cbs) = pad_cbs(12);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, q).unwrap();
    hub.set_relay_enabled(true);
    hub.note_mock_now(10_000);

    let first = spend(cbs[0], 1_000);
    let bump = spend(cbs[0], 50_000);
    hub.accept_tx(&first).expect("first");
    hub.accept_tx(&bump).expect("replacement");
    hub.remove_for_block(&[bump.compute_txid()], RemovalReason::Block);

    let loser = spend(cbs[1], 1_000);
    hub.accept_tx(&loser).expect("loser");
    hub.remove_for_block_spent(&[], &[OutPoint::new(cbs[1], 0)]);

    let lone = spend(cbs[2], 1_000);
    hub.accept_tx(&lone).expect("lone");
    hub.rollback_1p1c_parent(&lone.compute_txid(), &[]);

    let stale = spend(cbs[3], 1_000);
    hub.accept_tx(&stale).expect("stale");
    hub.set_expiry_hours(1);
    hub.note_mock_now(10_000 + 3_600 + 5);
    assert_eq!(hub.expire_stale(), 1);

    let low = spend(cbs[4], 1_000);
    let high = spend(cbs[5], 50_000);
    hub.accept_tx(&low).expect("low");
    hub.accept_tx(&high).expect("high");
    hub.set_max_weight(high.weight().to_wu());
    hub.trim_over_budget();

    let events = all_events(&hub);
    assert_consecutive_from_one(&events);
    let removals: Vec<PoolChange> = changes(&events)
        .into_iter()
        .filter(|c| matches!(c, PoolChange::Removed { .. }))
        .collect();
    assert_eq!(
        removals,
        vec![
            removed(
                first.compute_txid(),
                RemovalReason::Replaced {
                    by: bump.compute_txid()
                }
            ),
            removed(bump.compute_txid(), RemovalReason::Block),
            removed(loser.compute_txid(), RemovalReason::Conflict),
            removed(lone.compute_txid(), RemovalReason::Rollback),
            removed(stale.compute_txid(), RemovalReason::Expiry),
            removed(low.compute_txid(), RemovalReason::SizeLimit),
        ]
    );
    assert_eq!(live_set(&hub), BTreeSet::from([high.compute_txid()]));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reorg_evict_journals_reorg_for_the_tree() {
    let (store, q, cbs) = copy_maturity_pad(3);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let parent = spend(cbs[0], 1_000);
    let child = child_of(&parent, 1_000);
    hub.accept_tx(&parent).expect("parent");
    hub.accept_tx(&child).expect("child");
    while q.tip_height().map(|h| h.0).unwrap_or(0) > 0 {
        q.disconnect_tip().unwrap();
    }
    hub.evict_after_reorg();
    let events = all_events(&hub);
    assert_consecutive_from_one(&events);
    let gone: BTreeSet<Txid> = events[2..]
        .iter()
        .map(|e| match e.change {
            PoolChange::Removed {
                txid,
                reason: RemovalReason::Reorg,
            } => txid,
            other => panic!("expected a reorg removal, got {other:?}"),
        })
        .collect();
    assert_eq!(
        gone,
        BTreeSet::from([parent.compute_txid(), child.compute_txid()])
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&store);
}

#[test]
fn reopen_numbers_nothing_for_loaded_transactions() {
    let (_store, q, cbs) = pad_cbs(12);
    let dir = tmp();
    {
        let hub = MempoolHub::open(&dir, Arc::clone(&q)).unwrap();
        hub.set_relay_enabled(true);
        hub.accept_tx(&spend(cbs[0], 1_000)).expect("admit");
        hub.flush().unwrap();
    }
    let hub = MempoolHub::open(&dir, q).unwrap();
    assert_eq!(hub.live_count(), 1);
    let read = hub.events().read(1, 10);
    assert_eq!((read.oldest, read.next), (1, 1));
    assert_eq!(read.from, EventsFrom::Events(Vec::new()));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A listing taken with its sequence at any point, plus every later event,
/// is the final listing.
#[test]
fn snapshot_plus_events_is_the_final_listing() {
    let (_store, q, cbs) = pad_cbs(12);
    let dir = tmp();
    let hub = MempoolHub::open(&dir, q).unwrap();
    hub.set_relay_enabled(true);
    hub.note_mock_now(10_000);
    let mut snaps = vec![hub.live_txids_at_event_seq()];
    let mut step = |hub: &MempoolHub| snaps.push(hub.live_txids_at_event_seq());

    let a = spend(cbs[0], 1_000);
    let b = spend(cbs[1], 1_000);
    let b_child = child_of(&b, 1_000);
    let c = spend(cbs[2], 1_000);
    for tx in [&a, &b, &b_child, &c] {
        hub.accept_tx(tx).expect("admit");
        step(&hub);
    }
    let a_bump = spend(cbs[0], 50_000);
    hub.accept_tx(&a_bump).expect("replacement");
    step(&hub);
    hub.remove_for_block_spent(&[b.compute_txid()], &[OutPoint::new(cbs[2], 0)]);
    step(&hub);
    hub.note_mock_now(10_000 + 3_605);
    let d = spend(cbs[3], 1_000);
    let e = spend(cbs[4], 50_000);
    hub.accept_tx(&d).expect("d");
    hub.accept_tx(&e).expect("e");
    step(&hub);
    hub.set_expiry_hours(1);
    hub.expire_stale();
    step(&hub);
    hub.set_max_weight(e.weight().to_wu());
    hub.trim_over_budget();

    let events = all_events(&hub);
    assert_consecutive_from_one(&events);
    let last = hub.live_txids_at_event_seq();
    assert_eq!(last.1, events.len() as u64 + 1);
    let fin: BTreeSet<Txid> = last.0.iter().copied().collect();
    assert_eq!(fin, BTreeSet::from([e.compute_txid()]));
    assert_eq!(snaps.len(), 9);
    for snap in &snaps {
        assert_eq!(replay(snap, &events), fin, "snapshot at {}", snap.1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_admits_number_without_gaps() {
    let (_store, q, cbs) = pad_cbs(12);
    let dir = tmp();
    let hub = Arc::new(MempoolHub::open(&dir, q).unwrap());
    hub.set_relay_enabled(true);
    let snaps = std::thread::scope(|s| {
        let watcher = s.spawn(|| {
            let mut snaps = Vec::new();
            while hub.live_count() < cbs.len() {
                snaps.push(hub.live_txids_at_event_seq());
                std::thread::yield_now();
            }
            snaps
        });
        for chunk in cbs.chunks(3) {
            let hub = Arc::clone(&hub);
            s.spawn(move || {
                for cb in chunk {
                    hub.accept_tx(&spend(*cb, 1_000)).expect("admit");
                }
            });
        }
        watcher.join().unwrap()
    });
    let events = all_events(&hub);
    assert_eq!(events.len(), cbs.len());
    assert_consecutive_from_one(&events);
    let fin = live_set(&hub);
    for snap in &snaps {
        assert_eq!(replay(snap, &events), fin, "snapshot at {}", snap.1);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn noise(n: usize) -> impl Iterator<Item = PoolChange> {
    (0..n).map(|i| PoolChange::Removed {
        txid: bitcoin::hashes::Hash::from_byte_array([(i % 251) as u8; 32]),
        reason: RemovalReason::Block,
    })
}

#[test]
fn the_ring_reports_a_cursor_too_old_or_ahead() {
    let log = MempoolEventLog::new();
    log.record(noise(EVENT_RING_CAP + 2));
    let head = EVENT_RING_CAP as u64 + 3;
    let at = |from, limit| log.read(from, limit);
    assert_eq!(
        at(2, 1),
        EventRead {
            epoch: log.epoch(),
            oldest: 3,
            next: head,
            from: EventsFrom::TooOld,
        }
    );
    let EventsFrom::Events(first) = at(3, 2).from else {
        panic!("the oldest kept sequence reads");
    };
    assert_eq!(first.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![3, 4]);
    assert_eq!(at(head, 10).from, EventsFrom::Events(Vec::new()));
    assert_eq!(at(head + 1, 10).from, EventsFrom::Ahead);
    assert_ne!(
        MempoolEventLog::new().epoch(),
        log.epoch(),
        "each log draws its own epoch"
    );
}

#[test]
fn a_subscriber_wakes_on_a_numbered_change_only() {
    let log = MempoolEventLog::new();
    let mut rx = log.subscribe();
    log.record(noise(0));
    assert!(!rx.has_changed().unwrap(), "nothing numbered, nothing sent");
    log.record(noise(2));
    assert!(rx.has_changed().unwrap());
    assert_eq!(*rx.borrow_and_update(), 3);
}
