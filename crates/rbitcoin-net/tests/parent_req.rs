use rbitcoin_net::tx_relay::parent_req::*;
use rbitcoin_net::tx_relay::GETDATA_TX_INTERVAL_SECS;

#[test]
fn txid_parent_already_have_does_not_follow_another_peers_wtxid() {
    let mut t = ParentTracker::new();
    let hash = [0xcd; 32];
    t.schedule(hash, 2, true, 1_000);
    assert_eq!(
        t.note_inv(1, hash, false, 1_000, true),
        ParentNote::RequestNow
    );
    assert_eq!(
        t.note_inv(3, hash, false, 1_000, true),
        ParentNote::Deferred
    );
    let now = 1_000 + GETDATA_TX_INTERVAL_SECS;
    let mut saw_txid = false;
    let dropped = t.take_due(2, now, |h, wtxid| {
        assert_eq!(*h, hash);
        assert!(!wtxid, "txid parent is checked as a txid");
        saw_txid = true;
        true
    });
    assert!(saw_txid);
    assert!(
        dropped.is_empty(),
        "a txid parent already in the mempool is not requested"
    );
    let follow = t.take_due(3, now, |_, wtxid| {
        assert!(wtxid, "wtxid follow-up is not checked as a txid");
        false
    });
    assert_eq!(follow.len(), 1);
    assert!(follow[0].wtxid);
}

#[test]
fn inflight_wtxid_of_the_same_hash_is_not_requested_again_as_txid() {
    let mut t = ParentTracker::new();
    let inflight = [0x11; 32];
    let missing = [0x22; 32];
    assert_eq!(
        t.note_inv(1, inflight, true, 1_000, true),
        ParentNote::RequestNow
    );
    t.schedule(inflight, 2, false, 1_000);
    t.schedule(missing, 2, false, 1_000);
    let due = t.take_due(2, 1_000, |_, _| false);
    assert_eq!(
        due.len(),
        1,
        "the in-flight hash must not join this getdata"
    );
    assert_eq!(due[0].hash, missing);
    assert!(!due[0].wtxid, "the other parent stays a txid request");
}

/// RAM bound: rows stop at the per-peer cap, and a peer's rows and index
/// entries leave with it, so the table is at most the cap times the live
/// sessions. A hash one peer announced holds one announcement, not spare
/// capacity.
#[test]
fn rows_are_bounded_per_live_peer() {
    let mut t = ParentTracker::new();
    let peers = 3u64;
    for p in 0..peers {
        for i in 0..=MAX_PARENT_ANN_PER_PEER as u32 {
            let mut h = [0u8; 32];
            h[0] = p as u8;
            h[1..5].copy_from_slice(&i.to_le_bytes());
            t.note_inv(p, h, true, 1_000 + u64::from(i / 1_000), true);
        }
    }
    assert_eq!(t.announcements, peers as usize * MAX_PARENT_ANN_PER_PEER);
    assert!(t.by_hash.values().all(|slot| slot.anns.capacity() == 1));
    for p in 0..peers {
        t.forget_peer(p);
    }
    assert_eq!(t.announcements, 0);
    assert!(t.by_hash.is_empty());
    assert!(t.due_by_peer.is_empty() && t.inflight_by_peer.is_empty());
    assert!(t.hashes_by_peer.is_empty() && t.ann_per_peer.is_empty());
    assert!(t.sessions.is_empty());
}
