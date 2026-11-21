//! Peer, store, and halt results of single `events` handlers that the
//! catch-up journeys reach.
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::script::ScriptBuf;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness,
};
use rbitcoin_ibd::ibd::confirm::{ConfirmRejectClass, RejectParent};
use rbitcoin_ibd::ibd::events::{
    apply_block_framed, apply_cascade_reject, apply_confirm_reject, complete_stored_headers,
    disconnect_all_peers, on_empty_headers, on_known_headers_batch, ordered_live_has_header_room,
    FramedBody,
};
use rbitcoin_ibd::ibd::header_walk::InFlight;
use rbitcoin_ibd::ibd::peer_io::{PeerCmd, PeerSlot};
use rbitcoin_ibd::ibd::state::{IbdWorkState, InflightReq};
use rbitcoin_ibd::ibd::{MAX_ORDERED_HEADERS, ORDERED_HEADERS_SOFT_CAP};
use rbitcoin_net::codec::MAX_HEADERS_RESULTS;
use rbitcoin_primitives::Fk;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::Arc;
use tokio::sync::mpsc;

fn hash_n(n: u32) -> BlockHash {
    let mut raw = [0u8; 32];
    raw[..4].copy_from_slice(&n.to_le_bytes());
    BlockHash::from_byte_array(raw)
}

fn open(
    label: &str,
) -> (
    rbitcoin_query::testutil::TempDir,
    rbitcoin_net::chain::ChainHub,
) {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    (dir, hub)
}

fn peer(id: usize, peer_height: u32) -> (PeerSlot, mpsc::UnboundedReceiver<PeerCmd>) {
    let (cmd_tx, rx) = mpsc::unbounded_channel();
    let task = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .spawn(async {});
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, id as u8)), 8333);
    let (requested, solicited_bytes, solicited_ms) = rbitcoin_ibd::ibd::peer_io::solicit_track();
    (
        PeerSlot {
            id,
            addr,
            net: rbitcoin_net::NetAddr::from_socket(addr),
            cmd_tx,
            in_flight: Default::default(),
            requested,
            solicited_bytes,
            solicited_ms,
            open_block_bytes: Arc::new(AtomicU64::new(0)),
            any_rx_ms: Arc::new(AtomicU64::new(0)),
            getdata_wire: rbitcoin_ibd::ibd::peer_io::GetdataWire::new(),
            peer_height,
            connected_ms: 1,
            first_data_ms: 0,
            bytes_rx_total: Arc::new(AtomicU64::new(0)),
            rate: Default::default(),
            chain: Default::default(),
            conn_type: rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
            block_download_paused_until: None,
            late_answers: Default::default(),
            alive: true,
            task,
        },
        rx,
    )
}

fn mine(prev: BlockHash, time: u32, height: u32) -> Block {
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let mut script = if height == 0 {
        vec![0x00]
    } else {
        rbitcoin_consensus::bip34_height_script(height)
    };
    while script.len() < 2 {
        script.push(0x00);
    }
    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let header = Header {
        version: Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
        time,
        bits,
        nonce: 0,
    };
    let mut block = Block {
        header,
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = Target::from_compact(bits);
    for nonce in 0..u32::MAX {
        block.header.nonce = nonce;
        if block.header.validate_pow(target).is_ok() {
            break;
        }
    }
    block
}

fn asked(rx: &mut mpsc::UnboundedReceiver<PeerCmd>) -> bool {
    matches!(rx.try_recv(), Ok(PeerCmd::GetHeaders { .. }))
}

#[test]
fn disconnect_one_peer_sends_shutdown() {
    let (slot, mut rx) = peer(1, 1);
    let mut st = IbdWorkState::new(vec![slot], None, None);
    disconnect_all_peers(&mut st);
    assert!(matches!(rx.try_recv(), Ok(PeerCmd::Shutdown)));
    assert!(st.slots.is_empty());
}

fn fresh_ask(
    hub: &rbitcoin_net::chain::ChainHub,
    peer_height: u32,
    lag: u32,
) -> (IbdWorkState, mpsc::UnboundedReceiver<PeerCmd>) {
    let (slot, rx) = peer(1, peer_height);
    let gen = hub.tip_hash();
    let mut st = IbdWorkState::new(vec![slot], gen, hub.tip_height());
    st.max_peer_height = lag;
    (st, rx)
}

#[allow(clippy::cognitive_complexity)] // one empty-headers session, one arm per lag and streak
#[test]
fn empty_headers_latch_and_ask() {
    let (dir, hub) = open("empty-headers");

    let (mut st, mut rx) = fresh_ask(&hub, 20, 10);
    let queued = hash_n(20);
    st.ordered.push_back(queued);
    st.ordered_set.insert(queued);
    st.empty_header_streak = 1;
    assert!(!on_empty_headers(&mut st, &hub));
    assert!(!st.headers_done);
    assert!(!asked(&mut rx));

    let (mut st, _rx) = fresh_ask(&hub, 20, 10);
    assert!(on_empty_headers(&mut st, &hub));
    assert!(!st.headers_done);

    let (mut st, mut rx) = fresh_ask(&hub, 20, 2);
    assert!(!on_empty_headers(&mut st, &hub));
    assert!(asked(&mut rx));
    assert!(!st.headers_done);

    let (mut st, mut rx) = fresh_ask(&hub, 20, 2);
    st.empty_header_streak = 6;
    st.inflight.insert(hash_n(23), InflightReq::new(1));
    assert!(!on_empty_headers(&mut st, &hub));
    assert!(asked(&mut rx));
    assert!(!st.headers_done);

    let (mut st, mut rx) = fresh_ask(&hub, 20, 2);
    st.empty_header_streak = 7;
    st.inflight.insert(hash_n(21), InflightReq::new(1));
    assert!(!on_empty_headers(&mut st, &hub));
    assert!(st.headers_done);
    assert!(!asked(&mut rx));

    let (mut st, mut rx) = fresh_ask(&hub, 20, 0);
    for i in 0..ORDERED_HEADERS_SOFT_CAP {
        st.ordered_set.insert(hash_n(1_000_000 + i as u32));
    }
    assert!(!on_empty_headers(&mut st, &hub));
    assert!(!asked(&mut rx));
    assert!(!st.headers_done);
    st.ordered_set.insert(hash_n(2));
    st.empty_header_streak = 0;
    assert!(!on_empty_headers(&mut st, &hub));
    assert!(!asked(&mut rx));

    let (mut st, mut rx) = fresh_ask(&hub, 20, 0);
    st.ordered_set.insert(hash_n(3));
    assert!(!on_empty_headers(&mut st, &hub));
    assert!(asked(&mut rx));

    let (mut st, mut rx) = fresh_ask(&hub, 20, 0);
    for i in 0..ORDERED_HEADERS_SOFT_CAP {
        st.ordered_set.insert(hash_n(3_000_000 + i as u32));
    }
    st.empty_header_streak = 6;
    st.inflight.insert(hash_n(22), InflightReq::new(1));
    assert!(!on_empty_headers(&mut st, &hub));
    assert!(!st.headers_done);
    assert!(!asked(&mut rx));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ordered_live_header_room_bounds() {
    let soft = ORDERED_HEADERS_SOFT_CAP;
    let max = MAX_ORDERED_HEADERS;
    assert!(ordered_live_has_header_room(0, false));
    assert!(ordered_live_has_header_room(soft - 1, false));
    assert!(!ordered_live_has_header_room(soft, false));
    assert!(ordered_live_has_header_room(soft, true));
    assert!(!ordered_live_has_header_room(soft + 1, false));
    assert!(ordered_live_has_header_room(max - 1, true));
    assert!(!ordered_live_has_header_room(max, true));
    assert!(!ordered_live_has_header_room(max + 1, true));

    let (dir, hub) = open("stored-room");
    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let mut inflight = InFlight::capture(&st);
    assert!(complete_stored_headers(
        &mut st,
        &hub,
        &mut inflight,
        1,
        MAX_HEADERS_RESULTS
    ));
    assert!(!complete_stored_headers(&mut st, &hub, &mut inflight, 1, 1));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn known_batch_asks_only_for_a_full_window() {
    let (dir, hub) = open("known-window");
    let (mut st, mut rx) = fresh_ask(&hub, 20, 0);
    for i in 0..4 {
        st.ordered_set.insert(hash_n(30 + i));
    }
    on_known_headers_batch(&mut st, &hub, 1, MAX_HEADERS_RESULTS - 1);
    assert!(!asked(&mut rx));
    on_known_headers_batch(&mut st, &hub, 1, MAX_HEADERS_RESULTS);
    assert!(asked(&mut rx));
    let _ = std::fs::remove_dir_all(dir);
}

fn offer_framed(
    st: &mut IbdWorkState,
    hub: &rbitcoin_net::chain::ChainHub,
    hash: BlockHash,
    height: u32,
    payload: &[u8],
    write_next: u32,
) {
    st.inflight.insert(hash, InflightReq::new(0));
    st.record_height(hash, height);
    st.header_fks.insert(hash, Fk(1));
    let next = AtomicU32::new(write_next);
    apply_block_framed(
        st,
        hub,
        &next,
        None,
        FramedBody {
            peer: 0,
            hash,
            payload: payload.to_vec(),
        },
    );
}

#[test]
fn framed_body_keeps_the_height_window_and_a_side_block() {
    let (dir, hub) = open("framed-window");
    let gen = hub.tip_hash().unwrap();
    let parent = mine(gen, 1_600_000_100, 1);
    hub.accept_block(parent.clone()).unwrap();
    assert_eq!(hub.tip_height(), Some(1));
    let payload = serialize(&parent);
    let ahead = rbitcoin_ibd::ibd::CONTIG_DENSIFY_AHEAD;

    let mut st = IbdWorkState::new(Vec::new(), hub.tip_hash(), hub.tip_height());
    let over = hash_n(40);
    offer_framed(&mut st, &hub, over, 1 + ahead + 1, &payload, 1);
    assert!(st.body.is_missing(&over));
    assert!(!hub.query.block_queue_has_hash(&over.to_byte_array()));

    let at_densify = hash_n(41);
    offer_framed(&mut st, &hub, at_densify, 1 + ahead + 1, &payload, 2);
    assert!(hub.query.block_queue_has_hash(&at_densify.to_byte_array()));
    assert!(!st.body.is_missing(&at_densify));

    let at_tip_hi = hash_n(42);
    offer_framed(&mut st, &hub, at_tip_hi, 1 + ahead, &payload, 0);
    assert!(hub.query.block_queue_has_hash(&at_tip_hi.to_byte_array()));

    let on_densify = hash_n(44);
    let on_densify_h = 3 + ahead;
    offer_framed(&mut st, &hub, on_densify, on_densify_h, &payload, 3);
    assert!(hub.query.block_queue_has_hash(&on_densify.to_byte_array()));
    assert!(!st.body.is_missing(&on_densify));
    assert!(!st.reorg.held_bodies.contains(&parent.block_hash()));

    let rejected = hash_n(43);
    st.body.mark_rejected(rejected);
    offer_framed(&mut st, &hub, rejected, 2, &payload, 0);
    assert!(!hub.query.block_queue_has_hash(&rejected.to_byte_array()));

    let genesis_block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let genesis = genesis_block.block_hash();
    assert_eq!(genesis, gen);
    offer_framed(&mut st, &hub, genesis, 0, &serialize(&genesis_block), 0);
    assert!(!st.reorg.held_bodies.contains(&genesis));
    assert!(!hub.query.block_queue_has_hash(&genesis.to_byte_array()));

    let side = mine(gen, 1_600_000_200, 1);
    let side_hash = side.block_hash();
    let side_bytes = serialize(&side);
    offer_framed(&mut st, &hub, side_hash, 1, &side_bytes, 0);
    assert!(st.reorg.held_bodies.contains(&side_hash));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tip_child_bad_prev_halts_only_for_the_same_hash() {
    let (dir, hub) = open("tip-child");
    let tip = hub.tip_hash().unwrap();
    let err = "unexpected previous header";
    let hash = hash_n(60);
    let mut st = IbdWorkState::new(Vec::new(), Some(tip), Some(0));
    st.note_path_prev(hash, tip);
    for _ in 0..2 {
        apply_confirm_reject(
            &mut st,
            1,
            hash,
            ConfirmRejectClass::SoftWire,
            err,
            None,
            Some(&hub),
            1,
            None,
            None,
            RejectParent::default(),
        );
        assert!(st.halt.is_none());
    }
    apply_confirm_reject(
        &mut st,
        1,
        hash,
        ConfirmRejectClass::SoftWire,
        err,
        None,
        Some(&hub),
        1,
        None,
        None,
        RejectParent::default(),
    );
    assert!(st.halt.is_some());

    let mut other = IbdWorkState::new(Vec::new(), Some(tip), Some(0));
    for i in 0..3 {
        let hash = hash_n(70 + i);
        other.note_path_prev(hash, tip);
        apply_confirm_reject(
            &mut other,
            1,
            hash,
            ConfirmRejectClass::SoftWire,
            err,
            None,
            Some(&hub),
            1,
            None,
            None,
            RejectParent::default(),
        );
    }
    assert!(other.halt.is_none());
    let _ = std::fs::remove_dir_all(dir);
}

/// The mutated sender's drop is `a_mutated_block_drops_the_sender_not_a_noban_neighbor`.
#[test]
fn a_tip_child_bad_prev_keeps_its_sender() {
    let (dir, hub) = open("punish-mutated");
    let tip = hub.tip_hash().unwrap();
    let (slot, mut rx) = peer(1, 10);
    let mut st = IbdWorkState::new(vec![slot], Some(tip), Some(0));
    let hash = hash_n(81);
    st.note_path_prev(hash, tip);
    apply_confirm_reject(
        &mut st,
        1,
        hash,
        ConfirmRejectClass::SoftWire,
        "unexpected previous merkle root",
        None,
        Some(&hub),
        1,
        None,
        Some(1),
        RejectParent::default(),
    );
    assert!(st.slots[0].alive);
    assert!(rx.try_recv().is_err());
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `MaybeDiscourageAndDisconnect` keeps a manual peer whatever it sent.
/// A `--connect` peer that sends a mutated body stays connected, and the
/// block is asked for again as for any other sender.
#[test]
fn mutated_clear_keeps_a_manual_sender() {
    let (dir, hub) = open("punish-mutated-manual");
    let tip = hub.tip_hash().unwrap();
    let (mut slot, mut rx) = peer(1, 10);
    slot.conn_type = rbitcoin_net::peers::PeerConnType::Manual;
    let mut st = IbdWorkState::new(vec![slot], Some(tip), Some(0));
    apply_confirm_reject(
        &mut st,
        4,
        hash_n(82),
        ConfirmRejectClass::SoftWire,
        "bad-txnmrklroot",
        None,
        Some(&hub),
        1,
        None,
        Some(1),
        RejectParent::default(),
    );
    assert!(st.slots[0].alive, "a manual peer is not dropped");
    assert!(rx.try_recv().is_err(), "no shutdown is sent to it");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn cascade_halts_only_for_the_same_hash_at_the_same_tip() {
    let hash = hash_n(110);
    let mut st = IbdWorkState::new(Vec::new(), None, None);
    for _ in 0..2 {
        apply_cascade_reject(&mut st, 4, hash, "fk mismatch", None);
        assert!(st.halt.is_none());
    }
    apply_cascade_reject(&mut st, 4, hash, "fk mismatch", None);
    assert!(st
        .halt
        .as_deref()
        .is_some_and(|halt| halt.contains("cascade repeated")));

    let mut st = IbdWorkState::new(Vec::new(), None, None);
    for i in 0..3 {
        apply_cascade_reject(&mut st, 4, hash_n(120 + i), "fk mismatch", None);
    }
    assert!(st.halt.is_none());
}
