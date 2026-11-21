//! Bounds and caps of the header walk: the clock window, the ordered and
//! refused-tip caps, the length cap, fork suppression under the floor, the
//! retire of an invalid block, and the getheaders locator.
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoin::CompactTarget;
use bitcoin::ScriptBuf;
use bitcoin::TxMerkleNode;
use rbitcoin_consensus::{Milestone, MilestoneAnchor};
use rbitcoin_ibd::ibd::header_walk::*;
use rbitcoin_ibd::ibd::peer_io::{solicit_track, PeerCmd, PeerSlot};
use rbitcoin_ibd::ibd::state::IbdWorkState;
use rbitcoin_ibd::ibd::MAX_ORDERED_HEADERS;
use rbitcoin_net::chain::ChainHub;
use rbitcoin_net::NetAddr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use tokio::sync::mpsc;

fn mine(prev: BlockHash, n: u32) -> Header {
    let mut h = Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([n as u8; 32]),
        time: 1_600_000_000 + n,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: n,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut h);
    h
}

fn slot(id: usize) -> (PeerSlot, mpsc::UnboundedReceiver<PeerCmd>) {
    let (cmd_tx, rx) = mpsc::unbounded_channel();
    let task = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .spawn(async {});
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 9, 0, id as u8)), 8333);
    (
        PeerSlot {
            id,
            addr,
            net: NetAddr::from_socket(addr),
            cmd_tx,
            in_flight: Default::default(),
            requested: solicit_track().0,
            solicited_bytes: solicit_track().1,
            solicited_ms: solicit_track().2,
            open_block_bytes: Arc::new(AtomicU64::new(0)),
            any_rx_ms: Arc::new(AtomicU64::new(0)),
            getdata_wire: rbitcoin_ibd::ibd::peer_io::GetdataWire::new(),
            peer_height: 50_000,
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

struct ResetClock;

impl Drop for ResetClock {
    fn drop(&mut self) {
        set_walk_unix_for_test(None);
    }
}

fn bare(label: &str) -> (rbitcoin_query::testutil::TempDir, ChainHub, Header) {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let gen_hdr = hub.header_of(&gen).unwrap();
    (dir, hub, gen_hdr)
}

fn opened(
    label: &str,
) -> (
    rbitcoin_query::testutil::TempDir,
    ChainHub,
    IbdWorkState,
    Header,
) {
    let (dir, hub, gen_hdr) = bare(label);
    let gen = gen_hdr.block_hash();
    let (s0, rx0) = slot(0);
    let (s1, rx1) = slot(1);
    std::mem::forget(rx0);
    std::mem::forget(rx1);
    let mut st = IbdWorkState::new(vec![s0, s1], Some(gen), Some(0));
    ensure_origin(&mut st, &hub);
    (dir, hub, st, gen_hdr)
}

fn fresh(hub: &ChainHub) -> IbdWorkState {
    let gen = hub.tip_hash().unwrap();
    let (s0, rx0) = slot(0);
    let (s1, rx1) = slot(1);
    std::mem::forget(rx0);
    std::mem::forget(rx1);
    IbdWorkState::new(vec![s0, s1], Some(gen), Some(0))
}

fn checkpoint(height: u32, hash: BlockHash, supplier: Option<NetAddr>) -> Checkpoint {
    Checkpoint {
        hash,
        height,
        height_wide: u64::from(height),
        work: [0; 32],
        header: None,
        times: Vec::new(),
        diff: DiffSnap::default(),
        supplied_by: supplier,
    }
}

fn high_floor() -> Milestone {
    Milestone {
        height: 1_000_000,
        anchor: Some(MilestoneAnchor {
            hash: BlockHash::from_byte_array([0xab; 32]),
            min_work_be: [0xff; 32],
        }),
    }
}

fn one_more_work(work: [u8; 32]) -> [u8; 32] {
    let mut out = work;
    for byte in out.iter_mut().rev() {
        let (next, wrapped) = byte.overflowing_add(1);
        *byte = next;
        if !wrapped {
            break;
        }
    }
    out
}

fn fork_from(prev: BlockHash, n: u32) -> Vec<Header> {
    let first = mine(prev, n);
    let second = mine(first.block_hash(), n + 1);
    vec![first, second]
}

#[test]
fn a_clock_two_hours_behind_the_median_still_starts_the_walk() {
    let _clock = ResetClock;
    let (_dir, hub, gen) = bare("clock-two-hours");
    let genesis_time = u64::from(gen.time);
    let mut behind = fresh(&hub);
    set_walk_unix_for_test(Some(genesis_time - 7_201));
    ensure_origin(&mut behind, &hub);
    assert!(behind.header_walk.clock_refused);
    assert!(behind.header_walk.max_headers.is_none());
    set_walk_unix_for_test(Some(genesis_time - 7_200));
    ensure_origin(&mut behind, &hub);
    assert!(!behind.header_walk.clock_refused);
    assert!(behind.header_walk.max_headers.is_some());
    assert!(behind.header_walk.origin);
}

#[test]
fn eleven_header_times_use_the_middle_time_as_the_walk_median() {
    let _clock = ResetClock;
    let (_dir, hub, _gen) = bare("clock-eleven");
    let mut st = fresh(&hub);
    set_walk_unix_for_test(Some(0));
    ensure_origin(&mut st, &hub);
    assert!(st.header_walk.clock_refused);
    let mut times = vec![0u32];
    times.extend([10_000; 5]);
    times.extend([50_000; 5]);
    st.header_walk.tip.times = times;
    set_walk_unix_for_test(Some(10_000 - 7_200));
    ensure_origin(&mut st, &hub);
    assert!(
        !st.header_walk.clock_refused,
        "the middle of the eleven times is inside the two-hour window"
    );
    assert!(st.header_walk.max_headers.is_some());
}

/// One-past bound of the `MAX_ORDERED_HEADERS` hard cap. The soft cap and
/// the empty-queue latch are `peer_header_sync_journey`'s.
#[test]
fn header_poll_waits_at_the_ordered_hard_cap() {
    let mut st = IbdWorkState::new(vec![], None, None);
    let ask = |st: &IbdWorkState, live: usize| {
        header_poll(
            st,
            HeaderPollIn {
                live,
                need_ready_headroom: false,
                lag: 0,
                min_cache: 0,
                fan: 0,
            },
        )
    };
    st.header_walk.origin = true;
    st.header_walk.tip.height = 4;
    assert!(matches!(ask(&st, MAX_ORDERED_HEADERS), HeaderPoll::Wait));
    assert!(matches!(ask(&st, MAX_ORDERED_HEADERS - 1), HeaderPoll::Ask));
}

/// Which chain the walk follows, and so what is asked next.
#[test]
fn an_unlinked_or_empty_batch_is_not_a_competing_chain() {
    let (_dir, hub, mut st, gen) = opened("suppress-unlinked");
    let tip = st.header_walk.tip_hash();
    assert!(!suppress_competing_chain(&mut st, &hub, 0, &[]));
    assert_eq!(st.header_walk.tip_hash(), tip);
    let kept = mine(gen.block_hash(), 1);
    assert!(extend_tip(&mut st, &hub, &[kept], None));
    let walked = st.header_walk.tip_hash();
    st.header_walk.checkpoints.clear();
    let linked = mine(gen.block_hash(), 2);
    let broken = mine(gen.block_hash(), 3);
    assert!(!suppress_competing_chain(
        &mut st,
        &hub,
        0,
        &[linked, broken]
    ));
    assert_eq!(st.header_walk.tip_hash(), walked);
}

/// Which chain the walk follows when a short fork stays above or crosses the floor.
#[test]
fn a_short_continuation_above_the_floor_is_not_adopted_as_a_fork() {
    let (_dir, hub, mut st, gen) = opened("suppress-above");
    let kept = mine(gen.block_hash(), 1);
    assert!(extend_tip(&mut st, &hub, &[kept], None));
    let walked = kept.block_hash();
    st.header_walk.checkpoints.clear();
    let fork = fork_from(gen.block_hash(), 20);
    assert!(suppress_competing_chain(&mut st, &hub, 0, &fork));
    assert_eq!(st.header_walk.tip_hash(), Some(walked));

    let (_dir, mut hub, mut st, gen) = opened("suppress-cross");
    let kept = mine(gen.block_hash(), 1);
    assert!(extend_tip(&mut st, &hub, &[kept], None));
    let walked = kept.block_hash();
    st.header_walk.checkpoints.clear();
    hub.milestone = Milestone {
        height: 1_000_000,
        anchor: Some(MilestoneAnchor {
            hash: BlockHash::from_byte_array([0xcd; 32]),
            min_work_be: one_more_work(st.header_walk.tip_work()),
        }),
    };
    let fork = fork_from(gen.block_hash(), 30);
    let adopted = fork[1].block_hash();
    assert!(!suppress_competing_chain(&mut st, &hub, 0, &fork));
    assert_eq!(st.header_walk.tip_hash(), Some(adopted));
    assert_ne!(st.header_walk.tip_hash(), Some(walked));
}

#[test]
fn the_oldest_refused_tip_stays_until_the_cap_is_passed() {
    let (_dir, _hub, mut st, gen) = opened("invalid-cap");
    let bad = mine(gen.block_hash(), 1);
    st.reorg.invalid.mark(bad.block_hash().to_byte_array());
    let mut prev = bad;
    let mut oldest = None;
    for n in 0..1024 {
        let hdr = mine(prev.block_hash(), n + 2);
        assert!(refuse_invalid_batch(&mut st, 0, &[hdr]));
        if n == 0 {
            oldest = Some(hdr);
        }
        prev = hdr;
    }
    let oldest = oldest.unwrap();
    let still = mine(oldest.block_hash(), 9_000);
    assert!(
        refuse_invalid_batch(&mut st, 0, &[still]),
        "the first refused tip is still refused at the cap"
    );
    let after = mine(oldest.block_hash(), 9_001);
    assert!(
        !refuse_invalid_batch(&mut st, 0, &[after]),
        "the next refusal of a new tip drops the oldest"
    );
}

/// Cap neighborhood: the dead-end set stays at `DEAD_END_CAP` entries.
#[test]
fn the_oldest_dead_end_gives_way_past_the_cap() {
    let (_dir, _hub, mut st, _gen) = opened("dead-end-cap");
    let hashes: Vec<BlockHash> = (1..=DEAD_END_CAP + 1)
        .map(|n| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(n as u64).to_le_bytes());
            BlockHash::from_byte_array(bytes)
        })
        .collect();
    for hash in &hashes[..DEAD_END_CAP] {
        note_dead(&mut st, *hash);
    }
    assert_eq!(st.header_walk.dead_ends.len(), DEAD_END_CAP);
    assert!(
        st.header_walk.dead_ends.contains(&hashes[0]),
        "the oldest dead end stays at the cap"
    );
    note_dead(&mut st, hashes[0]);
    assert_eq!(st.header_walk.dead_ends.len(), DEAD_END_CAP);
    assert!(
        st.header_walk.dead_ends.contains(&hashes[0]),
        "a dead end already kept drops nothing"
    );
    note_dead(&mut st, hashes[DEAD_END_CAP]);
    assert_eq!(st.header_walk.dead_ends.len(), DEAD_END_CAP);
    assert!(
        !st.header_walk.dead_ends.contains(&hashes[0]),
        "past the cap the oldest dead end gives way"
    );
    assert!(
        hashes[1..]
            .iter()
            .all(|h| st.header_walk.dead_ends.contains(h)),
        "every newer dead end is kept"
    );
}

/// The body-queue rows above an invalid block leave the store.
#[test]
fn retiring_a_block_drops_the_queue_above_its_parent_and_keeps_the_base() {
    let (_dir, hub, mut st, gen) = opened("retire-bounds");
    let h1 = mine(gen.block_hash(), 1);
    let h2 = mine(h1.block_hash(), 2);
    hub.ensure_header(&h1).unwrap();
    hub.ensure_header(&h2).unwrap();
    let parent = h1.block_hash();
    let failed = h2.block_hash();
    let sentinel = BlockHash::from_byte_array([0x5a; 32]);
    let arm = |st: &mut IbdWorkState| {
        st.record_height(parent, 1);
        st.record_height(failed, 2);
    };
    arm(&mut st);
    hub.query
        .block_queue_enqueue(1, parent.to_byte_array(), 1, b"a")
        .unwrap();
    hub.query
        .block_queue_enqueue(2, failed.to_byte_array(), 2, b"b")
        .unwrap();

    st.header_walk.origin = false;
    st.header_walk.tip.hash = Some(sentinel);
    st.header_walk.tip.height = 5;
    retire_invalid(&mut st, &hub, failed, 2);
    assert_eq!(st.header_walk.tip.hash, Some(sentinel));
    let queued = hub.query.block_queue_queued_heights();
    assert!(queued.contains(&1));
    assert!(!queued.contains(&2));

    arm(&mut st);
    st.header_walk.origin = true;
    st.header_walk.tip.hash = Some(sentinel);
    st.header_walk.tip.height = 0;
    retire_invalid(&mut st, &hub, failed, 2);
    assert_eq!(st.header_walk.tip.hash, Some(sentinel));

    arm(&mut st);
    st.header_walk.origin = true;
    st.header_walk.tip.hash = Some(sentinel);
    st.header_walk.tip.height = 2;
    st.header_walk.base_height = 1;
    st.header_walk.base_hash = Some(sentinel);
    retire_invalid(&mut st, &hub, failed, 2);
    assert_eq!(st.header_walk.tip.hash, Some(parent));
    assert_eq!(st.header_walk.base_hash, Some(sentinel));
    assert_eq!(st.header_walk.base_height, 1);

    arm(&mut st);
    st.header_walk.tip.hash = Some(failed);
    st.header_walk.tip.height = 2;
    st.header_walk.base_height = 5;
    st.header_walk.base_hash = Some(sentinel);
    retire_invalid(&mut st, &hub, failed, 2);
    assert_eq!(st.header_walk.base_height, 1);
    assert_eq!(st.header_walk.base_hash, Some(parent));

    arm(&mut st);
    st.header_walk.tip.hash = Some(failed);
    st.header_walk.tip.height = 2;
    st.header_walk.base_height = 0;
    st.header_walk.checkpoints = vec![checkpoint(1, sentinel, None)];
    retire_invalid(&mut st, &hub, failed, 2);
    assert_eq!(st.header_walk.checkpoints.len(), 1);
    assert_eq!(st.header_walk.checkpoints[0].hash, sentinel);

    arm(&mut st);
    st.header_walk.tip.hash = Some(failed);
    st.header_walk.tip.height = 2;
    st.header_walk.checkpoints = vec![checkpoint(0, gen.block_hash(), None)];
    retire_invalid(&mut st, &hub, failed, 2);
    assert_eq!(st.header_walk.checkpoints.len(), 2);
    assert_eq!(st.header_walk.checkpoints.last().unwrap().hash, parent);
    assert_eq!(st.header_walk.checkpoints.last().unwrap().height, 1);
}

/// One-past bounds of the confirmed tip in the getheaders locator.
#[test]
fn the_locator_names_the_confirmed_tip_only_between_the_anchor_and_the_queue() {
    let (_dir, hub, _gen) = bare("confirmed-between");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(2, op_true, vec![]).unwrap();
    let tip = hub.tip_hash().unwrap();
    assert_eq!(hub.tip_height(), Some(2));
    let mut st = fresh(&hub);
    let front = BlockHash::from_byte_array([0x71; 32]);
    st.ordered.push_back(front);
    st.hash_height.insert(front, 4);
    assert_eq!(confirmed_tip_above_anchor(&st, &hub, 0), Some(tip));
    st.hash_height.insert(front, 2);
    assert!(confirmed_tip_above_anchor(&st, &hub, 0).is_none());
    st.hash_height.insert(front, 4);
    assert!(confirmed_tip_above_anchor(&st, &hub, 2).is_none());
    assert!(confirmed_tip_above_anchor(&st, &hub, 3).is_none());
}

#[test]
fn a_header_that_lands_on_the_length_cap_is_still_allowed() {
    let (_dir, hub, mut st, gen) = opened("length-cap");
    st.header_walk.tip.height = 3;
    st.header_walk.tip.height_wide = 3;
    st.header_walk.max_headers = Some(4);
    let hdr = mine(gen.block_hash(), 1);
    assert!(extend_tip(&mut st, &hub, &[hdr], None));
    assert_eq!(st.header_walk.tip_height(), 4);
    assert!(!st.header_walk.length_exceeded);
    assert!(!store_would_pass_length(&mut st, 0));
    assert!(!st.header_walk.length_exceeded);
    assert!(store_would_pass_length(&mut st, 1));
    assert!(st.header_walk.length_exceeded);
}

#[test]
fn a_batch_that_does_not_link_does_not_extend_or_mark_the_length_cap() {
    let (_dir, hub, mut st, gen) = opened("extend-link");
    let before = st.header_walk.tip_hash();
    let mut bad = mine(gen.block_hash(), 1);
    bad.bits = CompactTarget::from_consensus(0x1d00ffff);
    assert!(!extend_tip(&mut st, &hub, &[bad], None));
    assert_eq!(st.header_walk.tip_hash(), before);
    assert!(!st.header_walk.length_exceeded);
    st.header_walk.tip.height = 5;
    st.header_walk.tip.height_wide = 5;
    st.header_walk.max_headers = Some(4);
    assert!(!extend_tip(&mut st, &hub, &[], None));
    assert!(!st.header_walk.length_exceeded);
    assert_eq!(st.header_walk.tip_hash(), before);
}

#[test]
fn an_unproved_resume_keeps_the_tip_until_the_next_header_is_indexed() {
    let (_dir, mut hub, mut st, gen) = opened("resume-keep");
    let hdr = mine(gen.block_hash(), 1);
    let saved = hdr.block_hash();
    assert!(extend_tip(&mut st, &hub, &[hdr], Some(0)));
    assert!(adopt_path(&hub).exists());
    hub.milestone = high_floor();
    let mut resumed = fresh(&hub);
    assert!(restore_adopt(&mut resumed, &hub));
    assert!(!resumed.header_walk.proven);
    assert_eq!(resumed.header_walk.tip_hash(), Some(saved));
    assert!(send_getheaders(&mut resumed, &hub).unwrap());
    assert_eq!(resumed.header_walk.tip_hash(), Some(saved));
    assert!(adopt_path(&hub).exists());

    let mut reset = fresh(&hub);
    assert!(restore_adopt(&mut reset, &hub));
    let next = reset.header_walk.tip_height().saturating_add(1);
    reset.record_height(BlockHash::from_byte_array([0x81; 32]), next);
    assert!(send_getheaders(&mut reset, &hub).unwrap());
    assert_eq!(reset.header_walk.tip_hash(), Some(gen.block_hash()));
    assert!(!adopt_path(&hub).exists());
}

/// One-past bound of a lighter fork in the getheaders locator.
#[test]
fn the_locator_names_a_challenger_only_when_it_is_taller_than_the_tip() {
    let (_dir, hub, _gen) = bare("locator-challenger");
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.generate_to_script(2, op_true, vec![]).unwrap();
    let mut st = fresh(&hub);
    let low = BlockHash::from_byte_array([0x91; 32]);
    let high = BlockHash::from_byte_array([0x92; 32]);
    st.header_walk.challenger = Some(Challenger {
        fork_hash: BlockHash::from_byte_array([0x93; 32]),
        fork_height: 1,
        tip: WalkTip {
            hash: Some(low),
            height: 2,
            ..WalkTip::default()
        },
        checkpoints: Vec::new(),
    });
    assert!(!header_ask_locator(&st, &hub).refill.contains(&low));
    let ch = st.header_walk.challenger.as_mut().unwrap();
    ch.tip.height = 3;
    ch.tip.hash = Some(high);
    assert!(header_ask_locator(&st, &hub).refill.contains(&high));
}
