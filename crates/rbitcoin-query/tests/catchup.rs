use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::catchup::*;
use rbitcoin_query::sh_builder::{load_seal, store_seal};
use rbitcoin_query::testutil::FixtureChain;
use rbitcoin_query::Query;
use rbitcoin_store::StoreError;
use rbitcoin_store::{HeaderRecord, InputRecord, OutputRecord, ScriptHashRecord, TxRecord};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn coinbase_block(
    h: u32,
    prev: Fk,
    parent_hash: Option<[u8; 32]>,
) -> (HeaderRecord, rbitcoin_query::TxApply) {
    let version = 1;
    let timestamp = h + 1;
    let bits = 0x207fffff;
    let nonce = h;
    let mut merkle = [0u8; 32];
    merkle[0..4].copy_from_slice(&h.to_le_bytes());
    merkle[4] = 0xcd;
    let hash = match parent_hash {
        None => merkle,
        Some(ph) => {
            rbitcoin_store::block_header_hash(version, &ph, &merkle, timestamp, bits, nonce)
        }
    };
    let header = HeaderRecord {
        prev_fk: prev,
        version,
        timestamp,
        bits,
        nonce,
        merkle_root: merkle,
        hash,
        size: 0,
        weight: 0,
    };
    let mut txid = [0u8; 32];
    txid[0..4].copy_from_slice(&h.to_le_bytes());
    txid[31] = 0xcb;
    let ta = rbitcoin_query::TxApply {
        tx: TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        inputs: vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
            sequence: u32::MAX,
            script_sig: vec![h as u8],
            witness: vec![],
        }],
        outputs: vec![OutputRecord::unspent(50_0000_0000, vec![0x51, h as u8])],
    };
    (header, ta)
}

#[test]
fn unknown_index_mode_byte_is_corrupt() {
    let (_dir, q) = rbitcoin_query::testutil::tiny_query_labeled("idx-mode-byte");
    for bad in [0u8, 3] {
        q.index_mode_cell
            .store(bad, std::sync::atomic::Ordering::SeqCst);
        match q.index_mode() {
            Err(StoreError::Corrupt(msg)) => {
                assert_eq!(msg, "index mode byte", "byte {bad}");
            }
            other => panic!("byte {bad} must be corrupt, got {other:?}"),
        }
    }
    q.index_mode_cell
        .store(IndexMode::Direct as u8, std::sync::atomic::Ordering::SeqCst);
    assert!(q.index_mode().expect("direct").is_direct());
    q.index_mode_cell
        .store(IndexMode::Tip as u8, std::sync::atomic::Ordering::SeqCst);
    assert!(q.index_mode().expect("tip").is_tip());
    assert!(!q.index_mode().expect("tip").is_direct());
}

fn seed_direct_chain(q: &Query, n: u32) {
    q.enter_direct_index_mode().unwrap();
    extend_direct_chain(q, n);
    assert_eq!(q.tip_height(), Some(Height(n - 1)));
    assert!(q.store.txs.count() >= u64::from(n));
}

fn extend_direct_chain(q: &Query, add: u32) {
    if add == 0 {
        return;
    }
    let start = q.tip_height().map(|h| h.0.saturating_add(1)).unwrap_or(0);
    let mut prev = Fk::NULL;
    let mut parent_hash: Option<[u8; 32]> = None;
    if start > 0 {
        let prev_h = Height(start - 1);
        prev = q.store.confirmed.get(prev_h).unwrap().unwrap();
        parent_hash = Some(q.get_header(prev).unwrap().hash);
    }
    for h in start..start + add {
        let (header, ta) = coinbase_block(h, prev, parent_hash);
        parent_hash = Some(header.hash);
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
}

#[test]
fn finalize_sh_runs_durable_head_missing_hwm_keeps_seal() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-hwm");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 3);
    let n0 = q.finalize_sh_runs().unwrap();
    assert!(n0 >= 1 || q.store.scripthash.has_durable_index());
    assert!(q.store.scripthash.has_durable_index());
    let count_before = q.store.scripthash.entry_count();
    let sh0 = rbitcoin_store::script_hash(&[0x51, 0]);

    let runs_dir = dir.join("scripthash.runs");
    std::fs::create_dir_all(&runs_dir).unwrap();
    let high_seal = 1_411_000_000u64;
    store_seal(&runs_dir, high_seal).unwrap();
    q.sh_run.refresh_seal();
    let _ = std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME));
    assert_eq!(q.store.scripthash.include_hwm(), 0);
    assert_eq!(q.sh_run.sealed_max_create_fk(), high_seal);

    let _ = q.finalize_sh_runs().unwrap();
    assert_eq!(
        q.sh_run.sealed_max_create_fk(),
        high_seal,
        "SEAL must not be clamped to 0 when HWM was missing"
    );
    assert_eq!(
        q.store.scripthash.include_hwm(),
        high_seal,
        "include_hwm must bootstrap from SEAL"
    );
    assert!(
        !q.store.scripthash.entries(&sh0).unwrap().is_empty(),
        "durable head must remain"
    );
    assert!(q.store.scripthash.entry_count() >= count_before);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A legacy head has no include file. A SEAL within a million creates of
/// the stem is the lost tail, and this open unlinks it. The next restart
/// is not what records the span.
#[test]
fn missing_hwm_unlinks_a_nearby_seal_on_this_open() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-seal-tail");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let old = q.store.scripthash.include_hwm();
    assert!(old > 1);
    assert!(old - 1 <= 1_000_000);
    q.sh_run.refresh_seal();
    assert_eq!(q.sh_run.sealed_max_create_fk(), old);
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    assert_eq!(q.store.txs.count(), 1);
    std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME)).unwrap();
    assert_eq!(q.store.scripthash.include_hwm(), 0);
    let cut = rbitcoin_store::script_hash(&[0x51, 1]);
    let before = q.store.scripthash.entries(&cut).unwrap();
    assert!(
        before.iter().any(|(fk, _)| fk.0 > 1),
        "tail create must be indexed before repair: {before:?}"
    );
    q.finalize_sh_runs().unwrap();
    let after = q.store.scripthash.entries(&cut).unwrap();
    assert!(
        after.iter().all(|(fk, _)| fk.0 <= 1),
        "this open left a create past the stem: {after:?}"
    );
    assert_eq!(q.store.scripthash.include_hwm(), 1);
    assert!(q.sh_run.sealed_max_create_fk() <= 1);
    assert!(q.sh_is_tip_ready());
    let bytes = std::fs::read(dir.join("scripthash.recheck")).unwrap();
    assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), old);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `include_hwm` above the create count is not tip-ready. Open drops that
/// tail with the disconnect unlink. A second open does not rebuild.
#[test]
fn sh_floor_above_the_create_count_drops_the_tail() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-lost-tail");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    assert!(q.sh_is_tip_ready());
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    assert_eq!(q.store.txs.count(), 1);
    assert!(!q.sh_is_tip_ready());
    let cut = rbitcoin_store::script_hash(&[0x51, 1]);
    let before = q.store.scripthash.entries(&cut).unwrap();
    assert!(
        before.iter().any(|(fk, _)| fk.0 > 1),
        "tail create must be indexed before repair: {before:?}"
    );
    q.finalize_sh_runs().unwrap();
    let after = q.store.scripthash.entries(&cut).unwrap();
    assert!(
        after.iter().all(|(fk, _)| fk.0 <= 1),
        "history must not keep a create past the stem: {after:?}"
    );
    assert!(q.sh_is_tip_ready());
    assert!(!rbitcoin_store::scripthash::sh_rebuild_marked(&dir));
    let n = q.store.scripthash.entry_count();
    q.finalize_sh_runs().unwrap();
    assert_eq!(q.store.scripthash.entry_count(), n);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The tail creates are already gone from the locator, so their outputs
/// cannot be read. Startup lowers the watermark and leaves the packed head.
/// It does not build that head again from Class A.
#[test]
fn missing_tail_outputs_lower_the_watermark_without_a_rebuild() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-tail-missing");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    assert!(q.sh_is_tip_ready());
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    assert_eq!(q.store.txs.count(), 1);
    assert!(q.store.scripthash.include_hwm() > 1);
    let cut = rbitcoin_store::script_hash(&[0x51, 1]);
    let before = q.store.scripthash.entries(&cut).unwrap();
    assert!(
        before.iter().any(|(fk, _)| fk.0 > 1),
        "tail create must be indexed before repair: {before:?}"
    );
    let count_before = q.store.scripthash.entry_count();
    let n = q.finalize_sh_runs().unwrap();
    assert_eq!(n, 0, "missing outputs must not rematerialize Class A");
    assert_eq!(q.store.scripthash.entry_count(), count_before);
    let after = q.store.scripthash.entries(&cut).unwrap();
    assert!(
        after.iter().any(|(fk, _)| fk.0 > 1),
        "a packed head has no key to unlink, so the row stays: {after:?}"
    );
    assert_eq!(q.store.scripthash.include_hwm(), 1);
    assert!(q.sh_run.sealed_max_create_fk() <= 1);
    assert!(!rbitcoin_store::scripthash::sh_rebuild_marked(&dir));
    assert!(q.sh_is_tip_ready());
    assert_eq!(q.finalize_sh_runs().unwrap(), 0);
    assert_eq!(q.store.scripthash.entry_count(), count_before);
    let _ = std::fs::remove_dir_all(&dir);
}

thread_local! {
    static SAW_HWM_PUBLISH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

fn snap_hwm_before_replace(q: &Query) {
    SAW_HWM_PUBLISH.with(|c| c.set(true));
    let covered = q.store.txs.count();
    assert!(q.sh_run.sealed_max_create_fk() <= covered);
    let path = q.store.path().join(rbitcoin_store::INCLUDE_HWM_NAME);
    assert!(
        path.is_file(),
        "the watermark file is replaced, not deleted first"
    );
    let buf = std::fs::read(&path).unwrap();
    let cur = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    assert!(cur > covered);
}

fn connect_spk(q: &Query, h: u32, prev: Fk, parent_hash: Option<[u8; 32]>, spk: &[u8]) -> Fk {
    let (header, mut ta) = coinbase_block(h, prev, parent_hash);
    ta.outputs[0] = OutputRecord::unspent(50_0000_0000, spk.to_vec());
    q.connect_block(Height(h), &header, &[ta]).unwrap()
}

/// The packed row still ends on a create past the covered count. A later
/// create of that script, below that end and inside the live count, is stored.
/// Replaying a create already inside the live count does not duplicate it.
#[test]
fn stale_tail_stores_a_lower_live_create() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-stale-lower");
    q.enter_direct_index_mode().unwrap();
    let script_s = [0x51u8, 0xab];
    let script_t = [0x51u8, 0xcd];
    let mut prev = Fk::NULL;
    let mut parent = None;
    for (h, spk) in [
        script_s.as_slice(),
        script_t.as_slice(),
        script_s.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let fk = connect_spk(&q, h as u32, prev, parent, spk);
        parent = Some(q.get_header(fk).unwrap().hash);
        prev = fk;
    }
    q.finalize_sh_runs().unwrap();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    assert_eq!(q.store.txs.count(), 1);
    q.finalize_sh_runs().unwrap();
    let sh = rbitcoin_store::script_hash(&script_s);
    let before: Vec<u64> = q
        .store
        .scripthash
        .entries(&sh)
        .unwrap()
        .into_iter()
        .map(|(fk, _)| fk.0)
        .collect();
    assert_eq!(
        before,
        vec![1, 3],
        "packed row keeps the cut tail: {before:?}"
    );
    let recs = [
        ScriptHashRecord::from_fk(sh, Fk(1)),
        ScriptHashRecord::from_fk(sh, Fk(2)),
        ScriptHashRecord::from_fk(sh, Fk(8)),
    ];
    let (n, _) = q
        .store
        .scripthash
        .put_create_batch_append_through(&recs, 2)
        .unwrap();
    assert_eq!(n, 1, "the new create below the stale end must be stored");
    let after: Vec<u64> = q
        .store
        .scripthash
        .entries(&sh)
        .unwrap()
        .into_iter()
        .map(|(fk, _)| fk.0)
        .collect();
    assert_eq!(after, vec![1, 2]);
    let (n2, _) = q
        .store
        .scripthash
        .put_create_batch_append_through(&recs, 2)
        .unwrap();
    assert_eq!(
        n2, 0,
        "a create already inside the live count is not stored again"
    );
    let again: Vec<u64> = q
        .store
        .scripthash
        .entries(&sh)
        .unwrap()
        .into_iter()
        .map(|(fk, _)| fk.0)
        .collect();
    assert_eq!(again, vec![1, 2]);
    let sh_hole = rbitcoin_store::script_hash(&[0x51, 0xee]);
    q.store
        .scripthash
        .put_create_batch_append(&[
            ScriptHashRecord::from_fk(sh_hole, Fk(1)),
            ScriptHashRecord::from_fk(sh_hole, Fk(4)),
            ScriptHashRecord::from_fk(sh_hole, Fk(9)),
        ])
        .unwrap();
    let (n_hole, _) = q
        .store
        .scripthash
        .put_create_batch_append_through(&[ScriptHashRecord::from_fk(sh_hole, Fk(2))], 5)
        .unwrap();
    assert_eq!(n_hole, 1);
    let hole: Vec<u64> = q
        .store
        .scripthash
        .entries(&sh_hole)
        .unwrap()
        .into_iter()
        .map(|(fk, _)| fk.0)
        .collect();
    assert_eq!(hole, vec![1, 2, 4]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The live count has already moved past the stale end. A real create at or
/// below that end is still stored, and storing it again does not duplicate it.
#[test]
fn live_count_past_the_stale_end_stores_the_lower_create() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-stale-past");
    q.enter_direct_index_mode().unwrap();
    let script_s = [0x51u8, 0xab];
    let script_t = [0x51u8, 0xcd];
    let mut prev = Fk::NULL;
    let mut parent = None;
    for (h, spk) in [
        script_s.as_slice(),
        script_t.as_slice(),
        script_s.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let fk = connect_spk(&q, h as u32, prev, parent, spk);
        parent = Some(q.get_header(fk).unwrap().hash);
        prev = fk;
    }
    q.finalize_sh_runs().unwrap();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    q.finalize_sh_runs().unwrap();
    let sh = rbitcoin_store::script_hash(&script_s);
    let before: Vec<u64> = q
        .store
        .scripthash
        .entries(&sh)
        .unwrap()
        .into_iter()
        .map(|(fk, _)| fk.0)
        .collect();
    assert_eq!(before, vec![1, 3]);
    let rec = [ScriptHashRecord::from_fk(sh, Fk(2))];
    let (n, _) = q
        .store
        .scripthash
        .put_create_batch_append_through(&rec, 10)
        .unwrap();
    assert_eq!(n, 1, "a create under the stale end must be stored");
    let after: Vec<u64> = q
        .store
        .scripthash
        .entries(&sh)
        .unwrap()
        .into_iter()
        .map(|(fk, _)| fk.0)
        .collect();
    assert!(after.contains(&2), "row after the late append: {after:?}");
    let (n2, _) = q
        .store
        .scripthash
        .put_create_batch_append_through(&rec, 10)
        .unwrap();
    assert_eq!(n2, 0, "the same create is not stored twice");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The shortened head is synced before the old slab is freed and before
/// `live_count` drops. A crash in between must not subtract the tail twice
/// or reuse the slab the head still names.
#[test]
fn repair_syncs_the_head_before_freeing_the_old_slab() {
    use rbitcoin_store::scripthash::{KeyHome, ScriptHashTable};
    use rbitcoin_store::ShHeadValue;
    use std::cell::{Cell, RefCell};

    thread_local! {
        static BEFORE: Cell<u64> = const { Cell::new(0) };
        static OFF: Cell<u64> = const { Cell::new(0) };
        static PREFIX: RefCell<[u8; 8]> = const { RefCell::new([0; 8]) };
        static KEY: RefCell<[u8; 32]> = const { RefCell::new([0; 32]) };
        static SAW: Cell<bool> = const { Cell::new(false) };
    }

    fn snap(sh: &ScriptHashTable) {
        let key = KEY.with(|c| *c.borrow());
        let ents: Vec<u64> = sh
            .entries(&key)
            .unwrap()
            .into_iter()
            .map(|(fk, _)| fk.0)
            .collect();
        assert_eq!(ents, vec![1], "the new head is already published");
        let before = BEFORE.with(|c| c.get());
        assert_eq!(
            sh.entry_count(),
            before,
            "live_count stays put until the head is synced"
        );
        let off = OFF.with(|c| c.get());
        let expect = PREFIX.with(|c| *c.borrow());
        let home = sh.locate_head(&key).unwrap().unwrap().1;
        let body = sh.body_for(&key, KeyHome::from(home));
        let mut got = [0u8; 8];
        body.read_at(off, &mut got).unwrap();
        assert_eq!(got, expect, "the old slab is not a freelist link yet");
        assert!(
            rbitcoin_store::scripthash::repair_heads_synced_for_test() > 0,
            "the head file is synced before the free"
        );
        SAW.with(|c| c.set(true));
    }

    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-repair-sync");
    q.enter_direct_index_mode().unwrap();
    let script_s = [0x51u8, 0xab];
    let script_t = [0x51u8, 0xcd];
    let mut prev = Fk::NULL;
    let mut parent = None;
    for (h, spk) in [
        script_s.as_slice(),
        script_t.as_slice(),
        script_s.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let fk = connect_spk(&q, h as u32, prev, parent, spk);
        parent = Some(q.get_header(fk).unwrap().hash);
        prev = fk;
    }
    q.finalize_sh_runs().unwrap();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    q.finalize_sh_runs().unwrap();
    let sh = rbitcoin_store::script_hash(&script_s);
    let (val, home) = q.store.scripthash.locate_head(&sh).unwrap().unwrap();
    let off = match val {
        ShHeadValue::Slab { off, .. } => off,
        other => panic!("two creates sit in a slab, got {other:?}"),
    };
    let body = q.store.scripthash.body_for(&sh, KeyHome::from(home));
    let mut prefix = [0u8; 8];
    body.read_at(off, &mut prefix).unwrap();
    BEFORE.with(|c| c.set(q.store.scripthash.entry_count()));
    OFF.with(|c| c.set(off));
    PREFIX.with(|c| *c.borrow_mut() = prefix);
    KEY.with(|c| *c.borrow_mut() = sh);
    SAW.with(|c| c.set(false));
    rbitcoin_store::scripthash::set_repair_retire_hook_for_test(Some(snap));
    let (n, _) = q
        .store
        .scripthash
        .put_create_batch_append_through(&[ScriptHashRecord::from_fk(sh, Fk(1))], 1)
        .unwrap();
    rbitcoin_store::scripthash::set_repair_retire_hook_for_test(None);
    assert!(SAW.with(|c| c.get()), "retire hook did not run");
    assert_eq!(n, 0);
    let after: Vec<u64> = q
        .store
        .scripthash
        .entries(&sh)
        .unwrap()
        .into_iter()
        .map(|(fk, _)| fk.0)
        .collect();
    assert_eq!(after, vec![1]);
    assert_eq!(
        q.store.scripthash.entry_count(),
        BEFORE.with(|c| c.get()) - 1
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn txid_at(h: u32) -> [u8; 32] {
    let mut txid = [0u8; 32];
    txid[0..4].copy_from_slice(&h.to_le_bytes());
    txid[31] = 0xcb;
    txid
}

/// Rows flushed past `include_hwm` still have to be rechecked after a cut
/// that leaves the watermark at or below the new create count.
#[test]
fn flushed_tail_above_the_watermark_is_rechecked_on_open() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-through");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let count = q.store.txs.count();
    assert!(count > 0);
    assert!(q.store.scripthash.include_hwm() <= count);
    let through = count.saturating_add(2);
    std::fs::write(dir.join("scripthash.through"), through.to_le_bytes()).unwrap();
    drop(q);
    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    let spans = rbitcoin_store::scripthash::sh_recheck_spans(q.store.path()).unwrap();
    assert_eq!(
        spans,
        vec![(count, through)],
        "a durable row above include_hwm was left out of the recheck span"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The flush marker lands before the body sync, so a crash in between still
/// has the high create the watermark has not recorded.
#[test]
fn include_hwm_advance_records_the_flushed_tail_first() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-through-advance");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    let count = q.store.txs.count();
    q.sh.applied_max_fk.store(count, Ordering::Release);
    q.advance_sh_include_hwm().unwrap();
    let bytes = std::fs::read(dir.join("scripthash.through")).expect("scripthash.through");
    let through = u64::from_le_bytes(bytes.as_slice().try_into().unwrap());
    assert_eq!(through, count);
    assert_eq!(q.store.scripthash.include_hwm(), count);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The lost-tail span has to cover a flushed row past `include_hwm`.
/// Stopping the span at the watermark leaves that row in history after reuse.
#[test]
fn lost_tail_recheck_reaches_the_flushed_mark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-through-span");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let hwm = q.store.scripthash.include_hwm();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    assert!(hwm > 1, "hwm {hwm}");
    let through = hwm.saturating_add(4);
    std::fs::write(dir.join("scripthash.through"), through.to_le_bytes()).unwrap();
    q.finalize_sh_runs().unwrap();
    let spans = rbitcoin_store::scripthash::sh_recheck_spans(q.store.path()).unwrap();
    assert_eq!(
        spans,
        vec![(1, through)],
        "the recheck span stopped at include_hwm {hwm}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A repaired posting can be synced while `include_hwm` still names an older
/// create. The marker is the live count, and an ordinary append does not
/// write `u64::MAX`.
#[test]
fn repaired_body_records_the_live_count_not_the_sentinel() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-through-repair");
    let sh = rbitcoin_store::script_hash(&[0x51, 0xee]);
    q.store
        .scripthash
        .put_create_batch_append(&[
            ScriptHashRecord::from_fk(sh, Fk(1)),
            ScriptHashRecord::from_fk(sh, Fk(4)),
            ScriptHashRecord::from_fk(sh, Fk(9)),
        ])
        .unwrap();
    assert!(
        !dir.join("scripthash.through").exists(),
        "an ordinary append must not record u64::MAX"
    );
    q.store
        .scripthash
        .put_create_batch_append_through(&[ScriptHashRecord::from_fk(sh, Fk(2))], 5)
        .unwrap();
    let bytes = std::fs::read(dir.join("scripthash.through")).expect("scripthash.through");
    let through = u64::from_le_bytes(bytes.as_slice().try_into().unwrap());
    assert_eq!(through, 5);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A full rebuild wipes the head. A leftover flushed-tail mark would make
/// the next open recheck creates the new head does not have.
#[test]
fn force_rebuild_clears_the_flushed_tail_mark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-through-wipe");
    std::fs::write(dir.join("scripthash.through"), 9u64.to_le_bytes()).unwrap();
    q.sh_run.prepare_force_full_rebuild(&q.store).unwrap();
    assert!(
        !dir.join("scripthash.through").exists(),
        "the rebuild left scripthash.through"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A past-end read or a slab repair writes `scripthash.rebuild` before any
/// wipe. That marker still has to wipe. Keeping the inclusion mark would
/// leave the sealed corrupt head tip-ready and then delete the marker.
#[test]
fn fault_rebuild_marker_wipes_the_inclusion_mark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-rebuild-fault");
    q.enter_direct_index_mode().unwrap();
    rbitcoin_store::scripthash::mark_sh_rebuild(q.store.path()).unwrap();
    rbitcoin_store::scripthash::store_include_hwm(q.store.path(), 5).unwrap();
    let mut mark = [0u8; 16];
    mark[..8].copy_from_slice(&1u64.to_le_bytes());
    mark[8..].copy_from_slice(&4u64.to_le_bytes());
    std::fs::write(q.store.path().join("scripthash.recheck"), mark).unwrap();
    q.finalize_sh_runs().unwrap();
    assert_eq!(
        q.store.scripthash.include_hwm(),
        0,
        "a fault marker left the inclusion mark"
    );
    assert!(
        !q.store.path().join("scripthash.recheck").exists(),
        "a fault marker left the recheck span"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The resume byte means the wipe already finished. Wiping the inclusion
/// mark and the recheck span would throw away a head the last attempt
/// had already sealed.
#[test]
fn interrupted_rebuild_keeps_the_inclusion_mark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-rebuild-resume");
    q.enter_direct_index_mode().unwrap();
    rbitcoin_store::scripthash::mark_sh_rebuild_resume(q.store.path()).unwrap();
    rbitcoin_store::scripthash::store_include_hwm(q.store.path(), 5).unwrap();
    let mut mark = [0u8; 16];
    mark[..8].copy_from_slice(&1u64.to_le_bytes());
    mark[8..].copy_from_slice(&4u64.to_le_bytes());
    std::fs::write(q.store.path().join("scripthash.recheck"), mark).unwrap();
    q.finalize_sh_runs().unwrap();
    assert_eq!(
        q.store.scripthash.include_hwm(),
        5,
        "the resume wiped the inclusion mark"
    );
    let got = std::fs::read(q.store.path().join("scripthash.recheck")).expect("scripthash.recheck");
    assert_eq!(got, mark);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cut create number that now pays a different script stays on the old
/// row. Windowed history must not return it, and a newest page must not
/// spend one of its slots on it.
#[test]
fn reused_cut_fk_stays_out_of_windowed_history() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-reused-hist");
    q.enter_direct_index_mode().unwrap();
    let script_s = [0x51u8, 0xab];
    let script_o = [0x51u8, 0xee];
    let mut prev = Fk::NULL;
    let mut parent = None;
    for (h, spk) in [
        script_s.as_slice(),
        script_s.as_slice(),
        script_o.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let fk = connect_spk(&q, h as u32, prev, parent, spk);
        parent = Some(q.get_header(fk).unwrap().hash);
        prev = fk;
    }
    q.finalize_sh_runs().unwrap();
    let sh = rbitcoin_store::script_hash(&script_s);
    q.store
        .scripthash
        .put_create_batch_append(&[ScriptHashRecord::from_fk(sh, Fk(3))])
        .unwrap();
    let mut mark = [0u8; 16];
    mark[..8].copy_from_slice(&2u64.to_le_bytes());
    mark[8..].copy_from_slice(&3u64.to_le_bytes());
    std::fs::write(q.store.path().join("scripthash.recheck"), mark).unwrap();
    let bad = txid_at(2);
    let window = rbitcoin_query::HistoryFilter::height_window(2, None);
    let hist = q.scripthash_history_filtered(&sh, &window).unwrap();
    assert!(
        hist.rows.iter().all(|row| row.txid != bad),
        "from_height history returned the reused create: {:?}",
        hist.rows.iter().map(|row| row.tx_fk).collect::<Vec<_>>()
    );
    let mut page = rbitcoin_query::HistoryFilter::esplora_chain_page(None);
    page.limit = Some(2);
    let rows = q.scripthash_history_filtered(&sh, &page).unwrap().rows;
    assert!(
        rows.iter().all(|row| row.txid != bad),
        "the newest page included the reused create"
    );
    assert_eq!(
        rows.len(),
        2,
        "the reused create took a slot and the page came back short: {rows:?}"
    );
    let full = q
        .scripthash_history_filtered(
            &sh,
            &rbitcoin_query::HistoryFilter::esplora_chain_page(None),
        )
        .unwrap();
    assert!(full.rows.iter().all(|row| row.txid != bad));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same reused create is not a height touch, a subscription status,
/// or a join-cap create. A create outside the span still counts, including
/// a pending copy of a real one and a null fk that no span covers.
#[test]
fn reused_cut_fk_stays_out_of_touch_and_create_count() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-reused-touch");
    q.enter_direct_index_mode().unwrap();
    let script_s = [0x51u8, 0xab];
    let script_o = [0x51u8, 0xee];
    let mut prev = Fk::NULL;
    let mut parent = None;
    for (h, spk) in [
        script_s.as_slice(),
        script_s.as_slice(),
        script_o.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let fk = connect_spk(&q, h as u32, prev, parent, spk);
        parent = Some(q.get_header(fk).unwrap().hash);
        prev = fk;
    }
    q.finalize_sh_runs().unwrap();
    let sh = rbitcoin_store::script_hash(&script_s);
    let only = [0x99u8; 32];
    q.store
        .scripthash
        .put_create_batch_append(&[
            ScriptHashRecord::from_fk(sh, Fk(3)),
            ScriptHashRecord::from_fk(only, Fk(3)),
        ])
        .unwrap();
    q.sh.ram_head
        .lock()
        .unwrap()
        .insert(sh, vec![Fk(1), Fk(3), Fk(4), Fk::NULL]);
    let mut mark = [0u8; 16];
    mark[..8].copy_from_slice(&2u64.to_le_bytes());
    mark[8..].copy_from_slice(&3u64.to_le_bytes());
    std::fs::write(q.store.path().join("scripthash.recheck"), mark).unwrap();
    assert!(
        q.scripthash_tx_fks_at_height(&sh, Height(2))
            .unwrap()
            .is_empty(),
        "height 2 still reports the reused create"
    );
    assert!(!q.scripthash_touched_at_height(&sh, Height(2)).unwrap());
    let touch = q.block_touch(Height(2)).unwrap();
    assert!(!q.scripthash_touched_by(&sh, &touch).unwrap());
    assert!(!q.scripthash_touched_by(&only, &touch).unwrap());
    assert!(!q.scripthash_has_postings(&only).unwrap());
    assert_eq!(q.scripthash_create_count(&only).unwrap(), 0);
    assert!(q.scripthash_has_postings(&sh).unwrap());
    let at_real = q.scripthash_tx_fks_at_height(&sh, Height(0)).unwrap();
    assert_eq!(at_real, vec![Fk(1)]);
    assert!(q.scripthash_touched_at_height(&sh, Height(0)).unwrap());
    // Durable 1 and 2, plus pending 1, 4, and null. Pending 3 is the cut.
    assert_eq!(q.scripthash_create_count(&sh).unwrap(), 5);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A second lost-tail span is its own record. History still drops a reused
/// create that sits only in that later span.
#[test]
fn later_recheck_span_drops_its_own_reused_create() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-recheck-span");
    q.enter_direct_index_mode().unwrap();
    let script_s = [0x51u8, 0xab];
    let script_o = [0x51u8, 0xee];
    let mut prev = Fk::NULL;
    let mut parent = None;
    for (h, spk) in [
        script_s.as_slice(),
        script_s.as_slice(),
        script_o.as_slice(),
    ]
    .into_iter()
    .enumerate()
    {
        let fk = connect_spk(&q, h as u32, prev, parent, spk);
        parent = Some(q.get_header(fk).unwrap().hash);
        prev = fk;
    }
    q.finalize_sh_runs().unwrap();
    let sh = rbitcoin_store::script_hash(&script_s);
    q.store
        .scripthash
        .put_create_batch_append(&[ScriptHashRecord::from_fk(sh, Fk(3))])
        .unwrap();
    let mut mark = [0u8; 32];
    mark[0..8].copy_from_slice(&0u64.to_le_bytes());
    mark[8..16].copy_from_slice(&1u64.to_le_bytes());
    mark[16..24].copy_from_slice(&2u64.to_le_bytes());
    mark[24..32].copy_from_slice(&3u64.to_le_bytes());
    std::fs::write(q.store.path().join("scripthash.recheck"), mark).unwrap();
    let bad = txid_at(2);
    let hist = q
        .scripthash_history_filtered(
            &sh,
            &rbitcoin_query::HistoryFilter::esplora_chain_page(None),
        )
        .unwrap();
    assert!(
        hist.rows.iter().all(|row| row.txid != bad),
        "the later span still returned the reused create: {:?}",
        hist.rows.iter().map(|row| row.tx_fk).collect::<Vec<_>>()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn snap_recheck_before_watermark(q: &Query) {
    let path = q.store.path().join("scripthash.recheck");
    let bytes = std::fs::read(&path).expect("recheck marker before the watermark moves");
    assert_eq!(bytes.len(), 16);
    let covered = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let old = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
    assert_eq!(covered, q.store.txs.count());
    assert!(old > covered);
    let hwm_bytes = std::fs::read(q.store.path().join(rbitcoin_store::INCLUDE_HWM_NAME)).unwrap();
    let hwm = u64::from_le_bytes(hwm_bytes[0..8].try_into().unwrap());
    assert!(hwm > covered, "the watermark file is still the high one");
}

/// The lost-tail repair records which create numbers may have been reused
/// before it replaces the watermark. History uses that span later.
#[test]
fn lost_tail_records_the_recheck_span_before_the_watermark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-recheck");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let old = q.store.scripthash.include_hwm();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    assert!(old > 1);
    set_sh_hwm_publish_for_test(Some(snap_recheck_before_watermark));
    q.finalize_sh_runs().unwrap();
    set_sh_hwm_publish_for_test(None);
    let bytes = std::fs::read(q.store.path().join("scripthash.recheck")).unwrap();
    assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), old);
    assert_eq!(q.store.scripthash.include_hwm(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The seal drops before the watermark file is replaced. A crash in between
/// still has the old watermark, so the next start retries instead of copying
/// the old seal back into a missing file.
#[test]
fn lost_tail_lowers_the_seal_before_replacing_the_watermark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-hwm-order");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    assert!(q.store.scripthash.include_hwm() > 1);
    assert!(q.sh_run.sealed_max_create_fk() > 1);
    SAW_HWM_PUBLISH.with(|c| c.set(false));
    set_sh_hwm_publish_for_test(Some(snap_hwm_before_replace));
    let n = q.finalize_sh_runs().unwrap();
    set_sh_hwm_publish_for_test(None);
    assert!(
        SAW_HWM_PUBLISH.with(|c| c.get()),
        "publish hook did not run"
    );
    assert_eq!(n, 0);
    assert_eq!(q.store.scripthash.include_hwm(), 1);
    assert!(q.sh_run.sealed_max_create_fk() <= 1);
    assert!(q.sh_is_tip_ready());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Write-behind starts before tip finalize. A lost tail still names the
/// old count, so catch-up appends at or below that watermark skip their
/// flush, and the next recovery treats them as already covered.
#[test]
fn open_lowers_a_lost_tail_before_writebehind_recovery() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-open-tail");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let old = q.store.scripthash.include_hwm();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    assert!(old > 1);
    drop(q);
    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    let covered = q.store.txs.count();
    assert!(covered < old, "reopen kept the pre-cut count {covered}");
    assert_eq!(
        q.store.scripthash.include_hwm(),
        covered,
        "recovery still sees the pre-cut watermark {old}"
    );
    assert!(q.sh_run.sealed_max_create_fk() <= covered);
    let spans = rbitcoin_store::scripthash::sh_recheck_spans(q.store.path()).unwrap();
    assert!(
        spans.iter().any(|(lo, hi)| *lo == covered && *hi >= old),
        "the cut span was not on disk before recovery: {spans:?} old={old}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A missing include file whose SEAL is more than a million creates ahead
/// is the legacy watermark. Copying it into `include_hwm` at open would
/// make catch-up appends skip their flush. Tip finalize still bootstraps it.
#[test]
fn open_leaves_a_far_seal_out_of_the_inclusion_mark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-open-far-seal");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let count = q.store.txs.count();
    let far = count.saturating_add(1_000_001);
    store_seal(&dir.join("scripthash.runs"), far).unwrap();
    std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME)).unwrap();
    drop(q);
    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    assert_eq!(
        q.store.scripthash.include_hwm(),
        0,
        "open copied a far seal into the inclusion mark"
    );
    assert_eq!(q.sh_run.sealed_max_create_fk(), far);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn replace_include_hwm_overwrites_a_higher_mark() {
    let dir = std::env::temp_dir().join(format!("rbtc-hwm-replace-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    rbitcoin_store::scripthash::store_include_hwm(&dir, 9).unwrap();
    rbitcoin_store::scripthash::replace_include_hwm(&dir, 2).unwrap();
    assert_eq!(rbitcoin_store::scripthash::load_include_hwm(&dir), 2);
    rbitcoin_store::scripthash::store_include_hwm(&dir, 1).unwrap();
    assert_eq!(
        rbitcoin_store::scripthash::load_include_hwm(&dir),
        2,
        "the hot path still refuses a decrease"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A shard alloc bump past the file rebuilds from Class A once.
#[test]
fn sh_shard_offset_past_the_file_rebuilds_once() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-shard-off");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    assert!(q.sh_is_tip_ready());
    {
        let body = &q.store.scripthash.bodies[0];
        let mut state = q.store.scripthash.allocs[0].lock().unwrap();
        state.bump = body.logical_len() + 64;
        rbitcoin_store::scripthash::write_alloc_header(body, &state).unwrap();
    }
    assert!(q.store.scripthash.shard_offset_past_file().unwrap());
    q.finalize_sh_runs().unwrap();
    assert!(!q.store.scripthash.shard_offset_past_file().unwrap());
    assert!(!rbitcoin_store::scripthash::sh_rebuild_marked(&dir));
    assert!(q.sh_is_tip_ready());
    let n = q.store.scripthash.entry_count();
    q.finalize_sh_runs().unwrap();
    assert_eq!(q.store.scripthash.entry_count(), n);
    assert!(!q.store.scripthash.shard_offset_past_file().unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn finalize_sh_runs_empty_head_leftover_seal_is_wiped() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-stale");
    q.enter_direct_index_mode().unwrap();
    assert!(!q.store.scripthash.has_durable_index());

    let runs_dir = dir.join("scripthash.runs");
    std::fs::create_dir_all(&runs_dir).unwrap();
    let high_seal = 1_400_000_000u64;
    store_seal(&runs_dir, high_seal).unwrap();
    q.sh_run.refresh_seal();
    std::fs::write(runs_dir.join("000001.run"), b"leftover").unwrap();

    let _ = q.finalize_sh_runs().unwrap();
    assert_eq!(q.sh_run.sealed_max_create_fk(), 0);
    assert_eq!(load_seal(&runs_dir), 0);
    assert_eq!(q.scripthash_run_count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The next Class A commit stores `header_txs` while the previous tip flush
/// can still be excluding stores. That put has to wait the flush out.
#[test]
fn class_a_header_store_waits_out_the_tip_flush() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-flush-wait");
    q.enter_direct_index_mode().unwrap();
    let (h0, ta0) = coinbase_block(0, Fk::NULL, None);
    let prev = q.connect_block(Height(0), &h0, &[ta0]).unwrap();
    let _commit = q.lock_tip_commit().unwrap();
    drop(_commit);
    let hold = q.hold_tip_flushes();
    let (h1, ta1) = coinbase_block(1, prev, Some(h0.hash));
    let prev = q.commit_class_a_only(&h1, &[ta1]).unwrap();
    q.flush_tip(Some(Height(0))).unwrap();
    let (h2, ta2) = coinbase_block(2, prev, Some(h1.hash));
    let h2_fk = thread::scope(|scope| {
        let put = scope.spawn(|| q.commit_class_a_only(&h2, &[ta2]));
        let blocked = q.wait_tip_commit_blocked(Duration::from_secs(2));
        hold.store(false, Ordering::SeqCst);
        let h2_fk = put
            .join()
            .unwrap()
            .expect("header range put waits for the tip flush");
        assert!(
            blocked,
            "the header put must block on the in-flight tip flush"
        );
        h2_fk
    });
    assert!(q.store.header_txs.has_body(h2_fk).unwrap());
    drop(q);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn force_rebuild_recollects_class_a_not_empty_materialize() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-force-recol");
    seed_direct_chain(&q, 6);
    let _ = q.finalize_sh_runs().unwrap();
    assert!(q.store.scripthash.has_durable_index());

    q.set_sh_force_rebuild(true);
    let result = q.finalize_sh_runs();
    let n_mat = result.expect("finalize after FORCE must not fail empty");
    assert!(
        n_mat > 0,
        "materialize must load Class A creates, got {n_mat}"
    );
    assert!(
        q.store.scripthash.has_durable_index(),
        "head must not stay empty after FORCE collect+pack"
    );
    assert!(q.store.scripthash.entry_count() > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unsorted_shards_finalize_skips_catalog_runs() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-unsorted");
    seed_direct_chain(&q, 5);
    let n_mat = q.finalize_sh_runs().expect("unsorted-shards finalize");
    assert!(
        n_mat > 0 || q.store.scripthash.has_durable_index(),
        "unsorted-shards must settle SH"
    );
    assert!(q.store.scripthash.has_durable_index());
    assert_eq!(
        q.scripthash_run_count(),
        0,
        "unsorted-shards must not leave catalog runs"
    );
    assert!(
        !rbitcoin_store::unsorted_shard_dir(q.store.path()).exists()
            || std::fs::read_dir(rbitcoin_store::unsorted_shard_dir(q.store.path()))
                .map(|it| it.count() == 0)
                .unwrap_or(true),
        "unsorted dir must be cleared after seal"
    );
    let sh = rbitcoin_store::script_hash(&[0x51, 0]);
    assert!(
        !q.scripthash_history(&sh).unwrap().is_empty(),
        "Class A creates must be queryable"
    );
    assert!(q.sh_is_tip_ready() || q.store.scripthash.entry_count() > 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn durable_head_hwm_lag_discards_leftover_run() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-hwm-lag-skip");
    seed_direct_chain(&q, 6);
    let n0 = q.finalize_sh_runs().unwrap();
    assert!(n0 > 0 || q.store.scripthash.has_durable_index());
    assert!(q.store.scripthash.has_durable_index());
    let count_before = q.store.scripthash.entry_count();
    let tip_max = q.store.txs.count();
    assert!(tip_max >= 6);

    let lag = tip_max.saturating_sub(3).max(1);
    std::fs::write(
        dir.join(rbitcoin_store::INCLUDE_HWM_NAME),
        lag.to_le_bytes(),
    )
    .unwrap();
    assert!(
        q.store.scripthash.include_hwm() < tip_max,
        "planted HWM lag hwm={} tip_max={tip_max}",
        q.store.scripthash.include_hwm()
    );

    let runs_dir = dir.join("scripthash.runs");
    std::fs::create_dir_all(&runs_dir).unwrap();
    std::fs::write(runs_dir.join("000050.run"), b"leftover").unwrap();
    assert!(q.sh_run.on_disk_run_count() > 0);
    assert!(!q.sh_is_tip_ready(), "strict HWM/run check is still false");
    assert!(
        q.sh_use_writebehind(),
        "durable head must choose write-behind even when HWM lags"
    );

    let n1 = q.finalize_sh_runs().unwrap();
    assert_eq!(n1, 0, "must not collect onto a live head");
    assert_eq!(
        q.store.scripthash.entry_count(),
        count_before,
        "leftover run must not be applied onto the live head"
    );
    assert_eq!(q.scripthash_run_count(), 0, "leftover runs discarded");
    assert!(
        q.store.scripthash.include_hwm() >= tip_max,
        "Direct finalize backfills Class A tail (hwm={} tip_max={tip_max}), not leftover fk=99",
        q.store.scripthash.include_hwm()
    );
    assert!(
        q.store.scripthash.include_hwm() < 99,
        "leftover run fk=99 must not become include_hwm"
    );
    assert!(q.sh_is_tip_ready());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn finalize_sh_appends_unsorted_when_done_lags_before_any_shard() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-done-lag");
    seed_direct_chain(&q, 3);
    let n_shards = q.store.scripthash.head_shard_count();
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
    let done_last = rbitcoin_store::unsorted_done_last_fk(&udir, n_shards).unwrap();
    extend_direct_chain(&q, 2);
    assert!(q.store.txs.count() > done_last);
    assert!(
        !q.store.scripthash.unsealed_main_shards().is_empty(),
        "RAM merge writes head files; pack seal is later"
    );
    let _ = q.finalize_sh_runs().unwrap();
    let sh_old = rbitcoin_store::script_hash(&[0x51, 0]);
    let sh_new = rbitcoin_store::script_hash(&[0x51, 3]);
    assert!(
        !q.scripthash_history(&sh_old).unwrap().is_empty(),
        "creates from the original collect must remain"
    );
    assert!(
        !q.scripthash_history(&sh_new).unwrap().is_empty(),
        "creates after DONE must be in unsorted catch-up before pack"
    );
    assert!(q.sh_is_tip_ready());
    assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn finalize_sh_backfills_class_a_tail_when_shards_already_sealed() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-shard-lag");
    seed_direct_chain(&q, 3);
    let _ = q.finalize_sh_runs().unwrap();
    assert!(q.store.scripthash.has_durable_index());
    assert!(q.sh_is_tip_ready());
    extend_direct_chain(&q, 2);
    assert!(
        !q.sh_is_tip_ready(),
        "new Class A after seal must lag honest include_hwm"
    );
    let _ = q.finalize_sh_runs().unwrap();
    let sh_new = rbitcoin_store::script_hash(&[0x51, 3]);
    assert!(
        !q.scripthash_history(&sh_new).unwrap().is_empty(),
        "Direct finalize must backfill Class A tail onto sealed shards"
    );
    assert!(q.sh_is_tip_ready());
    assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
    let _ = std::fs::remove_dir_all(&dir);
}

/// `submitblock` confirms while the tail backfill has already sampled
/// `txs.count()`. That create has to land in the inclusion watermark or
/// materialize refuses and Esplora never binds.
#[test]
fn backfill_includes_create_that_lands_after_count_sample() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-backfill-race");
    seed_direct_chain(&q, 3);
    let _ = q.finalize_sh_runs().unwrap();
    assert!(q.sh_is_tip_ready());
    extend_direct_chain(&q, 1);
    assert!(!q.sh_is_tip_ready());
    set_sh_backfill_after_sample_for_test(Some(extend_one_during_backfill));
    let result = q.backfill_sh_creates_from_class_a();
    set_sh_backfill_after_sample_for_test(None);
    result.expect("backfill");
    assert!(
        q.sh_is_tip_ready(),
        "a create confirmed after the count sample stays inside include_hwm"
    );
    assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
    let _ = std::fs::remove_dir_all(&dir);
}

fn extend_one_during_backfill(q: &Query) {
    extend_direct_chain(q, 1);
}

/// Direct backfill syncs the new rows and then advances `include_hwm`.
/// The flushed-tail marker has to land first. A later cut otherwise
/// stops the recheck span at the old watermark.
#[test]
fn class_a_backfill_records_the_flushed_tail_before_the_watermark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-backfill-through");
    seed_direct_chain(&q, 3);
    q.finalize_sh_runs().unwrap();
    let _ = std::fs::remove_file(dir.join("scripthash.through"));
    extend_direct_chain(&q, 1);
    let count = q.store.txs.count();
    assert!(q.store.scripthash.include_hwm() < count);
    q.backfill_sh_creates_from_class_a().unwrap();
    let through = rbitcoin_store::scripthash::load_sh_through(q.store.path());
    assert_eq!(through, count);
    assert!(q.store.scripthash.include_hwm() >= count);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The unsorted seal flushes the new head before it publishes the
/// watermark. That flush is the only sync while write-behind is off.
#[test]
fn unsorted_seal_records_the_flushed_tail_before_the_watermark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-seal-through");
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let count = q.store.txs.count();
    let through = rbitcoin_store::scripthash::load_sh_through(q.store.path());
    assert_eq!(through, count);
    assert!(q.store.scripthash.include_hwm() >= count);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two `put_create_batch_append` calls on one scripthash corrupt the chain
/// when they overlap. The Class A tail and `rbtc-sh-wb` both append, so the
/// tail has to wait on `sh.appender`.
#[test]
fn class_a_tail_backfill_waits_on_sh_appender() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-backfill-appender");
    let q = Arc::new(q);
    seed_direct_chain(&q, 3);
    q.finalize_sh_runs().unwrap();
    extend_direct_chain(&q, 1);
    assert!(!q.sh_is_tip_ready());
    let sh_new = rbitcoin_store::script_hash(&[0x51, 3]);
    assert!(
        q.store.scripthash.entries(&sh_new).unwrap().is_empty(),
        "the lagging create is not indexed yet"
    );

    let hold = q.sh.appender.lock().unwrap();
    let q2 = Arc::clone(&q);
    let (tx, rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| {
            q2.backfill_sh_creates_from_class_a().expect("backfill");
        }));
        let _ = tx.send(result);
    });
    let timed = rx.recv_timeout(Duration::from_millis(400));
    drop(hold);
    if timed.is_err() {
        rx.recv_timeout(Duration::from_secs(5))
            .expect("backfill finishes once sh.appender is free")
            .unwrap_or_else(|payload| std::panic::resume_unwind(payload));
    }
    worker.join().unwrap();
    match timed {
        Ok(Ok(())) => panic!("Class A tail backfill appended while sh.appender was held"),
        Ok(Err(payload)) => std::panic::resume_unwind(payload),
        Err(_) => {}
    }
    assert!(
        !q.store.scripthash.entries(&sh_new).unwrap().is_empty(),
        "the lagging create is indexed after the appender is released"
    );
    assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
    assert!(q.sh_is_tip_ready());
    let _ = std::fs::remove_dir_all(&dir);
}

/// The ready sample inside the chase can miss a create that lands before
/// `finalize_sh_unsorted_cancellable` checks again. That create is still
/// behind the watermark, so the chase runs once more.
#[test]
fn finalize_chases_a_create_that_lands_after_the_ready_sample() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-ready-gap");
    seed_direct_chain(&q, 3);
    let _ = q.finalize_sh_runs().unwrap();
    assert!(q.sh_is_tip_ready());
    extend_direct_chain(&q, 1);
    assert!(!q.sh_is_tip_ready());
    set_sh_backfill_on_ready_for_test(Some(extend_one_during_backfill));
    let result = q.finalize_sh_unsorted_cancellable(None);
    set_sh_backfill_on_ready_for_test(None);
    result.expect("a create after the ready sample is chased");
    let sh_late = rbitcoin_store::script_hash(&[0x51, 4]);
    assert!(
        !q.scripthash_history(&sh_late).unwrap().is_empty(),
        "the create that landed after the ready sample is in the index"
    );
    assert!(q.sh_is_tip_ready());
    assert!(q.store.scripthash.include_hwm() >= q.store.txs.count());
    let _ = std::fs::remove_dir_all(&dir);
}
