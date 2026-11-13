use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::catchup::*;
use rbitcoin_query::sh_builder::{load_seal, store_seal};
use rbitcoin_query::testutil::FixtureChain;
use rbitcoin_query::Query;
use rbitcoin_store::StoreError;
use rbitcoin_store::{
    HeaderRecord, InputRecord, OutputRecord, ScriptHashRecord, StoreLayout, TxRecord,
};
use std::cell::Cell;
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
/// had already sealed. A mark that matches the create count is not a lost tail.
#[test]
fn interrupted_rebuild_keeps_the_inclusion_mark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-rebuild-resume");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let hwm = q.store.scripthash.include_hwm();
    assert!(hwm > 0);
    assert_eq!(hwm, q.store.txs.count());
    rbitcoin_store::scripthash::mark_sh_rebuild_resume(q.store.path()).unwrap();
    let mut mark = [0u8; 16];
    mark[..8].copy_from_slice(&1u64.to_le_bytes());
    mark[8..].copy_from_slice(&hwm.to_le_bytes());
    std::fs::write(q.store.path().join("scripthash.recheck"), mark).unwrap();
    q.finalize_sh_runs().unwrap();
    assert_eq!(
        q.store.scripthash.include_hwm(),
        hwm,
        "the resume wiped the inclusion mark"
    );
    let got = std::fs::read(q.store.path().join("scripthash.recheck")).expect("scripthash.recheck");
    assert_eq!(got, mark);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Resume byte `2` keeps sealed shards. It must not keep an inclusion
/// mark above the covered count. Finalize then reports a create gap and
/// never clears the marker, so the next start fails the same way.
#[test]
fn resume_marker_still_lowers_a_lost_tail() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-resume-tail");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let old = q.store.scripthash.include_hwm();
    assert!(old > 1);
    rbitcoin_store::scripthash::mark_sh_rebuild_resume(q.store.path()).unwrap();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    drop(q);
    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    let covered = q.store.txs.count();
    assert!(covered < old, "reopen kept the pre-cut count {covered}");
    assert!(
        rbitcoin_store::scripthash::sh_rebuild_resume(q.store.path()),
        "open cleared a resume that has not finished"
    );
    assert_eq!(
        q.store.scripthash.include_hwm(),
        covered,
        "the resume mark left the pre-cut watermark {old}"
    );
    let spans = rbitcoin_store::scripthash::sh_recheck_spans(q.store.path()).unwrap();
    assert!(
        spans.iter().any(|(lo, hi)| *lo == covered && *hi >= old),
        "the cut span was not on disk: {spans:?} old={old}"
    );
    q.finalize_sh_runs()
        .expect("finalize must not stick on the create gap");
    assert_eq!(q.store.scripthash.include_hwm(), covered);
    assert!(
        !rbitcoin_store::scripthash::sh_rebuild_marked(q.store.path()),
        "a finished finalize left the resume mark"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A resume mark with no include file still has to copy a nearby SEAL
/// and then unlink it. Skipping that copy leaves the seal above the stem
/// and the next finalize never lowers it.
#[test]
fn resume_marker_unlinks_a_nearby_seal_when_the_include_file_is_missing() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-resume-seal");
    q.enter_direct_index_mode().unwrap();
    seed_direct_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    let old = q.store.scripthash.include_hwm();
    assert!(old > 1);
    q.sh_run.refresh_seal();
    assert_eq!(q.sh_run.sealed_max_create_fk(), old);
    std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME)).unwrap();
    rbitcoin_store::scripthash::mark_sh_rebuild_resume(q.store.path()).unwrap();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    drop(q);
    let q = Query::open_or_create_tiny(dir.path()).unwrap();
    let covered = q.store.txs.count();
    assert!(covered < old);
    assert_eq!(
        q.store.scripthash.include_hwm(),
        covered,
        "the resume mark left the nearby seal above the stem"
    );
    assert!(q.sh_run.sealed_max_create_fk() <= covered);
    let _ = std::fs::remove_dir_all(&dir);
}

fn history_txids(q: &Query, sh: &[u8; 32]) -> Vec<[u8; 32]> {
    q.scripthash_history(sh)
        .unwrap()
        .into_iter()
        .map(|row| row.txid)
        .collect()
}

fn plant_done_at(q: &Query, last: u64, word: u64) {
    let n = q.store.scripthash.head_shard_count();
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    std::fs::create_dir_all(&udir).unwrap();
    let counts = vec![word; n];
    rbitcoin_store::scripthash_materialize::write_phase_done(
        &udir,
        rbitcoin_store::scripthash_materialize::KEYS_DONE_NAME,
        rbitcoin_store::scripthash_materialize::KEYS_DONE_MAGIC,
        last,
        &counts,
    )
    .unwrap();
    rbitcoin_store::scripthash_materialize::write_phase_done(
        &udir,
        rbitcoin_store::scripthash_materialize::POST_DONE_NAME,
        rbitcoin_store::scripthash_materialize::POST_DONE_MAGIC,
        last,
        &counts,
    )
    .unwrap();
}

fn index_two_pays(q: &Query) -> ([u8; 32], Vec<[u8; 32]>) {
    let script = vec![0x51, 0xee, 0x11];
    connect_coinbase_paying(q, script.clone());
    connect_coinbase_paying(q, script.clone());
    q.finalize_sh_runs().unwrap();
    let sh = rbitcoin_store::script_hash(&script);
    let txids = history_txids(q, &sh);
    assert_eq!(txids.len(), 2, "the double pay was not indexed");
    (sh, txids)
}

/// A fault marker wipes the body, then `DONE` still names the create count.
/// Skip would mark the old map packed. A script paid twice still points
/// into the body that wipe cut back.
#[test]
fn fault_rebuild_with_done_at_the_count_keeps_both_pays() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-rebuild-done");
    let (sh, before) = index_two_pays(&q);
    plant_done_at(&q, q.store.txs.count(), 0);
    rbitcoin_store::scripthash::mark_sh_rebuild(q.store.path()).unwrap();
    q.finalize_sh_runs().unwrap();
    assert_eq!(
        history_txids(&q, &sh),
        before,
        "the rebuild republished the wiped body"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pack-complete head with no include mark and no SEAL takes the same
/// wipe. `DONE` at the create count must not put the old map back.
#[test]
fn unproven_head_with_done_at_the_count_keeps_both_pays() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-unproven-done");
    let (sh, before) = index_two_pays(&q);
    let count = q.store.txs.count();
    let n_shards = q.store.scripthash.head_shard_count();
    let path = dir.path().to_path_buf();
    plant_done_at(&q, count, 0);
    std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME)).unwrap();
    std::fs::remove_file(q.sh_run.runs_dir.join("SEAL")).unwrap();
    drop(q);
    let q = reopen_layout(&path, n_shards);
    assert_eq!(q.store.scripthash.include_hwm(), 0);
    assert_eq!(q.sh_run.sealed_max_create_fk(), 0);
    assert!(q.store.scripthash.has_durable_index());
    q.finalize_sh_runs().unwrap();
    assert_eq!(
        history_txids(&q, &sh),
        before,
        "the unproven wipe republished the wiped body"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Resume byte `2` is written before `include_hwm` and SEAL. A crash in
/// that window leaves a pack-complete head with floor 0. Deleting it
/// throws away shards the resume mark was supposed to keep.
#[test]
fn resume_keeps_a_pack_complete_head_with_no_inclusion_mark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-resume-floor0");
    let (sh, before) = index_two_pays(&q);
    let n_shards = q.store.scripthash.head_shard_count();
    let path = dir.path().to_path_buf();
    let base = rbitcoin_store::scripthash::sorted_main_shard_path(&path, 0, n_shards);
    let mphf = rbitcoin_store::scripthash_mphf::mphf_path(&base);
    let mphf_before = std::fs::read(&mphf).unwrap();
    std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME)).unwrap();
    std::fs::remove_file(q.sh_run.runs_dir.join("SEAL")).unwrap();
    rbitcoin_store::scripthash::mark_sh_rebuild_resume(&path).unwrap();
    drop(q);
    let q = reopen_layout(&path, n_shards);
    assert_eq!(q.store.scripthash.include_hwm(), 0);
    assert_eq!(q.sh_run.sealed_max_create_fk(), 0);
    assert!(q.store.scripthash.has_durable_index());
    let mut mark = [0u8; 16];
    mark[..8].copy_from_slice(&1u64.to_le_bytes());
    mark[8..].copy_from_slice(&4u64.to_le_bytes());
    std::fs::write(q.store.path().join("scripthash.recheck"), mark).unwrap();
    q.finalize_sh_runs()
        .expect("a resume head must not fail the create gap");
    let got = std::fs::read(q.store.path().join("scripthash.recheck")).unwrap_or_default();
    assert_eq!(got, mark, "the resume wiped the sealed head");
    assert_eq!(
        std::fs::read(&mphf).unwrap_or_default(),
        mphf_before,
        "the resume replaced the packed extract"
    );
    assert_eq!(history_txids(&q, &sh), before);
    assert!(
        q.store.scripthash.include_hwm() > 0,
        "the tail backfill did not publish the inclusion mark"
    );
    assert!(
        !rbitcoin_store::scripthash::sh_rebuild_marked(q.store.path()),
        "a finished finalize left the resume mark"
    );
    assert!(q.sh_is_tip_ready());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A resume head is pack-complete and has no inclusion mark yet. Startup
/// must not enter Tip. The next block would publish the watermark over
/// creates the pack never scanned. Finalize backfills first.
#[test]
fn resume_head_stays_direct_until_the_tail_is_backfilled() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-resume-direct");
    let script = vec![0x51, 0xee, 0x11];
    let (sh, before) = index_two_pays(&q);
    std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME)).unwrap();
    std::fs::remove_file(q.sh_run.runs_dir.join("SEAL")).unwrap();
    rbitcoin_store::scripthash::mark_sh_rebuild_resume(q.store.path()).unwrap();
    assert!(
        !q.sh_use_writebehind(),
        "a resume head started write-behind before the tail backfill"
    );
    connect_coinbase_paying(&q, script);
    q.finalize_sh_runs().unwrap();
    let txids = history_txids(&q, &sh);
    assert_eq!(
        txids.len(),
        before.len() + 1,
        "the tail pay was not indexed"
    );
    assert!(txids.starts_with(&before));
    assert!(
        !rbitcoin_store::scripthash::sh_rebuild_marked(q.store.path()),
        "a finished finalize left the resume mark"
    );
    assert!(q.sh_use_writebehind());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Open sees a shard bump past the file. The wipe byte has to be on disk
/// before startup can enter Tip, or the appender dies on the torn body
/// and the next start does the same.
#[test]
fn shard_bump_writes_the_wipe_byte_before_tip() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-bump-mark");
    q.enter_direct_index_mode().unwrap();
    seed_reopenable_chain(&q, 2);
    q.finalize_sh_runs().unwrap();
    assert!(q.store.scripthash.include_hwm() > 0);
    {
        let body = &q.store.scripthash.bodies[0];
        let mut state = q.store.scripthash.allocs[0].lock().unwrap();
        state.bump = body.logical_len() + 64;
        rbitcoin_store::scripthash::write_alloc_header(body, &state).unwrap();
    }
    let n_shards = q.store.scripthash.head_shard_count();
    let path = dir.path().to_path_buf();
    drop(q);
    let q = reopen_layout(&path, n_shards);
    let marker = std::fs::read(path.join("scripthash.rebuild")).unwrap_or_default();
    assert_eq!(
        marker, b"1",
        "a shard bump past the file did not write the wipe byte"
    );
    assert!(q.store.scripthash.has_durable_index());
    q.discard_unproven_scripthash_head().unwrap();
    assert!(
        !q.store.scripthash.has_durable_index(),
        "startup left the torn head in place"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A wipe request can sit next to a restored pack mark and inclusion
/// watermark. Leaving that head lets startup serve it. The wipe has to
/// finish, and the resume byte has to replace the wipe byte so the next
/// finalize does not delete the shards it is about to pack.
#[test]
fn wipe_marker_deletes_a_head_that_still_has_an_inclusion_mark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-wipe-with-hwm");
    let (sh, before) = index_two_pays(&q);
    rbitcoin_store::scripthash::mark_sh_rebuild(q.store.path()).unwrap();
    let mut mark = [0u8; 16];
    mark[..8].copy_from_slice(&1u64.to_le_bytes());
    mark[8..].copy_from_slice(&4u64.to_le_bytes());
    std::fs::write(q.store.path().join("scripthash.recheck"), mark).unwrap();
    assert!(q.store.scripthash.include_hwm() > 0);
    assert!(q.store.scripthash.has_durable_index());
    q.discard_unproven_scripthash_head().unwrap();
    assert_eq!(
        q.store.scripthash.entry_count(),
        0,
        "the wipe marker left the head"
    );
    assert!(
        !q.store.scripthash.has_durable_index(),
        "the wipe marker left the pack marks"
    );
    assert!(
        !q.store.path().join("scripthash.recheck").exists(),
        "the wipe marker left the recheck span"
    );
    assert!(
        rbitcoin_store::scripthash::sh_rebuild_resume(q.store.path()),
        "a finished wipe left the wipe byte, so the next finalize deletes the new packs"
    );
    q.finalize_sh_runs().unwrap();
    assert_eq!(history_txids(&q, &sh), before);
    assert!(
        !rbitcoin_store::scripthash::sh_rebuild_marked(q.store.path()),
        "a finished finalize left the rebuild mark"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The body reset can stick while the map and `DONE` stay, and no wipe
/// byte was written. Skip then marks that map packed over the empty body.
#[test]
fn empty_body_with_done_at_the_count_keeps_both_pays() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-empty-body-done");
    let (sh, before) = index_two_pays(&q);
    let count = q.store.txs.count();
    let n_shards = q.store.scripthash.head_shard_count();
    let path = dir.path().to_path_buf();
    plant_done_at(&q, count, 0);
    q.store
        .scripthash
        .reinit_empty_for_cold_materialize()
        .unwrap();
    q.store.scripthash.flush().unwrap();
    std::fs::remove_file(dir.join(rbitcoin_store::INCLUDE_HWM_NAME)).unwrap();
    std::fs::remove_file(q.sh_run.runs_dir.join("SEAL")).unwrap();
    assert!(!rbitcoin_store::scripthash::sh_rebuild_marked(&path));
    drop(q);
    let q = reopen_layout(&path, n_shards);
    assert_eq!(q.store.scripthash.entry_count(), 0);
    assert!(!q.store.scripthash.has_durable_index());
    q.finalize_sh_runs()
        .expect("an empty body must be collected again");
    assert_eq!(
        history_txids(&q, &sh),
        before,
        "DONE at the count published the leftover map onto the empty body"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// `DONE` names the live count and the unsealed shard has no map. Skip
/// would pack that shard empty, so the create is missing from history.
#[test]
fn done_at_the_count_without_a_map_indexes_the_pay() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-done-no-map");
    let script = vec![0x51, 0xee, 0x22];
    connect_coinbase_paying(&q, script.clone());
    let sh = rbitcoin_store::script_hash(&script);
    let n = q.store.scripthash.head_shard_count();
    plant_done_at(&q, q.store.txs.count(), 7);
    let base = rbitcoin_store::scripthash::sorted_main_shard_path(q.store.path(), 0, n);
    assert!(
        !rbitcoin_store::scripthash_mphf::MphfHead::exists(&base),
        "the fixture already had a map"
    );
    q.finalize_sh_runs().unwrap();
    assert_eq!(
        q.scripthash_history(&sh).unwrap().len(),
        1,
        "DONE at the count packed an empty shard"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Dropping a `DONE` last above the count has to sync that directory.
/// A crash can otherwise restore the marker after the map removal stuck.
#[test]
fn open_syncs_the_unsorted_dir_when_done_is_above_the_count() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-done-fsync");
    seed_reopenable_chain(&q, 2);
    let n_shards = q.store.scripthash.head_shard_count();
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
    let old = rbitcoin_store::unsorted_done_last_fk(&udir, n_shards).unwrap();
    cut_creates_to(&q, 1);
    assert!(old > q.store.txs.count());
    let path = dir.path().to_path_buf();
    drop(q);
    rbitcoin_store::file::arm_fsync_dir_trace();
    let q = reopen_layout(&path, n_shards);
    let synced = rbitcoin_store::file::take_fsynced_dirs();
    assert!(
        !udir.join("DONE.keys").is_file(),
        "DONE.keys survived the cut open"
    );
    assert!(
        synced.iter().any(|p| p == &udir),
        "open dropped DONE without syncing {}: {synced:?}",
        udir.display()
    );
    drop(q);
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

/// A crash can pack one shard, then the next open can cut Class A under
/// the `DONE` last. That last must not become `include_hwm`, and the
/// spills past the cut must not stay in the index.
#[test]
fn unsorted_done_above_the_count_does_not_publish_that_watermark() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-done-above");
    seed_direct_chain(&q, 3);
    let n_shards = q.store.scripthash.head_shard_count();
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
    let old = rbitcoin_store::unsorted_done_last_fk(&udir, n_shards).unwrap();
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(1, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(1).unwrap();
    let covered = q.store.txs.count();
    assert_eq!(covered, 1);
    assert!(
        old > covered,
        "planted DONE last {old} is not above the cut"
    );
    rbitcoin_store::scripthash_materialize::set_before_unsorted_pack_for_test(Some(
        snap_through_before_unsorted_pack,
    ));
    let result = q.finalize_sh_runs();
    rbitcoin_store::scripthash_materialize::set_before_unsorted_pack_for_test(None);
    result.unwrap();
    let seen = THROUGH_BEFORE_PACK.with(|c| c.get());
    assert!(
        seen >= old,
        "through was {seen} before the first pack, DONE last was {old}"
    );
    assert_eq!(
        q.store.scripthash.include_hwm(),
        covered,
        "DONE last {old} was published as include_hwm"
    );
    let dropped = rbitcoin_store::script_hash(&[0x51, 1]);
    let kept = rbitcoin_store::script_hash(&[0x51, 0]);
    let stale = q.store.scripthash.entries(&dropped).unwrap();
    assert!(
        stale.iter().all(|(fk, _)| fk.0 <= covered),
        "a create past the cut stayed in the index: {stale:?}"
    );
    assert!(
        !q.store.scripthash.entries(&kept).unwrap().is_empty(),
        "the covered create was not indexed"
    );
    let spans = rbitcoin_store::scripthash::sh_recheck_spans(q.store.path()).unwrap();
    assert!(
        spans.iter().any(|(lo, hi)| *lo == covered && *hi >= old),
        "the cut span was not on disk: {spans:?} old={old}"
    );
    assert!(q.sh_is_tip_ready());
    let _ = std::fs::remove_dir_all(&dir);
}

fn script_on_shard(n_shards: usize, shard: usize, tag: u8) -> Vec<u8> {
    for b in 0u16..=255 {
        let script = vec![0x51, tag, b as u8];
        let sh = rbitcoin_store::script_hash(&script);
        if rbitcoin_store::scripthash_head::prefix_shard_of(&sh, n_shards) == shard {
            return script;
        }
    }
    panic!("no script lands on shard {shard}");
}

fn header_for_coinbase(
    h: u32,
    prev: Fk,
    parent_hash: [u8; 32],
    txid: &[u8; 32],
) -> (HeaderRecord, rbitcoin_query::TxApply) {
    let (mut header, mut ta) = coinbase_block(h, prev, Some(parent_hash));
    ta.tx.txid = *txid;
    header.merkle_root = rbitcoin_primitives::merkle_root_from_txids(&[*txid]);
    header.hash = rbitcoin_store::block_header_hash(
        header.version,
        &parent_hash,
        &header.merkle_root,
        header.timestamp,
        header.bits,
        header.nonce,
    );
    (header, ta)
}

/// Height 0 stores `block_header_hash` and the coinbase merkle, so a later
/// open keeps that block.
fn seed_reopenable_chain(q: &Query, n: u32) {
    q.enter_direct_index_mode().unwrap();
    let mut prev = Fk::NULL;
    let mut parent_hash = [0u8; 32];
    for h in 0..n {
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&h.to_le_bytes());
        txid[31] = 0xcb;
        let (header, ta) = header_for_coinbase(h, prev, parent_hash, &txid);
        parent_hash = header.hash;
        prev = q.connect_block(Height(h), &header, &[ta]).unwrap();
    }
    assert_eq!(q.tip_height(), Some(Height(n - 1)));
    assert!(q.store.txs.count() >= u64::from(n));
}

fn connect_coinbase_paying(q: &Query, script: Vec<u8>) {
    q.enter_direct_index_mode().unwrap();
    let h = q
        .tip_height()
        .map(|tip| tip.0.saturating_add(1))
        .unwrap_or(0);
    let prev = if h == 0 {
        Fk::NULL
    } else {
        q.store.confirmed.get(Height(h - 1)).unwrap().unwrap()
    };
    let parent_hash = if h == 0 {
        [0u8; 32]
    } else {
        q.get_header(prev).unwrap().hash
    };
    let mut txid = [0u8; 32];
    txid[0..4].copy_from_slice(&h.to_le_bytes());
    txid[30] = h as u8;
    txid[31] = 0xcb;
    let (header, mut ta) = header_for_coinbase(h, prev, parent_hash, &txid);
    ta.outputs = vec![OutputRecord::unspent(50_0000_0000, script)];
    q.connect_block(Height(h), &header, &[ta]).unwrap();
}

fn cut_creates_to(q: &Query, keep: u64) {
    let end = q.store.txs.body.body_logical_len();
    q.store.txs.body.truncate_body_to(keep, end).unwrap();
    q.store.txs.create_loc.truncate_to_count(keep).unwrap();
    assert_eq!(q.store.txs.count(), keep);
}

fn reopen_layout(dir: &std::path::Path, shards: usize) -> Query {
    let layout = StoreLayout::tiny(dir).with_sh_shards(shards);
    Query::open_or_create_layout(layout).unwrap()
}

/// Direct mode collects scripthash after IBD. A `DONE` last above the cut
/// has to be recorded while the count is still short, or a chain that grows
/// back to that last packs the pre-cut spills and skips the new creates.
#[test]
fn open_drops_done_above_the_cut_before_the_chain_grows() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-done-regrow");
    seed_reopenable_chain(&q, 3);
    let n_shards = q.store.scripthash.head_shard_count();
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
    let old = rbitcoin_store::unsorted_done_last_fk(&udir, n_shards).unwrap();
    cut_creates_to(&q, 1);
    let path = dir.path().to_path_buf();
    drop(q);
    let q = reopen_layout(&path, n_shards);
    let covered = q.store.txs.count();
    assert!(covered < old, "reopen left count {covered}, DONE was {old}");
    let through = rbitcoin_store::scripthash::load_sh_through(q.store.path());
    assert!(
        through >= old,
        "open left through {through}, DONE last was {old}"
    );
    assert!(
        !udir.join("DONE.keys").is_file(),
        "DONE.keys still names the pre-cut scan"
    );
    assert!(
        !udir.join("DONE.post").is_file(),
        "DONE.post still names the pre-cut scan"
    );
    let fresh = vec![0x52, 1];
    while q.store.txs.count() < old {
        connect_coinbase_paying(&q, fresh.clone());
    }
    q.finalize_sh_runs().unwrap();
    assert!(
        !q.scripthash_history(&rbitcoin_store::script_hash(&fresh))
            .unwrap()
            .is_empty(),
        "creates that replaced the cut were not indexed"
    );
    let stale = rbitcoin_store::script_hash(&[0x51, 1]);
    assert!(
        q.scripthash_history(&stale).unwrap().is_empty(),
        "the pre-cut script is still history"
    );
    assert!(q.sh_is_tip_ready());
    let _ = std::fs::remove_dir_all(&dir);
}

/// Packing one shard, then cutting under `DONE`, must not replace that
/// shard's extract. Finalize while the count is still short: that is the
/// collect that walks every shard.
#[test]
fn packed_shard_keeps_its_extract_across_a_done_cut() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("q-sh-packed-cut").unwrap();
    let layout = StoreLayout::tiny(dir.path()).with_sh_shards(2);
    let q = Query::open_or_create_layout(layout).unwrap();
    seed_reopenable_chain(&q, 3);
    let n_shards = q.store.scripthash.head_shard_count();
    assert_eq!(n_shards, 2);
    let kept = rbitcoin_store::script_hash(&[0x51, 0]);
    let shard = rbitcoin_store::scripthash_head::prefix_shard_of(&kept, n_shards);
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
    let old = rbitcoin_store::unsorted_done_last_fk(&udir, n_shards).unwrap();
    rbitcoin_store::scripthash_materialize::pack_one_extract_shard(
        &q.store.scripthash,
        &udir,
        shard,
    )
    .unwrap();
    let unsealed = q.store.scripthash.unsealed_main_shards();
    assert!(
        !unsealed.contains(&shard),
        "packed shard {shard} is still unsealed: {unsealed:?}"
    );
    assert!(
        unsealed.iter().any(|s| *s != shard),
        "the other shard was packed too"
    );
    let base = rbitcoin_store::scripthash::sorted_main_shard_path(q.store.path(), shard, n_shards);
    let mphf = rbitcoin_store::scripthash_mphf::mphf_path(&base);
    let before = std::fs::read(&mphf).unwrap();
    cut_creates_to(&q, 1);
    assert!(old > q.store.txs.count());
    q.finalize_sh_runs().unwrap();
    let after = std::fs::read(&mphf).unwrap();
    assert_eq!(before, after, "finalize replaced the packed shard extract");
    assert!(
        !q.scripthash_history(&kept).unwrap().is_empty(),
        "the create that stayed on the packed shard disappeared"
    );
    assert_eq!(
        q.store.scripthash.include_hwm(),
        1,
        "DONE last {old} was published as include_hwm"
    );
    let stale = rbitcoin_store::script_hash(&[0x51, 1]);
    assert!(
        q.scripthash_history(&stale).unwrap().is_empty(),
        "the pre-cut script is still history"
    );
    assert!(q.sh_is_tip_ready());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A packed shard already has its map. Key and post spills for that shard
/// are deleted after the scan, and they grow with the rest of the chain.
#[test]
fn collect_does_not_spill_a_packed_shard() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("q-sh-sealed-spill").unwrap();
    let layout = StoreLayout::tiny(dir.path()).with_sh_shards(2);
    let q = Query::open_or_create_layout(layout).unwrap();
    let n_shards = 2;
    let packed_script = script_on_shard(n_shards, 0, 0x41);
    let open_script = script_on_shard(n_shards, 1, 0x42);
    connect_coinbase_paying(&q, packed_script.clone());
    connect_coinbase_paying(&q, packed_script);
    connect_coinbase_paying(&q, open_script.clone());
    connect_coinbase_paying(&q, open_script);
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
    rbitcoin_store::scripthash_materialize::pack_one_extract_shard(&q.store.scripthash, &udir, 0)
        .unwrap();
    let unsealed = q.store.scripthash.unsealed_main_shards();
    assert!(
        !unsealed.contains(&0),
        "shard 0 is still unsealed: {unsealed:?}"
    );
    assert!(
        unsealed.contains(&1),
        "shard 1 was packed too: {unsealed:?}"
    );
    let _ = std::fs::remove_dir_all(udir.join("keys"));
    let _ = std::fs::remove_dir_all(udir.join("post"));
    let last = q.store.txs.count();
    thread_local! {
        static KEY_SPILL: Cell<(bool, bool)> = const { Cell::new((false, false)) };
    }
    fn snap_key_spills(dir: &std::path::Path) {
        KEY_SPILL.with(|c| {
            c.set((
                rbitcoin_store::scripthash_materialize::unsorted_keys_path(dir, 0).exists(),
                rbitcoin_store::scripthash_materialize::unsorted_keys_path(dir, 1).exists(),
            ));
        });
    }
    rbitcoin_store::scripthash_materialize::set_before_keys_merge_for_test(Some(snap_key_spills));
    rbitcoin_store::scripthash_materialize::collect_keys_from_txs(
        &q.store.txs,
        &q.store.scripthash,
        &udir,
        1,
        last,
        1,
        None,
    )
    .unwrap();
    let (sealed_keys, open_keys) = KEY_SPILL.with(|c| c.get());
    assert!(!sealed_keys, "the packed shard got key spills");
    assert!(open_keys, "the unsealed shard collected no keys");
    rbitcoin_store::scripthash_materialize::collect_posts_from_txs(
        &q.store.txs,
        &q.store.scripthash,
        &udir,
        1,
        last,
        1,
        None,
    )
    .unwrap();
    let sealed_posts = rbitcoin_store::scripthash_materialize::unsorted_post_path(&udir, 0);
    let open_posts = rbitcoin_store::scripthash_materialize::unsorted_post_path(&udir, 1);
    assert!(
        !sealed_posts.exists(),
        "the packed shard got post spills at {}",
        sealed_posts.display()
    );
    assert!(
        open_posts.exists(),
        "the unsealed shard collected no posts at {}",
        open_posts.display()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Keys collect, pass-1 maps on both shards, and a pack mark on shard 0.
/// `DONE` still names the scanned count. The other shard has no pack mark.
fn pass1_with_one_pack_mark(label: &str) -> (rbitcoin_store::testutil::TempDir, u64) {
    let dir = rbitcoin_store::testutil::TempDir::labeled(label).unwrap();
    let layout = StoreLayout::tiny(dir.path()).with_sh_shards(2);
    let q = Query::open_or_create_layout(layout).unwrap();
    seed_reopenable_chain(&q, 3);
    let n_shards = q.store.scripthash.head_shard_count();
    assert_eq!(n_shards, 2);
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
    let old = rbitcoin_store::unsorted_done_last_fk(&udir, n_shards).unwrap();
    rbitcoin_store::scripthash_materialize::seal_mphf_from_keys(
        &q.store.scripthash,
        &udir,
        n_shards,
        None,
    )
    .unwrap();
    let packed = rbitcoin_store::scripthash::sorted_main_shard_path(q.store.path(), 0, n_shards);
    rbitcoin_store::scripthash::write_shard_pack_mark(&packed).unwrap();
    let pass1 = rbitcoin_store::scripthash::sorted_main_shard_path(q.store.path(), 1, n_shards);
    assert!(
        rbitcoin_store::scripthash_mphf::MphfHead::exists(&pass1),
        "pass-1 map was not sealed"
    );
    assert!(
        !rbitcoin_store::scripthash::shard_pack_mark_path(&pass1).is_file(),
        "the pass-1 shard was already packed"
    );
    drop(q);
    (dir, old)
}

fn assert_pass1_shard_stays_unpacked(dir: &std::path::Path) {
    let q = reopen_layout(dir, 2);
    let pass1 = rbitcoin_store::scripthash::sorted_main_shard_path(q.store.path(), 1, 2);
    assert!(
        !rbitcoin_store::scripthash::shard_pack_mark_path(&pass1).is_file(),
        "open wrote a pack mark on the pass-1 shard"
    );
    assert_eq!(
        q.store.scripthash.include_hwm(),
        0,
        "open published the pass-1 create count"
    );
    assert!(
        !q.store.scripthash.has_durable_index(),
        "the pass-1 head was treated as finished"
    );
    let packed = rbitcoin_store::scripthash::sorted_main_shard_path(q.store.path(), 0, 2);
    assert!(
        rbitcoin_store::scripthash::shard_pack_mark_path(&packed).is_file(),
        "the packed shard lost its mark"
    );
}

/// Open drops `DONE` while a pass-1 map is still on disk. Once the key and
/// post directories are gone too, the next open must not pack that map.
#[test]
fn reopen_after_done_drop_does_not_pack_a_pass1_shard() {
    let (dir, old) = pass1_with_one_pack_mark("q-sh-pass1-done-drop");
    let layout = StoreLayout::tiny(dir.path()).with_sh_shards(2);
    let q = Query::open_or_create_layout(layout).unwrap();
    cut_creates_to(&q, 1);
    assert!(old > q.store.txs.count());
    let path = dir.path().to_path_buf();
    drop(q);
    let q = reopen_layout(&path, 2);
    let udir = rbitcoin_store::unsorted_shard_dir(&path);
    assert!(
        !udir.join("DONE.keys").is_file(),
        "DONE.keys survived the cut open"
    );
    drop(q);
    let _ = std::fs::remove_dir_all(udir.join("keys"));
    let _ = std::fs::remove_dir_all(udir.join("post"));
    assert_pass1_shard_stays_unpacked(&path);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A full collect deletes the unsorted directory before the new keys exist.
/// A crash in that gap must not pack the pass-1 shard on the next open.
#[test]
fn clear_unsorted_does_not_pack_a_pass1_shard() {
    let (dir, _old) = pass1_with_one_pack_mark("q-sh-pass1-clear");
    let path = dir.path().to_path_buf();
    rbitcoin_store::clear_unsorted_shard_dir(&rbitcoin_store::unsorted_shard_dir(&path)).unwrap();
    assert_pass1_shard_stays_unpacked(&path);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The chain can reach the old `DONE` last before the first finalize.
/// The packed shard keeps its extract. The new creates on that shard
/// arrive from the tail backfill, and the inclusion mark stays at the
/// cut until that append finishes.
#[test]
fn open_regrowth_appends_onto_a_packed_shard() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("q-sh-packed-regrow").unwrap();
    let layout = StoreLayout::tiny(dir.path()).with_sh_shards(2);
    let q = Query::open_or_create_layout(layout).unwrap();
    seed_reopenable_chain(&q, 3);
    let n_shards = q.store.scripthash.head_shard_count();
    let kept = rbitcoin_store::script_hash(&[0x51, 0]);
    let shard = rbitcoin_store::scripthash_head::prefix_shard_of(&kept, n_shards);
    let udir = rbitcoin_store::unsorted_shard_dir(q.store.path());
    rbitcoin_store::collect_unsorted_shard_files(&q.store, &udir, n_shards, 1, None).unwrap();
    let old = rbitcoin_store::unsorted_done_last_fk(&udir, n_shards).unwrap();
    rbitcoin_store::scripthash_materialize::pack_one_extract_shard(
        &q.store.scripthash,
        &udir,
        shard,
    )
    .unwrap();
    let base = rbitcoin_store::scripthash::sorted_main_shard_path(q.store.path(), shard, n_shards);
    let mphf = rbitcoin_store::scripthash_mphf::mphf_path(&base);
    let before = std::fs::read(&mphf).unwrap();
    cut_creates_to(&q, 1);
    let path = dir.path().to_path_buf();
    drop(q);
    let q = reopen_layout(&path, n_shards);
    let through = rbitcoin_store::scripthash::load_sh_through(q.store.path());
    assert!(
        through >= old,
        "open left through {through}, DONE last was {old}"
    );
    assert!(!udir.join("DONE.keys").is_file(), "DONE.keys survived open");
    let fresh = script_on_shard(n_shards, shard, 0x7a);
    while q.store.txs.count() < old {
        connect_coinbase_paying(&q, fresh.clone());
    }
    q.finalize_sh_runs().unwrap();
    let after = std::fs::read(&mphf).unwrap();
    assert_eq!(before, after, "finalize replaced the packed shard extract");
    assert!(
        !q.scripthash_history(&kept).unwrap().is_empty(),
        "the create that stayed on the packed shard disappeared"
    );
    assert!(
        !q.scripthash_history(&rbitcoin_store::script_hash(&fresh))
            .unwrap()
            .is_empty(),
        "a new create on the packed shard was not indexed"
    );
    let stale = rbitcoin_store::script_hash(&[0x51, 1]);
    assert!(
        q.scripthash_history(&stale).unwrap().is_empty(),
        "the pre-cut script is still history"
    );
    assert!(q.sh_is_tip_ready());
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

thread_local! {
    static BACKFILL_THROUGH_AT_SAMPLE: Cell<u64> = const { Cell::new(u64::MAX) };
}

fn snap_through_at_sample(q: &Query) {
    let through = rbitcoin_store::scripthash::load_sh_through(q.store.path());
    BACKFILL_THROUGH_AT_SAMPLE.with(|c| c.set(through));
}

thread_local! {
    static THROUGH_BEFORE_PACK: Cell<u64> = const { Cell::new(0) };
}

fn snap_through_before_unsorted_pack(through: u64) {
    THROUGH_BEFORE_PACK.with(|c| c.set(through));
}

/// A wave can seal the ingest head before the flush. The through marker
/// has to name that count before the first append, or a crash plus a cut
/// leaves the synced fk out of `scripthash.recheck`.
#[test]
fn class_a_backfill_names_the_tail_before_the_append() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-backfill-before");
    seed_direct_chain(&q, 3);
    q.finalize_sh_runs().unwrap();
    let _ = std::fs::remove_file(dir.join("scripthash.through"));
    extend_direct_chain(&q, 1);
    let count = q.store.txs.count();
    assert!(q.store.scripthash.include_hwm() < count);
    set_sh_backfill_after_sample_for_test(Some(snap_through_at_sample));
    q.backfill_sh_creates_from_class_a().unwrap();
    set_sh_backfill_after_sample_for_test(None);
    let seen = BACKFILL_THROUGH_AT_SAMPLE.with(|c| c.get());
    assert_eq!(
        seen, count,
        "the marker was still {seen} when the append began"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Write-behind can seal inside the append, then wait a second before
/// `advance_sh_include_hwm`. The marker still has to be on disk.
#[test]
fn writebehind_names_the_tail_before_a_throttled_advance() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("q-sh-wb-before");
    seed_direct_chain(&q, 2);
    q.enter_tip_index_mode();
    let height = Height(1);
    let header_fk = q.store.confirmed.get(height).unwrap().unwrap();
    let tx_fks = q.store.header_txs.get_list(header_fk).unwrap().unwrap();
    let mut records = Vec::new();
    for fk in tx_fks {
        q.collect_scripthash_creates(fk, &mut records, None)
            .unwrap();
    }
    assert!(!records.is_empty());
    q.sh.pending
        .lock()
        .unwrap()
        .push_back(rbitcoin_query::connect::ShPendingJob {
            height: Height(50),
            header_fk: Fk::NULL,
            records: Vec::new(),
        });
    let _ = std::fs::remove_file(dir.join("scripthash.through"));
    let applied = q
        .apply_sh_job_inner(&rbitcoin_query::connect::ShPendingJob {
            height,
            header_fk,
            records,
        })
        .unwrap();
    assert!(applied, "the job did not append");
    let through = rbitcoin_store::scripthash::load_sh_through(q.store.path());
    assert_eq!(through, q.store.txs.count());
    assert_eq!(
        q.store.scripthash.include_hwm(),
        0,
        "the throttled advance published the watermark"
    );
    let _ = std::fs::remove_dir_all(&dir);
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
