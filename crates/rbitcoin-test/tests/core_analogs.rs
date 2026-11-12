//! Core functional analogs (inventory `analog=`).
//!
//! Unmodified Core scripts that touch LevelDB / `blocks/` / assumevalid logs
//! cannot `run`. These scenarios keep the behavior we still want:
//!
//! 1. `--milestone` skip-below / check-above + mempool persist + leftover
//!    pool through catch-up then tip-mode purge, torn sidecar open, then
//!    missing prevout still fails when scripts are skipped
//!    (`feature_assumevalid.py`, `mempool_persist.py`)
//! 2. Reconstruct height 1 after wiping `tx.head/` (`feature_reindex*.py`)
//! 3. BIP158 basic filters built from Class A match the reference builder,
//!    including below a seqsigwit prune (`rpc_getblockfilter.py`,
//!    `feature_blockfilterindex_prune.py`)

use bitcoin::hashes::Hash;
use bitcoin::{
    Amount, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use rbitcoin_consensus::{grind_regtest_pow, ChainParams, ConsensusError, Milestone};
use rbitcoin_net::mempool_events::RemovalReason;
use rbitcoin_net::MempoolHub;
use rbitcoin_primitives::Height;
use rbitcoin_query::accept_and_connect_block;
use rbitcoin_query::{ConfirmError, Query};
use rbitcoin_test::mine::{mine_regtest_block, regtest_genesis, spend_anyone_can_spend};
use rbitcoin_test::{
    assert_reconstruct_eq, open_mature_regtest_with_spend, pad_empty_from, MatureRegtestChain,
    TestDatadir,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn query_tip_hash(q: &Query) -> BlockHash {
    let h = q.tip_height().unwrap();
    let (_, rec) = q.header_at_height(h).unwrap().unwrap();
    BlockHash::from_byte_array(rec.hash)
}

#[test]
fn shared_mature_regtest_copy_keeps_the_other_tip() {
    let params = ChainParams::regtest();
    let a = TestDatadir::new().unwrap();
    let b = TestDatadir::new().unwrap();
    let (qa, ca) = open_mature_regtest_with_spend(a.store_path(), &params);
    let (qb, cb) = open_mature_regtest_with_spend(b.store_path(), &params);
    assert_eq!(qa.tip_height(), qb.tip_height());
    assert_eq!(ca.tip_hash(), cb.tip_hash());
    assert_eq!(query_tip_hash(&qa), ca.tip_hash());
    assert_eq!(ca.matured_coinbase_txid, cb.matured_coinbase_txid);
    assert!(ca.tip_height() > params.coinbase_maturity());
    let next = ca.tip_height() + 1;
    let block = mine_regtest_block(
        ca.tip_hash(),
        ca.blocks.last().unwrap().header.time + 600,
        next,
        vec![],
    );
    accept_and_connect_block(&qa, &params, Height(next), &block, Milestone::NONE).unwrap();
    assert_eq!(query_tip_hash(&qb), cb.tip_hash());
    assert_ne!(query_tip_hash(&qa), query_tip_hash(&qb));
}

/// One mature pad: mempool persist, restart leftover through catch-up then
/// tip-mode purge, then `--milestone` skip-below / check-above, then missing
/// prevout still fails under a high milestone (scripts skipped).
///
/// Core `feature_assumevalid.py` + `mempool_persist.py`.
#[test]
fn analog_milestone_and_mempool_persist() {
    let params = ChainParams::regtest();
    let td = TestDatadir::new().unwrap();
    let (q, chain) = open_mature_regtest_with_spend(td.store_path(), &params);

    let spend_block = &chain.blocks[chain.spend_height as usize];
    let spend_txid = spend_block.txdata[1].compute_txid();
    let unconf = spend_anyone_can_spend(spend_txid, 0, Amount::from_sat(48_0000_0000));
    let want = unconf.compute_txid();

    let mp_dir = td.path().join("mempool");
    let q_arc = Arc::new(q);
    let fee_sat = {
        let hub = MempoolHub::open_with_weight(&mp_dir, Arc::clone(&q_arc), 50_000_000).unwrap();
        hub.set_relay_enabled(true);
        let r = hub
            .accept_tx(&unconf)
            .expect("accept unconfirmed spend of confirmed anyone-can-spend");
        assert_eq!(r.txid, want);
        hub.flush().expect("SIGTERM-equivalent flush");
        assert!(hub.contains(&want));
        r.fee_sat
    };
    let hub2 = MempoolHub::open_with_weight(&mp_dir, Arc::clone(&q_arc), 50_000_000).unwrap();
    assert!(
        hub2.contains(&want),
        "flushed mempool must still hold the tx after reopen"
    );
    assert_eq!(hub2.live_count(), 1);
    assert_eq!(hub2.get_live_meta(&want).map(|m| m.0), Some(fee_sat));
    drop(hub2);
    let (tip, tip_time, h) =
        pin_restart_catchup_then_tip_purge(&mp_dir, &q_arc, &params, &chain, &want);
    pin_torn_mempool_persist(&mp_dir, &q_arc, &chain, &want);

    let q = q_arc.as_ref();
    let mut bad = spend_anyone_can_spend(spend_txid, 0, Amount::from_sat(47_0000_0000));
    bad.input[0].script_sig = ScriptBuf::from_bytes(vec![0x6a]);

    let catchup_tip = h - 1;
    let bad_block = mine_regtest_block(tip, tip_time + 600, h, vec![bad]);

    let ms_skip = Milestone::height(h);
    let ms_check = Milestone::height(h - 1);
    assert!(ms_skip.skips_scripts_at(h));
    assert!(!ms_check.skips_scripts_at(h));

    let err = accept_and_connect_block(q, &params, Height(h), &bad_block, ms_check)
        .expect_err("invalid script above milestone must fail");
    let msg = err.to_string().to_lowercase();
    assert!(
        msg.contains("script") || msg.contains("opcode") || msg.contains("return"),
        "expected script failure above milestone, got: {err}"
    );
    assert_eq!(q.tip_height(), Some(Height(catchup_tip)));

    accept_and_connect_block(q, &params, Height(h), &bad_block, ms_skip)
        .expect("invalid script below milestone must be skipped");
    assert_eq!(q.tip_height(), Some(Height(h)));

    let ms_hi = Milestone::height(1_000_000);
    let mut phantom = mine_regtest_block(
        bad_block.block_hash(),
        bad_block.header.time + 600,
        h + 1,
        vec![],
    );
    phantom.txdata.push(Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0xcd; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    });
    phantom.header.merkle_root = phantom.compute_merkle_root().unwrap();
    grind_regtest_pow(&mut phantom.header);
    let err = accept_and_connect_block(q, &params, Height(h + 1), &phantom, ms_hi)
        .expect_err("prevout must fail");
    assert!(
        matches!(
            err,
            ConfirmError::Rules(
                ConsensusError::MissingPrevout
                    | ConsensusError::BadTx("bad-txns-inputs-missingorspent"),
            )
        ),
        "expected missing-prevout class under milestone, got: {err}"
    );
}

/// Restart with a leftover pool, connect catch-up (relay off), then tip-mode
/// `set_relay_enabled(true)`: same-txid confirmed gone, input-conflict gone,
/// child of a now-confirmed parent kept, DEAD marks durable without `flush`.
fn pin_restart_catchup_then_tip_purge(
    mp_dir: &Path,
    q: &Arc<Query>,
    params: &ChainParams,
    chain: &MatureRegtestChain,
    leftover: &bitcoin::Txid,
) -> (BlockHash, u32, u32) {
    let (pad_tip, pad_time) = pad_empty_from(
        q.as_ref(),
        params,
        chain.tip_hash(),
        chain.blocks.last().unwrap().header.time,
        chain.spend_height + 1,
        chain.spend_height + 5,
    );
    let spend_cb = |h: usize, sats: u64| {
        spend_anyone_can_spend(
            chain.blocks[h].txdata[0].compute_txid(),
            0,
            Amount::from_sat(sats),
        )
    };
    let same = spend_cb(2, 49_0000_0000);
    let loser = spend_cb(3, 48_0000_0000);
    let winner = spend_cb(3, 47_0000_0000);
    let parent = spend_cb(4, 49_0000_0000);
    let child = spend_anyone_can_spend(parent.compute_txid(), 0, Amount::from_sat(48_0000_0000));
    let extras = [
        spend_cb(5, 49_0000_0000),
        spend_cb(6, 49_0000_0000),
        spend_cb(7, 49_0000_0000),
    ];
    let same_id = same.compute_txid();
    let loser_id = loser.compute_txid();
    let parent_id = parent.compute_txid();
    let child_id = child.compute_txid();
    let extra_ids: Vec<_> = extras.iter().map(|t| t.compute_txid()).collect();
    assert_ne!(loser_id, winner.compute_txid());

    let h = chain.spend_height + 6;
    let blk = mine_regtest_block(
        pad_tip,
        pad_time + 600,
        h,
        vec![same.clone(), winner, parent.clone()],
    );
    {
        let hub = MempoolHub::open_with_weight(mp_dir, Arc::clone(q), 50_000_000).unwrap();
        hub.set_relay_enabled(true);
        hub.accept_tx(&same).expect("accept same-txid leftover");
        hub.accept_tx(&loser).expect("accept conflict loser");
        hub.accept_tx(&parent).expect("accept parent");
        hub.accept_tx(&child).expect("accept child of parent");
        for tx in &extras {
            hub.accept_tx(tx).expect("accept ballast leftover");
        }
        hub.flush().expect("persist leftover pool");
        hub.set_relay_enabled(false);
        let _ = q.confirm_stats().take_window();
        accept_and_connect_block(q.as_ref(), params, Height(h), &blk, Milestone::NONE)
            .expect("catch-up connect");
        let w = q.confirm_stats().take_window();
        assert_eq!(
            w.arch_write_spend_ns, 0,
            "Class A must not put_spend_batch; spentness is post_commit abs-meta"
        );
        assert_eq!(
            w.fill_missing_n, 0,
            "lookup stamp already bound parent loc; finish must not fill_missing"
        );
        let same_coin = chain.blocks[2].txdata[0].compute_txid();
        let parent_coin = chain.blocks[4].txdata[0].compute_txid();
        assert!(
            q.is_outpoint_spent(same_coin.as_byte_array(), 0).unwrap(),
            "same-txid leftover parent coin must be confirmed-spent after connect"
        );
        assert!(
            q.is_outpoint_spent(parent_coin.as_byte_array(), 0).unwrap(),
            "confirmed parent leftover coin must be confirmed-spent after connect"
        );
        assert!(
            hub.contains(&same_id) && hub.contains(&loser_id) && hub.contains(&parent_id),
            "relay off must leave confirmed and conflicted txs in the leftover pool"
        );
        assert!(hub.contains(&child_id) && hub.contains(leftover));
    }

    {
        let hub = MempoolHub::open_with_weight(mp_dir, Arc::clone(q), 50_000_000).unwrap();
        assert!(
            hub.contains(&same_id) && hub.contains(&loser_id) && hub.contains(&parent_id),
            "reopen after catch-up must load leftover txs before tip-mode purge"
        );
        hub.set_relay_enabled(true);
        assert!(
            !hub.contains(&same_id),
            "same-txid confirmed leftover must drop at relay-on"
        );
        assert!(
            !hub.contains(&loser_id),
            "input-conflict leftover must drop at relay-on"
        );
        assert!(
            !hub.contains(&parent_id),
            "confirmed parent leftover must drop at relay-on"
        );
        assert!(
            hub.contains(&child_id),
            "child of a now-confirmed parent must stay"
        );
        assert!(hub.contains(leftover), "unrelated leftover must stay");
        for id in &extra_ids {
            assert!(hub.contains(id), "ballast leftover must stay (no compact)");
        }
    }

    {
        let hub = MempoolHub::open_with_weight(mp_dir, Arc::clone(q), 50_000_000).unwrap();
        assert!(
            !hub.contains(&same_id) && !hub.contains(&loser_id) && !hub.contains(&parent_id),
            "purge DEAD marks must survive drop without flush"
        );
        assert!(hub.contains(&child_id) && hub.contains(leftover));
        hub.set_relay_enabled(true);
        let mut strip = extra_ids;
        strip.push(child_id);
        assert_eq!(
            hub.remove_for_block(&strip, RemovalReason::Block),
            strip.len()
        );
        hub.flush()
            .expect("restore singleton leftover for slots.tmp pin");
    }

    (blk.block_hash(), blk.header.time, h + 1)
}

/// Issue 859: a hard stop can publish `slots` ahead of `tx.body`. The hub open
/// the node uses keeps the in-range prefix, quarantines an unreadable sidecar,
/// and still accepts. A path that is not a directory still fails.
fn pin_torn_mempool_persist(
    mp_dir: &Path,
    q: &Arc<Query>,
    chain: &MatureRegtestChain,
    want: &bitcoin::Txid,
) {
    std::fs::write(mp_dir.join("fee_history"), b"fee-hist-v1").unwrap();
    std::fs::write(mp_dir.join("fee_history.log"), b"fee-log-v1").unwrap();
    pin_slots_tmp_finishes(mp_dir, q, want);

    let tail = spend_anyone_can_spend(
        chain.blocks[5].txdata[0].compute_txid(),
        0,
        Amount::from_sat(49_0000_0000),
    );
    let tail_id = tail.compute_txid();
    assert_ne!(&tail_id, want);
    let (body_prefix, slots_prefix, body_full, slots_full) =
        flush_prefix_then_tail(mp_dir, q, want, &tail, &tail_id);
    pin_prefix_kept_tail_dropped(mp_dir, q, want, &tail_id, &body_prefix, &slots_full);
    pin_new_body_old_slots(mp_dir, q, want, &tail_id, &body_full, &slots_prefix);
    pin_unreadable_sidecar_then_accept(
        mp_dir,
        q,
        want,
        &tail,
        &tail_id,
        &body_prefix,
        &slots_prefix,
    );
    pin_file_path_still_fails(mp_dir, q);
}

fn pin_slots_tmp_finishes(mp_dir: &Path, q: &Arc<Query>, want: &bitcoin::Txid) {
    std::fs::copy(mp_dir.join("slots"), mp_dir.join("slots.tmp")).unwrap();
    assert!(mp_dir.join("slots.tmp").exists());
    let hub = MempoolHub::open_with_weight(mp_dir, Arc::clone(q), 50_000_000)
        .expect("open finishes leftover slots.tmp");
    assert!(
        !mp_dir.join("slots.tmp").exists(),
        "leftover slots.tmp must be renamed away"
    );
    assert_eq!(hub.live_count(), 1);
    assert!(hub.contains(want));
}

fn flush_prefix_then_tail(
    mp_dir: &Path,
    q: &Arc<Query>,
    want: &bitcoin::Txid,
    tail: &Transaction,
    tail_id: &bitcoin::Txid,
) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let body_prefix = std::fs::read(mp_dir.join("tx.body")).unwrap();
    let slots_prefix = std::fs::read(mp_dir.join("slots")).unwrap();
    let hub = MempoolHub::open_with_weight(mp_dir, Arc::clone(q), 50_000_000).unwrap();
    hub.set_relay_enabled(true);
    hub.accept_tx(tail).expect("accept tail spend");
    hub.flush().expect("flush prefix plus tail");
    assert!(hub.contains(want) && hub.contains(tail_id));
    drop(hub);
    let body_full = std::fs::read(mp_dir.join("tx.body")).unwrap();
    let slots_full = std::fs::read(mp_dir.join("slots")).unwrap();
    assert!(body_full.len() > body_prefix.len());
    (body_prefix, slots_prefix, body_full, slots_full)
}

fn pin_prefix_kept_tail_dropped(
    mp_dir: &Path,
    q: &Arc<Query>,
    want: &bitcoin::Txid,
    tail_id: &bitcoin::Txid,
    body_prefix: &[u8],
    slots_full: &[u8],
) {
    // Slots name the tail; the body file is the previous prefix (logical end
    // on the first record). That is the issue 859 tear.
    std::fs::write(mp_dir.join("tx.body"), body_prefix).unwrap();
    std::fs::write(mp_dir.join("slots"), slots_full).unwrap();
    let hub = MempoolHub::open_with_weight(mp_dir, Arc::clone(q), 50_000_000)
        .expect("truncated body under later slots must open");
    assert!(hub.contains(want), "in-range prefix stays");
    assert!(!hub.contains(tail_id), "out-of-range tail is absent");
    assert_eq!(hub.live_count(), 1);
    assert_fee_history(mp_dir);
    assert!(
        torn_asides(mp_dir).is_empty(),
        "a skipped tail is not a quarantine"
    );
}

fn pin_new_body_old_slots(
    mp_dir: &Path,
    q: &Arc<Query>,
    want: &bitcoin::Txid,
    tail_id: &bitcoin::Txid,
    body_full: &[u8],
    slots_prefix: &[u8],
) {
    std::fs::write(mp_dir.join("tx.body"), body_full).unwrap();
    std::fs::write(mp_dir.join("slots"), slots_prefix).unwrap();
    let hub = MempoolHub::open_with_weight(mp_dir, Arc::clone(q), 50_000_000)
        .expect("new body and previous slots must open");
    assert!(hub.contains(want), "previous live set stays");
    assert!(
        !hub.contains(tail_id),
        "admit missing from the previous slots stays absent"
    );
    assert_fee_history(mp_dir);
}

fn pin_unreadable_sidecar_then_accept(
    mp_dir: &Path,
    q: &Arc<Query>,
    want: &bitcoin::Txid,
    tail: &Transaction,
    tail_id: &bitcoin::Txid,
    body_prefix: &[u8],
    slots_prefix: &[u8],
) {
    std::fs::write(mp_dir.join("tx.body"), body_prefix).unwrap();
    std::fs::write(mp_dir.join("slots"), slots_prefix).unwrap();
    let mut body = std::fs::read(mp_dir.join("tx.body")).unwrap();
    // Schema-4 txid starts 32 bytes into the packed record. Flip it so the
    // slot's txid does not match the payload. The tx bytes still decode.
    let txid_at = 16 + 32;
    assert!(body.len() > txid_at, "payload has a txid");
    body[txid_at] ^= 0xff;
    std::fs::write(mp_dir.join("tx.body"), &body).unwrap();
    let corrupt_body = std::fs::read(mp_dir.join("tx.body")).unwrap();
    let corrupt_slots = std::fs::read(mp_dir.join("slots")).unwrap();
    let corrupt_meta = std::fs::read(mp_dir.join("meta")).unwrap();
    std::fs::write(mp_dir.join("slots.tmp"), b"slots-tmp").unwrap();
    std::fs::write(mp_dir.join("tx.body.tmp"), b"body-tmp").unwrap();
    let hub = MempoolHub::open_with_weight(mp_dir, Arc::clone(q), 50_000_000)
        .expect("unreadable sidecar must open empty");
    assert_eq!(hub.live_count(), 0);
    assert!(!hub.contains(want));
    assert!(!mp_dir.join("slots.tmp").exists());
    assert!(!mp_dir.join("tx.body.tmp").exists());
    let aside = sole_torn_aside(mp_dir);
    assert_eq!(std::fs::read(aside.join("tx.body")).unwrap(), corrupt_body);
    assert_eq!(std::fs::read(aside.join("slots")).unwrap(), corrupt_slots);
    assert_eq!(std::fs::read(aside.join("meta")).unwrap(), corrupt_meta);
    assert_eq!(
        std::fs::read(aside.join("slots.tmp")).unwrap(),
        b"slots-tmp"
    );
    assert_eq!(
        std::fs::read(aside.join("tx.body.tmp")).unwrap(),
        b"body-tmp"
    );
    assert_fee_history(mp_dir);
    hub.set_relay_enabled(true);
    let accepted = hub
        .accept_tx(tail)
        .expect("empty mempool after quarantine still accepts");
    assert_eq!(accepted.txid, *tail_id);
    assert!(hub.contains(tail_id));
}

fn pin_file_path_still_fails(mp_dir: &Path, q: &Arc<Query>) {
    let not_dir = mp_dir.parent().unwrap().join("mempool-not-a-dir");
    std::fs::write(&not_dir, b"file").unwrap();
    let err = match MempoolHub::open_with_weight(&not_dir, Arc::clone(q), 50_000_000) {
        Ok(_) => panic!("a file path must not open as a mempool directory"),
        Err(e) => e,
    };
    let low = err.to_lowercase();
    assert!(
        low.contains("io") || low.contains("directory") || low.contains("not a directory"),
        "expected an IO open failure, got {err}"
    );
    assert_eq!(std::fs::read(&not_dir).unwrap(), b"file");
    assert!(
        torn_asides(&not_dir).is_empty(),
        "an IO failure must not quarantine"
    );
}

fn assert_fee_history(mp_dir: &Path) {
    assert_eq!(
        std::fs::read(mp_dir.join("fee_history")).unwrap(),
        b"fee-hist-v1"
    );
    assert_eq!(
        std::fs::read(mp_dir.join("fee_history.log")).unwrap(),
        b"fee-log-v1"
    );
}

fn torn_asides(mp_dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(mp_dir) else {
        return out;
    };
    for ent in rd.flatten() {
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("torn-") {
            out.push(ent.path());
        }
    }
    out
}

fn sole_torn_aside(mp_dir: &Path) -> PathBuf {
    let dirs = torn_asides(mp_dir);
    assert_eq!(dirs.len(), 1, "one quarantine directory, got {dirs:?}");
    dirs.into_iter().next().unwrap()
}

fn first_head_sidecar(head: &Path, ext: &str) -> PathBuf {
    for ent in std::fs::read_dir(head).unwrap() {
        let p = ent.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) == Some(ext) {
            return p;
        }
    }
    panic!("no *.{ext} under {}", head.display());
}

fn assert_query_open_refuses(store: &Path, needle: &str) {
    let err = match Query::open_or_create_tiny(store) {
        Ok(_) => panic!("Query::open must refuse ({needle})"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains(needle), "expected {needle:?} in {msg}");
    assert!(
        store.join("txout.body").is_file(),
        "Class A kept after {needle} refuse"
    );
}

fn assert_query_rebuilds_from_class_a(store: &Path, b1: &bitcoin::Block, cb_txid: &[u8; 32]) {
    let q = Query::open_or_create_tiny(store).expect("torn current tx.head rebuilds from Class A");
    assert_eq!(q.tip_height(), Some(Height(2)));
    assert!(
        q.tx_head_occupied() >= 3,
        "open must rebuild tx.head from Class A bodies"
    );
    assert!(
        q.get_tx_by_txid(cb_txid).unwrap().is_some(),
        "txid must resolve after head rebuild"
    );
    assert_reconstruct_eq(&q, 1, b1);
}

/// Archive reconstruct of height 1 after dropping RAM and wiping `tx.head/`
/// (`feature_reindex*.py` / operator delete-head reopen). Same pad: crash-open
/// clamps an unsealed tip; leftover fuse8 v1 refuses; truncated MPHF / empty
/// meta rebuild from Class A.
#[test]
fn analog_reconstruct_after_lost_head() {
    let td = TestDatadir::new().unwrap();
    let params = ChainParams::regtest();
    let genesis = regtest_genesis();
    let store = td.store_path();
    let b1;
    let b2;
    let cb_txid;
    let b3_cb;
    {
        let q = Query::open_or_create_tiny(&store).unwrap();
        accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, Milestone::NONE).unwrap();
        b1 = mine_regtest_block(genesis.block_hash(), genesis.header.time + 600, 1, vec![]);
        accept_and_connect_block(&q, &params, Height(1), &b1, Milestone::NONE).unwrap();
        b2 = mine_regtest_block(b1.block_hash(), b1.header.time + 600, 2, vec![]);
        accept_and_connect_block(&q, &params, Height(2), &b2, Milestone::NONE).unwrap();
        q.flush().unwrap();
        assert_eq!(q.tip_height(), Some(Height(2)));
        cb_txid = b1.txdata[0].compute_txid().to_byte_array();
        let seal_path = store.join("tip_seal");
        let seal = std::fs::read(&seal_path).expect("tip_seal after complete barrier");
        let b3 = mine_regtest_block(b2.block_hash(), b2.header.time + 600, 3, vec![]);
        accept_and_connect_block(&q, &params, Height(3), &b3, Milestone::NONE).unwrap();
        assert_eq!(q.tip_height(), Some(Height(3)));
        b3_cb = b3.txdata[0].compute_txid().to_byte_array();
        std::fs::write(&seal_path, seal).expect("restore pre-height-3 seal");
    }

    let q_clamp = Query::open_or_create_tiny(&store).unwrap();
    assert_eq!(q_clamp.tip_height(), Some(Height(2)));
    let view = q_clamp
        .pin_chain_view()
        .unwrap()
        .expect("Electrum/RPC chain_tip after crash-open");
    assert_eq!(view.height, Height(2));
    assert_eq!(view.hash, b2.block_hash().to_byte_array());
    let b3_fk = q_clamp
        .get_tx_by_txid(&b3_cb)
        .unwrap()
        .expect("height-3 Class A kept")
        .0;
    assert!(
        !q_clamp.store().is_confirmed_strong(b3_fk).unwrap(),
        "leftover strong above clamped tip must not be confirmed"
    );
    drop(q_clamp);

    let head = store.join("tx.head");
    assert!(head.is_dir(), "tiny store writes segmented tx.head/");
    std::fs::remove_dir_all(&head).expect("wipe tx.head");

    let q2 = Query::open_or_create_tiny(&store).unwrap();
    assert_eq!(q2.tip_height(), Some(Height(2)));
    assert!(
        q2.tx_head_occupied() >= 3,
        "open must rebuild tx.head from Class A bodies"
    );
    assert!(
        q2.get_tx_by_txid(&cb_txid).unwrap().is_some(),
        "txid must resolve after head rebuild"
    );
    assert_reconstruct_eq(&q2, 1, &b1);
    let rec = q2
        .reconstruct_block_at_height(Height(1))
        .expect("reconstruct height 1 after wiped tx.head");
    assert_eq!(rec.block_hash(), b1.block_hash());
    drop(q2);

    let fuse = first_head_sidecar(&head, "fuse8");
    let fuse_ok = std::fs::read(&fuse).unwrap();
    let mut v1 = Vec::from(*b"BF8R");
    v1.extend_from_slice(&1u32.to_le_bytes());
    v1.extend_from_slice(&0u64.to_le_bytes());
    std::fs::write(&fuse, &v1).unwrap();
    assert_query_open_refuses(&store, "fuse8 v1");
    std::fs::write(&fuse, fuse_ok).unwrap();

    let mphf = first_head_sidecar(&head, "mphf");
    let mphf_ok = std::fs::read(&mphf).unwrap();
    std::fs::write(&mphf, &mphf_ok[..8.min(mphf_ok.len())]).unwrap();
    assert_query_rebuilds_from_class_a(&store, &b1, &cb_txid);

    std::fs::write(head.join("meta"), []).unwrap();
    assert_query_rebuilds_from_class_a(&store, &b1, &cb_txid);
}

/// Filters the appender materializes from Class A match rust-bitcoin's
/// `new_script_filter`: coinbase-only, a spend, and a block with a duplicate
/// script, an OP_RETURN, and a segwit output. The build runs after a
/// seqsigwit prune has passed those blocks (reconstruct refuses them).
#[test]
fn analog_block_filters_from_class_a() {
    use bitcoin::bip158::BlockFilter;
    use std::collections::HashMap;

    let params = ChainParams::regtest();
    let td = TestDatadir::new().unwrap();
    let (q, chain) = open_mature_regtest_with_spend(td.store_path(), &params);
    let mut blocks = chain.blocks.clone();

    let spend = &blocks[chain.spend_height as usize].txdata[1];
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let mixed = Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: spend.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: op_true.clone(),
            },
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: op_true,
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x04, 1, 2, 3, 4]),
            },
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes([&[0x00, 0x14][..], &[7u8; 20]].concat()),
            },
        ],
    };
    let tip = blocks.last().unwrap();
    let h_mixed = blocks.len() as u32;
    let b = mine_regtest_block(
        tip.block_hash(),
        tip.header.time + 600,
        h_mixed,
        vec![mixed],
    );
    accept_and_connect_block(&q, &params, Height(h_mixed), &b, Milestone::NONE).unwrap();
    blocks.push(b);

    let mut outs: HashMap<OutPoint, ScriptBuf> = HashMap::new();
    for b in &blocks {
        for tx in &b.txdata {
            let txid = tx.compute_txid();
            for (vout, o) in tx.output.iter().enumerate() {
                outs.insert(OutPoint::new(txid, vout as u32), o.script_pubkey.clone());
            }
        }
    }
    let reference = |b: &bitcoin::Block| {
        BlockFilter::new_script_filter(b, |op| {
            outs.get(op)
                .cloned()
                .ok_or(bitcoin::bip158::Error::UtxoMissing(*op))
        })
        .unwrap()
    };
    let tip = blocks.last().unwrap();
    let last = h_mixed + Query::SEQSIGWIT_KEEP_HEIGHTS + 1;
    pad_empty_from(
        &q,
        &params,
        tip.block_hash(),
        tip.header.time,
        h_mixed + 1,
        last,
    );
    q.set_prune_seqsigwit(true).unwrap();
    q.apply_prune_seqsigwit_tip().unwrap();
    assert!(q.reconstruct_block_at_height(Height(h_mixed)).is_err());

    // Materialize after the prune on the appender, stopped after its first
    // commit and restarted: every mined block matches the reference and the
    // header chain is unbroken to the tip.
    q.set_block_filter_index(true).unwrap();
    let q = Arc::new(q);
    let run_appender = |until: &dyn Fn(Option<u32>) -> bool| {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let bf = rbitcoin_query::spawn_index_writebehind(
            Arc::clone(&q),
            Arc::clone(&stop),
            || {},
            || {},
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while !until(q.basic_filter_hwm().unwrap()) {
            assert!(std::time::Instant::now() < deadline, "appender stalled");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        bf.join().unwrap();
        q.basic_filter_hwm().unwrap()
    };
    assert!(run_appender(&|h| h.is_some()).is_some());
    assert_eq!(run_appender(&|h| h == Some(last)), Some(last));
    let mut prev = bitcoin::bip158::FilterHeader::from_byte_array([0u8; 32]);
    for h in 0..=last {
        let (bytes, header) = q.basic_filter_at(h).unwrap().unwrap();
        let filter = BlockFilter::new(&bytes);
        if let Some(b) = blocks.get(h as usize) {
            assert_eq!(filter, reference(b), "filter at {h}");
        }
        assert_eq!(header, filter.filter_header(&prev), "header chain at {h}");
        prev = header;
    }
    // The completion-driven window reader builds the same filters, reading
    // windows that straddle the prune line and share parents across heights.
    for start in (0..=last).step_by(37) {
        let end = (start + 36).min(last);
        let window = q
            .read_index_window(&q.index_heights(start, end, None).unwrap())
            .unwrap();
        for (i, block) in window.blocks.iter().enumerate() {
            let h = start + i as u32;
            assert_eq!(block.height, Height(h));
            let built = q.basic_filter_from_window(&window, i).unwrap();
            assert_eq!(
                built.content,
                q.basic_filter_at(h).unwrap().unwrap().0,
                "window filter at {h}"
            );
        }
    }
    drop(q);

    // Reorg the tip while the index is off: reopening with it on must not
    // serve the stale-branch slot.
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    q.disconnect_tip().unwrap();
    let (_, parent) = q.header_at_height(Height(last - 1)).unwrap().unwrap();
    let mut alt = mine_regtest_block(
        BlockHash::from_byte_array(parent.hash),
        parent.timestamp + 601,
        last,
        vec![],
    );
    alt.txdata[0].output[0].value = Amount::from_sat(1_0000_0000);
    alt.header.merkle_root = alt.compute_merkle_root().unwrap();
    grind_regtest_pow(&mut alt.header);
    accept_and_connect_block(&q, &params, Height(last), &alt, Milestone::NONE).unwrap();
    drop(q);
    let q = Query::open_or_create_tiny(td.store_path()).unwrap();
    q.set_block_filter_index(true).unwrap();
    assert_eq!(
        q.basic_filter_hwm().unwrap(),
        Some(last - 1),
        "open drops the slot whose block left the best chain"
    );
    q.release_index_writebehind(Height(last));
    rbitcoin_query::build_indexes_released(&q).unwrap();
    let (bytes, _) = q.basic_filter_at(last).unwrap().unwrap();
    assert_eq!(bytes, reference(&alt).content);
}
