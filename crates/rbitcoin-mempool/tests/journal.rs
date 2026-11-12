use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use rbitcoin_mempool::accept::MapUtxoProvider;
use rbitcoin_mempool::{ActiveMempool, ChainTipCtx, Coin, PoolChange, RemovalReason};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

const TIP_OK: ChainTipCtx = ChainTipCtx {
    height: 1_000_000,
    mtp: u32::MAX,
};

fn tmp_dir() -> rbitcoin_store::testutil::TempDir {
    rbitcoin_store::testutil::TempDir::labeled("mempool-journal").unwrap()
}

fn chain_coins(n: u8) -> (Vec<OutPoint>, MapUtxoProvider) {
    let mut map = HashMap::new();
    let mut ops = Vec::new();
    for i in 0..n {
        let op = OutPoint {
            txid: Txid::from_byte_array([i.wrapping_add(1); 32]),
            vout: 0,
        };
        let coin = Coin {
            txout: TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            create_height: 1,
            create_mtp: 0,
            is_coinbase: false,
            create_fk: None,
        };
        map.insert(op, coin);
        ops.push(op);
    }
    (ops, MapUtxoProvider { map })
}

fn spend(op: OutPoint, out_value: u64) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: op,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(out_value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn out0(tx: &Transaction) -> OutPoint {
    OutPoint {
        txid: tx.compute_txid(),
        vout: 0,
    }
}

fn removed(txid: Txid, reason: RemovalReason) -> PoolChange {
    PoolChange::Removed { txid, reason }
}

fn journal(mp: &mut ActiveMempool) -> Vec<PoolChange> {
    mp.drain_journal().collect()
}

#[test]
fn admit_journals_fee_weight_vsize_and_time() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(1);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    mp.set_node_clock(Arc::new(AtomicU64::new(1_794_950_000)));
    let tx = spend(ops[0], 98_766);
    let r = mp.accept_tx(&tx, &utxos, TIP_OK).expect("admit");
    let vsize = rbitcoin_consensus::policy::vbytes_ceil(mp.graph.adjusted_weight_of(&r.txid));
    assert_eq!(
        journal(&mut mp),
        vec![PoolChange::Added {
            txid: r.txid,
            fee_sat: 1_234,
            weight: tx.weight().to_wu(),
            vsize,
            time: 1_794_950_000,
        }]
    );
    assert!(journal(&mut mp).is_empty(), "a drain empties the journal");
}

#[test]
fn replacement_journals_conflict_tree_before_the_add() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(1);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let parent = spend(ops[0], 99_000);
    let child = spend(out0(&parent), 98_000);
    mp.accept_tx(&parent, &utxos, TIP_OK).expect("parent");
    mp.accept_tx(&child, &utxos, TIP_OK).expect("child");
    let _ = journal(&mut mp);
    let replacement = spend(ops[0], 90_000);
    let by = replacement.compute_txid();
    mp.accept_tx(&replacement, &utxos, TIP_OK)
        .expect("replacement");
    let got = journal(&mut mp);
    assert_eq!(got.len(), 3, "{got:?}");
    let first_two: BTreeSet<Txid> = got[..2]
        .iter()
        .map(|c| match c {
            PoolChange::Removed {
                txid,
                reason: RemovalReason::Replaced { by: b },
            } if *b == by => *txid,
            other => panic!("expected a removal replaced by {by}, got {other:?}"),
        })
        .collect();
    assert_eq!(
        first_two,
        BTreeSet::from([parent.compute_txid(), child.compute_txid()])
    );
    assert!(matches!(got[2], PoolChange::Added { txid, .. } if txid == by));
}

#[test]
fn weight_budget_eviction_journals_sizelimit() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(2);
    let low = spend(ops[0], 99_000);
    let high = spend(ops[1], 50_000);
    let mut mp = ActiveMempool::open_or_create_with_limit(&dir, low.weight().to_wu()).unwrap();
    mp.accept_tx(&low, &utxos, TIP_OK).expect("low fits");
    let _ = journal(&mut mp);
    mp.accept_tx(&high, &utxos, TIP_OK)
        .expect("high evicts low");
    let got = journal(&mut mp);
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(matches!(got[0], PoolChange::Added { txid, .. } if txid == high.compute_txid()));
    assert_eq!(
        got[1],
        removed(low.compute_txid(), RemovalReason::SizeLimit)
    );
}

#[test]
fn block_removal_journals_block_then_conflict_tree() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(2);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let mined = spend(ops[0], 99_000);
    let loser = spend(ops[1], 99_000);
    let loser_child = spend(out0(&loser), 98_000);
    for tx in [&mined, &loser, &loser_child] {
        mp.accept_tx(tx, &utxos, TIP_OK).expect("admit");
    }
    let _ = journal(&mut mp);
    let (n, gone) = mp
        .remove_block_txids(&[mined.compute_txid()], &[ops[1]])
        .unwrap();
    assert_eq!((n, gone.len()), (1, 2));
    let got = journal(&mut mp);
    assert_eq!(got[0], removed(mined.compute_txid(), RemovalReason::Block));
    let conflicts: BTreeSet<Txid> = got[1..]
        .iter()
        .map(|c| match c {
            PoolChange::Removed {
                txid,
                reason: RemovalReason::Conflict,
            } => *txid,
            other => panic!("expected a conflict removal, got {other:?}"),
        })
        .collect();
    assert_eq!(
        conflicts,
        BTreeSet::from([loser.compute_txid(), loser_child.compute_txid()])
    );
}

#[test]
fn open_and_compact_journal_nothing() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(2);
    {
        let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
        for op in &ops {
            mp.accept_tx(&spend(*op, 99_000), &utxos, TIP_OK)
                .expect("admit");
        }
        mp.flush().unwrap();
    }
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    assert_eq!(mp.live_count(), 2);
    assert!(
        journal(&mut mp).is_empty(),
        "loaded records are not changes"
    );
    mp.compact().unwrap();
    assert_eq!(mp.live_count(), 2);
    assert!(journal(&mut mp).is_empty(), "a rebuild is not a change");
}

/// A replacement that does not commit was never in the pool. Its conflict
/// leaves as a rollback, not as replaced by it, and the restore journals the
/// add.
#[test]
fn failed_replacement_journals_a_rollback_then_the_restore() {
    let dir = tmp_dir();
    let (ops, utxos) = chain_coins(1);
    let mut mp = ActiveMempool::open_or_create(&dir).unwrap();
    let victim = spend(ops[0], 99_000);
    let id = mp.accept_tx(&victim, &utxos, TIP_OK).expect("victim").txid;
    let _ = journal(&mut mp);
    let replacement = spend(ops[0], 90_000);
    mp.store.fail_next_append = true;
    assert!(mp.accept_tx(&replacement, &utxos, TIP_OK).is_err());
    let got = journal(&mut mp);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0], removed(id, RemovalReason::Rollback));
    assert!(matches!(got[1], PoolChange::Added { txid, .. } if txid == id));
    assert!(mp.graph.contains(&id));
}
