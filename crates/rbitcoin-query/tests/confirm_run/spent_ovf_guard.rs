//! A crash that leaves `guard/spent.ovf` restores the pre-append nodes.
//! Replay then appends the nodes the chain's spend delta names.
use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version};
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Txid, Witness,
};
use rbitcoin_consensus::block::bip34_height_script;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::accept_and_connect_block;

fn coinbase(height: u32) -> Transaction {
    let mut ss = if height == 0 {
        vec![0x00]
    } else {
        bip34_height_script(height)
    };
    while ss.len() < 2 {
        ss.push(0x00);
    }
    Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(ss),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn spend_one(prev: Txid, val: Amount) -> Transaction {
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: val,
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn mine(prev: bitcoin::BlockHash, time: u32, height: u32, extra: Vec<Transaction>) -> Block {
    let bits = CompactTarget::from_consensus(0x207f_ffff);
    let mut txdata = vec![coinbase(height)];
    txdata.extend(extra);
    let mut block = Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([0; 32]),
            time,
            bits,
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let target = bitcoin::Target::from_compact(bits);
    for nonce in 0..u32::MAX {
        block.header.nonce = nonce;
        if block.header.validate_pow(target).is_ok() {
            break;
        }
    }
    block
}

fn page0(path: &std::path::Path) -> Vec<u8> {
    let mut file = std::fs::File::open(path).unwrap();
    let n = file.metadata().unwrap().len().min(4096) as usize;
    let mut buf = vec![0u8; 4096];
    std::io::Read::read_exact(&mut file, &mut buf[..n]).unwrap();
    buf
}

/// Checkpoint two overflow nodes, append a third, and stop before the clear.
/// Open shows the two. Replay appends the third from the connected block.
#[test]
fn torn_spent_ovf_replay_appends_the_delta_node() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("spent-ovf-replay");
    q.set_spend_index(true);
    let params = ChainParams::regtest();
    let ms = Milestone::NONE;
    let maturity = params.coinbase_maturity();
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    accept_and_connect_block(&q, &params, Height::GENESIS, &genesis, ms).unwrap();
    let mut tip = genesis.block_hash();
    let mut tip_time = genesis.header.time;
    let mut coinbases = Vec::new();
    for h in 1..=maturity + 1 {
        let b = mine(tip, tip_time + 600, h, Vec::new());
        coinbases.push(b.txdata[0].compute_txid());
        accept_and_connect_block(&q, &params, Height(h), &b, ms).unwrap();
        tip = b.block_hash();
        tip_time = b.header.time;
    }
    let parent = tip;
    let parent_time = tip_time;
    let c1 = coinbases[0];
    let hy = maturity + 2;
    let connect_spend = |q: &rbitcoin_query::Query, sats: u64, time: u32| {
        let tx = spend_one(c1, Amount::from_sat(sats));
        let txid = tx.compute_txid();
        let block = mine(parent, time, hy, vec![tx]);
        accept_and_connect_block(q, &params, Height(hy), &block, ms).unwrap();
        txid
    };

    let _tx_a = connect_spend(&q, 49_0000_0000, parent_time + 600);
    q.store().checkpoint_spend_through(hy).unwrap();
    assert_eq!(q.store().spenders.count(), 0);
    let mark = q.store().path().join("guard/spent.ovf");
    assert!(!mark.exists());

    q.disconnect_tip().unwrap();
    let _tx_b = connect_spend(&q, 48_0000_0000, parent_time + 1_200);
    assert_eq!(q.store().spenders.count(), 2, "promote appends both nodes");
    assert!(mark.is_file(), "the first append after sync arms");
    q.store().checkpoint_spend_through(hy).unwrap();
    assert!(!mark.exists(), "the checkpoint sync clears the mark");
    assert_eq!(q.store().spenders.count(), 2);
    let pre = [
        q.store().spenders.get(Fk(1)).unwrap(),
        q.store().spenders.get(Fk(2)).unwrap(),
    ];
    let ovf = q.store().path().join("spent.ovf");
    let pre_page = page0(&ovf);
    let before = q.spenders_raw(c1.as_byte_array(), 0).unwrap();
    let before_fks: Vec<_> = before.iter().map(|p| p.spending_tx_fk).collect();
    assert!(before_fks.contains(&pre[0].0) && before_fks.contains(&pre[1].0));

    q.disconnect_tip().unwrap();
    let tx_c = connect_spend(&q, 47_0000_0000, parent_time + 1_800);
    assert_eq!(q.store().spenders.count(), 3);
    assert!(mark.is_file());
    let armed = std::fs::read(&mark).unwrap();
    q.store().spenders.append(Fk(9), 1, Fk(3)).unwrap();
    assert_eq!(
        std::fs::read(&mark).unwrap(),
        armed,
        "a later append must not snapshot the torn page"
    );
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&ovf).unwrap();
        std::io::Write::write_all(&mut file, &[0xffu8; 4096]).unwrap();
        file.sync_all().unwrap();
    }
    let fk_c = q.tx_fk_by_txid(tx_c.as_byte_array()).unwrap().unwrap();
    let store = q.store().path().to_path_buf();
    drop(q);

    let q = rbitcoin_query::Query::open_or_create_tiny(&store).unwrap();
    q.set_spend_index(true);
    assert!(!store.join("guard/spent.ovf").exists());
    assert_eq!(q.store().spenders.count(), 2);
    assert_eq!(q.store().spenders.get(Fk(1)).unwrap(), pre[0]);
    assert_eq!(q.store().spenders.get(Fk(2)).unwrap(), pre[1]);
    assert!(matches!(
        q.store().spenders.get(Fk(3)),
        Err(rbitcoin_store::StoreError::NotFound)
    ));
    assert_eq!(page0(&store.join("spent.ovf")), pre_page);
    assert_ne!(page0(&store.join("spent.ovf")), vec![0xffu8; 4096]);
    let restored = q.spenders_raw(c1.as_byte_array(), 0).unwrap();
    let restored_fks: Vec<_> = restored.iter().map(|p| p.spending_tx_fk).collect();
    assert!(restored_fks.contains(&pre[0].0) && restored_fks.contains(&pre[1].0));
    assert!(
        !restored_fks.contains(&fk_c),
        "the torn tail is not the committed list"
    );

    let replayed = rbitcoin_query::replay_spend_annotations(&q).unwrap();
    assert!(
        replayed >= 1,
        "replay rewrites the connected spend, got {replayed}"
    );
    assert_eq!(q.store().spenders.count(), 3);
    let after = q.spenders_raw(c1.as_byte_array(), 0).unwrap();
    let after_fks: Vec<_> = after.iter().map(|p| p.spending_tx_fk).collect();
    assert!(
        after_fks.contains(&fk_c),
        "replay must append the connected spender, got {after_fks:?}"
    );
    let _ = dir;
}
