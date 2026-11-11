//! A covered-prefix cut can reuse a spender fk. Block validation and the
//! Electrum spend join have to ignore that fk when its input no longer
//! names the parent output.
use rbitcoin_primitives::{Fk, Height};
use rbitcoin_query::block_pipeline::{
    structural_apply_one_meta, structural_mark_pending, RunCreateHeight, StructuralScratch,
};
use rbitcoin_query::scripthash::ScriptHashOutpoint;
use rbitcoin_query::{ChainView, FkMap, Query};
use rbitcoin_store::header_table::{block_header_hash, HeaderRecord};
use rbitcoin_store::tx_table::{InputParent, InputRecord, OutputRecord, TxRecord};
use rbitcoin_store::ClassCWrite;

fn tmp() -> std::path::PathBuf {
    let p = rbitcoin_store::testutil::fresh_path("reused-pipe");
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn hdr(prev: Fk, parent_hash: [u8; 32], salt: u8, merkle: [u8; 32]) -> HeaderRecord {
    let version = 1i32;
    let timestamp = u32::from(salt) + 1;
    let bits = 0x207fffff;
    let nonce = u32::from(salt);
    let hash = if prev.is_null() {
        block_header_hash(version, &[0u8; 32], &merkle, timestamp, bits, nonce)
    } else {
        block_header_hash(version, &parent_hash, &merkle, timestamp, bits, nonce)
    };
    HeaderRecord {
        prev_fk: prev,
        version,
        timestamp,
        bits,
        nonce,
        merkle_root: merkle,
        hash,
        size: 0,
        weight: 0,
    }
}

fn on_disk_hwm(path: &std::path::Path) -> u64 {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).unwrap();
    f.seek(SeekFrom::Start(8)).unwrap();
    let mut buf = [0u8; 8];
    f.read_exact(&mut buf).unwrap();
    u64::from_le_bytes(buf)
}

fn write_hwm(path: &std::path::Path, logical: u64) {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(8)).unwrap();
    f.write_all(&logical.to_le_bytes()).unwrap();
}

fn coinbase(salt: u8) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    (
        TxRecord {
            txid: [salt; 32],
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![salt], vec![])],
        vec![OutputRecord::unspent(50, vec![0x51])],
    )
}

fn connect_coinbase(
    s: &rbitcoin_store::Store,
    write: &ClassCWrite,
    h: u8,
    prev: Fk,
    parent_hash: [u8; 32],
) -> (Fk, [u8; 32]) {
    let txid = [h; 32];
    let (rec, ins, outs) = coinbase(h);
    let tx_fk = s
        .put_tx_full_batch_indexed(&[(rec, ins, outs)], false)
        .unwrap()[0];
    let merkle = rbitcoin_primitives::merkle_root_from_txids(&[txid]);
    let header = hdr(prev, parent_hash, h, merkle);
    let hash = header.hash;
    let header_fk = s.put_header(&header).unwrap();
    s.header_txs.put_range(write, header_fk, tx_fk, 1).unwrap();
    s.strong_tx.set_strong(write, tx_fk, header_fk).unwrap();
    s.confirmed
        .set(write, Height(u32::from(h)), header_fk)
        .unwrap();
    (header_fk, hash)
}

fn outpoint(fk: Fk) -> ScriptHashOutpoint {
    ScriptHashOutpoint {
        scripthash: [0; 32],
        create_tx_fk: fk,
        vout: 0,
        txid: [0; 32],
        value: 50,
        create_height: 0,
        unspendable: false,
    }
}

fn mark(scratch: &StructuralScratch, create: Fk) -> Result<(), rbitcoin_query::ConfirmError> {
    let spends = vec![([0u8; 32], 0u32, Fk(99), create, 0u32)];
    let mut pending = rbitcoin_query::block_pipeline::BatchSpent::default();
    let run = RunCreateHeight::Map(FkMap::default());
    structural_mark_pending(&spends, &mut pending, &run, &scratch.durable_spent)
}

/// The store says the parent is unspent. Validation and the spend join
/// must agree, including when the stored spender's height is below the
/// create. A later input that still names the parent is spent.
#[test]
fn reused_spender_does_not_reject_the_parent() {
    let dir = tmp();
    let write = ClassCWrite::for_test();
    let parent = Fk(1);
    let (hash0, genesis) = {
        let q = Query::open_or_create_tiny(&dir).unwrap();
        let s = q.store();
        let (genesis, hash0) = connect_coinbase(s, &write, 0, Fk::NULL, [0u8; 32]);
        s.txs.flush().unwrap();
        let tx_end = on_disk_hwm(&dir.join("txout.body"));
        let sp_end = on_disk_hwm(&dir.join("spent.body"));
        let in_end = on_disk_hwm(&dir.join("seqsigwit.body"));
        let spender = s
            .put_tx_full_batch_indexed(
                &[(
                    TxRecord {
                        txid: [2u8; 32],
                        version: 1,
                        locktime: 0,
                        input_count: 1,
                        output_count: 1,
                    },
                    vec![InputRecord {
                        prev_txid: [0u8; 32],
                        parent: InputParent::Prevout {
                            create_fk: parent,
                            vout: 0,
                        },
                        sequence: u32::MAX,
                        script_sig: vec![],
                        witness: vec![],
                    }],
                    vec![OutputRecord::unspent(1, vec![2])],
                )],
                false,
            )
            .unwrap()[0];
        assert_eq!(spender, Fk(2));
        s.put_spend_create(parent, 0, spender, 0).unwrap();
        let merkle = rbitcoin_primitives::merkle_root_from_txids(&[[2u8; 32]]);
        let header = hdr(genesis, hash0, 1, merkle);
        let header_fk = s.put_header(&header).unwrap();
        s.header_txs
            .put_range(&write, header_fk, spender, 1)
            .unwrap();
        s.strong_tx.set_strong(&write, spender, header_fk).unwrap();
        s.confirmed.set(&write, Height(1), header_fk).unwrap();
        s.flush_class_c_tip().unwrap();
        s.txs.flush().unwrap();
        write_hwm(&dir.join("txout.body"), tx_end);
        write_hwm(&dir.join("spent.body"), sp_end);
        write_hwm(&dir.join("seqsigwit.body"), in_end);
        (hash0, genesis)
    };

    let q = Query::open_or_create_tiny(&dir).unwrap();
    let s = q.store();
    assert_eq!(s.txs.count(), 1);
    assert_eq!(s.confirmed.tip_height(), Some(Height(0)));
    assert_eq!(s.unspent_create_vouts(parent, &[0], None).unwrap(), vec![0]);
    let other = s.put_tx_full_batch_indexed(&[coinbase(9)], false).unwrap()[0];
    assert_eq!(other, Fk(2));
    let other_rec = hdr(genesis, hash0, 9, [9u8; 32]);
    let other_hash = other_rec.hash;
    let other_header = s.put_header(&other_rec).unwrap();
    s.header_txs
        .put_range(&write, other_header, other, 1)
        .unwrap();
    s.strong_tx.set_strong(&write, other, other_header).unwrap();
    s.confirmed.set(&write, Height(1), other_header).unwrap();
    s.rebuild_height_fence().unwrap();
    let (multi, field, vin) = s.txs.get_output_spender_meta(parent, 0).unwrap();
    assert!(!multi);
    assert_eq!(field, Fk(2));

    let mut scratch = StructuralScratch::default();
    scratch.height_by_id.insert(1, 0);
    scratch.field_h_by_id.insert(field.0, 1);
    structural_apply_one_meta(
        &q,
        Some((field, 0, vin)),
        1,
        0,
        0,
        Fk(99),
        7,
        Some(1),
        &mut scratch,
    )
    .unwrap();
    assert!(
        !scratch.durable_spent.contains(&(1, 0)),
        "a reused fk is not a confirmed spend of the parent"
    );
    mark(&scratch, parent).expect("the parent is still unspent");

    let mut below = StructuralScratch::default();
    below.height_by_id.insert(1, 5);
    below.field_h_by_id.insert(field.0, 1);
    structural_apply_one_meta(
        &q,
        Some((field, 0, vin)),
        1,
        0,
        0,
        Fk(99),
        7,
        Some(1),
        &mut below,
    )
    .expect("a reused fk below the create height is not corrupt");
    assert!(!below.durable_spent.contains(&(1, 0)));

    let view = ChainView {
        height: Height(1),
        hash: other_hash,
        header_fk: other_header,
    };
    let joined = q
        .join_spends_wave_fks(
            &[outpoint(parent)],
            &[Some(0)],
            &[Some((field, 0, vin))],
            &view,
        )
        .unwrap();
    assert!(
        joined[0].is_empty(),
        "the join kept a spender that does not name the parent: {:?}",
        joined[0]
    );

    let real = s
        .put_tx_full_batch_indexed(
            &[(
                TxRecord {
                    txid: [3u8; 32],
                    version: 1,
                    locktime: 0,
                    input_count: 1,
                    output_count: 1,
                },
                vec![InputRecord {
                    prev_txid: [0u8; 32],
                    parent: InputParent::Prevout {
                        create_fk: parent,
                        vout: 0,
                    },
                    sequence: u32::MAX,
                    script_sig: vec![],
                    witness: vec![],
                }],
                vec![OutputRecord::unspent(1, vec![3])],
            )],
            false,
        )
        .unwrap()[0];
    s.put_spend_create(parent, 0, real, 0).unwrap();
    let real_header = s
        .put_header(&hdr(other_header, other_hash, 3, [3u8; 32]))
        .unwrap();
    s.header_txs
        .put_range(&write, real_header, real, 1)
        .unwrap();
    s.strong_tx.set_strong(&write, real, real_header).unwrap();
    s.confirmed.set(&write, Height(2), real_header).unwrap();
    s.rebuild_height_fence().unwrap();
    let (multi, field, vin) = s.txs.get_output_spender_meta(parent, 0).unwrap();
    let flags = if multi {
        rbitcoin_store::output_flags::MULTI_SPENDER
    } else {
        assert_eq!(field, real);
        0
    };
    let mut spent = StructuralScratch::default();
    spent.height_by_id.insert(1, 0);
    if let Some(id) = field.get() {
        spent.field_h_by_id.insert(id, 2);
    }
    structural_apply_one_meta(
        &q,
        Some((field, flags, vin)),
        1,
        0,
        0,
        Fk(99),
        7,
        Some(2),
        &mut spent,
    )
    .unwrap();
    assert!(spent.durable_spent.contains(&(1, 0)));
    let err = mark(&spent, parent).unwrap_err();
    assert!(
        err.to_string()
            .contains("prevout already spent on best chain"),
        "{err}"
    );
    let view = ChainView {
        height: Height(2),
        hash: [3u8; 32],
        header_fk: real_header,
    };
    let joined = q
        .join_spends_wave_fks(
            &[outpoint(parent)],
            &[Some(0)],
            &[Some((field, flags, vin))],
            &view,
        )
        .unwrap();
    assert!(
        joined[0].contains(&real),
        "the real spender dropped out of the join: {:?}",
        joined[0]
    );
    assert!(
        !joined[0].contains(&Fk(2)),
        "the join kept the reused fk: {:?}",
        joined[0]
    );
    let _ = std::fs::remove_dir_all(&dir);
}
