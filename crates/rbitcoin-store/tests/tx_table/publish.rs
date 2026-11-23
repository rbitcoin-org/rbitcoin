//! Class A append publishes body headers, then the locator header last.
use rbitcoin_store::file::FILE_HEADER_LEN;
use rbitcoin_store::tx_table::{InputRecord, OutputRecord, TxRecord, TxTable};

fn on_disk_hwm(file: &rbitcoin_store::file::TableFile) -> u64 {
    let mut buf = [0u8; 8];
    file.pread_all(8, &mut buf).unwrap();
    u64::from_le_bytes(buf)
}

fn one(n: u8) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    let mut txid = [0u8; 32];
    txid[0] = n;
    (
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
        vec![OutputRecord::unspent(1000, vec![n])],
    )
}

struct Disarm(rbitcoin_store::io_handle::IoHandle);

impl Drop for Disarm {
    fn drop(&mut self) {
        rbitcoin_store::io_handle::disarm_pwrite(self.0);
    }
}

fn set_disk_hwm(file: &rbitcoin_store::file::TableFile, len: u64) {
    file.pwrite_all(8, &len.to_le_bytes()).unwrap();
}

fn outs(t: &TxTable, fk: u64) -> Vec<rbitcoin_store::tx_table::OutputRecord> {
    t.get_meta_and_outputs(rbitcoin_primitives::Fk(fk))
        .unwrap()
        .1
}

fn numbered(n: u16) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    let mut txid = [0u8; 32];
    txid[..2].copy_from_slice(&n.to_le_bytes());
    (
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
        vec![OutputRecord::unspent(1000, n.to_le_bytes().to_vec())],
    )
}

/// The locator header of the second create landed and the body headers did
/// not. The barrier syncs Class A before Class C, so no commit names that
/// create: open keeps the prefix the body headers cover, and the next
/// append takes the dropped number.
#[test]
fn body_header_short_of_the_locator_reopens_at_the_covered_prefix() {
    let dir = super::tempfile_dir("body-behind-loc");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    let tx_end = on_disk_hwm(&t.body.body);
    let in_end = on_disk_hwm(&t.seqsigwit.body);
    let sp_end = on_disk_hwm(&t.spent.body);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    assert!(on_disk_hwm(&t.body.body) > tx_end);
    set_disk_hwm(&t.body.body, tx_end);
    set_disk_hwm(&t.seqsigwit.body, in_end);
    set_disk_hwm(&t.spent.body, sp_end);
    drop(t);
    let t = TxTable::open_tiny(&dir).expect("an unpublished tail truncates");
    assert_eq!(t.count(), 1);
    assert_eq!(outs(&t, 1)[0].script, vec![1]);
    let again = t.put_full_batch_indexed(&[one(3)], false).unwrap();
    assert_eq!(again, vec![rbitcoin_primitives::Fk(2)]);
    assert_eq!(outs(&t, 2)[0].script, vec![3]);
}

/// Only the witness body header fell behind. Open cuts every stem to the
/// creates that header still covers.
#[test]
fn short_witness_body_header_reopens_at_the_covered_prefix() {
    let dir = super::tempfile_dir("witness-behind-loc");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    let in_end = on_disk_hwm(&t.seqsigwit.body);
    t.put_full_batch_indexed(&[one(2), one(3)], false).unwrap();
    set_disk_hwm(&t.seqsigwit.body, in_end);
    drop(t);
    let t = TxTable::open_tiny(&dir).expect("an unpublished tail truncates");
    assert_eq!(t.count(), 1);
    assert_eq!(t.input.count(), 1);
    assert_eq!(t.txids.count(), 1);
}

/// `create.loc` landed and `seqsigwit.loc` did not. Open cuts back to the
/// shorter locator instead of refusing the datadir.
#[test]
fn seqsigwit_loc_behind_create_loc_reopens_at_the_shorter_count() {
    let dir = super::tempfile_dir("seq-loc-behind");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    let seq_end = on_disk_hwm(&t.seqsigwit_loc.loc);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    assert!(on_disk_hwm(&t.seqsigwit_loc.loc) > seq_end);
    set_disk_hwm(&t.seqsigwit_loc.loc, seq_end);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    assert_eq!(t.seqsigwit_loc.count(), 1);
    assert_eq!(outs(&t, 1)[0].script, vec![1]);
}

/// A 1024-create window whose `create.off` checkpoint did not land opens at
/// the last create that does not need that checkpoint.
#[test]
fn short_create_off_reopens_at_the_last_complete_window() {
    let dir = super::tempfile_dir("short-create-off");
    let t = TxTable::create_tiny(&dir).unwrap();
    let batch: Vec<_> = (1..=1024).map(numbered).collect();
    t.put_full_batch_indexed(&batch, false).unwrap();
    assert_eq!(t.create_loc.count(), 1024);
    assert!(on_disk_hwm(&t.create_loc.off) > FILE_HEADER_LEN as u64);
    set_disk_hwm(&t.create_loc.off, FILE_HEADER_LEN as u64);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1023);
    assert_eq!(t.create_loc.count(), 1023);
    assert_eq!(outs(&t, 1)[0].script, 1u16.to_le_bytes().to_vec());
    assert_eq!(outs(&t, 1023)[0].script, 1023u16.to_le_bytes().to_vec());
    assert!(t
        .get_meta_and_outputs(rbitcoin_primitives::Fk(1024))
        .is_err());
}

/// A locator header pwrite that misses fails the append, though RAM moved.
/// Flush does not then store that locator header, no later append stacks on
/// it, and reopen keeps none of it.
#[test]
fn locator_header_miss_fails_the_append() {
    let dir = super::tempfile_dir("loc-header-miss");
    let t = TxTable::create_tiny(&dir).unwrap();
    let loc_fd = t.create_loc.loc.io_handle();
    rbitcoin_store::io_handle::arm_fail_hwm_pwrites(loc_fd, 1);
    let disarm = Disarm(loc_fd);
    let before = FILE_HEADER_LEN as u64;
    assert!(t.put_full_batch_indexed(&[one(1)], false).is_err());
    drop(disarm);
    assert_eq!(t.create_loc.count(), 1);
    assert_eq!(on_disk_hwm(&t.create_loc.loc), before);
    t.create_loc.loc.flush().unwrap();
    assert_eq!(
        on_disk_hwm(&t.create_loc.loc),
        before,
        "flush stored a locator header the pwrite had missed"
    );
    assert!(
        t.put_full_batch_indexed(&[one(2)], false).is_err(),
        "an append stacked on a failed one"
    );
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 0);
}

fn wide(n: u8) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    let mut txid = [0u8; 32];
    txid[0] = n;
    txid[1] = 0xff;
    let outs = (0..256)
        .map(|i| OutputRecord::unspent(1000, vec![n, i as u8]))
        .collect();
    (
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 256,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![], vec![])],
        outs,
    )
}

/// The overflow header pwrite fails, so the append fails and no later one
/// runs. Reopen drops the unpublished create instead of keeping one that
/// cannot be decoded.
#[test]
fn ovf_header_miss_does_not_seal_the_create() {
    let dir = super::tempfile_dir("ovf-header-seal");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[wide(1)], false).unwrap();
    let ovf_fd = t.create_loc.ovf.io_handle();
    rbitcoin_store::io_handle::arm_fail_hwm_pwrites(ovf_fd, 8);
    let disarm = Disarm(ovf_fd);
    assert!(t.put_full_batch_indexed(&[wide(2)], false).is_err());
    assert!(t.put_full_batch_indexed(&[one(3)], false).is_err());
    drop(disarm);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    assert_eq!(outs(&t, 1).len(), 256);
    assert!(t.get_meta_and_outputs(rbitcoin_primitives::Fk(2)).is_err());
}

/// Segment files and no `tx.head/meta` are a torn rebuild. Open wipes that
/// directory, serves the txid from Class A, and the next open keeps the head.
#[test]
fn tx_head_without_meta_rebuilds_from_class_a() {
    let dir = super::tempfile_dir("head-no-meta");
    let t = TxTable::create_tiny(&dir).unwrap();
    let batch = [one(7)];
    let txid = batch[0].0.txid;
    t.put_full_batch_indexed(&batch, false).unwrap();
    t.head.flush().unwrap();
    drop(t);
    let root = dir.join("tx.head");
    std::fs::write(root.join("000000"), b"torn-segment").unwrap();
    std::fs::remove_file(root.join("meta")).unwrap();

    rbitcoin_log::capture_logs(true);
    let t = TxTable::open_tiny(&dir).unwrap();
    let first = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let text = first
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("tx.head rebuild begin"), "{text}");
    assert_eq!(
        t.get_by_txid(&txid).unwrap().unwrap().0,
        rbitcoin_primitives::Fk(1)
    );
    drop(t);

    rbitcoin_log::capture_logs(true);
    let t = TxTable::open_tiny(&dir).unwrap();
    let second = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let text = second
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !text.contains("tx.head rebuild begin"),
        "a finished head rebuilds again: {text}"
    );
    assert_eq!(
        t.get_by_txid(&txid).unwrap().unwrap().0,
        rbitcoin_primitives::Fk(1)
    );
}

/// A kill leaves `tx.head` past the creates open keeps: its inserts ran
/// ahead of the barrier that names them. Open drops only the segments that
/// reach past the cut, sealed or open, and backfills from there. A sealed
/// segment below the cut stays as it was, so a kill costs a segment, not
/// the whole head.
#[test]
fn open_cut_keeps_the_tx_head_segments_below_it() {
    use rbitcoin_store::address_head::HeadLayout;
    use std::sync::atomic::Ordering;
    let dir = super::tempfile_dir("head-cut-keeps-sealed");
    // 8-bit head: 204 keys per segment.
    let t = TxTable::create_with_head_layout(&dir, HeadLayout::new(8).unwrap()).unwrap();
    for n in 1..=450u16 {
        t.put_full_batch_indexed(&[numbered(n)], true).unwrap();
    }
    t.head.flush().unwrap();
    t.put_full_batch_indexed(&[numbered(451)], true).unwrap();
    t.head.flush().unwrap();
    let before = t.head.segments_snapshot();
    let ids: Vec<u32> = before.iter().map(|seg| seg.file_id).collect();
    let kept = before[0].clone();
    assert!(kept.sealed && before[1].sealed, "two segments sealed");
    let kept_end = kept.first_fk + kept.count.load(Ordering::Relaxed) - 1;
    let dropped_end = before[1].first_fk + before[1].count.load(Ordering::Relaxed) - 1;
    assert!(kept_end < 300 && dropped_end > 300);
    assert_eq!(t.head.last_inserted_fk(), 451);
    drop((before, t));

    let t = TxTable::open_seqsigwit(
        &dir,
        &dir,
        rbitcoin_store::HeadOpenOpts::TINY,
        Some(300),
        true,
    )
    .unwrap();
    assert_eq!(t.count(), 300);
    let after = t.head.segments_snapshot();
    assert_eq!(t.head.bits(), 8, "open wiped and rebuilt the whole head");
    assert_eq!(
        (after[0].file_id, after[0].first_fk, after[0].sealed),
        (kept.file_id, 1, true)
    );
    assert_eq!(
        after[0].count.load(Ordering::Relaxed),
        kept_end,
        "open rebuilt a sealed segment below the cut"
    );
    assert_eq!(t.head.last_inserted_fk(), 300);
    for n in 1..=300u16 {
        let (fk, _) = t
            .get_by_txid(&numbered(n).0.txid)
            .unwrap()
            .unwrap_or_else(|| panic!("create {n} missing from tx.head"));
        assert_eq!(fk.0, u64::from(n));
    }
    assert!(t.get_by_txid(&numbered(345).0.txid).unwrap().is_none());
    let root = rbitcoin_store::segmented_head::head_root(&dir);
    for id in ids.iter().filter(|id| **id != kept.file_id) {
        let base = format!("{id:06}");
        for ent in std::fs::read_dir(&root).unwrap().flatten() {
            let name = ent.file_name().to_string_lossy().into_owned();
            assert!(
                name != base && !name.starts_with(&format!("{base}.")),
                "a dropped segment's file stayed: {name}"
            );
        }
    }
    t.head.flush().unwrap();
    drop((after, t));
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 300);
    assert_eq!(t.head.last_inserted_fk(), 300);
    assert_eq!(t.head.bits(), 8);
}
