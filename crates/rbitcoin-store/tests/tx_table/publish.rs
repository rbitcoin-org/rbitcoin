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

fn seqsigwit_bytes(t: &TxTable, fk: u64) -> Vec<u8> {
    let (off, len) = t.seqsigwit_range(rbitcoin_primitives::Fk(fk)).unwrap();
    t.seqsigwit
        .with_bytes_at(off, len, |b| Ok(b.to_vec()))
        .unwrap()
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

/// A body header short of the locator count is the covered prefix.
/// Open keeps that create and drops the locator tail.
#[test]
fn body_header_short_of_the_locator_reopens_at_that_prefix() {
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
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    assert_eq!(t.create_loc.count(), 1);
    assert_eq!(outs(&t, 1)[0].script, vec![1]);
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

/// A covered-prefix cut leaves `tx.head/meta` naming creates the body
/// headers never finished. Open shortens that count. It does not rebuild.
#[test]
fn tx_head_past_the_covered_prefix_keeps_its_meta() {
    let dir = super::tempfile_dir("head-past-prefix");
    let t = TxTable::create_tiny(&dir).unwrap();
    let first = one(1);
    let txid1 = first.0.txid;
    t.put_full_batch_indexed(&[first], true).unwrap();
    let tx_end = on_disk_hwm(&t.body.body);
    let in_end = on_disk_hwm(&t.seqsigwit.body);
    let sp_end = on_disk_hwm(&t.spent.body);
    let second = one(2);
    let txid2 = second.0.txid;
    t.put_full_batch_indexed(&[second], true).unwrap();
    t.head.flush().unwrap();
    assert_eq!(t.head.last_inserted_fk(), 2);
    set_disk_hwm(&t.body.body, tx_end);
    set_disk_hwm(&t.seqsigwit.body, in_end);
    set_disk_hwm(&t.spent.body, sp_end);
    drop(t);

    rbitcoin_log::capture_logs(true);
    let t = TxTable::open_tiny(&dir).unwrap();
    let first_open = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let text = first_open
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !text.contains("tx.head rebuild begin"),
        "a head that still has meta was rebuilt: {text}"
    );
    assert_eq!(t.count(), 1);
    assert_eq!(t.head.last_inserted_fk(), 1);
    assert_eq!(
        t.get_by_txid(&txid1).unwrap().unwrap().0,
        rbitcoin_primitives::Fk(1)
    );
    assert!(t.get_by_txid(&txid2).unwrap().is_none());
    let third = one(3);
    let txid3 = third.0.txid;
    t.put_full_batch_indexed(&[third], true).unwrap();
    assert_eq!(t.count(), 2);
    assert_eq!(
        t.get_by_txid(&txid3).unwrap().unwrap().0,
        rbitcoin_primitives::Fk(2)
    );
    assert!(t.get_by_txid(&txid2).unwrap().is_none());
    drop(t);

    rbitcoin_log::capture_logs(true);
    let t = TxTable::open_tiny(&dir).unwrap();
    let second_open = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let text = second_open
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !text.contains("tx.head rebuild begin"),
        "the shortened head rebuilds on the next open: {text}"
    );
    assert_eq!(
        t.get_by_txid(&txid1).unwrap().unwrap().0,
        rbitcoin_primitives::Fk(1)
    );
    assert_eq!(
        t.get_by_txid(&txid3).unwrap().unwrap().0,
        rbitcoin_primitives::Fk(2)
    );
}

/// A monolithic `tx.head` file is not a torn segment directory.
#[test]
fn legacy_mono_tx_head_still_refuses_open() {
    let dir = super::tempfile_dir("head-mono");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    drop(t);
    let root = dir.join("tx.head");
    std::fs::remove_dir_all(&root).unwrap();
    std::fs::write(&root, b"mono").unwrap();
    let msg = match TxTable::open_tiny(&dir) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("legacy mono head opened"),
    };
    assert!(msg.contains("legacy monolithic"), "{msg}");
}

/// Flat `tx.head.meta` is the pre-directory layout and still refuses.
#[test]
fn flat_tx_head_meta_still_refuses_open() {
    let dir = super::tempfile_dir("head-flat-meta");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    drop(t);
    std::fs::rename(dir.join("tx.head").join("meta"), dir.join("tx.head.meta")).unwrap();
    let msg = match TxTable::open_tiny(&dir) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("flat tx.head.meta opened"),
    };
    assert!(msg.contains("index refuses flat tx.head.meta"), "{msg}");
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

/// A torn `seqsigwit.prune` means the witness cut already happened.
/// Open keeps the creates the short witness locator no longer names.
#[test]
fn torn_prune_file_keeps_creates_past_the_witness_stem() {
    let dir = super::tempfile_dir("torn-prune-stem");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    let seq_end = on_disk_hwm(&t.seqsigwit_loc.loc);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    assert!(on_disk_hwm(&t.seqsigwit_loc.loc) > seq_end);
    set_disk_hwm(&t.seqsigwit_loc.loc, seq_end);
    drop(t);
    std::fs::write(dir.join("seqsigwit.prune"), []).unwrap();
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 2);
    assert_eq!(t.create_loc.count(), 2);
    assert_eq!(t.seqsigwit_loc.count(), 2);
    assert!(
        seqsigwit_bytes(&t, 2).iter().all(|&b| b == 0),
        "the create the short locator did not name has no witness"
    );
    let mut third = one(3);
    third.1[0].script_sig = vec![0xab];
    t.put_full_batch_indexed(&[third], false).unwrap();
    assert_eq!(t.count(), 3);
    assert_eq!(t.seqsigwit_loc.count(), 3);
    assert!(
        seqsigwit_bytes(&t, 2).iter().all(|&b| b == 0),
        "the next append must not reuse the gap slot"
    );
    assert_eq!(
        t.get_full(rbitcoin_primitives::Fk(3)).unwrap().1[0].script_sig,
        vec![0xab]
    );
    assert_eq!(outs(&t, 1)[0].script, vec![1]);
    assert_eq!(outs(&t, 2)[0].script, vec![2]);
}

/// A second torn locator starts past the first gap. The creates between
/// those fills already have a witness, so open must not mark them empty.
#[test]
fn later_fill_keeps_the_witness_between_two_gaps() {
    let dir = super::tempfile_dir("gap-between");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    let after_first = on_disk_hwm(&t.seqsigwit_loc.loc);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    set_disk_hwm(&t.seqsigwit_loc.loc, after_first);
    drop(t);
    std::fs::write(dir.join("seqsigwit.prune"), []).unwrap();
    let t = TxTable::open_tiny(&dir).unwrap();
    assert!(t.witness_row_is_gap(2));
    assert!(!t.witness_row_is_gap(1));
    let mut third = one(3);
    third.1[0].script_sig = vec![0xab];
    t.put_full_batch_indexed(&[third], false).unwrap();
    let after_third = on_disk_hwm(&t.seqsigwit_loc.loc);
    t.put_full_batch_indexed(&[one(4)], false).unwrap();
    set_disk_hwm(&t.seqsigwit_loc.loc, after_third);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert!(t.witness_row_is_gap(2), "the first empty row stays a gap");
    assert!(
        !t.witness_row_is_gap(3),
        "the witness between the fills is still a witness"
    );
    assert!(t.witness_row_is_gap(4), "the new short locator is a gap");
    assert!(!t.witness_row_is_gap(1));
    assert_eq!(
        t.get_full(rbitcoin_primitives::Fk(3)).unwrap().1[0].script_sig,
        vec![0xab]
    );
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert!(t.witness_row_is_gap(2));
    assert!(!t.witness_row_is_gap(3));
    assert!(t.witness_row_is_gap(4));
}

/// A short body header cuts the creates. A prune file must not leave the
/// witness locator, or a gap span, naming the creates that were dropped.
#[test]
fn witness_ahead_of_the_covered_prefix_is_cut_back() {
    let dir = super::tempfile_dir("witness-ahead");
    let t = TxTable::create_tiny(&dir).unwrap();
    let mut first = one(1);
    first.1[0].script_sig = vec![0x11];
    t.put_full_batch_indexed(&[first], false).unwrap();
    let tx_end = on_disk_hwm(&t.body.body);
    let sp_end = on_disk_hwm(&t.spent.body);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    let mut third = one(3);
    third.1[0].script_sig = vec![0x33];
    t.put_full_batch_indexed(&[third], false).unwrap();
    set_disk_hwm(&t.body.body, tx_end);
    set_disk_hwm(&t.spent.body, sp_end);
    drop(t);
    std::fs::write(dir.join("seqsigwit.prune"), []).unwrap();
    let mut gap = [0u8; 16];
    gap[..8].copy_from_slice(&1u64.to_le_bytes());
    gap[8..].copy_from_slice(&3u64.to_le_bytes());
    std::fs::write(dir.join("seqsigwit.gap"), gap).unwrap();

    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    assert_eq!(t.seqsigwit_loc.count(), 1);
    assert!(!t.witness_row_is_gap(1));
    let mut next = one(4);
    next.1[0].script_sig = vec![0x44];
    t.put_full_batch_indexed(&[next], false).unwrap();
    assert_eq!(t.count(), 2);
    assert_eq!(t.seqsigwit_loc.count(), 2);
    assert!(!t.witness_row_is_gap(2));
    assert_eq!(
        t.get_full(rbitcoin_primitives::Fk(2)).unwrap().1[0].script_sig,
        vec![0x44]
    );
    assert_eq!(
        t.get_full(rbitcoin_primitives::Fk(1)).unwrap().1[0].script_sig,
        vec![0x11]
    );
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.seqsigwit_loc.count(), 2);
    assert!(!t.witness_row_is_gap(2));
    assert_eq!(
        t.get_full(rbitcoin_primitives::Fk(2)).unwrap().1[0].script_sig,
        vec![0x44]
    );
}

/// The witness locator already names the covered prefix. The body counter
/// was opened at the longer create count and must come back before append.
#[test]
fn matched_witness_locator_resets_the_body_count() {
    let dir = super::tempfile_dir("witness-match");
    let t = TxTable::create_tiny(&dir).unwrap();
    let mut first = one(1);
    first.1[0].script_sig = vec![0x11];
    t.put_full_batch_indexed(&[first], false).unwrap();
    let tx_end = on_disk_hwm(&t.body.body);
    let sp_end = on_disk_hwm(&t.spent.body);
    let sw_end = on_disk_hwm(&t.seqsigwit_loc.loc);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    set_disk_hwm(&t.body.body, tx_end);
    set_disk_hwm(&t.spent.body, sp_end);
    set_disk_hwm(&t.seqsigwit_loc.loc, sw_end);
    drop(t);
    std::fs::write(dir.join("seqsigwit.prune"), []).unwrap();
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    assert_eq!(t.seqsigwit_loc.count(), 1);
    assert_eq!(t.seqsigwit.count(), 1);
    let mut next = one(3);
    next.1[0].script_sig = vec![0x33];
    t.put_full_batch_indexed(&[next], false).unwrap();
    assert_eq!(t.count(), 2);
    assert_eq!(t.seqsigwit.count(), 2);
    assert_eq!(t.seqsigwit_loc.count(), 2);
    assert_eq!(
        t.get_full(rbitcoin_primitives::Fk(2)).unwrap().1[0].script_sig,
        vec![0x33]
    );
    assert_eq!(
        t.get_full(rbitcoin_primitives::Fk(1)).unwrap().1[0].script_sig,
        vec![0x11]
    );
}

/// The witness stem was already cut to an empty locator. Open must not
/// invent an empty witness row for every create still in the chain.
#[test]
fn finished_witness_cut_does_not_fill_empty_rows() {
    let dir = super::tempfile_dir("witness-cut-zero");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    assert_eq!(t.count(), 2);
    t.cut_seqsigwit_stem_to_header().unwrap();
    assert_eq!(t.seqsigwit_loc.count(), 0);
    drop(t);
    std::fs::write(dir.join("seqsigwit.prune"), []).unwrap();
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 2);
    assert_eq!(t.seqsigwit_loc.count(), 0);
    assert_eq!(t.seqsigwit.count(), 0);
    assert!(!t.witness_row_is_gap(1));
    assert!(!t.witness_row_is_gap(2));
    assert!(
        !dir.join("seqsigwit.gap").exists(),
        "a finished cut is not an empty-witness span"
    );
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 2);
    assert_eq!(t.seqsigwit_loc.count(), 0);
    assert!(!t.witness_row_is_gap(1));
    assert!(!t.witness_row_is_gap(2));
}

/// Deleting a gap span past the covered count has to sync the directory.
/// A crash that restores the old dirent would hide a later witness.
#[test]
fn removing_a_witness_gap_syncs_the_directory() {
    let dir = super::tempfile_dir("witness-gap-dir");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    let tx_end = on_disk_hwm(&t.body.body);
    let sp_end = on_disk_hwm(&t.spent.body);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    set_disk_hwm(&t.body.body, tx_end);
    set_disk_hwm(&t.spent.body, sp_end);
    drop(t);
    std::fs::write(dir.join("seqsigwit.prune"), []).unwrap();
    let mut gap = [0u8; 16];
    gap[..8].copy_from_slice(&1u64.to_le_bytes());
    gap[8..].copy_from_slice(&3u64.to_le_bytes());
    std::fs::write(dir.join("seqsigwit.gap"), gap).unwrap();
    rbitcoin_store::file::arm_fsync_dir_trace();
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    assert!(!dir.join("seqsigwit.gap").exists());
    drop(t);
    let synced = rbitcoin_store::file::take_fsynced_dirs();
    assert!(
        synced.iter().any(|p| p == &dir),
        "the gap dirent delete must be durable; synced {synced:?}"
    );
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

/// A spend slot write must not extend the body header a missed locator left
/// as the commit. The body header of that wave may already be ahead; flush
/// keeps it, and the locator header stays at the previous create.
#[test]
fn spend_annotation_does_not_publish_a_withheld_body_end() {
    let dir = super::tempfile_dir("spend-withheld-body");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[one(1)], false).unwrap();
    let loc_end = on_disk_hwm(&t.create_loc.loc);
    let loc_fd = t.create_loc.loc.io_handle();
    rbitcoin_store::io_handle::arm_fail_hwm_pwrites(loc_fd, 1);
    let disarm = Disarm(loc_fd);
    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    drop(disarm);
    let spent_end = on_disk_hwm(&t.spent.body);
    assert!(t.spent.body_logical_len() >= spent_end);
    assert_eq!(on_disk_hwm(&t.create_loc.loc), loc_end);
    let pair = t
        .create_loc
        .range_batch(&[rbitcoin_primitives::Fk(1)])
        .unwrap()[0]
        .expect("create 1");
    t.set_output_spender_meta_at(
        pair.spent.0,
        pair.spent.1,
        0,
        false,
        rbitcoin_primitives::Fk(1),
        0,
    )
    .unwrap();
    assert_eq!(on_disk_hwm(&t.spent.body), spent_end);
    t.spent.body.flush().unwrap();
    assert_eq!(on_disk_hwm(&t.spent.body), spent_end);
    assert_eq!(on_disk_hwm(&t.create_loc.loc), loc_end);
}

/// A locator header pwrite that misses still publishes RAM. The body header
/// of that wave may land first. Flush does not then store the locator header.
/// The next connect retries it, and reopen sees both creates.
#[test]
fn locator_header_miss_retries_on_the_next_append() {
    let dir = super::tempfile_dir("loc-header-miss");
    let t = TxTable::create_tiny(&dir).unwrap();
    let loc_fd = t.create_loc.loc.io_handle();
    rbitcoin_store::io_handle::arm_fail_hwm_pwrites(loc_fd, 1);
    let disarm = Disarm(loc_fd);
    let before = FILE_HEADER_LEN as u64;
    t.put_full_batch_indexed(&[one(1)], false)
        .expect("a missed header pwrite is not a failed connect");
    drop(disarm);
    assert_eq!(t.create_loc.count(), 1);
    assert!(t.body.body_logical_len() > before);
    assert_eq!(on_disk_hwm(&t.create_loc.loc), before);
    t.body
        .with_bytes_at(before, 1, |_| Ok(()))
        .expect("in-process readers follow the RAM end");
    t.create_loc.loc.flush().unwrap();
    assert_eq!(
        on_disk_hwm(&t.create_loc.loc),
        before,
        "flush stored a locator header the pwrite had missed"
    );

    t.put_full_batch_indexed(&[one(2)], false).unwrap();
    assert!(on_disk_hwm(&t.create_loc.loc) > before);
    assert!(on_disk_hwm(&t.body.body) > before);
    assert!(on_disk_hwm(&t.seqsigwit.body) > before);
    assert!(on_disk_hwm(&t.spent.body) > before);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 2);
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

/// The overflow header misses, then a later block with no overflow row
/// commits. Reopen still returns that create's outputs.
#[test]
fn ovf_header_miss_then_plain_block_reopens_the_create() {
    let dir = super::tempfile_dir("ovf-header-retry");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[wide(1)], false).unwrap();
    let ovf_fd = t.create_loc.ovf.io_handle();
    rbitcoin_store::io_handle::arm_fail_hwm_pwrites(ovf_fd, 1);
    let disarm = Disarm(ovf_fd);
    t.put_full_batch_indexed(&[wide(2)], false).unwrap();
    drop(disarm);
    t.put_full_batch_indexed(&[one(3)], false).unwrap();
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 3);
    assert_eq!(outs(&t, 2).len(), 256);
    assert_eq!(outs(&t, 2)[0].script, vec![2, 0]);
    assert_eq!(outs(&t, 3)[0].script, vec![3]);
}

/// Every overflow header pwrite fails, including the later block's retry.
/// Reopen drops the unpublished create instead of keeping one that cannot
/// be decoded.
#[test]
fn ovf_header_miss_does_not_seal_the_create() {
    let dir = super::tempfile_dir("ovf-header-seal");
    let t = TxTable::create_tiny(&dir).unwrap();
    t.put_full_batch_indexed(&[wide(1)], false).unwrap();
    let ovf_fd = t.create_loc.ovf.io_handle();
    rbitcoin_store::io_handle::arm_fail_hwm_pwrites(ovf_fd, 8);
    let disarm = Disarm(ovf_fd);
    t.put_full_batch_indexed(&[wide(2)], false).unwrap();
    t.put_full_batch_indexed(&[one(3)], false).unwrap();
    drop(disarm);
    drop(t);
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    assert_eq!(outs(&t, 1).len(), 256);
    assert!(t.get_meta_and_outputs(rbitcoin_primitives::Fk(2)).is_err());
}
