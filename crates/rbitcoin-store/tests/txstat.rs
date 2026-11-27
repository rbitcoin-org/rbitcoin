use rbitcoin_primitives::Fk;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::testutil::TempDir;
use rbitcoin_store::txstat::*;

fn tiny(fee: u64, base: u32, wit: u32) -> TxStatRow {
    TxStatRow {
        fee_sat: fee,
        base,
        wit_extra: wit,
    }
}

#[test]
fn txstat_blob_longer_than_the_file_is_corrupt() {
    let err = checked_blob_len(1 << 30, 32).expect_err("huge len");
    match err {
        StoreError::Corrupt(msg) => assert!(msg.contains("txstat"), "{msg}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(checked_blob_len(4, 32).unwrap(), 4);
}

#[test]
fn page0_stamp_is_not_in_the_txstat_mark() {
    let dir = TempDir::labeled("txstat-page0").unwrap();
    // Past one page, so page 0 is not also the partial tail.
    let rows: Vec<TxStatRow> = (1..=600u64).map(|i| tiny(i, 100, 10)).collect();
    let stamped = tiny(9, 9, 9);
    {
        let t = TxStat::create(&dir).unwrap();
        t.append_batch(0, &rows).unwrap();
        // The trace sees an arm that is cleared before `write_row` returns.
        #[cfg(debug_assertions)]
        rbitcoin_store::page_guard::arm_store_mark_trace();
        t.write_row(Fk(1), &stamped).unwrap();
        #[cfg(debug_assertions)]
        assert!(
            !rbitcoin_store::page_guard::take_armed_store_marks()
                .iter()
                .any(|m| m == rbitcoin_store::page_guard::TXSTAT_MARK),
            "a page-0 stamp armed guard/txstat"
        );
        assert!(
            !dir.join("guard/txstat").exists(),
            "a page-0 stamp is the Class A first page, not this mark"
        );
    }
    let path = dir.join("txstat.body");
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    use std::io::{Seek, SeekFrom, Write};
    file.seek(SeekFrom::Start(32)).unwrap();
    file.write_all(&[0xA5; 8]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    rbitcoin_store::store::restore_open_marks(&rbitcoin_store::StoreLayout::tiny(dir.path()))
        .unwrap();
    let t = TxStat::open(&dir).unwrap();
    assert_eq!(t.get_cell(Fk(1)).unwrap(), [0xA5; 8]);
    assert_ne!(t.get_cell(Fk(1)).unwrap(), pack_cell(&stamped).unwrap().0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(debug_assertions)]
#[test]
fn torn_interior_txstat_page_restores_the_pre_stamp_bytes() {
    let dir = TempDir::labeled("txstat-interior").unwrap();
    let path = dir.join("txstat.body");
    let rows: Vec<TxStatRow> = (1..=1200u64).map(|i| tiny(i, 100, 10)).collect();
    let old = pack_cell(&rows[599]).unwrap().0;
    {
        let t = TxStat::create(&dir).unwrap();
        t.append_batch(0, &rows).unwrap();
        assert!(!dir.join("guard/txstat").exists());
        fail_next_txstat_guard_before_clear(&path);
        assert!(
            t.write_row(Fk(600), &tiny(9, 9, 9)).is_err(),
            "the failpoint stops after the live pwrite, before the mark is cleared"
        );
        assert!(dir.join("guard/txstat").is_file());
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    use std::io::{Seek, SeekFrom, Write};
    file.seek(SeekFrom::Start(4096)).unwrap();
    file.write_all(&[0xA5; 4096]).unwrap();
    file.sync_all().unwrap();
    drop(file);
    rbitcoin_store::store::restore_open_marks(&rbitcoin_store::StoreLayout::tiny(dir.path()))
        .unwrap();
    assert!(!dir.join("guard/txstat").exists());
    let t = TxStat::open(&dir).unwrap();
    assert_eq!(t.count(), 1200);
    assert_eq!(t.get_cell(Fk(600)).unwrap(), old);
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(debug_assertions)]
#[test]
fn a_later_stamp_repairs_the_page_a_failed_stamp_tore() {
    let dir = TempDir::labeled("txstat-second-stamp").unwrap();
    let path = dir.join("txstat.body");
    let rows: Vec<TxStatRow> = (1..=1200u64).map(|i| tiny(i, 100, 10)).collect();
    let old = pack_cell(&rows[599]).unwrap().0;
    let later = tiny(7, 7, 7);
    {
        let t = TxStat::create(&dir).unwrap();
        t.append_batch(0, &rows).unwrap();
        fail_next_txstat_guard_before_clear(&path);
        assert!(t.write_row(Fk(600), &tiny(9, 9, 9)).is_err());
        assert!(dir.join("guard/txstat").is_file());
        t.write_row(Fk(1100), &later).unwrap();
        assert_eq!(t.get_cell(Fk(600)).unwrap(), old);
        assert_eq!(t.get_cell(Fk(1100)).unwrap(), pack_cell(&later).unwrap().0);
    }
    assert!(!dir.join("guard/txstat").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn create_empty_then_extend_zeros() {
    let dir = TempDir::labeled("txstat-extend").unwrap();
    let t = TxStat::create(&dir).unwrap();
    assert_eq!(t.count(), 0);
    t.extend_or_truncate_to(2).unwrap();
    assert_eq!(t.count(), 2);
    assert_eq!(t.get_cell(Fk(1)).unwrap(), [0u8; 8]);
    assert_eq!(t.get_cell(Fk(2)).unwrap(), [0u8; 8]);
    t.truncate_to_count(1).unwrap();
    assert_eq!(t.count(), 1);
    assert!(t.get_cell(Fk(2)).is_err());
}

#[test]
fn uleb_typical_fits_in_cell() {
    let row = tiny(1000, 110, 112);
    let (cell, tail) = pack_cell(&row).unwrap();
    assert!(tail.is_none());
    assert_eq!(parse_cell(cell).unwrap(), CellParse::Complete(row));
    assert_eq!(row.size(), 222);
    assert_eq!(row.weight(), 4 * 110 + 112);
}

#[test]
fn former_n_in_byte_no_longer_forces_a_tail() {
    let row = tiny(50_000, 200, 200_000);
    let (cell, tail) = pack_cell(&row).unwrap();
    assert!(tail.is_none(), "three fields of this row fit in 8 B");
    assert_eq!(parse_cell(cell).unwrap(), CellParse::Complete(row));
}

#[test]
fn overflow_is_remaining_bytes_only() {
    let row = tiny(u64::from(u32::MAX), 4_000_000, 4_000_000);
    let stream = encode_stream(&row).unwrap();
    assert!(stream.len() > 8, "wide fee and sizes must miss 8 B");
    let (cell, tail) = pack_cell(&row).unwrap();
    let tail = tail.expect("tail");
    assert_eq!(tail.as_slice(), &stream[8..]);
    assert_eq!(parse_cell(cell).unwrap(), CellParse::NeedTail);
    assert_eq!(parse_with_tail(cell, &tail).unwrap(), row);
}

#[test]
fn header_blob_roundtrip() {
    let dir = TempDir::labeled("txstat-ovf").unwrap();
    let t = TxStat::create(&dir).unwrap();
    let small = tiny(1000, 110, 0);
    let fat = tiny(u64::from(u32::MAX), 4_000_000, 4_000_000);
    t.append_batch(0, &[small, fat]).unwrap();
    t.write_block_rows(Fk(1), 1, &[small, fat]).unwrap();
    let blob = t.header_blob(Fk(1)).unwrap();
    assert!(!blob.is_empty());
    let got = t.get_range(1, 2, Some(&blob)).unwrap();
    assert_eq!(got[0], Some(small));
    assert_eq!(got[1], Some(fat));
    assert_eq!(t.get_row_merged(Fk(2), 1, &blob).unwrap(), Some(fat));
}

#[test]
fn leftover_txfixed_body_unlinked_on_open() {
    let dir = TempDir::labeled("txstat-leftover").unwrap();
    std::fs::write(dir.join("txfixed.body"), b"junk").unwrap();
    let _t = TxStat::open(&dir).unwrap();
    assert!(!dir.join("txfixed.body").exists());
    assert!(dir.join("txstat.body").is_file());
}

#[test]
fn range_reads_the_cell_and_header_blob_reads_the_slot() {
    let dir = TempDir::labeled("txstat-slot").unwrap();
    let t = TxStat::create(&dir).unwrap();
    let small = tiny(1000, 110, 0);
    let fat = tiny(u64::from(u32::MAX), 4_000_000, 4_000_000);
    t.append_batch(0, &[small, fat]).unwrap();
    assert_eq!(t.get_range(1, 1, None).unwrap(), vec![Some(small)]);
    let err = match t.get_range(1, 4, None) {
        Ok(_) => panic!("range accepted a fk past the count"),
        Err(err) => err,
    };
    assert!(matches!(err, StoreError::NotFound), "{err:?}");

    assert!(t.header_blob(Fk(1)).unwrap().is_empty());
    t.write_block_rows(Fk(1), 1, &[small, fat]).unwrap();
    let blob = t.header_blob(Fk(1)).unwrap();
    assert!(!blob.is_empty());
    let got = t.get_range(1, 2, Some(&blob)).unwrap();
    assert_eq!(got[0], Some(small));
    assert_eq!(got[1], Some(fat));
    assert!(t.header_blob(Fk(2)).unwrap().is_empty());
}

/// Readers stamp unstamped blocks (Esplora block routes, `getblock`), so
/// `put_header_blob` runs on several threads at once. Each header must read
/// back its own blob. Equal-length blobs make a shared offset silent: the
/// slot still decodes, with another block's tails.
#[test]
fn concurrent_header_blobs_keep_their_own_bytes() {
    const THREADS: u64 = 8;
    const PER: u64 = 400;
    let dir = TempDir::labeled("txstat-ovf-race").unwrap();
    let t = std::sync::Arc::new(TxStat::create(&dir).unwrap());
    let blob_for = |fk: u64| {
        let tail = fk.to_le_bytes().repeat(4);
        encode_ovf_blob(&[(1, tail)]).unwrap()
    };
    let start = std::sync::Arc::new(std::sync::Barrier::new(THREADS as usize));
    let handles: Vec<_> = (0..THREADS)
        .map(|i| {
            let t = std::sync::Arc::clone(&t);
            let start = std::sync::Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                for k in 0..PER {
                    let fk = 1 + k * THREADS + i;
                    t.put_header_blob(Fk(fk), &blob_for(fk)).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let total: u64 = (1..=THREADS * PER)
        .map(|fk| blob_for(fk).len() as u64)
        .sum();
    assert_eq!(
        t.ovf.data_len(),
        total,
        "appends neither overlap nor leave gaps"
    );
    let wrong: Vec<u64> = (1..=THREADS * PER)
        .filter(|&fk| t.header_blob(Fk(fk)).unwrap() != blob_for(fk))
        .collect();
    assert!(wrong.is_empty(), "headers read another blob: {wrong:?}");
}

#[test]
fn open_refuses_a_legacy_txstat_ahead_journal() {
    let dir = TempDir::labeled("txstat-legacy-ahead").unwrap();
    let t = TxStat::create(&dir).unwrap();
    t.append_batch(0, &[tiny(1, 2, 3)]).unwrap();
    drop(t);
    std::fs::write(dir.join("txstat.body.ahead"), b"TTA1").unwrap();
    let err = match TxStat::open(&dir) {
        Ok(_) => panic!("open accepted a legacy ahead journal"),
        Err(err) => err,
    };
    match err {
        StoreError::Corrupt(msg) => assert!(msg.contains("txstat.body.ahead"), "{msg}"),
        other => panic!("{other:?}"),
    }
    let _ = std::fs::remove_dir_all(dir.path());
}

#[test]
fn append_batch_relies_on_the_class_a_tail_guard() {
    let dir = TempDir::labeled("txstat-append-no-ahead").unwrap();
    let t = TxStat::create(&dir).unwrap();
    t.append_batch(0, &[tiny(1, 2, 3)]).unwrap();
    assert_eq!(t.count(), 1);
    // The trace sees an arm that is cleared before the append returns.
    #[cfg(debug_assertions)]
    rbitcoin_store::page_guard::arm_store_mark_trace();
    let rows: Vec<TxStatRow> = (2..=1200u64).map(|i| tiny(i, 100, 10)).collect();
    t.append_batch(1, &rows).unwrap();
    #[cfg(debug_assertions)]
    assert!(
        !rbitcoin_store::page_guard::take_armed_store_marks()
            .iter()
            .any(|m| m == rbitcoin_store::page_guard::TXSTAT_MARK),
        "an append armed guard/txstat"
    );
    assert!(!dir.join("txstat.body.ahead").exists());
    assert!(
        !dir.join("guard/txstat").exists(),
        "an append-only batch stays on the Class A tail guard"
    );
    // An interior stamp does arm it, so the trace is live.
    #[cfg(debug_assertions)]
    {
        rbitcoin_store::page_guard::arm_store_mark_trace();
        t.write_row(Fk(600), &tiny(9, 9, 9)).unwrap();
        assert!(rbitcoin_store::page_guard::take_armed_store_marks()
            .iter()
            .any(|m| m == rbitcoin_store::page_guard::TXSTAT_MARK));
    }
    let _ = std::fs::remove_dir_all(dir.path());
}

/// The slot sync in `put_header_blob` must not publish a slot whose blob
/// bytes and `txstat.ovf` length are still unsynced. A failed overflow sync
/// stops the put before the slot is stamped.
#[cfg(debug_assertions)]
#[test]
fn header_blob_syncs_the_overflow_before_its_slot() {
    let dir = TempDir::labeled("txstat-ovf-order").unwrap();
    let t = TxStat::create(&dir).unwrap();
    t.flush().unwrap();
    let blob = encode_ovf_blob(&[(1, vec![0x5Au8; 32])]).unwrap();
    rbitcoin_store::io_handle::arm_fail_sync(t.ovf.io_handle(), 1);
    assert!(
        t.put_header_blob(Fk(1), &blob).is_err(),
        "the slot was stamped without syncing txstat.ovf"
    );
    assert!(t.header_blob(Fk(1)).unwrap().is_empty());
    t.put_header_blob(Fk(1), &blob).unwrap();
    assert_eq!(t.header_blob(Fk(1)).unwrap(), blob);
}
