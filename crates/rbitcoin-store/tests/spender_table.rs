use rbitcoin_primitives::Fk;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::file::FILE_HEADER_LEN;
use rbitcoin_store::spender_table::*;
use rbitcoin_store::Store;

#[test]
fn append_get_chain() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spender-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = SpenderTable::create(&dir).unwrap();
    assert!(dir.join("spent.ovf").exists(), "schema 17 name");
    assert!(
        !dir.join("spenders.body").exists(),
        "legacy filename must not be created"
    );
    let a = t.append(Fk(10), 3, Fk::NULL).unwrap();
    let b = t.append(Fk(11), 4, a).unwrap();
    assert_eq!(t.get(a).unwrap(), (Fk(10), 3, Fk::NULL));
    assert_eq!(t.get(b).unwrap(), (Fk(11), 4, a));
    assert_eq!(t.count(), 2);
    assert!(matches!(
        t.append(Fk::NULL, 0, Fk::NULL),
        Err(StoreError::InvalidFk)
    ));
    assert!(matches!(t.get(Fk::NULL), Err(StoreError::InvalidFk)));
    assert!(matches!(t.get(Fk(99)), Err(StoreError::NotFound)));
    let freeze_dir = rbitcoin_store::testutil::TempDir::labeled("spender-freeze").unwrap();
    let freeze = Store::create_tiny(freeze_dir.path()).unwrap();
    let g = freeze.hold_utxo_view();
    t.flush(&SpenderFreeze::new(&g)).unwrap();
    t.flush_async().unwrap();
    drop(t);
    let t = SpenderTable::open(&dir).unwrap();
    assert_eq!(t.count(), 2);
    assert_eq!(t.get(a).unwrap(), (Fk(10), 3, Fk::NULL));
    let dir2 = dir.with_extension("empty");
    let _ = std::fs::remove_dir_all(&dir2);
    std::fs::create_dir_all(&dir2).unwrap();
    let t2 = SpenderTable::open(&dir2).unwrap();
    assert_eq!(t2.count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn open_rejects_bad_body_size() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spender-bad-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = SpenderTable::create(&dir).unwrap();
    t.append(Fk(1), 0, Fk::NULL).unwrap();
    drop(t);
    // Shrink below HWM so open clamps logical_len to a non-multiple of 16.
    let body = dir.join("spent.ovf");
    std::fs::OpenOptions::new()
        .write(true)
        .open(&body)
        .unwrap()
        .set_len((FILE_HEADER_LEN + 3) as u64)
        .unwrap();
    assert!(matches!(
        SpenderTable::open(&dir),
        Err(StoreError::Corrupt(_))
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_renames_leftover_spenders_body_to_spent_ovf() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spender-legacy-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    {
        let t = SpenderTable::create(&dir).unwrap();
        t.append(Fk(7), 9, Fk::NULL).unwrap();
        let freeze_dir =
            rbitcoin_store::testutil::TempDir::labeled("spender-legacy-freeze").unwrap();
        let freeze = Store::create_tiny(freeze_dir.path()).unwrap();
        let g = freeze.hold_utxo_view();
        t.flush(&SpenderFreeze::new(&g)).unwrap();
    }
    std::fs::rename(dir.join("spent.ovf"), dir.join("spenders.body")).unwrap();
    assert!(!dir.join("spent.ovf").exists());
    let t = SpenderTable::open(&dir).unwrap();
    assert!(dir.join("spent.ovf").exists());
    assert!(!dir.join("spenders.body").exists());
    assert_eq!(t.count(), 1);
    assert_eq!(t.get(Fk(1)).unwrap(), (Fk(7), 9, Fk::NULL));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn append_fk_or_vin_overflow_is_corrupt() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spender-ovf-cap-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = SpenderTable::create(&dir).unwrap();
    match t.append(Fk(1u64 << 40), 0, Fk::NULL) {
        Err(StoreError::Corrupt(m)) => assert!(m.contains("u40"), "{m}"),
        other => panic!("expected u40 Corrupt, got {other:?}"),
    }
    match t.append(Fk(1), 1u32 << 16, Fk::NULL) {
        Err(StoreError::Corrupt(m)) => assert!(m.contains("u16"), "{m}"),
        other => panic!("expected u16 Corrupt, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn spender_get_reads_the_packed_record() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-spender-fields-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = SpenderTable::create(&dir).unwrap();
    let next = Fk(0x1111_2222_3333_4444);
    let id = t.append(Fk(0x0102_0304), 0x0107, next).unwrap();
    assert_eq!(t.get(id).unwrap(), (Fk(0x0102_0304), 0x0107, next));
    match t.get(Fk(99)) {
        Err(StoreError::NotFound) => {}
        other => panic!("missing spender must be NotFound, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

const PAGE: usize = 4096;

fn page_at(path: &std::path::Path, off: u64) -> Vec<u8> {
    let mut file = std::fs::File::open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let mut buf = vec![0u8; PAGE];
    if off >= len {
        return buf;
    }
    let n = ((len - off) as usize).min(PAGE);
    std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(off)).unwrap();
    std::io::Read::read_exact(&mut file, &mut buf[..n]).unwrap();
    buf
}

/// A later append must finish the guard directory sync when the mark is
/// already present. The first arm's rename can land while that sync fails.
#[test]
fn a_later_append_syncs_the_guard_directory() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("spent-ovf-arm-retry").unwrap();
    let t = SpenderTable::create(dir.path()).unwrap();
    t.append(Fk(1), 1, Fk::NULL).unwrap();
    let guard = dir.path().join("guard");
    assert!(guard.join("spent.ovf").is_file());
    #[cfg(unix)]
    {
        rbitcoin_store::file::arm_fsync_dir_trace();
        t.append(Fk(2), 2, Fk::NULL).unwrap();
        let dirs = rbitcoin_store::file::take_fsynced_dirs();
        assert!(
            dirs.iter().any(|d| d == &guard),
            "a retry must sync guard/ before it writes, got {dirs:?}"
        );
    }
    #[cfg(not(unix))]
    t.append(Fk(2), 2, Fk::NULL).unwrap();
}

/// Flush before any spent.ovf append. `guard/` may not exist yet, and
/// retiring a mark that was never armed must not fail looking for it.
#[test]
fn flush_before_any_spent_ovf_append_does_not_need_guard() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("spent-ovf-no-guard").unwrap();
    let path = dir.path().to_path_buf();
    let s = Store::create_tiny(&path).unwrap();
    let guard = path.join("guard");
    if guard.exists() {
        std::fs::remove_dir_all(&guard).unwrap();
    }
    let g = s.hold_utxo_view();
    s.spenders.sync_data_only(&SpenderFreeze::new(&g)).unwrap();
    assert!(!path.join("guard/spent.ovf").exists());
}

/// A checkpoint whose mark is already gone must still sync `guard/`.
/// Unlink can land while that directory sync fails.
#[test]
fn clear_of_a_missing_spent_ovf_mark_syncs_the_guard_directory() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("spent-ovf-clear-retry").unwrap();
    let path = dir.path().to_path_buf();
    let s = Store::create_tiny(&path).unwrap();
    s.spenders.append(Fk(1), 1, Fk::NULL).unwrap();
    let mark = path.join("guard/spent.ovf");
    std::fs::remove_file(&mark).unwrap();
    #[cfg(unix)]
    {
        rbitcoin_store::file::arm_fsync_dir_trace();
        let g = s.hold_utxo_view();
        s.spenders.sync_data_only(&SpenderFreeze::new(&g)).unwrap();
        let dirs = rbitcoin_store::file::take_fsynced_dirs();
        let guard = path.join("guard");
        assert!(
            dirs.iter().any(|d| d == &guard),
            "a missing mark must still sync guard/, got {dirs:?}"
        );
    }
    #[cfg(not(unix))]
    {
        let g = s.hold_utxo_view();
        s.spenders.sync_data_only(&SpenderFreeze::new(&g)).unwrap();
    }
    assert!(!mark.exists());
}

/// A fixture with no `meta` still arms. The mark is the pre-append pages.
#[test]
fn fixture_without_meta_arms_spent_ovf_once() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("spent-ovf-nometa").unwrap();
    let t = SpenderTable::create(dir.path()).unwrap();
    assert!(!dir.path().join("meta").exists());
    let mark = dir.path().join("guard/spent.ovf");
    t.append(Fk(1), 1, Fk::NULL).unwrap();
    assert!(mark.is_file(), "a fixture with no meta still arms");
    assert!(!dir.path().join("meta").exists());
    let armed = std::fs::read(&mark).unwrap();
    t.append(Fk(2), 2, Fk::NULL).unwrap();
    assert_eq!(
        std::fs::read(&mark).unwrap(),
        armed,
        "a later append must not snapshot the torn page"
    );
}

/// Sync clears the mark. A crash that leaves it restores the pre-append
/// pages, including a tail past page 0, and does not keep the torn bytes.
#[test]
fn torn_spent_ovf_reopens_as_the_pre_append_pages() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("spent-ovf-restore").unwrap();
    let path = dir.path().to_path_buf();
    let committed = 256u64;
    let mark = path.join("guard/spent.ovf");
    let ovf = path.join("spent.ovf");
    let tail_off = 4096u64;
    let pre_tail;
    let pre_page0;
    let kept;
    {
        let s = Store::create_tiny(&path).unwrap();
        for i in 1..=committed {
            s.spenders.append(Fk(i), i as u32, Fk::NULL).unwrap();
        }
        {
            let g = s.hold_utxo_view();
            s.spenders.sync_data_only(&SpenderFreeze::new(&g)).unwrap();
        }
        assert!(!mark.exists(), "sync clears the spent.ovf mark");
        assert_eq!(s.spenders.count(), committed);
        kept = s.spenders.get(Fk(committed)).unwrap();
        pre_page0 = page_at(&ovf, 0);
        pre_tail = page_at(&ovf, tail_off);
        let first = s.spenders.append(Fk(committed + 1), 1, Fk::NULL).unwrap();
        assert!(mark.is_file());
        let armed = std::fs::read(&mark).unwrap();
        let second = s.spenders.append(Fk(committed + 2), 2, first).unwrap();
        assert_eq!(std::fs::read(&mark).unwrap(), armed);
        assert_eq!(s.spenders.count(), committed + 2);
        let _ = (second, first);
    }
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&ovf).unwrap();
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(0)).unwrap();
        std::io::Write::write_all(&mut file, &[0xffu8; PAGE]).unwrap();
        std::io::Seek::seek(&mut file, std::io::SeekFrom::Start(tail_off)).unwrap();
        std::io::Write::write_all(&mut file, &[0xffu8; PAGE]).unwrap();
        file.sync_all().unwrap();
    }
    assert!(mark.is_file(), "the crash leaves the mark");
    let s = Store::open_tiny(&path).unwrap();
    assert!(!mark.exists(), "open removes the mark");
    assert_eq!(s.spenders.count(), committed);
    assert_eq!(s.spenders.get(Fk(committed)).unwrap(), kept);
    assert!(matches!(
        s.spenders.get(Fk(committed + 1)),
        Err(StoreError::NotFound)
    ));
    assert_eq!(page_at(&ovf, 0), pre_page0);
    assert_eq!(page_at(&ovf, tail_off), pre_tail);
    assert_ne!(page_at(&ovf, 0), vec![0xffu8; PAGE]);
}

/// A sync that returns an error leaves the mark. A later sync that would
/// otherwise succeed still leaves it: a retried fsync can return 0 after
/// the kernel dropped the dirty pages.
#[test]
fn failed_spent_ovf_sync_leaves_the_mark_armed() {
    let dir = rbitcoin_store::testutil::TempDir::labeled("spent-ovf-latch").unwrap();
    let path = dir.path().to_path_buf();
    let mark = path.join("guard/spent.ovf");
    let s = Store::create_tiny(&path).unwrap();
    s.spenders.append(Fk(1), 1, Fk::NULL).unwrap();
    assert!(mark.is_file(), "the first append arms");
    let handle = s.spenders.body.io_handle();
    rbitcoin_store::io_handle::arm_fail_sync(handle, 1);
    let g = s.hold_utxo_view();
    let freeze = SpenderFreeze::new(&g);
    let err = s.spenders.sync_data_only(&freeze).unwrap_err();
    assert!(mark.is_file(), "a failed sync leaves the mark: {err}");
    let err = s.spenders.sync_data_only(&freeze).unwrap_err();
    assert!(
        mark.is_file(),
        "a retry must not clear the mark after a failed sync: {err}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("earlier spent.ovf sync failed"),
        "the retry must be the latch, got {msg}"
    );
}
