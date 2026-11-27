//! A mark of whole 4 KiB images, and an append that stays off those pages.
use rbitcoin_primitives::{SCHEMA_VERSION, STORE_MAGIC};
use rbitcoin_store::page_guard::{
    append_past_end, arm_page_guard, arm_page_guard_group, clear_page_guard, restore_page_guard,
    restore_page_guard_group,
};
use rbitcoin_store::testutil::TempDir;
use rbitcoin_store::StoreError;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const PAGE: usize = 4096;

fn fill(byte: u8) -> Vec<u8> {
    vec![byte; PAGE]
}

fn write_bytes(path: &Path, off: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap();
    let end = off + bytes.len() as u64;
    if file.metadata().unwrap().len() < end {
        file.set_len(end).unwrap();
    }
    file.seek(SeekFrom::Start(off)).unwrap();
    file.write_all(bytes).unwrap();
}

fn read_bytes(path: &Path, off: u64, n: usize) -> Vec<u8> {
    let mut file = std::fs::File::open(path).unwrap();
    file.seek(SeekFrom::Start(off)).unwrap();
    let mut buf = vec![0u8; n];
    file.read_exact(&mut buf).unwrap();
    buf
}

fn open_rw(path: &Path) -> std::fs::File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .unwrap()
}

#[test]
fn backward_restore_puts_the_preimage_back() {
    let dir = TempDir::labeled("page-guard-back").unwrap();
    let live = dir.path().join("live");
    let mark = dir.path().join("guard");
    let pre = fill(0x11);
    write_bytes(&live, 0, &pre);
    arm_page_guard(&mark, &[(0, &pre)]).unwrap();
    write_bytes(&live, 0, &fill(0x22));
    let file = open_rw(&live);
    assert!(restore_page_guard(&mark, &file, &live).unwrap());
    drop(file);
    assert_eq!(read_bytes(&live, 0, PAGE), pre);
    assert!(!mark.exists());
}

#[test]
fn forward_restore_writes_the_armed_image() {
    let dir = TempDir::labeled("page-guard-fwd").unwrap();
    let live = dir.path().join("live");
    let mark = dir.path().join("guard");
    write_bytes(&live, 0, &fill(0x11));
    let next = fill(0x33);
    arm_page_guard(&mark, &[(0, &next)]).unwrap();
    write_bytes(&live, 100, &[0xAB; 50]);
    let file = open_rw(&live);
    assert!(restore_page_guard(&mark, &file, &live).unwrap());
    drop(file);
    assert_eq!(read_bytes(&live, 0, PAGE), next);
    assert!(!mark.exists());
}

#[test]
fn restore_copies_every_armed_page() {
    let dir = TempDir::labeled("page-guard-two").unwrap();
    let live = dir.path().join("live");
    let mark = dir.path().join("guard");
    let first = fill(0x41);
    let second = fill(0x42);
    write_bytes(&live, 0, &first);
    write_bytes(&live, PAGE as u64, &second);
    arm_page_guard(&mark, &[(0, &first), (PAGE as u64, &second)]).unwrap();
    write_bytes(&live, 0, &fill(0x00));
    write_bytes(&live, PAGE as u64, &fill(0x00));
    let file = open_rw(&live);
    assert!(restore_page_guard(&mark, &file, &live).unwrap());
    drop(file);
    assert_eq!(read_bytes(&live, 0, PAGE), first);
    assert_eq!(read_bytes(&live, PAGE as u64, PAGE), second);
    assert!(!mark.exists());
}

#[test]
fn missing_mark_leaves_the_mixed_page() {
    let dir = TempDir::labeled("page-guard-absent").unwrap();
    let live = dir.path().join("live");
    let mark = dir.path().join("guard");
    let mixed = fill(0x44);
    write_bytes(&live, 0, &mixed);
    let file = open_rw(&live);
    assert!(!restore_page_guard(&mark, &file, &live).unwrap());
    clear_page_guard(&mark, &file, &live).unwrap();
    drop(file);
    assert_eq!(read_bytes(&live, 0, PAGE), mixed);
    assert!(!mark.exists());
}

#[test]
fn a_mark_that_does_not_parse_is_not_absence() {
    let dir = TempDir::labeled("page-guard-bad").unwrap();
    let live = dir.path().join("live");
    let mark = dir.path().join("guard");
    let mixed = fill(0x55);
    write_bytes(&live, 0, &mixed);
    std::fs::write(&mark, b"nope").unwrap();
    let file = open_rw(&live);
    let err = restore_page_guard(&mark, &file, &live).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)));
    drop(file);
    assert_eq!(read_bytes(&live, 0, PAGE), mixed);
    assert!(mark.exists());

    let mut raw = Vec::new();
    raw.extend_from_slice(&STORE_MAGIC);
    raw.extend_from_slice(&1u16.to_le_bytes());
    raw.extend_from_slice(&0u16.to_le_bytes());
    raw.extend_from_slice(&1u32.to_le_bytes());
    raw.extend_from_slice(&0u64.to_le_bytes());
    raw.extend_from_slice(&mixed);
    std::fs::write(&mark, &raw).unwrap();
    let file = open_rw(&live);
    let err = restore_page_guard(&mark, &file, &live).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)));
    drop(file);
    assert_eq!(read_bytes(&live, 0, PAGE), mixed);

    raw[4..6].copy_from_slice(&SCHEMA_VERSION.to_le_bytes());
    raw[6] = 1;
    std::fs::write(&mark, &raw).unwrap();
    let file = open_rw(&live);
    let err = restore_page_guard(&mark, &file, &live).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)));
    drop(file);
    assert_eq!(read_bytes(&live, 0, PAGE), mixed);
    assert!(mark.exists());
}

#[test]
fn arm_refuses_a_page_that_is_not_one_image() {
    let dir = TempDir::labeled("page-guard-arm").unwrap();
    let mark = dir.path().join("guard");
    let page = fill(0x01);
    let err = arm_page_guard(&mark, &[]).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)));
    let err = arm_page_guard(&mark, &[(100, &page)]).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)));
    let err = arm_page_guard(&mark, &[(0, &page[..10])]).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)));
    let err = arm_page_guard(&mark, &[(0, &page), (0, &page)]).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)));
    assert!(!mark.exists());
}

#[test]
fn arm_refuses_a_second_mark_and_a_bare_name() {
    let dir = TempDir::labeled("page-guard-twice").unwrap();
    let mark = dir.path().join("guard");
    let live = dir.path().join("live");
    let page = fill(0x01);
    arm_page_guard(&mark, &[(0, &page)]).unwrap();
    let before = std::fs::read(&mark).unwrap();
    let err = arm_page_guard(&mark, &[(0, &page)]).unwrap_err();
    assert!(matches!(err, StoreError::Rejected(_)));
    assert_eq!(std::fs::read(&mark).unwrap(), before);

    let bare = Path::new("page-guard-bare-name");
    let err = arm_page_guard(bare, &[(0, &page)]).unwrap_err();
    assert!(matches!(err, StoreError::Rejected(_)));
    let file = open_rw(&live);
    let err = clear_page_guard(bare, &file, &live).unwrap_err();
    assert!(matches!(err, StoreError::Rejected(_)));
    let err = restore_page_guard(bare, &file, &live).unwrap_err();
    assert!(matches!(err, StoreError::Rejected(_)));
}

#[test]
fn clear_of_a_missing_mark_syncs_the_directory() {
    let dir = TempDir::labeled("page-guard-clear-missing").unwrap();
    let live = dir.path().join("live");
    let mark = dir.path().join("guard");
    write_bytes(&live, 0, &fill(0x11));
    let file = open_rw(&live);
    #[cfg(unix)]
    {
        rbitcoin_store::file::arm_fsync_dir_trace();
        clear_page_guard(&mark, &file, &live).unwrap();
        let dirs = rbitcoin_store::file::take_fsynced_dirs();
        assert!(
            dirs.iter().any(|d| d == dir.path()),
            "a retry after the unlink must still sync the directory, got {dirs:?}"
        );
    }
    #[cfg(not(unix))]
    clear_page_guard(&mark, &file, &live).unwrap();
}

#[test]
fn arm_syncs_the_store_directory_when_guard_is_new() {
    let dir = TempDir::labeled("page-guard-new-dir").unwrap();
    let mark = dir.path().join("guard").join("mark");
    let page = fill(0x01);
    #[cfg(unix)]
    {
        rbitcoin_store::file::arm_fsync_dir_trace();
        arm_page_guard(&mark, &[(0, &page)]).unwrap();
        let dirs = rbitcoin_store::file::take_fsynced_dirs();
        assert!(
            dirs.iter().any(|d| d == dir.path()),
            "a new guard directory must be durable in the store directory, got {dirs:?}"
        );
    }
    #[cfg(not(unix))]
    arm_page_guard(&mark, &[(0, &page)]).unwrap();
    assert!(mark.is_file());
}

#[test]
fn arm_syncs_the_store_directory_when_guard_already_exists() {
    let dir = TempDir::labeled("page-guard-old-dir").unwrap();
    let guard = dir.path().join("guard");
    std::fs::create_dir(&guard).unwrap();
    let mark = guard.join("mark");
    let page = fill(0x01);
    #[cfg(unix)]
    {
        rbitcoin_store::file::arm_fsync_dir_trace();
        arm_page_guard(&mark, &[(0, &page)]).unwrap();
        let dirs = rbitcoin_store::file::take_fsynced_dirs();
        assert!(
            dirs.iter().any(|d| d == dir.path()),
            "a guard directory left by a failed sync must still be synced, got {dirs:?}"
        );
    }
    #[cfg(not(unix))]
    arm_page_guard(&mark, &[(0, &page)]).unwrap();
    assert!(mark.is_file());
}

#[test]
fn append_past_end_writes_only_a_fresh_page() {
    let dir = TempDir::labeled("page-guard-append").unwrap();
    let path = dir.path().join("live");
    let file = open_rw(&path);
    file.set_len(100).unwrap();

    let err = append_past_end(&file, &path, 100, 100, &[1, 2, 3]).unwrap_err();
    assert!(matches!(err, StoreError::Rejected(_)));
    let err = append_past_end(&file, &path, 4096, 0, &fill(0x01)).unwrap_err();
    assert!(matches!(err, StoreError::Rejected(_)));
    append_past_end(&file, &path, 100, 50, &[]).unwrap();
    append_past_end(&file, &path, 100, 4096, &[9u8; 16]).unwrap();
    drop(file);
    assert_eq!(read_bytes(&path, 4096, 16), vec![9u8; 16]);
    assert_eq!(read_bytes(&path, 0, 100), vec![0u8; 100]);

    let path = dir.path().join("fresh");
    let file = open_rw(&path);
    let image = fill(0x66);
    append_past_end(&file, &path, 0, 0, &image).unwrap();
    drop(file);
    assert_eq!(read_bytes(&path, 0, PAGE), image);

    let path = dir.path().join("span");
    let file = open_rw(&path);
    file.set_len(4096).unwrap();
    append_past_end(&file, &path, 4096, 4096, &fill(0x77)).unwrap();
    let err = append_past_end(&file, &path, 5000, 4096, &[1u8; 8]).unwrap_err();
    assert!(matches!(err, StoreError::Rejected(_)));
    drop(file);
}

#[test]
fn group_restore_names_each_file() {
    let dir = TempDir::labeled("page-guard-group").unwrap();
    let a = dir.path().join("confirmed.body");
    let b = dir.path().join("strong_tx.body");
    let mark = dir.path().join("guard/class_c");
    write_bytes(&a, 0, &fill(0x11));
    write_bytes(&b, 0, &fill(0x22));
    let next_a = fill(0xA1);
    let next_b = fill(0xB2);
    arm_page_guard_group(
        &mark,
        &[
            ("confirmed.body", 0, next_a.as_slice()),
            ("strong_tx.body", 0, next_b.as_slice()),
        ],
    )
    .unwrap();
    write_bytes(&a, 0, &fill(0x00));
    write_bytes(&b, 0, &fill(0x00));
    assert!(restore_page_guard_group(&mark, dir.path()).unwrap());
    assert_eq!(read_bytes(&a, 0, PAGE), next_a);
    assert_eq!(read_bytes(&b, 0, PAGE), next_b);
    assert!(!mark.exists());
}

#[test]
fn group_arm_replaces_one_file_and_keeps_another() {
    let dir = TempDir::labeled("page-guard-merge").unwrap();
    let head = dir.path().join("header.head");
    let mlt = dir.path().join("header.head.mlt");
    let mark = dir.path().join("guard/header.head");
    let old_head = fill(0x31);
    let kept_page = fill(0x34);
    let kept_mlt = fill(0x32);
    let new_head = fill(0x33);
    arm_page_guard_group(
        &mark,
        &[
            ("header.head", 0, old_head.as_slice()),
            ("header.head", PAGE as u64, kept_page.as_slice()),
            ("header.head.mlt", 0, kept_mlt.as_slice()),
        ],
    )
    .unwrap();
    arm_page_guard_group(&mark, &[("header.head", 0, new_head.as_slice())]).unwrap();
    write_bytes(&head, 0, &fill(0x00));
    write_bytes(&head, PAGE as u64, &fill(0x00));
    write_bytes(&mlt, 0, &fill(0x00));
    assert!(restore_page_guard_group(&mark, dir.path()).unwrap());
    assert_eq!(read_bytes(&head, 0, PAGE), new_head);
    assert_eq!(read_bytes(&head, PAGE as u64, PAGE), kept_page);
    assert_eq!(read_bytes(&mlt, 0, PAGE), kept_mlt);
}

#[test]
fn clear_drops_only_the_synced_file() {
    let dir = TempDir::labeled("page-guard-clear-one").unwrap();
    let head = dir.path().join("header.head");
    let mlt = dir.path().join("header.head.mlt");
    let mark = dir.path().join("guard/header.head");
    let head_image = fill(0x41);
    let mlt_image = fill(0x42);
    arm_page_guard_group(
        &mark,
        &[
            ("header.head", 0, head_image.as_slice()),
            ("header.head.mlt", 0, mlt_image.as_slice()),
        ],
    )
    .unwrap();
    // The head moves past its marked image, so a restore that still held
    // the head record would show up here.
    let head_written = fill(0x51);
    write_bytes(&head, 0, &head_written);
    write_bytes(&mlt, 0, &fill(0x00));
    let head_file = open_rw(&head);
    clear_page_guard(&mark, &head_file, &head).unwrap();
    drop(head_file);
    write_bytes(&mlt, 0, &fill(0x00));
    assert!(restore_page_guard_group(&mark, dir.path()).unwrap());
    assert_eq!(read_bytes(&head, 0, PAGE), head_written);
    assert_eq!(read_bytes(&mlt, 0, PAGE), mlt_image);
    assert!(!mark.exists());
}

/// A clear removes a legacy single-file mark it can parse. A mark of a kind
/// it does not know stays, and the clear is `Corrupt`.
#[test]
fn clear_keeps_a_mark_of_an_unknown_kind() {
    let dir = TempDir::labeled("page-guard-unknown-kind").unwrap();
    let head = dir.path().join("header.head");
    let mark = dir.path().join("guard/header.head");
    arm_page_guard_group(&mark, &[("header.head", 0, fill(0x41).as_slice())]).unwrap();
    let mut raw = std::fs::read(&mark).unwrap();
    raw[6..8].copy_from_slice(&7u16.to_le_bytes());
    std::fs::write(&mark, &raw).unwrap();
    write_bytes(&head, 0, &fill(0x41));
    let head_file = open_rw(&head);
    let err = clear_page_guard(&mark, &head_file, &head).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
    assert_eq!(std::fs::read(&mark).unwrap(), raw);

    let legacy = dir.path().join("guard/legacy");
    arm_page_guard(&legacy, &[(0, fill(0x41).as_slice())]).unwrap();
    clear_page_guard(&legacy, &head_file, &head).unwrap();
    assert!(!legacy.exists());
}

#[test]
fn clear_of_a_missing_mark_syncs_its_directory() {
    let dir = TempDir::labeled("page-guard-missing-clear").unwrap();
    let live = dir.path().join("header.head");
    let mark = dir.path().join("guard").join("header.head");
    std::fs::create_dir_all(mark.parent().unwrap()).unwrap();
    write_bytes(&live, 0, &fill(0x11));
    let file = open_rw(&live);
    #[cfg(unix)]
    {
        rbitcoin_store::file::arm_fsync_dir_trace();
        clear_page_guard(&mark, &file, &live).unwrap();
        let synced = rbitcoin_store::file::take_fsynced_dirs();
        let parent = mark.parent().unwrap();
        assert!(
            synced.iter().any(|p| p == parent),
            "a missing mark must still sync its directory, got {synced:?}"
        );
    }
    #[cfg(not(unix))]
    clear_page_guard(&mark, &file, &live).unwrap();
}

#[test]
fn group_restore_syncs_the_live_directory_before_the_mark_is_gone() {
    let dir = TempDir::labeled("page-guard-restore-dir").unwrap();
    let mark = dir.path().join("guard").join("class_c");
    let image = fill(0x5A);
    arm_page_guard_group(&mark, &[("fresh.body", 0, image.as_slice())]).unwrap();
    let live = dir.path().join("fresh.body");
    assert!(!live.exists());
    #[cfg(unix)]
    {
        rbitcoin_store::file::arm_fsync_dir_trace();
        assert!(restore_page_guard_group(&mark, dir.path()).unwrap());
        let synced = rbitcoin_store::file::take_fsynced_dirs();
        assert!(!mark.exists());
        let dir_at = synced.iter().position(|p| p == dir.path());
        let guard_at = synced.iter().position(|p| p == mark.parent().unwrap());
        assert!(
            dir_at.is_some() && guard_at.is_some() && dir_at < guard_at,
            "live dir must be durable before the mark is unlinked, got {synced:?}"
        );
    }
    #[cfg(not(unix))]
    assert!(restore_page_guard_group(&mark, dir.path()).unwrap());
    assert_eq!(read_bytes(&live, 0, PAGE), image);
}

#[test]
fn group_mark_count_that_cannot_fit_is_corrupt() {
    let dir = TempDir::labeled("page-guard-count").unwrap();
    let mark = dir.path().join("guard").join("class_c");
    std::fs::create_dir_all(mark.parent().unwrap()).unwrap();
    let mut raw = Vec::new();
    raw.extend_from_slice(&STORE_MAGIC);
    raw.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    raw.extend_from_slice(&1u16.to_le_bytes());
    raw.extend_from_slice(&3u32.to_le_bytes());
    assert_eq!(raw.len(), 12);
    std::fs::write(&mark, &raw).unwrap();
    let err = restore_page_guard_group(&mark, dir.path()).unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err:?}");
    assert!(mark.exists());
}

#[test]
fn first_arm_syncs_the_store_directory() {
    let dir = TempDir::labeled("page-guard-mkdir").unwrap();
    let mark = dir.path().join("guard").join("mark");
    assert!(!mark.parent().unwrap().exists());
    #[cfg(unix)]
    {
        rbitcoin_store::file::arm_fsync_dir_trace();
        arm_page_guard(&mark, &[(0, &fill(0x01))]).unwrap();
        let synced = rbitcoin_store::file::take_fsynced_dirs();
        assert!(
            synced.iter().any(|p| p == dir.path()),
            "creating guard/ must sync the store directory, got {synced:?}"
        );
    }
    #[cfg(not(unix))]
    arm_page_guard(&mark, &[(0, &fill(0x01))]).unwrap();
    assert!(mark.is_file());
}
