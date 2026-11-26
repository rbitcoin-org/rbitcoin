//! A mark of whole 4 KiB images, and an append that stays off those pages.
use rbitcoin_primitives::STORE_MAGIC;
use rbitcoin_store::page_guard::{
    append_past_end, arm_page_guard, clear_page_guard, restore_page_guard,
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
    clear_page_guard(&mark).unwrap();
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
