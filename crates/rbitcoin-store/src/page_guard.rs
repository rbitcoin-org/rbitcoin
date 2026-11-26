//! Full-page images published by rename.
//!
//! [`arm_page_guard`] writes every 4 KiB image the next live write will dirty,
//! then syncs and renames the mark. [`restore_page_guard`] copies those images
//! onto the live file and removes the mark. It does not read the live bytes.
//! [`arm_page_guard_group`] is the same publish for several files: each record
//! names the file, because each file has its own page 0.
//! [`append_past_end`] writes only when the range shares no 4 KiB block with a
//! byte below `committed_end`.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use rbitcoin_primitives::{schema_file_openable, SCHEMA_VERSION, STORE_MAGIC};

use crate::durability::Durable;
use crate::error::StoreError;
use crate::file::{fsync_parent_dir, handle_pwrite_all, write_synced_tmp_rename};

pub const PAGE: u64 = crate::tx_table::BODY_PAGE_SIZE;
const HEAD: usize = 12;
const RECORD: usize = 8 + PAGE as usize;
const GROUP_KIND: u16 = 1;

/// Forward images for `confirmed[]`, `header_txs_*`, and `strong_tx`.
pub const CLASS_C_MARK: &str = "guard/class_c";
/// Forward images for `header.body`.
pub const HEADER_BODY_MARK: &str = "guard/header.body";
/// Forward images for one `header.head` generation and its `.mlt`.
pub const HEADER_HEAD_MARK: &str = "guard/header.head";

#[doc(hidden)]
pub fn arm_page_guard(path: &Path, pages: &[(u64, &[u8])]) -> Result<(), StoreError> {
    ensure_mark_parent(path)?;
    if path.try_exists().map_err(|e| StoreError::io(path, e))? {
        return Err(StoreError::Rejected("page guard mark is already armed"));
    }
    if pages.is_empty() {
        return Err(StoreError::Corrupt("page guard arm is empty"));
    }
    let count = u32::try_from(pages.len())
        .map_err(|_| StoreError::Corrupt("page guard arm is too large"))?;
    let mut seen = Vec::with_capacity(pages.len());
    for &(offset, image) in pages {
        if !offset.is_multiple_of(PAGE) || image.len() != PAGE as usize {
            return Err(StoreError::Corrupt("page guard image is not one page"));
        }
        if seen.contains(&offset) {
            return Err(StoreError::Corrupt("page guard names one page twice"));
        }
        seen.push(offset);
    }
    let mut buf = Vec::with_capacity(HEAD + pages.len() * RECORD);
    buf.extend_from_slice(&STORE_MAGIC);
    buf.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    for &(offset, image) in pages {
        buf.extend_from_slice(&offset.to_le_bytes());
        buf.extend_from_slice(image);
    }
    write_synced_tmp_rename(path, &buf)
}

/// One group mark for several files. A retry replaces the previous in-flight
/// file by rename; leftover `(file, offset)` images the new set does not
/// name stay, and new images win on overlap.
#[doc(hidden)]
pub fn arm_page_guard_group(path: &Path, pages: &[(&str, u64, &[u8])]) -> Result<(), StoreError> {
    mark_parent(path)?;
    if pages.is_empty() {
        return Err(StoreError::Corrupt("page guard arm is empty"));
    }
    let mut seen: Vec<(&str, u64)> = Vec::with_capacity(pages.len());
    for &(file, offset, image) in pages {
        if !valid_guard_name(file) {
            return Err(StoreError::Corrupt("page guard file name"));
        }
        if !offset.is_multiple_of(PAGE) || image.len() != PAGE as usize {
            return Err(StoreError::Corrupt("page guard image is not one page"));
        }
        if seen
            .iter()
            .any(|&(have, off)| have == file && off == offset)
        {
            return Err(StoreError::Corrupt("page guard names one page twice"));
        }
        seen.push((file, offset));
    }
    let leftover = load_group_leftover(path, &seen)?;
    let count = u32::try_from(pages.len().saturating_add(leftover.len()))
        .map_err(|_| StoreError::Corrupt("page guard arm is too large"))?;
    let mut buf = Vec::with_capacity(HEAD + (pages.len() + leftover.len()) * (2 + 16 + RECORD));
    buf.extend_from_slice(&STORE_MAGIC);
    buf.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    buf.extend_from_slice(&GROUP_KIND.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    for (file, offset, image) in &leftover {
        encode_group_record(&mut buf, file, *offset, image)?;
    }
    for &(file, offset, image) in pages {
        encode_group_record(&mut buf, file, offset, image)?;
    }
    write_synced_tmp_rename(path, &buf)
}

/// Copies every image onto `data` when `mark` exists.
///
/// `Ok(false)` is a missing mark: `data` is left alone. A mark that does not
/// parse is an error, and the live file is left alone.
#[doc(hidden)]
pub fn restore_page_guard(mark: &Path, data: &File, data_path: &Path) -> Result<bool, StoreError> {
    mark_parent(mark)?;
    let raw = match std::fs::read(mark) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(StoreError::io(mark, e)),
    };
    let pages = mark_pages(&raw)?;
    for (offset, at) in pages {
        handle_pwrite_all(data, data_path, offset, &raw[at..at + PAGE as usize])?;
    }
    data.durable_sync_data()
        .map_err(|e| StoreError::io(data_path, e))?;
    remove_mark(mark)?;
    Ok(true)
}

/// Copies every named image onto its file under `dir`. Does not read live bytes.
///
/// `Ok(false)` is a missing mark. A mark that does not parse is an error, and
/// the live files are left alone.
#[doc(hidden)]
pub fn restore_page_guard_group(mark: &Path, dir: &Path) -> Result<bool, StoreError> {
    mark_parent(mark)?;
    let raw = match std::fs::read(mark) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(StoreError::io(mark, e)),
    };
    let pages = mark_group_pages(&raw)?;
    let mut opened: Vec<(String, File, PathBuf)> = Vec::new();
    for (name, offset, at) in &pages {
        let data_path = dir.join(name);
        if !opened.iter().any(|(have, _, _)| have == name) {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&data_path)
                .map_err(|e| StoreError::io(&data_path, e))?;
            opened.push((name.clone(), file, data_path.clone()));
        }
        let Some((_, data, live)) = opened.iter().find(|(have, _, _)| have == name) else {
            return Err(StoreError::Corrupt("page guard file name"));
        };
        handle_pwrite_all(data, live, *offset, &raw[*at..*at + PAGE as usize])?;
    }
    for (_, data, data_path) in &opened {
        data.durable_sync_data()
            .map_err(|e| StoreError::io(data_path, e))?;
    }
    remove_mark(mark)?;
    Ok(true)
}

/// Syncs `data`, then removes `path` and syncs its directory.
///
/// A path that is already gone is `Ok` after the sync. A mark with no
/// directory is an error, so a relative name cannot skip that sync.
#[doc(hidden)]
pub fn clear_page_guard(path: &Path, data: &File, data_path: &Path) -> Result<(), StoreError> {
    clear_page_guard_files(path, &[(data, data_path)])
}

/// Syncs every live file, then removes `path` and syncs its directory.
#[doc(hidden)]
pub fn clear_page_guard_files(path: &Path, files: &[(&File, &Path)]) -> Result<(), StoreError> {
    mark_parent(path)?;
    for (data, data_path) in files {
        data.durable_sync_data()
            .map_err(|e| StoreError::io(*data_path, e))?;
    }
    remove_mark(path)
}

/// Restore `dir/<mark>` when it exists, then continue. Missing is `Ok`.
#[doc(hidden)]
pub fn restore_store_group(dir: &Path, mark: &str) -> Result<bool, StoreError> {
    restore_page_guard_group(&dir.join(mark), dir)
}

/// Promote `meta` to 31 when this directory is a datadir still on 30.
///
/// A table fixture with no `meta` still arms. A plain open does not call this.
#[doc(hidden)]
pub fn promote_meta_31(dir: &Path) -> Result<(), StoreError> {
    match crate::store::check_meta(dir) {
        Ok(ver) if ver < 31 => crate::store::write_meta_at(dir, 31),
        Ok(_) => Ok(()),
        Err(StoreError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Arm a store group mark after `meta` is 31. Empty is a no-op.
#[doc(hidden)]
pub fn arm_store_group(
    dir: &Path,
    mark: &str,
    pages: &[(&str, u64, &[u8])],
) -> Result<(), StoreError> {
    if pages.is_empty() {
        return Ok(());
    }
    promote_meta_31(dir)?;
    arm_page_guard_group(&dir.join(mark), pages)
}

/// File name of `path` as a single component, or `Corrupt`.
#[doc(hidden)]
pub fn guard_file_name(path: &Path) -> Result<&str, StoreError> {
    path.file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty() && !n.contains('/') && !n.contains('\\'))
        .ok_or(StoreError::Corrupt("page guard file name"))
}

fn encode_group_record(
    buf: &mut Vec<u8>,
    file: &str,
    offset: u64,
    image: &[u8],
) -> Result<(), StoreError> {
    let name_len =
        u16::try_from(file.len()).map_err(|_| StoreError::Corrupt("page guard file name"))?;
    buf.extend_from_slice(&name_len.to_le_bytes());
    buf.extend_from_slice(file.as_bytes());
    buf.extend_from_slice(&offset.to_le_bytes());
    buf.extend_from_slice(image);
    Ok(())
}

fn load_group_leftover(
    path: &Path,
    incoming: &[(&str, u64)],
) -> Result<Vec<(String, u64, Vec<u8>)>, StoreError> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::io(path, e)),
    };
    let pages = mark_group_pages(&raw)?;
    let mut leftover = Vec::new();
    for (name, offset, at) in pages {
        if incoming
            .iter()
            .any(|&(have, off)| have == name && off == offset)
        {
            continue;
        }
        leftover.push((name, offset, raw[at..at + PAGE as usize].to_vec()));
    }
    Ok(leftover)
}

fn valid_guard_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= u16::MAX as usize
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
        && name != "."
        && name != ".."
        && Path::new(name).components().count() == 1
}

fn mark_parent(path: &Path) -> Result<&Path, StoreError> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        _ => Err(StoreError::Rejected("page guard mark has no directory")),
    }
}

fn remove_mark(path: &Path) -> Result<(), StoreError> {
    let parent = mark_parent(path)?;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(StoreError::io(path, e)),
    }
    fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
    Ok(())
}

/// Create `path`'s directory and sync that directory's parent.
///
/// The mark rename syncs the guard directory. The store directory still has
/// to name `guard/` before a crash, or the mark never comes back. A
/// `guard/` that already exists is synced again, because an earlier arm may
/// have created it and then failed that sync.
fn ensure_mark_parent(path: &Path) -> Result<(), StoreError> {
    let parent = mark_parent(path)?;
    if !parent.is_dir() {
        std::fs::create_dir_all(parent).map_err(|e| StoreError::io(parent, e))?;
    }
    if let Some(grand) = parent.parent().filter(|p| !p.as_os_str().is_empty()) {
        fsync_parent_dir(grand).map_err(|e| StoreError::io(grand, e))?;
    }
    Ok(())
}

/// Writes `bytes` at `offset` when no byte of the write shares a 4 KiB block
/// with a byte below `committed_end`. An empty write is `Ok`.
#[doc(hidden)]
pub fn append_past_end(
    file: &File,
    path: &Path,
    committed_end: u64,
    offset: u64,
    bytes: &[u8],
) -> Result<(), StoreError> {
    if bytes.is_empty() {
        return Ok(());
    }
    if shares_committed_page(committed_end, offset, bytes.len() as u64) {
        return Err(StoreError::Rejected("append shares a committed page"));
    }
    handle_pwrite_all(file, path, offset, bytes)
}

fn shares_committed_page(committed_end: u64, offset: u64, len: u64) -> bool {
    if len == 0 || committed_end == 0 {
        return false;
    }
    if offset.checked_add(len - 1).is_none() || offset < committed_end {
        return true;
    }
    let last_committed = (committed_end - 1) / PAGE;
    offset / PAGE <= last_committed
}

fn mark_pages(raw: &[u8]) -> Result<Vec<(u64, usize)>, StoreError> {
    if raw.len() < HEAD || raw[..4] != STORE_MAGIC {
        return Err(StoreError::Corrupt("page guard mark is not a guard file"));
    }
    let schema = u16::from_le_bytes([raw[4], raw[5]]);
    if !schema_file_openable(schema) {
        return Err(StoreError::Corrupt("page guard mark schema"));
    }
    if raw[6] != 0 || raw[7] != 0 {
        return Err(StoreError::Corrupt("page guard mark reserved"));
    }
    let count = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
    if count == 0 || raw.len() != HEAD + count * RECORD {
        return Err(StoreError::Corrupt("page guard mark length"));
    }
    let mut pages = Vec::with_capacity(count);
    for i in 0..count {
        let at = HEAD + i * RECORD;
        let mut off = [0u8; 8];
        off.copy_from_slice(&raw[at..at + 8]);
        let offset = u64::from_le_bytes(off);
        if !offset.is_multiple_of(PAGE) || pages.iter().any(|&(have, _)| have == offset) {
            return Err(StoreError::Corrupt("page guard names a torn page"));
        }
        pages.push((offset, at + 8));
    }
    Ok(pages)
}

fn mark_group_pages(raw: &[u8]) -> Result<Vec<(String, u64, usize)>, StoreError> {
    if raw.len() < HEAD || raw[..4] != STORE_MAGIC {
        return Err(StoreError::Corrupt("page guard mark is not a guard file"));
    }
    let schema = u16::from_le_bytes([raw[4], raw[5]]);
    if !schema_file_openable(schema) {
        return Err(StoreError::Corrupt("page guard mark schema"));
    }
    let kind = u16::from_le_bytes([raw[6], raw[7]]);
    if kind != GROUP_KIND {
        return Err(StoreError::Corrupt("page guard mark reserved"));
    }
    let count = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]) as usize;
    if count == 0 {
        return Err(StoreError::Corrupt("page guard mark length"));
    }
    let mut pages = Vec::with_capacity(count);
    let mut at = HEAD;
    for _ in 0..count {
        if raw.len() < at + 2 {
            return Err(StoreError::Corrupt("page guard mark length"));
        }
        let name_len = u16::from_le_bytes([raw[at], raw[at + 1]]) as usize;
        at += 2;
        if name_len == 0 || raw.len() < at + name_len + 8 + PAGE as usize {
            return Err(StoreError::Corrupt("page guard mark length"));
        }
        let name = std::str::from_utf8(&raw[at..at + name_len])
            .map_err(|_| StoreError::Corrupt("page guard file name"))?;
        if !valid_guard_name(name) {
            return Err(StoreError::Corrupt("page guard file name"));
        }
        at += name_len;
        let mut off = [0u8; 8];
        off.copy_from_slice(&raw[at..at + 8]);
        let offset = u64::from_le_bytes(off);
        at += 8;
        if !offset.is_multiple_of(PAGE)
            || pages
                .iter()
                .any(|(have, have_off, _)| have == name && *have_off == offset)
        {
            return Err(StoreError::Corrupt("page guard names a torn page"));
        }
        pages.push((name.to_string(), offset, at));
        at += PAGE as usize;
    }
    if at != raw.len() {
        return Err(StoreError::Corrupt("page guard mark length"));
    }
    Ok(pages)
}
