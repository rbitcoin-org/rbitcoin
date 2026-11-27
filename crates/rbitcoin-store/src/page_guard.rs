//! Full-page images published by rename.
//!
//! [`arm_page_guard`] writes every 4 KiB image the next live write will dirty,
//! then syncs and renames the mark. [`restore_page_guard`] copies those images
//! onto the live file and removes the mark. It does not read the live bytes.
//! [`append_past_end`] writes only when the range shares no 4 KiB block with a
//! byte below `committed_end`.

use std::fs::File;
use std::path::Path;

use rbitcoin_primitives::{schema_file_openable, SCHEMA_VERSION, STORE_MAGIC};

use crate::durability::Durable;
use crate::error::StoreError;
use crate::file::{fsync_parent_dir, handle_pwrite_all, write_synced_tmp_rename};

const PAGE: u64 = crate::tx_table::BODY_PAGE_SIZE;
const HEAD: usize = 12;
const RECORD: usize = 8 + PAGE as usize;

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

/// Syncs `data`, then removes `path` and syncs its directory.
///
/// A path that is already gone is `Ok` after the sync. A mark with no
/// directory is an error, so a relative name cannot skip that sync.
#[doc(hidden)]
pub fn clear_page_guard(path: &Path, data: &File, data_path: &Path) -> Result<(), StoreError> {
    mark_parent(path)?;
    data.durable_sync_data()
        .map_err(|e| StoreError::io(data_path, e))?;
    remove_mark(path)
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
/// to name `guard/` before a crash, or the mark never comes back.
fn ensure_mark_parent(path: &Path) -> Result<(), StoreError> {
    let parent = mark_parent(path)?;
    if parent.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|e| StoreError::io(parent, e))?;
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
