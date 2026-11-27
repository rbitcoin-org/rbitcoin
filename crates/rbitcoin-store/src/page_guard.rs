//! Full-page images published by rename.
//!
//! [`arm_page_guard`] writes every 4 KiB image the next live write will dirty,
//! then syncs and renames the mark. [`restore_page_guard`] copies those images
//! onto the live file and removes the mark. It does not read the live bytes.
//! [`arm_page_guard_group`] is the same publish for several files: each record
//! names the file, because each file has its own page 0.
//! [`append_past_end`] writes only when the range shares no 4 KiB block with a
//! byte below `committed_end`.

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use rbitcoin_primitives::{schema_file_openable, SCHEMA_VERSION, STORE_MAGIC};

use crate::durability::Durable;
use crate::error::StoreError;
use crate::file::{
    encode_leading_header, fsync_parent_dir, handle_pread_all, handle_pwrite_all,
    write_synced_tmp_rename, TableFile, FILE_HEADER_LEN,
};

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
/// Backward image of `spent.ovf` page 0 and its tail block.
pub const SPENT_OVF_MARK: &str = "guard/spent.ovf";
/// Prefix of one scripthash-commit mark (`guard/sh-00`, `guard/sh-ovf`).
pub const SH_MARK_PREFIX: &str = "guard/sh-";
/// Backward images of interior `txstat.body` and `txstat.blk` pages.
pub const TXSTAT_MARK: &str = "guard/txstat";
/// Forward images for one `blockfilter` put (body tail, idx tail, page 0).
pub const BLOCKFILTER_MARK: &str = "guard/blockfilter";
/// Forward images for one `sp_tweaks` put (body tail, idx tail, page 0).
pub const SP_TWEAKS_MARK: &str = "guard/sp_tweaks";

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

/// One process-wide hold for every mark. Arm and clear of the same path must
/// sit inside one hold, or a second flusher can rename the file between them.
#[doc(hidden)]
pub fn hold_marks() -> MutexGuard<'static, ()> {
    static MARKS: OnceLock<Mutex<()>> = OnceLock::new();
    MARKS
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

/// One group mark for several files. A retry replaces the image at the same
/// file and offset. Other offsets stay, including other pages of a file this
/// set names.
#[doc(hidden)]
pub fn arm_page_guard_group(path: &Path, pages: &[(&str, u64, &[u8])]) -> Result<(), StoreError> {
    ensure_mark_parent(path)?;
    if pages.is_empty() {
        return Err(StoreError::Corrupt("page guard arm is empty"));
    }
    let mut seen: HashSet<(&str, u64)> = HashSet::with_capacity(pages.len());
    for &(file, offset, image) in pages {
        if !valid_guard_name(file) {
            return Err(StoreError::Corrupt("page guard file name"));
        }
        if !offset.is_multiple_of(PAGE) || image.len() != PAGE as usize {
            return Err(StoreError::Corrupt("page guard image is not one page"));
        }
        if !seen.insert((file, offset)) {
            return Err(StoreError::Corrupt("page guard names one page twice"));
        }
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
        write_restored_page(data, data_path, offset, &raw[at..at + PAGE as usize], None)?;
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
    if !replay_page_guard_group(mark, dir)? {
        return Ok(false);
    }
    remove_mark(mark)?;
    Ok(true)
}

/// [`restore_page_guard_group`] that leaves the mark in place.
///
/// The images are on the device when this returns. The caller removes the
/// mark once the state the mark stands for is durable elsewhere.
fn replay_page_guard_group(mark: &Path, dir: &Path) -> Result<bool, StoreError> {
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
        write_restored_page(data, live, *offset, &raw[*at..*at + PAGE as usize], None)?;
    }
    for (_, data, data_path) in &opened {
        data.durable_sync_data()
            .map_err(|e| StoreError::io(data_path, e))?;
    }
    // A created directory entry has to be durable before the mark is gone.
    let mut parents: Vec<&Path> = Vec::new();
    for (_, _, data_path) in &opened {
        let parent = data_path.parent().unwrap_or(dir);
        if !parents.contains(&parent) {
            fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
            parents.push(parent);
        }
    }
    Ok(true)
}

/// Copies named images onto existing files. A missing live file is skipped.
///
/// A short file keeps its length: the sidecar pads to 4 KiB, and restore
/// writes only the bytes that were on disk. An empty live file is filled
/// with the full page.
#[doc(hidden)]
pub fn restore_page_guard_group_fit(mark: &Path, dir: &Path) -> Result<bool, StoreError> {
    mark_parent(mark)?;
    let raw = match std::fs::read(mark) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(StoreError::io(mark, e)),
    };
    let pages = mark_group_pages(&raw)?;
    // A forward `*.ahead` image is the post-commit page. The backward mark
    // wins: drop the sidecar before any head open can replay it.
    let mut dropped_ahead: Vec<String> = Vec::new();
    for (name, _, _) in &pages {
        if dropped_ahead.iter().any(|have| have == name) {
            continue;
        }
        drop_ahead_sidecar(dir, name)?;
        dropped_ahead.push(name.clone());
    }
    let mut opened: Vec<(String, File, PathBuf, u64)> = Vec::new();
    for (name, offset, at) in &pages {
        let data_path = dir.join(name);
        if !opened.iter().any(|(have, _, _, _)| have == name) {
            let file = match OpenOptions::new().read(true).write(true).open(&data_path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(StoreError::io(&data_path, e)),
            };
            let len = file
                .metadata()
                .map_err(|e| StoreError::io(&data_path, e))?
                .len();
            opened.push((name.clone(), file, data_path.clone(), len));
        }
        let Some((_, data, live, len)) = opened.iter().find(|(have, _, _, _)| have == name) else {
            continue;
        };
        let image = &raw[*at..*at + PAGE as usize];
        write_restored_page(data, live, *offset, image, Some(*len))?;
    }
    for (_, data, data_path, _) in &opened {
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

/// Syncs every live file, then drops those files' images.
///
/// Records for a file this call did not sync stay armed. The mark file goes
/// away only when nothing remains.
#[doc(hidden)]
pub fn clear_page_guard_files(path: &Path, files: &[(&File, &Path)]) -> Result<(), StoreError> {
    mark_parent(path)?;
    for (data, data_path) in files {
        data.durable_sync_data()
            .map_err(|e| StoreError::io(*data_path, e))?;
    }
    let mut synced = HashSet::with_capacity(files.len());
    for (_, data_path) in files {
        synced.insert(guard_file_name(data_path)?.to_string());
    }
    retain_unsynced(path, &synced)
}

/// Rewrite `path` without records for `synced`. Delete it when none remain.
fn retain_unsynced(path: &Path, synced: &HashSet<String>) -> Result<(), StoreError> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let parent = mark_parent(path)?;
            fsync_parent_dir(parent).map_err(|err| StoreError::io(parent, err))?;
            return Ok(());
        }
        Err(e) => return Err(StoreError::io(path, e)),
    };
    let pages = match mark_group_pages(&raw) {
        Ok(pages) => pages,
        Err(StoreError::Corrupt("page guard mark reserved")) => {
            // Only a single-file mark that parses is removed. A kind this
            // binary does not know stays for the restore to refuse.
            mark_pages(&raw)?;
            return remove_mark(path);
        }
        Err(e) => return Err(e),
    };
    let mut keep = Vec::new();
    for (name, offset, at) in pages {
        if synced.contains(&name) {
            continue;
        }
        keep.push((name, offset, raw[at..at + PAGE as usize].to_vec()));
    }
    if keep.is_empty() {
        return remove_mark(path);
    }
    let count = u32::try_from(keep.len())
        .map_err(|_| StoreError::Corrupt("page guard arm is too large"))?;
    let mut buf = Vec::with_capacity(HEAD + keep.len() * (2 + 16 + RECORD));
    buf.extend_from_slice(&STORE_MAGIC);
    buf.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    buf.extend_from_slice(&GROUP_KIND.to_le_bytes());
    buf.extend_from_slice(&count.to_le_bytes());
    for (file, offset, image) in &keep {
        encode_group_record(&mut buf, file, *offset, image)?;
    }
    write_synced_tmp_rename(path, &buf)
}

/// Restore `dir/<mark>` when it exists, then continue. Missing is `Ok`.
#[doc(hidden)]
pub fn restore_store_group(dir: &Path, mark: &str) -> Result<bool, StoreError> {
    restore_page_guard_group(&dir.join(mark), dir)
}

/// Copy `dir/<mark>` onto its files and keep the mark. Missing is `Ok(false)`.
pub(crate) fn replay_store_group(dir: &Path, mark: &str) -> Result<bool, StoreError> {
    replay_page_guard_group(&dir.join(mark), dir)
}

/// Copy `dir/<mark>` onto `dir/<data_name>` when the mark exists.
///
/// `Ok(false)` is a missing mark. A present mark is copied without reading
/// the live bytes. The data file is created when the mark names one that
/// is not there yet.
#[doc(hidden)]
pub fn restore_store_file(dir: &Path, mark: &str, data_name: &str) -> Result<bool, StoreError> {
    let mark_path = dir.join(mark);
    match mark_path.try_exists() {
        Ok(false) => return Ok(false),
        Ok(true) => {}
        Err(e) => return Err(StoreError::io(&mark_path, e)),
    }
    let data_path = dir.join(data_name);
    // Default is truncate-false. Naming it adds a ratchet-counted truncate(.
    #[allow(clippy::suspicious_open_options)]
    let data = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&data_path)
        .map_err(|e| StoreError::io(&data_path, e))?;
    // The open may have just created the file. Its name must be durable in
    // `dir` before the mark that rebuilds it goes away.
    fsync_parent_dir(dir).map_err(|e| StoreError::io(dir, e))?;
    restore_page_guard(&mark_path, &data, &data_path)
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

/// `guard/sh-<shard>` for one scripthash body (`00` or `ovf`).
#[doc(hidden)]
pub fn sh_mark(shard: &str) -> String {
    format!("{SH_MARK_PREFIX}{shard}")
}

/// Copy every `guard/sh-*` mark onto its live files, then drop the marks.
#[doc(hidden)]
pub fn restore_sh_marks(dir: &Path) -> Result<(), StoreError> {
    let guard = dir.join("guard");
    let rd = match std::fs::read_dir(&guard) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StoreError::io(&guard, e)),
    };
    let mut names: Vec<String> = Vec::new();
    for ent in rd {
        let ent = ent.map_err(|e| StoreError::io(&guard, e))?;
        let name = ent.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !published_sh_mark(name) {
            continue;
        }
        let file = match ent.file_type() {
            Ok(t) if t.is_file() => true,
            Ok(_) => false,
            Err(e) => return Err(StoreError::io(ent.path(), e)),
        };
        if file {
            names.push(name.to_string());
        }
    }
    names.sort_unstable();
    for name in names {
        restore_page_guard_group_fit(&guard.join(name), dir)?;
    }
    Ok(())
}

/// Drop every `guard/sh-*` mark. Missing is `Ok`.
#[doc(hidden)]
pub fn clear_sh_marks(dir: &Path) -> Result<(), StoreError> {
    let guard = dir.join("guard");
    let rd = match std::fs::read_dir(&guard) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StoreError::io(&guard, e)),
    };
    let mut any = false;
    for ent in rd {
        let ent = ent.map_err(|e| StoreError::io(&guard, e))?;
        let name = ent.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with("sh-") {
            continue;
        }
        let path = ent.path();
        match std::fs::remove_file(&path) {
            Ok(()) => any = true,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(StoreError::io(&path, e)),
        }
    }
    if any {
        fsync_parent_dir(&guard).map_err(|e| StoreError::io(&guard, e))?;
    }
    Ok(())
}

/// Sync every live file, then drop those files' relative names from `mark`.
#[doc(hidden)]
pub fn clear_page_guard_rel(
    mark: &Path,
    dir: &Path,
    files: &[(&File, &Path)],
) -> Result<(), StoreError> {
    mark_parent(mark)?;
    for (data, data_path) in files {
        data.durable_sync_data()
            .map_err(|e| StoreError::io(*data_path, e))?;
    }
    let mut synced = HashSet::with_capacity(files.len());
    for (_, data_path) in files {
        synced.insert(guard_rel_name(dir, data_path)?);
    }
    retain_unsynced(mark, &synced)
}

/// Drop `names` from `mark` without syncing live files. Used before a rename
/// replaces a file the mark still images.
#[doc(hidden)]
pub fn drop_page_guard_names(mark: &Path, names: &HashSet<String>) -> Result<(), StoreError> {
    mark_parent(mark)?;
    retain_unsynced(mark, names)
}

/// Drop `rel` from every `guard/sh-*` mark, then sync `dir`.
#[doc(hidden)]
/// A renamed `guard/sh-*` mark. `sh-<shard>.tmp` is a rename leftover that
/// may be partial; restore and drop skip it, and reset removes it.
pub(crate) fn published_sh_mark(name: &str) -> bool {
    name.starts_with("sh-") && !name.ends_with(".tmp")
}

pub fn drop_sh_rel(dir: &Path, rel: &str) -> Result<(), StoreError> {
    let guard = dir.join("guard");
    let rd = match std::fs::read_dir(&guard) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StoreError::io(&guard, e)),
    };
    let mut names = HashSet::new();
    names.insert(rel.to_string());
    for ent in rd {
        let ent = ent.map_err(|e| StoreError::io(&guard, e))?;
        let name = ent.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if published_sh_mark(name) {
            drop_page_guard_names(&ent.path(), &names)?;
        }
    }
    if let Some(parent) = Path::new(rel).parent() {
        if !parent.as_os_str().is_empty() {
            let live_parent = dir.join(parent);
            if live_parent.is_dir() {
                fsync_parent_dir(&live_parent).map_err(|e| StoreError::io(&live_parent, e))?;
            }
        }
    }
    Ok(())
}

/// Store-relative 1–2 component name of `path`.
#[doc(hidden)]
pub fn guard_rel_name(dir: &Path, path: &Path) -> Result<String, StoreError> {
    let rel = path
        .strip_prefix(dir)
        .map_err(|_| StoreError::Corrupt("page guard file name"))?;
    let name = rel
        .to_str()
        .ok_or(StoreError::Corrupt("page guard file name"))?
        .replace('\\', "/");
    if !valid_guard_name(&name) {
        return Err(StoreError::Corrupt("page guard file name"));
    }
    Ok(name)
}

/// Remove `{file}.ahead` next to a file the mark is about to restore.
fn drop_ahead_sidecar(dir: &Path, name: &str) -> Result<(), StoreError> {
    let live = dir.join(name);
    let Some(file_name) = live.file_name() else {
        return Ok(());
    };
    let mut ahead = file_name.to_os_string();
    ahead.push(".ahead");
    let side = match live.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(ahead),
        _ => PathBuf::from(ahead),
    };
    match std::fs::remove_file(&side) {
        Ok(()) => {}
        // An earlier unlink may have landed and its directory sync failed.
        // Sync again so the sidecar cannot come back after the mark is gone.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(StoreError::io(&side, e)),
    }
    if let Some(parent) = side.parent().filter(|p| p.is_dir()) {
        fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
    }
    Ok(())
}

/// Read one 4 KiB block. Bytes past EOF are zeros. A missing file is zeros.
#[doc(hidden)]
pub fn read_live_page(
    path: &Path,
    file: &File,
    block: u64,
) -> Result<[u8; PAGE as usize], StoreError> {
    let mut image = [0u8; PAGE as usize];
    let len = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(image),
        Err(e) => return Err(StoreError::io(path, e)),
    };
    if block < len {
        let n = ((len - block) as usize).min(PAGE as usize);
        handle_pread_all(file, path, block, &mut image[..n])?;
    }
    Ok(image)
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
    replaced: &HashSet<(&str, u64)>,
) -> Result<Vec<(String, u64, Vec<u8>)>, StoreError> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::io(path, e)),
    };
    let pages = mark_group_pages(&raw)?;
    let mut leftover = Vec::new();
    for (name, offset, at) in pages {
        if replaced.contains(&(name.as_str(), offset)) {
            continue;
        }
        leftover.push((name, offset, raw[at..at + PAGE as usize].to_vec()));
    }
    Ok(leftover)
}

/// The (file, page offset) records `mark` holds. A missing mark holds none.
pub(crate) fn armed_group_pages(mark: &Path) -> Result<HashSet<(String, u64)>, StoreError> {
    let raw = match std::fs::read(mark) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(StoreError::io(mark, e)),
    };
    Ok(mark_group_pages(&raw)?
        .into_iter()
        .map(|(name, offset, _)| (name, offset))
        .collect())
}

fn valid_guard_name(name: &str) -> bool {
    if name.is_empty()
        || name.len() > u16::MAX as usize
        || name.contains('\\')
        || name.contains('\0')
    {
        return false;
    }
    let path = Path::new(name);
    if path.is_absolute() {
        return false;
    }
    let mut n = 0usize;
    for c in path.components() {
        match c {
            Component::Normal(s) => {
                let s = s.to_str().unwrap_or("");
                if s.is_empty() || s == "." || s == ".." {
                    return false;
                }
                n += 1;
                if n > 2 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    n == 1 || n == 2
}

/// `fit_len` is the live length read before this restore's first write.
/// `None` or an empty file takes the whole image.
fn write_restored_page(
    data: &File,
    live: &Path,
    offset: u64,
    image: &[u8],
    fit_len: Option<u64>,
) -> Result<(), StoreError> {
    let len = fit_len.unwrap_or(0);
    if len == 0 {
        return handle_pwrite_all(data, live, offset, image);
    }
    if offset >= len {
        return Ok(());
    }
    let n = ((len - offset) as usize).min(image.len());
    handle_pwrite_all(data, live, offset, &image[..n])
}

fn mark_parent(path: &Path) -> Result<&Path, StoreError> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => Ok(parent),
        _ => Err(StoreError::Rejected("page guard mark has no directory")),
    }
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

/// One file's append inside [`commit_forward_appends`].
///
/// `new_logical` is the length the leading header names after this write.
#[doc(hidden)]
pub struct ForwardAppend<'a> {
    pub file: &'a TableFile,
    pub at: u64,
    pub bytes: &'a [u8],
    pub new_logical: u64,
}

#[cfg(debug_assertions)]
static FAIL_FORWARD: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// The next [`commit_forward_appends`] in `dir` arms, then returns before
/// the shared pages are written. The mark stays.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn fail_next_forward_after_arm(dir: &Path) {
    FAIL_FORWARD
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(dir.to_path_buf());
}

#[cfg(debug_assertions)]
fn take_fail_forward(dir: &Path) -> bool {
    let mut armed = FAIL_FORWARD.lock().unwrap_or_else(|e| e.into_inner());
    let Some(i) = armed.iter().position(|p| p == dir) else {
        return false;
    };
    armed.remove(i);
    true
}

/// Result of [`commit_forward_appends`].
///
/// `Undo` means no mark was published, so the caller can drop the RAM plan.
/// `Keep` means a mark may still name this commit. The caller must not undo
/// slot counts or delete segment files. A later put has to wait for reopen.
#[doc(hidden)]
pub enum ForwardCommit {
    Done,
    Undo(StoreError),
    Keep(StoreError),
}

/// Publish one forward append group.
///
/// Fresh 4 KiB blocks (strictly past the committed tail block) are synced
/// before the mark. Page 0 and the tail block are the mark: open copies
/// those images and the append completes. `new_logical` is adopted in RAM
/// only after the mark is cleared, so a later `flush` does not rewrite page 0.
#[doc(hidden)]
pub fn commit_forward_appends(
    dir: &Path,
    mark: &str,
    writes: &[ForwardAppend<'_>],
) -> ForwardCommit {
    if writes.is_empty() {
        return ForwardCommit::Done;
    }
    let _hold = hold_marks();
    let mut files: Vec<&TableFile> = Vec::new();
    for w in writes {
        if w.file.trailing_header {
            return ForwardCommit::Undo(StoreError::Corrupt(
                "forward append is a leading-header file",
            ));
        }
        if !files.iter().any(|f| f.path() == w.file.path()) {
            files.push(w.file);
        }
    }
    let mut logical: Vec<u64> = files.iter().map(|f| f.logical_len()).collect();
    for w in writes {
        let Some(i) = files.iter().position(|f| f.path() == w.file.path()) else {
            return ForwardCommit::Undo(StoreError::Corrupt("page guard file name"));
        };
        let end = w.at.saturating_add(w.bytes.len() as u64);
        logical[i] = logical[i].max(w.new_logical).max(end);
    }
    let planned = match plan_forward_pages(&files, writes, &logical) {
        Ok(planned) => planned,
        Err(e) => return ForwardCommit::Undo(e),
    };
    if let Err(e) = sync_fresh_spans(&files, writes, &planned.fresh) {
        return ForwardCommit::Undo(e);
    }
    let names = match files
        .iter()
        .map(|f| guard_rel_name(dir, f.path()))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(names) => names,
        Err(e) => return ForwardCommit::Undo(e),
    };
    if let Err(e) = publish_forward_images(dir, mark, &files, &names, &planned.images) {
        // The mark rename can land, or unlink can land without its directory
        // sync. Either way the segment files have to stay.
        return ForwardCommit::Keep(e);
    }
    for (fi, file) in files.iter().enumerate() {
        file.adopt_durable_len(logical[fi]);
    }
    ForwardCommit::Done
}

struct ForwardPages {
    fresh: Vec<(usize, usize, u64, std::ops::Range<usize>)>,
    images: Vec<(usize, u64, [u8; PAGE as usize])>,
}

/// Shared pages (page 0 and the committed tail block) become the image.
/// Bytes strictly past that tail are fresh spans, synced before the mark.
fn plan_forward_pages(
    files: &[&TableFile],
    writes: &[ForwardAppend<'_>],
    logical: &[u64],
) -> Result<ForwardPages, StoreError> {
    let mut fresh = Vec::new();
    let mut images = Vec::new();
    for (fi, file) in files.iter().enumerate() {
        let old = file.logical_len();
        let new_logical = logical[fi];
        let mut pages = std::collections::BTreeSet::new();
        if new_logical != old {
            pages.insert(0u64);
        }
        collect_forward_spans(fi, file, writes, old, &mut pages, &mut fresh);
        for page in pages {
            let mut image = read_live_page(file.path(), &file.read_file, page)?;
            if page == 0 {
                image[..FILE_HEADER_LEN]
                    .copy_from_slice(&encode_leading_header(file.kind, new_logical));
            }
            for w in writes.iter().filter(|w| w.file.path() == file.path()) {
                if shared_page(page, old) {
                    overlay_page(&mut image, page, w.at, w.bytes);
                }
            }
            images.push((fi, page, image));
        }
    }
    Ok(ForwardPages { fresh, images })
}

fn collect_forward_spans(
    fi: usize,
    file: &TableFile,
    writes: &[ForwardAppend<'_>],
    old: u64,
    pages: &mut std::collections::BTreeSet<u64>,
    fresh: &mut Vec<(usize, usize, u64, std::ops::Range<usize>)>,
) {
    for (wi, w) in writes.iter().enumerate() {
        if w.file.path() != file.path() || w.bytes.is_empty() {
            continue;
        }
        let mut i = 0usize;
        while i < w.bytes.len() {
            let off = w.at + i as u64;
            let page = off & !(PAGE - 1);
            let page_hi = (page + PAGE - off) as usize;
            let end = i.saturating_add(page_hi).min(w.bytes.len());
            if shared_page(page, old) {
                pages.insert(page);
            } else {
                fresh.push((fi, wi, off, i..end));
            }
            i = end;
        }
    }
}

fn sync_fresh_spans(
    files: &[&TableFile],
    writes: &[ForwardAppend<'_>],
    fresh: &[(usize, usize, u64, std::ops::Range<usize>)],
) -> Result<(), StoreError> {
    let mut synced = std::collections::HashSet::new();
    for (fi, wi, at, range) in fresh {
        let file = files[*fi];
        let bytes = &writes[*wi].bytes[range.clone()];
        let end = at.saturating_add(bytes.len() as u64);
        file.ensure_capacity(end)?;
        append_past_end(&file.read_file, file.path(), file.logical_len(), *at, bytes)?;
        synced.insert(*fi);
    }
    for fi in &synced {
        files[*fi].sync_data_only()?;
        // A roll creates the segment files just before this sync. The mark
        // names those bytes, so the directory entry has to be durable first.
        if let Some(parent) = files[*fi]
            .path()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
        }
    }
    Ok(())
}

fn publish_forward_images(
    dir: &Path,
    mark: &str,
    files: &[&TableFile],
    names: &[String],
    images: &[(usize, u64, [u8; PAGE as usize])],
) -> Result<(), StoreError> {
    if images.is_empty() {
        return Ok(());
    }
    let refs: Vec<(&str, u64, &[u8])> = images
        .iter()
        .map(|(fi, off, image)| (names[*fi].as_str(), *off, image.as_slice()))
        .collect();
    arm_store_group(dir, mark, &refs)?;
    #[cfg(debug_assertions)]
    if take_fail_forward(dir) {
        return Err(StoreError::io(
            dir.join(mark),
            std::io::Error::other("injected forward guard failure"),
        ));
    }
    for (fi, off, image) in images {
        let file = files[*fi];
        file.ensure_capacity(off.saturating_add(PAGE))?;
        write_restored_page(&file.read_file, file.path(), *off, image, None)?;
    }
    let live: Vec<(&File, &Path)> = images
        .iter()
        .map(|(fi, _, _)| *fi)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|fi| (&files[fi].read_file, files[fi].path()))
        .collect();
    clear_page_guard_rel(&dir.join(mark), dir, &live)
}

fn shared_page(page: u64, old: u64) -> bool {
    if old == 0 {
        return page == 0;
    }
    let tail = (old - 1) & !(PAGE - 1);
    page == 0 || page <= tail
}

fn overlay_page(image: &mut [u8; PAGE as usize], page: u64, off: u64, bytes: &[u8]) {
    let end = off.saturating_add(bytes.len() as u64);
    let lo = off.max(page);
    let hi = end.min(page + PAGE);
    if lo >= hi {
        return;
    }
    let src = (lo - off) as usize;
    let dst = (lo - page) as usize;
    let n = (hi - lo) as usize;
    image[dst..dst + n].copy_from_slice(&bytes[src..src + n]);
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
    // One record is at least a 1-byte name, its length, the offset, and a page.
    const MIN_RECORD: usize = 2 + 1 + 8 + PAGE as usize;
    let rest = raw.len().saturating_sub(HEAD);
    if rest / MIN_RECORD < count {
        return Err(StoreError::Corrupt("page guard mark length"));
    }
    let mut pages = Vec::with_capacity(count);
    let mut seen: HashSet<(String, u64)> = HashSet::with_capacity(count);
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
        if !offset.is_multiple_of(PAGE) || !seen.insert((name.to_string(), offset)) {
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
