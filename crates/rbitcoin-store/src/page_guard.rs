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
use crate::file::{fsync_parent_dir, handle_pread_all, handle_pwrite_all, write_synced_tmp_rename};

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
        write_restored_page(data, data_path, offset, &raw[at..at + PAGE as usize], false)?;
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
        write_restored_page(data, live, *offset, &raw[*at..*at + PAGE as usize], false)?;
    }
    for (_, data, data_path) in &opened {
        data.durable_sync_data()
            .map_err(|e| StoreError::io(data_path, e))?;
    }
    remove_mark(mark)?;
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
    let mut opened: Vec<(String, File, PathBuf)> = Vec::new();
    for (name, offset, at) in &pages {
        let data_path = dir.join(name);
        if !opened.iter().any(|(have, _, _)| have == name) {
            let file = match OpenOptions::new().read(true).write(true).open(&data_path) {
                Ok(file) => file,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(StoreError::io(&data_path, e)),
            };
            opened.push((name.clone(), file, data_path.clone()));
        }
        let Some((_, data, live)) = opened.iter().find(|(have, _, _)| have == name) else {
            continue;
        };
        write_restored_page(data, live, *offset, &raw[*at..*at + PAGE as usize], true)?;
    }
    for (_, data, data_path) in &opened {
        data.durable_sync_data()
            .map_err(|e| StoreError::io(data_path, e))?;
    }
    // The created directory entry has to be durable before the mark is gone.
    fsync_parent_dir(dir).map_err(|e| StoreError::io(dir, e))?;
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
        if !name.starts_with("sh-") {
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
        if name.starts_with("sh-") {
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
        Ok(()) => {
            if let Some(parent) = side.parent() {
                fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::io(&side, e)),
    }
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

fn write_restored_page(
    data: &File,
    live: &Path,
    offset: u64,
    image: &[u8],
    fit: bool,
) -> Result<(), StoreError> {
    let len = if fit {
        data.metadata().map_err(|e| StoreError::io(live, e))?.len()
    } else {
        0
    };
    if !fit || len == 0 {
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
