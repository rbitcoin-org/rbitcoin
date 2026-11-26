//! Class A tear guard under `store/tear_guard/`.
//!
//! `first` keeps one sealed copy of each stem's first 4 KiB. `tail.0` and
//! `tail.1` alternate the partial last block and every stem's published
//! length. `armed` names the slot generation that holds the before-image.
//! Open copies that generation back without reading the live bytes, and
//! ignores a newer slot. With no `armed` file, open still writes a zeroed
//! page back and leaves a nonzero page alone.

use crate::bulk_io::{self, ReadOp, WriteOp};
use crate::durability::Durable;
use crate::error::StoreError;
use crate::file::{self, TableFile, FILE_HEADER_LEN};
use crate::io_handle::IoHandle;
use bitcoin_hashes::{sha256, Hash, HashEngine};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

const PAGE: usize = 4096;
const STEM_N: usize = 16;
const FIRST_BYTES: u64 = (STEM_N * 2 * PAGE) as u64;
const TAIL_BYTES: u64 = ((STEM_N + 1) * PAGE) as u64;
const CAPF: &[u8; 4] = b"CAPF";
const CAPT: &[u8; 4] = b"CAPT";
const VERSION: u16 = 1;
/// Bytes of the commit record covered by its own checksum.
const COMMIT_BODY: usize = 40;
const COMMIT_SUM_AT: usize = 40;
const TAIL_HEADS: usize = 56;
const TAIL_LENS: usize = 312;
const CHECKSUM_AT: usize = 24;
const CHECKSUM_END: usize = 56;

pub(crate) const CORRUPT_PAGE: &str = "class A page image does not decode over a zeroed block";

/// Sync-array order. Open and the barrier both use this list.
pub(crate) const STEMS: [&str; STEM_N] = [
    "txout.body",
    "seqsigwit.body",
    "spent.body",
    "create.loc",
    "create.loc.ovf",
    "create.off",
    "seqsigwit.loc",
    "seqsigwit.loc.ovf",
    "seqsigwit.off",
    "txid.body",
    "txstat.body",
    "txstat.ovf",
    "txstat.blk",
    "input.loc",
    "input.off",
    "input.body",
];

fn tail_span(published: u64, file_len: u64) -> (u64, u16) {
    if published == 0 || published.is_multiple_of(PAGE as u64) || published > file_len {
        return (0, 0);
    }
    let off = published & !(PAGE as u64 - 1);
    let n = published - off;
    if n == 0 || n > PAGE as u64 {
        return (0, 0);
    }
    (off, n as u16)
}

pub(crate) fn stem_path(hot: &Path, seq: &Path, name: &str) -> PathBuf {
    // `open_seqsigwit` keeps these next to seqsigwit when the store is split.
    if name.starts_with("seqsigwit.") || name.starts_with("txstat.") || name.starts_with("input.") {
        seq.join(name)
    } else {
        hot.join(name)
    }
}

fn guard_dir(hot: &Path) -> PathBuf {
    hot.join("tear_guard")
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut eng = sha256::HashEngine::default();
    for part in parts {
        eng.input(part);
    }
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn tail_checksum(buf: &[u8]) -> [u8; 32] {
    sha256_parts(&[&buf[..CHECKSUM_AT], &buf[CHECKSUM_END..]])
}

fn le_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(bytes);
    u64::from_le_bytes(buf)
}

fn le_u16(bytes: &[u8]) -> u16 {
    let mut buf = [0u8; 2];
    buf.copy_from_slice(bytes);
    u16::from_le_bytes(buf)
}

struct TailSlot {
    generation: u64,
    published: [u64; STEM_N],
    tail_off: [u64; STEM_N],
    tail_len: [u16; STEM_N],
    raw: Vec<u8>,
}

fn parse_tail(raw: Vec<u8>) -> Option<TailSlot> {
    if raw.len() != TAIL_BYTES as usize || raw[0..4] != *CAPT {
        return None;
    }
    if le_u16(&raw[4..6]) != VERSION || le_u16(&raw[6..8]) != STEM_N as u16 {
        return None;
    }
    let generation = le_u64(&raw[8..16]);
    if generation == 0 || tail_checksum(&raw) != raw[CHECKSUM_AT..CHECKSUM_END] {
        return None;
    }
    let mut published = [0u64; STEM_N];
    let mut tail_off = [0u64; STEM_N];
    let mut tail_len = [0u16; STEM_N];
    for i in 0..STEM_N {
        let head = TAIL_HEADS + i * 16;
        published[i] = le_u64(&raw[head..head + 8]);
        tail_off[i] = le_u64(&raw[head + 8..head + 16]);
        tail_len[i] = le_u16(&raw[TAIL_LENS + i * 2..TAIL_LENS + i * 2 + 2]);
        if tail_len[i] as usize > PAGE {
            return None;
        }
    }
    Some(TailSlot {
        generation,
        published,
        tail_off,
        tail_len,
        raw,
    })
}

fn image_of(slot: &TailSlot, stem: usize) -> &[u8] {
    let page = PAGE + stem * PAGE;
    let n = slot.tail_len[stem] as usize;
    &slot.raw[page..page + n]
}

struct FirstCommit {
    image: Vec<u8>,
}

fn parse_commit(first: &[u8], stem: usize) -> Option<FirstCommit> {
    let image_at = stem * 2 * PAGE;
    let commit_at = image_at + PAGE;
    if first.len() < commit_at + PAGE {
        return None;
    }
    let commit = &first[commit_at..commit_at + PAGE];
    if commit[0..4] != *CAPF || le_u16(&commit[4..6]) as usize != stem {
        return None;
    }
    if le_u16(&commit[6..8]) != PAGE as u16 {
        return None;
    }
    if sha256_parts(&[&commit[..COMMIT_BODY]]) != commit[COMMIT_SUM_AT..COMMIT_SUM_AT + 32] {
        return None;
    }
    let image = first[image_at..image_at + PAGE].to_vec();
    if sha256_parts(&[&image]) != commit[8..40] {
        return None;
    }
    Some(FirstCommit { image })
}

fn fill_commit(page: &mut [u8], stem: usize, image: &[u8]) {
    page[..PAGE].fill(0);
    page[0..4].copy_from_slice(CAPF);
    page[4..6].copy_from_slice(&(stem as u16).to_le_bytes());
    page[6..8].copy_from_slice(&(PAGE as u16).to_le_bytes());
    page[8..40].copy_from_slice(&sha256_parts(&[image]));
    let sum = sha256_parts(&[&page[..COMMIT_BODY]]);
    page[COMMIT_SUM_AT..COMMIT_SUM_AT + 32].copy_from_slice(&sum);
}

fn pread_exact(file: &File, path: &Path, offset: u64, buf: &mut [u8]) -> Result<(), StoreError> {
    if buf.is_empty() {
        return Ok(());
    }
    let mut op = ReadOp {
        fd: IoHandle::from_file(file),
        offset,
        buf,
        result: i32::MIN,
    };
    bulk_io::pread_batch(std::slice::from_mut(&mut op));
    finish_read(path, op.result, buf.len())
}

fn finish_read(path: &Path, result: i32, want: usize) -> Result<(), StoreError> {
    if result < 0 {
        return Err(StoreError::io(
            path,
            std::io::Error::from_raw_os_error(-result),
        ));
    }
    if result as usize != want {
        return Err(StoreError::Corrupt("class A page image short read"));
    }
    Ok(())
}

fn pwrite_exact(file: &File, path: &Path, offset: u64, buf: &[u8]) -> Result<(), StoreError> {
    if buf.is_empty() {
        return Ok(());
    }
    let mut op = WriteOp {
        fd: IoHandle::from_file(file),
        offset,
        buf,
        result: i32::MIN,
    };
    bulk_io::pwrite_batch(std::slice::from_mut(&mut op));
    if op.result < 0 {
        return Err(StoreError::io(
            path,
            std::io::Error::from_raw_os_error(-op.result),
        ));
    }
    if op.result as usize != buf.len() {
        return Err(StoreError::io(
            path,
            std::io::Error::other("class A page image short write"),
        ));
    }
    Ok(())
}

fn sync_files(files: &[(&Path, &File)]) -> Result<(), StoreError> {
    if files.is_empty() {
        return Ok(());
    }
    #[cfg(debug_assertions)]
    if crate::durability::flushes_skipped() {
        return Ok(());
    }
    let handles: Vec<_> = files.iter().map(|(_, f)| IoHandle::from_file(f)).collect();
    let res = bulk_io::sync_data_batch(&handles).unwrap_or_else(|| vec![i32::MIN; handles.len()]);
    for ((path, file), result) in files.iter().zip(res) {
        match result {
            0 => {}
            i32::MIN => file
                .durable_sync_data()
                .map_err(|e| StoreError::io(*path, e))?,
            errno => {
                return Err(StoreError::io(
                    *path,
                    std::io::Error::from_raw_os_error(-errno),
                ));
            }
        }
    }
    Ok(())
}

fn open_rw(path: &Path) -> Result<File, StoreError> {
    file::table_open_opts()
        .open(path)
        .map_err(|e| StoreError::io(path, e))
}

fn read_fixed(path: &Path, len: u64) -> Result<Option<Vec<u8>>, StoreError> {
    if !path.try_exists().map_err(|e| StoreError::io(path, e))? {
        return Ok(None);
    }
    let file = open_rw(path)?;
    let got = file.metadata().map_err(|e| StoreError::io(path, e))?.len();
    if got != len {
        return Ok(None);
    }
    let mut buf = vec![0u8; len as usize];
    pread_exact(&file, path, 0, &mut buf)?;
    Ok(Some(buf))
}

fn header_published(file: &File, path: &Path, file_len: u64) -> Result<u64, StoreError> {
    if file_len < FILE_HEADER_LEN as u64 {
        return Ok(0);
    }
    let mut header = [0u8; FILE_HEADER_LEN];
    pread_exact(file, path, 0, &mut header)?;
    Ok(le_u64(&header[8..16]))
}

fn create_zero_file(path: &Path, len: u64) -> Result<bool, StoreError> {
    if path.try_exists().map_err(|e| StoreError::io(path, e))? {
        return Ok(false);
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let file = opts.open(path).map_err(|e| StoreError::io(path, e))?;
    file.set_len(len).map_err(|e| StoreError::io(path, e))?;
    file.durable_sync_data()
        .map_err(|e| StoreError::io(path, e))?;
    Ok(true)
}

/// A missing tail file, or one that is not yet a `CAPT` header, becomes generation 0.
fn write_vacant_tail(path: &Path) -> Result<(), StoreError> {
    let file = open_rw(path)?;
    let len = file.metadata().map_err(|e| StoreError::io(path, e))?.len();
    if len >= 4 {
        let mut magic = [0u8; 4];
        pread_exact(&file, path, 0, &mut magic)?;
        if magic == *CAPT {
            return Ok(());
        }
    }
    if len < TAIL_BYTES {
        file.set_len(TAIL_BYTES)
            .map_err(|e| StoreError::io(path, e))?;
    }
    let mut buf = vec![0u8; TAIL_BYTES as usize];
    buf[0..4].copy_from_slice(CAPT);
    buf[4..6].copy_from_slice(&VERSION.to_le_bytes());
    buf[6..8].copy_from_slice(&(STEM_N as u16).to_le_bytes());
    let sum = tail_checksum(&buf);
    buf[CHECKSUM_AT..CHECKSUM_END].copy_from_slice(&sum);
    pwrite_exact(&file, path, 0, &buf)?;
    sync_files(&[(path, &file)])
}

const ARMED_MAGIC: &[u8; 4] = b"CARM";
const ARMED_LEN: usize = 16;

/// Store `meta` when this directory is a datadir. A table fixture has no
/// `meta`; the arm still publishes, and open of that fixture never served a
/// schema check.
fn meta_version(hot: &Path) -> Result<Option<u16>, StoreError> {
    match crate::store::check_meta(hot) {
        Ok(ver) => Ok(Some(ver)),
        Err(StoreError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Publish `tear_guard/armed` naming `generation`.
///
/// Errors while `meta` is still 30 and does not create the file. An existing
/// mark is left in place: the appender calls this again inside one window.
#[doc(hidden)]
pub fn arm_named_generation(hot: &Path, generation: u64) -> Result<(), StoreError> {
    if meta_version(hot)?.is_some_and(|ver| ver < 31) {
        return Err(StoreError::Rejected("class A arm while meta is 30"));
    }
    let path = guard_dir(hot).join("armed");
    if path.try_exists().map_err(|e| StoreError::io(&path, e))? {
        return Ok(());
    }
    publish_armed(&path, generation)
}

fn armed_bytes(generation: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ARMED_LEN);
    buf.extend_from_slice(ARMED_MAGIC);
    buf.extend_from_slice(&rbitcoin_primitives::SCHEMA_VERSION.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&generation.to_le_bytes());
    buf
}

fn publish_armed(path: &Path, generation: u64) -> Result<(), StoreError> {
    file::write_synced_tmp_rename(path, &armed_bytes(generation))
}

/// Overwrite an existing mark. The previous bytes stay until the rename.
fn replace_armed(path: &Path, generation: u64) -> Result<(), StoreError> {
    publish_armed(path, generation)
}

/// The appender's arm. Promotes `meta` to 31 and syncs it before the rename
/// when the datadir is still 30. A newer sealed slot replaces the mark with
/// that generation; otherwise the current mark stays.
pub(crate) fn arm_for_appender(hot: &Path) -> Result<u64, StoreError> {
    let dir = guard_dir(hot);
    let armed = read_armed(&dir)?;
    let newest = newest_generation(&dir)?;
    if let Some(generation) = armed {
        if newest <= generation {
            return Ok(generation);
        }
        // The newer slot is a quiescent seal. Name it by replacing the mark
        // in one rename, so a crash still has one of the two generations.
        if meta_version(hot)?.is_some_and(|ver| ver < 31) {
            return Err(StoreError::Rejected("class A arm while meta is 30"));
        }
        replace_armed(&dir.join("armed"), newest)?;
        return Ok(newest);
    }
    if meta_version(hot)?.is_some_and(|ver| ver < 31) {
        crate::store::write_meta_at(hot, 31)?;
    }
    arm_named_generation(hot, newest)?;
    Ok(newest)
}

/// Remove `tear_guard/armed` and sync its directory. Already gone is fine.
pub(crate) fn clear_armed(hot: &Path) -> Result<(), StoreError> {
    clear_armed_file(&guard_dir(hot).join("armed"))
}

fn clear_armed_file(path: &Path) -> Result<(), StoreError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Err(StoreError::Rejected("class A armed mark has no directory"));
    };
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(StoreError::io(path, e)),
    }
    file::fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
    Ok(())
}

fn read_armed(dir: &Path) -> Result<Option<u64>, StoreError> {
    let path = dir.join("armed");
    let raw = match std::fs::read(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(StoreError::io(&path, e)),
    };
    if raw.len() != ARMED_LEN || raw[0..4] != *ARMED_MAGIC {
        return Err(StoreError::Corrupt("class A armed mark"));
    }
    let schema = le_u16(&raw[4..6]);
    if !rbitcoin_primitives::schema_file_openable(schema) || raw[6] != 0 || raw[7] != 0 {
        return Err(StoreError::Corrupt("class A armed mark"));
    }
    Ok(Some(le_u64(&raw[8..16])))
}

fn newest_generation(dir: &Path) -> Result<u64, StoreError> {
    let (slot0, slot1) = load_tails(dir)?;
    Ok(match (slot0, slot1) {
        (Some(a), Some(b)) => a.generation.max(b.generation),
        (Some(a), None) => a.generation,
        (None, Some(b)) => b.generation,
        (None, None) => 0,
    })
}

fn named_slot<'a>(
    generation: u64,
    slot0: &'a Option<TailSlot>,
    slot1: &'a Option<TailSlot>,
) -> Result<Option<&'a TailSlot>, StoreError> {
    match (slot0, slot1) {
        (Some(slot), _) if slot.generation == generation => Ok(Some(slot)),
        (_, Some(slot)) if slot.generation == generation => Ok(Some(slot)),
        _ if generation == 0 => Ok(None),
        _ => Err(StoreError::Corrupt("class A armed generation missing")),
    }
}

/// Copy the named generation onto every stem except `spent.body`, drop any
/// newer slot, and remove `armed`. Live bytes are not consulted.
fn restore_named_generation(
    hot: &Path,
    seq: &Path,
    dir: &Path,
    generation: u64,
    first_raw: &[u8],
    slot0: &Option<TailSlot>,
    slot1: &Option<TailSlot>,
) -> Result<(), StoreError> {
    let slot = named_slot(generation, slot0, slot1)?;
    for (i, name) in STEMS.iter().enumerate() {
        if *name == "spent.body" {
            continue;
        }
        restore_armed_stem(hot, seq, name, i, first_raw, slot)?;
    }
    if let Some(slot) = slot {
        let settled = le_u64(&slot.raw[16..24]);
        let current = crate::tx_table::read_class_a_synced(hot)?;
        if current != settled {
            file::write_synced_tmp_rename(
                &hot.join(crate::tx_table::CLASS_A_SYNCED_NAME),
                &settled.to_le_bytes(),
            )?;
        }
    }
    retire_other_slots(dir, generation)?;
    clear_armed_file(&dir.join("armed"))
}

fn restore_armed_stem(
    hot: &Path,
    seq: &Path,
    name: &str,
    stem: usize,
    first_raw: &[u8],
    slot: Option<&TailSlot>,
) -> Result<(), StoreError> {
    let path = stem_path(hot, seq, name);
    if !path.try_exists().map_err(|e| StoreError::io(&path, e))? {
        return Ok(());
    }
    let file = open_rw(&path)?;
    let file_len = file.metadata().map_err(|e| StoreError::io(&path, e))?.len();
    if file_len == 0 {
        return Ok(());
    }
    let mut wrote = false;
    let page0_from_slot =
        slot.is_some_and(|slot| slot.tail_off[stem] == 0 && slot.tail_len[stem] > 0);
    if let Some(slot) = slot.filter(|_| page0_from_slot) {
        let mut image = image_of(slot, stem).to_vec();
        stamp_loaded_len(&mut image, slot.published[stem]);
        pwrite_exact(&file, &path, 0, &image)?;
        wrote = true;
    } else if let Some(commit) = parse_commit(first_raw, stem) {
        let mut image = commit.image;
        let published = slot.map(|slot| slot.published[stem]).unwrap_or(0);
        let len = recorded_len(slot, stem, published, le_u64(&image[8..16]));
        image[8..16].copy_from_slice(&len.to_le_bytes());
        pwrite_exact(&file, &path, 0, &image)?;
        wrote = true;
    }
    if let Some(slot) = slot {
        let off = slot.tail_off[stem];
        let n = slot.tail_len[stem];
        if n > 0 && off >= PAGE as u64 {
            let image = image_of(slot, stem);
            let take = (n as usize).min(image.len());
            pwrite_exact(&file, &path, off, &image[..take])?;
            wrote = true;
        }
    }
    if wrote {
        sync_files(&[(&path, &file)])?;
    }
    Ok(())
}

fn retire_other_slots(dir: &Path, keep: u64) -> Result<(), StoreError> {
    for name in ["tail.0", "tail.1"] {
        let path = dir.join(name);
        let Some(raw) = read_fixed(&path, TAIL_BYTES)? else {
            continue;
        };
        let Some(slot) = parse_tail(raw) else {
            continue;
        };
        if keep != 0 && slot.generation == keep {
            continue;
        }
        let file = open_rw(&path)?;
        pwrite_exact(&file, &path, 0, &[0, 0, 0, 0])?;
        sync_files(&[(&path, &file)])?;
    }
    Ok(())
}

const CATK: &[u8; 4] = b"CATK";
const CATK_HEAD: usize = 16;

/// Apply a leftover `CATK` `{stem}.kept` when its range is zeroes, then unlink it.
fn migrate_kept(hot: &Path, seq: &Path) -> Result<(), StoreError> {
    for name in STEMS {
        migrate_one_kept(&stem_path(hot, seq, name))?;
    }
    Ok(())
}

fn kept_side(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("file"))
        .to_os_string();
    name.push(".kept");
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(name),
        _ => PathBuf::from(name),
    }
}

fn migrate_one_kept(path: &Path) -> Result<(), StoreError> {
    let side = kept_side(path);
    if !side.try_exists().map_err(|e| StoreError::io(&side, e))? {
        return Ok(());
    }
    let raw = read_side(&side)?;
    if let Some((block, image)) = parse_catk(&raw) {
        if path.try_exists().map_err(|e| StoreError::io(path, e))? {
            let file = open_rw(path)?;
            let file_len = file.metadata().map_err(|e| StoreError::io(path, e))?.len();
            let end = block.saturating_add(image.len() as u64);
            if end <= file_len {
                let mut current = vec![0u8; image.len()];
                pread_exact(&file, path, block, &mut current)?;
                if all_zero(&current) {
                    pwrite_exact(&file, path, block, image)?;
                    sync_files(&[(path, &file)])?;
                }
            }
        }
    }
    match std::fs::remove_file(&side) {
        Ok(()) => {
            let parent = side.parent().unwrap_or_else(|| Path::new("."));
            file::fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(StoreError::io(&side, e)),
    }
    Ok(())
}

fn read_side(path: &Path) -> Result<Vec<u8>, StoreError> {
    let file = open_rw(path)?;
    let n = file.metadata().map_err(|e| StoreError::io(path, e))?.len();
    if n > (PAGE + CATK_HEAD) as u64 {
        return Ok(Vec::new());
    }
    let mut buf = vec![0u8; n as usize];
    pread_exact(&file, path, 0, &mut buf)?;
    Ok(buf)
}

fn parse_catk(raw: &[u8]) -> Option<(u64, &[u8])> {
    if raw.len() < CATK_HEAD || raw[0..4] != *CATK {
        return None;
    }
    let block = le_u64(&raw[4..12]);
    let n = u32::from_le_bytes(raw[12..16].try_into().ok()?) as usize;
    if !block.is_multiple_of(PAGE as u64) || n == 0 || n > PAGE || raw.len() != CATK_HEAD + n {
        return None;
    }
    Some((block, &raw[CATK_HEAD..]))
}

fn ensure_guard(hot: &Path) -> Result<(), StoreError> {
    let dir = guard_dir(hot);
    let created_dir = !dir.try_exists().map_err(|e| StoreError::io(&dir, e))?;
    std::fs::create_dir_all(&dir).map_err(|e| StoreError::io(&dir, e))?;
    let first = dir.join("first");
    let tail0 = dir.join("tail.0");
    let tail1 = dir.join("tail.1");
    let mut created = created_dir;
    created |= create_zero_file(&first, FIRST_BYTES)?;
    created |= create_zero_file(&tail0, TAIL_BYTES)?;
    created |= create_zero_file(&tail1, TAIL_BYTES)?;
    write_vacant_tail(&tail0)?;
    write_vacant_tail(&tail1)?;
    if created {
        file::fsync_parent_dir(hot).map_err(|e| StoreError::io(hot, e))?;
        file::fsync_parent_dir(&dir).map_err(|e| StoreError::io(&dir, e))?;
    }
    Ok(())
}

fn load_tails(dir: &Path) -> Result<(Option<TailSlot>, Option<TailSlot>), StoreError> {
    let slot0 = read_fixed(&dir.join("tail.0"), TAIL_BYTES)?.and_then(parse_tail);
    let slot1 = read_fixed(&dir.join("tail.1"), TAIL_BYTES)?.and_then(parse_tail);
    Ok((slot0, slot1))
}

fn newer<'a>(a: &'a TailSlot, b: &'a Option<TailSlot>) -> &'a TailSlot {
    match b {
        Some(other) if other.generation > a.generation => other,
        _ => a,
    }
}

fn all_zero(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.iter().all(|b| *b == 0)
}

/// Create the guard if needed, restore zeroed pages, and seal a vacant `first`.
///
/// When neither tail slot is usable, write `tail.0` as generation 1 from the
/// bytes already on disk so a later tear has a synced image.
pub(crate) fn prepare_and_restore(hot: &Path, seq: &Path) -> Result<(), StoreError> {
    migrate_kept(hot, seq)?;
    ensure_guard(hot)?;
    let dir = guard_dir(hot);
    let first_path = dir.join("first");
    let first_raw = read_fixed(&first_path, FIRST_BYTES)?.unwrap_or_default();
    let (slot0, slot1) = load_tails(&dir)?;
    if let Some(generation) = read_armed(&dir)? {
        restore_named_generation(hot, seq, &dir, generation, &first_raw, &slot0, &slot1)?;
        seal_vacant_from_disk(hot, seq, &first_path, &first_raw)?;
        return Ok(());
    }
    let best = match (&slot0, &slot1) {
        (Some(a), b) => Some(newer(a, b)),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    for (i, name) in STEMS.iter().enumerate() {
        restore_stem(hot, seq, name, i, &first_raw, best)?;
    }
    seal_vacant_from_disk(hot, seq, &first_path, &first_raw)?;
    if best.is_none() {
        let named = crate::tx_table::read_class_a_synced(hot)?;
        publish_tail_from_disk(hot, seq, &dir, named)?;
    }
    Ok(())
}

fn restore_stem(
    hot: &Path,
    seq: &Path,
    name: &str,
    stem: usize,
    first_raw: &[u8],
    best: Option<&TailSlot>,
) -> Result<(), StoreError> {
    let path = stem_path(hot, seq, name);
    if !path.try_exists().map_err(|e| StoreError::io(&path, e))? {
        return Ok(());
    }
    let file = open_rw(&path)?;
    let file_len = file.metadata().map_err(|e| StoreError::io(&path, e))?.len();
    if file_len == 0 {
        return Ok(());
    }
    let header_len = header_published(&file, &path, file_len)?;
    let mut published = best
        .map(|slot| slot.published[stem])
        .filter(|n| *n > 0)
        .unwrap_or(header_len);
    let page_n = (file_len as usize).min(PAGE);
    let mut page0 = vec![0u8; page_n];
    pread_exact(&file, &path, 0, &mut page0)?;
    let page0_zero = all_zero(&page0);
    let page0_restored = restore_page0(&file, &path, stem, published, first_raw, best, &page0)?;
    if page0_restored {
        // The live header was zeros, so `published` was 0 when no slot parsed.
        // The length just written is the one the tail check has to use.
        let restored_len = header_published(&file, &path, file_len)?;
        if restored_len > published {
            published = restored_len;
        }
    }
    let tail_restored = restore_tail_block(&file, &path, stem, published, file_len, best)?;
    if page0_restored || tail_restored {
        sync_files(&[(&path, &file)])?;
    }
    refuse_zero_prefix(
        &file,
        &path,
        name,
        published,
        file_len,
        ZeroRefuse {
            page0_unrestored: page0_zero && !page0_restored,
            tail_restored,
            no_slot: best.is_none(),
        },
    )
}

struct ZeroRefuse {
    page0_unrestored: bool,
    tail_restored: bool,
    no_slot: bool,
}

fn restore_page0(
    file: &File,
    path: &Path,
    stem: usize,
    published: u64,
    first_raw: &[u8],
    best: Option<&TailSlot>,
    page0: &[u8],
) -> Result<bool, StoreError> {
    if all_zero(page0) {
        if let Some(commit) = parse_commit(first_raw, stem) {
            let mut image = commit.image;
            let len = recorded_len(best, stem, published, le_u64(&image[8..16]));
            image[8..16].copy_from_slice(&len.to_le_bytes());
            pwrite_exact(file, path, 0, &image)?;
            return Ok(true);
        }
    }
    let Some(slot) = best else {
        return Ok(false);
    };
    if slot.tail_off[stem] != 0 || slot.tail_len[stem] == 0 {
        return Ok(false);
    }
    let raw = image_of(slot, stem);
    let mut image = raw.to_vec();
    stamp_loaded_len(&mut image, slot.published[stem]);
    // One write. A page that is still the unstamped image is that write
    // without the slot length, so the next open would otherwise keep it.
    if page_holds(page0, &image) {
        return Ok(false);
    }
    if all_zero(page0) || page_holds(page0, raw) {
        pwrite_exact(file, path, 0, &image)?;
        return Ok(true);
    }
    Ok(false)
}

fn page_holds(page: &[u8], image: &[u8]) -> bool {
    page.len() >= image.len()
        && &page[..image.len()] == image
        && page[image.len()..].iter().all(|byte| *byte == 0)
}

fn stamp_loaded_len(image: &mut [u8], published: u64) {
    if published > 0 && image.len() >= 16 {
        image[8..16].copy_from_slice(&published.to_le_bytes());
    }
}

/// A tail slot's length wins over the length bytes inside a page image.
/// Those bytes can be a later `persist_hwm` that landed during the copy.
fn recorded_len(best: Option<&TailSlot>, stem: usize, published: u64, image_len: u64) -> u64 {
    if let Some(slot) = best {
        if slot.published[stem] > 0 {
            return slot.published[stem];
        }
    }
    if published > image_len {
        published
    } else {
        image_len
    }
}

fn restore_tail_block(
    file: &File,
    path: &Path,
    stem: usize,
    published: u64,
    file_len: u64,
    best: Option<&TailSlot>,
) -> Result<bool, StoreError> {
    let (off, n) = tail_span(published, file_len);
    if n == 0 || off < PAGE as u64 {
        return Ok(false);
    }
    let mut prefix = vec![0u8; n as usize];
    pread_exact(file, path, off, &mut prefix)?;
    if !all_zero(&prefix) {
        return Ok(false);
    }
    let Some(slot) = best else {
        return Ok(false);
    };
    if slot.tail_off[stem] != off || slot.tail_len[stem] < n {
        return Ok(false);
    }
    let image = image_of(slot, stem);
    let take = (n as usize).min(image.len());
    pwrite_exact(file, path, off, &image[..take])?;
    Ok(true)
}

/// A coinbase edge, an unstamped txstat cell, an empty seqsigwit pad, and an
/// unspent slot are zero bytes. With no tail slot yet, that prefix is the
/// data, not a tear.
fn zero_tail_is_record(name: &str) -> bool {
    name == "input.body"
        || name == "seqsigwit.body"
        || name == "spent.body"
        || name.starts_with("txstat.")
}

fn refuse_zero_prefix(
    file: &File,
    path: &Path,
    name: &str,
    published: u64,
    file_len: u64,
    flags: ZeroRefuse,
) -> Result<(), StoreError> {
    if published == 0 || file_len == 0 {
        return Ok(());
    }
    // A synced image may itself be zeros (unstamped txstat cells, an empty
    // seqsigwit pad, an unspent slot). Stop only when a zeroed prefix had
    // no usable image to put back.
    if flags.page0_unrestored {
        let page_n = (file_len as usize).min(PAGE).min(published as usize);
        if page_n > 0 {
            let mut page0 = vec![0u8; page_n];
            pread_exact(file, path, 0, &mut page0)?;
            if all_zero(&page0) {
                return Err(StoreError::Corrupt(CORRUPT_PAGE));
            }
        }
    }
    let (off, n) = tail_span(published, file_len);
    if n > 0
        && off >= PAGE as u64
        && !flags.tail_restored
        && !(flags.no_slot && zero_tail_is_record(name))
    {
        let mut prefix = vec![0u8; n as usize];
        pread_exact(file, path, off, &mut prefix)?;
        if all_zero(&prefix) {
            return Err(StoreError::Corrupt(CORRUPT_PAGE));
        }
    }
    Ok(())
}

fn seal_vacant_from_disk(
    hot: &Path,
    seq: &Path,
    first_path: &Path,
    first_raw: &[u8],
) -> Result<(), StoreError> {
    let mut images = Vec::new();
    for (i, name) in STEMS.iter().enumerate() {
        if parse_commit(first_raw, i).is_some() {
            continue;
        }
        let path = stem_path(hot, seq, name);
        let Some(image) = page0_to_seal(&path)? else {
            continue;
        };
        images.push((i, image));
    }
    write_seals(first_path, &images)
}

fn page0_to_seal(path: &Path) -> Result<Option<Vec<u8>>, StoreError> {
    if !path.try_exists().map_err(|e| StoreError::io(path, e))? {
        return Ok(None);
    }
    let file = open_rw(path)?;
    let file_len = file.metadata().map_err(|e| StoreError::io(path, e))?.len();
    let published = header_published(&file, path, file_len)?;
    if published < PAGE as u64 {
        return Ok(None);
    }
    let mut image = vec![0u8; PAGE];
    let n = (file_len as usize).min(PAGE);
    if n > 0 {
        pread_exact(&file, path, 0, &mut image[..n])?;
    }
    if n > 0 && all_zero(&image[..n]) {
        return Ok(None);
    }
    Ok(Some(image))
}

fn write_seals(first_path: &Path, images: &[(usize, Vec<u8>)]) -> Result<(), StoreError> {
    if images.is_empty() {
        return Ok(());
    }
    let first = open_rw(first_path)?;
    if first
        .metadata()
        .map_err(|e| StoreError::io(first_path, e))?
        .len()
        < FIRST_BYTES
    {
        first
            .set_len(FIRST_BYTES)
            .map_err(|e| StoreError::io(first_path, e))?;
    }
    for (stem, image) in images {
        let at = (*stem as u64) * 2 * PAGE as u64;
        pwrite_exact(&first, first_path, at, image)?;
    }
    sync_files(&[(first_path, &first)])?;
    for (stem, image) in images {
        let mut commit = vec![0u8; PAGE];
        fill_commit(&mut commit, *stem, image);
        let at = (*stem as u64) * 2 * PAGE as u64 + PAGE as u64;
        pwrite_exact(&first, first_path, at, &commit)?;
    }
    sync_files(&[(first_path, &first)])
}

struct Snap {
    published: u64,
    file_len: u64,
    fd: IoHandle,
    _file: File,
}

fn publish_tail_from_disk(
    hot: &Path,
    seq: &Path,
    dir: &Path,
    settled: u64,
) -> Result<(), StoreError> {
    let mut snaps = Vec::with_capacity(STEM_N);
    for name in STEMS {
        snaps.push(snap_stem(&stem_path(hot, seq, name))?);
    }
    let specs: Vec<(u64, u64, Option<IoHandle>)> = snaps
        .iter()
        .map(|snap| match snap {
            Some(snap) => (snap.published, snap.file_len, Some(snap.fd)),
            None => (0, 0, None),
        })
        .collect();
    let tail_path = dir.join("tail.0");
    let tail = open_rw(&tail_path)?;
    write_tail_image(&tail, &tail_path, 1, settled, &specs, true)?;
    drop(snaps);
    Ok(())
}

fn snap_stem(path: &Path) -> Result<Option<Snap>, StoreError> {
    if !path.try_exists().map_err(|e| StoreError::io(path, e))? {
        return Ok(None);
    }
    let file = open_rw(path)?;
    let file_len = file.metadata().map_err(|e| StoreError::io(path, e))?.len();
    let published = header_published(&file, path, file_len)?;
    let fd = IoHandle::from_file(&file);
    Ok(Some(Snap {
        published,
        file_len,
        fd,
        _file: file,
    }))
}

fn write_tail_image(
    file: &File,
    path: &Path,
    generation: u64,
    settled: u64,
    stems: &[(u64, u64, Option<IoHandle>)],
    sync_now: bool,
) -> Result<(), StoreError> {
    let len = file.metadata().map_err(|e| StoreError::io(path, e))?.len();
    if len < TAIL_BYTES {
        file.set_len(TAIL_BYTES)
            .map_err(|e| StoreError::io(path, e))?;
    }
    let buf = tail_image_buf(path, generation, settled, stems)?;
    pwrite_exact(file, path, 0, &buf)?;
    if sync_now {
        sync_files(&[(path, file)])?;
    }
    Ok(())
}

/// Header plus the tail pages the barrier copies. Does not write the file.
fn tail_image_buf(
    path: &Path,
    generation: u64,
    settled: u64,
    stems: &[(u64, u64, Option<IoHandle>)],
) -> Result<Vec<u8>, StoreError> {
    let mut buf = vec![0u8; TAIL_BYTES as usize];
    buf[0..4].copy_from_slice(CAPT);
    buf[4..6].copy_from_slice(&VERSION.to_le_bytes());
    buf[6..8].copy_from_slice(&(STEM_N as u16).to_le_bytes());
    buf[8..16].copy_from_slice(&generation.to_le_bytes());
    buf[16..24].copy_from_slice(&settled.to_le_bytes());
    let mut spans = [(0u64, 0u16); STEM_N];
    for (i, (published, file_len, _)) in stems.iter().enumerate() {
        let (off, n) = tail_span(*published, *file_len);
        spans[i] = (off, n);
        let head = TAIL_HEADS + i * 16;
        buf[head..head + 8].copy_from_slice(&published.to_le_bytes());
        buf[head + 8..head + 16].copy_from_slice(&off.to_le_bytes());
        buf[TAIL_LENS + i * 2..TAIL_LENS + i * 2 + 2].copy_from_slice(&n.to_le_bytes());
    }
    read_tail_images(path, &mut buf, stems, &spans)?;
    for (i, (published, _, _)) in stems.iter().enumerate() {
        let (off, n) = spans[i];
        if off == 0 && n >= 16 {
            let at = PAGE + i * PAGE;
            stamp_loaded_len(&mut buf[at..at + n as usize], *published);
        }
    }
    let sum = tail_checksum(&buf);
    buf[CHECKSUM_AT..CHECKSUM_END].copy_from_slice(&sum);
    Ok(buf)
}

fn read_tail_images(
    path: &Path,
    buf: &mut [u8],
    stems: &[(u64, u64, Option<IoHandle>)],
    spans: &[(u64, u16)],
) -> Result<(), StoreError> {
    let mut ops: Vec<ReadOp<'_>> = Vec::new();
    let mut pages: Vec<&mut [u8]> = buf[PAGE..].chunks_mut(PAGE).take(STEM_N).collect();
    for (i, page) in pages.iter_mut().enumerate() {
        let n = spans[i].1 as usize;
        if n == 0 {
            continue;
        }
        let Some(fd) = stems[i].2 else {
            return Err(StoreError::Corrupt("class A tail stem missing"));
        };
        ops.push(ReadOp {
            fd,
            offset: spans[i].0,
            buf: &mut page[..n],
            result: i32::MIN,
        });
    }
    if ops.is_empty() {
        return Ok(());
    }
    bulk_io::pread_batch(&mut ops);
    for op in &ops {
        finish_read(path, op.result, op.buf.len())?;
    }
    Ok(())
}

/// Slot to overwrite, and the generation to write. `protect` is the
/// generation `armed` names. That slot stays, even when it is the older one.
fn barrier_slot(
    slot0: &Option<TailSlot>,
    slot1: &Option<TailSlot>,
    protect: Option<u64>,
) -> (u8, u64) {
    let next = match (slot0, slot1) {
        (None, None) => 1,
        (Some(a), None) => a.generation.saturating_add(1),
        (None, Some(b)) => b.generation.saturating_add(1),
        (Some(a), Some(b)) => a.generation.max(b.generation).saturating_add(1),
    };
    let holds = |slot: &Option<TailSlot>| {
        protect.is_some_and(|generation| slot.as_ref().is_some_and(|s| s.generation == generation))
    };
    if holds(slot0) && !holds(slot1) {
        return (1, next);
    }
    if holds(slot1) && !holds(slot0) {
        return (0, next);
    }
    inactive_slot(slot0, slot1)
}

fn inactive_slot(slot0: &Option<TailSlot>, slot1: &Option<TailSlot>) -> (u8, u64) {
    match (
        slot0.as_ref().map(|slot| slot.generation),
        slot1.as_ref().map(|slot| slot.generation),
    ) {
        (None, None) => (0, 1),
        (Some(gen0), None) => (1, gen0 + 1),
        (None, Some(gen1)) => (0, gen1 + 1),
        (Some(gen0), Some(gen1)) if gen1 > gen0 => (0, gen1 + 1),
        (Some(gen0), Some(_)) => (1, gen0 + 1),
    }
}

/// Copy partial tails into the inactive slot and seal any full page 0 once.
///
/// One thread appends each stem and stores `published_len` after that
/// pwrite. This thread reads only up to the length it loaded, then writes
/// the slot and fsyncs it with those stems. No page lock.
pub(crate) fn write_barrier(
    hot: &Path,
    files: &[&TableFile; STEM_N],
    settled: u64,
    protect: Option<u64>,
) -> Result<u64, StoreError> {
    for (file, name) in files.iter().zip(STEMS) {
        debug_assert!(
            file.path().ends_with(name),
            "class A stem order drifted at {name}"
        );
    }
    ensure_guard(hot)?;
    let dir = guard_dir(hot);
    let (slot0, slot1) = load_tails(&dir)?;
    let (inactive, generation) = barrier_slot(&slot0, &slot1, protect);
    let tail_path = dir.join(if inactive == 0 { "tail.0" } else { "tail.1" });
    let tail = open_rw(&tail_path)?;
    let first_path = dir.join("first");
    let first_raw = read_fixed(&first_path, FIRST_BYTES)?.unwrap_or_default();
    let mut specs = Vec::with_capacity(STEM_N);
    for file in files {
        let published = file
            .published_len
            .load(std::sync::atomic::Ordering::Acquire);
        let file_len = file
            .read_file
            .metadata()
            .map_err(|e| StoreError::io(file.path(), e))?
            .len();
        specs.push((published, file_len, Some(file.io_handle())));
    }
    let tail_buf = tail_image_buf(&tail_path, generation, settled, &specs)?;
    let mut images = Vec::new();
    for (i, file) in files.iter().enumerate() {
        if parse_commit(&first_raw, i).is_some() || specs[i].0 < PAGE as u64 {
            continue;
        }
        let mut image = vec![0u8; PAGE];
        let n = (specs[i].1 as usize).min(PAGE);
        if n > 0 {
            pread_exact(&file.read_file, file.path(), 0, &mut image[..n])?;
        }
        if n > 0 && all_zero(&image[..n]) {
            continue;
        }
        stamp_loaded_len(&mut image, specs[i].0);
        images.push((i, image));
    }
    let len = tail
        .metadata()
        .map_err(|e| StoreError::io(&tail_path, e))?
        .len();
    if len < TAIL_BYTES {
        tail.set_len(TAIL_BYTES)
            .map_err(|e| StoreError::io(&tail_path, e))?;
    }
    pwrite_exact(&tail, &tail_path, 0, &tail_buf)?;
    crate::file::TableFile::sync_data_all_with(files, &[(&tail_path, &tail)])?;
    write_seals(&first_path, &images)?;
    Ok(generation)
}
