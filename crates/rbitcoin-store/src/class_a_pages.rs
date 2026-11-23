//! Class A tear guard under `store/tear_guard/`.
//!
//! `first` keeps one sealed copy of each stem's first 4 KiB. `tail.0` and
//! `tail.1` alternate the partial last block and every stem's published
//! length. Readers stay on the main file. Open writes a zeroed page back.

use crate::bulk_io::{self, ReadOp, WriteOp};
use crate::durability::Durable;
use crate::error::StoreError;
use crate::file::{self, TableFile, FILE_HEADER_LEN};
use crate::io_handle::IoHandle;
use crate::tx_table::may_repair;
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
fn write_vacant_tail(path: &Path, repair: bool) -> Result<(), StoreError> {
    let file = open_rw(path)?;
    let len = file.metadata().map_err(|e| StoreError::io(path, e))?.len();
    if len >= 4 {
        let mut magic = [0u8; 4];
        pread_exact(&file, path, 0, &mut magic)?;
        if magic == *CAPT {
            return Ok(());
        }
    }
    may_repair(repair, "source: a tear_guard tail is not a tail")?;
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

const CATK: &[u8; 4] = b"CATK";
const CATK_HEAD: usize = 16;

/// Apply a leftover `CATK` `{stem}.kept` when its range is zeroes, then unlink it.
fn migrate_kept(hot: &Path, seq: &Path, repair: bool) -> Result<(), StoreError> {
    for name in STEMS {
        migrate_one_kept(&stem_path(hot, seq, name), repair)?;
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

fn migrate_one_kept(path: &Path, repair: bool) -> Result<(), StoreError> {
    let side = kept_side(path);
    if !side.try_exists().map_err(|e| StoreError::io(&side, e))? {
        return Ok(());
    }
    may_repair(
        repair,
        "source: a Class A kept block is still beside its stem",
    )?;
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

fn ensure_guard(hot: &Path, repair: bool) -> Result<(), StoreError> {
    let dir = guard_dir(hot);
    let first = dir.join("first");
    let tail0 = dir.join("tail.0");
    let tail1 = dir.join("tail.1");
    for path in [&dir, &first, &tail0, &tail1] {
        if !path.try_exists().map_err(|e| StoreError::io(path, e))? {
            may_repair(repair, "source: tear_guard is missing a file")?;
        }
    }
    let created_dir = !dir.try_exists().map_err(|e| StoreError::io(&dir, e))?;
    std::fs::create_dir_all(&dir).map_err(|e| StoreError::io(&dir, e))?;
    let mut created = created_dir;
    created |= create_zero_file(&first, FIRST_BYTES)?;
    created |= create_zero_file(&tail0, TAIL_BYTES)?;
    created |= create_zero_file(&tail1, TAIL_BYTES)?;
    write_vacant_tail(&tail0, repair)?;
    write_vacant_tail(&tail1, repair)?;
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
///
/// With `repair` false a page to restore, a seal or tail to write, or a
/// missing guard file refuses the open instead: an `--assumehot` source.
pub(crate) fn prepare_and_restore(hot: &Path, seq: &Path, repair: bool) -> Result<(), StoreError> {
    migrate_kept(hot, seq, repair)?;
    ensure_guard(hot, repair)?;
    let dir = guard_dir(hot);
    let first_path = dir.join("first");
    let first_raw = read_fixed(&first_path, FIRST_BYTES)?.unwrap_or_default();
    let (slot0, slot1) = load_tails(&dir)?;
    let best = match (&slot0, &slot1) {
        (Some(a), b) => Some(newer(a, b)),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };
    for (i, name) in STEMS.iter().enumerate() {
        restore_stem(hot, seq, name, i, &first_raw, best, repair)?;
    }
    seal_vacant_from_disk(hot, seq, &first_path, &first_raw, repair)?;
    if best.is_none() {
        may_repair(repair, "source: tear_guard has no tail")?;
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
    repair: bool,
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
    let page0_restored = match page0_image(stem, published, first_raw, best, &page0) {
        Some(image) => {
            may_repair(repair, "source: a Class A first page is torn")?;
            pwrite_exact(&file, &path, 0, &image)?;
            true
        }
        None => false,
    };
    if page0_restored {
        // The live header was zeros, so `published` was 0 when no slot parsed.
        // The length just written is the one the tail check has to use.
        let restored_len = header_published(&file, &path, file_len)?;
        if restored_len > published {
            published = restored_len;
        }
    }
    let tail_restored = restore_tail_block(&file, &path, stem, published, file_len, best, repair)?;
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

/// The first page open writes back over `page0`, if any.
fn page0_image(
    stem: usize,
    published: u64,
    first_raw: &[u8],
    best: Option<&TailSlot>,
    page0: &[u8],
) -> Option<Vec<u8>> {
    if all_zero(page0) {
        if let Some(commit) = parse_commit(first_raw, stem) {
            let mut image = commit.image;
            let len = recorded_len(best, stem, published, le_u64(&image[8..16]));
            image[8..16].copy_from_slice(&len.to_le_bytes());
            return Some(image);
        }
    }
    let slot = best?;
    if slot.tail_off[stem] != 0 || slot.tail_len[stem] == 0 {
        return None;
    }
    let raw = image_of(slot, stem);
    let mut image = raw.to_vec();
    stamp_loaded_len(&mut image, slot.published[stem]);
    // One write. A page that is still the unstamped image is that write
    // without the slot length, so the next open would otherwise keep it.
    if page_holds(page0, &image) {
        return None;
    }
    (all_zero(page0) || page_holds(page0, raw)).then_some(image)
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
    repair: bool,
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
    // A synced zero image is the block on disk: nothing to put back.
    if all_zero(&image[..take]) {
        return Ok(true);
    }
    may_repair(repair, "source: a Class A tail block is torn")?;
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
    repair: bool,
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
    if !images.is_empty() {
        may_repair(repair, "source: a Class A first page has no seal")?;
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

/// The newest valid slot already records `buf` (all but its generation and
/// checksum): the barrier has nothing new to guard, so neither slot is
/// written and a clean open and shutdown leave the guard as it was.
fn newest_holds(slot0: &Option<TailSlot>, slot1: &Option<TailSlot>, buf: &[u8]) -> bool {
    let newest = match (slot0, slot1) {
        (Some(a), b) => newer(a, b),
        (None, Some(b)) => b,
        (None, None) => return false,
    };
    let raw = &newest.raw;
    raw.len() == buf.len()
        && raw[..8] == buf[..8]
        && raw[16..CHECKSUM_AT] == buf[16..CHECKSUM_AT]
        && raw[CHECKSUM_END..] == buf[CHECKSUM_END..]
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
) -> Result<(), StoreError> {
    for (file, name) in files.iter().zip(STEMS) {
        debug_assert!(
            file.path().ends_with(name),
            "class A stem order drifted at {name}"
        );
    }
    ensure_guard(hot, true)?;
    let dir = guard_dir(hot);
    let (slot0, slot1) = load_tails(&dir)?;
    let (inactive, generation) = inactive_slot(&slot0, &slot1);
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
    if images.is_empty() && newest_holds(&slot0, &slot1, &tail_buf) {
        return crate::file::TableFile::sync_data_all_with(files, &[]);
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
    write_seals(&first_path, &images)
}
