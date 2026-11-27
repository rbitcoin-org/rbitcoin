use crate::error::StoreError;
use crate::file::{self, TableFile, FILE_HEADER_LEN};
use crate::hashhead::{initial_slots_for, HashHead, HeadScale};
use crate::page_guard::{self, PAGE};
use bitcoin_hashes::{sha256, Hash, HashEngine};
use rbitcoin_primitives::{bytes, le_i32, le_u32, le_u64, Fk, TableKind};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};

#[cfg(debug_assertions)]
mod flush_hold {
    use std::cell::RefCell;
    use std::sync::Arc;

    use crate::array_table::TipFlushHold;

    thread_local! {
        static HOLD: RefCell<Option<Arc<TipFlushHold>>> = const { RefCell::new(None) };
    }

    pub(super) fn bind(hold: Option<Arc<TipFlushHold>>) {
        HOLD.with(|slot| *slot.borrow_mut() = hold);
    }

    pub(super) fn wait() {
        let Some(hold) = HOLD.with(|slot| slot.borrow().clone()) else {
            return;
        };
        hold.wait_while_set();
    }
}

/// Pause [`HeaderTable::flush`] while `put_lock` is still held, after the
/// live write and before the mark is gone.
#[doc(hidden)]
#[cfg(debug_assertions)]
pub fn bind_header_flush_hold(hold: Option<std::sync::Arc<crate::array_table::TipFlushHold>>) {
    flush_hold::bind(hold);
}

pub const HEADER_HEAD_DIR_REFUSE: &str =
    "header.head is a shard directory; wipe header.head and header.body and reindex";

pub const HEADER_HEAD_EMPTY_REFUSE: &str =
    "header.head is empty at target slots; wipe header.head, header.head.mlt, and header.body and reindex";

const HEADER_HEAD_AHEAD: &str =
    "header.head.ahead is a legacy page image; this open does not restore it";
const HEADER_HEAD_GEN_AHEAD: &str =
    "a header.head.gN.ahead is a legacy page image; this open does not restore it";

fn legacy_ahead(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".ahead");
    path.with_file_name(name)
}

/// Live `header.body` record: consensus fields only. See SCHEMA.md.
pub const HEADER_RECORD_LEN: usize = 88;
/// Schema 24/25 record. Open strips the trailing `size`/`weight` back to 88.
pub const HEADER_RECORD_LEN_V24: usize = 96;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HeaderRecord {
    pub prev_fk: Fk,
    pub version: i32,
    pub timestamp: u32,
    pub bits: u32,
    pub nonce: u32,
    pub merkle_root: [u8; 32],
    pub hash: [u8; 32],
    /// Not written to `header.body`. Block size comes from `txstat`.
    pub size: u32,
    /// Not written to `header.body`. Block weight comes from `txstat`.
    pub weight: u32,
}

impl HeaderRecord {
    pub fn encode(&self) -> [u8; HEADER_RECORD_LEN] {
        let mut out = [0u8; HEADER_RECORD_LEN];
        out[0..8].copy_from_slice(&self.prev_fk.0.to_le_bytes());
        out[8..12].copy_from_slice(&self.version.to_le_bytes());
        out[12..16].copy_from_slice(&self.timestamp.to_le_bytes());
        out[16..20].copy_from_slice(&self.bits.to_le_bytes());
        out[20..24].copy_from_slice(&self.nonce.to_le_bytes());
        out[24..56].copy_from_slice(&self.merkle_root);
        out[56..88].copy_from_slice(&self.hash);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, StoreError> {
        let Some(buf) = buf.first_chunk::<HEADER_RECORD_LEN>() else {
            return Err(StoreError::Corrupt("short header record"));
        };
        Ok(Self {
            prev_fk: Fk(le_u64!(buf, 0)),
            version: le_i32!(buf, 8),
            timestamp: le_u32!(buf, 12),
            bits: le_u32!(buf, 16),
            nonce: le_u32!(buf, 20),
            merkle_root: bytes!(buf, 24, 32),
            hash: bytes!(buf, 56, 32),
            size: 0,
            weight: 0,
        })
    }
}

/// Double-SHA256 of a bitcoin block header (80 bytes), internal byte order.
pub fn block_header_hash(
    version: i32,
    prev_hash: &[u8; 32],
    merkle_root: &[u8; 32],
    timestamp: u32,
    bits: u32,
    nonce: u32,
) -> [u8; 32] {
    let mut ser = [0u8; 80];
    ser[0..4].copy_from_slice(&version.to_le_bytes());
    ser[4..36].copy_from_slice(prev_hash);
    ser[36..68].copy_from_slice(merkle_root);
    ser[68..72].copy_from_slice(&timestamp.to_le_bytes());
    ser[72..76].copy_from_slice(&bits.to_le_bytes());
    ser[76..80].copy_from_slice(&nonce.to_le_bytes());
    let mut eng = sha256::HashEngine::default();
    eng.input(&ser);
    let mid = sha256::Hash::from_engine(eng);
    let mut eng2 = sha256::HashEngine::default();
    eng2.input(mid.as_byte_array());
    sha256::Hash::from_engine(eng2).to_byte_array()
}

/// `header.head` plus overflow gens `header.head.g1`, `header.head.g2`, …
#[doc(hidden)]
pub struct HeaderHead {
    pub base: PathBuf,
    pub target_slots: u64,
    pub gens: RwLock<Vec<HashHead>>,
}

#[doc(hidden)]
pub fn header_head_occupied(dir: &Path) -> Result<u64, StoreError> {
    let base = dir.join("header.head");
    if !base.is_file() {
        return Ok(0);
    }
    let mut n = HashHead::open(&base)?.occupied();
    let mut i = 1usize;
    loop {
        let p = header_gen_path(&base, i);
        if !p.is_file() {
            break;
        }
        n = n.saturating_add(HashHead::open(p)?.occupied());
        i += 1;
    }
    Ok(n)
}

#[doc(hidden)]
pub fn header_gen_path(base: &Path, i: usize) -> PathBuf {
    if i == 0 {
        return base.to_path_buf();
    }
    let mut p = base.as_os_str().to_os_string();
    p.push(format!(".g{i}"));
    PathBuf::from(p)
}

impl HeaderHead {
    #[doc(hidden)]
    pub fn create(base: PathBuf, scale: HeadScale) -> Result<Self, StoreError> {
        let target_slots = initial_slots_for(scale);
        let h = HashHead::create_with_slots(&base, target_slots)?;
        Ok(Self {
            base,
            target_slots,
            gens: RwLock::new(vec![h]),
        })
    }

    #[doc(hidden)]
    pub fn open(base: PathBuf, body_count: u64, scale: HeadScale) -> Result<Self, StoreError> {
        crate::file::refuse_if_present(&legacy_ahead(&base), HEADER_HEAD_AHEAD)?;
        if base.is_dir() {
            return Err(StoreError::Layout(HEADER_HEAD_DIR_REFUSE.to_string()));
        }
        if !base.is_file() {
            return Err(StoreError::io(
                &base,
                std::io::Error::new(std::io::ErrorKind::NotFound, "header.head missing"),
            ));
        }
        crate::hashhead::discard_grow_part(&base);
        let target_slots = initial_slots_for(scale);
        let mut gens = vec![HashHead::open(&base)?];
        let mut i = 1usize;
        loop {
            let p = header_gen_path(&base, i);
            if !p.is_file() {
                break;
            }
            crate::file::refuse_if_present(&legacy_ahead(&p), HEADER_HEAD_GEN_AHEAD)?;
            gens.push(HashHead::open(p)?);
            i += 1;
        }
        if gens.len() == 1 && gens[0].slots() < target_slots {
            let g = gens.remove(0);
            gens.push(g.rewrite_to_slots(target_slots)?);
        } else if gens.len() == 1
            && gens[0].slots() >= target_slots
            && gens[0].occupied() == 0
            && (body_count > 0 || gens[0].multi_count() > 0)
        {
            return Err(StoreError::Layout(HEADER_HEAD_EMPTY_REFUSE.to_string()));
        }
        Ok(Self {
            base,
            target_slots,
            gens: RwLock::new(gens),
        })
    }

    #[doc(hidden)]
    pub fn get_all(&self, key: &[u8; 32]) -> Result<Vec<Fk>, StoreError> {
        let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::new();
        for h in gens.iter().rev() {
            out.extend(h.get_all(key)?);
        }
        Ok(out)
    }

    #[doc(hidden)]
    pub fn insert_many(&self, entries: &[([u8; 32], Fk)]) -> Result<(), StoreError> {
        let mut rest: Vec<([u8; 32], Fk)> = entries.to_vec();
        while !rest.is_empty() {
            let leftover = {
                let last = {
                    let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
                    gens.len().saturating_sub(1)
                };
                let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
                gens[last].insert_many_file(&rest, |_| {})?
            };
            if leftover.is_empty() {
                return Ok(());
            }
            self.roll()?;
            rest = leftover;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn roll(&self) -> Result<(), StoreError> {
        let mut gens = self.gens.write().unwrap_or_else(|e| e.into_inner());
        // Another ensure may have rolled while we dropped the read lock.
        if gens.last().is_some_and(|h| !h.at_load_cap()) {
            return Ok(());
        }
        let i = gens.len();
        let p = header_gen_path(&self.base, i);
        // Twice the last generation: a lookup probes every generation, so
        // equal sizes would make it linear in the header count.
        let slots = gens
            .last()
            .map_or(self.target_slots, |h| h.slots().saturating_mul(2));
        gens.push(HashHead::create_with_slots(p, slots)?);
        Ok(())
    }

    #[doc(hidden)]
    pub fn flush(&self) -> Result<(), StoreError> {
        let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
        for h in gens.iter() {
            h.flush()?;
        }
        Ok(())
    }

    #[doc(hidden)]
    pub fn flush_async(&self) -> Result<(), StoreError> {
        let gens = self.gens.read().unwrap_or_else(|e| e.into_inner());
        for h in gens.iter() {
            h.flush_async()?;
        }
        Ok(())
    }
}

pub struct HeaderTable {
    pub body: TableFile,
    pub head: HeaderHead,
    pub count: std::sync::atomic::AtomicU64,
    /// Serializes check-then-put so two threads cannot both miss and both append
    /// the same full hash (I1 + I4).
    pub put_lock: Mutex<()>,
}

impl HeaderTable {
    pub fn create(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::create_with_scale(dir, HeadScale::Mainnet)
    }

    pub fn create_tiny(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::create_with_scale(dir, HeadScale::Tiny)
    }

    pub fn create_with_scale(dir: &std::path::Path, scale: HeadScale) -> Result<Self, StoreError> {
        let body = TableFile::create(dir.join("header.body"), TableKind::Header)?;
        let head = HeaderHead::create(dir.join("header.head"), scale)?;
        Ok(Self {
            body,
            head,
            count: std::sync::atomic::AtomicU64::new(0),
            put_lock: Mutex::new(()),
        })
    }

    pub fn open(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::open_with_scale(dir, HeadScale::Mainnet)
    }

    pub fn open_tiny(dir: &std::path::Path) -> Result<Self, StoreError> {
        Self::open_with_scale(dir, HeadScale::Tiny)
    }

    pub fn open_with_scale(dir: &std::path::Path, scale: HeadScale) -> Result<Self, StoreError> {
        page_guard::restore_store_group(dir, page_guard::HEADER_BODY_MARK)?;
        page_guard::restore_store_group(dir, page_guard::HEADER_HEAD_MARK)?;
        let body = TableFile::open(dir.join("header.body"), TableKind::Header)?;
        let body_len = body.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if body_len % HEADER_RECORD_LEN as u64 != 0 {
            return Err(StoreError::Corrupt("header body size"));
        }
        let count = body_len / HEADER_RECORD_LEN as u64;
        let head = HeaderHead::open(dir.join("header.head"), count, scale)?;
        Ok(Self {
            body,
            head,
            count: std::sync::atomic::AtomicU64::new(count),
            put_lock: Mutex::new(()),
        })
    }

    /// Schema 24/25 → 26: strip trailing `size`/`weight` so each row is 88 B.
    ///
    /// Writes `header.body.grow`, fsyncs, renames over `header.body`. A body
    /// that is already 88 B is left alone. Occupied `header.head` disambiguates
    /// lengths that divide both 88 and 96.
    pub fn rewrite_v24_body_to_88(dir: &Path) -> Result<(), StoreError> {
        let path = dir.join("header.body");
        if !path.is_file() {
            return Ok(());
        }
        let grow = {
            let mut p = path.as_os_str().to_os_string();
            p.push(".grow");
            PathBuf::from(p)
        };
        let _ = std::fs::remove_file(&grow);
        let src = TableFile::open(&path, TableKind::Header)?;
        let body_len = src.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if body_len == 0 {
            return Ok(());
        }
        let n88 = body_len / HEADER_RECORD_LEN as u64;
        let n96 = body_len / HEADER_RECORD_LEN_V24 as u64;
        let aligned88 = body_len % HEADER_RECORD_LEN as u64 == 0;
        let aligned96 = body_len % HEADER_RECORD_LEN_V24 as u64 == 0;
        let n = if aligned96 && aligned88 {
            let occ = header_head_occupied(dir)?;
            if occ == n88 || occ == 0 {
                return Ok(());
            }
            if occ == n96 {
                n96
            } else {
                return Err(StoreError::Corrupt("header body size"));
            }
        } else if aligned88 {
            return Ok(());
        } else if aligned96 {
            n96
        } else {
            return Err(StoreError::Corrupt("header body size"));
        };
        let dst = TableFile::create(&grow, TableKind::Header)?;
        let mut blob = Vec::new();
        blob.try_reserve_exact(n as usize * HEADER_RECORD_LEN)
            .map_err(|_| StoreError::Corrupt("header body rewrite OOM"))?;
        for i in 0..n {
            let off = FILE_HEADER_LEN as u64 + i * HEADER_RECORD_LEN_V24 as u64;
            let mut raw = [0u8; HEADER_RECORD_LEN_V24];
            src.read_at(off, &mut raw)?;
            blob.extend_from_slice(&raw[..HEADER_RECORD_LEN]);
        }
        let new_len = FILE_HEADER_LEN as u64 + n * HEADER_RECORD_LEN as u64;
        let pages = compose_body_pages(&dst, FILE_HEADER_LEN as u64, &blob, new_len)?;
        let _hold = page_guard::hold_marks();
        let name = page_guard::guard_file_name(&grow)?;
        let refs: Vec<(&str, u64, &[u8])> = pages
            .iter()
            .map(|(off, image)| (name, *off, image.as_slice()))
            .collect();
        page_guard::arm_page_guard_group(&dir.join(page_guard::HEADER_BODY_MARK), &refs)?;
        dst.write_at(FILE_HEADER_LEN as u64, &blob)?;
        dst.set_logical_len(new_len)?;
        dst.flush()?;
        page_guard::clear_page_guard(
            &dir.join(page_guard::HEADER_BODY_MARK),
            &dst.read_file,
            dst.path(),
        )?;
        drop(dst);
        drop(src);
        std::fs::rename(&grow, &path).map_err(|e| StoreError::io(&path, e))?;
        file::fsync_parent_dir(dir).map_err(|e| StoreError::io(dir, e))?;
        Ok(())
    }

    /// `true` when `header.body` is still schema-24 rows (96 B, not also 88 B).
    ///
    /// A length that divides both widths is left to [`Self::rewrite_v24_body_to_88`]
    /// on a schema 24/25 open. Calling that scan on every later open would read
    /// `header.head` again whenever the row count is a multiple of 12.
    pub(crate) fn header_body_needs_v24_rewrite(dir: &Path) -> Result<bool, StoreError> {
        let path = dir.join("header.body");
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(e) => return Err(StoreError::io(&path, e)),
        };
        let mut hdr = [0u8; FILE_HEADER_LEN];
        match std::io::Read::read(&mut file, &mut hdr) {
            Ok(n) if n == FILE_HEADER_LEN => {}
            Ok(_) => return Ok(false),
            Err(e) => return Err(StoreError::io(&path, e)),
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&hdr[8..16]);
        let body_len = u64::from_le_bytes(raw).saturating_sub(FILE_HEADER_LEN as u64);
        Ok(body_len > 0
            && body_len % HEADER_RECORD_LEN_V24 as u64 == 0
            && body_len % HEADER_RECORD_LEN as u64 != 0)
    }

    pub fn head_target_slots(&self) -> u64 {
        self.head.target_slots
    }

    /// Write gate: at most one body row per full block hash (I1).
    ///
    /// - If `hash` already exists → return that fk (ignore caller's `prev_fk`).
    /// - Else if `prev_fk` is non-null → parent must exist and
    ///   `hash` must equal SHA256D(header fields with parent.hash as prev) (I2/I3).
    /// - Else (`prev_fk` null) → append as-is (genesis / synthetic test rows).
    ///
    /// Lookup + insert hold [`Self::put_lock`] (I4).
    pub fn ensure(&self, rec: &HeaderRecord) -> Result<Fk, StoreError> {
        let mut fks = self.ensure_batch(std::slice::from_ref(rec))?;
        fks.pop().ok_or(StoreError::Corrupt("ensure_batch empty"))
    }

    /// Batch [`Self::ensure`]: one `put_lock`, one `header.body` write, chunked head insert.
    ///
    /// Output fks align with `recs`. Duplicate hashes in the batch share one body row.
    pub fn ensure_batch(&self, recs: &[HeaderRecord]) -> Result<Vec<Fk>, StoreError> {
        use std::sync::atomic::Ordering;
        if recs.is_empty() {
            return Ok(Vec::new());
        }
        let _g = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = Vec::with_capacity(recs.len());
        let mut fresh: Vec<(Fk, HeaderRecord)> = Vec::new();
        let mut seen: Vec<([u8; 32], Fk)> = Vec::new();
        let mut next = self.count.load(Ordering::Acquire);
        for rec in recs {
            if let Some((_, fk)) = seen.iter().rev().find(|(h, _)| *h == rec.hash) {
                out.push(*fk);
                continue;
            }
            if let Some((fk, _)) = self.get_by_hash_unlocked(&rec.hash)? {
                seen.push((rec.hash, fk));
                out.push(fk);
                continue;
            }
            if !rec.prev_fk.is_null() {
                let parent = self.parent_for_batch(rec.prev_fk, &fresh)?;
                Self::check_parent_edge(rec, &parent)?;
            }
            next = next.saturating_add(1);
            let fk = Fk(next);
            let mut stored = rec.clone();
            stored.prev_fk = rec.prev_fk;
            fresh.push((fk, stored));
            seen.push((rec.hash, fk));
            out.push(fk);
        }
        if fresh.is_empty() {
            return Ok(out);
        }
        let base = self.count.load(Ordering::Acquire);
        let offset = FILE_HEADER_LEN as u64 + base * HEADER_RECORD_LEN as u64;
        let mut blob = Vec::with_capacity(fresh.len().saturating_mul(HEADER_RECORD_LEN));
        let mut head_entries: Vec<([u8; 32], Fk)> = Vec::with_capacity(fresh.len());
        for (fk, rec) in &fresh {
            blob.extend_from_slice(&rec.encode());
            head_entries.push((rec.hash, *fk));
        }
        let new_len = offset.saturating_add(blob.len() as u64);
        let pages = compose_body_pages(&self.body, offset, &blob, new_len)?;
        let Some(dir) = self.body.path().parent() else {
            return Err(StoreError::Rejected("page guard mark has no directory"));
        };
        {
            // Drop before `insert_many`. That flush takes the same hold.
            let _hold = page_guard::hold_marks();
            let name = page_guard::guard_file_name(self.body.path())?;
            let refs: Vec<(&str, u64, &[u8])> = pages
                .iter()
                .map(|(off, image)| (name, *off, image.as_slice()))
                .collect();
            page_guard::arm_store_group(dir, page_guard::HEADER_BODY_MARK, &refs)?;
            self.body.write_at(offset, &blob)?;
            // Head insert fdatasyncs. The body must be durable first so a crash
            // cannot leave header.head naming an fk above the durable row count.
            self.body.sync_data_only()?;
            page_guard::clear_page_guard(
                &dir.join(page_guard::HEADER_BODY_MARK),
                &self.body.read_file,
                self.body.path(),
            )?;
        }
        self.count
            .store(base.saturating_add(fresh.len() as u64), Ordering::Release);
        self.head.insert_many(&head_entries)?;
        Ok(out)
    }

    #[doc(hidden)]
    pub fn parent_for_batch(
        &self,
        prev_fk: Fk,
        fresh: &[(Fk, HeaderRecord)],
    ) -> Result<HeaderRecord, StoreError> {
        if let Some((_, rec)) = fresh.iter().rev().find(|(fk, _)| *fk == prev_fk) {
            return Ok(rec.clone());
        }
        self.get(prev_fk)
    }

    #[doc(hidden)]
    pub fn check_parent_edge(rec: &HeaderRecord, parent: &HeaderRecord) -> Result<(), StoreError> {
        let expect = block_header_hash(
            rec.version,
            &parent.hash,
            &rec.merkle_root,
            rec.timestamp,
            rec.bits,
            rec.nonce,
        );
        if expect != rec.hash {
            return Err(StoreError::Corrupt(
                "header prev_fk does not match block hash (false parent edge)",
            ));
        }
        Ok(())
    }

    /// Rows `1..=through`, and not a row appended after the caller sampled `through`.
    pub fn for_each_record_through<F>(&self, through: u64, mut f: F) -> Result<(), StoreError>
    where
        F: FnMut(Fk, HeaderRecord) -> Result<(), StoreError>,
    {
        let n = self.count().min(through);
        const CHUNK: u64 = 1024;
        let mut buf = vec![0u8; CHUNK as usize * HEADER_RECORD_LEN];
        let mut id = 1u64;
        while id <= n {
            let take = (n - id + 1).min(CHUNK);
            let nbytes = take as usize * HEADER_RECORD_LEN;
            let offset = FILE_HEADER_LEN as u64 + (id - 1) * HEADER_RECORD_LEN as u64;
            self.body.read_at(offset, &mut buf[..nbytes])?;
            for i in 0..take as usize {
                let start = i * HEADER_RECORD_LEN;
                let rec = HeaderRecord::decode(&buf[start..start + HEADER_RECORD_LEN])?;
                f(Fk(id + i as u64), rec)?;
            }
            id += take;
        }
        Ok(())
    }

    /// `nBits` of rows `1..=count` sampled once. Index `fk - 1`.
    pub fn bits_in_fk_order(&self) -> Result<Vec<u32>, StoreError> {
        let n = self.count();
        let mut bits = vec![0u32; n as usize];
        self.for_each_record_through(n, |fk, rec| {
            let i = (fk.0 - 1) as usize;
            let slot = bits.get_mut(i).ok_or(StoreError::Corrupt("header fk"))?;
            *slot = rec.bits;
            Ok(())
        })?;
        Ok(bits)
    }

    pub fn get(&self, fk: Fk) -> Result<HeaderRecord, StoreError> {
        use std::sync::atomic::Ordering;
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        let count = self.count.load(Ordering::Acquire);
        if id == 0 || id > count {
            return Err(StoreError::NotFound);
        }
        let offset = FILE_HEADER_LEN as u64 + (id - 1) * HEADER_RECORD_LEN as u64;
        let mut buf = [0u8; HEADER_RECORD_LEN];
        self.body.read_at(offset, &mut buf)?;
        HeaderRecord::decode(&buf)
    }

    pub fn get_by_hash(&self, hash: &[u8; 32]) -> Result<Option<(Fk, HeaderRecord)>, StoreError> {
        // Head reads are safe without put_lock (body append-only; head multi-list
        // is append-oriented). Callers that check-then-put must use ensure.
        self.get_by_hash_unlocked(hash)
    }

    #[doc(hidden)]
    pub fn get_by_hash_unlocked(
        &self,
        hash: &[u8; 32],
    ) -> Result<Option<(Fk, HeaderRecord)>, StoreError> {
        // 16-byte head prefix may collide — verify full hash on the body.
        for fk in self.head.get_all(hash)? {
            let rec = self.get(fk)?;
            if rec.hash == *hash {
                return Ok(Some((fk, rec)));
            }
        }
        Ok(None)
    }

    /// Number of header rows currently stored (highest fk = this value).
    pub fn count(&self) -> u64 {
        self.count.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn flush(&self) -> Result<(), StoreError> {
        let _g = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.body.flush()?;
        self.head.flush()?;
        #[cfg(debug_assertions)]
        flush_hold::wait();
        Ok(())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        let _g = self.put_lock.lock().unwrap_or_else(|e| e.into_inner());
        self.body.flush_async()?;
        self.head.flush_async()?;
        Ok(())
    }
}

fn compose_body_pages(
    body: &TableFile,
    offset: u64,
    blob: &[u8],
    new_logical: u64,
) -> Result<Vec<(u64, [u8; PAGE as usize])>, StoreError> {
    let old_logical = body.logical_len();
    let mut pages = BTreeSet::new();
    if new_logical != old_logical {
        pages.insert(0u64);
    }
    if !blob.is_empty() {
        let first = (offset / PAGE) * PAGE;
        let last = ((offset + blob.len() as u64 - 1) / PAGE) * PAGE;
        let mut page = first;
        while page <= last {
            pages.insert(page);
            page += PAGE;
        }
    }
    let mut images = Vec::with_capacity(pages.len());
    for page in pages {
        let mut image = [0u8; PAGE as usize];
        if page < old_logical {
            let n = ((old_logical - page) as usize).min(PAGE as usize);
            body.pread_all(page, &mut image[..n])?;
        }
        if page == 0 {
            image[..FILE_HEADER_LEN]
                .copy_from_slice(&file::encode_leading_header(TableKind::Header, new_logical));
        }
        overlay_bytes(&mut image, page, offset, blob);
        images.push((page, image));
    }
    Ok(images)
}

fn overlay_bytes(image: &mut [u8; PAGE as usize], page: u64, off: u64, bytes: &[u8]) {
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
