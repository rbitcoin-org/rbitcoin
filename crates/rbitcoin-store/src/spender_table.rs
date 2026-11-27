//! Multi-spender overflow (`spent.ovf`, schema 22).
//!
//! Common case stores a sole `spending_tx_fk` + vin on the create output. Only
//! when an outpoint has multiple annotated spenders do we allocate nodes here.
//!
//! Fixed 16 B records (1-based fk): packed `(fk:u40, vin:u16)` | `next:u64`.
//!
//! The first append after a sync arms `guard/spent.ovf` with the current
//! page 0 and tail block. Later appends in that window leave the mark.
//! Sync removes it.

use crate::error::StoreError;
use crate::file::{fsync_parent_dir, TableFile, FILE_HEADER_LEN};
use crate::tx_table::{pack_spent_field, unpack_spent_field};
use rbitcoin_primitives::{le_u64, Fk, TableKind};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub const SPENDER_RECORD_LEN: usize = 16;
/// Multi-spender overflow next to `spent.body` (schema 17).
pub const SPENT_OVF_NAME: &str = "spent.ovf";
#[doc(hidden)]
pub const LEGACY_SPENDERS_BODY: &str = "spenders.body";

/// The annotate freeze. [`Self::new`] borrows [`crate::store::UtxoViewGuard`]
/// for the sync and the clear.
pub struct SpenderFreeze<'a> {
    _view: std::marker::PhantomData<&'a ()>,
}

impl<'a> SpenderFreeze<'a> {
    pub fn new(guard: &'a crate::store::UtxoViewGuard<'_>) -> Self {
        let _ = guard.view;
        Self {
            _view: std::marker::PhantomData,
        }
    }
}

pub struct SpenderTable {
    pub body: TableFile,
    pub count: AtomicU64,
    /// A body sync failed. A retry can return 0 after the kernel dropped
    /// the dirty pages, so the mark stays until restart.
    sync_failed: AtomicBool,
}

#[doc(hidden)]
pub fn spent_ovf_path(dir: &Path) -> Result<std::path::PathBuf, StoreError> {
    let ovf = dir.join(SPENT_OVF_NAME);
    let legacy = dir.join(LEGACY_SPENDERS_BODY);
    match (ovf.exists(), legacy.exists()) {
        (true, true) => {
            eprintln!(
                "store: dropping leftover {LEGACY_SPENDERS_BODY} (schema 17 uses {SPENT_OVF_NAME})"
            );
            let _ = std::fs::remove_file(&legacy);
        }
        (false, true) => {
            eprintln!("store: renaming {LEGACY_SPENDERS_BODY} → {SPENT_OVF_NAME}");
            std::fs::rename(&legacy, &ovf).map_err(|e| StoreError::io(&legacy, e))?;
        }
        _ => {}
    }
    Ok(ovf)
}

impl SpenderTable {
    pub fn create(dir: &Path) -> Result<Self, StoreError> {
        let body = TableFile::create(dir.join(SPENT_OVF_NAME), TableKind::Spender)?;
        Ok(Self {
            body,
            count: AtomicU64::new(0),
            sync_failed: AtomicBool::new(false),
        })
    }

    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        let path = spent_ovf_path(dir)?;
        if !path.exists() {
            return Self::create(dir);
        }
        let body = TableFile::open(path, TableKind::Spender)?;
        let body_len = body.logical_len().saturating_sub(FILE_HEADER_LEN as u64);
        if body_len % SPENDER_RECORD_LEN as u64 != 0 {
            return Err(StoreError::Corrupt("spenders body size"));
        }
        let count = body_len / SPENDER_RECORD_LEN as u64;
        Ok(Self {
            body,
            count: AtomicU64::new(count),
            sync_failed: AtomicBool::new(false),
        })
    }

    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    #[doc(hidden)]
    pub fn offset(id: u64) -> u64 {
        FILE_HEADER_LEN as u64 + (id - 1) * SPENDER_RECORD_LEN as u64
    }

    /// Append one list node. Returns its fk.
    pub fn append(&self, spending_tx_fk: Fk, vin: u32, next: Fk) -> Result<Fk, StoreError> {
        if spending_tx_fk.is_null() {
            return Err(StoreError::InvalidFk);
        }
        let packed = pack_spent_field(spending_tx_fk, vin)?;
        // Single annotator role: load → write → publish count.
        self.arm_guard()?;
        let id = self.count.load(Ordering::Acquire) + 1;
        let mut buf = [0u8; SPENDER_RECORD_LEN];
        buf[0..8].copy_from_slice(&packed.to_le_bytes());
        buf[8..16].copy_from_slice(&next.0.to_le_bytes());
        self.body.write_at(Self::offset(id), &buf)?;
        self.count.store(id, Ordering::Release);
        Ok(Fk(id))
    }

    pub fn get(&self, fk: Fk) -> Result<(Fk, u32, Fk), StoreError> {
        let id = fk.get().ok_or(StoreError::InvalidFk)?;
        let count = self.count.load(Ordering::Acquire);
        if id == 0 || id > count {
            return Err(StoreError::NotFound);
        }
        let mut buf = [0u8; SPENDER_RECORD_LEN];
        self.body.read_at(Self::offset(id), &mut buf)?;
        let packed = le_u64!(buf, 0);
        let (spend_tx, vin) = unpack_spent_field(packed)?;
        Ok((spend_tx, vin, Fk(le_u64!(buf, 8))))
    }

    pub fn flush(&self, _freeze: &SpenderFreeze<'_>) -> Result<(), StoreError> {
        self.refuse_if_sync_failed()?;
        self.finish_sync(self.body.flush())
    }

    pub fn sync_data_only(&self, _freeze: &SpenderFreeze<'_>) -> Result<(), StoreError> {
        self.refuse_if_sync_failed()?;
        self.finish_sync(self.body.sync_data_only())
    }

    fn refuse_if_sync_failed(&self) -> Result<(), StoreError> {
        if self.sync_failed.load(Ordering::Acquire) {
            return Err(StoreError::io(
                self.body.path(),
                std::io::Error::other("an earlier spent.ovf sync failed; restart the node"),
            ));
        }
        Ok(())
    }

    /// Latch the first body sync error and leave the mark in place.
    fn finish_sync(&self, synced: Result<(), StoreError>) -> Result<(), StoreError> {
        if let Err(e) = synced {
            self.sync_failed.store(true, Ordering::Release);
            return Err(e);
        }
        self.clear_mark()
    }

    fn store_dir(&self) -> Result<&Path, StoreError> {
        self.body
            .path()
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(StoreError::Corrupt("spent.ovf has no directory"))
    }

    /// Page 0 and the block that holds the published end, before this append.
    fn arm_guard(&self) -> Result<(), StoreError> {
        let dir = self.store_dir()?;
        let mark = dir.join(crate::page_guard::SPENT_OVF_MARK);
        if mark.try_exists().map_err(|e| StoreError::io(&mark, e))? {
            // The rename can land and the directory sync can fail. A retry
            // must finish that sync before it writes the body. It must not
            // replace the image this mark already holds.
            let parent = mark
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or(StoreError::Corrupt("spent.ovf mark has no directory"))?;
            fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
            return Ok(());
        }
        let logical = self.body.logical_len();
        let page = crate::page_guard::PAGE;
        let mut offs = vec![0u64];
        if logical > 0 {
            let tail = (logical - 1) & !(page - 1);
            if tail != 0 {
                offs.push(tail);
            }
        }
        let mut images = Vec::with_capacity(offs.len());
        for off in offs {
            images.push((off, self.page_image(off)?));
        }
        let refs: Vec<(u64, &[u8])> = images
            .iter()
            .map(|(off, image)| (*off, image.as_slice()))
            .collect();
        crate::page_guard::promote_meta_31(dir)?;
        crate::page_guard::arm_page_guard(&mark, &refs)
    }

    fn page_image(&self, offset: u64) -> Result<Vec<u8>, StoreError> {
        let mut image = vec![0u8; crate::page_guard::PAGE as usize];
        let file_len = self
            .body
            .read_file
            .metadata()
            .map_err(|e| StoreError::io(self.body.path(), e))?
            .len();
        if offset >= file_len {
            return Ok(image);
        }
        let n = (file_len - offset).min(crate::page_guard::PAGE) as usize;
        self.body.pread_exact(offset, &mut image[..n])?;
        Ok(image)
    }

    fn clear_mark(&self) -> Result<(), StoreError> {
        let dir = self.store_dir()?;
        let mark = dir.join(crate::page_guard::SPENT_OVF_MARK);
        if !mark.try_exists().map_err(|e| StoreError::io(&mark, e))? {
            // Unlink can land and the directory sync can fail. The checkpoint
            // must not publish until that sync has been retried. A directory
            // that was never created never held a mark, so there is no
            // barrier to finish.
            let parent = mark
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .ok_or(StoreError::Corrupt("spent.ovf mark has no directory"))?;
            if parent.try_exists().map_err(|e| StoreError::io(parent, e))? {
                fsync_parent_dir(parent).map_err(|e| StoreError::io(parent, e))?;
            }
            return Ok(());
        }
        crate::page_guard::clear_page_guard(&mark, &self.body.read_file, self.body.path())
    }

    pub fn flush_async(&self) -> Result<(), StoreError> {
        self.body.flush_async()
    }
}
