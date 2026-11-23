//! Schema-29 `spend.pages` reader.
//!
//! Open moves a 29 page log into the schema-30 delta as one generation, then
//! removes these files. Nothing else reads them.
//!
//! `spend.pages.commit`: `magic:[u8; 4] | schema:u16 | held:u16 | height:u32
//! | generation:u32 | committed_len:u64 | n:u32`, then `n` records of
//! `page_off:u64 | log_off:u64 | image_len:u32 | generation:u32`, then an
//! optional `sealed_tip:u32`. A record generation of zero is the header
//! generation. An image is raw page bytes at `log_off` in
//! `spend.pages.{generation}`, or in `spend.pages` once the header
//! generation was renamed there. Every slot an image covers overrides
//! `spent.body`, an explicit zero included. Page 0's first 16 bytes are the
//! `spent.body` header, not slots.

use crate::error::StoreError;
use crate::file::fsync_parent_dir;
use crate::tx_table::BODY_PAGE_SIZE;
use rbitcoin_primitives::{schema_file_openable, STORE_MAGIC};
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;

pub const SPEND_PAGES_NAME: &str = "spend.pages";
pub const SPEND_PAGES_COMMIT_NAME: &str = "spend.pages.commit";

const COMMIT_HEAD: usize = 28;
const COMMIT_REC: usize = 24;

/// The committed page images of a schema-29 log, each cut at the body end.
/// Every slot an image covers overrides `spent.body`.
pub(crate) struct V29Log {
    pub(crate) images: Vec<(u64, Vec<u8>)>,
    /// Confirmed tip the pages may name spends from. A held log is `u32::MAX`,
    /// so the open filter runs `keep` over it as 29 did before a fold.
    pub(crate) tip: u32,
}

fn rd_u32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn rd_u64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}

/// Read the committed log, cut at `body_end`. `None` when there is no commit.
pub(crate) fn read(dir: &Path, body_end: u64) -> Result<Option<V29Log>, StoreError> {
    let commit_path = dir.join(SPEND_PAGES_COMMIT_NAME);
    let raw = match std::fs::read(&commit_path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(StoreError::io(&commit_path, e)),
    };
    if raw.len() < COMMIT_HEAD {
        return Err(StoreError::Corrupt("spend.pages.commit short"));
    }
    if raw[0..4] != STORE_MAGIC {
        return Err(StoreError::BadMagic);
    }
    let ver = u16::from_le_bytes([raw[4], raw[5]]);
    if !schema_file_openable(ver) {
        return Err(StoreError::BadSchema(ver));
    }
    let held = u16::from_le_bytes([raw[6], raw[7]]) != 0;
    let height = rd_u32(&raw, 8);
    let header_gen = rd_u32(&raw, 12);
    let committed_len = rd_u64(&raw, 16);
    let n = rd_u32(&raw, 24) as usize;
    let need = COMMIT_HEAD.saturating_add(n.saturating_mul(COMMIT_REC));
    if raw.len() < need {
        return Err(StoreError::Corrupt("spend.pages.commit short"));
    }
    let sealed_tip = if raw.len() >= need + 4 {
        rd_u32(&raw, need)
    } else {
        height
    };
    let mut files: HashMap<u32, (File, u64)> = HashMap::new();
    let mut pages = Vec::with_capacity(n);
    let mut named = std::collections::HashSet::new();
    for i in 0..n {
        let at = COMMIT_HEAD + i * COMMIT_REC;
        let page_off = rd_u64(&raw, at);
        let log_off = rd_u64(&raw, at + 8);
        let image_len = u64::from(rd_u32(&raw, at + 16));
        let generation = match rd_u32(&raw, at + 20) {
            0 => header_gen,
            g => g,
        };
        if !page_off.is_multiple_of(BODY_PAGE_SIZE) || image_len > BODY_PAGE_SIZE {
            return Err(StoreError::Corrupt(
                "spend.pages.commit record is not one page",
            ));
        }
        if !named.insert(page_off) {
            return Err(StoreError::Corrupt("spend.pages.commit names a page twice"));
        }
        let (file, limit) = match files.entry(generation) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(open_image(dir, generation, header_gen, committed_len)?)
            }
        };
        if log_off.saturating_add(image_len) > *limit {
            return Err(StoreError::Corrupt("spend.pages short"));
        }
        let len = image_len.min(body_end.saturating_sub(page_off));
        let mut image = vec![0u8; len as usize];
        crate::file::handle_pread_all(file, &dir.join(SPEND_PAGES_NAME), log_off, &mut image)?;
        if !image.is_empty() {
            pages.push((page_off, image));
        }
    }
    let tip = if held {
        u32::MAX
    } else {
        height.max(sealed_tip)
    };
    Ok(Some(V29Log { images: pages, tip }))
}

/// Open the file holding `generation` and the length its records may use.
fn open_image(
    dir: &Path,
    generation: u32,
    header_gen: u32,
    committed_len: u64,
) -> Result<(File, u64), StoreError> {
    let numbered = dir.join(format!("{SPEND_PAGES_NAME}.{generation}"));
    let path = if generation == header_gen && !numbered.exists() {
        dir.join(SPEND_PAGES_NAME)
    } else {
        numbered
    };
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(StoreError::Corrupt("spend.pages short"))
        }
        Err(e) => return Err(StoreError::io(&path, e)),
    };
    let file_len = file.metadata().map_err(|e| StoreError::io(&path, e))?.len();
    let limit = if generation == header_gen {
        if file_len < committed_len {
            return Err(StoreError::Corrupt("spend.pages short"));
        }
        committed_len
    } else {
        file_len
    };
    Ok((file, limit))
}

fn is_v29_name(name: &str) -> bool {
    name == SPEND_PAGES_NAME || name.starts_with("spend.pages.")
}

/// True when [`remove`] would remove a file.
pub(crate) fn present(dir: &Path) -> Result<bool, StoreError> {
    if dir.join(SPEND_PAGES_COMMIT_NAME).exists() {
        return Ok(true);
    }
    for entry in std::fs::read_dir(dir).map_err(|e| StoreError::io(dir, e))? {
        let entry = entry.map_err(|e| StoreError::io(dir, e))?;
        if entry.file_name().to_str().is_some_and(is_v29_name) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Remove the schema-29 files: the commit first, durably, then the images.
/// A crash in between leaves images with no commit, which this removes.
pub(crate) fn remove(dir: &Path) -> Result<(), StoreError> {
    let commit_path = dir.join(SPEND_PAGES_COMMIT_NAME);
    let mut removed = match std::fs::remove_file(&commit_path) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(StoreError::io(&commit_path, e)),
    };
    if removed {
        fsync_parent_dir(dir).map_err(|e| StoreError::io(dir, e))?;
    }
    let entries = std::fs::read_dir(dir).map_err(|e| StoreError::io(dir, e))?;
    for entry in entries {
        let entry = entry.map_err(|e| StoreError::io(dir, e))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if is_v29_name(name) {
            std::fs::remove_file(entry.path()).map_err(|e| StoreError::io(entry.path(), e))?;
            removed = true;
        }
    }
    if removed {
        fsync_parent_dir(dir).map_err(|e| StoreError::io(dir, e))?;
    }
    Ok(())
}
