//! Create numbers a covered-prefix cut dropped.
//!
//! A later transaction can reuse one of those numbers. A spend mark that
//! still names it counts only when that create's input still names the
//! parent output. The file is optional. No schema bump.

use crate::error::StoreError;
use std::path::Path;

const SPEND_RECHECK_NAME: &str = "spend.recheck";

/// Spans from earlier cuts. Missing file means none.
///
/// Each record is `covered ‖ old`. Records are sorted. Overlap
/// (`covered < prev_end`) is corrupt. A shared endpoint is allowed.
pub(crate) fn read_spend_recheck(dir: &Path) -> Result<Vec<(u64, u64)>, StoreError> {
    let path = dir.join(SPEND_RECHECK_NAME);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(StoreError::io(&path, e)),
    };
    if bytes.is_empty() || !bytes.len().is_multiple_of(16) {
        return Err(StoreError::Corrupt("spend.recheck"));
    }
    let mut spans = Vec::with_capacity(bytes.len() / 16);
    let mut prev_end = 0u64;
    for chunk in bytes.chunks_exact(16) {
        let covered = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
        let old = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
        if covered >= old || covered < prev_end {
            return Err(StoreError::Corrupt("spend.recheck"));
        }
        prev_end = old;
        spans.push((covered, old));
    }
    Ok(spans)
}

fn write_spend_recheck(dir: &Path, spans: &[(u64, u64)]) -> Result<(), StoreError> {
    let mut bytes = Vec::with_capacity(spans.len() * 16);
    for &(covered, old) in spans {
        bytes.extend_from_slice(&covered.to_le_bytes());
        bytes.extend_from_slice(&old.to_le_bytes());
    }
    crate::file::write_synced_tmp_rename(&dir.join(SPEND_RECHECK_NAME), &bytes)
}

/// Overlap and a shared endpoint become one span. A gap stays two spans.
fn merge_spend_recheck(spans: &mut Vec<(u64, u64)>, covered: u64, old: u64) {
    spans.push((covered, old));
    spans.sort_by_key(|span| (span.0, span.1));
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(spans.len());
    for (covered, old) in spans.drain(..) {
        if let Some(last) = merged.last_mut() {
            if covered <= last.1 {
                last.1 = last.1.max(old);
                continue;
            }
        }
        merged.push((covered, old));
    }
    *spans = merged;
}

/// Remember that creates in `(covered, old]` were cut and can be reused.
pub(crate) fn note_spend_recheck(dir: &Path, covered: u64, old: u64) -> Result<(), StoreError> {
    if old <= covered {
        return Ok(());
    }
    let mut spans = read_spend_recheck(dir)?;
    merge_spend_recheck(&mut spans, covered, old);
    write_spend_recheck(dir, &spans)
}
