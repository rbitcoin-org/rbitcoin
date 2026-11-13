//! Every file flush (`sync_all` / `sync_data`) goes through [`Durable`].
//! `lint/ast-grep/rules/sync-direct.yml` refuses a direct call.
//!
//! A debug test binary may skip them for its whole process with
//! [`crate::skip_flushes_before_main!`]. In-process tests cannot tell a
//! flushed file from a cached one, and on macOS each flush is `F_FULLFSYNC`,
//! which drains the whole drive cache: parallel tests queue behind one
//! another and miss their wall clocks. The switch is
//! `cfg(debug_assertions)`, so a release node always flushes.

use std::fs::File;
use std::io;
#[cfg(debug_assertions)]
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(debug_assertions)]
static SKIP: AtomicBool = AtomicBool::new(false);

#[cfg(debug_assertions)]
static FLUSHED: AtomicU64 = AtomicU64::new(0);

#[cfg(debug_assertions)]
pub(crate) fn skip_in_this_process() {
    SKIP.store(true, Ordering::Relaxed);
}

/// Whether this process skips flushes. Only a test binary turns it on.
#[cfg(debug_assertions)]
pub fn flushes_skipped() -> bool {
    SKIP.load(Ordering::Relaxed)
}

/// Flush syscalls this process has made through [`Durable`]. Lets a test
/// see that a skipped flush never reached the OS.
#[cfg(debug_assertions)]
pub fn flushes_issued() -> u64 {
    FLUSHED.load(Ordering::Relaxed)
}

/// `sync_all` / `sync_data` on a [`File`], skipped when [`flushes_skipped`].
pub trait Durable {
    fn durable_sync_all(&self) -> io::Result<()>;
    fn durable_sync_data(&self) -> io::Result<()>;
}

impl Durable for File {
    fn durable_sync_all(&self) -> io::Result<()> {
        #[cfg(debug_assertions)]
        if flushes_skipped() {
            return Ok(());
        }
        #[cfg(debug_assertions)]
        FLUSHED.fetch_add(1, Ordering::Relaxed);
        self.sync_all()
    }

    fn durable_sync_data(&self) -> io::Result<()> {
        #[cfg(debug_assertions)]
        if flushes_skipped() {
            return Ok(());
        }
        #[cfg(debug_assertions)]
        FLUSHED.fetch_add(1, Ordering::Relaxed);
        self.sync_data()
    }
}
