//! Every file flush (`sync_all` / `sync_data`) goes through [`Durable`].
//! `lint/ast-grep/rules/sync-direct.yml` refuses a direct call.

use std::fs::File;
use std::io;

/// `sync_all` / `sync_data` on a [`File`].
pub trait Durable {
    fn durable_sync_all(&self) -> io::Result<()>;
    fn durable_sync_data(&self) -> io::Result<()>;
}

impl Durable for File {
    fn durable_sync_all(&self) -> io::Result<()> {
        self.sync_all()
    }

    fn durable_sync_data(&self) -> io::Result<()> {
        self.sync_data()
    }
}
