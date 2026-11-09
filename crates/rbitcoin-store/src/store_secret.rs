//! Datadir-local secret for at-rest script XOR and keyed `tx.head` probes.
//!
//! On **datadir create**, a 32-byte CSPRNG secret is written to `store/store.secret`
//! (mode 0600 when the OS allows). Derived material:
//!
//! - **Script XOR:** `xor_key_byte(i) = secret[i % 32] ^ stream_mix(i)` applied to
//!   on-disk `scriptPubKey`, `scriptSig`, and witness item bytes (Bitcoin Core–style
//!   at-rest obfuscation of script/witness blobs only — not txids or amounts).
//! - **TXID mix:** `mix_txid(txid) = SHA256(secret || txid)` is the **page-local**
//!   probe key for the open `tx.head` segment (15-bit page + in-page double hash).
//!   Without it, anyone can grind ~2¹⁵ SHA256d hashes into one 4 KiB page.
//!   Sealed MPHF/fuse consume the same mixed u64. Mix is not a file-shard selector
//!   (segments are by create_fk range; SH shards are scripthash prefix).
//!
//! Plaintext reconstruct always de-obfuscates on read. Missing secret on open of a
//! schema-12+ store is an error (wipe / recreate datadir).

use crate::error::StoreError;
use bitcoin_hashes::{sha256, Hash};
use std::io::Read;
use std::path::{Path, PathBuf};

/// On-disk filename under the store directory.
pub const SECRET_FILE: &str = "store.secret";
/// Raw secret length (bytes).
pub const SECRET_LEN: usize = 32;

/// Process-owned datadir secret (clone cheaply via Arc at higher layers).
#[derive(Clone, PartialEq, Eq)]
pub struct StoreSecret {
    pub bytes: [u8; SECRET_LEN],
}

impl std::fmt::Debug for StoreSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreSecret(<redacted>)")
    }
}

impl StoreSecret {
    /// Cryptographically random secret (datadir create).
    pub fn generate() -> Self {
        let mut bytes = [0u8; SECRET_LEN];
        getrandom::fill(&mut bytes).expect("CSPRNG for store.secret");
        // Reject all-zero (astronomically unlikely) so tests can detect missing entropy.
        if bytes.iter().all(|&b| b == 0) {
            bytes[0] = 1;
        }
        Self { bytes }
    }

    /// Fixed secret for unit tests (not for production create).
    pub fn from_bytes(bytes: [u8; SECRET_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; SECRET_LEN] {
        &self.bytes
    }

    /// Persist under `store_dir/store.secret`.
    pub fn write_to_store_dir(&self, store_dir: &Path) -> Result<(), StoreError> {
        let path = secret_path(store_dir);
        if path.exists() {
            return Err(StoreError::io(
                &path,
                std::io::Error::new(std::io::ErrorKind::AlreadyExists, "store.secret exists"),
            ));
        }
        crate::file::write_synced_tmp_rename(&path, &self.bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| StoreError::io(&path, e))?;
        }
        Ok(())
    }

    /// Load existing secret; `Err` if missing or wrong length.
    pub fn load_from_store_dir(store_dir: &Path) -> Result<Self, StoreError> {
        let path = secret_path(store_dir);
        let mut f = std::fs::File::open(&path).map_err(|e| StoreError::io(&path, e))?;
        let mut bytes = [0u8; SECRET_LEN];
        f.read_exact(&mut bytes)
            .map_err(|e| StoreError::io(&path, e))?;

        let mut extra = [0u8; 1];
        match f.read(&mut extra) {
            Ok(0) => {}
            Ok(_) => {
                return Err(StoreError::Corrupt(
                    "store.secret longer than 32 bytes (wipe datadir)",
                ))
            }
            Err(e) => return Err(StoreError::io(&path, e)),
        }
        Ok(Self { bytes })
    }

    /// Load an existing secret, or generate and write one on datadir create.
    pub fn load_or_create(store_dir: &Path) -> Result<Self, StoreError> {
        let path = secret_path(store_dir);
        if path.exists() {
            return Self::load_from_store_dir(store_dir);
        }
        let s = Self::generate();
        s.write_to_store_dir(store_dir)?;
        Ok(s)
    }

    /// Load a secret that must already exist. A missing file is corruption,
    /// never a fresh key: regenerating it would silently unread every stored
    /// script and invalidate the keyed `tx.head` probes.
    pub fn load_existing(store_dir: &Path) -> Result<Self, StoreError> {
        if !secret_path(store_dir).exists() {
            return Err(StoreError::Corrupt(
                "store.secret missing (schema 12+ requires wipe or recreate)",
            ));
        }
        Self::load_from_store_dir(store_dir)
    }

    /// Stream byte for XOR of script/witness at absolute payload offset `off`.
    #[inline]
    pub fn xor_key_byte(&self, off: u64) -> u8 {
        let i = (off as usize) % SECRET_LEN;
        // Mix position so long scripts do not simply repeat the secret.
        let mix = ((off.wrapping_mul(0x9E37_79B9_7F4A_7C15)) >> 56) as u8;
        self.bytes[i] ^ mix
    }

    /// XOR `buf` in place (encode and decode are the same operation).
    ///
    /// Same stream as [`Self::xor_key_byte`]: 8-byte words, then a tail.
    #[inline]
    pub fn xor_bytes(&self, start_off: u64, buf: &mut [u8]) {
        const GOLDEN: u64 = 0x9E37_79B9_7F4A_7C15;
        let secret = &self.bytes;
        let mut off = start_off;
        let mut chunks = buf.chunks_exact_mut(8);
        for chunk in chunks.by_ref() {
            let mut k = [0u8; 8];
            for (j, kb) in k.iter_mut().enumerate() {
                let o = off.wrapping_add(j as u64);
                *kb = secret[(o as usize) % SECRET_LEN] ^ ((o.wrapping_mul(GOLDEN) >> 56) as u8);
            }
            let mut word = [0u8; 8];
            word.copy_from_slice(chunk);
            chunk
                .copy_from_slice(&(u64::from_ne_bytes(word) ^ u64::from_ne_bytes(k)).to_ne_bytes());
            off = off.wrapping_add(8);
        }
        for b in chunks.into_remainder() {
            let mix = (off.wrapping_mul(GOLDEN) >> 56) as u8;
            *b ^= secret[(off as usize) % SECRET_LEN] ^ mix;
            off = off.wrapping_add(1);
        }
    }

    /// Keyed mix for open-hash probes: `SHA256(secret || txid)`.
    pub fn mix_txid(&self, txid: &[u8; 32]) -> [u8; 32] {
        let mut eng = sha256::HashEngine::default();
        use bitcoin_hashes::HashEngine;
        eng.input(&self.bytes);
        eng.input(txid);
        let d = sha256::Hash::from_engine(eng);
        *d.as_byte_array()
    }
}

#[inline]
pub fn secret_path(store_dir: &Path) -> PathBuf {
    store_dir.join(SECRET_FILE)
}
