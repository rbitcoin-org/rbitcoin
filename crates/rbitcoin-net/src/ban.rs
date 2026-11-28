//! Manual ban list behind Core's `setban` / `listbanned` / `clearbanned`.
//!
//! An entry is an IPv4 or IPv6 subnet, or one onion / I2P identity, with an
//! expiry. Only manual bans live here: automatic discouragement for
//! misbehavior is a separate in-memory set on [`crate::PeerHub`], and only
//! manual bans are written to the ban file. A manual ban matches loopback
//! too, as in Core, so an operator can ban a local peer; discouragement
//! never records loopback. An overlay-identity entry matches outbound
//! dials and live outbound sessions to that identity; an inbound overlay
//! connection arrives through the local proxy and is seen as loopback, so
//! no overlay entry can match it at accept.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

/// Core's default manual ban length when `setban` passes no `bantime`.
pub const DEFAULT_BAN_SECS: u64 = 24 * 60 * 60;
/// Widest IPv4 prefix a manual ban may name. Anything broader is refused.
pub const MIN_V4_PREFIX: u8 = 8;
/// Widest IPv6 prefix a manual ban may name. Anything broader is refused.
pub const MIN_V6_PREFIX: u8 = 16;

/// What one manual ban names: a subnet, or one overlay identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BanTarget {
    V4 { addr: Ipv4Addr, prefix: u8 },
    V6 { addr: Ipv6Addr, prefix: u8 },
    Onion([u8; 32]),
    I2p([u8; 32]),
}

impl fmt::Display for BanTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 { addr, prefix } => write!(f, "{addr}/{prefix}"),
            Self::V6 { addr, prefix } => write!(f, "{addr}/{prefix}"),
            Self::Onion(pk) => write!(f, "{}.onion", crate::netaddr::encode_onion_name(pk)),
            Self::I2p(dest) => write!(
                f,
                "{}{}",
                crate::netaddr::encode_i2p_name(dest),
                crate::netaddr::I2P_SUFFIX
            ),
        }
    }
}

impl BanTarget {
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match (self, ip.to_canonical()) {
            (Self::V4 { addr, prefix }, IpAddr::V4(v4)) => {
                let mask = v4_mask(*prefix);
                u32::from(*addr) & mask == u32::from(v4) & mask
            }
            (Self::V6 { addr, prefix }, IpAddr::V6(v6)) => {
                let mask = v6_mask(*prefix);
                u128::from(*addr) & mask == u128::from(v6) & mask
            }
            _ => false,
        }
    }

    pub fn matches_net(&self, net: crate::NetAddr) -> bool {
        match net {
            crate::NetAddr::Ip(sock) => self.matches_ip(sock.ip()),
            crate::NetAddr::Cjdns { ip, .. } => self.matches_ip(IpAddr::V6(ip)),
            crate::NetAddr::Onion { pk, .. } => *self == Self::Onion(pk),
            crate::NetAddr::I2p { dest, .. } => *self == Self::I2p(dest),
            crate::NetAddr::Name { .. } => false,
        }
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    }
}

fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix.min(128)))
    }
}

/// Why a `setban` target string did not parse.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BanParseError {
    /// Not an IP, subnet, onion, or I2P identity.
    Invalid,
    /// A subnet wider than [`MIN_V4_PREFIX`] / [`MIN_V6_PREFIX`].
    TooBroad,
}

impl fmt::Display for BanParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid => write!(f, "invalid IP, subnet, or overlay identity"),
            Self::TooBroad => write!(f, "subnet prefix is too broad"),
        }
    }
}

impl std::error::Error for BanParseError {}

/// Parse a `setban` target: an IPv4/IPv6 address, a CIDR subnet, an onion
/// name (with or without `:port`), or an I2P `.b32.i2p` name. A subnet's
/// address is masked down to its network address, as in Core.
pub fn parse_ban_target(s: &str) -> Result<BanTarget, BanParseError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(BanParseError::Invalid);
    }
    if let Some(target) = parse_overlay_target(s) {
        return target;
    }
    parse_subnet_target(s)
}

fn parse_overlay_target(s: &str) -> Option<Result<BanTarget, BanParseError>> {
    if let Some(idx) = s.find(".onion") {
        let rest = &s[idx + ".onion".len()..];
        if !rest.is_empty() && !rest.starts_with(':') {
            return None;
        }
        // A `:port` suffix is dropped, but only when it is a port: a
        // malformed suffix must not silently widen the ban to the
        // identity on every port.
        if let Some(port) = rest.strip_prefix(':') {
            if port.parse::<u16>().is_err() {
                return Some(Err(BanParseError::Invalid));
            }
        }
        return Some(
            crate::netaddr::decode_onion_name(&s[..idx])
                .map(BanTarget::Onion)
                .ok_or(BanParseError::Invalid),
        );
    }
    if let Some(name) = crate::netaddr::strip_i2p_suffix(s) {
        return Some(
            crate::netaddr::decode_i2p_name(name)
                .map(BanTarget::I2p)
                .ok_or(BanParseError::Invalid),
        );
    }
    let (host, port_ok) = match s.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().is_ok()),
        None => (s, true),
    };
    if let Some(name) = crate::netaddr::strip_i2p_suffix(host) {
        if !port_ok {
            return Some(Err(BanParseError::Invalid));
        }
        return Some(
            crate::netaddr::decode_i2p_name(name)
                .map(BanTarget::I2p)
                .ok_or(BanParseError::Invalid),
        );
    }
    None
}

fn parse_subnet_target(s: &str) -> Result<BanTarget, BanParseError> {
    let (ip_s, prefix_s) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let ip: IpAddr = ip_s.parse().map_err(|_| BanParseError::Invalid)?;
    match ip {
        IpAddr::V4(v4) => {
            let prefix = parse_prefix(prefix_s, 32)?;
            if prefix < MIN_V4_PREFIX {
                return Err(BanParseError::TooBroad);
            }
            Ok(BanTarget::V4 {
                addr: Ipv4Addr::from(u32::from(v4) & v4_mask(prefix)),
                prefix,
            })
        }
        IpAddr::V6(v6) => {
            let prefix = parse_prefix(prefix_s, 128)?;
            if prefix < MIN_V6_PREFIX {
                return Err(BanParseError::TooBroad);
            }
            // An IPv4-mapped address (::ffff:a.b.c.d) is an IPv4 target:
            // admission canonicalizes mapped addresses to V4, so a stored
            // V6 entry would never match. Store the embedded V4 form, with
            // the prefix counted from where the V4 part starts (bit 96).
            if let Some(v4) = v6.to_ipv4_mapped() {
                if prefix <= 96 {
                    return Err(BanParseError::TooBroad);
                }
                let prefix = prefix - 96;
                if prefix < MIN_V4_PREFIX {
                    return Err(BanParseError::TooBroad);
                }
                return Ok(BanTarget::V4 {
                    addr: Ipv4Addr::from(u32::from(v4) & v4_mask(prefix)),
                    prefix,
                });
            }
            Ok(BanTarget::V6 {
                addr: Ipv6Addr::from(u128::from(v6) & v6_mask(prefix)),
                prefix,
            })
        }
    }
}

fn parse_prefix(s: Option<&str>, full: u8) -> Result<u8, BanParseError> {
    let Some(s) = s else {
        return Ok(full);
    };
    let n: u32 = s.parse().map_err(|_| BanParseError::Invalid)?;
    u8::try_from(n)
        .ok()
        .filter(|p| *p <= full)
        .ok_or(BanParseError::Invalid)
}

/// One manual ban: its target, when it was added, and when it ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BanEntry {
    pub target: BanTarget,
    pub created: u64,
    pub banned_until: u64,
}

/// `add` named a target that is already banned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AlreadyBanned;

impl fmt::Display for AlreadyBanned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IP/Subnet already banned")
    }
}

impl std::error::Error for AlreadyBanned {}

/// Why a ban-list change did not take effect.
#[derive(Debug)]
pub enum BanUpdateError {
    /// `add` named a target that is already banned.
    AlreadyBanned(AlreadyBanned),
    /// The change could not be written to the ban file. The in-memory
    /// list is left unchanged, so the caller can retry once storage
    /// recovers.
    Persist(std::io::Error),
}

impl fmt::Display for BanUpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyBanned(e) => e.fmt(f),
            Self::Persist(e) => write!(f, "cannot write ban list: {e}"),
        }
    }
}

impl std::error::Error for BanUpdateError {}

/// The manual ban list, plus the ban file it is persisted to when the node
/// wired one with [`crate::PeerHub::set_ban_file`].
#[derive(Debug, Default)]
pub struct BanList {
    entries: Vec<BanEntry>,
    file: Option<PathBuf>,
}

impl BanList {
    /// Load `path` (Core `banlist.json` shape) and persist later changes
    /// back to it. A missing file starts an empty list. A file that
    /// exists but cannot be read also starts empty, but is left
    /// unwired: later changes stay in memory rather than overwriting
    /// a file whose contents were never loaded.
    pub fn set_file(&mut self, path: PathBuf, now: u64) {
        match load_ban_file(&path) {
            BanFileLoad::Loaded(mut entries) => {
                entries.retain(|e| e.banned_until >= now);
                dedupe_entries(&mut entries);
                self.entries = entries;
                self.file = Some(path);
            }
            BanFileLoad::Missing => {
                self.entries = Vec::new();
                self.file = Some(path);
            }
            BanFileLoad::Unreadable => {
                self.entries = Vec::new();
                self.file = None;
            }
        }
    }

    pub fn add(
        &mut self,
        target: BanTarget,
        created: u64,
        banned_until: u64,
    ) -> Result<BanEntry, BanUpdateError> {
        self.sweep(created);
        // Core's `Ban` replaces a row whose ban has run out: after the
        // sweep only a row expiring exactly now can remain, and it no
        // longer counts as banned (`IsBanned` is `now < banned_until`).
        if let Some(pos) = self.entries.iter().position(|e| e.target == target) {
            if self.entries[pos].banned_until > created {
                return Err(BanUpdateError::AlreadyBanned(AlreadyBanned));
            }
            let entry = BanEntry {
                target,
                created,
                banned_until,
            };
            let backup = self.entries.clone();
            self.entries[pos] = entry;
            if let Err(e) = self.save(created) {
                self.entries = backup;
                return Err(BanUpdateError::Persist(e));
            }
            return Ok(entry);
        }
        let entry = BanEntry {
            target,
            created,
            banned_until,
        };
        let backup = self.entries.clone();
        self.entries.push(entry);
        if let Err(e) = self.save(created) {
            self.entries = backup;
            return Err(BanUpdateError::Persist(e));
        }
        Ok(entry)
    }

    pub fn remove(
        &mut self,
        target: BanTarget,
        now: u64,
    ) -> Result<Option<BanEntry>, BanUpdateError> {
        self.sweep(now);
        let Some(pos) = self.entries.iter().position(|e| e.target == target) else {
            return Ok(None);
        };
        let backup = self.entries.clone();
        let entry = self.entries.remove(pos);
        if let Err(e) = self.save(now) {
            self.entries = backup;
            return Err(BanUpdateError::Persist(e));
        }
        Ok(Some(entry))
    }

    pub fn clear(&mut self, now: u64) -> Result<usize, BanUpdateError> {
        let n = self.entries.len();
        if n == 0 && self.file.is_none() {
            return Ok(0);
        }
        // With a file wired, the empty list is persisted even when
        // memory is already empty: rows the load dropped as expired
        // are still on disk, and a clear must not leave them there to
        // revive under a corrected clock.
        let backup = std::mem::take(&mut self.entries);
        if let Err(e) = self.save(now) {
            self.entries = backup;
            return Err(BanUpdateError::Persist(e));
        }
        Ok(n)
    }

    pub fn list(&mut self, now: u64) -> Vec<BanEntry> {
        if self.sweep(now) {
            self.save_best_effort(now);
        }
        let mut out = self.entries.clone();
        out.sort_by_key(|e| (e.created, e.banned_until));
        out
    }

    pub fn is_banned_ip(&mut self, ip: IpAddr, now: u64) -> bool {
        if self.sweep(now) {
            self.save_best_effort(now);
        }
        // Core's IsBanned matches only while banned_until > now: a row
        // expiring exactly now is still listed but no longer enforced.
        self.entries
            .iter()
            .any(|e| e.banned_until > now && e.target.matches_ip(ip))
    }

    pub fn is_banned_net(&mut self, net: crate::NetAddr, now: u64) -> bool {
        if self.sweep(now) {
            self.save_best_effort(now);
        }
        self.entries
            .iter()
            .any(|e| e.banned_until > now && e.target.matches_net(net))
    }

    fn sweep(&mut self, now: u64) -> bool {
        let before = self.entries.len();
        // Core's SweepBanned drops a row only once now > banned_until.
        self.entries.retain(|e| e.banned_until >= now);
        self.entries.len() != before
    }

    fn save(&self, now: u64) -> std::io::Result<()> {
        let Some(path) = &self.file else {
            return Ok(());
        };
        write_ban_file(path, &self.entries, now)
    }

    /// Persist after a read-path sweep, where a failed write can only be
    /// logged: the next change rewrites the whole file anyway.
    fn save_best_effort(&self, now: u64) {
        if let Err(e) = self.save(now) {
            if let Some(path) = &self.file {
                rbitcoin_log::warn!("banlist: write {}: {e}", path.display());
            }
        }
    }
}

fn write_ban_file(path: &std::path::Path, entries: &[BanEntry], now: u64) -> std::io::Result<()> {
    let rows: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            serde_json::json!({
                "version": 1,
                "address": e.target.to_string(),
                "ban_created": e.created,
                "banned_until": e.banned_until,
                "ban_duration": e.banned_until.saturating_sub(e.created),
                "time_remaining": e.banned_until.saturating_sub(now),
                "ban_reason": "manually added",
            })
        })
        .collect();
    let body = serde_json::json!({ "banned_nets": rows }).to_string();
    let tmp = path.with_extension("json.new");
    {
        use rbitcoin_store::durability::Durable as _;
        use std::io::Write as _;
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(body.as_bytes())?;
        // A crash after the rename must not leave an empty banlist.json:
        // the temp file's bytes are on disk before it becomes the file.
        f.durable_sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // The rename is a directory change: sync the parent directory so a
    // power loss cannot drop it and resurrect the previous list (or no
    // list). The rename has already landed, so a failed directory sync
    // is logged, not reported: failing the update here would roll the
    // in-memory list back out of sync with the file on disk.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = rbitcoin_store::file::fsync_parent_dir(parent) {
                rbitcoin_log::warn!("banlist: sync {}: {e}", parent.display());
            }
        }
    }
    Ok(())
}

enum BanFileLoad {
    Loaded(Vec<BanEntry>),
    /// No file yet: first use.
    Missing,
    /// The file exists but could not be read.
    Unreadable,
}

fn load_ban_file(path: &std::path::Path) -> BanFileLoad {
    let body = match std::fs::read_to_string(path) {
        Ok(body) => body,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return BanFileLoad::Missing,
        Err(e) => {
            rbitcoin_log::warn!(
                "banlist: read {}: {e}; bans will not persist",
                path.display()
            );
            return BanFileLoad::Unreadable;
        }
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) else {
        rbitcoin_log::warn!(
            "banlist: {} is not valid JSON; starting empty",
            path.display()
        );
        return BanFileLoad::Loaded(Vec::new());
    };
    let Some(rows) = v.get("banned_nets").and_then(|r| r.as_array()) else {
        return BanFileLoad::Loaded(Vec::new());
    };
    BanFileLoad::Loaded(rows.iter().filter_map(ban_entry_from_json).collect())
}

/// One row per target. Loading normalizes each row's address, so two
/// spellings of one target (`192.0.2.1/32`, `::ffff:192.0.2.1/128`)
/// would otherwise load as duplicates a single removal cannot clear.
/// The row with the latest expiry wins.
fn dedupe_entries(entries: &mut Vec<BanEntry>) {
    let mut out: Vec<BanEntry> = Vec::with_capacity(entries.len());
    for e in entries.drain(..) {
        match out.iter_mut().find(|o| o.target == e.target) {
            Some(o) if e.banned_until > o.banned_until => *o = e,
            Some(_) => {}
            None => out.push(e),
        }
    }
    *entries = out;
}

fn ban_entry_from_json(row: &serde_json::Value) -> Option<BanEntry> {
    let target = parse_ban_target(row.get("address")?.as_str()?).ok()?;
    Some(BanEntry {
        target,
        created: row.get("ban_created")?.as_u64()?,
        banned_until: row.get("banned_until")?.as_u64()?,
    })
}
