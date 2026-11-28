//! Fixed seeds, DNS seed names, and the process peer book ([`AddrMan`]).
//!
//! Each remembered address carries a **byte of informational flags** used to
//! rank dial candidates: prefer untried / known-good / fast peers; only fall
//! back to incompatible or recently-failed hosts when the good set is empty.
//!
//! The book can be **persisted** under the datadir (`peers` file) so discovered
//! addrs and flags survive restarts.

use bitcoin::p2p::ServiceFlags;
use rbitcoin_primitives::Network;
use rbitcoin_store::durability::Durable as _;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

use crate::asmap::AsMap;
use crate::netaddr::{parse_net_addr, strip_i2p_suffix, strip_onion_suffix, NetAddr, OnlyNet};
use crate::netgroup::{netgroup_net, outbound_group, select_diverse};

#[doc(hidden)]
pub fn net_addr_unspecified(addr: NetAddr) -> bool {
    matches!(addr, NetAddr::Ip(s) if s.ip().is_unspecified())
}

/// Skip a recently dialed addr while any other candidate remains.
pub const DIAL_ATTEMPT_RECENT: Duration = Duration::from_secs(10 * 60);

#[doc(hidden)]
pub fn attempt_is_recent(when: Instant, now: Instant) -> bool {
    matches!(
        now.saturating_duration_since(when)
            .cmp(&DIAL_ATTEMPT_RECENT),
        std::cmp::Ordering::Less
    )
}

/// Service bits we advertise and ask DNS seeds for (`NETWORK|WITNESS|P2P_V2` = `0x809`).
pub fn required_seed_services() -> ServiceFlags {
    ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2
}

/// DNS seed service-bit filter hostname (`x<hex>.<seed>`).
pub fn dns_seed_query_host(seed: &str, services: ServiceFlags) -> String {
    format!("x{:x}.{seed}", services.to_u64())
}

/// DNS seed hostnames (resolve at runtime with default port).
///
/// Core `vSeeds` in `src/kernel/chainparams.cpp`, in Core's order. The
/// trailing dot keeps each name absolute, so the resolver never tries the
/// search domain first.
pub fn dns_seeds(network: Network) -> &'static [&'static str] {
    match network {
        Network::Mainnet => &[
            "dnsseed.bluematt.me.",
            "seed.bitcoin.jonasschnelli.ch.",
            "seed.btc.petertodd.net.",
            "seed.bitcoin.sprovoost.nl.",
            "dnsseed.emzy.de.",
            "seed.bitcoin.wiz.biz.",
            "seed.mainnet.achownodes.xyz.",
        ],
        Network::Testnet => &[
            "testnet-seed.bitcoin.jonasschnelli.ch.",
            "seed.tbtc.petertodd.net.",
            "testnet-seed.bluematt.me.",
            "seed.testnet.achownodes.xyz.",
        ],
        Network::Signet => &[
            "seed.signet.bitcoin.sprovoost.nl.",
            "seed.signet.achownodes.xyz.",
        ],
        Network::Testnet4 => &[
            "seed.testnet4.bitcoin.sprovoost.nl.",
            "seed.testnet4.wiz.biz.",
        ],
        Network::Testnet5 | Network::Regtest => &[],
    }
}

/// Core `contrib/seeds/nodes_<net>.txt`, the input to Core's
/// `chainparamsseeds.h`. Refresh with `scripts/core-fixed-seeds.sh COMMIT`.
fn fixed_seed_text(network: Network) -> &'static str {
    match network {
        Network::Mainnet => include_str!("../seeds/nodes_main.txt"),
        Network::Testnet => include_str!("../seeds/nodes_test.txt"),
        Network::Signet => include_str!("../seeds/nodes_signet.txt"),
        Network::Testnet4 => include_str!("../seeds/nodes_testnet4.txt"),
        Network::Testnet5 | Network::Regtest => "",
    }
}

/// Core's fixed seeds for `network` (IPv4, IPv6, Tor v3, I2P, CJDNS), in
/// Core's order, parsed as the caller pulls them.
///
/// The table stays Core's text so a refresh is a byte copy that diffs
/// against Core.
#[doc(hidden)]
pub fn fixed_seeds(network: Network) -> impl Iterator<Item = NetAddr> {
    fixed_seed_lines(network).map(parse_fixed_seed)
}

/// The address text of each table line, comments and blanks dropped.
fn fixed_seed_lines(network: Network) -> impl Iterator<Item = &'static str> {
    fixed_seed_text(network)
        .lines()
        .map(|line| line.split_once('#').map_or(line, |(addr, _)| addr).trim())
        .filter(|addr| !addr.is_empty())
}

/// The net a seed line names by its suffix (Tor, I2P), read before the
/// parse. `None` is clearnet, where only the parse tells IPv4, IPv6, and
/// CJDNS apart.
fn suffix_net(addr: &str) -> Option<OnlyNet> {
    let host = addr.rsplit_once(':').map_or(addr, |(host, _)| host);
    if strip_i2p_suffix(host).is_some() {
        Some(OnlyNet::I2p)
    } else if strip_onion_suffix(host).is_some() {
        Some(OnlyNet::Onion)
    } else {
        None
    }
}

fn parse_fixed_seed(addr: &str) -> NetAddr {
    parse_net_addr(addr).expect("Core fixed seed parses")
}

/// Default P2P port for a network.
pub fn default_port(network: Network) -> u16 {
    network.default_p2p_port()
}

/// Default JSON-RPC TCP port for a network (Core-matching).
pub fn default_rpc_port(network: Network) -> u16 {
    network.default_rpc_port()
}

/// Per listed seed: Core `x<hex>.` filter hostname first, then the bare seed.
pub fn seed_lookup_names(network: Network) -> Vec<Vec<String>> {
    let bits = required_seed_services();
    dns_seeds(network)
        .iter()
        .map(|seed| vec![dns_seed_query_host(seed, bits), (*seed).to_string()])
        .collect()
}

/// Prefer the x-filter A/AAAA set when it is non-empty; otherwise the unfiltered set.
pub fn pick_seed_results(x_ips: &[SocketAddr], plain_ips: &[SocketAddr]) -> Vec<SocketAddr> {
    if !x_ips.is_empty() {
        x_ips.to_vec()
    } else {
        plain_ips.to_vec()
    }
}

#[doc(hidden)]
pub fn resolve_host_port(host: &str, port: u16) -> Vec<SocketAddr> {
    let with_port = format!("{host}:{port}");
    match with_port.to_socket_addrs() {
        Ok(iter) => iter.collect(),
        Err(_) => Vec::new(),
    }
}

/// Resolve DNS seed hostnames to socket addresses using the network default port.
///
/// Each seed is queried as `x809.<seed>` first. If that name returns no
/// addresses, the unfiltered seed name is tried. First success wins per seed
/// so the same IPs are not injected twice.
pub fn resolve_dns_seeds(network: Network) -> Vec<SocketAddr> {
    let port = default_port(network);
    let mut out = Vec::new();
    for names in seed_lookup_names(network) {
        let x_ips = names
            .first()
            .map(|h| resolve_host_port(h, port))
            .unwrap_or_default();
        let plain_ips = if x_ips.is_empty() {
            names
                .get(1)
                .map(|h| resolve_host_port(h, port))
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for a in pick_seed_results(&x_ips, &plain_ips) {
            if !out.contains(&a) {
                out.push(a);
            }
        }
    }
    out
}

/// DNS seed hostnames with the network default port for SOCKS domain CONNECT.
///
/// Does not call [`ToSocketAddrs`] — the proxy performs remote DNS.
pub fn socks_dns_seed_dests(network: Network) -> Vec<(String, u16)> {
    let port = default_port(network);
    dns_seeds(network)
        .iter()
        .map(|host| ((*host).to_string(), port))
        .collect()
}

/// Informational peer flags packed into one byte (more bits reserved for later).
///
/// | bit | name | meaning |
/// |-----|------|---------|
/// | 0 | `HAS_CONNECTED` | Successful BIP324 handshake at least once |
/// | 1 | `FAST` | Observed <100 ms first-data latency and >10 Mbps |
/// | 2 | `SLOW` | Observed >250 ms latency or <1 Mbps |
/// | 3 | `INCOMPATIBLE` | No v2 transport (or similar protocol reject) |
/// | 4 | `FAILED_LAST_CONNECT` | Last dial failed for network/timeout reasons |
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Hash)]
pub struct PeerFlags(pub u8);

impl PeerFlags {
    pub const HAS_CONNECTED: u8 = 1 << 0;
    pub const FAST: u8 = 1 << 1;
    pub const SLOW: u8 = 1 << 2;
    pub const INCOMPATIBLE: u8 = 1 << 3;
    pub const FAILED_LAST_CONNECT: u8 = 1 << 4;

    /// Latency below this and throughput above [`Self::FAST_BPS_MIN`] → `FAST`.
    pub const FAST_LATENCY_MS: u64 = 100;
    /// Throughput floor for `FAST` (10 Mbps = 1.25 MB/s).
    pub const FAST_BPS_MIN: u64 = 10_000_000 / 8;
    /// Latency above this **or** throughput below [`Self::SLOW_BPS_MAX`] → `SLOW`.
    pub const SLOW_LATENCY_MS: u64 = 250;
    /// Throughput ceiling for `SLOW` (1 Mbps = 125 KB/s).
    pub const SLOW_BPS_MAX: u64 = 1_000_000 / 8;

    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    #[inline]
    pub const fn contains(self, bit: u8) -> bool {
        self.0 & bit != 0
    }

    #[inline]
    pub fn insert(&mut self, bit: u8) {
        self.0 |= bit;
    }

    #[inline]
    pub fn remove(&mut self, bit: u8) {
        self.0 &= !bit;
    }

    #[inline]
    pub fn set(&mut self, bit: u8, on: bool) {
        if on {
            self.insert(bit);
        } else {
            self.remove(bit);
        }
    }

    pub fn has_connected(self) -> bool {
        self.contains(Self::HAS_CONNECTED)
    }
    pub fn is_fast(self) -> bool {
        self.contains(Self::FAST)
    }
    pub fn is_slow(self) -> bool {
        self.contains(Self::SLOW)
    }
    pub fn is_incompatible(self) -> bool {
        self.contains(Self::INCOMPATIBLE)
    }
    pub fn failed_last_connect(self) -> bool {
        self.contains(Self::FAILED_LAST_CONNECT)
    }

    /// Never dialed / no outcome recorded yet.
    pub fn is_untried(self) -> bool {
        self.0 == 0
    }

    /// Dial preference tier: **0 = preferred**, **1 = ok**, **2 = last resort**.
    ///
    /// Preferred: untried, fast, or previously connected without failure/slow/incompat.
    /// Last resort: incompatible or failed last connect.
    pub fn dial_tier(self) -> u8 {
        if self.is_incompatible() || self.failed_last_connect() {
            return 2;
        }
        if self.is_slow() && !self.is_fast() {
            return 1;
        }
        0
    }

    /// Update `FAST` / `SLOW` from a measured sample. Clears the opposite bit.
    pub fn apply_speed_sample(&mut self, latency_ms: u64, bytes_per_sec: u64) {
        let fast = latency_ms < Self::FAST_LATENCY_MS && bytes_per_sec > Self::FAST_BPS_MIN;
        let slow = latency_ms > Self::SLOW_LATENCY_MS || bytes_per_sec < Self::SLOW_BPS_MAX;
        if fast {
            self.insert(Self::FAST);
            self.remove(Self::SLOW);
        } else if slow {
            self.insert(Self::SLOW);
            self.remove(Self::FAST);
        }
        // else: mid-range — leave prior classification
    }
}

/// One remembered peer address + flags.
#[derive(Clone, Debug)]
pub struct PeerEntry {
    pub addr: NetAddr,
    pub flags: PeerFlags,
    /// Unix seconds when a peer said it last saw this row. `0` means no peer
    /// taught a time yet (a seed, `addnode`, or a v1/v2 `peers` row before
    /// its first serve).
    pub last_seen: u32,
}

/// Core's trust window for a gossiped address time: after 1973 and no more
/// than ten minutes ahead. A row outside the window takes
/// [`UNKNOWN_SEEN_AGE_SECS`] back from the node clock.
pub const ADDR_TIME_FLOOR: u32 = 100_000_000;

/// Age a row with no trusted time starts at: Core backdates an untrusted
/// address time by five days.
pub const UNKNOWN_SEEN_AGE_SECS: u64 = 5 * 24 * 60 * 60;

/// Core's `ProcessAddrs` penalty on a time a peer gossiped, so one source
/// cannot hold a row fresher than two hours of its own claim.
pub const GOSSIP_TIME_PENALTY_SECS: u32 = 2 * 60 * 60;

fn backdated_seen(now: u64) -> u32 {
    let now = now.min(u64::from(u32::MAX)) as u32;
    now.saturating_sub(UNKNOWN_SEEN_AGE_SECS as u32)
}

/// The Unix time a gossiped address is taken to have been seen: its own time
/// when it is inside Core's window, else five days back. Never `0`, so every
/// gossiped row ages from a fixed point.
#[doc(hidden)]
pub fn learned_addr_time(time: u32, now: u64) -> u32 {
    if time <= ADDR_TIME_FLOOR || u64::from(time) > now.saturating_add(600) {
        backdated_seen(now)
    } else {
        time
    }
}

/// The time a `getaddr` reply or `getnodeaddresses` row carries. A row that
/// no peer taught a time, or whose stored time is more than ten minutes in
/// the future, is backdated as Core's `ProcessAddrs` does.
#[doc(hidden)]
pub fn row_reply_time(last_seen: u32, now: u64) -> u32 {
    let now = now.min(u64::from(u32::MAX)) as u32;
    if last_seen == 0 || u64::from(last_seen) > u64::from(now).saturating_add(600) {
        return now.saturating_sub(UNKNOWN_SEEN_AGE_SECS as u32);
    }
    last_seen
}

/// Same network host, ignoring the port. Core compares an address to the peer
/// that sent it with `CNetAddr` equality, so an inbound peer's self-announce
/// (listen port) matches its source (TCP port) and takes no gossip penalty.
#[doc(hidden)]
pub fn same_host(a: NetAddr, b: NetAddr) -> bool {
    match (a, b) {
        (NetAddr::Ip(x), NetAddr::Ip(y)) => x.ip().to_canonical() == y.ip().to_canonical(),
        (NetAddr::Onion { pk: x, .. }, NetAddr::Onion { pk: y, .. }) => x == y,
        (NetAddr::I2p { dest: x, .. }, NetAddr::I2p { dest: y, .. }) => x == y,
        (NetAddr::Cjdns { ip: x, .. }, NetAddr::Cjdns { ip: y, .. }) => x == y,
        (NetAddr::Name { id: x, .. }, NetAddr::Name { id: y, .. }) => x == y,
        _ => false,
    }
}

/// Hard cap for learned / `peers` file / addrv2 (not `--connect` / DNS inject).
///
/// Ours, not a Core constant (Core uses new/tried buckets). Must stay
/// strictly above Core GetAddr
/// [`MAX_ADDR_TO_SEND`](crate::peer::MAX_ADDR_TO_SEND) /
/// [`MAX_PCT_ADDR_TO_SEND`](crate::peer::MAX_PCT_ADDR_TO_SEND)
/// (`1000 / 0.23`) so a reply can still be 1000 addresses.
pub const MAX_ADDR_MAN: usize = 8192;

/// Rows a source netgroup has taught after which, in a full book, its
/// addresses evict nothing: 1/16 of [`MAX_ADDR_MAN`] (512). A group can hold
/// more when it taught them while the book had room.
///
/// The same share Core gives one source group: its addresses land in at most
/// `ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP` (64) of the 1,024 new buckets.
pub const MAX_ROWS_PER_SOURCE_GROUP: usize = MAX_ADDR_MAN / 16;

/// Shared wake for a new dialable row. Clones of one book share it.
#[derive(Clone)]
struct AddrAdded(Arc<Notify>);

impl Default for AddrAdded {
    fn default() -> Self {
        Self(Arc::new(Notify::new()))
    }
}

impl std::fmt::Debug for AddrAdded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AddrAdded")
    }
}

/// Peer book: seeds, learned addrs, and dial ranking.
#[derive(Debug, Default, Clone)]
pub struct AddrMan {
    /// Insertion-order keys (IPv4 preferred on inject).
    pub order: Vec<NetAddr>,
    pub by_addr: HashMap<NetAddr, PeerFlags>,
    /// Unix seconds a peer last said it saw the row. A row with no entry has
    /// no learned time; see [`row_reply_time`].
    seen: HashMap<NetAddr, u32>,
    /// The value [`Self::stamp_missing_seen_for`] replaced on a row. A flush
    /// or merge keeps the normalized time when the other book still holds
    /// the replaced one, even when the normalized time is lower.
    seen_replaced: HashMap<NetAddr, u32>,
    pub asmap: Option<Arc<AsMap>>,
    pub last_attempt: HashMap<NetAddr, Instant>,
    pub only_net: Vec<OnlyNet>,
    /// `--proxy` or `--onion`. Default off: an onion row is not a peer.
    pub onion_reachable: bool,
    /// `--i2p-sam`. Default off.
    pub i2p_reachable: bool,
    pub cjdns_reachable: bool,
    /// Netgroup of the peer that taught each learned row. RAM only: a row
    /// loaded from the `peers` file, a seed, or a row first added by a dial
    /// has none; a learned row keeps its source after the node connects to
    /// it, and a copy from another live book keeps it. At most one entry per
    /// row; it leaves with the row.
    learned_from: HashMap<NetAddr, u64>,
    /// Rows in `learned_from` per source netgroup. A group leaves with its
    /// last row, so this never holds more entries than `learned_from`.
    taught_by_group: HashMap<u64, usize>,
    /// Wakes a catch-up wait when a new row is stored.
    added: AddrAdded,
}

impl AddrMan {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_asmap(&mut self, asmap: Option<Arc<AsMap>>) {
        self.asmap = asmap;
    }

    pub fn asmap(&self) -> Option<&AsMap> {
        self.asmap.as_deref()
    }

    pub fn inject(&mut self, addrs: impl IntoIterator<Item = SocketAddr>) {
        for a in addrs {
            if crate::netaddr::clearnet_unroutable(a.ip()) {
                continue;
            }
            self.add(a);
        }
        self.sort_order_ipv4_first();
    }

    /// Core's fixed-seed fallback (`ThreadOpenConnections`): add `network`'s
    /// [`fixed_seeds`] for each net this process can dial that has no row in
    /// the book. Returns how many rows were added. The table is not read
    /// when no net is wanted. Tor and I2P lines for unwanted nets, and the
    /// IP and CJDNS lines when none of those three is wanted, are skipped
    /// before the parse.
    pub fn add_fixed_seeds(&mut self, network: Network) -> usize {
        let wanted: Vec<OnlyNet> = OnlyNet::ALL
            .into_iter()
            .filter(|net| {
                self.reachable(*net) && !self.order.iter().any(|a| OnlyNet::of(*a) == *net)
            })
            .collect();
        let mut added = 0;
        if !wanted.is_empty() {
            let clearnet_wanted = wanted
                .iter()
                .any(|net| matches!(net, OnlyNet::Ipv4 | OnlyNet::Ipv6 | OnlyNet::Cjdns));
            let seeds = fixed_seed_lines(network)
                .filter(|line| match suffix_net(line) {
                    Some(net) => wanted.contains(&net),
                    None => clearnet_wanted,
                })
                .map(parse_fixed_seed);
            for addr in seeds {
                if !wanted.contains(&OnlyNet::of(addr)) || self.by_addr.contains_key(&addr) {
                    continue;
                }
                self.add_addr(addr);
                added += 1;
            }
        }
        self.sort_order_ipv4_first();
        added
    }

    pub fn set_only_net(&mut self, only: Vec<OnlyNet>) {
        self.only_net = only;
        self.retain_dialable();
    }

    pub fn set_onion_reachable(&mut self, on: bool) {
        self.onion_reachable = on;
        self.retain_dialable();
    }

    pub fn set_i2p_reachable(&mut self, on: bool) {
        self.i2p_reachable = on;
        self.retain_dialable();
    }

    pub fn set_cjdns_reachable(&mut self, on: bool) {
        self.cjdns_reachable = on;
        self.retain_dialable();
    }

    pub fn reachable(&self, net: OnlyNet) -> bool {
        if !net.allowed_by(&self.only_net) {
            return false;
        }
        match net {
            OnlyNet::Ipv4 | OnlyNet::Ipv6 => true,
            OnlyNet::Onion => self.onion_reachable,
            OnlyNet::I2p => self.i2p_reachable,
            OnlyNet::Cjdns => self.cjdns_reachable,
        }
    }

    #[doc(hidden)]
    pub fn dialable(&self, addr: NetAddr) -> bool {
        !matches!(addr, NetAddr::Name { .. }) && self.reachable(OnlyNet::of(addr))
    }

    #[doc(hidden)]
    pub fn retain_dialable(&mut self) {
        let gone: Vec<NetAddr> = self
            .order
            .iter()
            .copied()
            .filter(|a| !self.dialable(*a))
            .collect();
        for addr in gone {
            self.evict_one(addr);
        }
    }

    /// Like [`Self::take_dial_candidates`] plus onion and I2P rows this process can dial.
    ///
    /// `overlay_live` says an outbound onion or I2P peer is already live. A
    /// batch of two or more always keeps one slot for an eligible overlay row.
    /// A one-peer batch takes that slot only when `overlay_live` is false, so
    /// a lost onion peer is replaced by the next single redial. Onion and I2P
    /// rows take no netgroup: Core's one-outbound-per-group rule leaves those
    /// networks out.
    pub fn take_dial_candidates_net(
        &self,
        max: usize,
        exclude: &HashSet<NetAddr>,
        occupied: &[SocketAddr],
        overlay_live: bool,
    ) -> Vec<NetAddr> {
        let ip_ex: HashSet<SocketAddr> = exclude
            .iter()
            .copied()
            .filter_map(NetAddr::socket_addr)
            .collect();
        // `ip_paced`: every eligible IP row was tried recently, so `ip` is
        // the one paced redial. Overlay rows must not take the slots the
        // other IP rows are due on later passes: this pass adds one at most.
        let (ip, ip_paced) = self.pick_dial_candidates(max, &ip_ex, occupied);
        let ip: Vec<NetAddr> = ip.into_iter().map(NetAddr::from_socket).collect();
        let now = Instant::now();
        let mut overlay: Vec<(u8, NetAddr)> = self
            .order
            .iter()
            .copied()
            .filter(|a| a.is_overlay() && self.dialable(*a) && !exclude.contains(a))
            .map(|a| (self.flags_of(&a).dial_tier(), a))
            .collect();
        overlay.sort_by_key(|(tier, _)| *tier);
        let ip_has_fresh = ip.iter().any(|a| self.flags_of(a).dial_tier() < 2);
        if ip_has_fresh {
            overlay.retain(|(tier, a)| {
                *tier < 2
                    && !self.flags_of(a).is_incompatible()
                    && !self.recently_attempted_addr(*a, now)
            });
        } else if overlay
            .iter()
            .any(|(_, a)| !self.flags_of(a).is_incompatible())
        {
            overlay.retain(|(_, a)| !self.flags_of(a).is_incompatible());
            if overlay
                .iter()
                .any(|(_, a)| !self.recently_attempted_addr(*a, now))
            {
                overlay.retain(|(_, a)| !self.recently_attempted_addr(*a, now));
            }
        }
        let mut out = ip;
        // A full clearnet batch used to return before any onion or I2P row.
        // Keep one slot for the best eligible overlay. A one-peer batch keeps
        // it only while no overlay outbound is live. An overlay that was only
        // kept as a fallback (every row attempted inside the recent window)
        // does not displace a clearnet row.
        let overlay_fresh = overlay
            .iter()
            .any(|(_, a)| !self.recently_attempted_addr(*a, now));
        if overlay_fresh && out.len() >= max && (max >= 2 || !overlay_live) {
            out.pop();
        }
        let room = if ip_paced {
            max.min(out.len() + 1)
        } else {
            max
        };
        for (_, a) in overlay {
            if out.len() >= room {
                break;
            }
            if !out.contains(&a) {
                out.push(a);
            }
        }
        out
    }

    #[doc(hidden)]
    pub fn recently_attempted_addr(&self, addr: NetAddr, now: Instant) -> bool {
        self.last_attempt
            .get(&addr)
            .is_some_and(|&t| attempt_is_recent(t, now))
    }

    pub fn add(&mut self, addr: SocketAddr) {
        self.add_addr(NetAddr::from_socket(addr));
    }

    pub fn add_addr(&mut self, addr: NetAddr) {
        if !self.dialable(addr) {
            return;
        }
        if self.by_addr.contains_key(&addr) {
            return;
        }
        if self.order.len() >= MAX_ADDR_MAN {
            let _ = self.evict_oldest_new();
        }
        self.by_addr.insert(addr, PeerFlags::empty());
        self.order.push(addr);
        self.note_added();
    }

    /// One permit when a new row lands. A waiter that is not armed yet still
    /// sees it on the next poll of [`Self::added`].
    #[doc(hidden)]
    pub fn added(&self) -> Arc<Notify> {
        Arc::clone(&self.added.0)
    }

    fn note_added(&self) {
        self.added.0.notify_one();
    }

    /// Insert or keep existing; never clears known flags when already present.
    ///
    /// Uncapped so `merge_from` can union then trim. A row this process cannot
    /// dial is dropped. [`Self::load`] restores the file, then the caller sets
    /// reachability.
    pub fn add_with_flags(&mut self, addr: SocketAddr, flags: PeerFlags) {
        self.add_with_flags_addr(NetAddr::from_socket(addr), flags);
    }

    pub fn add_with_flags_addr(&mut self, addr: NetAddr, flags: PeerFlags) {
        if !self.dialable(addr) {
            if self.by_addr.contains_key(&addr) {
                self.evict_one(addr);
            }
            return;
        }
        self.remember(addr, flags);
    }

    /// Insert without a reachability check. [`Self::load`] restores the file,
    /// then the caller sets which nets this process can dial.
    #[doc(hidden)]
    pub fn remember(&mut self, addr: NetAddr, flags: PeerFlags) {
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.0 |= flags.0;
            return;
        }
        self.by_addr.insert(addr, flags);
        self.order.push(addr);
        self.note_added();
    }

    /// Insert `addr`, taught by `source`, evicting last-resort then oldest new at `cap`.
    ///
    /// Returns true when `addr` is now in the book. Duplicates, an already
    /// over-cap book (`add` exceed), and a full book of only tried addrs
    /// return false. Never exceeds `cap`. In a full book, a source netgroup
    /// that already taught [`MAX_ROWS_PER_SOURCE_GROUP`] of the rows evicts
    /// nothing, so one sender cannot replace the rest of the book.
    pub fn add_learned(&mut self, addr: SocketAddr, source: SocketAddr, cap: usize) -> bool {
        self.add_learned_addr(
            NetAddr::from_socket(addr),
            NetAddr::from_socket(source),
            cap,
        )
    }

    pub fn add_learned_addr(&mut self, addr: NetAddr, source: NetAddr, cap: usize) -> bool {
        self.add_learned_addr_at(addr, source, 0, 0, 0, cap)
    }

    /// [`Self::add_learned_addr`] for a row a peer claimed at `claimed`
    /// (Unix seconds, already inside Core's window). `penalty` is Core's
    /// discount on that claim (`0` for a row a peer announces as itself).
    /// `now` is the node clock.
    ///
    /// Core selects the refresh interval from the sanitized but unpenalized
    /// `addr.nTime`, then stores `addr.nTime - time_penalty`
    /// (`AddrManImpl::AddSingle`). A held row takes the new time only when it
    /// is at least an hour (or a day, for a claim older than a day) newer, so
    /// one gossip stream cannot hold a row fresh.
    pub fn add_learned_addr_at(
        &mut self,
        addr: NetAddr,
        source: NetAddr,
        claimed: u32,
        penalty: u32,
        now: u64,
        cap: usize,
    ) -> bool {
        let last_seen = claimed.saturating_sub(penalty);
        if !self.dialable(addr) {
            return false;
        }
        if self.by_addr.contains_key(&addr) {
            self.refresh_seen(addr, claimed, last_seen, now);
            return false;
        }
        if cap == 0 {
            return false;
        }
        if self.order.len() > cap {
            return false;
        }
        let group = netgroup_net(source, self.asmap());
        if self.order.len() == cap && (self.at_share(group) || !self.evict_for_learn()) {
            return false;
        }
        self.by_addr.insert(addr, PeerFlags::empty());
        if last_seen != 0 {
            self.seen.insert(addr, last_seen);
        }
        self.order.push(addr);
        self.charge(addr, group);
        self.note_added();
        true
    }

    /// Core `AddSingle` refresh interval for a row seen within the last day.
    const SEEN_UPDATE_ONLINE_SECS: u64 = 60 * 60;
    /// Core `AddSingle` refresh interval for a row last seen a day or more ago.
    const SEEN_UPDATE_OFFLINE_SECS: u64 = 24 * 60 * 60;

    /// Take `last_seen` for a held row when it is newer than what the book
    /// has by Core's interval for the claim's age.
    fn refresh_seen(&mut self, addr: NetAddr, claimed: u32, last_seen: u32, now: u64) {
        if last_seen == 0 {
            return;
        }
        let stored = self.seen.get(&addr).copied().unwrap_or(0);
        let online = now.saturating_sub(u64::from(claimed)) < Self::SEEN_UPDATE_OFFLINE_SECS;
        let interval = if online {
            Self::SEEN_UPDATE_ONLINE_SECS
        } else {
            Self::SEEN_UPDATE_OFFLINE_SECS
        };
        if u64::from(stored) + interval < u64::from(last_seen) {
            self.seen.insert(addr, last_seen);
            self.seen_replaced.remove(&addr);
        }
    }

    /// Store a row a peer gossiped at `time` (untrusted Unix seconds).
    ///
    /// Sanitizes the time to Core's window, charges the source two hours
    /// unless the row is that peer's own host, and applies the held-row
    /// refresh interval. The one ingest for `addrv2`, `addr`, and a catch-up
    /// `getaddr` reply.
    pub fn add_gossiped_addr(
        &mut self,
        addr: NetAddr,
        source: NetAddr,
        time: u32,
        now: u64,
        cap: usize,
    ) -> bool {
        let claimed = learned_addr_time(time, now);
        let penalty = if same_host(addr, source) {
            0
        } else {
            GOSSIP_TIME_PENALTY_SECS
        };
        self.add_learned_addr_at(addr, source, claimed, penalty, now, cap)
    }

    /// `group` already taught its share of the rows.
    fn at_share(&self, group: u64) -> bool {
        self.taught_by_group.get(&group).copied().unwrap_or(0) >= MAX_ROWS_PER_SOURCE_GROUP
    }

    /// Record `group` as the source of `addr`, a row with no source yet.
    fn charge(&mut self, addr: NetAddr, group: u64) {
        self.learned_from.insert(addr, group);
        *self.taught_by_group.entry(group).or_insert(0) += 1;
    }

    /// Copy `other`'s row `addr` with its flags and learned time. A row this
    /// book lacks also takes `other`'s source, so a copy between live books
    /// keeps each group's share. A row both books hold keeps this book's
    /// source and takes the newer or normalized time. A full book takes no new untried row
    /// from a group at its share, as [`Self::add_learned_addr`] refuses it: a
    /// group that taught its share in each of two live books does not hold
    /// both after they are reconciled. A row `other` connected to is always
    /// taken: a peer that answered a dial is not gossip.
    pub fn copy_row_from(&mut self, other: &AddrMan, addr: NetAddr) {
        let held = self.by_addr.contains_key(&addr);
        let group = other.learned_from.get(&addr).copied();
        let flags = other.flags_of(&addr);
        if !held
            && !flags.has_connected()
            && self.order.len() >= MAX_ADDR_MAN
            && group.is_some_and(|g| self.at_share(g))
        {
            return;
        }
        self.add_with_flags_addr(addr, flags);
        if self.by_addr.contains_key(&addr) {
            self.merge_seen_from(other, addr);
        }
        if held || !self.by_addr.contains_key(&addr) {
            return;
        }
        if let Some(group) = group {
            self.charge(addr, group);
        }
    }

    /// Take `other`'s time for `addr` when it is newer, or when `other` holds
    /// the normalized value for a time this book replaced (a future time
    /// reset to the backdate is lower, not newer).
    pub fn merge_seen_from(&mut self, other: &AddrMan, addr: NetAddr) {
        let other_seen = other.last_seen_of(&addr);
        if other_seen == 0 {
            return;
        }
        let self_seen = self.last_seen_of(&addr);
        let normalized = other.seen_replaced.get(&addr).copied() == Some(self_seen);
        if normalized || other_seen > self_seen {
            self.seen.insert(addr, other_seen);
            self.seen_replaced.remove(&addr);
        }
    }

    /// Source netgroup charged for `addr`, if a peer taught it.
    #[doc(hidden)]
    pub fn source_group_of(&self, addr: NetAddr) -> Option<u64> {
        self.learned_from.get(&addr).copied()
    }

    /// Rows with a known source, and the source netgroups that taught them.
    #[doc(hidden)]
    pub fn source_tally(&self) -> (usize, usize) {
        (self.learned_from.len(), self.taught_by_group.len())
    }

    #[doc(hidden)]
    pub fn evict_one(&mut self, addr: NetAddr) {
        self.by_addr.remove(&addr);
        self.seen.remove(&addr);
        self.seen_replaced.remove(&addr);
        self.last_attempt.remove(&addr);
        if let Some(group) = self.learned_from.remove(&addr) {
            if let Entry::Occupied(mut n) = self.taught_by_group.entry(group) {
                *n.get_mut() -= 1;
                if *n.get() == 0 {
                    n.remove();
                }
            }
        }
        self.order.retain(|a| *a != addr);
    }

    #[doc(hidden)]
    pub fn evict_oldest_new(&mut self) -> bool {
        let victim = self
            .order
            .iter()
            .copied()
            .find(|a| !self.flags_of(a).has_connected());
        let Some(addr) = victim else {
            return false;
        };
        self.evict_one(addr);
        true
    }

    #[doc(hidden)]
    pub fn evict_for_learn(&mut self) -> bool {
        let victim = self
            .order
            .iter()
            .copied()
            .find(|a| self.flags_of(a).is_incompatible())
            .or_else(|| {
                self.order
                    .iter()
                    .copied()
                    .find(|a| self.flags_of(a).failed_last_connect())
            });
        if let Some(addr) = victim {
            self.evict_one(addr);
            return true;
        }
        self.evict_oldest_new()
    }

    #[doc(hidden)]
    pub fn trim_to_cap(&mut self, cap: usize) {
        if self.order.len() <= cap {
            return;
        }
        let mut keep: Vec<NetAddr> = self
            .order
            .iter()
            .copied()
            .filter(|a| self.flags_of(a).has_connected())
            .collect();
        keep.extend(
            self.order
                .iter()
                .copied()
                .filter(|a| !self.flags_of(a).has_connected()),
        );
        keep.truncate(cap);
        let keep_set: HashSet<NetAddr> = keep.iter().copied().collect();
        self.order = keep;
        self.by_addr.retain(|a, _| keep_set.contains(a));
        self.seen.retain(|a, _| keep_set.contains(a));
        self.seen_replaced.retain(|a, _| keep_set.contains(a));
        self.last_attempt.retain(|a, _| keep_set.contains(a));
        self.learned_from.retain(|a, _| keep_set.contains(a));
        self.taught_by_group.clear();
        for group in self.learned_from.values() {
            *self.taught_by_group.entry(*group).or_insert(0) += 1;
        }
    }

    /// Merge another book into this one (flag bits OR'd for shared addrs).
    ///
    /// Rows this process cannot dial are left out, and a full book leaves out
    /// an untried row from a source group at its share. Trim after.
    /// Sources follow [`Self::copy_row_from`].
    pub fn merge_from(&mut self, other: &AddrMan) {
        for e in other.entries() {
            self.copy_row_from(other, e.addr);
        }
        self.trim_to_cap(MAX_ADDR_MAN);
        self.sort_order_ipv4_first();
    }

    #[doc(hidden)]
    pub fn sort_order_ipv4_first(&mut self) {
        // Prefer IPv4: many lab hosts have no IPv6 route, and IPv6 seeds only
        // burn connect-timeout slots during IBD dial.
        self.order.sort_by_key(|a| a.is_ipv6());
    }

    pub fn peers(&self) -> Vec<SocketAddr> {
        self.order
            .iter()
            .copied()
            .filter_map(NetAddr::socket_addr)
            .collect()
    }

    pub fn flags(&self, addr: &SocketAddr) -> PeerFlags {
        self.flags_of(&NetAddr::from_socket(*addr))
    }

    pub fn connect_failed(&self, addr: NetAddr) -> bool {
        self.flags_of(&addr).failed_last_connect()
    }

    #[doc(hidden)]
    pub fn flags_of(&self, addr: &NetAddr) -> PeerFlags {
        self.by_addr
            .get(addr)
            .copied()
            .unwrap_or_else(PeerFlags::empty)
    }

    #[doc(hidden)]
    pub fn entry_of(&self, addr: &NetAddr) -> Option<PeerEntry> {
        self.by_addr.get(addr).map(|&flags| PeerEntry {
            addr: *addr,
            flags,
            last_seen: self.last_seen_of(addr),
        })
    }

    /// Unix seconds a peer last said it saw `addr`; `0` when none did.
    pub fn last_seen_of(&self, addr: &NetAddr) -> u32 {
        self.seen.get(addr).copied().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.order.len()
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Successful handshake: the row is known good. The time is not touched
    /// here, as Core's `Good_` leaves `nTime` alone at verack so a live
    /// outbound peer is not advertised as just seen.
    pub fn note_connected_addr(&mut self, addr: NetAddr) {
        self.add_addr(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.insert(PeerFlags::HAS_CONNECTED);
            f.remove(PeerFlags::FAILED_LAST_CONNECT);
            f.remove(PeerFlags::INCOMPATIBLE);
        }
    }

    /// A full outbound session ended. Core `Connected_` runs from
    /// `FinalizeNode` and refreshes the row when its time is more than twenty
    /// minutes old.
    pub fn note_disconnected_addr(&mut self, addr: NetAddr, now: u32) {
        const REFRESH_SECS: u32 = 20 * 60;
        let stored = self.seen.get(&addr).copied().unwrap_or(0);
        if now.saturating_sub(stored) > REFRESH_SECS {
            self.seen.insert(addr, now);
            self.seen_replaced.remove(&addr);
        }
    }

    /// Fix a time for the rows one reply returns, once: a missing time takes
    /// the five-day backdate, and a stored time more than ten minutes ahead
    /// is rewritten to it, as `ProcessAddrs` would. The row then ages instead
    /// of looking five days old on every serve. The caller holds the book
    /// lock with its row selection, so every address is live.
    #[doc(hidden)]
    pub fn stamp_missing_seen_for(&mut self, addrs: &[NetAddr], now: u64) {
        let backdated = backdated_seen(now);
        let now32 = now.min(u64::from(u32::MAX)) as u32;
        for addr in addrs {
            let replaced = self.seen.get(addr).copied().unwrap_or(0);
            let stale = replaced == 0 || u64::from(replaced) > u64::from(now32).saturating_add(600);
            if stale {
                self.seen.insert(*addr, backdated);
                self.seen_replaced.insert(*addr, replaced);
            }
        }
    }

    /// Record a dial attempt at `when`. Not persisted.
    pub fn note_attempt_at(&mut self, addr: SocketAddr, when: Instant) {
        self.last_attempt.insert(NetAddr::from_socket(addr), when);
    }

    pub fn last_attempt_of(&self, addr: NetAddr) -> Option<Instant> {
        self.last_attempt.get(&addr).copied()
    }

    pub fn dial_order(&self) -> &[NetAddr] {
        &self.order
    }

    pub fn is_dialable(&self, addr: NetAddr) -> bool {
        self.by_addr.contains_key(&addr) && self.dialable(addr)
    }

    pub fn note_attempt_addr(&mut self, addr: NetAddr) {
        self.last_attempt.insert(addr, Instant::now());
    }

    #[doc(hidden)]
    pub fn recently_attempted(&self, addr: SocketAddr, now: Instant) -> bool {
        self.recently_attempted_addr(NetAddr::from_socket(addr), now)
    }

    /// Dial failed. `incompatible` = no v2 / protocol reject; else network/timeout.
    pub fn note_connect_failed_addr(&mut self, addr: NetAddr, incompatible: bool) {
        if net_addr_unspecified(addr) {
            return;
        }
        self.add_addr(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            if incompatible {
                f.insert(PeerFlags::INCOMPATIBLE);
                f.remove(PeerFlags::FAILED_LAST_CONNECT);
            } else {
                f.insert(PeerFlags::FAILED_LAST_CONNECT);
            }
        }
    }

    /// Throughput / latency sample from an active session.
    pub fn note_speed_addr(&mut self, addr: NetAddr, latency_ms: u64, bytes_per_sec: u64) {
        if net_addr_unspecified(addr) {
            return;
        }
        self.add_addr(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.insert(PeerFlags::HAS_CONNECTED);
            f.apply_speed_sample(latency_ms, bytes_per_sec);
        }
    }

    /// IBD stall / relative-slow: force `SLOW`, clear `FAST` (mid-range samples
    /// would otherwise leave a prior FAST bit and keep `dial_tier` 0).
    pub fn note_ibd_slow_addr(&mut self, addr: NetAddr) {
        if net_addr_unspecified(addr) {
            return;
        }
        self.add_addr(addr);
        if let Some(f) = self.by_addr.get_mut(&addr) {
            f.insert(PeerFlags::HAS_CONNECTED);
            f.insert(PeerFlags::SLOW);
            f.remove(PeerFlags::FAST);
        }
    }

    /// `Dead` speed sample, then IBD-outlier override when `ibd_outlier`.
    pub fn apply_ibd_dead_speed_addr(
        &mut self,
        addr: NetAddr,
        latency_ms: u64,
        bps: Option<u64>,
        ibd_outlier: bool,
    ) {
        if net_addr_unspecified(addr) {
            return;
        }
        if let Some(bps) = bps {
            self.note_speed_addr(addr, latency_ms, bps);
        }
        if ibd_outlier {
            self.note_ibd_slow_addr(addr);
        }
    }

    /// Ranked dial list: tier 0 first (untried / fast / good history), then slow,
    /// then failed-last-connect. Within a tier, IPv4 before IPv6.
    ///
    /// `INCOMPATIBLE` is omitted while any other candidate remains so a mixed
    /// book does not burn outbound slots on known-v1. If every remaining addr
    /// is incompatible, those are returned as last-resort.
    ///
    /// [`select_diverse`] runs **per tier** and is strict, as Core's
    /// automatic outbound is: no pick shares a netgroup with `occupied` or
    /// with another pick, so a book that spans fewer groups than `max`
    /// returns fewer than `max`. `occupied` is the live outbound peers whose
    /// groups are taken (Core counts full-relay, block-relay and manual,
    /// never inbound). Tor, I2P, CJDNS and unroutable rows are exempt
    /// ([`outbound_group`]).
    ///
    /// Addrs attempted within [`DIAL_ATTEMPT_RECENT`] are omitted while any
    /// other candidate remains; when none remains, only the one attempted
    /// longest ago is returned. Rows in an `occupied` group are dropped
    /// first, so neither fallback waits on a row the rule will not dial.
    pub fn take_dial_candidates(
        &self,
        max: usize,
        exclude: &HashSet<SocketAddr>,
        occupied: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        self.pick_dial_candidates(max, exclude, occupied).0
    }

    /// [`Self::take_dial_candidates`], and whether the pick is the paced
    /// redial of a recently attempted row. The caller gets the decision, not
    /// a second reading of the clock.
    fn pick_dial_candidates(
        &self,
        max: usize,
        exclude: &HashSet<SocketAddr>,
        occupied: &[SocketAddr],
    ) -> (Vec<SocketAddr>, bool) {
        if max == 0 || self.order.is_empty() {
            return (Vec::new(), false);
        }
        let mut ranked: Vec<(u8, bool, bool, SocketAddr)> = self
            .order
            .iter()
            .copied()
            .filter_map(|a| {
                if !self.dialable(a) {
                    return None;
                }
                let sock = a.socket_addr()?;
                if exclude.contains(&sock) {
                    return None;
                }
                let f = self.flags_of(&a);
                Some((f.dial_tier(), sock.is_ipv6(), f.is_incompatible(), sock))
            })
            .collect();
        let asmap = self.asmap.as_deref();
        let mut occupied_groups: HashSet<u64> = occupied
            .iter()
            .filter_map(|a| outbound_group(*a, asmap))
            .collect();
        // The rule never dials these, so they must not suppress a fallback.
        ranked.retain(|(_, _, _, a)| {
            outbound_group(*a, asmap).is_none_or(|g| !occupied_groups.contains(&g))
        });
        ranked.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        if ranked.iter().any(|(_, _, incompat, _)| !*incompat) {
            ranked.retain(|(_, _, incompat, _)| !*incompat);
        }
        let now = Instant::now();
        let paced = !ranked.is_empty()
            && ranked
                .iter()
                .all(|(_, _, _, a)| self.recently_attempted(*a, now));
        if !paced {
            ranked.retain(|(_, _, _, a)| !self.recently_attempted(*a, now));
        } else {
            // Every row was attempted recently: dial only the one tried
            // longest ago, so a refill pass does not redial each dead row.
            let oldest = ranked
                .iter()
                .min_by_key(|(_, _, _, a)| self.last_attempt_of(NetAddr::from_socket(*a)))
                .copied();
            ranked = oldest.into_iter().collect();
        }
        let mut out = Vec::new();
        for tier in 0u8..=2 {
            if out.len() >= max {
                break;
            }
            let slice: Vec<SocketAddr> = ranked
                .iter()
                .filter(|(t, _, _, _)| *t == tier)
                .map(|(_, _, _, a)| *a)
                .collect();
            if slice.is_empty() {
                continue;
            }
            let need = max - out.len();
            let picked =
                select_diverse(&slice, need, &occupied_groups, |a| outbound_group(a, asmap));
            occupied_groups.extend(picked.iter().filter_map(|a| outbound_group(*a, asmap)));
            out.extend(picked);
        }
        (out, paced)
    }

    /// Round-robin-ish: take up to `max` peers starting at `offset`.
    /// Still prefers better dial tiers by walking a ranked list.
    pub fn take_outbound_offset_occupied(
        &self,
        max: usize,
        offset: usize,
        occupied: &[SocketAddr],
    ) -> Vec<SocketAddr> {
        if self.order.is_empty() || max == 0 {
            return Vec::new();
        }
        let exclude: HashSet<SocketAddr> = occupied.iter().copied().collect();
        let ranked = self.take_dial_candidates(self.order.len(), &exclude, occupied);
        if ranked.is_empty() {
            return Vec::new();
        }
        let n = ranked.len();
        let mut out = Vec::with_capacity(max.min(n));
        for i in 0..max.min(n) {
            out.push(ranked[(offset + i) % n]);
        }
        out
    }

    /// Snapshot of all entries (for tests / diagnostics).
    pub fn entries(&self) -> Vec<PeerEntry> {
        self.order.iter().filter_map(|a| self.entry_of(a)).collect()
    }

    /// On-disk format magic line (text, one peer per line).
    pub const PEERS_FILE_MAGIC: &'static str = "rbitcoin-peers-v1";
    pub const PEERS_FILE_MAGIC_V2: &'static str = "rbitcoin-peers-v2";
    /// Adds the row's last-seen Unix seconds as the third field.
    pub const PEERS_FILE_MAGIC_V3: &'static str = "rbitcoin-peers-v3";

    /// Load peers + flags from `path`. Missing file → empty book (not an error).
    pub fn load(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let f = std::fs::File::open(path)?;
        let reader = BufReader::new(f);
        let mut am = Self::new();
        let mut saw_magic = false;
        for (lineno, line) in reader.lines().enumerate() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if !saw_magic {
                if line != Self::PEERS_FILE_MAGIC
                    && line != Self::PEERS_FILE_MAGIC_V2
                    && line != Self::PEERS_FILE_MAGIC_V3
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "peers file {}:{}: expected magic `{}`, `{}`, or `{}`",
                            path.display(),
                            lineno + 1,
                            Self::PEERS_FILE_MAGIC,
                            Self::PEERS_FILE_MAGIC_V2,
                            Self::PEERS_FILE_MAGIC_V3
                        ),
                    ));
                }
                saw_magic = true;
                continue;
            }
            let mut parts = line.split_whitespace();
            let Some(addr_s) = parts.next() else {
                continue;
            };
            let flags_s = parts.next().unwrap_or("0");
            let addr: NetAddr = addr_s.parse().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "peers file {}:{}: bad addr: {e}",
                        path.display(),
                        lineno + 1
                    ),
                )
            })?;
            let flags_u: u8 = if let Some(hex) = flags_s
                .strip_prefix("0x")
                .or_else(|| flags_s.strip_prefix("0X"))
            {
                u8::from_str_radix(hex, 16).map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "peers file {}:{}: bad flags: {e}",
                            path.display(),
                            lineno + 1
                        ),
                    )
                })?
            } else {
                flags_s.parse().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "peers file {}:{}: bad flags: {e}",
                            path.display(),
                            lineno + 1
                        ),
                    )
                })?
            };
            if crate::netaddr::netaddr_unroutable_gossip(addr) {
                continue;
            }
            let last_seen: u32 = match parts.next() {
                None => 0,
                Some(s) => s.parse().map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "peers file {}:{}: bad time: {e}",
                            path.display(),
                            lineno + 1
                        ),
                    )
                })?,
            };
            am.remember(addr, PeerFlags(flags_u));
            if last_seen != 0 {
                am.seen.insert(addr, last_seen);
            }
        }
        if !saw_magic && am.is_empty() {
            // Empty or comment-only without magic — treat as empty book.
            return Ok(Self::new());
        }
        am.trim_to_cap(MAX_ADDR_MAN);
        am.sort_order_ipv4_first();
        Ok(am)
    }

    /// Atomic save of peers, flags, and row times to `path` (`path.tmp` then
    /// rename).
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            writeln!(f, "{}", Self::PEERS_FILE_MAGIC_V3)?;
            writeln!(
                f,
                "# addr flags seen  (flags: bit0=connected bit1=fast bit2=slow bit3=incompat bit4=fail)"
            )?;
            for e in self.entries() {
                writeln!(f, "{} 0x{:02x} {}", e.addr, e.flags.0, e.last_seen)?;
            }
            f.durable_sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}
