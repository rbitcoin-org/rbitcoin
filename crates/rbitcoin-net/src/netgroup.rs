//! Outbound / inbound netgroup key, as Core's `NetGroupManager::GetGroup`:
//! asmap ASN, or IPv4 `/16` / IPv6 `/32` (Hurricane Electric `/36`).

use crate::asmap::AsMap;
use crate::netaddr::linked_ipv4;
use crate::NetAddr;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

// Key ranges. Core puts the network class in the first group byte, so no
// two classes share a group. IPv4 `/16` keys are below 2^16.
/// Onion, I2P, CJDNS, and `--proxy` names: BIP155 network id, then bits.
const OVERLAY: u64 = 1 << 32;
/// Asmap ASNs.
const ASN: u64 = 2 << 32;
/// IPv6 `/32`, shifted to leave four bits for the Hurricane Electric `/36`.
const IPV6: u64 = 1 << 40;

/// Stable neighborhood key, as Core's `GetGroup`. With asmap, the ASN (IPv4
/// and IPv6 that map to the same ASN share a key). An address the asmap
/// does not cover (ASN 0), or no asmap, gets its prefix group. An IPv6
/// address that embeds an IPv4 is looked up and grouped as that IPv4.
pub fn netgroup(addr: SocketAddr, asmap: Option<&AsMap>) -> u64 {
    let (lookup, prefix) = prefix_group(addr.ip());
    let asn = lookup.zip(asmap).map_or(0, |(ip, m)| m.mapped_as(ip));
    if asn != 0 {
        // An ASN fits in 32 bits and `ASN` sits at bit 33, so `|` and `^`
        // are the same key. `wrapping_add` drops that `|`.
        ASN.wrapping_add(u64::from(asn))
    } else {
        prefix
    }
}

/// Key for the ten-minute inbound pause after a slot eviction: the
/// eviction group, except for CJDNS. Core uses its sixteen CJDNS groups only
/// to pick an eviction victim and has no pause. Pausing one would refuse a
/// sixteenth of CJDNS, so the pause keys a CJDNS peer on its `/32`.
pub fn slot_pause_group(addr: SocketAddr) -> u64 {
    match addr.ip() {
        IpAddr::V6(v6) if crate::netaddr::is_cjdns_ip(v6) => ipv6_group(v6),
        _ => netgroup(addr, None),
    }
}

/// The address the asmap looks up (`None`: not looked up) and the prefix
/// group. Core keys CJDNS by the four bits after its constant `fc` byte and
/// never looks it up.
fn prefix_group(ip: IpAddr) -> (Option<IpAddr>, u64) {
    let v6 = match ip {
        IpAddr::V4(v4) => return (Some(ip), ipv4_group(v4)),
        IpAddr::V6(v6) => v6,
    };
    if crate::netaddr::is_cjdns_ip(v6) {
        // The overlay bit, the network id, and the nibble do not overlap,
        // so `|` and `^` are the same key. `wrapping_add` drops that `|`.
        let nibble = u64::from(v6.octets()[1] >> 4);
        return (
            None,
            OVERLAY
                .wrapping_add(u64::from(6u8) << 8)
                .wrapping_add(nibble),
        );
    }
    match linked_ipv4(v6) {
        Some(v4) => (Some(IpAddr::V4(v4)), ipv4_group(v4)),
        None => (Some(ip), ipv6_group(v6)),
    }
}

fn ipv4_group(v4: Ipv4Addr) -> u64 {
    let o = v4.octets();
    // The high byte sits above the low byte, so `|` and `^` are the same key.
    (u64::from(o[0]) << 8).wrapping_add(u64::from(o[1]))
}

/// Core: Hurricane Electric `2001:470::/32` by `/36`, the rest by `/32`.
fn ipv6_group(v6: Ipv6Addr) -> u64 {
    let o = v6.octets();
    let slash32 = u32::from_be_bytes([o[0], o[1], o[2], o[3]]);
    let he_net = o[..4] == [32, 1, 4, 112];
    let nibble = if he_net { o[4] >> 4 } else { 0 };
    // `IPV6` sits at bit 40, above the `/32` and the Hurricane Electric nibble.
    IPV6.wrapping_add(u64::from(slash32) << 4)
        .wrapping_add(u64::from(nibble))
}

/// Group key for the one-automatic-outbound-per-group rule, or `None` where
/// the rule does not apply. Core (`ThreadOpenConnections`) leaves CJDNS out,
/// as it does Tor and I2P: their groups are random key bits, not routes.
/// Core never stores a local or unroutable address in addrman, so it never
/// dials one automatically. Here such rows come only from the operator
/// (`addpeeraddress`, `--connect`), so they stay exempt too, and a local test
/// network can still open many outbound peers on `127.0.0.1`.
pub fn outbound_group(addr: SocketAddr, asmap: Option<&AsMap>) -> Option<u64> {
    let ip = addr.ip();
    let cjdns = matches!(ip, IpAddr::V6(v) if crate::netaddr::is_cjdns_ip(v));
    if cjdns || crate::netaddr::clearnet_unroutable(ip) {
        return None;
    }
    Some(netgroup(addr, asmap))
}

/// [`netgroup`] for any session net. An onion or I2P session's `addr` is the
/// `0.0.0.0` placeholder, so these key by network and the first four address
/// bits, as Core's `GetGroup` does, in the overlay range.
pub fn netgroup_net(addr: NetAddr, asmap: Option<&AsMap>) -> u64 {
    match addr {
        NetAddr::Ip(sock) => netgroup(sock, asmap),
        NetAddr::Cjdns { ip, port } => netgroup(SocketAddr::from((ip, port)), asmap),
        // BIP155 network ids: 4 is TorV3, 5 is I2P. The overlay bit, the
        // network id, and the nibble do not overlap, so `|` and `^` are the
        // same key. `wrapping_add` drops that `|`.
        NetAddr::Onion { pk, .. } => OVERLAY
            .wrapping_add(u64::from(4u8) << 8)
            .wrapping_add(u64::from(pk[0] >> 4)),
        NetAddr::I2p { dest, .. } => OVERLAY
            .wrapping_add(u64::from(5u8) << 8)
            .wrapping_add(u64::from(dest[0] >> 4)),
        // A `--proxy` hostname has no address bits to split on.
        NetAddr::Name { .. } => OVERLAY.wrapping_add(u64::from(u8::MAX) << 8),
    }
}

/// Walk `ranked` and take at most one addr per group, as Core does for
/// automatic outbound: an addr whose group is in `occupied_groups` (a live
/// outbound peer's) or already picked is skipped, even when that leaves
/// slots empty. An addr whose group is `None` is exempt
/// ([`outbound_group`]).
pub fn select_diverse(
    ranked: &[SocketAddr],
    max: usize,
    occupied_groups: &HashSet<u64>,
    mut group_of: impl FnMut(SocketAddr) -> Option<u64>,
) -> Vec<SocketAddr> {
    let mut picked = Vec::new();
    let mut used = occupied_groups.clone();
    for &addr in ranked {
        if picked.len() >= max {
            break;
        }
        if let Some(g) = group_of(addr) {
            if !used.insert(g) {
                continue;
            }
        }
        picked.push(addr);
    }
    picked
}
