use rbitcoin_net::netaddr::{NetAddr, OnlyNet};
use rbitcoin_net::netgroup::netgroup;
use rbitcoin_net::seeds::*;
use rbitcoin_primitives::Network;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// One /16 per `o`, so ranking tests are not cut by the one-per-group rule.
fn addr(o: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, o, 3, 4)), 8333)
}

#[test]
fn inject_drops_unroutable_and_add_learned_keeps_it() {
    use std::net::Ipv6Addr;
    let mut book = AddrMan::new();
    let public = addr(4);
    book.inject([
        "10.0.0.1:8333".parse().unwrap(),
        "127.0.0.1:8333".parse().unwrap(),
        "192.0.2.1:8333".parse().unwrap(),
        "0.0.0.0:8333".parse().unwrap(),
        "100.64.0.1:8333".parse().unwrap(),
        "198.18.0.1:8333".parse().unwrap(),
        "240.0.0.1:8333".parse().unwrap(),
        "[2001:db8::1]:8333".parse().unwrap(),
        "[2001:10::1]:8333".parse().unwrap(),
        "[2001:20::1]:8333".parse().unwrap(),
        "[100::1]:8333".parse().unwrap(),
        "0.1.2.3:8333".parse().unwrap(),
        "[2002:0a00:1::]:8333".parse().unwrap(),
        "[2002:0102:0304::1]:8333".parse().unwrap(),
        "[64:ff9b::a00:1]:8333".parse().unwrap(),
        "[::a00:1]:8333".parse().unwrap(),
        "[::ffff:0:a00:1]:8333".parse().unwrap(),
        "[::ffff:a00:1]:8333".parse().unwrap(),
        "[64:ff9b:1::a00:1]:8333".parse().unwrap(),
        "[64:ff9b:1:1::102:304]:8333".parse().unwrap(),
        "[2001:0:102:304::f5ff:fffe]:8333".parse().unwrap(),
        "[3fff::1]:8333".parse().unwrap(),
        "[2001:2::1]:8333".parse().unwrap(),
        "[2001:2:0:ffff:ffff:ffff:ffff:ffff]:8333".parse().unwrap(),
        public,
    ]);
    assert_eq!(book.len(), 1);
    assert!(book
        .entry_of(&rbitcoin_net::NetAddr::from_socket(public))
        .is_some());
    let sixto4_public: SocketAddr = "[2002:0102:0304::]:8333".parse().unwrap();
    let nat64_public: SocketAddr = "[64:ff9b::102:304]:8333".parse().unwrap();
    let compatible_public: SocketAddr = "[::102:304]:8333".parse().unwrap();
    let siit_public: SocketAddr = "[::ffff:0:102:304]:8333".parse().unwrap();
    let nat64_local_public: SocketAddr = "[64:ff9b:1::102:304]:8333".parse().unwrap();
    let mapped_public: SocketAddr = "[::ffff:102:304]:8333".parse().unwrap();
    let bench_outside: SocketAddr = "[2001:2:1::1]:8333".parse().unwrap();
    book.inject([
        sixto4_public,
        nat64_public,
        compatible_public,
        siit_public,
        nat64_local_public,
        mapped_public,
        bench_outside,
    ]);
    assert!(
        book.entry_of(&rbitcoin_net::NetAddr::from_socket(sixto4_public))
            .is_some(),
        "6to4 of a public IPv4 stays when the suffix is zero"
    );
    assert!(
        book.entry_of(&rbitcoin_net::NetAddr::from_socket(nat64_public))
            .is_some(),
        "NAT64 of a public IPv4 stays"
    );
    assert!(book
        .entry_of(&rbitcoin_net::NetAddr::from_socket(compatible_public))
        .is_some());
    assert!(book
        .entry_of(&rbitcoin_net::NetAddr::from_socket(siit_public))
        .is_some());
    assert!(book
        .entry_of(&rbitcoin_net::NetAddr::from_socket(nat64_local_public))
        .is_some());
    assert!(book
        .entry_of(&rbitcoin_net::NetAddr::from_socket(mapped_public))
        .is_some());
    assert!(
        book.entry_of(&rbitcoin_net::NetAddr::from_socket(bench_outside))
            .is_some(),
        "2001:2:1::/48 is outside the benchmarking prefix"
    );
    let lan: SocketAddr = "10.0.0.1:8333".parse().unwrap();
    assert!(book.add_learned(lan, lan, 64));
    assert!(book
        .entry_of(&rbitcoin_net::NetAddr::from_socket(lan))
        .is_some());
    let cjdns: SocketAddr =
        SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)), 8333);
    book.set_cjdns_reachable(true);
    book.inject([cjdns]);
    assert!(
        book.entries()
            .iter()
            .any(|e| matches!(e.addr, NetAddr::Cjdns { .. })),
        "fc00::/8 is CJDNS, not a unique-local bogon"
    );
}

fn addr_n(i: u32) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(
            11,
            ((i >> 16) & 0xff) as u8,
            ((i >> 8) & 0xff) as u8,
            (i & 0xff) as u8,
        )),
        8333,
    )
}

#[test]
fn dial_tier_preferred_vs_last_resort() {
    assert_eq!(PeerFlags::empty().dial_tier(), 0); // untried
    let mut f = PeerFlags::empty();
    f.insert(PeerFlags::HAS_CONNECTED);
    assert_eq!(f.dial_tier(), 0);
    f.insert(PeerFlags::FAST);
    assert_eq!(f.dial_tier(), 0);

    let mut slow = PeerFlags::empty();
    slow.insert(PeerFlags::HAS_CONNECTED);
    slow.insert(PeerFlags::SLOW);
    assert_eq!(slow.dial_tier(), 1);

    let mut bad = PeerFlags::empty();
    bad.insert(PeerFlags::FAILED_LAST_CONNECT);
    assert_eq!(bad.dial_tier(), 2);
    let mut inc = PeerFlags::empty();
    inc.insert(PeerFlags::INCOMPATIBLE);
    assert_eq!(inc.dial_tier(), 2);
}

#[test]
fn speed_sample_sets_fast_or_slow() {
    let mut f = PeerFlags::empty();
    f.apply_speed_sample(50, PeerFlags::FAST_BPS_MIN + 1);
    assert!(f.is_fast());
    assert!(!f.is_slow());
    f.apply_speed_sample(300, 1000);
    assert!(f.is_slow());
    assert!(!f.is_fast());
}

#[test]
fn take_dial_prefers_untried_and_good_over_failed() {
    let mut am = AddrMan::new();
    let good = addr(1);
    let untried = addr(2);
    let failed = addr(3);
    let incompat = addr(4);
    am.add(failed);
    am.add(incompat);
    am.add(good);
    am.add(untried);
    am.note_connected_addr(rbitcoin_net::NetAddr::from_socket(good));
    am.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(failed), false);
    am.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(incompat), true);

    let got = am.take_dial_candidates(4, &HashSet::new(), &[]);
    assert_eq!(got.len(), 3);
    assert!(!got.contains(&incompat));
    let tiers: Vec<u8> = got.iter().map(|a| am.flags(a).dial_tier()).collect();
    assert_eq!(tiers[0], 0);
    assert_eq!(tiers[1], 0);
    assert_eq!(tiers[2], 2);
    assert!(am.flags(&got[2]).failed_last_connect());
}

#[test]
fn take_dial_incompatible_when_nothing_else() {
    let mut am = AddrMan::new();
    let a = addr(1);
    let b = addr(2);
    am.add(a);
    am.add(b);
    am.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(a), true);
    am.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(b), true);
    let got = am.take_dial_candidates(48, &HashSet::new(), &[]);
    assert_eq!(got.len(), 2);
    assert!(got.contains(&a));
    assert!(got.contains(&b));
}

#[test]
fn exclude_skips_blocked() {
    let mut am = AddrMan::new();
    am.add(addr(1));
    am.add(addr(2));
    let mut ex = HashSet::new();
    ex.insert(addr(1));
    let got = am.take_dial_candidates(10, &ex, &[]);
    assert_eq!(got, vec![addr(2)]);
}

fn slash16(a: u8, b: u8, host: u8) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(a, b, 0, host)), 8333)
}

/// Core never opens two automatic outbound connections into one /16. A
/// book whose rows sit in two /16s yields two picks for sixteen slots, not
/// sixteen (eclipse F2: 16 of 16 outbound in an attacker's two /16s).
#[test]
fn take_dial_two_slash16s_yield_two_picks() {
    let mut am = AddrMan::new();
    for i in 1..=8 {
        am.add(slash16(44, 1, i));
        am.add(slash16(44, 2, i));
    }
    let got = am.take_dial_candidates(16, &HashSet::new(), &[]);
    assert_eq!(got, vec![slash16(44, 1, 1), slash16(44, 2, 1)]);
}

/// A /16 that already has a live outbound peer yields no pick.
#[test]
fn take_dial_occupied_slash16_yields_none() {
    let mut am = AddrMan::new();
    for i in 1..=8 {
        am.add(slash16(44, 1, i));
    }
    let occupied = [slash16(44, 1, 99)];
    assert!(am
        .take_dial_candidates(8, &HashSet::new(), &occupied)
        .is_empty());
}

/// Loopback and other unroutable rows only reach the book from the operator
/// (`addpeeraddress`, `--connect`); Core never dials them automatically.
/// They take no group, so a local test network still fills.
#[test]
fn take_dial_loopback_rows_take_no_group() {
    let mut am = AddrMan::new();
    for port in 1..=8 {
        am.add(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port));
    }
    let occupied = [SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 99)];
    assert_eq!(
        am.take_dial_candidates(8, &HashSet::new(), &occupied).len(),
        8
    );
}

#[test]
fn take_dial_mixed_groups_picks_distinct() {
    let mut am = AddrMan::new();
    for g in 1u8..=32 {
        am.add(slash16(g, 0, 1));
    }
    let got = am.take_dial_candidates(16, &HashSet::new(), &[]);
    assert_eq!(got.len(), 16);
    let groups: HashSet<u64> = got.iter().map(|a| netgroup(*a, None)).collect();
    assert_eq!(groups.len(), 16);
}

#[test]
fn take_dial_skips_occupied_group() {
    let mut am = AddrMan::new();
    am.add(slash16(1, 2, 1));
    am.add(slash16(1, 3, 1));
    let occupied = [slash16(1, 2, 9)];
    let got = am.take_dial_candidates(1, &HashSet::new(), &occupied);
    assert_eq!(got, vec![slash16(1, 3, 1)]);
}

/// The group rule is not a preference: a better-tier addr in an occupied
/// group is skipped, and a last-resort addr in a free group is taken.
#[test]
fn take_dial_occupied_group_tier0_loses_to_free_group_last_resort() {
    let mut am = AddrMan::new();
    let good_same = slash16(1, 2, 1);
    let lemon = slash16(9, 9, 1);
    am.add(good_same);
    am.add(lemon);
    am.note_connected_addr(rbitcoin_net::NetAddr::from_socket(good_same));
    am.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(lemon), false);
    let occupied = [slash16(1, 2, 9)];
    let got = am.take_dial_candidates(2, &HashSet::new(), &occupied);
    assert_eq!(got, vec![lemon]);
}

/// The recent-attempt fallback looks only at rows the group rule would
/// dial. A fresh row in an occupied /16 must not hide a recently attempted
/// row in a free /16 for the ten-minute window.
#[test]
fn take_dial_recent_free_group_beats_fresh_occupied_group() {
    let mut am = AddrMan::new();
    let blocked = slash16(45, 1, 2);
    let free = slash16(45, 2, 1);
    am.add(blocked);
    am.add(free);
    am.note_attempt_at(free, Instant::now());
    let occupied = [slash16(45, 1, 1)];
    assert_eq!(
        am.take_dial_candidates(1, &HashSet::new(), &occupied),
        vec![free]
    );
}

/// When every row the rule would dial was attempted inside the recent
/// window, a call returns one row, the least recently attempted, so a
/// refill pass does not redial every dead address. Once that attempt is
/// noted, the next call moves on. A fresh row brings back the full batch.
#[test]
fn take_dial_all_recent_returns_least_recent_one() {
    let mut am = AddrMan::new();
    let (a, b, c) = (slash16(45, 1, 1), slash16(45, 2, 1), slash16(45, 3, 1));
    am.inject([a, b, c]);
    let now = Instant::now();
    let ago = |s| now.checked_sub(Duration::from_secs(s)).expect("clock");
    am.note_attempt_at(a, ago(3));
    am.note_attempt_at(b, ago(5));
    am.note_attempt_at(c, ago(1));
    assert_eq!(am.take_dial_candidates(3, &HashSet::new(), &[]), vec![b]);
    am.note_attempt_at(b, now);
    assert_eq!(am.take_dial_candidates(3, &HashSet::new(), &[]), vec![a]);
    let (d, e) = (slash16(45, 4, 1), slash16(45, 5, 1));
    am.inject([d, e]);
    assert_eq!(am.take_dial_candidates(3, &HashSet::new(), &[]), vec![d, e]);
}

/// When the IP pick is the paced redial, onion and I2P rows do not take the
/// slots the other IP rows are due on later passes: the pass adds one
/// overlay row at most. With a fresh IP row the batch fills as before.
#[test]
fn take_dial_net_paced_ip_adds_one_overlay_row() {
    let mut am = AddrMan::new();
    am.set_onion_reachable(true);
    let (a, b) = (slash16(45, 1, 1), slash16(45, 2, 1));
    am.inject([a, b]);
    let now = Instant::now();
    let ago = |s| now.checked_sub(Duration::from_secs(s)).expect("clock");
    am.note_attempt_at(a, ago(3));
    am.note_attempt_at(b, ago(5));
    for i in 1..=4u8 {
        am.add_addr(NetAddr::Onion {
            pk: [i; 32],
            port: 8333,
        });
    }
    let got = am.take_dial_candidates_net(8, &HashSet::new(), &[], false);
    assert_eq!(got.len(), 2, "{got:?}");
    assert_eq!(got[0], NetAddr::from_socket(b));
    assert!(got[1].is_overlay());

    am.inject([slash16(45, 3, 1)]);
    let got = am.take_dial_candidates_net(8, &HashSet::new(), &[], false);
    assert_eq!(got.len(), 5, "a fresh IP row and every onion row: {got:?}");
}

/// The same holds for the known-v1 fallback: a compatible row in an
/// occupied /16 must not hide an incompatible row in a free /16.
#[test]
fn take_dial_incompatible_free_group_beats_compatible_occupied_group() {
    let mut am = AddrMan::new();
    let blocked = slash16(45, 1, 2);
    let v1 = slash16(45, 2, 1);
    am.add(blocked);
    am.add(v1);
    am.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(v1), true);
    let occupied = [slash16(45, 1, 1)];
    assert_eq!(
        am.take_dial_candidates(1, &HashSet::new(), &occupied),
        vec![v1]
    );
}

/// Core's `GetGroup` puts an IPv6 address that embeds an IPv4 (6to4 here)
/// in that IPv4's /16, so the pair yields one pick.
#[test]
fn take_dial_6to4_shares_its_ipv4_slash16() {
    let mut am = AddrMan::new();
    let v4: SocketAddr = "45.1.0.1:8333".parse().unwrap();
    let six_to_four: SocketAddr = "[2002:2d01:2::]:8333".parse().unwrap();
    am.inject([v4, six_to_four]);
    assert_eq!(am.len(), 2);
    assert_eq!(am.take_dial_candidates(2, &HashSet::new(), &[]), vec![v4]);
}

/// Core groups Hurricane Electric `2001:470::/32` by /36, so two /36s in
/// that /32 are two groups.
#[test]
fn take_dial_henet_groups_by_slash36() {
    let mut am = AddrMan::new();
    let a: SocketAddr = "[2001:470:1000::1]:8333".parse().unwrap();
    let b: SocketAddr = "[2001:470:2000::1]:8333".parse().unwrap();
    am.inject([a, b]);
    assert_eq!(am.take_dial_candidates(2, &HashSet::new(), &[]), vec![a, b]);
}

#[test]
fn take_dial_skips_recent_attempt_while_others_remain() {
    let mut am = AddrMan::new();
    am.add(addr(1));
    am.add(addr(2));
    am.note_attempt_addr(rbitcoin_net::NetAddr::from_socket(addr(1)));
    let got = am.take_dial_candidates(2, &HashSet::new(), &[]);
    assert_eq!(got, vec![addr(2)]);

    let mut only = AddrMan::new();
    only.add(addr(1));
    only.note_attempt_addr(rbitcoin_net::NetAddr::from_socket(addr(1)));
    assert_eq!(
        only.take_dial_candidates(1, &HashSet::new(), &[]),
        vec![addr(1)],
        "sole remaining addr is still dialed even if recently attempted"
    );

    let mut aged = AddrMan::new();
    aged.add(addr(1));
    aged.add(addr(2));
    let old = Instant::now()
        .checked_sub(DIAL_ATTEMPT_RECENT + Duration::from_secs(1))
        .expect("clock");
    aged.note_attempt_at(addr(1), old);
    let got = aged.take_dial_candidates(2, &HashSet::new(), &[]);
    assert_eq!(got.len(), 2);
    assert!(got.contains(&addr(1)));
    assert!(got.contains(&addr(2)));

    let now = Instant::now();
    let mut edge = AddrMan::new();
    edge.add(addr(1));
    edge.note_attempt_at(
        addr(1),
        now.checked_sub(DIAL_ATTEMPT_RECENT).expect("clock"),
    );
    assert!(
        !edge.recently_attempted(addr(1), now),
        "an attempt exactly ten minutes old is not recent"
    );
    edge.note_attempt_at(
        addr(1),
        now.checked_sub(DIAL_ATTEMPT_RECENT)
            .expect("clock")
            .checked_add(Duration::from_secs(1))
            .expect("clock"),
    );
    assert!(edge.recently_attempted(addr(1), now));
}

#[test]
fn add_learned_evicts_failed_when_at_cap() {
    let mut am = AddrMan::new();
    for i in 1..=3 {
        am.add(addr(i));
        am.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(addr(i)), i == 1);
    }
    assert!(am.add_learned(addr(9), addr(9), 3));
    assert_eq!(am.len(), 3);
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr(9)))
        .is_some());
    assert!(
        am.entry_of(&rbitcoin_net::NetAddr::from_socket(addr(1)))
            .is_none(),
        "incompatible is evicted before failed-last-connect"
    );
}

#[test]
fn add_learned_keeps_good_when_full() {
    let mut am = AddrMan::new();
    for i in 1..=3 {
        am.add(addr(i));
        am.note_connected_addr(rbitcoin_net::NetAddr::from_socket(addr(i)));
    }
    assert!(!am.add_learned(addr(9), addr(9), 3));
    assert_eq!(am.len(), 3);
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr(9)))
        .is_none());
    assert!(!am.add_learned(addr(1), addr(1), 3));
}

#[test]
fn add_learned_evicts_oldest_new_when_at_cap() {
    let mut am = AddrMan::new();
    for i in 1..=3 {
        am.add(addr(i));
    }
    assert!(am.add_learned(addr(9), addr(9), 3));
    assert_eq!(am.len(), 3);
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr(9)))
        .is_some());
    assert!(
        am.entry_of(&rbitcoin_net::NetAddr::from_socket(addr(1)))
            .is_none(),
        "oldest new is evicted after incompat/failed"
    );
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr(2)))
        .is_some());
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr(3)))
        .is_some());
}

#[test]
fn add_learned_fills_past_getaddr_cache_pct() {
    const NEED: usize =
        rbitcoin_net::peer::MAX_ADDR_TO_SEND * 100 / rbitcoin_net::peer::MAX_PCT_ADDR_TO_SEND;
    let mut am = AddrMan::new();
    for i in 0..=NEED {
        assert!(
            am.add_learned(addr_n(i as u32), addr_n(i as u32), MAX_ADDR_MAN),
            "MAX_ADDR_MAN={} rejected insert {i} (need len > {NEED})",
            MAX_ADDR_MAN
        );
    }
    assert!(am.len() > NEED, "len={} need > {NEED}", am.len());
}

/// Attacker address `i`, spread over two /16s (44.1 and 44.2), never in
/// [`addr_n`]'s 11/8.
fn attacker_addr(i: u32) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(
            44,
            1 + (i & 1) as u8,
            ((i >> 9) & 0xff) as u8,
            ((i >> 1) & 0xff) as u8,
        )),
        8333,
    )
}

/// Book size for the flood tests: four shares, so the eviction scans stay
/// cheap in a debug build. The share is the same at [`MAX_ADDR_MAN`].
const BOOK: usize = 4 * MAX_ROWS_PER_SOURCE_GROUP;

/// A full book of honest rows, each taught by itself as `addpeeraddress` does.
fn full_honest_book() -> AddrMan {
    let mut am = AddrMan::new();
    for i in 0..BOOK as u32 {
        assert!(am.add_learned(addr_n(i), addr_n(i), BOOK));
    }
    am
}

fn honest_rows(am: &AddrMan) -> usize {
    am.entries()
        .iter()
        .filter(|e| matches!(e.addr, NetAddr::Ip(s) if s.ip().to_string().starts_with("11.")))
        .count()
}

/// Four books' worth of addresses, from `first` on, taught by `source(i)`.
fn flood(am: &mut AddrMan, first: u32, source: impl Fn(u32) -> SocketAddr) -> usize {
    (first..first + 4 * BOOK as u32)
        .filter(|&i| am.add_learned(attacker_addr(i), source(i), BOOK))
        .count()
}

#[test]
fn one_source_group_replaces_at_most_its_share_of_a_full_book() {
    let mut am = full_honest_book();
    let one_ip = SocketAddr::from(([44, 1, 0, 1], 8333));
    assert_eq!(flood(&mut am, 0, |_| one_ip), MAX_ROWS_PER_SOURCE_GROUP);
    assert_eq!(am.len(), BOOK);
    assert_eq!(honest_rows(&am), BOOK - MAX_ROWS_PER_SOURCE_GROUP);

    // The bound is per group: a second /16 takes its own share, no more.
    let other_group = SocketAddr::from(([45, 9, 0, 1], 8333));
    let more = flood(&mut am, 4 * BOOK as u32, |_| other_group);
    assert_eq!(more, MAX_ROWS_PER_SOURCE_GROUP);
    assert_eq!(honest_rows(&am), BOOK - 2 * MAX_ROWS_PER_SOURCE_GROUP);
}

#[test]
fn many_sources_in_one_group_share_one_bound() {
    let mut am = full_honest_book();
    // Every address from a different IP, all inside 44.1/16.
    let taught = flood(&mut am, 0, |i| {
        SocketAddr::from(([44, 1, (i >> 8) as u8, i as u8], 8333))
    });
    assert_eq!(taught, MAX_ROWS_PER_SOURCE_GROUP);
    assert_eq!(honest_rows(&am), BOOK - MAX_ROWS_PER_SOURCE_GROUP);
}

/// A source given as `::ffff:a.b.c.d` (IPv4-mapped IPv6) is charged to the
/// /16 of `a.b`: two such sources in different /16s do not share one group,
/// and a mapped source shares its group with the same /16 seen natively.
#[test]
fn a_mapped_ipv4_source_is_charged_to_its_slash16() {
    let mapped = |a: u8, b: u8| {
        SocketAddr::from((std::net::Ipv4Addr::new(a, b, 0, 1).to_ipv6_mapped(), 8333))
    };
    let mut am = full_honest_book();
    assert_eq!(
        flood(&mut am, 0, |_| mapped(44, 1)),
        MAX_ROWS_PER_SOURCE_GROUP
    );
    assert!(
        am.add_learned(attacker_addr(9 * BOOK as u32), mapped(45, 9), BOOK),
        "a mapped peer in another /16 has its own share"
    );
    let native = SocketAddr::from(([44, 1, 0, 2], 8333));
    assert!(
        !am.add_learned(attacker_addr(9 * BOOK as u32 + 1), native, BOOK),
        "the same /16 seen natively is at its share"
    );
}

#[test]
fn one_peer_fills_an_empty_book() {
    // A seed or addr-fetch reply, and a fresh node's first peers, may fill
    // the whole book from one source: nothing is displaced until it is full.
    let mut am = AddrMan::new();
    let seed = SocketAddr::from(([44, 1, 0, 1], 8333));
    let taught = (0..MAX_ADDR_MAN as u32)
        .filter(|&i| am.add_learned(addr_n(i), seed, MAX_ADDR_MAN))
        .count();
    assert_eq!(taught, MAX_ADDR_MAN);
    assert!(!am.add_learned(attacker_addr(0), seed, MAX_ADDR_MAN));
    let other = SocketAddr::from(([45, 9, 0, 1], 8333));
    assert!(
        am.add_learned(attacker_addr(0), other, MAX_ADDR_MAN),
        "another group still replaces the oldest untried row"
    );
}

#[test]
fn a_source_teaches_again_once_its_rows_leave() {
    // A small cap so the share is crossed in a few hundred rows.
    let cap = MAX_ROWS_PER_SOURCE_GROUP + 88;
    let mut am = AddrMan::new();
    let seed = SocketAddr::from(([44, 1, 0, 1], 8333));
    for i in 0..cap as u32 {
        assert!(am.add_learned(addr_n(i), seed, cap));
    }
    let next = |i: u32| addr_n(cap as u32 + i);
    assert!(!am.add_learned(next(0), seed, cap));

    // Another group evicts the seed's oldest rows, one per insert.
    let other = SocketAddr::from(([45, 9, 0, 1], 8333));
    for i in 0..88 {
        assert!(am.add_learned(attacker_addr(i), other, cap));
    }
    assert!(!am.add_learned(next(0), seed, cap), "still at its share");
    assert!(am.add_learned(attacker_addr(88), other, cap));
    assert!(
        am.add_learned(next(0), seed, cap),
        "one row under its share"
    );

    // A trim (shutdown merge, `peers` load) drops the seed's rows too.
    let mut trimmed = AddrMan::new();
    for i in 0..cap as u32 {
        assert!(trimmed.add_learned(addr_n(i), seed, cap));
    }
    let share = MAX_ROWS_PER_SOURCE_GROUP;
    trimmed.trim_to_cap(share);
    assert!(!trimmed.add_learned(next(0), seed, share), "kept its share");
    trimmed.trim_to_cap(share - 1);
    assert!(trimmed.add_learned(next(0), seed, share - 1));
}

#[test]
fn a_source_group_leaves_with_its_last_row() {
    // The source tallies' bound: an evicted row takes its source with it, and
    // a group with no row left is dropped.
    let mut am = AddrMan::new();
    let seed = SocketAddr::from(([44, 1, 0, 1], 8333));
    let other = SocketAddr::from(([45, 9, 0, 1], 8333));
    for i in 0..4 {
        assert!(am.add_learned(addr_n(i), seed, 4));
    }
    assert_eq!(am.source_tally(), (4, 1));
    for i in 0..4 {
        assert!(am.add_learned(attacker_addr(i), other, 4));
    }
    assert_eq!(
        am.source_tally(),
        (4, 1),
        "the seed's last row took its group"
    );
}

#[test]
fn add_keeps_tried_and_may_exceed_cap() {
    let mut am = AddrMan::new();
    for i in 0..MAX_ADDR_MAN {
        let a = addr_n(i as u32);
        am.add(a);
        am.note_connected_addr(rbitcoin_net::NetAddr::from_socket(a));
    }
    let extra = addr_n(MAX_ADDR_MAN as u32);
    am.add(extra);
    assert_eq!(am.len(), MAX_ADDR_MAN + 1);
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(extra))
        .is_some());
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr_n(0)))
        .is_some());
    assert!(!am.add_learned(
        addr_n(MAX_ADDR_MAN as u32 + 1),
        addr_n(MAX_ADDR_MAN as u32 + 1),
        MAX_ADDR_MAN
    ));
    assert_eq!(am.len(), MAX_ADDR_MAN + 1);
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(extra))
        .is_some());
}

#[test]
fn add_evicts_oldest_new_at_cap() {
    let mut am = AddrMan::new();
    for i in 0..MAX_ADDR_MAN {
        am.add(addr_n(i as u32));
    }
    let extra = addr_n(MAX_ADDR_MAN as u32);
    am.add(extra);
    assert_eq!(am.len(), MAX_ADDR_MAN);
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(extra))
        .is_some());
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr_n(0)))
        .is_none());
    assert!(am
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr_n(1)))
        .is_some());
}

/// A merged row keeps the source group that taught it. A row both books
/// hold keeps this book's source, and a row this book cannot dial is left
/// out with its source.
#[test]
fn merge_from_keeps_each_rows_source() {
    let mut a = AddrMan::new();
    let mut b = AddrMan::new();
    b.set_onion_reachable(true);
    let src = |o: u8| SocketAddr::from(([44, o, 0, 1], 8333));
    assert!(a.add_learned(addr_n(0), src(1), MAX_ADDR_MAN));
    assert!(b.add_learned(addr_n(0), src(2), MAX_ADDR_MAN));
    assert!(b.add_learned(addr_n(1), src(3), MAX_ADDR_MAN));
    let src4 = NetAddr::from_socket(src(4));
    assert!(b.add_learned_addr(onion(), src4, MAX_ADDR_MAN));
    b.add(addr_n(2));
    let (both, only_b) = (
        NetAddr::from_socket(addr_n(0)),
        NetAddr::from_socket(addr_n(1)),
    );
    let (own, others) = (a.source_group_of(both), b.source_group_of(both));
    assert!(own.is_some() && own != others);
    a.merge_from(&b);
    assert_eq!(a.len(), 3);
    assert_eq!(a.source_tally(), (2, 2));
    assert_eq!(
        a.source_group_of(both),
        own,
        "a shared row keeps this book's source"
    );
    assert_eq!(a.source_group_of(only_b), b.source_group_of(only_b));
}

/// The share binds only in a full book, for a copy as for a learned
/// address: a book with room takes another row from a group already at its
/// share.
#[test]
fn merge_into_a_book_with_room_is_not_bound_by_the_share() {
    let src = SocketAddr::from(([44, 1, 0, 1], 8333));
    let mut a = AddrMan::new();
    for i in 0..MAX_ROWS_PER_SOURCE_GROUP as u32 {
        assert!(a.add_learned(addr_n(i), src, MAX_ADDR_MAN));
    }
    let mut b = AddrMan::new();
    assert!(b.add_learned(addr_n(MAX_ADDR_MAN as u32), src, MAX_ADDR_MAN));
    a.merge_from(&b);
    assert_eq!(a.source_tally(), (MAX_ROWS_PER_SOURCE_GROUP + 1, 1));
}

/// The shutdown merge runs into the book as it stood at catch-up, which
/// still charges a group for rows the live book has since evicted. A row
/// the live book connected to is kept whatever its teacher's share: a
/// restart keeps connected rows first.
#[test]
fn merge_keeps_a_connected_row_from_a_group_at_its_share() {
    let src = SocketAddr::from(([44, 1, 0, 1], 8333));
    let mut stale = AddrMan::new();
    for i in 0..MAX_ADDR_MAN as u32 {
        if (i as usize) < MAX_ROWS_PER_SOURCE_GROUP {
            assert!(stale.add_learned(addr_n(i), src, MAX_ADDR_MAN));
        } else {
            stale.add(addr_n(i));
        }
    }
    let mut live = stale.clone();
    let other = SocketAddr::from(([45, 1, 0, 1], 8333));
    assert!(live.add_learned(addr_n(100_000), other, MAX_ADDR_MAN));
    let connected = NetAddr::from_socket(addr_n(100_001));
    assert!(live.add_learned_addr(connected, NetAddr::from_socket(src), MAX_ADDR_MAN));
    live.note_connected_addr(connected);
    stale.merge_from(&live);
    assert!(stale.flags_of(&connected).has_connected());
    assert_eq!(stale.len(), MAX_ADDR_MAN);
}

#[test]
fn merge_from_trims_to_cap_keeping_tried() {
    let mut a = AddrMan::new();
    for i in 0..MAX_ADDR_MAN {
        let x = addr_n(i as u32);
        a.add(x);
        a.note_connected_addr(rbitcoin_net::NetAddr::from_socket(x));
    }
    let mut b = AddrMan::new();
    for i in 0..8 {
        b.add(addr_n(MAX_ADDR_MAN as u32 + i));
    }
    a.merge_from(&b);
    assert_eq!(a.len(), MAX_ADDR_MAN);
    assert!(
        a.entry_of(&rbitcoin_net::NetAddr::from_socket(addr_n(0)))
            .is_some(),
        "tried addrs must survive merge trim"
    );
    assert!(
        a.entry_of(&rbitcoin_net::NetAddr::from_socket(addr_n(
            MAX_ADDR_MAN as u32
        )))
        .is_none(),
        "extra new from the other book must not grow past cap"
    );
}

#[test]
fn load_trims_tried_then_new_to_cap() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-peers-cap-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("peers");
    let mut body = String::from("rbitcoin-peers-v1\n");
    let n_tried = 2000u32;
    let n_total = MAX_ADDR_MAN as u32 + 904;
    for i in 0..n_tried {
        body.push_str(&format!("{} 0x01\n", addr_n(i)));
    }
    for i in n_tried..n_total {
        body.push_str(&format!("{} 0x00\n", addr_n(i)));
    }
    std::fs::write(&path, body).unwrap();
    let loaded = AddrMan::load(&path).unwrap();
    assert_eq!(loaded.len(), MAX_ADDR_MAN);
    for i in 0..n_tried {
        assert!(
            loaded
                .entry_of(&rbitcoin_net::NetAddr::from_socket(addr_n(i)))
                .is_some(),
            "tried {i} must survive trim"
        );
        assert!(loaded.flags(&addr_n(i)).has_connected());
    }
    let n_new_kept = MAX_ADDR_MAN - n_tried as usize;
    assert!(loaded
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr_n(n_tried)))
        .is_some());
    assert!(loaded
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr_n(
            n_tried + n_new_kept as u32 - 1
        )))
        .is_some());
    assert!(loaded
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr_n(n_total - 1)))
        .is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn peers_file_roundtrip_preserves_flags() {
    let dir = std::env::temp_dir().join(format!("rbitcoin-peers-test-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("peers");
    let mut am = AddrMan::new();
    let a = addr(10);
    let b = addr(20);
    am.add(a);
    am.note_connected_addr(rbitcoin_net::NetAddr::from_socket(a));
    am.note_speed_addr(
        rbitcoin_net::NetAddr::from_socket(a),
        40,
        PeerFlags::FAST_BPS_MIN + 100,
    );
    am.add(b);
    am.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(b), true);
    am.save(&path).unwrap();

    let loaded = AddrMan::load(&path).unwrap();
    assert_eq!(loaded.len(), 2);
    assert!(loaded.flags(&a).has_connected());
    assert!(loaded.flags(&a).is_fast());
    assert!(loaded.flags(&b).is_incompatible());

    // merge does not wipe flags when re-adding seed
    let mut merged = loaded;
    merged.add(a);
    assert!(merged.flags(&a).is_fast());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seed_lookup_names_x_filter_before_unfiltered() {
    let names = seed_lookup_names(Network::Mainnet);
    assert_eq!(names[0][0], "x809.dnsseed.bluematt.me.");
    assert_eq!(names[0][1], "dnsseed.bluematt.me.");
    for net in [
        Network::Mainnet,
        Network::Testnet,
        Network::Signet,
        Network::Testnet4,
    ] {
        let names = seed_lookup_names(net);
        assert_eq!(names.len(), dns_seeds(net).len());
        for (pair, seed) in names.iter().zip(dns_seeds(net)) {
            assert_eq!(pair, &[format!("x809.{seed}"), seed.to_string()]);
        }
    }
    assert!(seed_lookup_names(Network::Regtest).is_empty());
    assert!(seed_lookup_names(Network::Testnet5).is_empty());
}

#[test]
fn pick_seed_results_first_success_wins() {
    let x = addr(1);
    let plain = addr(2);
    assert_eq!(pick_seed_results(&[x], &[plain]), vec![x]);
    assert_eq!(pick_seed_results(&[], &[plain]), vec![plain]);
    assert!(pick_seed_results(&[], &[]).is_empty());
    assert_eq!(pick_seed_results(&[x, addr(3)], &[plain]), vec![x, addr(3)]);
}

#[test]
fn dns_seed_query_host_matches_core_x_filter() {
    use bitcoin::p2p::ServiceFlags;
    let bits = required_seed_services();
    assert!(bits.has(ServiceFlags::NETWORK));
    assert!(bits.has(ServiceFlags::WITNESS));
    assert!(bits.has(ServiceFlags::P2P_V2));
    assert_eq!(bits.to_u64(), 0x809);
    assert_eq!(
        dns_seed_query_host("seed.mainnet.achownodes.xyz.", bits),
        "x809.seed.mainnet.achownodes.xyz."
    );
    assert_eq!(
        dns_seed_query_host("seed.signet.bitcoin.sprovoost.nl", bits),
        "x809.seed.signet.bitcoin.sprovoost.nl"
    );
}

#[test]
fn network_ports_and_seed_lists() {
    assert_eq!(default_port(Network::Mainnet), 8333);
    assert_eq!(default_port(Network::Testnet), 18333);
    assert_eq!(default_port(Network::Signet), 38333);
    assert_eq!(default_port(Network::Regtest), 18444);
    assert_eq!(default_rpc_port(Network::Mainnet), 8332);
    assert_eq!(default_rpc_port(Network::Testnet), 18332);
    assert_eq!(default_rpc_port(Network::Signet), 38332);
    assert_eq!(default_rpc_port(Network::Regtest), 18443);
    assert!(dns_seeds(Network::Regtest).is_empty());
    assert_eq!(fixed_seeds(Network::Regtest).count(), 0);
    // Regtest has no seeds → resolve paths stay empty (no network I/O).
    assert!(resolve_dns_seeds(Network::Regtest).is_empty());
}

#[test]
fn dns_seeds_not_resolved_locally_when_proxy() {
    for net in [
        Network::Mainnet,
        Network::Testnet,
        Network::Signet,
        Network::Testnet4,
        Network::Regtest,
    ] {
        let dests = socks_dns_seed_dests(net);
        let names = dns_seeds(net);
        assert_eq!(dests.len(), names.len());
        for ((host, port), want) in dests.iter().zip(names.iter()) {
            assert_eq!(host, want);
            assert_eq!(*port, default_port(net));
            assert!(
                host.parse::<std::net::IpAddr>().is_err(),
                "SOCKS seed dest must stay a hostname, got {host}"
            );
        }
    }
}

#[test]
fn peer_flags_set_remove_and_mid_range_speed() {
    let mut f = PeerFlags::empty();
    assert!(f.is_untried());
    f.set(PeerFlags::HAS_CONNECTED, true);
    assert!(f.has_connected());
    f.set(PeerFlags::HAS_CONNECTED, false);
    assert!(!f.has_connected());
    // Mid-range sample leaves prior classification alone.
    f.insert(PeerFlags::FAST);
    f.apply_speed_sample(150, PeerFlags::FAST_BPS_MIN / 2);
    assert!(f.is_fast());
    assert!(!f.is_slow());
}

#[test]
fn note_ibd_slow_clears_fast_and_is_tier_one() {
    let mut am = AddrMan::new();
    let a = addr(11);
    am.note_speed_addr(
        rbitcoin_net::NetAddr::from_socket(a),
        40,
        PeerFlags::FAST_BPS_MIN + 100,
    );
    assert!(am.flags(&a).is_fast());
    assert_eq!(am.flags(&a).dial_tier(), 0);
    am.note_ibd_slow_addr(rbitcoin_net::NetAddr::from_socket(a));
    assert!(am.flags(&a).is_slow(), "IBD outlier must be SLOW");
    assert!(!am.flags(&a).is_fast(), "IBD outlier must not keep FAST");
    assert_eq!(am.flags(&a).dial_tier(), 1);
}

#[test]
fn apply_ibd_dead_speed_outlier_mid_range_does_not_restore_fast() {
    let mut am = AddrMan::new();
    let a = addr(12);
    am.note_speed_addr(
        rbitcoin_net::NetAddr::from_socket(a),
        40,
        PeerFlags::FAST_BPS_MIN + 100,
    );
    assert!(am.flags(&a).is_fast());
    // Relative-slow kick sample is often 150–500 KB/s (above SLOW_BPS_MAX).
    am.apply_ibd_dead_speed_addr(
        rbitcoin_net::NetAddr::from_socket(a),
        150,
        Some(300_000),
        true,
    );
    assert!(
        am.flags(&a).is_slow() && !am.flags(&a).is_fast(),
        "cooldown Dead mid-range must not restore FAST: {:?}",
        am.flags(&a)
    );
    assert_eq!(am.flags(&a).dial_tier(), 1);
}

#[test]
fn apply_ibd_dead_speed_without_outlier_keeps_mid_range_fast() {
    let mut am = AddrMan::new();
    let a = addr(13);
    am.note_speed_addr(
        rbitcoin_net::NetAddr::from_socket(a),
        40,
        PeerFlags::FAST_BPS_MIN + 100,
    );
    am.apply_ibd_dead_speed_addr(
        rbitcoin_net::NetAddr::from_socket(a),
        150,
        Some(300_000),
        false,
    );
    assert!(
        am.flags(&a).is_fast() && !am.flags(&a).is_slow(),
        "graceful Dead mid-range still leaves prior FAST"
    );
}

#[test]
fn addrman_merge_offset_and_ipv4_sort() {
    use std::net::{IpAddr, Ipv6Addr};
    let v4 = addr(1);
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8333);
    let mut a = AddrMan::new();
    a.add(v6);
    a.add(v4);
    a.inject([v6, v4]); // already present no-op + re-sort
    assert_eq!(a.peers()[0], v4, "IPv4 preferred over IPv6");

    let mut b = AddrMan::new();
    b.add_with_flags(addr(9), {
        let mut f = PeerFlags::empty();
        f.insert(PeerFlags::SLOW);
        f
    });
    a.merge_from(&b);
    assert!(a.flags(&addr(9)).is_slow());
    assert!(a
        .entry_of(&rbitcoin_net::NetAddr::from_socket(addr(9)))
        .is_some());
    assert!(!a.is_empty());

    let ranked = a.take_dial_candidates(2, &HashSet::new(), &[]);
    assert_eq!(ranked.len(), 2);
    let offset = a.take_outbound_offset_occupied(3, 1, &[]);
    assert_eq!(offset.len(), 3.min(a.len()));
    assert!(a.take_outbound_offset_occupied(0, 0, &[]).is_empty());
    assert!(a.take_dial_candidates(0, &HashSet::new(), &[]).is_empty());
}

#[test]
fn peers_file_load_errors_and_empty() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-peers-err-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let missing = dir.join("no-such-peers");
    assert!(AddrMan::load(&missing).unwrap().is_empty());

    let bad = dir.join("bad");
    std::fs::write(&bad, "not-magic\n1.2.3.4:8333 0\n").unwrap();
    assert!(AddrMan::load(&bad).is_err());

    let emptyish = dir.join("emptyish");
    std::fs::write(&emptyish, "# just a comment\n\n").unwrap();
    assert!(AddrMan::load(&emptyish).unwrap().is_empty());

    let ok = dir.join("ok");
    std::fs::write(
        &ok,
        format!(
            "{}\n{} 0x03\n{} 16\n# trailing\n",
            AddrMan::PEERS_FILE_MAGIC,
            addr(1),
            addr(2)
        ),
    )
    .unwrap();
    let loaded = AddrMan::load(&ok).unwrap();
    assert_eq!(loaded.len(), 2);
    assert!(loaded.flags(&addr(1)).has_connected());
    assert!(loaded.flags(&addr(1)).is_fast()); // bits 0|1
    assert!(loaded.flags(&addr(2)).failed_last_connect()); // bit 4 = 16

    let bad_addr = dir.join("bad-addr");
    std::fs::write(
        &bad_addr,
        format!("{}\nnot-an-addr 0\n", AddrMan::PEERS_FILE_MAGIC),
    )
    .unwrap();
    assert!(AddrMan::load(&bad_addr).is_err());

    let bad_hex = dir.join("bad-hex");
    std::fs::write(
        &bad_hex,
        format!("{}\n{} 0xZZ\n", AddrMan::PEERS_FILE_MAGIC, addr(1)),
    )
    .unwrap();
    assert!(AddrMan::load(&bad_hex).is_err());

    let bad_dec = dir.join("bad-dec");
    std::fs::write(
        &bad_dec,
        format!("{}\n{} not-a-number\n", AddrMan::PEERS_FILE_MAGIC, addr(1)),
    )
    .unwrap();
    assert!(AddrMan::load(&bad_dec).is_err());

    let ok_upper = dir.join("ok-upper");
    std::fs::write(
        &ok_upper,
        format!("{}\n{} 0X01\n", AddrMan::PEERS_FILE_MAGIC, addr(7)),
    )
    .unwrap();
    let u = AddrMan::load(&ok_upper).unwrap();
    assert!(u.flags(&addr(7)).has_connected());

    // Save creates parent dir; note_connected clears fail/incompat bits.
    let nested = dir.join("nested").join("peers");
    let mut am = AddrMan::new();
    am.add(addr(3));
    am.note_connect_failed_addr(rbitcoin_net::NetAddr::from_socket(addr(3)), true);
    assert!(am.flags(&addr(3)).is_incompatible());
    am.note_connected_addr(rbitcoin_net::NetAddr::from_socket(addr(3)));
    assert!(am.flags(&addr(3)).has_connected());
    assert!(!am.flags(&addr(3)).is_incompatible());
    am.save(&nested).unwrap();
    assert!(nested.is_file());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn load_drops_unroutable_clearnet_and_keeps_cjdns() {
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-peers-bogon-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("peers");
    std::fs::write(
        &path,
        "\
rbitcoin-peers-v2
1.2.3.4:8333 0x01
10.0.0.1:8333 0x01
100.64.0.1:8333 0x00
[fc00::1]:8333 0x00
",
    )
    .unwrap();
    let loaded = AddrMan::load(&path).unwrap();
    let public: SocketAddr = "1.2.3.4:8333".parse().unwrap();
    assert!(
        loaded
            .entry_of(&rbitcoin_net::NetAddr::from_socket(public))
            .is_some(),
        "a public address still loads"
    );
    assert!(loaded.flags(&public).has_connected());
    let lan: SocketAddr = "10.0.0.1:8333".parse().unwrap();
    assert!(
        loaded
            .entry_of(&rbitcoin_net::NetAddr::from_socket(lan))
            .is_none(),
        "a remembered RFC1918 address is not dialed again"
    );
    let cgnat: SocketAddr = "100.64.0.1:8333".parse().unwrap();
    assert!(loaded
        .entry_of(&rbitcoin_net::NetAddr::from_socket(cgnat))
        .is_none());
    assert!(
        loaded
            .entries()
            .iter()
            .any(|e| matches!(e.addr, NetAddr::Cjdns { .. })),
        "fc00::/8 stays a CJDNS row"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn onion() -> NetAddr {
    "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
        .parse()
        .unwrap()
}

fn i2p() -> NetAddr {
    NetAddr::I2p {
        dest: [7u8; 32],
        port: 8333,
    }
}

fn cjdns() -> NetAddr {
    NetAddr::Cjdns {
        ip: "fc00::1".parse().unwrap(),
        port: 8333,
    }
}

#[test]
fn add_with_flags_drops_a_net_only_net_excludes() {
    let mut am = AddrMan::new();
    am.set_only_net(vec![OnlyNet::Onion]);
    am.set_onion_reachable(true);
    am.add_with_flags_addr(NetAddr::from_socket(addr(1)), PeerFlags::empty());
    assert!(
        am.is_empty(),
        "a peers-file merge must not keep clearnet in an onion-only book"
    );
}

#[test]
fn learned_cjdns_stays_out_until_the_node_can_dial_it() {
    let mut am = AddrMan::new();
    assert!(!am.add_learned_addr(cjdns(), cjdns(), 8));
    assert!(am.is_empty());
    am.set_cjdns_reachable(true);
    assert!(am.add_learned_addr(cjdns(), cjdns(), 8));
}

#[test]
fn onion_and_i2p_stay_out_until_this_process_can_dial_them() {
    let mut am = AddrMan::new();
    am.add_addr(onion());
    assert!(!am.add_learned_addr(i2p(), i2p(), 8));
    am.add_with_flags_addr(onion(), PeerFlags::empty());
    assert!(
        am.is_empty(),
        "no SOCKS and no SAM means those rows are not peers"
    );
    am.set_onion_reachable(true);
    am.add_addr(onion());
    assert!(am.entries().iter().any(|e| e.addr == onion()));
    am.set_i2p_reachable(true);
    assert!(am.add_learned_addr(i2p(), i2p(), 8));
}

#[test]
fn turning_a_net_off_drops_rows_already_in_the_book() {
    let mut am = AddrMan::new();
    am.set_onion_reachable(true);
    am.set_i2p_reachable(true);
    am.set_cjdns_reachable(true);
    am.add_addr(onion());
    am.add_addr(i2p());
    am.add_addr(cjdns());
    am.add(addr(1));
    assert_eq!(am.len(), 4);
    am.set_only_net(vec![OnlyNet::Onion]);
    assert_eq!(
        am.len(),
        1,
        "only-net must drop rows this process will not dial"
    );
    assert!(am.entries().iter().all(|e| e.addr == onion()));
    am.set_onion_reachable(false);
    assert!(
        am.is_empty(),
        "clearing SOCKS drops onion rows already stored"
    );
}

#[test]
fn full_clearnet_batch_does_not_reserve_an_unreachable_overlay() {
    let mut am = AddrMan::new();
    for i in 1..=8u8 {
        am.add(addr(i));
    }
    am.add_addr(onion());
    am.add_addr(i2p());
    let got = am.take_dial_candidates_net(8, &HashSet::new(), &[], false);
    assert_eq!(got.len(), 8, "{got:?}");
    assert!(
        got.iter().all(|a| matches!(a, NetAddr::Ip(_))),
        "an onion this process cannot dial must not take a clearnet slot: {got:?}"
    );
}

#[test]
fn one_peer_batch_takes_the_overlay_slot_only_without_a_live_overlay() {
    let mut am = AddrMan::new();
    am.set_onion_reachable(true);
    am.add(addr(1));
    am.add(addr(2));
    am.add_addr(onion());
    assert_eq!(
        am.take_dial_candidates_net(1, &HashSet::new(), &[], false),
        vec![onion()],
        "no live overlay outbound: the single redial replaces it"
    );
    let got = am.take_dial_candidates_net(1, &HashSet::new(), &[], true);
    assert!(matches!(got.as_slice(), [NetAddr::Ip(_)]), "{got:?}");
}

/// A failed onion stays eligible while every clearnet row is last-resort. A
/// one-peer batch must not hand it the slot again inside the recent-attempt
/// window, or that slot never returns to clearnet.
#[test]
fn one_peer_batch_skips_a_recently_attempted_overlay() {
    let mut am = AddrMan::new();
    am.set_onion_reachable(true);
    am.add(addr(1));
    am.note_connect_failed_addr(NetAddr::Ip(addr(1)), false);
    am.add_addr(onion());
    am.note_attempt_addr(onion());
    am.note_connect_failed_addr(onion(), false);
    let got = am.take_dial_candidates_net(1, &HashSet::new(), &[], false);
    assert_eq!(got, vec![NetAddr::Ip(addr(1))], "{got:?}");
}

#[test]
fn dns_seeds_match_core_v32() {
    assert_eq!(
        dns_seeds(Network::Mainnet),
        [
            "dnsseed.bluematt.me.",
            "seed.bitcoin.jonasschnelli.ch.",
            "seed.btc.petertodd.net.",
            "seed.bitcoin.sprovoost.nl.",
            "dnsseed.emzy.de.",
            "seed.bitcoin.wiz.biz.",
            "seed.mainnet.achownodes.xyz.",
        ]
    );
    assert_eq!(
        dns_seeds(Network::Testnet),
        [
            "testnet-seed.bitcoin.jonasschnelli.ch.",
            "seed.tbtc.petertodd.net.",
            "testnet-seed.bluematt.me.",
            "seed.testnet.achownodes.xyz.",
        ]
    );
    assert_eq!(
        dns_seeds(Network::Signet),
        [
            "seed.signet.bitcoin.sprovoost.nl.",
            "seed.signet.achownodes.xyz.",
        ]
    );
    assert_eq!(
        dns_seeds(Network::Testnet4),
        [
            "seed.testnet4.bitcoin.sprovoost.nl.",
            "seed.testnet4.wiz.biz.",
        ]
    );
    let removed = [
        "seed.bitcoin.sipa.be",
        "seed.testnet.bitcoin.sprovoost.nl",
        "seed.bitcoinstats.com",
        "dnsseed.bitcoin.dashjr-list-of-p2p-nodes.us",
        "testnet-seed.bitcoin.schildbach.de",
    ];
    for net in [Network::Mainnet, Network::Testnet, Network::Signet] {
        for host in dns_seeds(net) {
            assert!(
                !removed.contains(&host.trim_end_matches('.')),
                "{net}: Core dropped {host}"
            );
        }
    }
}

/// Counts in [`OnlyNet::ALL`] order: ipv4, ipv6, onion, i2p, cjdns.
fn per_net(addrs: impl IntoIterator<Item = NetAddr>) -> [usize; 5] {
    let mut n = [0usize; 5];
    for a in addrs {
        let i = OnlyNet::ALL
            .iter()
            .position(|net| *net == OnlyNet::of(a))
            .unwrap();
        n[i] += 1;
    }
    n
}

fn net_addr(s: &str) -> NetAddr {
    s.parse().unwrap()
}

#[test]
fn fixed_seeds_are_core_v32_tables() {
    use bitcoin::hashes::{sha256, Hash};
    // `scripts/core-fixed-seeds.sh` prints these after a refresh.
    for (file, bytes, want) in [
        (
            "nodes_main.txt",
            include_bytes!("../seeds/nodes_main.txt").as_slice(),
            "9607d27cd55aaff7422213f57f2797acedc65a34b0c018c7f57f274c2ca88dcb",
        ),
        (
            "nodes_test.txt",
            include_bytes!("../seeds/nodes_test.txt").as_slice(),
            "b2b359f05c3965811ee34a2594d49984e74b164007ffb2221c8a572db033f110",
        ),
        (
            "nodes_signet.txt",
            include_bytes!("../seeds/nodes_signet.txt").as_slice(),
            "1544288fcd05ebf48d7c1a8df2e39e3d20958ebac6b9a5b825b74fcd733ed075",
        ),
        (
            "nodes_testnet4.txt",
            include_bytes!("../seeds/nodes_testnet4.txt").as_slice(),
            "6def93c209a371b7e34ebdd66cf6bd38f8e3ec4938a9e0627dce8b362b91b462",
        ),
    ] {
        assert_eq!(sha256::Hash::hash(bytes).to_string(), want, "{file}");
    }
    let main: Vec<NetAddr> = fixed_seeds(Network::Mainnet).collect();
    assert_eq!(per_net(main.iter().copied()), [512, 512, 512, 512, 9]);
    for want in [
        "3.11.75.34:8333",
        "[2001:1284:f502:9104:419d:b3ea:216:61eb]:8333",
        "24yjwaf2ni6wz44pmqpw3jyjhksoko7wxzelp6uyep2pdlgb5epbnoqd.onion:8333",
        "22qtnewwrxin6r77r4h4qttospl5rkmoljpbuedx4w33virx46sq.b32.i2p:0",
        "[fc10:efa7:ca6:1548:f8c:6bb9:1cc4:63ae]:8333",
    ] {
        assert!(
            main.contains(&net_addr(want)),
            "mainnet fixed seeds lack {want}"
        );
    }
    assert!(
        main.iter()
            .all(|a| a.port() == 8333 || matches!(a, NetAddr::I2p { port: 0, .. })),
        "a mainnet fixed seed has a port Core does not use"
    );
    let test: Vec<NetAddr> = fixed_seeds(Network::Testnet).collect();
    assert_eq!(per_net(test.iter().copied()), [67, 37, 76, 6, 4]);
    assert!(test.contains(&net_addr("3.253.163.14:18333")));
    let signet: Vec<NetAddr> = fixed_seeds(Network::Signet).collect();
    assert_eq!(per_net(signet.iter().copied()), [75, 57, 72, 7, 3]);
    assert!(signet.contains(&net_addr(
        "2uqd5pbaxn26o7fl7nqtm2khetqocislppxtxrpqg55wtbcqdrf2y5qd.onion:38333"
    )));
    let testnet4: Vec<NetAddr> = fixed_seeds(Network::Testnet4).collect();
    assert_eq!(per_net(testnet4.iter().copied()), [56, 55, 78, 14, 4]);
    for want in [
        "3.234.184.245:48333",
        "2sltzrq7ts5t4il5nimp75og2jksbwdjmgbdykz5ljeoqrxemzlakeyd.onion:48333",
        "[fc10:efa7:ca6:1548:f8c:6bb9:1cc4:63ae]:48333",
    ] {
        assert!(
            testnet4.contains(&net_addr(want)),
            "testnet4 fixed seeds lack {want}"
        );
    }
    assert_eq!(fixed_seeds(Network::Regtest).count(), 0);
    assert!(dns_seeds(Network::Testnet5).is_empty());
    assert_eq!(fixed_seeds(Network::Testnet5).count(), 0);
}

#[test]
fn fixed_seeds_fill_only_reachable_nets_the_book_lacks() {
    let mut clear = AddrMan::new();
    assert_eq!(clear.add_fixed_seeds(Network::Mainnet), 1024);
    assert_eq!(
        per_net(clear.dial_order().iter().copied()),
        [512, 512, 0, 0, 0]
    );

    let mut all = AddrMan::new();
    all.set_onion_reachable(true);
    all.set_i2p_reachable(true);
    all.set_cjdns_reachable(true);
    assert_eq!(all.add_fixed_seeds(Network::Mainnet), 2057);

    let mut onion_no_dns = AddrMan::new();
    onion_no_dns.set_onion_reachable(true);
    assert_eq!(
        onion_no_dns.add_fixed_seeds(Network::Mainnet),
        1536,
        "`--onion` alone keeps clearnet reachable (direct), as in Core"
    );

    let mut dns_answered = AddrMan::new();
    dns_answered.set_onion_reachable(true);
    let v6: SocketAddr = "[2001:4860::1]:8333".parse().unwrap();
    dns_answered.inject([addr(1), v6]);
    assert_eq!(dns_answered.add_fixed_seeds(Network::Mainnet), 512);
    assert_eq!(
        per_net(dns_answered.dial_order().iter().copied()),
        [1, 1, 512, 0, 0],
        "`--onion` with a DNS answer adds onion seeds and no clearnet seed"
    );
    assert_eq!(dns_answered.add_fixed_seeds(Network::Mainnet), 0);
}

#[test]
fn onion_only_fixed_seed_fallback_never_offers_clearnet() {
    let mut am = AddrMan::new();
    am.set_onion_reachable(true);
    am.set_only_net(vec![OnlyNet::Onion]);
    assert_eq!(am.add_fixed_seeds(Network::Mainnet), 512);
    assert_eq!(per_net(am.dial_order().iter().copied()), [0, 0, 512, 0, 0]);
    let got = am.take_dial_candidates_net(16, &HashSet::new(), &[], false);
    assert_eq!(got.len(), 16);
    assert!(
        got.iter().all(|a| matches!(a, NetAddr::Onion { .. })),
        "{got:?}"
    );
}
