fn hostile_ver(addr: SocketAddr) -> VersionMessage {
    VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 7,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    }
}

#[tokio::test]
async fn addrv2_gossip_drops_unroutable_clearnet() {
    use bitcoin::p2p::message::NetworkMessage;
    use std::sync::{Arc, Mutex};

    let peers = rbitcoin_net::peers::PeerHub::new();
    let book = Arc::new(Mutex::new(rbitcoin_net::seeds::AddrMan::new()));
    peers.set_addrman(Arc::clone(&book));
    let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
    let ver = hostile_ver(src_addr);
    let peer = peers.register(
        src_addr,
        src_addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    peer.set_wants_addrv2();
    let dst_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 8333);
    let dst = peers.register(
        dst_addr,
        dst_addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    dst.set_wants_addrv2();
    let (_dst_tx, mut dst_rx) = dst.open_out();
    peers.set_mock_now(peer.connected_at_secs() + 10_000);
    let t = peers.now_secs() as u32 - 60;

    let public = AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9)),
        port: 8333,
    };
    let lan = AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
        port: 8333,
    };
    let cgnat = AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(100, 64, 0, 1)),
        port: 8333,
    };
    let zero_port = AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 8)),
        port: 0,
    };
    let i2p = AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::I2p([0x11; 32]),
        port: 0,
    };
    let tor_v2 = AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::TorV2([0xab; 10]),
        port: 8333,
    };
    let cjdns_bad = AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Cjdns(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        port: 8333,
    };
    let cjdns = AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
        port: 8333,
    };
    let unknown = AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Unknown(0x99, vec![1, 2, 3, 4]),
        port: 8333,
    };
    let mut follow = PeerFollowState::new();
    on_addrv2(
        &mut follow,
        Some(peer.as_ref()),
        &[
            lan,
            public.clone(),
            cgnat,
            zero_port,
            i2p.clone(),
            tor_v2,
            cjdns_bad,
            cjdns.clone(),
            unknown.clone(),
        ],
    )
    .unwrap();

    let got = dst_rx
        .try_recv()
        .expect("the public address is relayed")
        .expect_msg();
    let NetworkMessage::AddrV2(sent) = got else {
        panic!("expected addrv2, got {got:?}");
    };
    assert_eq!(sent, vec![public, i2p, cjdns, unknown]);
    assert!(
        dst_rx.try_recv().is_err(),
        "unroutable rows, port-0 clearnet, Tor v2, and non-CJDNS are not relayed"
    );
    let book = book.lock().unwrap_or_else(|e| e.into_inner());
    let public_sock = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 8333);
    let lan_sock = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8333);
    assert!(book.entry_of(&rbitcoin_net::NetAddr::from_socket(public_sock)).is_some());
    assert!(
        book.entry_of(&rbitcoin_net::NetAddr::from_socket(lan_sock)).is_none(),
        "learn_addrv2 does not store RFC1918"
    );
}

/// Core `ProcessAddrs` rewrites an insane address time to five days ago for
/// `AddrMan` and skips relay when the sanitized time is not within 10 minutes,
/// so a neighbor never receives a future or 1970 time.
#[tokio::test]
async fn addrv2_relay_sanitizes_an_insane_time() {
    use bitcoin::p2p::message::NetworkMessage;
    use std::sync::{Arc, Mutex};

    let now = 1_700_000_000u64;
    let peers = rbitcoin_net::peers::PeerHub::new();
    let book = Arc::new(Mutex::new(rbitcoin_net::seeds::AddrMan::new()));
    peers.set_addrman(Arc::clone(&book));
    peers.set_mock_now(now - 20);
    let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
    let ver = hostile_ver(src_addr);
    let src = peers.register(
        src_addr,
        src_addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    src.set_wants_addrv2();
    let dst_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 8333);
    let dst = peers.register(
        dst_addr,
        dst_addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    dst.set_wants_addrv2();
    let (_, mut dst_rx) = dst.open_out();
    peers.set_mock_now(now);
    while dst_rx.try_recv().is_ok() {}

    let mut follow = PeerFollowState::new();
    on_addrv2(
        &mut follow,
        Some(src.as_ref()),
        &[AddrV2Message {
            time: now as u32 + 3_600,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9)),
            port: 8333,
        }],
    )
    .unwrap();
    assert!(
        dst_rx.try_recv().is_err(),
        "an insane future time backdates past 10 minutes and is not relayed"
    );
    let stored = book
        .lock()
        .unwrap()
        .last_seen_of(&"9.9.9.9:8333".parse().unwrap());
    assert!(
        stored > 0 && stored <= now as u32 - 5 * 24 * 60 * 60,
        "stored={stored}"
    );

    let fresh = AddrV2Message {
        time: now as u32 - 60,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 10)),
        port: 8333,
    };
    on_addrv2(&mut follow, Some(src.as_ref()), std::slice::from_ref(&fresh)).unwrap();
    let got = dst_rx.try_recv().expect("fresh row relays").expect_msg();
    let NetworkMessage::AddrV2(rows) = got else {
        panic!("expected addrv2, got {got:?}");
    };
    assert_eq!(rows, vec![fresh]);
}

/// A peer that announces its own listen address from a different TCP source
/// port keeps the full claim: Core compares the host, not the port.
#[test]
fn a_self_announcement_keeps_its_full_time_across_ports() {
    use std::sync::Mutex;

    let (_dir, chain) = rbitcoin_net::chain::tiny_regtest_hub_labeled("getaddr-self-announce");
    let chain = rbitcoin_net::ChainHub::into_arc(chain);
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_000);
    peers.set_addrman(Arc::new(Mutex::new(rbitcoin_net::seeds::AddrMan::new())));
    let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 5555);
    let src = peers.register(
        src_addr,
        src_addr,
        &hostile_ver(src_addr),
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut follow = PeerFollowState::new();
    on_addrv2(
        &mut follow,
        Some(src.as_ref()),
        &[AddrV2Message {
            time: 1_699_996_400,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9)),
            port: 8333,
        }],
    )
    .unwrap();
    let ask_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21001);
    let ask = peers.register(
        ask_addr,
        ask_addr,
        &hostile_ver(ask_addr),
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    ask.set_wants_addrv2();
    let (out_tx, mut out_rx) = ask.open_out();
    on_getaddr(&chain, &out_tx, Some(ask.as_ref())).unwrap();
    let rows = loop {
        let out = out_rx.try_recv().expect("a getaddr reply");
        if let NetworkMessage::AddrV2(rows) = out.expect_msg() {
            break rows;
        }
    };
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].time, 1_699_996_400);
}

/// A reply stamps only the rows it returns. A v1 getaddr that leaves an
/// onion out does not start its backdate.
#[test]
fn getaddr_stamps_only_the_rows_it_returns() {
    use std::sync::Mutex;

    let now = 1_700_000_000u64;
    let (_dir, chain) = rbitcoin_net::chain::tiny_regtest_hub_labeled("getaddr-returned");
    let chain = rbitcoin_net::ChainHub::into_arc(chain);
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(now);
    let mut am = rbitcoin_net::seeds::AddrMan::new();
    am.set_onion_reachable(true);
    let onion: rbitcoin_net::NetAddr =
        "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:8333"
            .parse()
            .unwrap();
    am.add_addr(onion);
    let book = Arc::new(Mutex::new(am));
    peers.set_addrman(Arc::clone(&book));

    let v1_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21002);
    let v1 = peers.register(
        v1_addr,
        v1_addr,
        &hostile_ver(v1_addr),
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (v1_tx, mut v1_rx) = v1.open_out();
    on_getaddr(&chain, &v1_tx, Some(v1.as_ref())).unwrap();
    let rows = loop {
        let out = v1_rx.try_recv().expect("a v1 getaddr reply");
        if let NetworkMessage::Addr(rows) = out.expect_msg() {
            break rows;
        }
    };
    assert!(rows.is_empty(), "v1 excludes the onion: {rows:?}");
    assert_eq!(
        book.lock().unwrap().last_seen_of(&onion),
        0,
        "a row this reply did not return is not stamped"
    );

    peers.set_mock_now(now + 10 * 24 * 60 * 60);
    let v2_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21003);
    let v2 = peers.register(
        v2_addr,
        v2_addr,
        &hostile_ver(v2_addr),
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    v2.set_wants_addrv2();
    let (v2_tx, mut v2_rx) = v2.open_out();
    on_getaddr(&chain, &v2_tx, Some(v2.as_ref())).unwrap();
    let rows = loop {
        let out = v2_rx.try_recv().expect("a v2 getaddr reply");
        if let NetworkMessage::AddrV2(rows) = out.expect_msg() {
            break rows;
        }
    };
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].time,
        (now + 10 * 24 * 60 * 60 - 5 * 24 * 60 * 60) as u32
    );
}

/// A peers file written on a fast clock is normalized once: the first v2
/// reply backdates the row, and a later reply reports the same point, not a
/// fresh five-days-old time.
#[test]
fn a_future_peers_time_is_backdated_once() {
    use std::sync::Mutex;

    let now = 1_700_000_000u64;
    let dir = std::env::temp_dir().join(format!(
        "rbitcoin-peers-future-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("peers");
    std::fs::write(
        &path,
        "rbitcoin-peers-v3\n9.9.9.9:8333 0x00 1700003600\n",
    )
    .unwrap();
    let book = Arc::new(Mutex::new(
        rbitcoin_net::seeds::AddrMan::load(&path).unwrap(),
    ));
    let (_hub_dir, chain) = rbitcoin_net::chain::tiny_regtest_hub_labeled("getaddr-future");
    let chain = rbitcoin_net::ChainHub::into_arc(chain);
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(now);
    peers.set_addrman(Arc::clone(&book));

    let ask = peers.register(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21004),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21004),
        &hostile_ver(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            21004,
        )),
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    ask.set_wants_addrv2();
    let (out_tx, mut out_rx) = ask.open_out();
    on_getaddr(&chain, &out_tx, Some(ask.as_ref())).unwrap();
    let rows = loop {
        let out = out_rx.try_recv().expect("a getaddr reply");
        if let NetworkMessage::AddrV2(rows) = out.expect_msg() {
            break rows;
        }
    };
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].time, (now - 5 * 24 * 60 * 60) as u32);

    peers.set_mock_now(now + 10 * 24 * 60 * 60);
    let ask = peers.register(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21005),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 21005),
        &hostile_ver(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            21005,
        )),
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    ask.set_wants_addrv2();
    let (out_tx, mut out_rx) = ask.open_out();
    on_getaddr(&chain, &out_tx, Some(ask.as_ref())).unwrap();
    let rows = loop {
        let out = out_rx.try_recv().expect("a getaddr reply");
        if let NetworkMessage::AddrV2(rows) = out.expect_msg() {
            break rows;
        }
    };
    assert_eq!(
        rows[0].time,
        (now - 5 * 24 * 60 * 60) as u32,
        "the backdate is fixed once, not recomputed"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A peer gossips this node's own onion, I2P, CJDNS and external addresses
/// back on a clearnet session. The relay fan-out passes none of them on, to
/// a clearnet neighbor or to an onion one, and still relays a stranger's.
#[tokio::test]
async fn addrv2_relay_drops_own_addresses() {
    use bitcoin::p2p::message::NetworkMessage;

    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let rbitcoin_net::NetAddr::Onion { pk, .. } = onion else {
        unreachable!()
    };
    let cjdns_ip = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 7);
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_p2p_i2p(rbitcoin_net::NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    });
    peers.set_external_endpoints(vec![
        "42.42.42.42:28333".parse().unwrap(),
        format!("{}:28334", onion.host_str()).parse().unwrap(),
        rbitcoin_net::netaddr::ExternalEndpoint::BareIp(IpAddr::V6(cjdns_ip)),
    ]);
    let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
    let ver = hostile_ver(src_addr);
    let src = peers.register(
        src_addr,
        src_addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    src.set_wants_addrv2();
    let clear_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)), 8333);
    let clear = peers.register(
        clear_addr,
        clear_addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    clear.set_wants_addrv2();
    let (_, mut clear_rx) = clear.open_out();
    let onion_net: rbitcoin_net::NetAddr =
        "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:8333"
            .parse()
            .unwrap();
    let onion_sock = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8333);
    let onion_peer = peers.register_net(
        onion_sock,
        onion_net,
        onion_sock,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    onion_peer.set_wants_addrv2();
    let (_, mut onion_rx) = onion_peer.open_out();
    peers.set_mock_now(src.connected_at_secs() + 10_000);
    let t = peers.now_secs() as u32 - 60;

    let row = |addr: AddrV2, port: u16| AddrV2Message {
        time: t,
        services: ServiceFlags::NETWORK,
        addr,
        port,
    };
    let stranger = row(AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9)), 8333);
    // The onion neighbor's own self-announce (our onion, on an onion link)
    // is not relay; drop it so only the fan-out is counted.
    while clear_rx.try_recv().is_ok() {}
    while onion_rx.try_recv().is_ok() {}
    let mut follow = PeerFollowState::new();
    on_addrv2(
        &mut follow,
        Some(src.as_ref()),
        &[
            row(AddrV2::TorV3(pk), 8333),
            row(AddrV2::I2p([0x11; 32]), 0),
            row(AddrV2::Ipv4(Ipv4Addr::new(42, 42, 42, 42)), 8333),
            row(AddrV2::Cjdns(cjdns_ip), 8333),
            stranger.clone(),
        ],
    )
    .unwrap();

    let mut relayed = Vec::new();
    for rx in [&mut clear_rx, &mut onion_rx] {
        while let Ok(out) = rx.try_recv() {
            let NetworkMessage::AddrV2(rows) = out.expect_msg() else {
                panic!("expected addrv2");
            };
            relayed.extend(rows);
        }
    }
    assert!(!relayed.is_empty(), "the stranger's address is relayed");
    assert!(
        relayed.iter().all(|r| r == &stranger),
        "no neighbor is sent this node's own address: {relayed:?}"
    );
}

fn hostile_addr(port: u16, time: u32) -> AddrV2Message {
    AddrV2Message {
        time,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(9, 9, 9, 9)),
        port,
    }
}

#[tokio::test]
async fn hostile_peer_session() {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::block::Header;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hostile-session");
    hub.ensure_genesis().unwrap();
    hub.confirm_empty_regtest(200)
        .unwrap();
    let genesis = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(0))
        .unwrap()
        .block_hash();

    let peers = rbitcoin_net::peers::PeerHub::new();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = hostile_ver(bind);
    let peer = peers.register(
        bind,
        bind,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (out_tx, mut out_rx) = peer.open_out();
    let mut follow = PeerFollowState::new();

    let hdr = Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    for batch in 0..4u32 {
        let headers: Vec<Header> = (0..2_000u32)
            .map(|i| {
                let mut h = hdr;
                h.nonce = batch * 2_000 + i;
                h
            })
            .collect();
        on_headers(&hub, &out_tx, &mut follow, Some(&peer), &headers)
            .await
            .unwrap();
    }
    assert_eq!(follow.pending_headers.len(), rbitcoin_net::peer::MAX_PENDING_HEADERS);
    let kept = *follow.pending_headers.keys().next().unwrap();
    let kept_hdr = follow.pending_headers[&kept];
    on_headers(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        &[kept_hdr],
    )
    .await
    .unwrap();
    assert_eq!(follow.pending_headers.len(), rbitcoin_net::peer::MAX_PENDING_HEADERS);
    assert!(follow.pending_headers.contains_key(&kept));
    let mut extra = hdr;
    extra.nonce = 9_000_000;
    let extra_hash = extra.block_hash();
    on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[extra])
        .await
        .unwrap();
    assert_eq!(follow.pending_headers.len(), rbitcoin_net::peer::MAX_PENDING_HEADERS);
    assert!(!follow.pending_headers.contains_key(&extra_hash));

    // One continuation needs one slot. The other orphans stay, so a later
    // parent can still join them.
    let mut continuation = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(200))
        .unwrap();
    continuation.prev_blockhash = hub.tip_hash().unwrap();
    continuation.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x55; 32]);
    continuation.time = continuation.time.saturating_add(600);
    continuation.nonce = 0;
    rbitcoin_consensus::grind_regtest_pow(&mut continuation);
    let continuation_hash = continuation.block_hash();
    on_headers(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        &[continuation],
    )
    .await
    .unwrap();
    assert_eq!(
        follow.pending_headers.len(),
        rbitcoin_net::peer::MAX_PENDING_HEADERS
    );
    assert!(follow.pending_headers.contains_key(&continuation_hash));

    while out_rx.try_recv().is_ok() {}

    let gh = GetHeadersMessage::new(vec![genesis], BlockHash::from_byte_array([0u8; 32]));
    on_getheaders(&hub, &out_tx, &mut follow, Some(&peer), &gh)
        .await
        .unwrap();
    let NetworkMessage::Headers(first) = out_rx.try_recv().unwrap().expect_msg() else {
        panic!("one getheaders under the budget must be answered");
    };
    assert_eq!(first.len(), 200, "locator after genesis walks the tip");
    let mut unread = Vec::new();
    for _ in 0..400 {
        handle_decoded_peer_msg(
            RawNetworkMessage::new(
                Magic::from(Network::Regtest),
                NetworkMessage::GetHeaders(GetHeadersMessage::new(
                    vec![genesis],
                    BlockHash::from_byte_array([0u8; 32]),
                )),
            ),
            &hub,
            &out_tx,
            &mut follow,
            Some(&peer),
        )
        .await
        .unwrap();
        match out_rx.try_recv() {
            Ok(reply) => unread.push(reply),
            Err(_) => break,
        }
    }
    let queued = 1 + unread.len();
    let batch = first.len().saturating_mul(81);
    let room = rbitcoin_net::peers::PEER_SEND_BUDGET / batch;
    assert!(
        queued <= room + 2,
        "queued {queued} header batches while the peer read nothing (room {room})"
    );
    assert!(queued > 1, "a getheaders under the budget produced no further reply");

    drop(unread);
    assert!(!peer.send_over_budget());
    let before = peer.send_queued();
    out_tx.send(NetworkMessage::Inv(vec![Inventory::Block(genesis)]))
    .unwrap();
    out_tx.send(NetworkMessage::NotFound(vec![Inventory::Block(genesis)]))
    .unwrap();
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let tx_n = tx.total_size();
    out_tx.send(NetworkMessage::Tx(tx)).unwrap();
    out_tx.send(NetworkMessage::Addr(vec![(0, Address::new(&bind, ServiceFlags::NONE))]))
    .unwrap();
    assert_eq!(
        peer.send_queued() - before,
        36 + 36 + tx_n + 30,
        "inv, notfound, tx, and addr share the send budget"
    );

    let block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
    let block_n = block.total_size();
    assert!(block_n > 64, "a block is not the fallback size");
    assert_eq!(
        rbitcoin_net::peers::outbound_msg_bytes(&NetworkMessage::Block(block.clone())),
        block_n
    );
    let v2 = NetworkMessage::AddrV2(vec![AddrV2Message {
        time: 1,
        services: ServiceFlags::NONE,
        addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
        port: 1,
    }]);
    assert_eq!(rbitcoin_net::peers::outbound_msg_bytes(&v2), 61);
    let hsi = HeaderAndShortIds::from_block(&block, 1, 1, &[0]).unwrap();
    let compact_n = bitcoin::consensus::encode::serialize(&hsi).len();
    assert_eq!(
        rbitcoin_net::peers::outbound_msg_bytes(&NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi
        })),
        compact_n
    );
    let txns = bitcoin::bip152::BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![block.txdata[0].clone()],
    };
    let blocktxn_n = bitcoin::consensus::encode::serialize(&txns).len();
    assert!(blocktxn_n > 64, "a blocktxn is not the fallback size");
    assert_eq!(
        rbitcoin_net::peers::outbound_msg_bytes(&NetworkMessage::BlockTxn(
            bitcoin::p2p::message_compact_blocks::BlockTxn { transactions: txns }
        )),
        blocktxn_n
    );
    assert_eq!(rbitcoin_net::peers::PEER_SEND_BUDGET, 4 * 1024 * 1024);
    while out_rx.try_recv().is_ok() {}
    assert_eq!(peer.send_queued(), 0, "every reply taken off the queue is released");
    let at_cap = hold_send_bytes(&peer, rbitcoin_net::peers::PEER_SEND_BUDGET);
    assert!(
        !peer.send_over_budget(),
        "the cap itself is still inside the budget"
    );
    out_tx.send(PeerOut::Encoded(vec![0])).unwrap();
    assert!(peer.send_over_budget());
    drop(at_cap);
    while out_rx.try_recv().is_ok() {}
    handle_peer_inventory_msg(
        &NetworkMessage::GetAddr,
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
    )
    .unwrap();
    let mut addrs = 0usize;
    while let Ok(msg) = out_rx.try_recv() {
        if matches!(
            msg.expect_msg(),
            NetworkMessage::Addr(_) | NetworkMessage::AddrV2(_)
        ) {
            addrs += 1;
        }
    }
    assert_eq!(addrs, 1, "the first getaddr is answered");
    handle_peer_inventory_msg(
        &NetworkMessage::GetAddr,
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
    )
    .unwrap();
    assert!(
        out_rx.try_recv().is_err(),
        "a second getaddr is not answered"
    );

    hostile_addr_relay(&peers, &peer, &ver, &mut follow).await;

    let _ = std::fs::remove_dir_all(dir);
}

/// True once the node answers `nonce`. False when the session closes first.
/// Frames are applied in order, so a pong means every earlier frame ran.
async fn pong_after(raw: &mut V2PlainSession, nonce: u64) -> bool {
    write_peer_msg(raw, NetworkMessage::Ping(nonce)).await;
    let wait = async {
        loop {
            match next_peer_msg(raw).await {
                Ok(NetworkMessage::Pong(n)) if n == nonce => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    };
    tokio::time::timeout(Duration::from_secs(60), wait)
        .await
        .expect("the node answers the ping or closes the session")
}

/// A relay peer sends transactions whose scripts fail. Nine of them and a
/// policy reject leave the session up. The tenth script failure closes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn script_failures_disconnect_a_relay_peer_and_policy_rejects_do_not() {
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let mut t = paused_serve("script-reject-score", 0, &["/rbitcoin:test(script-reject)/"]).await;
    let hub = Arc::clone(&t.node.hub);
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    hub.mine(10, ScriptBuf::from_bytes(vec![0x00]), vec![])
        .unwrap();
    hub.mine(100, op_true.clone(), vec![]).unwrap();
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(t.dir.join("mp"), Arc::clone(&hub.query))
        .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let spend = |height: u32, extra: i64| {
        let coinbase = hub
            .query
            .reconstruct_block_at_height(Height(height))
            .unwrap()
            .txdata
            .swap_remove(0);
        let value = coinbase.output[0].value.to_sat();
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: coinbase.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value.saturating_add_signed(extra)),
                script_pubkey: op_true.clone(),
            }],
        }
    };
    let (raw, _) = &mut t.clients[0];
    for height in 1..=9 {
        write_peer_msg(raw, NetworkMessage::Tx(spend(height, -20_000))).await;
    }
    // Pays out more than its coin holds: a policy reject.
    write_peer_msg(raw, NetworkMessage::Tx(spend(11, 1))).await;
    assert!(
        pong_after(raw, 1).await,
        "nine script failures and a policy reject keep the peer"
    );
    write_peer_msg(raw, NetworkMessage::Tx(spend(10, -20_000))).await;
    assert!(
        !pong_after(raw, 2).await,
        "the tenth script failure disconnects the peer"
    );
    let _ = std::fs::remove_dir_all(&t.dir);
}


#[allow(clippy::cognitive_complexity)] // address-relay chapter of the same session
async fn hostile_addr_relay(
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
    peer: &std::sync::Arc<rbitcoin_net::peers::LivePeer>,
    ver: &VersionMessage,
    follow: &mut PeerFollowState,
) {
        peer.set_wants_addrv2();
        let (_, mut src_rx) = peer.open_out();
        let mut neigh = Vec::new();
        let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22000);
        let dst = peers.register(a, a, ver, true, rbitcoin_net::peers::PeerConnType::Inbound);
        dst.set_wants_addrv2();
        let (_, rx) = dst.open_out();
        neigh.push((dst.id, rx));
        let quiet_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 23000);
        let quiet = peers.register(
            quiet_addr,
            quiet_addr,
            ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        );
        let (_, mut quiet_rx) = quiet.open_out();

        let mut fresh = AddrTokenBucket::new(1_000);
        assert_eq!(fresh.take(5, 1_000), 1, "a new bucket holds one token");
        assert_eq!(fresh.take(1, 10_999), 0, "under 10 s is less than a token");
        let mut ten = AddrTokenBucket::new(1_000);
        assert_eq!(ten.take(1, 1_000), 1);
        assert_eq!(ten.take(1, 11_000), 1, "10 s refills one token");
        let mut capped = AddrTokenBucket::new(0);
        assert_eq!(
            capped.take(5_000, 1_000_000_000),
            MAX_ADDR_TO_SEND,
            "refill stops at the cap"
        );
        // A quiet peer refills its bucket: let 10_000 s of node time pass.
        let now = peer.connected_at_secs() + 10_000;
        peers.set_mock_now(now);
        let addr_time = (now - 60) as u32;

        let list: Vec<AddrV2Message> = (1..=3u8)
            .map(|i| AddrV2Message {
                time: addr_time,
                services: ServiceFlags::NETWORK,
                addr: AddrV2::Ipv4(Ipv4Addr::new(123, 123, 123, i)),
                port: 8333,
            })
            .collect();
        rbitcoin_log::capture_logs(true);
        on_addrv2(follow, Some(peer.as_ref()), &list).unwrap();
        let lines = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let mut batched = None;
        let mut batched_id = None;
        for (id, rx) in &mut neigh {
            if let Ok(msg) = rx.try_recv() {
                assert!(rx.try_recv().is_err(), "the neighbor gets a single message");
                batched_id = Some(*id);
                batched = Some(msg.expect_msg());
            }
        }
        let got = batched.expect("one addrv2");
        let NetworkMessage::AddrV2(sent) = &got else {
            panic!("expected addrv2, got {got:?}");
        };
        assert_eq!(sent, &list);
        let nbytes = serialize(&got).len();
        let want = format!(
            "p2p: {}",
            sending_addrv2_log(nbytes, batched_id.expect("neighbor id"))
        );
        assert!(
            lines.iter().any(|(_, l)| l == &want),
            "missing {want:?} in {lines:?}"
        );

        for i in 1..4u16 {
            let a = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 22000 + i);
            let p = peers.register(a, a, ver, true, rbitcoin_net::peers::PeerConnType::Inbound);
            p.set_wants_addrv2();
            let (_, rx) = p.open_out();
            neigh.push((p.id, rx));
        }

        let n = neigh.len();
        let mut even_port = None;
        let mut odd_port = None;
        let mut wrap_port = None;
        for port in 1..20_000u16 {
            let key = addr_key_oracle(&hostile_addr(port, addr_time));
            if (key as usize) < n * n {
                continue;
            }
            let start = (key as usize) % n;
            if key & 1 == 0 {
                even_port.get_or_insert(port);
            } else if start + 1 == n {
                wrap_port.get_or_insert(port);
            } else if start != 0 {
                odd_port.get_or_insert(port);
            }
            if even_port.is_some() && odd_port.is_some() && wrap_port.is_some() {
                break;
            }
        }
        let ports = [
            even_port.expect("an even relay key"),
            odd_port.expect("an odd relay key whose next neighbor does not wrap"),
            wrap_port.expect("an odd relay key whose next neighbor wraps"),
        ];
        for port in ports {
            let msg = hostile_addr(port, addr_time);
            on_addrv2(follow, Some(peer.as_ref()), std::slice::from_ref(&msg)).unwrap();
            let key = addr_key_oracle(&msg);
            let n_dest = if key & 1 == 0 { 1 } else { 2 };
            let start = (key as usize) % n;
            let mut expect = Vec::new();
            for step in 0..n_dest {
                let idx = if step == 0 {
                    start
                } else if start + 1 == n {
                    0
                } else {
                    start + 1
                };
                expect.push(neigh[idx].0);
            }
            expect.sort_unstable();
            let mut got_ids = Vec::new();
            for (id, rx) in &mut neigh {
                while rx.try_recv().is_ok() {
                    got_ids.push(*id);
                }
            }
            got_ids.sort_unstable();
            assert_eq!(
                got_ids, expect,
                "port {port} key {key:#x} start {start} must select those neighbors"
            );
            assert!(src_rx.try_recv().is_err(), "a peer does not relay to itself");
            assert!(
                quiet_rx.try_recv().is_err(),
                "a peer that did not ask for addrv2 is skipped"
            );
        }

        on_addrv2(follow, Some(peer.as_ref()), &[hostile_addr(8333, addr_time)]).unwrap();
        let mut reached = 0usize;
        for (_, rx) in &mut neigh {
            if rx.try_recv().is_ok() {
                reached += 1;
            }
        }
        assert!(
            (1..=2).contains(&reached),
            "one address reached {reached} neighbors"
        );
        let burst: Vec<_> = (1..1000u16)
            .map(|port| hostile_addr(port, addr_time))
            .collect();
        on_addrv2(follow, Some(peer.as_ref()), &burst).unwrap();
        for (_, rx) in &mut neigh {
            while rx.try_recv().is_ok() {}
        }
        on_addrv2(follow, Some(peer.as_ref()), &[hostile_addr(9_000, addr_time)]).unwrap();
        let mut extra_relay = 0usize;
        for (_, rx) in &mut neigh {
            if rx.try_recv().is_ok() {
                extra_relay += 1;
            }
        }
        assert_eq!(extra_relay, 0, "past the 1000-address burst nothing is relayed");

}

fn addr_flood(first_octet: u8) -> Vec<AddrV2Message> {
    (0..MAX_ADDR_TO_SEND as u32)
        .map(|i| AddrV2Message {
            time: 1_700_000_000,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(first_octet, (i >> 8) as u8, i as u8, 1)),
            port: 8333,
        })
        .collect()
}

/// Core v31.1 ADDR processing: a peer's token bucket starts at one address,
/// and an address with no token left is dropped before AddrMan, not only
/// before relay. A peer with the `addr` permission is not rate limited.
#[test]
fn addrv2_flood_is_rate_limited_before_addrman() {
    for (perm, want_learned) in [(false, 1usize), (true, MAX_ADDR_TO_SEND)] {
        let peers = rbitcoin_net::peers::PeerHub::new();
        if perm {
            let mut t = rbitcoin_net::NetPermTable::default();
            t.whitelist
                .push(rbitcoin_net::parse_whitelist("addr@127.0.0.1").unwrap());
            peers.set_net_perms(t);
        }
        let am = std::sync::Arc::new(std::sync::Mutex::new(rbitcoin_net::seeds::AddrMan::new()));
        peers.set_addrman(am.clone());
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let ver = hostile_ver(bind);
        let peer = peers.register(bind, bind, &ver, true, rbitcoin_net::peers::PeerConnType::Inbound);
        let mut follow = PeerFollowState::new();
        on_addrv2(&mut follow, Some(peer.as_ref()), &addr_flood(11)).unwrap();
        assert_eq!(
            am.lock().unwrap().len(),
            want_learned,
            "addr permission {perm}: addresses that reach AddrMan"
        );
        let info = peers
            .snapshot()
            .into_iter()
            .find(|p| p.id == peer.id)
            .expect("peer info");
        let limited = (MAX_ADDR_TO_SEND - want_learned) as u64;
        assert_eq!(
            (info.addr_processed, info.addr_rate_limited),
            (want_learned as u64, limited),
            "getpeerinfo addr counters, addr permission {perm}"
        );
    }
}

/// A full book charges each `addrv2` to the sending peer's netgroup: once
/// that group taught its share, its addresses replace nothing, inbound or
/// addr-fetch alike. A peer in another group still replaces the oldest row.
#[test]
fn addrv2_into_a_full_book_is_charged_to_the_sender_group() {
    use rbitcoin_net::peers::PeerConnType;
    use rbitcoin_net::seeds::{AddrMan, MAX_ADDR_MAN};
    let peers = rbitcoin_net::peers::PeerHub::new();
    let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let mut book = AddrMan::new();
    for i in 0..MAX_ADDR_MAN as u32 {
        let [_, b, c, d] = i.to_be_bytes();
        let row = SocketAddr::from(([11, b, c, d], 8333));
        assert!(book.add_learned(row, loopback, MAX_ADDR_MAN));
    }
    let am = std::sync::Arc::new(std::sync::Mutex::new(book));
    peers.set_addrman(am.clone());
    let ver = hostile_ver(loopback);
    let gossip = |last: u8| AddrV2Message {
        time: 1_700_000_000,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(93, 184, 216, last)),
        port: 8333,
    };
    let stored = |last: u8| {
        let row = SocketAddr::from(([93, 184, 216, last], 8333));
        am.lock().unwrap().entry_of(&rbitcoin_net::NetAddr::from_socket(row)).is_some()
    };
    let other_ip = SocketAddr::from(([203, 0, 113, 9], 40000));
    for (n, (from, conn_type, want)) in [
        (loopback, PeerConnType::Inbound, false),
        (loopback, PeerConnType::AddrFetch, false),
        (other_ip, PeerConnType::Inbound, true),
    ]
    .into_iter()
    .enumerate()
    {
        let inbound = conn_type == PeerConnType::Inbound;
        let peer = peers.register(from, loopback, &ver, inbound, conn_type);
        let mut follow = PeerFollowState::new();
        on_addrv2(&mut follow, Some(peer.as_ref()), &[gossip(n as u8)]).unwrap();
        assert_eq!(stored(n as u8), want, "{conn_type:?} from {from}");
        assert_eq!(am.lock().unwrap().len(), MAX_ADDR_MAN);
    }
}

fn regtest_child(parent: &bitcoin::block::Header, tag: u8) -> bitcoin::block::Header {
    pow_child(parent, u32::from(tag))
}

fn pow_child(parent: &bitcoin::block::Header, n: u32) -> bitcoin::block::Header {
    let mut header = *parent;
    header.prev_blockhash = parent.block_hash();
    let mut merkle = [0u8; 32];
    merkle[..4].copy_from_slice(&n.to_le_bytes());
    header.merkle_root = bitcoin::TxMerkleNode::from_byte_array(merkle);
    header.time = parent.time.saturating_add(600);
    header.bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
    header.nonce = 0;
    rbitcoin_consensus::grind_regtest_pow(&mut header);
    header
}

/// Does not connect to a header we have, and the hash misses `bits`.
/// A non-connecting header stays in the map without a store write.
fn unconnected_missing_target(n: u32) -> bitcoin::block::Header {
    let mut header = bitcoin::block::Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: n,
    };
    let mut merkle = [0u8; 32];
    merkle[..4].copy_from_slice(&n.to_le_bytes());
    header.merkle_root = bitcoin::TxMerkleNode::from_byte_array(merkle);
    let start = header.nonce;
    loop {
        if header.validate_pow(header.target()).is_err() {
            return header;
        }
        header.nonce = header.nonce.wrapping_add(1);
        assert_ne!(header.nonce, start, "regtest target rejected no nonce");
    }
}

/// Same shape as [`pow_child`], but the hash misses `bits`. No grind.
fn child_missing_target(parent: &bitcoin::block::Header, n: u32) -> bitcoin::block::Header {
    let mut header = *parent;
    header.prev_blockhash = parent.block_hash();
    let mut merkle = [0u8; 32];
    merkle[..4].copy_from_slice(&n.to_le_bytes());
    header.merkle_root = bitcoin::TxMerkleNode::from_byte_array(merkle);
    header.time = parent.time.saturating_add(600);
    header.bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
    header.nonce = n;
    let start = header.nonce;
    loop {
        if header.validate_pow(header.target()).is_err() {
            return header;
        }
        header.nonce = header.nonce.wrapping_add(1);
        assert_ne!(header.nonce, start, "regtest target rejected no nonce");
    }
}

fn pending_keys(follow: &PeerFollowState) -> HashSet<BlockHash> {
    follow.pending_headers.keys().copied().collect()
}

/// Put `headers` in the pending map. Used to reach [`MAX_PENDING_HEADERS`]
/// without a clone of that map on every header.
fn fill_pending(follow: &mut PeerFollowState, headers: &[bitcoin::block::Header]) {
    for header in headers {
        follow.pending_headers.insert(header.block_hash(), *header);
    }
}

/// Tip height for the pending-cap journeys. A one-block fork from two below
/// this tip has less work than the tip. The hostile locator journey stays at
/// height 200: its getheaders reply is the whole chain.
const CAP_TIP: u32 = 4;

fn nonconnecting_header(nonce: u32) -> bitcoin::block::Header {
    bitcoin::block::Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: BlockHash::from_byte_array([0x99; 32]),
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time: 0,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce,
    }
}

/// A peer sends full `headers` pages of non-connecting headers until the
/// pending map holds [`MAX_PENDING_HEADERS`].
async fn fill_nonconnecting_to_cap(
    hub: &ChainHub,
    out_tx: &PeerOutTx,
    follow: &mut PeerFollowState,
    peer: &rbitcoin_net::peers::LivePeer,
) {
    let headers: Vec<bitcoin::block::Header> = (0..MAX_PENDING_HEADERS as u32)
        .map(nonconnecting_header)
        .collect();
    for page in headers.chunks(MAX_HEADERS_RESULTS) {
        push(hub, out_tx, follow, Some(peer), NetworkMessage::Headers(page.to_vec())).await;
    }
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
}

/// At `MAX_PENDING_HEADERS`, a header the store will not keep must not drop
/// a non-connecting header or a fork that loses to the tip. A header the
/// store accepts still drops a losing fork and keeps one with more work.
#[tokio::test]
async fn cap_evicts_only_after_the_store_accepts() {
    use bitcoin::block::Header;
    use std::cmp::Ordering;

    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cap-evict-store");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(CAP_TIP, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP))
        .unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = hostile_ver(bind);
    let (out_tx, mut out_rx) = peer_out_channel();

    let mut above_limit = tip;
    above_limit.prev_blockhash = tip.block_hash();
    above_limit.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x11; 32]);
    above_limit.time = tip.time.saturating_add(600);
    above_limit.bits = bitcoin::CompactTarget::from_consensus(0x217f_ffff);
    above_limit.nonce = 0;
    assert!(
        above_limit.validate_pow(above_limit.target()).is_ok(),
        "a target above the pow limit still meets its own bits"
    );
    assert!(
        !hub.header_claimed_pow_ok(&above_limit),
        "pow limit rejects this target"
    );

    let mut bad_diff = tip;
    bad_diff.prev_blockhash = tip.block_hash();
    bad_diff.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x22; 32]);
    bad_diff.time = tip.time.saturating_add(600);
    bad_diff.bits = bitcoin::CompactTarget::from_consensus(0x207f_fffe);
    bad_diff.nonce = 0;
    rbitcoin_consensus::grind_regtest_pow(&mut bad_diff);
    assert!(hub.header_claimed_pow_ok(&bad_diff));
    let bad_diff_hash = bad_diff.block_hash();

    let peer = peers.register(
        bind,
        bind,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut follow = PeerFollowState::new();
    fill_nonconnecting_to_cap(&hub, &out_tx, &mut follow, &peer).await;
    let junk_hash = *follow.pending_headers.keys().next().unwrap();
    for rejected in [&above_limit, &bad_diff] {
        let before = pending_keys(&follow);
        on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[*rejected])
            .await
            .unwrap();
        assert_eq!(
            pending_keys(&follow),
            before,
            "a header the store rejects does not evict non-connecting headers"
        );
    }
    assert!(!hub.knows_header(&bad_diff_hash));
    assert!(
        !inv_asks_headers(&hub, &out_tx, &mut out_rx, &mut follow, &peer, junk_hash).await,
        "a header the store rejects evicted a non-connecting header"
    );
    let unseen = BlockHash::from_byte_array([0x5a; 32]);
    assert!(
        inv_asks_headers(&hub, &out_tx, &mut out_rx, &mut follow, &peer, unseen).await,
        "the session still asks for a header it does not hold"
    );

    let parent = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP - 1))
        .unwrap();
    // A child of genesis is not the next block's difficulty. The store
    // rejects it. A one-block fork from two below the tip has less work
    // than the tip and is a header the store keeps.
    let fork_parent = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP - 2))
        .unwrap();
    let heavier_a = regtest_child(&parent, 0xa1);
    let heavier_b = regtest_child(&heavier_a, 0xa2);
    let heavier_tip = heavier_b.block_hash();
    let mut follow = PeerFollowState::new();
    let peer = peers.register(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445),
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445),
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    on_headers(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        &[heavier_a, heavier_b],
    )
    .await
    .unwrap();
    assert_eq!(
        announced_work_cmp(&hub, &follow.pending_headers, heavier_tip),
        Some(Ordering::Greater)
    );
    let losers: Vec<Header> = (0..MAX_PENDING_HEADERS as u32 - 2)
        .map(|n| pow_child(&fork_parent, n))
        .collect();
    let loser_hash = losers[0].block_hash();
    let loser_hashes: HashSet<BlockHash> = losers.iter().map(|header| header.block_hash()).collect();
    // One sibling through the admit path. The rest fill the cap. Each
    // `on_headers` clones the whole map, and the eviction below is the
    // call under test.
    on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[losers[0]])
        .await
        .unwrap();
    fill_pending(&mut follow, &losers[1..]);
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    assert_eq!(
        announced_work_cmp(&hub, &follow.pending_headers, loser_hash),
        Some(Ordering::Less)
    );
    for rejected in [&above_limit, &bad_diff] {
        let before = pending_keys(&follow);
        on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[*rejected])
            .await
            .unwrap();
        assert_eq!(
            pending_keys(&follow),
            before,
            "a header the store rejects does not evict a losing fork"
        );
    }
    assert!(follow.pending_headers.contains_key(&heavier_tip));
    assert!(follow.pending_headers.contains_key(&loser_hash));

    let accepted = regtest_child(&tip, 0xb1);
    let accepted_hash = accepted.block_hash();
    take_msgs(&mut out_rx);
    on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[accepted])
        .await
        .unwrap();
    assert!(asked_blocks(&mut out_rx).contains(&accepted_hash));
    assert!(follow.pending_headers.contains_key(&heavier_tip));
    let dropped = loser_hashes
        .iter()
        .filter(|hash| !follow.pending_headers.contains_key(*hash))
        .count();
    assert_eq!(
        dropped, 1,
        "an accepted header drops one fork with less work"
    );
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    assert!(hub.knows_header(&accepted_hash));
}

/// Children of the tip have more work than the tip, so a full map of them
/// must still take one more. A longer fork than that child stays.
#[tokio::test]
async fn cap_accepts_the_next_header_when_equal_work_fills_the_map() {
    use std::cmp::Ordering;

    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cap-evict-equal");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(CAP_TIP, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP))
        .unwrap();
    let parent = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP - 1))
        .unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = hostile_ver(bind);
    let (out_tx, mut out_rx) = peer_out_channel();
    let peer = peers.register(
        bind,
        bind,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let heavy_a = regtest_child(&parent, 0xc1);
    let heavy_b = regtest_child(&heavy_a, 0xc2);
    let heavy_c = regtest_child(&heavy_b, 0xc3);
    let heavy = heavy_c.block_hash();
    let mut follow = PeerFollowState::new();
    on_headers(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        &[heavy_a, heavy_b, heavy_c],
    )
    .await
    .unwrap();
    let siblings: Vec<_> = (0..MAX_PENDING_HEADERS as u32 - 3)
        .map(|n| pow_child(&tip, n))
        .collect();
    let sibling_hashes: HashSet<BlockHash> =
        siblings.iter().map(|header| header.block_hash()).collect();
    // Siblings are not one chain, so a batch would keep only its last header.
    // One goes through `on_headers`. The rest fill the cap. The calls below
    // are what evict.
    on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[siblings[0]])
        .await
        .unwrap();
    fill_pending(&mut follow, &siblings[1..]);
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    let sibling_hash = siblings[0].block_hash();
    assert_eq!(
        announced_work_cmp(&hub, &follow.pending_headers, sibling_hash),
        Some(Ordering::Greater),
        "a child of the tip has more work than the tip"
    );
    assert_eq!(
        announced_work_cmp(&hub, &follow.pending_headers, heavy),
        Some(Ordering::Greater)
    );

    let next = pow_child(&tip, 9_000_000);
    let next_hash = next.block_hash();
    take_msgs(&mut out_rx);
    on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[next])
        .await
        .unwrap();
    assert!(hub.knows_header(&next_hash));
    assert!(
        asked_blocks(&mut out_rx).contains(&next_hash),
        "a full map of tip children still asks for the next block"
    );
    assert!(follow.pending_headers.contains_key(&heavy));
    let dropped = sibling_hashes
        .iter()
        .filter(|hash| !follow.pending_headers.contains_key(*hash))
        .count();
    assert_eq!(dropped, 1, "one equal-work sibling makes the slot");
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);

    let grand = pow_child(&next, 9_000_001);
    let grand_hash = grand.block_hash();
    on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[grand])
        .await
        .unwrap();
    assert!(follow.pending_headers.contains_key(&grand_hash));
    assert!(
        follow.pending_headers.contains_key(&next_hash),
        "the parent of the new header stays"
    );
    assert!(follow.pending_headers.contains_key(&heavy));
    let dropped = sibling_hashes
        .iter()
        .filter(|hash| !follow.pending_headers.contains_key(*hash))
        .count();
    assert_eq!(
        dropped, 2,
        "the grandchild drops one more sibling and leaves the longer fork"
    );
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    assert_eq!(
        work_of_header_path(&hub, &follow.pending_headers, grand_hash),
        work_of_header_path(&hub, &follow.pending_headers, heavy),
        "the three-header fork matches the grandchild"
    );
}

/// Headers that miss their target and do not connect fill the map without a
/// grind. One of them makes room for a header that meets the target. A
/// connecting header that misses its target is not inserted.
#[tokio::test]
async fn cap_accepts_the_next_header_when_failed_pow_fills_the_map() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cap-evict-pow");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(CAP_TIP, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP))
        .unwrap();
    let parent = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP - 1))
        .unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = hostile_ver(bind);
    let (out_tx, mut out_rx) = peer_out_channel();
    let peer = peers.register(
        bind,
        bind,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let heavy_a = regtest_child(&parent, 0xd1);
    let heavy_b = regtest_child(&heavy_a, 0xd2);
    let heavy_c = regtest_child(&heavy_b, 0xd3);
    let heavy = heavy_c.block_hash();
    let mut follow = PeerFollowState::new();
    on_headers(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        &[heavy_a, heavy_b, heavy_c],
    )
    .await
    .unwrap();
    let missed = child_missing_target(&tip, 0);
    let missed_hash = missed.block_hash();
    on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[missed])
        .await
        .unwrap();
    assert!(
        !follow.pending_headers.contains_key(&missed_hash),
        "a connecting header that misses its target was inserted"
    );
    assert_eq!(follow.pending_headers.len(), 3);
    let sample = unconnected_missing_target(0);
    assert!(
        !hub.header_claimed_pow_ok(&sample),
        "the filler misses its target"
    );
    let fillers: Vec<_> = (0..MAX_PENDING_HEADERS as u32 - 3)
        .map(unconnected_missing_target)
        .collect();
    let filler_hashes: HashSet<BlockHash> =
        fillers.iter().map(|header| header.block_hash()).collect();
    // One filler through the admit path. The rest are the same headers.
    // The successor below is the eviction under test.
    on_headers(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        &[fillers[0]],
    )
    .await
    .unwrap();
    assert!(
        follow
            .pending_headers
            .contains_key(&fillers[0].block_hash()),
        "a header that misses its target was not admitted"
    );
    fill_pending(&mut follow, &fillers[1..]);
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    assert!(follow.pending_headers.contains_key(&heavy));

    let next = pow_child(&tip, 9_000_000);
    let next_hash = next.block_hash();
    take_msgs(&mut out_rx);
    on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[next])
        .await
        .unwrap();
    assert!(
        asked_blocks(&mut out_rx).contains(&next_hash),
        "a valid successor was refused"
    );
    assert!(follow.pending_headers.contains_key(&heavy));
    let dropped = filler_hashes
        .iter()
        .filter(|hash| !follow.pending_headers.contains_key(*hash))
        .count();
    assert_eq!(dropped, 1, "one header that misses its target makes the slot");
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    assert!(hub
        .query
        .get_header_by_hash(&next_hash.to_byte_array())
        .unwrap()
        .is_some());
}

/// One new header repeated for a whole `headers` message needs one slot.
#[tokio::test]
async fn cap_counts_one_repeated_header() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cap-evict-repeat");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(CAP_TIP, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = hostile_ver(bind);
    let (out_tx, mut out_rx) = peer_out_channel();
    let peer = peers.register(
        bind,
        bind,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut follow = PeerFollowState::new();
    fill_nonconnecting_to_cap(&hub, &out_tx, &mut follow, &peer).await;
    let before = pending_keys(&follow);
    let mut next = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP))
        .unwrap();
    next.prev_blockhash = hub.tip_hash().unwrap();
    next.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x61; 32]);
    next.time = next.time.saturating_add(600);
    next.nonce = 0;
    rbitcoin_consensus::grind_regtest_pow(&mut next);
    let next_hash = next.block_hash();
    let repeated = vec![next; MAX_HEADERS_RESULTS];
    take_msgs(&mut out_rx);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        NetworkMessage::Headers(repeated),
    )
    .await;
    assert!(hub.knows_header(&next_hash));
    assert!(
        asked_blocks(&mut out_rx).contains(&next_hash),
        "the repeated header was refused"
    );
    let dropped = before
        .iter()
        .filter(|hash| !follow.pending_headers.contains_key(*hash))
        .count();
    assert_eq!(dropped, 1, "one repeated header takes one slot");
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
}

fn bad_diffbits_child(tip: &bitcoin::block::Header) -> bitcoin::block::Header {
    let mut header = *tip;
    header.prev_blockhash = tip.block_hash();
    header.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x22; 32]);
    header.time = tip.time.saturating_add(600);
    header.bits = bitcoin::CompactTarget::from_consensus(0x207f_fffe);
    header.nonce = 0;
    rbitcoin_consensus::grind_regtest_pow(&mut header);
    header
}

/// Whether a block `inv` for `hash` makes the node send `getheaders`. A node
/// that holds the header, stored or waiting for its parent, asks for nothing.
/// Only the first block `inv` for an unheld hash is answered per session. A
/// held hash does not use that one ask, so a probe for an unseen hash can
/// follow it.
async fn inv_asks_headers(
    hub: &ChainHub,
    out_tx: &PeerOutTx,
    out_rx: &mut PeerOutRx,
    follow: &mut PeerFollowState,
    peer: &rbitcoin_net::peers::LivePeer,
    hash: BlockHash,
) -> bool {
    take_msgs(out_rx);
    push(
        hub,
        out_tx,
        follow,
        Some(peer),
        NetworkMessage::Inv(vec![Inventory::Block(hash)]),
    )
    .await;
    take_msgs(out_rx)
        .iter()
        .any(|msg| matches!(msg, NetworkMessage::GetHeaders(_)))
}

/// A peer announces a valid tip child, then a sibling the store rejects for
/// `bad-diffbits`. The node does not store or ask for the sibling, keeps the
/// body ask it already sent, and still does not know the sibling's hash.
/// Harder regtest bits would otherwise outrank the next valid header.
#[tokio::test]
async fn cap_store_kept_headers_skip_a_rejected_tip_child() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cap-evict-reject");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(CAP_TIP, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP))
        .unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = hostile_ver(bind);
    let (out_tx, mut out_rx) = peer_out_channel();
    let peer = peers.register(
        bind,
        bind,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut follow = PeerFollowState::new();
    let good = pow_child(&tip, 0x44);
    let good_hash = good.block_hash();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        NetworkMessage::Headers(vec![good]),
    )
    .await;
    assert_eq!(
        asked_blocks(&mut out_rx),
        vec![good_hash],
        "a valid tip child is asked for"
    );

    let bad = bad_diffbits_child(&tip);
    assert!(hub.header_claimed_pow_ok(&bad));
    let bad_hash = bad.block_hash();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        NetworkMessage::Headers(vec![bad]),
    )
    .await;
    assert!(!hub.knows_header(&bad_hash));
    assert!(
        asked_blocks(&mut out_rx).is_empty(),
        "a rejected header was asked for"
    );
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        NetworkMessage::Headers(vec![good]),
    )
    .await;
    assert!(
        asked_blocks(&mut out_rx).is_empty(),
        "a rejected header dropped the ask in flight, so it was sent again"
    );
    assert!(
        inv_asks_headers(&hub, &out_tx, &mut out_rx, &mut follow, &peer, bad_hash).await,
        "a header the store rejects was held for its parent"
    );
}

/// The last header of a message can be stored while an earlier hash is not
/// on that walk. Only the stored hash is admitted. A full map still drops
/// enough stale headers for that one hash.
#[tokio::test]
async fn cap_store_kept_headers_skip_an_earlier_hash() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cap-evict-walk");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(CAP_TIP, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP))
        .unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = hostile_ver(bind);
    let (out_tx, mut out_rx) = peer_out_channel();
    let peer = peers.register(
        bind,
        bind,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut follow = PeerFollowState::new();
    fill_nonconnecting_to_cap(&hub, &out_tx, &mut follow, &peer).await;
    let before = pending_keys(&follow);
    let side = pow_child(&tip, 0x51);
    let accepted = pow_child(&tip, 0x52);
    let side_hash = side.block_hash();
    let accepted_hash = accepted.block_hash();
    take_msgs(&mut out_rx);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        NetworkMessage::Headers(vec![side, accepted]),
    )
    .await;
    assert!(!hub.knows_header(&side_hash));
    assert!(hub.knows_header(&accepted_hash));
    assert_eq!(asked_blocks(&mut out_rx), vec![accepted_hash]);
    assert!(
        inv_asks_headers(&hub, &out_tx, &mut out_rx, &mut follow, &peer, side_hash).await,
        "an earlier header the store never saw was held for its parent"
    );
    let dropped = before
        .iter()
        .filter(|hash| !follow.pending_headers.contains_key(*hash))
        .count();
    assert_eq!(dropped, 1, "only the stored header takes a slot");
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
}

/// The last header is already in the store, so this call writes nothing.
/// Proof-of-work headers in front of it must not clear the map.
#[tokio::test]
async fn cap_already_stored_tip_frees_no_slot() {
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cap-evict-stored-tip");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(CAP_TIP, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(CAP_TIP))
        .unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = hostile_ver(bind);
    let (out_tx, mut out_rx) = peer_out_channel();
    let peer = peers.register(
        bind,
        bind,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut follow = PeerFollowState::new();
    fill_nonconnecting_to_cap(&hub, &out_tx, &mut follow, &peer).await;
    let before = pending_keys(&follow);
    let front: Vec<Header> = (0..2u32).map(|n| pow_child(&tip, 0x70 + n)).collect();
    let front_hashes: Vec<BlockHash> = front.iter().map(|h| h.block_hash()).collect();
    let mut message = front;
    message.push(tip);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        NetworkMessage::Headers(message),
    )
    .await;
    for hash in &front_hashes {
        assert!(!hub.knows_header(hash));
    }
    assert!(
        inv_asks_headers(&hub, &out_tx, &mut out_rx, &mut follow, &peer, front_hashes[0]).await,
        "a header in front of the stored tip was held for its parent"
    );
    let dropped = before
        .iter()
        .filter(|hash| !follow.pending_headers.contains_key(*hash))
        .count();
    assert_eq!(dropped, 0, "an already-stored last header frees no slot");
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
}

/// An empty `headers` answers our getheaders without a header job, so with
/// every ctrl-decode permit held it still finishes.
#[test]
fn empty_headers_takes_no_header_permit() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("empty-headers");
    let hub = rbitcoin_net::ChainHub::into_arc(hub);
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
    let peer = peers.register(
        bind,
        bind,
        &hostile_ver(bind),
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (out_tx, _out_rx) = peer.open_out();
    let mut follow = PeerFollowState::new();
    peer.note_awaiting_headers();
    let sem = Arc::clone(rbitcoin_net::msg_decode::ctrl_decode_semaphore());
    let all = u32::try_from(rbitcoin_net::msg_decode::ctrl_decode_permits()).unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("headers runtime")
        .block_on(async {
            let held = sem
                .acquire_many_owned(all)
                .await
                .expect("hold every permit");
            let headers = on_headers(&hub, &out_tx, &mut follow, Some(&peer), &[]);
            tokio::time::timeout(Duration::from_secs(10), headers)
                .await
                .expect("an empty headers takes no header permit")
                .expect("empty headers");
            drop(held);
        });
    assert!(!peer.is_awaiting_headers());
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `ProcessAddrs` relays an `addrv2` only when the incoming message
/// carries at most 10 addresses, even when rate limiting leaves <= 10 rows;
/// larger messages still feed `AddrMan` up to the token budget.
#[test]
fn addrv2_relay_respects_the_ten_address_message_cap() {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use bitcoin::p2p::address::{AddrV2, AddrV2Message};
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_net::peer::on_addrv2;
    use rbitcoin_net::peers::PeerConnType;
    use rbitcoin_net::send_queue::PeerOutRx;
    use rbitcoin_net::NetAddr;

    let t0 = 1_700_000_000u64;
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(t0);
    let book = Arc::new(Mutex::new(rbitcoin_net::seeds::AddrMan::new()));
    peers.set_addrman(Arc::clone(&book));

    let reg = |octet: u8| {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)), 8333);
        let peer = peers.register(addr, addr, &hostile_ver(addr), true, PeerConnType::Inbound);
        peer.set_wants_addrv2();
        peer
    };
    let src = reg(1);
    let n1 = reg(2);
    let n2 = reg(3);
    let (_n1_tx, mut rx1) = n1.open_out();
    let (_n2_tx, mut rx2) = n2.open_out();
    while rx1.try_recv().is_ok() {}
    while rx2.try_recv().is_ok() {}

    // Refill `src` well past 11 tokens so rate limiting does not trim the list.
    let now = t0 + 500;
    peers.set_mock_now(now);
    let row = |b: u8, c: u8, time: u64| AddrV2Message {
        time: time as u32,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(b, 2, 3, c)),
        port: 8333,
    };
    let drain_relayed = |a: &mut PeerOutRx, b: &mut PeerOutRx| {
        let mut got = HashSet::new();
        for rx in [a, b] {
            while let Ok(out) = rx.try_recv() {
                if let NetworkMessage::AddrV2(rows) = out.expect_msg() {
                    for r in rows {
                        if let Some(net) = NetAddr::from_addrv2(&r) {
                            got.insert(net);
                        }
                    }
                }
            }
        }
        got
    };
    let mut follow = PeerFollowState::new();

    let eleven: Vec<_> = (1..=11).map(|c| row(1, c, now - 60)).collect();
    on_addrv2(&mut follow, Some(src.as_ref()), &eleven).unwrap();
    assert!(
        drain_relayed(&mut rx1, &mut rx2).is_empty(),
        "an 11-address message must not relay"
    );
    for c in 1..=11 {
        let net: NetAddr = format!("1.2.3.{c}:8333").parse().unwrap();
        assert!(
            book.lock().unwrap().last_seen_of(&net) > 0,
            "oversized-for-relay {net} must still enter AddrMan"
        );
    }

    let ten: Vec<_> = (1..=10).map(|c| row(2, c, now - 60)).collect();
    on_addrv2(&mut follow, Some(src.as_ref()), &ten).unwrap();
    let relayed_ten = drain_relayed(&mut rx1, &mut rx2);
    assert_eq!(relayed_ten.len(), 10, "a 10-address message relays all 10: {relayed_ten:?}");

    // A fresh peer starts with 1 token; sending 11 addresses processes 1 row,
    // which still must not relay because `list.len() > 10`.
    let limited = reg(4);
    let mut follow_limited = PeerFollowState::new();
    let limited_eleven: Vec<_> = (1..=11).map(|c| row(3, c, now - 60)).collect();
    on_addrv2(&mut follow_limited, Some(limited.as_ref()), &limited_eleven).unwrap();
    assert!(
        drain_relayed(&mut rx1, &mut rx2).is_empty(),
        "rate limiting 11 rows down to 1 must still suppress relay"
    );
    let first_limited: NetAddr = "3.2.3.1:8333".parse().unwrap();
    assert!(
        book.lock().unwrap().last_seen_of(&first_limited) > 0,
        "token-admitted row from 11-entry message still enters AddrMan"
    );
}

/// Core `ProcessAddrs` relays a row only when `addr.time > now - 600`; rows
/// at or before `now - 600` (including sanitized insane times) still enter
/// `AddrMan` but are not relayed.
#[test]
fn addrv2_relay_requires_timestamp_strictly_within_ten_minutes() {
    use std::sync::Mutex;

    use bitcoin::p2p::address::{AddrV2, AddrV2Message};
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_net::peer::on_addrv2;
    use rbitcoin_net::peers::PeerConnType;
    use rbitcoin_net::send_queue::PeerOutRx;
    use rbitcoin_net::NetAddr;

    let t0 = 1_700_000_000u64;
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(t0);
    let book = Arc::new(Mutex::new(rbitcoin_net::seeds::AddrMan::new()));
    peers.set_addrman(Arc::clone(&book));

    let reg = |octet: u8| {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 1, octet)), 8333);
        let peer = peers.register(addr, addr, &hostile_ver(addr), true, PeerConnType::Inbound);
        peer.set_wants_addrv2();
        peer
    };
    let src = reg(1);
    let dst = reg(2);
    let (_dst_tx, mut dst_rx) = dst.open_out();
    while dst_rx.try_recv().is_ok() {}

    let now = t0 + 1_000;
    peers.set_mock_now(now);
    let row = |c: u8, time: u64| AddrV2Message {
        time: time as u32,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(Ipv4Addr::new(4, 2, 3, c)),
        port: 8333,
    };
    let drain = |rx: &mut PeerOutRx| {
        let mut rows = Vec::new();
        while let Ok(out) = rx.try_recv() {
            if let NetworkMessage::AddrV2(batch) = out.expect_msg() {
                rows.extend(batch);
            }
        }
        rows
    };
    let mut follow = PeerFollowState::new();

    for (c, time, label) in [
        (1u8, now - 600, "exact 10-minute boundary"),
        (2, now - 3_600, "one hour old"),
        (3, 100_000_000, "floor timestamp backdated to 5 days ago"),
    ] {
        on_addrv2(&mut follow, Some(src.as_ref()), &[row(c, time)]).unwrap();
        let relayed = drain(&mut dst_rx);
        assert!(
            relayed.is_empty(),
            "{label} (time={time}, now={now}) must not relay: {relayed:?}"
        );
        let net: NetAddr = format!("4.2.3.{c}:8333").parse().unwrap();
        assert!(
            book.lock().unwrap().last_seen_of(&net) > 0,
            "{label} must still enter AddrMan"
        );
    }

    on_addrv2(&mut follow, Some(src.as_ref()), &[row(4, now - 599)]).unwrap();
    let relayed = drain(&mut dst_rx);
    assert_eq!(relayed.len(), 1, "now - 599 must relay: {relayed:?}");
    assert_eq!(relayed[0].time, (now - 599) as u32);

    // Mixed small message relays only rows strictly within 10 minutes.
    let mixed = [row(5, now - 601), row(6, now - 300), row(7, now + 3_600)];
    on_addrv2(&mut follow, Some(src.as_ref()), &mixed).unwrap();
    let relayed = drain(&mut dst_rx);
    assert_eq!(relayed.len(), 1, "only fresh row relays from mixed list: {relayed:?}");
    assert_eq!(
        NetAddr::from_addrv2(&relayed[0]),
        Some("4.2.3.6:8333".parse().unwrap())
    );
}
