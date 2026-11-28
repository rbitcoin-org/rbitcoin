use rbitcoin_net::netaddr::ExternalEndpoint;
fn work_floor(low: u8) -> [u8; 32] {
    let mut min = [0u8; 32];
    min[31] = low;
    min
}

fn side_tips(hub: &rbitcoin_net::chain::ChainHub) -> usize {
    hub.chaintips()
        .iter()
        .filter(|t| t.status != "active")
        .count()
}

fn asked_blocks(rx: &mut PeerOutRx) -> Vec<BlockHash> {
    getdata_of(&take_msgs(rx))
        .into_iter()
        .map(|(hash, _)| hash)
        .collect()
}

fn zero_stop() -> BlockHash {
    BlockHash::from_byte_array([0u8; 32])
}

async fn push(
    hub: &rbitcoin_net::chain::ChainHub,
    out_tx: &PeerOutTx,
    follow: &mut PeerFollowState,
    session: Option<&rbitcoin_net::peers::LivePeer>,
    msg: NetworkMessage,
) {
    handle_peer_frame(frame_for(msg), hub, out_tx, follow, session)
        .await
        .unwrap();
}

fn orphan_body(prev: BlockHash, nonce: u32) -> bitcoin::Block {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::from_bytes(vec![0x01, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: op_true(),
        }],
    };
    let mut block = bitcoin::Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce,
        },
        txdata: vec![coinbase],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    block
}

/// A captured line at DEBUG that contains `needle`.
fn debug_logged(logs: &[(rbitcoin_log::Level, String)], needle: &str) -> bool {
    logs.iter()
        .any(|(level, msg)| *level == rbitcoin_log::Level::Debug && msg.contains(needle))
}

fn logs_have(needle: &str) -> bool {
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    logs.iter().any(|(_, msg)| msg.contains(needle))
}

/// Core `LogDebug(BCLog::NET, ...)`: a repeated `version` is a debug line
/// and keeps the session.
async fn redundant_version_is_a_debug_line(
    hub: &rbitcoin_net::chain::ChainHub,
    out_tx: &PeerOutTx,
    follow: &mut PeerFollowState,
    sess: &std::sync::Arc<rbitcoin_net::peers::LivePeer>,
) {
    rbitcoin_log::capture_logs(true);
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    push(
        hub,
        out_tx,
        follow,
        Some(sess.as_ref()),
        NetworkMessage::Version(hostile_ver(addr)),
    )
    .await;
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        debug_logged(&logs, "redundant version message"),
        "redundant version is a debug line: {logs:?}"
    );
    assert_eq!(follow.ban_score, 0, "redundant version must not disconnect");
}

/// A received addrv2 is a debug line (Core `LogDebug(BCLog::NET,
/// "received: ...")`). Logs stay captured for the caller.
async fn received_addrv2_is_a_debug_line(
    hub: &rbitcoin_net::chain::ChainHub,
    out_tx: &PeerOutTx,
    follow: &mut PeerFollowState,
    sess: &std::sync::Arc<rbitcoin_net::peers::LivePeer>,
) {
    use bitcoin::p2p::address::AddrV2;
    let one = vec![bitcoin::p2p::address::AddrV2Message {
        time: 1_700_000_000,
        services: ServiceFlags::NETWORK,
        addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(123, 123, 123, 2)),
        port: 8333,
    }];
    push(
        hub,
        out_tx,
        follow,
        Some(sess.as_ref()),
        NetworkMessage::AddrV2(one),
    )
    .await;
    let logs = rbitcoin_log::take_logs();
    assert!(
        debug_logged(&logs, "received: addrv2"),
        "a received addrv2 is a debug line: {logs:?}"
    );
}

/// wtxidrelay and sendaddrv2 before verack stick. Ping is logged. A second
/// verack is ignored. sendaddrv2 and an oversized addrv2 after verack disconnect.
async fn handshake_verack_and_addrv2(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::p2p::address::AddrV2;
    assert_eq!(
        rbitcoin_net::peer::sendaddrv2_after_verack_log(0),
        "sendaddrv2 received after verack, disconnecting peer=0"
    );
    assert_eq!(
        rbitcoin_net::peer::addrv2_message_size_log(1010),
        "addrv2 message size = 1010"
    );

    let sess = live_peer(peers, 18444, 1, true);
    assert_eq!(sess.id, 0, "first peer is the verack log's peer=0");

    rbitcoin_log::capture_logs(true);
    let done = apply_pre_verack(
        Some(sess.as_ref()),
        70016,
        &NetworkMessage::WtxidRelay,
        "wtxidrelay",
    );
    assert!(!done, "wtxidrelay is not verack");
    assert!(sess.wtxid_relay(), "wtxidrelay before verack must stick");
    assert!(
        !logs_have("Unsupported message \"wtxidrelay\""),
        "wtxidrelay before verack stays silent"
    );

    rbitcoin_log::capture_logs(true);
    let done = apply_pre_verack(
        Some(sess.as_ref()),
        70016,
        &NetworkMessage::SendAddrV2,
        "sendaddrv2",
    );
    assert!(!done);
    assert!(sess.wants_addrv2());
    assert!(
        !logs_have("Unsupported message \"sendaddrv2\""),
        "sendaddrv2 before verack stays silent"
    );

    rbitcoin_log::capture_logs(true);
    let done = apply_pre_verack(Some(sess.as_ref()), 70016, &NetworkMessage::Ping(1), "ping");
    assert!(!done);
    assert!(
        logs_have("Unsupported message \"ping\" prior to verack"),
        "ping before verack still logs"
    );
    assert!(apply_pre_verack(
        Some(sess.as_ref()),
        70016,
        &NetworkMessage::Verack,
        "verack"
    ));

    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    rbitcoin_log::capture_logs(true);
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::Verack,
    )
    .await;
    // Core `LogDebug(BCLog::NET, ...)`: a repeated handshake message is a
    // debug line, not an INFO line a peer can flood.
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        debug_logged(&logs, "ignoring redundant verack message"),
        "redundant verack is a debug line: {logs:?}"
    );
    assert_eq!(follow.ban_score, 0, "redundant verack must not disconnect");

    redundant_version_is_a_debug_line(hub, &out_tx, &mut follow, &sess).await;

    rbitcoin_log::capture_logs(true);
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::SendAddrV2,
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "post-verack sendaddrv2 must disconnect"
    );
    assert!(
        logs_have("sendaddrv2 received after verack, disconnecting peer=0"),
        "sendaddrv2 after verack names the peer"
    );

    let addrs = (0..1010u16)
        .map(|i| bitcoin::p2p::address::AddrV2Message {
            time: 1_700_000_000,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(123, 123, 123, 1)),
            port: 8333 + i,
        })
        .collect();
    follow.ban_score = 0;
    // Core logs a received addrv2 and its size refusal at debug, and the
    // oversized list is refused before it is measured.
    rbitcoin_log::capture_logs(true);
    received_addrv2_is_a_debug_line(hub, &out_tx, &mut follow, &sess).await;
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::AddrV2(addrs),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "oversized addrv2 must disconnect"
    );
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        debug_logged(&logs, "addrv2 message size = 1010"),
        "oversized addrv2 logs the count at debug: {logs:?}"
    );
    assert!(
        !logs.iter().any(|(_, m)| m.contains("received: addrv2")),
        "an oversized addrv2 is refused before it is measured: {logs:?}"
    );
}

/// An addr reply of 1000 to an addr-fetch session is not misbehavior, and
/// 1001 is. A `sendcmpct` announce byte of 2 and a `getdata` for a filtered
/// block while NODE_BLOOM is off disconnect. With no mempool, a tx `getdata`
/// gets no reply.
async fn wire_caps_one_past_disconnect(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use rbitcoin_net::peers::PeerConnType;
    let (out_tx, mut out_rx) = peer_out_channel();

    let fetch = live_peer_as(peers, 18601, 601, PeerConnType::AddrFetch);
    let sock = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 8333);
    let addrs = |n: usize| vec![(1_700_000_000u32, Address::new(&sock, ServiceFlags::NETWORK)); n];
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(fetch.as_ref()),
        NetworkMessage::Addr(addrs(MAX_ADDR_TO_SEND)),
    )
    .await;
    // An addr-fetch session ends after any reply of more than one address,
    // so the 1000 reply ends this session too. It is not misbehavior.
    assert_eq!(
        follow.ban_score, 0,
        "wire cap: an addr reply of exactly 1000 is not misbehavior"
    );
    let over = live_peer_as(peers, 18606, 606, PeerConnType::AddrFetch);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(over.as_ref()),
        NetworkMessage::Addr(addrs(MAX_ADDR_TO_SEND + 1)),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "wire cap: an addr reply of 1001 is misbehavior"
    );

    let sess = live_peer(peers, 18603, 603, true);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::Unknown {
            command: bitcoin::p2p::message::CommandString::try_from("sendcmpct").unwrap(),
            payload: vec![2, 2, 0, 0, 0, 0, 0, 0, 0],
        },
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "wire cap: a sendcmpct announce byte of 2 disconnects"
    );

    let sess = live_peer(peers, 18604, 604, true);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::GetData(vec![Inventory::Unknown {
            inv_type: 3,
            hash: [0; 32],
        }]),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "wire cap: getdata for a filtered block disconnects while NODE_BLOOM is off"
    );

    // This hub has no mempool, so it has no transaction to be missing.
    let _ = take_msgs(&mut out_rx);
    let sess = live_peer(peers, 18605, 605, true);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::GetData(vec![Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(
            [5; 32],
        ))]),
    )
    .await;
    assert!(
        take_msgs(&mut out_rx).is_empty(),
        "wire cap: a node without a mempool answers a tx getdata with nothing, not notfound"
    );
}

/// A `getblocks` locator of 101 hashes is answered with an `inv` of the
/// blocks after the fork point. 102 hashes disconnect.
async fn getblocks_locator_cap(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip = hub.tip_height().unwrap();
    assert!(tip >= 1, "the locator cap beat needs blocks after genesis");
    let genesis = header_at(hub, 0).block_hash();
    let locator = |n: usize| -> Vec<BlockHash> {
        (0..n)
            .map(|i| BlockHash::from_byte_array([i as u8 + 1; 32]))
            .chain(std::iter::once(genesis))
            .collect()
    };
    let (out_tx, mut out_rx) = peer_out_channel();
    let sess = live_peer(peers, 18602, 602, true);
    let mut follow = PeerFollowState::new();
    let inv_hashes = |msgs: Vec<NetworkMessage>| -> Vec<BlockHash> {
        msgs.into_iter()
            .filter_map(|m| match m {
                NetworkMessage::Inv(inv) => Some(inv),
                _ => None,
            })
            .flatten()
            .filter_map(|i| match i {
                Inventory::Block(h) | Inventory::WitnessBlock(h) => Some(h),
                _ => None,
            })
            .collect()
    };
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(locator(MAX_LOCATOR_SZ - 1), zero_stop())),
    )
    .await;
    assert_eq!(
        follow.ban_score, 0,
        "wire cap: a getblocks locator of 101 hashes is not misbehavior"
    );
    let served = inv_hashes(take_msgs(&mut out_rx));
    let expected: Vec<BlockHash> = (1..=tip).map(|h| header_at(hub, h).block_hash()).collect();
    assert_eq!(
        served, expected,
        "wire cap: a getblocks locator of 101 hashes gets an inv of every block after genesis"
    );

    // A zero hash is not a known block. Core's FindForkInGlobalIndex skips
    // it, so the known hash after it is the fork point.
    let mid = tip / 2;
    let mid_hash = header_at(hub, mid).block_hash();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(
            vec![BlockHash::from_byte_array([0u8; 32]), mid_hash],
            zero_stop(),
        )),
    )
    .await;
    let served = inv_hashes(take_msgs(&mut out_rx));
    let expected: Vec<BlockHash> = (mid + 1..=tip)
        .map(|h| header_at(hub, h).block_hash())
        .collect();
    assert_eq!(
        served, expected,
        "a zero locator hash is skipped; the next known hash is the fork point"
    );

    // No known hash: Core falls back to genesis and serves from after it,
    // never genesis itself.
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(
            vec![BlockHash::from_byte_array([0xee; 32])],
            zero_stop(),
        )),
    )
    .await;
    let served = inv_hashes(take_msgs(&mut out_rx));
    let expected: Vec<BlockHash> = (1..=tip).map(|h| header_at(hub, h).block_hash()).collect();
    assert_eq!(
        served, expected,
        "an unknown locator is answered from after genesis"
    );
    assert!(
        !served.contains(&genesis),
        "genesis is never served for a non-empty locator"
    );
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(sess.as_ref()),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(locator(MAX_LOCATOR_SZ), zero_stop())),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "wire cap: a getblocks locator of 102 hashes disconnects"
    );
}

/// Unknown-parent bodies and compacts stay header-only. A requested body is parked.
async fn unknown_parent_bodies(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    let peer = live_peer(peers, 18450, 2, false);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let block = orphan_body(BlockHash::from_byte_array([0xab; 32]), 0);
    let hash = block.block_hash();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Block(block),
    )
    .await;
    assert!(
        peer.stop.load(Ordering::SeqCst),
        "unsolicited unknown-parent body must disconnect"
    );
    assert!(
        !hub.knows_header(&hash),
        "unsolicited unknown-parent must not persist"
    );
    assert!(
        out_rx.try_recv().is_err(),
        "unsolicited unknown-parent must not getheaders"
    );

    let peer = live_peer(peers, 18451, 3, false);
    peer.note_awaiting_headers();
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let block = orphan_body(BlockHash::from_byte_array([0xab; 32]), 0);
    let hash = block.block_hash();
    follow.requested_blocks.ask(hub, hash);
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Block(block),
    )
    .await;
    assert!(
        !peer.stop.load(Ordering::SeqCst),
        "requested unknown-parent body must keep the session"
    );
    assert!(!hub.knows_header(&hash));
    let msg = out_rx.try_recv().expect("getheaders").expect_msg();
    assert!(
        matches!(msg, NetworkMessage::GetHeaders(_)),
        "requested unknown-parent body must getheaders, got {msg:?}"
    );
    assert!(
        follow.pending_blocks.contains_key(&hash),
        "requested unknown-parent body stays parked"
    );

    let peer = live_peer(peers, 18452, 4, false);
    peer.note_awaiting_headers();
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    let mut block = orphan_body(BlockHash::from_byte_array([0xcd; 32]), 0);
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        }),
    )
    .await;
    assert!(!peer.stop.load(Ordering::SeqCst));
    assert!(hub
        .query
        .get_header_by_hash(&block.block_hash().to_byte_array())
        .unwrap()
        .is_none());
    assert!(
        hub.held_body(&block.block_hash()).is_none()
            && !follow.pending_blocks.contains_key(&block.block_hash()),
        "unknown-parent compact is header-only"
    );
    assert!(follow.pending_headers.contains_key(&block.block_hash()));
    let msgs = take_msgs(&mut out_rx);
    assert!(
        msgs.iter()
            .any(|m| matches!(m, NetworkMessage::GetHeaders(_))),
        "unknown-parent compact must getheaders despite awaiting, got {msgs:?}"
    );
    peer.note_awaiting_headers();
    let mut child = block.clone();
    child.header.prev_blockhash = block.block_hash();
    child.header.merkle_root = child.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut child.header);
    let child_hsi = HeaderAndShortIds::from_block(&child, 1, 2, &[0]).unwrap();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: child_hsi,
        }),
    )
    .await;
    assert!(hub
        .query
        .get_header_by_hash(&child.block_hash().to_byte_array())
        .unwrap()
        .is_none());
    assert!(follow.pending_headers.contains_key(&child.block_hash()));
}

fn getheaders_count(rx: &mut PeerOutRx) -> usize {
    take_msgs(rx)
        .iter()
        .filter(|m| matches!(m, NetworkMessage::GetHeaders(_)))
        .count()
}

/// Core `p2p_sendheaders` parts 5b and 5c. An unconnecting header is not a
/// reply to our getheaders: it asks again only once an empty headers message
/// answered, or `HEADERS_RESPONSE_TIME` passed. A full batch continues from
/// its last hash. A long pending chain is walked from RAM back to genesis.
async fn header_flood_and_pending_walk(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};

    let start = 1_700_000_000u64;
    peers.set_mock_now(start);
    let peer = live_peer(peers, 18453, 5, false);
    peer.note_awaiting_headers();
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let unknown = Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array([0xab; 32]),
        merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
        time: 1,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    for (step, empty_first, now, want) in [
        ("unconnecting header while a getheaders is out", false, start, 0),
        ("empty headers answer, then unconnecting", true, start, 1),
        ("unconnecting again before the response time", false, start, 0),
        ("unconnecting after HEADERS_RESPONSE_TIME", false, start + 121, 1),
    ] {
        peers.set_mock_now(now);
        if empty_first {
            push(
                hub,
                &out_tx,
                &mut follow,
                Some(peer.as_ref()),
                NetworkMessage::Headers(vec![]),
            )
            .await;
        }
        push(
            hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(vec![unknown]),
        )
        .await;
        assert_eq!(getheaders_count(&mut out_rx), want, "{step}");
    }
    peers.set_mock_now(0);

    let mut headers = Vec::with_capacity(MAX_HEADERS_RESULTS);
    let mut prev = BlockHash::from_byte_array([0x11; 32]);
    for i in 0..MAX_HEADERS_RESULTS {
        let mut merkle = [0u8; 32];
        merkle[0] = (i >> 8) as u8;
        merkle[1] = i as u8;
        let hdr = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(merkle),
            time: 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: i as u32,
        };
        prev = hdr.block_hash();
        headers.push(hdr);
    }
    let last = headers.last().unwrap().block_hash();
    let our_tip = hub.tip_hash().unwrap();
    let peer = live_peer(peers, 18454, 6, false);
    let mut follow = PeerFollowState::new();
    let (out_tx, mut out_rx) = peer_out_channel();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(headers),
    )
    .await;
    let mut locators = Vec::new();
    for msg in take_msgs(&mut out_rx) {
        if let NetworkMessage::GetHeaders(gh) = msg {
            locators.push(gh.locator_hashes);
        }
    }
    assert_eq!(
        locators.len(),
        1,
        "a full unconnected batch continues once, from the last header"
    );
    assert_eq!(locators[0].first().copied(), Some(last));
    assert_ne!(locators[0].first().copied(), Some(our_tip));

    let genesis = hub.tip_hash().unwrap();
    let n = 2_500u32;
    let mut pending = HashMap::new();
    let mut prev = genesis;
    let mut tip = genesis;
    for i in 0..n {
        let mut merkle = [0u8; 32];
        merkle[..4].copy_from_slice(&(i + 1).to_le_bytes());
        let hdr = Header {
            version: Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array(merkle),
            time: 1 + i,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: i,
        };
        tip = hdr.block_hash();
        pending.insert(tip, hdr);
        prev = tip;
    }
    assert!(
        !hub.knows_header(&tip),
        "the pending walk's tip is not stored"
    );
    assert_eq!(
        announced_headers_height(hub, &pending, tip),
        n,
        "height comes from the pending map, then the stored genesis"
    );
    assert_eq!(
        header_branch_vs_tip(hub, &pending, tip),
        Some(std::cmp::Ordering::Greater)
    );
    assert!(header_announcement_connects(hub, &pending, genesis));
}

/// Claimed mainnet nBits without PoW does not fetch. A header whose parent
/// is missing does not fetch either.
async fn header_getdata_decisions(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};

    let gen = header_at(hub, 0);
    let hard = Header {
        version: Version::from_consensus(4),
        prev_blockhash: gen.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array([0x5a; 32]),
        time: gen.time.saturating_add(600),
        bits: CompactTarget::from_consensus(0x1d00ffff),
        nonce: 0,
    };
    let hard_hash = hard.block_hash();
    let mut pending = HashMap::new();
    pending.insert(hard_hash, hard);
    assert_ne!(
        announced_work_cmp(hub, &pending, hard_hash),
        Some(std::cmp::Ordering::Greater),
        "claimed nBits without PoW must not outwork the tip"
    );
    let peer = live_peer(peers, 18455, 7, false);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![hard]),
    )
    .await;
    assert!(
        asked_blocks(&mut out_rx).is_empty(),
        "must not getdata a header that only claims hard nBits"
    );
    assert!(!hub.is_connected(&hard_hash));

    let orphan = Header {
        version: Version::from_consensus(4),
        prev_blockhash: BlockHash::from_byte_array([0x11; 32]),
        merkle_root: TxMerkleNode::from_byte_array([0x5b; 32]),
        time: 1_300_000_000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let orphan_hash = orphan.block_hash();
    let mut pending = HashMap::new();
    pending.insert(orphan_hash, orphan);
    let want = fetchable_header_path_bodies(
        hub,
        &pending,
        orphan_hash,
        &PendingBlocks::new(),
        &HashSet::new(),
    );
    assert!(
        want.is_empty(),
        "a header path we cannot walk must not getdata"
    );
}

/// Below the floor a peer's headers are not stored and not fetched. The
/// batch that crosses the floor is fetched from height 1.
async fn minchainwork_while_tip_is_short(
    hub: &rbitcoin_net::chain::ChainHub,
    src: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip_before = hub.tip_height();
    hub.set_minimum_chain_work(Some(work_floor(0x1f)));
    let hdrs14: Vec<_> = (1..=14u32).map(|h| header_at(src, h)).collect();
    let peer = live_peer(peers, 18456, 8, false);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    for hdr in &hdrs14 {
        push(
            hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(vec![*hdr]),
        )
        .await;
    }
    let _ = take_msgs(&mut out_rx);
    let last = hdrs14[13].block_hash();
    assert_eq!(
        announced_headers_height(hub, &follow.pending_headers, last),
        14,
        "14 one-header announces report height 14"
    );
    assert_eq!(hub.tip_height(), tip_before);
    assert_eq!(side_tips(hub), 0, "low-work headers are not stored");

    hub.set_minimum_chain_work(Some(work_floor(0x65)));
    let hdrs50: Vec<_> = (1..=50u32).map(|h| header_at(src, h)).collect();
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(hdrs50[..49].to_vec()),
    )
    .await;
    assert!(
        asked_blocks(&mut out_rx).is_empty(),
        "49 headers stay under the floor"
    );
    assert_eq!(hub.tip_height(), tip_before);
    assert_eq!(side_tips(hub), 0, "low-work headers are not stored");

    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(hdrs50.clone()),
    )
    .await;
    let got = asked_blocks(&mut out_rx);
    assert_eq!(got.len(), MAX_SERVE_BLOCKS, "crossing the floor fetches");
    assert_eq!(got[0], hdrs50[0].block_hash());
    assert_eq!(
        got[MAX_SERVE_BLOCKS - 1],
        hdrs50[MAX_SERVE_BLOCKS - 1].block_hash()
    );
}

/// Harder claimed work than the tip is still `bad-diffbits` on regtest.
/// The body is not fetched and the header is not held.
async fn shorter_higher_work_rejected_by_the_store_is_not_fetched(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};

    let gen = header_at(hub, 0);
    let mut hard = Header {
        version: Version::from_consensus(4),
        prev_blockhash: gen.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array([0x5c; 32]),
        time: gen.time.saturating_add(600),
        bits: CompactTarget::from_consensus(0x1f7f_ffff),
        nonce: 0,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut hard);
    let hash = hard.block_hash();
    let mut pending = HashMap::new();
    pending.insert(hash, hard);
    assert_eq!(
        announced_work_cmp(hub, &pending, hash),
        Some(std::cmp::Ordering::Greater),
        "one harder header must outwork the short tip"
    );
    let peer = live_peer(peers, 18457, 9, false);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![hard]),
    )
    .await;
    assert!(
        asked_blocks(&mut out_rx).is_empty(),
        "a header the store rejects for bad-diffbits is not fetched"
    );
    assert!(
        !follow.pending_headers.contains_key(&hash),
        "a header the store rejects is not pending"
    );
}

/// Tip work below 0x65 serves nothing. The next block crosses and is served.
fn mine_across_the_work_floor(hub: &rbitcoin_net::chain::ChainHub) {
    let height = hub.tip_height().unwrap();
    assert!(height < 49, "floor cross starts below height 49");
    hub.confirm_empty_regtest(49 - height).unwrap();
    assert_eq!(hub.tip_height(), Some(49));
    assert!(!hub.meets_minimum_chain_work());
    let h49 = hub.tip_hash().unwrap();
    let below =
        headers_reply_for_getheaders(hub, &GetHeadersMessage::new(vec![h49], zero_stop())).unwrap();
    assert!(
        below.is_empty(),
        "getheaders below minchainwork must be empty"
    );
    let mined = hub.confirm_empty_regtest(1).unwrap();
    assert_eq!(hub.tip_height(), Some(50));
    assert!(hub.meets_minimum_chain_work());
    let above =
        headers_reply_for_getheaders(hub, &GetHeadersMessage::new(vec![h49], zero_stop())).unwrap();
    assert_eq!(above.len(), 1, "getheaders at the floor serves the new header");
    assert_eq!(above[0].block_hash(), mined[0]);
}

/// A tall tip does not reconstruct an unknown-parent compact. It asks for headers.
async fn tall_unknown_parent_skips_reconstruct(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    assert!(hub.tip_height().unwrap() >= 20);
    let peer = live_peer(peers, 18458, 10, false);
    peer.note_awaiting_headers();
    let block = orphan_body(BlockHash::from_byte_array([0xcd; 32]), 0);
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        }),
    )
    .await;
    assert!(
        hub.held_body(&block.block_hash()).is_none()
            && !follow.pending_blocks.contains_key(&block.block_hash()),
        "tall-tip unknown-parent compact must not reconstruct"
    );
    assert!(follow.pending_headers.contains_key(&block.block_hash()));
    let msgs = take_msgs(&mut out_rx);
    assert!(
        msgs.iter()
            .any(|m| matches!(m, NetworkMessage::GetHeaders(_))),
        "tall-tip unknown-parent compact must getheaders, got {msgs:?}"
    );
}

/// A bad-pow header in a `headers` message is scored too (Core
/// `BLOCK_INVALID_HEADER`), not only dropped. A fresh header, so the
/// cached-invalid check does not catch it first.
async fn headers_with_bad_pow_disconnect(hub: &rbitcoin_net::chain::ChainHub) {
    let gen = hub.tip_hash().unwrap();
    let tip_time = hub.tip_header().unwrap().time;
    let next_h = hub.tip_height().unwrap().saturating_add(1);
    let mut bad_header = rbitcoin_consensus::mine_regtest_paying(
        gen,
        tip_time.saturating_add(7),
        next_h,
        op_true(),
        vec![],
    )
    .header;
    let target = bitcoin::Target::from_compact(bad_header.bits);
    while bad_header.validate_pow(target).is_ok() {
        bad_header.nonce = bad_header.nonce.wrapping_add(1);
    }
    assert!(!hub.is_block_invalid(&bad_header.block_hash()));
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        None,
        NetworkMessage::Headers(vec![bad_header]),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "a headers message with bad pow must disconnect"
    );
    assert!(!hub.knows_header(&bad_header.block_hash()));

    // A stamp past the two-hour window is temporary: not the peer's fault.
    let now = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let future =
        rbitcoin_consensus::mine_regtest_paying(gen, now + 3 * 3600 + 7, next_h, op_true(), vec![]);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        None,
        NetworkMessage::Headers(vec![future.header]),
    )
    .await;
    assert_eq!(follow.ban_score, 0, "time-too-new headers must not disconnect");

    // The same checks score a compact block's header (Core `invalid header
    // via cmpctblock`). A fresh too-old stamp, so no cache catches it first.
    let too_old = rbitcoin_consensus::mine_regtest_paying(gen, 2, next_h, op_true(), vec![]);
    assert!(!hub.is_block_invalid(&too_old.block_hash()));
    let cmpct = bitcoin::p2p::message_compact_blocks::CmpctBlock {
        compact_block: bitcoin::bip152::HeaderAndShortIds {
            header: too_old.header,
            nonce: 0,
            short_ids: vec![],
            prefilled_txs: vec![bitcoin::bip152::PrefilledTransaction {
                idx: 0,
                tx: too_old.txdata[0].clone(),
            }],
        },
    };
    // Requested, so the low-work filter for unsolicited compact blocks does
    // not drop it before the header is checked.
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    assert!(follow.requested_blocks.claim(hub, too_old.block_hash()));
    push(hub, &out_tx, &mut follow, None, NetworkMessage::CmpctBlock(cmpct)).await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "a compact block with a too-old header must disconnect"
    );
}

/// Bad proof-of-work and a stamp at or below the parent's median time past
/// disconnect. A stamp past the two-hour window does not.
async fn header_reject_punishes_except_time(hub: &rbitcoin_net::chain::ChainHub) {
    let gen = hub.tip_hash().unwrap();
    let tip_time = hub.tip_header().unwrap().time;
    let next_h = hub.tip_height().unwrap().saturating_add(1);
    let mut bad_pow = rbitcoin_consensus::mine_regtest_paying(
        gen,
        tip_time.saturating_add(1),
        next_h,
        op_true(),
        vec![],
    );
    let target = bitcoin::Target::from_compact(bad_pow.header.bits);
    loop {
        bad_pow.header.nonce = bad_pow.header.nonce.wrapping_add(1);
        if bad_pow.header.validate_pow(target).is_err() {
            break;
        }
    }
    let pow_err = hub.ensure_header(&bad_pow.header).unwrap_err();
    assert!(
        !rbitcoin_net::chain::accept_err_is_temporary_time(&pow_err),
        "bad pow is not a temporary stamp: {pow_err}"
    );
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, bad_pow.block_hash());
    push(hub, &out_tx, &mut follow, None, NetworkMessage::Block(bad_pow.clone())).await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "a requested header with bad pow must disconnect"
    );
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        None,
        NetworkMessage::Block(bad_pow),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "an unrequested header with bad pow must disconnect"
    );

    // Core: a missing parent is `prev-blk-not-found` and Misbehaving. An
    // all-zero parent is missing too unless the block is genesis.
    let mut zero_prev = rbitcoin_consensus::mine_regtest_paying(
        gen,
        tip_time.saturating_add(2),
        next_h,
        op_true(),
        vec![],
    );
    zero_prev.header.prev_blockhash = zero_stop();
    rbitcoin_consensus::grind_regtest_pow(&mut zero_prev.header);
    let mut follow = PeerFollowState::new();
    push(hub, &out_tx, &mut follow, None, NetworkMessage::Block(zero_prev.clone())).await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "an unrequested block with an all-zero parent must disconnect"
    );
    assert!(!hub.knows_header(&zero_prev.block_hash()));

    // A stamp at or below the parent's median time past never becomes valid:
    // the median depends only on the block's ancestors.
    let too_old = rbitcoin_consensus::mine_regtest_paying(gen, 1, next_h, op_true(), vec![]);
    let old_err = hub.ensure_header(&too_old.header).unwrap_err();
    assert!(
        !rbitcoin_net::chain::accept_err_is_temporary_time(&old_err),
        "a stamp at or below the median time past is not temporary: {old_err}"
    );
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, too_old.block_hash());
    push(
        hub,
        &out_tx,
        &mut follow,
        None,
        NetworkMessage::Block(too_old.clone()),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "time-too-old must disconnect a requested block"
    );
    assert!(
        hub.is_block_invalid(&too_old.block_hash()),
        "a too-old block message is marked failed"
    );
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        None,
        NetworkMessage::Block(too_old),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "time-too-old must disconnect an unrequested block"
    );

    let now = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let future = rbitcoin_consensus::mine_regtest_paying(gen, now + 3 * 3600, 1, op_true(), vec![]);
    let time_err = hub.ensure_header(&future.header).unwrap_err();
    assert!(
        rbitcoin_net::chain::accept_err_is_temporary_time(&time_err),
        "a stamp past the two-hour window is temporary: {time_err}"
    );
    let mut follow = PeerFollowState::new();
    assert!(follow.requested_blocks.claim(hub, future.block_hash()));
    push(
        hub,
        &out_tx,
        &mut follow,
        None,
        NetworkMessage::Block(future.clone()),
    )
    .await;
    assert_eq!(
        follow.ban_score, 0,
        "time-too-new must not disconnect a requested block"
    );
    assert!(
        !hub.already_have_or_asked_block(&future.block_hash()),
        "a temporary reject releases the block ask"
    );
    let mut follow = PeerFollowState::new();
    push(hub, &out_tx, &mut follow, None, NetworkMessage::Block(future)).await;
    assert_eq!(
        follow.ban_score, 0,
        "time-too-new must not disconnect an unrequested block"
    );
}

/// Empty locator returns a header only when that hash has a body.
fn empty_locator_needs_a_body(hub: &std::sync::Arc<rbitcoin_net::chain::ChainHub>) {
    let tip = hub.tip_hash().unwrap();
    let connected =
        headers_reply_for_getheaders(hub, &GetHeadersMessage::new(vec![], tip)).unwrap();
    assert_eq!(connected.len(), 1, "connected hashstop is served");

    let t0 = hub.header_of(&tip).unwrap().time;
    let height = hub.tip_height().unwrap();
    let pending =
        rbitcoin_consensus::mine_regtest_paying(tip, t0 + 1, height + 1, op_true(), vec![]);
    hub.process_submitted_header(&pending.header).unwrap();
    assert!(!hub.is_connected(&pending.block_hash()));
    let header_only = headers_reply_for_getheaders(
        hub,
        &GetHeadersMessage::new(vec![], pending.block_hash()),
    )
    .unwrap();
    assert!(
        header_only.is_empty(),
        "header-only hashstop is not served"
    );

    hub.mine(1, op_true(), vec![]).unwrap();
    let stale = hub.tip_hash().unwrap();
    run_on_tip_accept(|| hub.invalidate_block_inner(stale)).unwrap();
    assert!(!hub.is_connected(&stale));
    assert!(
        hub.query.is_block_archived(&stale.to_byte_array()).unwrap(),
        "invalidated tip still has a body"
    );
    let with_body =
        headers_reply_for_getheaders(hub, &GetHeadersMessage::new(vec![], stale)).unwrap();
    assert_eq!(
        with_body.len(),
        1,
        "disconnected hashstop with a body is served"
    );
}

/// A bad block disconnects a plain peer. noban and manual peers keep the
/// session and score nothing (Core `MaybeDiscourageAndDisconnect`).
async fn noban_and_manual_bad_block_is_not_punished(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let mut bad_pow =
        rbitcoin_consensus::mine_regtest_paying(prev, time, height, op_true(), vec![]);
    // Regtest accepts about half of nonces, so +1 is often still valid work.
    let target = bitcoin::Target::from_compact(bad_pow.header.bits);
    loop {
        bad_pow.header.nonce = bad_pow.header.nonce.wrapping_add(1);
        if bad_pow.header.validate_pow(target).is_err() {
            break;
        }
    }
    let (out_tx, _rx) = peer_out_channel();

    let plain = live_peer(peers, 18472, 21, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, bad_pow.block_hash());
    on_block(
        hub,
        &out_tx,
        &mut follow,
        Some(plain.as_ref()),
        &bad_pow,
    )
    .await
    .unwrap();
    assert!(
        plain.stop.load(Ordering::SeqCst),
        "a plain peer is disconnected"
    );
    assert!(misbehavior_disconnects(
        follow.ban_score,
        Some(plain.as_ref())
    ));

    peers.set_noban(true);
    let kept = live_peer(peers, 18473, 22, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, bad_pow.block_hash());
    on_block(hub, &out_tx, &mut follow, Some(kept.as_ref()), &bad_pow)
        .await
        .unwrap();
    assert!(
        !kept.stop.load(Ordering::SeqCst),
        "Core never disconnects a noban peer for misbehavior"
    );
    assert_eq!(follow.ban_score, 0, "a noban peer gathers no score");
    assert!(
        !misbehavior_disconnects(BAN_SCORE_THRESHOLD, Some(kept.as_ref())),
        "a noban peer at the threshold stays connected"
    );
    assert!(misbehavior_disconnects(BAN_SCORE_THRESHOLD, None));
    assert!(!misbehavior_disconnects(BAN_SCORE_THRESHOLD - 1, None));
    peers.set_noban(false);

    // `--connect` and `addnode` peers are `manual`.
    let manual = live_peer_as(peers, 18477, 26, rbitcoin_net::peers::PeerConnType::Manual);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, bad_pow.block_hash());
    on_block(hub, &out_tx, &mut follow, Some(manual.as_ref()), &bad_pow)
        .await
        .unwrap();
    assert!(
        !manual.stop.load(Ordering::SeqCst),
        "Core never disconnects a manual peer for misbehavior"
    );
    assert_eq!(follow.ban_score, 0, "a manual peer gathers no score");
    assert!(
        !misbehavior_disconnects(BAN_SCORE_THRESHOLD, Some(manual.as_ref())),
        "a manual peer at the threshold stays connected"
    );
    // Core answers `sendaddrv2` after `verack` with `fDisconnect`, not
    // `Misbehaving`, so a manual peer is still dropped.
    on_sendaddrv2(&mut follow, Some(manual.as_ref()));
    assert!(
        manual.stop.load(Ordering::SeqCst),
        "a protocol violation still drops a manual peer"
    );
}

/// Core `IsBlockMutated`: a coinbase-less body with a 64-byte tx is dropped
/// and punished before relay or accept. Its hash is not cached as failed.
async fn sixty_four_byte_body_is_mutated(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let inner = rbitcoin_net::chain::sixty_four_byte_body(tip, time);
    let hash = inner.block_hash();
    let (out_tx, _rx) = peer_out_channel();
    let sender = live_peer(peers, 18474, 23, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, hash);
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, Some(sender.as_ref()), &inner)
        .await
        .unwrap();
    assert!(
        logs_have("Block mutated: 64-byte transaction without a coinbase"),
        "the drop names the mutation"
    );
    assert!(
        sender.stop.load(Ordering::SeqCst),
        "Core punishes a mutated block"
    );
    assert!(
        !hub.is_block_invalid(&hash),
        "the header's real body must stay acceptable"
    );
    assert!(!hub.knows_header(&hash), "a mutated body adds no header");
    assert!(
        !hub.already_have_or_asked_block(&hash),
        "a mutated drop forgets the ask so another peer can serve the real body"
    );
    assert!(!follow.requested_blocks.contains(&hash));
    assert_eq!(hub.tip_hash(), Some(tip));
}

/// An empty body has no merkle root. A header root of all zeros must not
/// pass that check and must not be stored.
async fn empty_body_null_merkle_bans_before_the_header(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip = hub.tip_hash().unwrap();
    let block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: tip,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: hub.tip_header().unwrap().time.saturating_add(4),
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: Vec::new(),
    };
    assert!(
        !block.check_merkle_root(),
        "an empty list has no merkle root"
    );
    let hash = block.block_hash();
    let (out_tx, _rx) = peer_out_channel();
    let sender = live_peer(peers, 18478, 27, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, hash);
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, Some(sender.as_ref()), &block)
        .await
        .unwrap();
    assert!(
        logs_have("Block mutated: bad-txnmrklroot, hashMerkleRoot mismatch"),
        "the drop names the missing root"
    );
    assert!(
        sender.stop.load(Ordering::SeqCst),
        "Core punishes a mutated block"
    );
    assert!(!hub.knows_header(&hash), "a mutated body adds no header");
    assert!(
        !hub.already_have_or_asked_block(&hash),
        "a mutated drop forgets the ask so another peer can serve the real body"
    );
    assert!(!follow.requested_blocks.contains(&hash));
    assert_eq!(hub.tip_hash(), Some(tip));
}

/// Core `AcceptBlockHeader` refuses a child of an invalid block as
/// `bad-prevblk` and does not index it. The ask is released, so after
/// `reconsiderblock` of the parent a peer can serve that child again.
async fn invalid_parent_child_is_fetched_after_reconsider(
    hub: &std::sync::Arc<rbitcoin_net::chain::ChainHub>,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    hub.mine(1, op_true(), vec![]).unwrap();
    let parent = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    run_on_tip_accept(|| hub.invalidate_block_inner(parent)).unwrap();
    let child = rbitcoin_consensus::mine_regtest_paying(parent, time, height, op_true(), vec![]);
    let hash = child.block_hash();
    let (out_tx, _rx) = peer_out_channel();

    // The parent of that header is valid. The header itself is the
    // invalidated block, and that alone disconnects.
    let teller = live_peer(peers, 18491, 41, true);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(teller.as_ref()),
        NetworkMessage::Headers(vec![hub.header_of(&parent).unwrap()]),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "invalidated header: a headers batch naming an invalidated block disconnects"
    );

    let sender = live_peer(peers, 18490, 40, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, hash);
    on_block(hub, &out_tx, &mut follow, Some(sender.as_ref()), &child)
        .await
        .unwrap();
    assert!(
        !hub.already_have_or_asked_block(&hash),
        "a bad-prevblk child is not left claimed"
    );

    run_on_tip_accept(|| hub.reconsider_block_inner(parent)).unwrap();
    assert_eq!(hub.tip_hash(), Some(parent));
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, hash);
    on_block(hub, &out_tx, &mut follow, Some(sender.as_ref()), &child)
        .await
        .unwrap();
    assert_eq!(hub.tip_hash(), Some(hash), "the refetched child connects");
}

/// Core `RemoveBlockRequest` on a merkle-mismatch drop: the body is not the
/// header's. Once the punished sender's session ends, the next peer that
/// announces the header is asked for the real body.
async fn merkle_mismatch_leaves_the_body_to_the_next_peer(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(2);
    let mut wrong = rbitcoin_net::chain::sixty_four_byte_body(tip, time);
    let hash = wrong.block_hash();
    wrong.txdata[0].output[0].value = bitcoin::Amount::from_sat(1);
    assert!(!wrong.check_merkle_root());
    let (out_tx, _rx) = peer_out_channel();
    let sender = live_peer(peers, 18475, 24, true);
    let mut follow = PeerFollowState::new();
    assert!(follow.requested_blocks.claim(hub, hash));
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, Some(sender.as_ref()), &wrong)
        .await
        .unwrap();
    assert!(
        logs_have("Block mutated: bad-txnmrklroot, hashMerkleRoot mismatch"),
        "the drop names the mutation"
    );
    assert!(
        sender.stop.load(Ordering::SeqCst),
        "Core punishes a mutated block"
    );
    assert!(!hub.is_block_invalid(&hash));
    drop(follow);
    let (next_tx, mut next_rx) = peer_out_channel();
    let mut next = PeerFollowState::new();
    on_headers(hub, &next_tx, &mut next, None, &[wrong.header])
        .await
        .unwrap();
    assert_eq!(
        asked_blocks(&mut next_rx),
        vec![hash],
        "the next peer to announce the header is asked for the body"
    );
    assert_eq!(hub.tip_hash(), Some(tip));
}

fn assert_witness_malleation_log() {
    let lines = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        lines
            .iter()
            .any(|(_, msg)| msg.contains("Block mutated: unexpected-witness")),
        "witness malleation logs the Core token: {lines:?}"
    );
    assert!(
        lines
            .iter()
            .all(|(_, msg)| !msg.contains("Block mutated: consensus:")),
        "the log is the reject token, not the error display: {lines:?}"
    );
}

/// Core drops a mutated copy without marking the block invalid, and its next
/// `SendMessages` asks for the block again while it is on the best header
/// chain. A manual peer stays connected, so tip follow asks it again at once,
/// for a merkle mismatch, a duplicated last transaction, and witness bytes
/// the block does not commit to (Core `IsBlockMutated` checks witness
/// malleation too).
async fn manual_peer_is_asked_again_after_a_mutated_copy(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::{OutPoint, Sequence, TxIn, TxOut, Version};
    use bitcoin::{Amount, ScriptBuf, Transaction, Witness};

    let tip = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(4);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let spend = |n: u32| Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([7u8; 32]), n),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: op_true(),
        }],
    };
    // Three transactions: repeating the last keeps the merkle root.
    let block = rbitcoin_consensus::mine_regtest_paying(
        tip,
        time,
        height,
        op_true(),
        vec![spend(0), spend(1)],
    );
    let hash = block.block_hash();
    let mut wrong_root = block.clone();
    wrong_root.txdata[0].output[0].value = Amount::from_sat(1);
    assert!(!wrong_root.check_merkle_root());
    let mut duplicated = block.clone();
    duplicated.txdata.push(block.txdata[2].clone());
    assert!(duplicated.check_merkle_root());
    // A witness leaves the txid, the merkle root and the hash as they were.
    let mut witnessed = block.clone();
    witnessed.txdata[1].input[0].witness = Witness::from_slice(&[[1u8; 3]]);
    assert!(witnessed.check_merkle_root());
    assert_eq!(witnessed.block_hash(), hash);

    for (n, copy) in [wrong_root, duplicated, witnessed].into_iter().enumerate() {
        let (out_tx, mut rx) = peer_out_channel();
        let manual = live_peer_as(
            peers,
            18479 + n as u16,
            28 + n as u64,
            rbitcoin_net::peers::PeerConnType::Manual,
        );
        let mut follow = PeerFollowState::new();
        admit_pending_header(&mut follow.pending_headers, hash, block.header);
        follow.requested_blocks.ask(hub, hash);
        if n == 2 {
            rbitcoin_log::capture_logs(true);
        }
        on_block(hub, &out_tx, &mut follow, Some(manual.as_ref()), &copy)
            .await
            .unwrap();
        if n == 2 {
            assert_witness_malleation_log();
        }
        assert!(!manual.stop.load(Ordering::SeqCst), "copy {n}: kept");
        assert!(!hub.is_block_invalid(&hash), "copy {n}: not invalid");
        assert_eq!(
            asked_blocks(&mut rx),
            vec![hash],
            "copy {n}: the block is asked for again"
        );
        assert!(follow.requested_blocks.contains(&hash), "copy {n}");
        assert_eq!(hub.tip_hash(), Some(tip));
        let mut requested = follow.requested_blocks;
        requested.remove(&hash);
    }
}

/// A 64-byte copy from a kept peer is asked again. The same copy from a
/// session Core drops leaves the hub ask clear, so another peer can claim it.
async fn sixty_four_byte_kept_peer_and_dropped_session(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    let tip = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(5);
    let short = rbitcoin_net::chain::sixty_four_byte_body(tip, time);
    let short_hash = short.block_hash();
    let (out_tx, mut rx) = peer_out_channel();
    let manual = live_peer_as(
        peers,
        18482,
        31,
        rbitcoin_net::peers::PeerConnType::Manual,
    );
    let mut follow = PeerFollowState::new();
    admit_pending_header(&mut follow.pending_headers, short_hash, short.header);
    follow.requested_blocks.ask(hub, short_hash);
    on_block(hub, &out_tx, &mut follow, Some(manual.as_ref()), &short)
        .await
        .unwrap();
    assert!(!manual.stop.load(Ordering::SeqCst), "64-byte: kept");
    assert!(!hub.is_block_invalid(&short_hash), "64-byte: not invalid");
    assert_eq!(
        asked_blocks(&mut rx),
        vec![short_hash],
        "64-byte: the kept peer is asked again"
    );
    assert!(follow.requested_blocks.contains(&short_hash));
    let mut requested = follow.requested_blocks;
    requested.remove(&short_hash);

    let dropped_body = rbitcoin_net::chain::sixty_four_byte_body(tip, time.saturating_add(1));
    let dropped_hash = dropped_body.block_hash();
    let (out_tx, mut rx) = peer_out_channel();
    let dropped = live_peer(peers, 18483, 32, false);
    let mut follow = PeerFollowState::new();
    admit_pending_header(
        &mut follow.pending_headers,
        dropped_hash,
        dropped_body.header,
    );
    follow.requested_blocks.ask(hub, dropped_hash);
    on_block(
        hub,
        &out_tx,
        &mut follow,
        Some(dropped.as_ref()),
        &dropped_body,
    )
    .await
    .unwrap();
    assert!(
        dropped.stop.load(Ordering::SeqCst),
        "a normal peer is dropped"
    );
    assert!(
        !hub.is_block_invalid(&dropped_hash),
        "the hash stays downloadable"
    );
    assert!(
        asked_blocks(&mut rx).is_empty(),
        "a dropped session is not asked again"
    );
    assert!(
        !hub.already_have_or_asked_block(&dropped_hash),
        "the hub ask is clear"
    );
    assert!(
        hub.claim_block_ask(&dropped_hash).is_some(),
        "another peer can claim the hash"
    );
    assert!(!follow.requested_blocks.contains(&dropped_hash));
    assert_eq!(hub.tip_hash(), Some(tip));
}

/// A signet block whose coinbase has no witness commitment can never satisfy
/// the challenge: that output is in the block hash. Core's
/// `CheckSignetBlockSolution` is `BLOCK_CONSENSUS`. Tip follow marks the hash
/// invalid and does not ask a kept peer again. Witness bytes with no
/// commitment are still a mutated copy (`unexpected-witness`): the hash does
/// not commit to them, so the same header can be served without that witness.
#[tokio::test]
async fn signet_block_without_a_witness_commitment_is_invalid() {
    use bitcoin::Witness;

    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("signet-no-commit");
    let mut params = ChainParams::regtest();
    params.signet_challenge = Some(bitcoin::ScriptBuf::from_bytes(vec![0x51]));
    let hub = ChainHub::new(q, params, Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let tip = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(600);

    let mut witnessed = rbitcoin_consensus::mine_empty_regtest(tip, time, 1);
    let witnessed_hash = witnessed.block_hash();
    witnessed.txdata[0].input[0].witness = Witness::from_slice(&[[1u8; 3]]);
    assert_eq!(witnessed.block_hash(), witnessed_hash);
    let (out_tx, mut rx) = peer_out_channel();
    let manual = live_peer_as(&peers, 18496, 90, rbitcoin_net::peers::PeerConnType::Manual);
    let mut follow = PeerFollowState::new();
    admit_pending_header(&mut follow.pending_headers, witnessed_hash, witnessed.header);
    follow.requested_blocks.ask(&hub, witnessed_hash);
    on_block(
        &hub,
        &out_tx,
        &mut follow,
        Some(manual.as_ref()),
        &witnessed,
    )
    .await
    .unwrap();
    assert!(!manual.stop.load(Ordering::SeqCst), "witness copy: kept");
    assert!(
        !hub.is_block_invalid(&witnessed_hash),
        "witness bytes the hash does not commit to stay downloadable"
    );
    assert_eq!(
        asked_blocks(&mut rx),
        vec![witnessed_hash],
        "the kept peer is asked for the real body"
    );
    let mut requested = follow.requested_blocks;
    requested.remove(&witnessed_hash);

    let bare = rbitcoin_consensus::mine_empty_regtest(tip, time.saturating_add(1), 1);
    let hash = bare.block_hash();
    assert_ne!(hash, witnessed_hash);
    assert!(bare.txdata[0].input[0].witness.is_empty());
    let (out_tx, mut rx) = peer_out_channel();
    let manual = live_peer_as(&peers, 18497, 91, rbitcoin_net::peers::PeerConnType::Manual);
    let mut follow = PeerFollowState::new();
    admit_pending_header(&mut follow.pending_headers, hash, bare.header);
    follow.requested_blocks.ask(&hub, hash);
    on_block(&hub, &out_tx, &mut follow, Some(manual.as_ref()), &bare)
        .await
        .unwrap();
    assert!(!manual.stop.load(Ordering::SeqCst), "kept");
    assert!(
        hub.is_block_invalid(&hash),
        "a signet block with no witness commitment is invalid"
    );
    assert!(
        asked_blocks(&mut rx).is_empty(),
        "the invalid hash is not asked for again"
    );
    assert_eq!(hub.tip_hash(), Some(tip));
    let _ = dir;
}

/// CVE-2012-2459: two identical transactions keep `check_merkle_root` and are
/// still not a block. Tip follow disconnects and does not cache the hash.
async fn duplicate_pair_disconnects(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::{OutPoint, Sequence, TxIn, TxOut, Version};
    use bitcoin::{Amount, ScriptBuf, Transaction, Witness};

    let cb = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x01, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::TWO,
            prev_blockhash: hub.tip_hash().unwrap(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: hub.tip_header().unwrap().time.saturating_add(3),
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        },
        txdata: vec![cb.clone(), cb],
    };
    block.header.merkle_root = block.compute_merkle_root().expect("pair");
    assert!(
        block.check_merkle_root(),
        "the duplicated pair still matches the header root"
    );
    let hash = block.block_hash();
    let tip = hub.tip_hash().unwrap();
    let (out_tx, _rx) = peer_out_channel();
    let sender = live_peer(peers, 18476, 25, true);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, hash);
    rbitcoin_log::capture_logs(true);
    on_block(
        hub,
        &out_tx,
        &mut follow,
        Some(sender.as_ref()),
        &block,
    )
    .await
    .unwrap();
    assert!(
        logs_have("Block mutated: bad-txns-duplicate"),
        "the drop names the duplicate pair"
    );
    assert!(
        sender.stop.load(Ordering::SeqCst),
        "tip follow disconnects a duplicate-pair body"
    );
    assert!(
        !hub.is_block_invalid(&hash),
        "the real body for this hash must stay acceptable"
    );
    assert!(!follow.requested_blocks.contains(&hash));
    assert_eq!(hub.tip_hash(), Some(tip));
}

/// A block whose header fails contextual checks still logs Core's reject reason.
async fn rejected_header_logs_core_reason(hub: &rbitcoin_net::chain::ChainHub) {
    use bitcoin::block::Version;
    use bitcoin::Target;
    let tip = hub.tip_height().unwrap();
    assert!(
        tip < 111,
        "the CLTV beat starts below activation, tip={tip}"
    );
    if tip < 110 {
        hub.confirm_empty_regtest(110 - tip).unwrap();
    }
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time + 1;
    let mut v3 = rbitcoin_consensus::mine_regtest_paying(prev, time, 111, op_true(), vec![]);
    v3.header.version = Version::from_consensus(3);
    let target = Target::from_compact(v3.header.bits);
    while v3.header.validate_pow(target).is_err() {
        v3.header.nonce = v3.header.nonce.wrapping_add(1);
    }
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, v3.block_hash());
    rbitcoin_log::reset_repeated_info();
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, None, &v3)
        .await
        .unwrap();
    let lines = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let want = format!("{}, bad-version(0x00000003)", v3.block_hash());
    assert!(
        lines.iter().any(|(_, l)| l == &want),
        "missing {want:?} in {lines:?}"
    );

    let now = u32::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    let future = rbitcoin_consensus::mine_regtest_paying(prev, now + 3 * 3600, 111, op_true(), vec![]);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(hub, future.block_hash());
    rbitcoin_log::reset_repeated_info();
    rbitcoin_log::capture_logs(true);
    on_block(hub, &out_tx, &mut follow, None, &future)
        .await
        .unwrap();
    let lines = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    assert!(
        lines
            .iter()
            .any(|(_, l)| l == "Block validation error: time-too-new"),
        "missing time-too-new in {lines:?}"
    );
}

/// A connecting header more than 288 below the tip disconnects. noban stays.
async fn ancient_weaker_fork_disconnects(
    hub: &rbitcoin_net::chain::ChainHub,
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) {
    use bitcoin::block::{Header, Version};
    use bitcoin::{CompactTarget, TxMerkleNode};

    assert!(hub.tip_height().unwrap() >= 300);
    let gen = header_at(hub, 0);
    let mut side = Header {
        version: Version::from_consensus(4),
        prev_blockhash: gen.block_hash(),
        merkle_root: TxMerkleNode::from_byte_array([0x9e; 32]),
        time: gen.time.saturating_add(600),
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut side);

    let peer = live_peer(peers, 18470, 11, false);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![side]),
    )
    .await;
    assert_eq!(follow.ban_score, 0, "an ancient fork is not a ban");
    assert!(
        peer.stop.load(Ordering::SeqCst),
        "an ancient weaker header disconnects"
    );

    // The window edge. A weaker fork header 288 blocks under the tip is
    // still in the window. One block deeper is ancient.
    let tip = hub.tip_height().unwrap();
    let fork_at = |height: u32, seed: u8| {
        let parent = header_at(hub, height - 1);
        let mut h = Header {
            version: Version::from_consensus(4),
            prev_blockhash: parent.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([seed; 32]),
            time: parent.time.saturating_add(600),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        rbitcoin_consensus::grind_regtest_pow(&mut h);
        h
    };
    let edge = live_peer(peers, 18484, 13, false);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(edge.as_ref()),
        NetworkMessage::Headers(vec![fork_at(tip - rbitcoin_net::peer::ANCIENT_TIP_BLOCKS, 0x9f)]),
    )
    .await;
    assert!(
        !edge.stop.load(Ordering::SeqCst),
        "ancient edge: a weaker fork 288 blocks under the tip keeps the session"
    );
    assert_eq!(
        follow.ban_score, 0,
        "ancient edge: a weaker fork 288 blocks under the tip is not misbehavior"
    );
    let past = live_peer(peers, 18485, 14, false);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(past.as_ref()),
        NetworkMessage::Headers(vec![fork_at(
            tip - rbitcoin_net::peer::ANCIENT_TIP_BLOCKS - 1,
            0xa0,
        )]),
    )
    .await;
    assert!(
        past.stop.load(Ordering::SeqCst),
        "ancient edge: a weaker fork 289 blocks under the tip disconnects"
    );

    peers.set_noban(true);
    let kept = live_peer(peers, 18471, 12, false);
    let mut follow = PeerFollowState::new();
    push(
        hub,
        &out_tx,
        &mut follow,
        Some(kept.as_ref()),
        NetworkMessage::Headers(vec![side]),
    )
    .await;
    assert!(
        !kept.stop.load(Ordering::SeqCst),
        "noban keeps the session on an ancient weaker fork"
    );
}

/// Clearnet externalip, then onion and i2p on the same address book.
/// `--no-discover` and the external address set here are what the overlay
/// beat checks, and the onion address stays set for the i2p beat.
#[test]
fn self_announce_clearnet_then_overlay() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    self_announce_clearnet(&peers);
    self_announce_overlay(&peers);
}

/// externalip is sent once, again after a day, and not when it is loopback
/// or `--no-discover` is set.
fn self_announce_clearnet(peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>) {
    let peer = live_peer(peers, 18480, 13, false);
    assert!(peer.take_local_addr_due(1_000).is_none());
    peers.set_listen_port(18445);
    peers.set_external_endpoints(vec!["42.42.42.42".parse().unwrap()]);
    let first = peer
        .take_local_addr_due(1_000)
        .expect("initial self-announce");
    assert_eq!(first.to_string(), "42.42.42.42:18445");
    assert!(peer.take_local_addr_due(1_000).is_none());
    assert!(peer.take_local_addr_due(1_000 + 24 * 3600 - 1).is_none());
    let again = peer
        .take_local_addr_due(1_000 + 24 * 3600)
        .expect("daily self-announce");
    assert_eq!(again.to_string(), "42.42.42.42:18445");
    peers.set_external_endpoints(vec!["127.0.0.1".parse().unwrap()]);
    assert!(
        peer.take_local_addr_due(1_000 + 48 * 3600).is_none(),
        "loopback must not be advertised"
    );

    peers.set_external_endpoints(vec!["42.42.42.42".parse().unwrap()]);
    peers.set_discover(false);
    assert!(
        peer.take_local_addr_due(1_000 + 72 * 3600).is_none(),
        "--no-discover must suppress self-announce"
    );
    assert!(peer.take_self_announce_msg().is_none());
    assert!(peers.rpc_local_addresses().is_empty());
}

/// Onion and i2p are advertised instead of `--externalip`. v1 ADDR cannot
/// carry an i2p destination. Onion stays set: the i2p beat is the same book.
fn self_announce_overlay(peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>) {
    use bitcoin::p2p::address::AddrV2;

    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:18444"
            .parse()
            .unwrap();
    let onion_peer = overlay_peer(
        peers,
        "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:8333"
            .parse()
            .unwrap(),
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    peers.set_p2p_onion(onion.host_str(), onion.port());
    peers.set_clearnet_listen(false);
    peers.set_listen_port(18445);
    assert!(peers.advertise_local_socket().is_none());
    match onion_peer.take_self_announce_msg().expect("onion announce") {
        NetworkMessage::AddrV2(v) => {
            assert_eq!(v.len(), 1, "{v:?}");
            assert!(matches!(v[0].addr, AddrV2::TorV3(_)));
            assert_eq!(v[0].port, 18444);
        }
        other => panic!("expected AddrV2 onion, got {other:?}"),
    }
    let rows = peers.rpc_local_addresses();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert!(rows[0].0.ends_with(".onion"));
    assert_eq!(rows[0].1, 18444);
    peers.set_discover(true);
    assert!(
        peers.advertise_local_socket().is_none(),
        "onion-only must not gossip --external-ip"
    );

    peers.set_discover(false);
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    };
    peers.set_p2p_i2p(i2p);
    let i2p_peer = overlay_peer(
        peers,
        rbitcoin_net::NetAddr::I2p {
            dest: [0x22; 32],
            port: 0,
        },
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    match i2p_peer.take_self_announce_msg().expect("i2p announce") {
        NetworkMessage::AddrV2(v) => {
            assert!(
                v.iter()
                    .any(|a| matches!(a.addr, AddrV2::I2p(d) if d == [0x11; 32]) && a.port == 0),
                "i2p destination is advertised, got {v:?}"
            );
            assert!(
                v.iter().all(|a| !matches!(a.addr, AddrV2::Ipv4(_))),
                "i2p announce must not fall back to externalip, got {v:?}"
            );
        }
        other => panic!("expected AddrV2 i2p, got {other:?}"),
    }
    let rows = peers.rpc_local_addresses();
    assert!(
        rows.iter().any(|row| row.0 == i2p.host_str() && row.1 == 0),
        "local addresses include the i2p destination, got {rows:?}"
    );
    assert!(
        rows.iter().all(|row| row.0 != "42.42.42.42"),
        "no-discover must not publish externalip, got {rows:?}"
    );
    let v1 = live_peer(peers, 18483, 16, false);
    assert!(
        v1.take_self_announce_msg().is_none(),
        "v1 ADDR cannot carry an I2P destination"
    );
}

/// An addrv2 session to `net`, as the dialer or the listener records it.
fn overlay_peer(
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
    net: rbitcoin_net::NetAddr,
    conn: rbitcoin_net::peers::PeerConnType,
) -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
    let addr = match net {
        rbitcoin_net::NetAddr::Ip(sock) => sock,
        other => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), other.port()),
    };
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 0,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let inbound = conn == rbitcoin_net::peers::PeerConnType::Inbound;
    let peer = peers.register_net(addr, net, addr, &ver, inbound, conn);
    peer.set_wants_addrv2();
    peer
}

fn self_announce_nets(peer: &rbitcoin_net::peers::LivePeer) -> Vec<&'static str> {
    use bitcoin::p2p::address::AddrV2;
    let Some(msg) = peer.take_self_announce_msg() else {
        return Vec::new();
    };
    let NetworkMessage::AddrV2(v) = msg else {
        panic!("expected AddrV2, got {msg:?}");
    };
    v.iter()
        .map(|a| match a.addr {
            AddrV2::Ipv4(_) => "ipv4",
            AddrV2::TorV3(_) => "onion",
            AddrV2::I2p(_) => "i2p",
            AddrV2::Cjdns(_) => "cjdns",
            ref other => panic!("unexpected self-announce {other:?}"),
        })
        .collect()
}

/// Onion, I2P and `--external-ip` all set. Each link announces only the
/// address of its own network, so no peer can tie two of them together.
#[test]
fn self_announce_stays_on_the_link_network() {
    use std::net::{IpAddr, Ipv4Addr};

    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    };
    let external = IpAddr::V4(Ipv4Addr::new(42, 42, 42, 42));
    let clearnet_peer = rbitcoin_net::NetAddr::Ip(SocketAddr::from(([93, 184, 216, 34], 8333)));
    let loopback_inbound = rbitcoin_net::NetAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 51000)));
    let hub_with = |with_onion: bool, with_i2p: bool| {
        let peers = rbitcoin_net::peers::PeerHub::new();
        peers.set_discover(true);
        peers.set_clearnet_listen(true);
        peers.set_listen_port(8333);
        peers.set_external_endpoints(vec![ExternalEndpoint::BareIp(external)]);
        if with_onion {
            peers.set_p2p_onion(onion.host_str(), onion.port());
        }
        if with_i2p {
            peers.set_overlay_loopback_forward(true);
            peers.set_p2p_i2p(i2p);
        }
        peers
    };

    let out = rbitcoin_net::peers::PeerConnType::OutboundFullRelay;
    let inbound = rbitcoin_net::peers::PeerConnType::Inbound;
    let starting = hub_with(true, false);
    starting.set_overlay_loopback_forward(true);
    let starting_peer = overlay_peer(&starting, loopback_inbound, inbound);
    assert!(
        starting_peer.take_local_addr_due(1_000).is_none(),
        "SAM ingress cannot announce a clearnet address while starting"
    );
    assert!(self_announce_nets(&starting_peer).is_empty());
    starting.set_p2p_i2p(i2p);
    assert_eq!(self_announce_nets(&starting_peer), ["i2p"]);

    let peers = hub_with(true, true);
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, clearnet_peer, out)),
        ["ipv4"],
        "a clearnet peer gets neither the onion nor the i2p address"
    );
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, clearnet_peer, inbound)),
        ["ipv4"]
    );
    let other_onion: rbitcoin_net::NetAddr =
        "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:8333"
            .parse()
            .unwrap();
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, other_onion, out)),
        ["onion"],
        "an onion peer gets the onion and not the clearnet IP"
    );
    assert!(
        overlay_peer(&peers, other_onion, out)
            .take_local_addr_due(1_000)
            .is_none(),
        "the clearnet-only announce timer skips an onion peer"
    );
    let other_i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0x44; 32],
        port: 0,
    };
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, other_i2p, out)),
        ["i2p"]
    );
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, loopback_inbound, inbound)),
        ["i2p"]
    );

    let tor_only = hub_with(true, false);
    tor_only.set_net_perms(rbitcoin_net::net_permissions::NetPermTable {
        onion_bind: loopback_inbound.socket_addr(),
        ..Default::default()
    });
    let tor_inbound = overlay_peer(&tor_only, loopback_inbound, inbound);
    assert_eq!(
        self_announce_nets(&tor_inbound),
        ["onion"],
        "inbound on the onion listener gets the onion and not the clearnet IP"
    );
    let v1_tor_inbound = live_peer(&tor_only, 51000, 41, true);
    assert!(
        v1_tor_inbound.take_self_announce_msg().is_none(),
        "v1 ADDR on the onion listener must not carry the clearnet IP"
    );

    let proxied = hub_with(true, true);
    proxied.set_proxies(rbitcoin_net::NetProxies {
        dialer: rbitcoin_net::socks::Dialer::socks(SocketAddr::from(([127, 0, 0, 1], 9050)), true),
        i2p_sam: None,
    });
    assert_eq!(
        self_announce_nets(&overlay_peer(&proxied, clearnet_peer, out)),
        ["onion"],
        "a clearnet peer dialled through the proxy gets the onion only"
    );

    let i2p_only = hub_with(false, true);
    assert_eq!(
        self_announce_nets(&overlay_peer(&i2p_only, loopback_inbound, inbound)),
        ["i2p"]
    );
    assert_eq!(
        self_announce_nets(&overlay_peer(&i2p_only, clearnet_peer, out)),
        ["ipv4"]
    );

    let cjdns_bind = std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 7);
    let cjdns_peer = rbitcoin_net::NetAddr::Cjdns {
        ip: std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 9),
        port: 8333,
    };
    let with_cjdns = hub_with(false, false);
    with_cjdns.set_cjdns_reachable(true);
    with_cjdns.set_external_endpoints(vec![ExternalEndpoint::BareIp(external), ExternalEndpoint::BareIp(IpAddr::V6(cjdns_bind))]);
    assert_eq!(
        self_announce_nets(&overlay_peer(&with_cjdns, cjdns_peer, inbound)),
        ["cjdns"],
        "a CJDNS peer gets the fc00::/8 address and not the public IP"
    );
    assert!(
        overlay_peer(&with_cjdns, cjdns_peer, out)
            .take_local_addr_due(1_000)
            .is_none(),
        "the v1 socket timer never hands out a CJDNS address"
    );
    assert_eq!(
        self_announce_nets(&overlay_peer(&with_cjdns, clearnet_peer, out)),
        ["ipv4"]
    );
    let cjdns_only = hub_with(false, false);
    cjdns_only.set_cjdns_reachable(true);
    cjdns_only.set_external_endpoints(vec![ExternalEndpoint::BareIp(IpAddr::V6(cjdns_bind))]);
    assert!(
        self_announce_nets(&overlay_peer(&cjdns_only, clearnet_peer, out)).is_empty(),
        "a clearnet peer is never sent the CJDNS address"
    );
    assert!(
        overlay_peer(&cjdns_only, clearnet_peer, inbound)
            .take_local_addr_due(1_000)
            .is_none()
    );
}

#[test]
fn external_onion_announcement_uses_the_configured_or_listen_port_on_tor() {
    use rbitcoin_net::peers::PeerConnType::{Inbound, OutboundFullRelay as Out};

    let native: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let public = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";
    let tor: rbitcoin_net::NetAddr =
        "3zvhyy5nu2tes4mi2znnie2fl2mv425udfrl6esnuxixpzb56twisrad.onion:8333"
            .parse()
            .unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_p2p_onion(native.host_str(), native.port());
    peers.set_listen_port(18445);
    let announce = || {
        let peer = overlay_peer(&peers, tor, Out);
        let (_, mut rx) = peer.open_out();
        peer.queue_self_announce_if_due();
        let PeerOut::Msg(NetworkMessage::AddrV2(addrs)) = rx.try_recv().unwrap().into_out() else {
            panic!("expected Tor addrv2");
        };
        assert_eq!(addrs.len(), 1);
        rbitcoin_net::NetAddr::from_addrv2(&addrs[0]).unwrap()
    };
    let direct = "93.184.216.34:8333".parse().unwrap();
    let ip = "42.42.42.42:28332";
    peers.set_external_endpoints(vec![ip.parse().unwrap(), public.parse().unwrap()]);
    assert_eq!(announce(), format!("{public}:18445").parse().unwrap());
    assert_eq!(self_announce_nets(&overlay_peer(&peers, direct, Out)), ["ipv4"]);
    let inbound = overlay_peer(&peers, direct, Inbound);
    assert_eq!(inbound.take_local_addr_due(1_000), Some(ip.parse().unwrap()));
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, direct, Inbound)),
        ["ipv4"]
    );

    peers.set_external_endpoints(vec![
        "42.42.42.42:28332".parse().unwrap(),
        public.parse().unwrap(),
        format!("{}:28334", native.host_str()).parse().unwrap(),
        format!("{public}:28333").parse().unwrap(),
    ]);
    assert_eq!(announce(), format!("{public}:28333").parse().unwrap());
    peers.set_external_endpoints(vec![public.parse().unwrap()]);

    peers.set_clearnet_listen(false);
    peers.set_tor_only_public_port(18444);
    assert_eq!(announce(), format!("{public}:18444").parse().unwrap());

    peers.set_discover(false);
    assert_eq!(announce(), native);
    peers.set_discover(true);
    peers.set_listen_port(0);
    assert_eq!(announce(), native);
}

#[test]
fn external_onion_withholds_self_announcements_on_shared_loopback() {
    use rbitcoin_net::net_permissions::{parse_whitelist, NetPermTable};
    use rbitcoin_net::peers::PeerConnType::Inbound;

    let peers = rbitcoin_net::PeerHub::new();
    peers.set_listen_port(18445);
    peers.set_external_endpoints(vec![
        "42.42.42.42:28332".parse().unwrap(),
        "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:28333"
            .parse()
            .unwrap(),
    ]);
    let loopback = "127.0.0.1:51000".parse().unwrap();
    let inbound = || overlay_peer(&peers, loopback, Inbound);

    assert!(inbound().take_local_addr_due(1_000).is_none());
    assert!(inbound().take_self_announce_msg().is_none());

    peers.set_net_perms(NetPermTable {
        onion_bind: Some("127.0.0.1:18446".parse().unwrap()),
        onion_bind_is_implicit: true,
        whitelist: vec![parse_whitelist("relay@127.0.0.1").unwrap()],
        ..Default::default()
    });
    assert!(inbound().take_local_addr_due(1_000).is_none());
    assert!(inbound().take_self_announce_msg().is_none());
    let socket = loopback.socket_addr().unwrap();
    assert!(peers.permission_strings(socket, true, socket).is_empty());

    peers.set_overlay_loopback_forward(true);
    peers.set_p2p_i2p(rbitcoin_net::NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    });
    assert!(inbound().take_self_announce_msg().is_none());
}

#[test]
fn local_endpoints_wait_for_startup_listener_permissions() {
    use rbitcoin_net::net_permissions::NetPermTable;

    let peers = rbitcoin_net::PeerHub::new();
    let endpoint = "42.42.42.42:28332";
    let external = endpoint.parse().unwrap();
    let onion_bind = "127.0.0.1:8334".parse().unwrap();
    std::thread::scope(|scope| {
        // Hold the permission table while the startup path publishes the endpoints.
        let held = peers.net_perms.lock().unwrap();
        let startup = scope.spawn(|| {
            peers.publish_local_endpoints(
                8333,
                vec![endpoint.parse().unwrap()],
                NetPermTable {
                    onion_bind: Some(onion_bind),
                    ..NetPermTable::default()
                },
            );
        });
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !peers.is_own_address(external) {
            assert!(std::time::Instant::now() < deadline, "endpoints were not registered");
            std::thread::yield_now();
        }
        assert!(peers.advertise_local_socket().is_none());
        drop(held);
        startup.join().unwrap();
    });
    assert_eq!(peers.advertise_local_socket(), external.socket_addr());
}

#[test]
fn marked_tor_listener_announces_the_public_onion() {
    use rbitcoin_net::net_permissions::NetPermTable;
    use rbitcoin_net::peers::PeerConnType::Inbound;
    use rbitcoin_net::NetAddr;

    let peers = rbitcoin_net::PeerHub::new();
    let tor_bind = "[::1]:8334".parse().unwrap();
    let normal_bind = "127.0.0.1:8333".parse().unwrap();
    peers.set_net_perms(NetPermTable {
        onion_bind: Some(tor_bind),
        ..NetPermTable::default()
    });
    peers.set_listen_port(8333);
    let native: NetAddr = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
        .parse()
        .unwrap();
    peers.set_p2p_onion(native.host_str(), native.port());
    let ip = "42.42.42.42:28332";
    peers.set_external_endpoints(vec![ip.parse().unwrap()]);
    let announce = |bind: SocketAddr| {
        let source = SocketAddr::new(bind.ip(), 51000);
        let ver = VersionMessage::new(
            ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            0,
            Address::new(&bind, ServiceFlags::NONE),
            Address::new(&source, ServiceFlags::NONE),
            0,
            "/rbitcoin:test/".into(),
            0,
        );
        let peer = peers.register(source, bind, &ver, true, Inbound);
        peer.set_wants_addrv2();
        let Some(NetworkMessage::AddrV2(addrs)) = peer.take_self_announce_msg() else {
            panic!("expected addrv2 on {bind}");
        };
        assert_eq!(addrs.len(), 1);
        NetAddr::from_addrv2(&addrs[0]).unwrap()
    };

    assert_eq!(announce(tor_bind), native);
    assert_eq!(announce(normal_bind), ip.parse().unwrap());
    let public = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:28333";
    peers.set_external_endpoints(vec![ip.parse().unwrap(), public.parse().unwrap()]);
    assert_eq!(announce(tor_bind), public.parse().unwrap());
    assert_eq!(announce(normal_bind), ip.parse().unwrap());

    let i2p = NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    };
    peers.set_overlay_loopback_forward(true);
    peers.set_p2p_i2p(i2p);
    assert_eq!(announce(tor_bind), public.parse().unwrap());
    assert_eq!(announce(normal_bind), i2p);
}

#[test]
fn a_down_i2p_address_is_not_advertised_but_stays_our_own() {
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    };
    let other_i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0x44; 32],
        port: 0,
    };
    let out = rbitcoin_net::peers::PeerConnType::OutboundFullRelay;
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_p2p_i2p(i2p);
    let lists_i2p = |peers: &rbitcoin_net::peers::PeerHub| {
        peers
            .rpc_local_addresses()
            .iter()
            .any(|row| row.0 == i2p.host_str())
    };

    peers.set_p2p_i2p_down(true);
    assert!(
        self_announce_nets(&overlay_peer(&peers, other_i2p, out)).is_empty(),
        "a down I2P address is not announced"
    );
    assert!(!lists_i2p(&peers), "getnetworkinfo leaves out a down I2P address");
    assert!(
        peers.is_own_address(i2p),
        "a down I2P address is still filtered from address replies"
    );

    peers.set_p2p_i2p_down(false);
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, other_i2p, out)),
        ["i2p"]
    );
    assert!(lists_i2p(&peers));
}

#[test]
fn a_down_onion_is_not_advertised_but_stays_our_own() {
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    };
    let other_onion: rbitcoin_net::NetAddr =
        "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:8333"
            .parse()
            .unwrap();
    let loopback_inbound = rbitcoin_net::NetAddr::Ip(SocketAddr::from(([127, 0, 0, 1], 51000)));
    let out = rbitcoin_net::peers::PeerConnType::OutboundFullRelay;
    let inbound = rbitcoin_net::peers::PeerConnType::Inbound;
    let tor_wallet: rbitcoin_net::NetAddr =
        "3zvhyy5nu2tes4mi2znnie2fl2mv425udfrl6esnuxixpzb56twisrad.onion:50001"
            .parse()
            .unwrap();
    let external_onion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_p2p_onion(onion.host_str(), onion.port());
    peers.set_overlay_loopback_forward(true);
    peers.set_p2p_i2p(i2p);
    peers.set_tor_wallet_onion(tor_wallet.host_str(), tor_wallet.port());
    peers.set_listen_port(50002);
    let lists = |peers: &rbitcoin_net::peers::PeerHub, host: String| {
        peers.rpc_local_addresses().iter().any(|row| row.0 == host)
    };
    let lists_onion = |peers: &rbitcoin_net::peers::PeerHub| lists(peers, onion.host_str());

    peers.set_tor_onions_down(true);
    assert!(
        self_announce_nets(&overlay_peer(&peers, other_onion, out)).is_empty(),
        "a down onion is not announced"
    );
    assert!(!lists_onion(&peers), "getnetworkinfo leaves out a down onion");
    assert!(
        !lists(&peers, tor_wallet.host_str()),
        "getnetworkinfo leaves out a down wallet onion"
    );
    assert!(
        peers.is_own_address(onion),
        "a down onion is still filtered from address replies"
    );
    assert!(
        peers.is_own_address(tor_wallet),
        "a down wallet onion is still filtered from address replies"
    );
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, loopback_inbound, inbound)),
        ["i2p"],
        "the I2P announcement continues while native Tor is down"
    );

    peers.set_external_endpoints(vec![external_onion.parse().unwrap()]);
    assert!(lists(&peers, external_onion.to_string()));
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, other_onion, out)),
        ["onion"],
        "the external onion stays eligible while the Tor controller is down"
    );

    peers.set_external_endpoints(Vec::new());
    peers.set_tor_onions_down(false);
    assert_eq!(
        self_announce_nets(&overlay_peer(&peers, other_onion, out)),
        ["onion"]
    );
    assert!(lists_onion(&peers));
    assert!(lists(&peers, tor_wallet.host_str()));
}

/// An addrv2 session to `net` whose VERSION says it reached us at `seen`.
fn reporting_peer(
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
    net: rbitcoin_net::NetAddr,
    conn: rbitcoin_net::peers::PeerConnType,
    seen: IpAddr,
) -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
    let addr = match net {
        rbitcoin_net::NetAddr::Ip(sock) => sock,
        other => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), other.port()),
    };
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&SocketAddr::new(seen, 50_123), ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 0,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let inbound = conn == rbitcoin_net::peers::PeerConnType::Inbound;
    let peer = peers.register_net(addr, net, addr, &ver, inbound, conn);
    peer.set_wants_addrv2();
    peer
}

/// The clearnet sockets one self-announce carries.
fn announced_ips(peer: &rbitcoin_net::peers::LivePeer) -> Vec<SocketAddr> {
    use bitcoin::p2p::address::AddrV2;
    let Some(msg) = peer.take_self_announce_msg() else {
        return Vec::new();
    };
    let NetworkMessage::AddrV2(v) = msg else {
        panic!("expected AddrV2, got {msg:?}");
    };
    v.iter()
        .filter_map(|a| match a.addr {
            AddrV2::Ipv4(ip) => Some(SocketAddr::new(IpAddr::V4(ip), a.port)),
            AddrV2::Ipv6(ip) => Some(SocketAddr::new(IpAddr::V6(ip), a.port)),
            _ => None,
        })
        .collect()
}

/// `--discover-from-peers` announces, at our listen port, the IP an outbound
/// clearnet peer reports reaching us at. Off by default; never to an inbound
/// peer, which anyone can be; never on an overlay or proxied link; an
/// unroutable or CJDNS report is ignored; a clearnet `--external-ip` wins;
/// `--no-discover` and no clearnet listener stop it.
#[test]
fn discover_from_peers_announces_the_reported_address() {
    use rbitcoin_net::peers::PeerConnType::{Inbound, OutboundFullRelay as Out};

    let seen = IpAddr::V4(Ipv4Addr::new(81, 2, 69, 160));
    let clearnet = rbitcoin_net::NetAddr::Ip(SocketAddr::from(([93, 184, 216, 34], 8333)));
    let hub = |from_peers: bool| {
        let peers = rbitcoin_net::peers::PeerHub::new();
        peers.set_discover(true);
        peers.set_clearnet_listen(true);
        peers.set_listen_port(8333);
        peers.set_discover_from_peers(from_peers);
        peers
    };

    assert!(
        reporting_peer(&hub(false), clearnet, Out, seen).take_self_announce_msg().is_none(),
        "off by default: a peer's report is never announced"
    );
    let on = hub(true);
    assert_eq!(
        announced_ips(&reporting_peer(&on, clearnet, Out, seen)),
        [SocketAddr::new(seen, 8333)],
        "the reported IP goes out at our listen port, not the peer-seen port"
    );
    // A fresh hub: `on` already holds `seen` from the outbound report.
    let fresh = hub(true);
    let inbound = reporting_peer(&fresh, clearnet, Inbound, seen);
    assert_eq!(inbound.reported_local_ip, None);
    assert!(
        inbound.take_self_announce_msg().is_none(),
        "an inbound peer's report is not taken"
    );
    assert!(
        !fresh.is_own_address(rbitcoin_net::NetAddr::Ip(SocketAddr::new(seen, 8333))),
        "nor recorded"
    );
    for bad in [
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 7)),
    ] {
        assert!(
            reporting_peer(&on, clearnet, Out, bad)
                .take_self_announce_msg()
                .is_none(),
            "an unroutable or CJDNS report {bad} is not announced"
        );
    }
    let onion: rbitcoin_net::NetAddr =
        "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:8333"
            .parse()
            .unwrap();
    assert!(
        reporting_peer(&on, onion, Out, seen).take_self_announce_msg().is_none(),
        "an onion peer never gets a clearnet IP"
    );
    let proxied = hub(true);
    proxied.set_proxies(rbitcoin_net::NetProxies {
        dialer: rbitcoin_net::socks::Dialer::socks(SocketAddr::from(([127, 0, 0, 1], 9050)), true),
        i2p_sam: None,
    });
    assert!(
        reporting_peer(&proxied, clearnet, Out, seen).take_self_announce_msg().is_none(),
        "a peer dialled through the proxy sees the exit, and gets nothing"
    );

    let external = hub(true);
    external.set_external_endpoints(vec!["42.42.42.42".parse().unwrap()]);
    assert_eq!(
        announced_ips(&reporting_peer(&external, clearnet, Out, seen)),
        [SocketAddr::from(([42, 42, 42, 42], 8333))],
        "a clearnet --external-ip wins over the report"
    );
    let cjdns_bind = hub(true);
    cjdns_bind.set_cjdns_reachable(true);
    cjdns_bind.set_external_endpoints(vec!["fc00::9".parse().unwrap()]);
    assert_eq!(
        announced_ips(&reporting_peer(&cjdns_bind, clearnet, Out, seen)),
        [SocketAddr::new(seen, 8333)],
        "a CJDNS address is not a clearnet --external-ip"
    );

    let no_discover = hub(true);
    no_discover.set_discover(false);
    assert!(reporting_peer(&no_discover, clearnet, Out, seen).take_self_announce_msg().is_none());
    let no_listen = hub(true);
    no_listen.set_clearnet_listen(false);
    assert!(reporting_peer(&no_listen, clearnet, Out, seen).take_self_announce_msg().is_none());
}

/// `ip(n)` for the reports in `discovered_reports_are_own_addresses_at_our_port`.
fn reported(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(81, 2, 70, n))
}

/// An outbound session from its own address whose VERSION reports `reported(n)`.
fn outbound_reporting(
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
    n: u8,
    v2: bool,
) -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
    let addr = SocketAddr::from(([93, 184, 217, n], 8333));
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&SocketAddr::new(reported(n), 50_123), ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 0,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(addr, addr, &ver, false, rbitcoin_net::peers::PeerConnType::OutboundFullRelay);
    if v2 {
        peer.set_wants_addrv2();
    }
    peer
}

/// A report becomes one of this node's own addresses once it is announced,
/// and only at the listen port: the peer picks the IP, so matching by IP
/// would let it hide another node's address at every port. A report the
/// daily timer holds back is not recorded. The newest
/// `MAX_DISCOVERED_IPS` are kept, a repeat keeps its place, and turning the
/// flag off forgets them. The connecting placeholder, whose `receiver` is
/// the peer's own socket, reports nothing.
#[test]
fn discovered_reports_are_own_addresses_at_our_port() {
    use rbitcoin_net::peers::{PeerConnType, MAX_DISCOVERED_IPS};
    let own_at = |peers: &rbitcoin_net::peers::PeerHub, n: u8, port: u16| {
        peers.is_own_address(rbitcoin_net::NetAddr::Ip(SocketAddr::new(reported(n), port)))
    };
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_discover(true);
    peers.set_clearnet_listen(true);
    peers.set_listen_port(8333);
    peers.set_discover_from_peers(true);

    let first = outbound_reporting(&peers, 1, true);
    assert!(!own_at(&peers, 1, 8333));
    assert!(first.take_self_announce_msg().is_some());
    assert!(own_at(&peers, 1, 8333), "an announced report is ours");
    assert!(!own_at(&peers, 1, 18333), "the reported IP at another port is not ours");

    let v1 = outbound_reporting(&peers, 2, false);
    assert!(matches!(v1.take_self_announce_msg(), Some(NetworkMessage::Addr(_))));
    assert!(own_at(&peers, 2, 8333), "a v1 addr announce records too");

    peers.set_discover_from_peers(false);
    assert!(!own_at(&peers, 1, 8333), "turning the flag off forgets the reports");
    peers.set_discover_from_peers(true);
    assert!(
        first.take_self_announce_msg().is_none(),
        "the daily timer holds the repeat back"
    );
    assert!(!own_at(&peers, 1, 8333), "evaluated but never sent, so not recorded");

    let cap = MAX_DISCOVERED_IPS as u8;
    for n in 10..=10 + cap {
        assert!(outbound_reporting(&peers, n, true).take_self_announce_msg().is_some());
    }
    assert!(!own_at(&peers, 10, 8333), "the oldest report is evicted at the cap");
    for n in 11..=10 + cap {
        assert!(own_at(&peers, n, 8333), "report {n} is ours");
    }
    // A repeat keeps its place, so the next new report evicts it.
    assert!(outbound_reporting(&peers, 11, true).take_self_announce_msg().is_some());
    assert!(outbound_reporting(&peers, 100, true).take_self_announce_msg().is_some());
    assert!(!own_at(&peers, 11, 8333) && own_at(&peers, 12, 8333), "a repeat is not re-added");

    let addr = SocketAddr::new(reported(7), 8333);
    let row = peers.register_connecting(addr, addr, false, PeerConnType::OutboundFullRelay);
    assert_eq!(row.reported_local_ip, None);
}

/// A peer gossips this node's own onion, I2P and external addresses back.
/// The `getaddr` reply still leaves them out.
#[test]
fn getaddr_reply_omits_own_addresses() {
    let onion: rbitcoin_net::NetAddr =
        "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8333"
            .parse()
            .unwrap();
    let i2p = rbitcoin_net::NetAddr::I2p {
        dest: [0x11; 32],
        port: 0,
    };
    let wallet_onion: rbitcoin_net::NetAddr =
        "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:8333"
            .parse()
            .unwrap();
    let external = SocketAddr::from(([42, 42, 42, 42], 8333));
    let other = SocketAddr::from(([93, 184, 216, 34], 8333));
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_000);
    let mut book = AddrMan::new();
    book.set_onion_reachable(true);
    book.set_i2p_reachable(true);
    peers.set_addrman(Arc::new(std::sync::Mutex::new(book)));
    let gossip = |addr: AddrV2, port: u16| AddrV2Message {
        time: 1,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        addr,
        port,
    };
    let rbitcoin_net::NetAddr::Onion { pk, .. } = onion else {
        unreachable!()
    };
    let rbitcoin_net::NetAddr::Onion { pk: wallet_pk, .. } = wallet_onion else {
        unreachable!()
    };
    let rows = [
        gossip(AddrV2::TorV3(pk), 8333),
        gossip(AddrV2::TorV3(wallet_pk), 8333),
        gossip(AddrV2::I2p([0x11; 32]), 0),
        gossip(AddrV2::Ipv4(Ipv4Addr::new(42, 42, 42, 42)), 8333),
        gossip(AddrV2::Ipv4(Ipv4Addr::new(93, 184, 216, 34)), 8333),
    ];
    peers.learn_addrv2(
        rbitcoin_net::NetAddr::Ip(SocketAddr::from(([198, 51, 100, 7], 8333))),
        &rows,
        peers.now_secs(),
    );
    let early_bind = SocketAddr::from(([127, 0, 0, 1], 8333));
    let cached = peers.addr_response_net(early_bind, true);
    assert_eq!(cached.len(), 1, "{cached:?}");
    assert_ne!(
        cached[0].1,
        rbitcoin_net::NetAddr::Ip(other),
        "this seed samples one of the node's own rows"
    );

    peers.set_p2p_onion(onion.host_str(), onion.port());
    peers.set_p2p_i2p(i2p);
    peers.set_external_endpoints(vec![ExternalEndpoint::BareIp(external.ip())]);
    peers.set_tor_wallet_onion(wallet_onion.host_str(), 50001);
    assert!(
        peers.addr_response_net(early_bind, true).is_empty(),
        "a reply cached before the own addresses were set still leaves them out"
    );
    let got: Vec<_> = peers
        .addr_response_net(SocketAddr::from(([127, 0, 0, 1], 8335)), true)
        .into_iter()
        .map(|(_, a)| a)
        .collect();
    assert_eq!(got, vec![rbitcoin_net::NetAddr::Ip(other)]);
    let v1 = peers.addr_response_for_bind(SocketAddr::from(([127, 0, 0, 1], 8334)));
    assert_eq!(v1.len(), 1, "{v1:?}");
    assert_eq!(v1[0].1.socket_addr().unwrap(), other);
}

/// One peer. Verack order, unknown parents, header floods, and minchainwork
/// share this hub. CLTV activates at 111 so a rejected header can log Core's
/// reason on the same chain.
#[tokio::test]
async fn peer_header_dos_and_self_announce() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("hdr-dos");
    let mut params = ChainParams::regtest();
    params.apply_test_activation_height("cltv", 111).unwrap();
    let hub = Arc::new(ChainHub::new(q, params, Milestone::NONE));
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();

    handshake_verack_and_addrv2(&hub, &peers).await;
    wire_caps_one_past_disconnect(&hub, &peers).await;
    unknown_parent_bodies(&hub, &peers).await;
    header_flood_and_pending_walk(&hub, &peers).await;

    let (src_dir, src) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-dos-src");
    src.ensure_genesis().unwrap();
    src.confirm_empty_regtest(50).unwrap();
    minchainwork_while_tip_is_short(&hub, &src, &peers).await;

    hub.confirm_empty_regtest(5).unwrap();
    assert_eq!(hub.tip_height(), Some(5));
    getblocks_locator_cap(&hub, &peers).await;
    header_getdata_decisions(&hub, &peers).await;
    shorter_higher_work_rejected_by_the_store_is_not_fetched(&hub, &peers).await;

    mine_across_the_work_floor(&hub);
    hub.set_minimum_chain_work(None);

    tall_unknown_parent_skips_reconstruct(&hub, &peers).await;
    header_reject_punishes_except_time(&hub).await;
    headers_with_bad_pow_disconnect(&hub).await;
    noban_and_manual_bad_block_is_not_punished(&hub, &peers).await;
    sixty_four_byte_body_is_mutated(&hub, &peers).await;
    empty_body_null_merkle_bans_before_the_header(&hub, &peers).await;
    merkle_mismatch_leaves_the_body_to_the_next_peer(&hub, &peers).await;
    manual_peer_is_asked_again_after_a_mutated_copy(&hub, &peers).await;
    sixty_four_byte_kept_peer_and_dropped_session(&hub, &peers).await;
    invalid_parent_child_is_fetched_after_reconsider(&hub, &peers).await;
    duplicate_pair_disconnects(&hub, &peers).await;
    rejected_header_logs_core_reason(&hub).await;

    let tip = hub.tip_height().unwrap();
    if tip < 300 {
        hub.confirm_empty_regtest(300 - tip).unwrap();
    }
    ancient_weaker_fork_disconnects(&hub, &peers).await;
    empty_locator_needs_a_body(&hub);

    let _ = std::fs::remove_dir_all(src_dir);
    let _ = std::fs::remove_dir_all(dir);
}

/// During IBD, a headers batch that ends the peer's chain and sits under
/// `-minimumchainwork` drops outbound full-relay and block-relay peers.
/// Inbound, manual, feeler, and addr-fetch stay. Equal work on a stale tip
/// stays in IBD and does not drop the outbound peer.
#[tokio::test]
async fn outbound_low_work_headers_disconnect_during_ibd() {
    use rbitcoin_net::peers::PeerConnType;
    use std::sync::atomic::Ordering;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-low-work");
    let hub = std::sync::Arc::new(hub);
    let mut floor = [0u8; 32];
    floor[30] = 0x10;
    // The floor has to be set before the first block lands. Leaving IBD
    // latches, and a later raise does not enter it again.
    hub.set_minimum_chain_work(Some(floor));
    hub.ensure_genesis().unwrap();
    hub.mine(4, op_true(), vec![]).unwrap();
    assert!(
        hub.in_ibd(),
        "a chain under the floor is still in initial block download"
    );
    let headers: Vec<_> = (1..=4u32).map(|h| header_at(&hub, h)).collect();
    let peers = rbitcoin_net::peers::PeerHub::new();

    async fn send(
        hub: &rbitcoin_net::chain::ChainHub,
        peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
        port: u16,
        nonce: u64,
        conn: PeerConnType,
        headers: &[bitcoin::block::Header],
    ) -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
        let peer = live_peer_as(peers, port, nonce, conn);
        let (out_tx, _rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        push(
            hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(headers.to_vec()),
        )
        .await;
        peer
    }

    rbitcoin_log::capture_logs(true);
    let outbound = send(
        &hub,
        &peers,
        18501,
        81,
        PeerConnType::OutboundFullRelay,
        &headers,
    )
    .await;
    assert!(
        outbound.stop.load(Ordering::SeqCst),
        "outbound full-relay with a short low-work chain drops"
    );
    assert!(logs_have(
        "outbound peer headers chain has insufficient work"
    ));

    rbitcoin_log::capture_logs(true);
    let block_only = send(&hub, &peers, 18502, 82, PeerConnType::BlockRelay, &headers).await;
    assert!(
        block_only.stop.load(Ordering::SeqCst),
        "block-relay-only with a short low-work chain drops"
    );
    assert!(logs_have(
        "outbound peer headers chain has insufficient work"
    ));

    rbitcoin_log::capture_logs(true);
    let inbound = send(&hub, &peers, 18503, 83, PeerConnType::Inbound, &headers).await;
    assert!(
        !inbound.stop.load(Ordering::SeqCst),
        "an inbound peer stays"
    );
    assert!(!logs_have(
        "outbound peer headers chain has insufficient work"
    ));

    rbitcoin_log::capture_logs(true);
    let manual = send(&hub, &peers, 18504, 84, PeerConnType::Manual, &headers).await;
    assert!(!manual.stop.load(Ordering::SeqCst), "a manual peer stays");
    assert!(!logs_have(
        "outbound peer headers chain has insufficient work"
    ));

    rbitcoin_log::capture_logs(true);
    let feeler = send(&hub, &peers, 18505, 85, PeerConnType::Feeler, &headers).await;
    assert!(!feeler.stop.load(Ordering::SeqCst), "a feeler stays");
    assert!(!logs_have(
        "outbound peer headers chain has insufficient work"
    ));

    rbitcoin_log::capture_logs(true);
    let addr_fetch = send(&hub, &peers, 18506, 86, PeerConnType::AddrFetch, &headers).await;
    assert!(
        !addr_fetch.stop.load(Ordering::SeqCst),
        "an addr-fetch peer stays"
    );
    assert!(!logs_have(
        "outbound peer headers chain has insufficient work"
    ));

    let met = hub.chain_work().unwrap().to_be_bytes();
    hub.set_minimum_chain_work(Some(met));
    let tip_time = u64::from(hub.tip_header().unwrap().time);
    hub.clock
        .set_mock(i64::try_from(tip_time + hub.max_tip_age_secs() + 1).unwrap());
    assert!(
        hub.in_ibd(),
        "a stale tip stays in initial block download when work meets the floor"
    );
    rbitcoin_log::capture_logs(true);
    let enough = send(
        &hub,
        &peers,
        18507,
        87,
        PeerConnType::OutboundFullRelay,
        &headers,
    )
    .await;
    assert!(
        !enough.stop.load(Ordering::SeqCst),
        "an outbound peer at the floor stays"
    );
    assert!(!logs_have(
        "outbound peer headers chain has insufficient work"
    ));

    let _ = std::fs::remove_dir_all(dir);
}

/// Core keeps `pindexBestKnownBlock` at the higher-work header. A later
/// short fork under the floor must not drop that outbound peer.
#[tokio::test]
async fn known_good_chain_survives_a_later_low_work_fork() {
    use rbitcoin_net::peers::PeerConnType;
    use std::sync::atomic::Ordering;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-best-known");
    let hub = std::sync::Arc::new(hub);
    let mut floor = [0u8; 32];
    floor[30] = 0x10;
    hub.set_minimum_chain_work(Some(floor));
    hub.ensure_genesis().unwrap();
    hub.mine(4, op_true(), vec![]).unwrap();
    let met = hub.chain_work().unwrap().to_be_bytes();
    hub.set_minimum_chain_work(Some(met));
    let tip_time = u64::from(hub.tip_header().unwrap().time);
    hub.clock
        .set_mock(i64::try_from(tip_time + hub.max_tip_age_secs() + 1).unwrap());
    assert!(
        hub.in_ibd(),
        "a stale tip stays in initial block download"
    );
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer_as(&peers, 18511, 91, PeerConnType::OutboundFullRelay);
    peer.note_best_known(hub.tip_hash().unwrap());
    let fork = regtest_header_chain(header_at(&hub, 0).block_hash(), 1);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    rbitcoin_log::capture_logs(true);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(fork),
    )
    .await;
    assert!(
        !peer.stop.load(Ordering::SeqCst),
        "a later low-work fork keeps a peer whose best known meets the floor"
    );
    assert!(!logs_have(
        "outbound peer headers chain has insufficient work"
    ));
    assert_eq!(
        peer.best_known(),
        Some(hub.tip_hash().unwrap()),
        "a low-work fork does not replace a best known header that meets the floor"
    );
    let again = regtest_header_chain(header_at(&hub, 0).block_hash(), 1);
    rbitcoin_log::capture_logs(true);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(again),
    )
    .await;
    assert!(
        !peer.stop.load(Ordering::SeqCst),
        "a second low-work fork keeps the peer"
    );
    assert!(!logs_have(
        "outbound peer headers chain has insufficient work"
    ));
    assert_eq!(peer.best_known(), Some(hub.tip_hash().unwrap()));
    let _ = std::fs::remove_dir_all(dir);
}

/// Inv, block, and compact must not replace a best-known header that has
/// more work. A later short fork then still keeps the outbound peer.
#[tokio::test]
async fn earlier_block_does_not_replace_best_known() {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_blockdata::Inventory;
    use rbitcoin_net::peers::PeerConnType;
    use std::sync::atomic::Ordering;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-best-known-inv");
    let hub = std::sync::Arc::new(hub);
    let mut floor = [0u8; 32];
    floor[30] = 0x10;
    hub.set_minimum_chain_work(Some(floor));
    hub.ensure_genesis().unwrap();
    hub.mine(4, op_true(), vec![]).unwrap();
    let met = hub.chain_work().unwrap().to_be_bytes();
    hub.set_minimum_chain_work(Some(met));
    let tip_time = u64::from(hub.tip_header().unwrap().time);
    hub.clock
        .set_mock(i64::try_from(tip_time + hub.max_tip_age_secs() + 1).unwrap());
    assert!(hub.in_ibd(), "a stale tip stays in initial block download");
    let tip = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer_as(&peers, 18512, 92, PeerConnType::OutboundFullRelay);
    peer.note_best_known(tip);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let unknown = BlockHash::from_byte_array([0xab; 32]);
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &[Inventory::Block(unknown)],
    )
    .unwrap();
    assert_eq!(
        peer.best_known(),
        Some(tip),
        "an unknown inv does not replace a best known header"
    );
    let early = hub
        .query
        .reconstruct_block_at_height(Height(1))
        .unwrap();
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &[Inventory::WitnessBlock(early.block_hash())],
    )
    .unwrap();
    assert_eq!(
        peer.best_known(),
        Some(tip),
        "an earlier block inv does not replace a best known header"
    );
    on_block(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &early,
    )
    .await
    .unwrap();
    assert_eq!(
        peer.best_known(),
        Some(tip),
        "an earlier block does not replace a best known header"
    );
    follow.cmpct_version = 2;
    let hsi = HeaderAndShortIds::from_block(&early, 1, 2, &[0]).unwrap();
    on_cmpctblock_reject_early(
        &hub,
        &mut follow,
        Some(peer.as_ref()),
        &hsi,
        early.block_hash(),
    )
    .unwrap();
    assert_eq!(
        peer.best_known(),
        Some(tip),
        "an earlier compact block does not replace a best known header"
    );
    peer.note_best_known(early.block_hash());
    let tip_block = hub.query.reconstruct_block_at_height(Height(4)).unwrap();
    on_block(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &tip_block,
    )
    .await
    .unwrap();
    assert_eq!(
        peer.best_known(),
        Some(tip),
        "a higher-work block still becomes best known"
    );
    let fork = regtest_header_chain(header_at(&hub, 0).block_hash(), 1);
    rbitcoin_log::capture_logs(true);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(fork),
    )
    .await;
    assert!(
        !peer.stop.load(Ordering::SeqCst),
        "a short low-work fork keeps the peer after an earlier block"
    );
    assert!(!logs_have(
        "outbound peer headers chain has insufficient work"
    ));
    let _ = std::fs::remove_dir_all(dir);
}

/// An equal-work fork is stored, then dropped from the pending map when the
/// body loses the tie. Its work must still count, or the next short low-work
/// headers message drops the outbound peer.
#[tokio::test]
async fn equal_work_fork_keeps_its_work_after_pending_drop() {
    use bitcoin::p2p::message_blockdata::Inventory;
    use rbitcoin_net::peers::PeerConnType;
    use std::sync::atomic::Ordering;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-equal-work");
    let hub = std::sync::Arc::new(hub);
    let mut floor = [0u8; 32];
    floor[30] = 0x10;
    hub.set_minimum_chain_work(Some(floor));
    hub.ensure_genesis().unwrap();
    hub.mine(4, op_true(), vec![]).unwrap();
    let met = hub.chain_work().unwrap().to_be_bytes();
    hub.set_minimum_chain_work(Some(met));
    let tip_time = u64::from(hub.tip_header().unwrap().time);
    hub.clock
        .set_mock(i64::try_from(tip_time + hub.max_tip_age_secs() + 1).unwrap());
    assert!(hub.in_ibd(), "a stale tip stays in initial block download");
    let tip = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer_as(&peers, 18513, 93, PeerConnType::OutboundFullRelay);
    peer.note_best_known(tip);
    let parent_hdr = header_at(&hub, 3);
    let mut fork_hdr = parent_hdr;
    fork_hdr.prev_blockhash = parent_hdr.block_hash();
    fork_hdr.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x44; 32]);
    fork_hdr.time = parent_hdr.time.saturating_add(600);
    fork_hdr.bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
    fork_hdr.nonce = 0;
    rbitcoin_consensus::grind_regtest_pow(&mut fork_hdr);
    let fork_hash = fork_hdr.block_hash();
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![fork_hdr]),
    )
    .await;
    assert!(
        hub.query
            .get_header_by_hash(&fork_hash.to_byte_array())
            .unwrap()
            .is_some(),
        "the equal-work fork is stored"
    );
    assert_eq!(
        peer.best_known(),
        Some(fork_hash),
        "an equal-work fork becomes best known"
    );
    assert!(
        !peer.stop.load(Ordering::SeqCst),
        "the equal-work fork itself stays connected"
    );
    follow.pending_headers.remove(&fork_hash);
    let early = hub
        .query
        .reconstruct_block_at_height(Height(1))
        .unwrap();
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &[Inventory::Block(early.block_hash())],
    )
    .unwrap();
    assert_eq!(
        peer.best_known(),
        Some(fork_hash),
        "a lower block does not replace an equal-work fork after it leaves pending"
    );
    let low_parent = header_at(&hub, 2);
    let mut low_hdr = low_parent;
    low_hdr.prev_blockhash = low_parent.block_hash();
    low_hdr.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x45; 32]);
    low_hdr.time = low_parent.time.saturating_add(600);
    low_hdr.bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
    low_hdr.nonce = 0;
    rbitcoin_consensus::grind_regtest_pow(&mut low_hdr);
    let low = vec![low_hdr];
    rbitcoin_log::capture_logs(true);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(low),
    )
    .await;
    assert!(
        !peer.stop.load(Ordering::SeqCst),
        "a short low-work headers message keeps the peer"
    );
    assert!(!logs_have(
        "outbound peer headers chain has insufficient work"
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn full_headers_page_is_not_an_insufficient_work_disconnect() {
    use rbitcoin_net::codec::MAX_HEADERS_RESULTS;
    use rbitcoin_net::peers::PeerConnType;
    assert!(
        !outbound_insufficient_work_disconnect(
            true,
            MAX_HEADERS_RESULTS,
            PeerConnType::OutboundFullRelay,
            true,
            false,
        ),
        "a full page is not the peer's tip"
    );
    assert!(outbound_insufficient_work_disconnect(
        true,
        MAX_HEADERS_RESULTS - 1,
        PeerConnType::BlockRelay,
        true,
        false,
    ));
    assert!(!outbound_insufficient_work_disconnect(
        true,
        MAX_HEADERS_RESULTS - 1,
        PeerConnType::OutboundFullRelay,
        true,
        true,
    ));
    assert!(!outbound_insufficient_work_disconnect(
        false,
        1,
        PeerConnType::OutboundFullRelay,
        true,
        false,
    ));
    assert!(!outbound_insufficient_work_disconnect(
        true,
        1,
        PeerConnType::Manual,
        true,
        false,
    ));
    assert!(!outbound_insufficient_work_disconnect(
        true,
        0,
        PeerConnType::OutboundFullRelay,
        true,
        false,
    ));
}

/// Tip work meets the floor. A bad-proof-of-work compact whose parent is the
/// tip scores like a bad `block` and asks the peer for nothing. A valid
/// compact of the next block still fills from the mempool.
#[tokio::test]
async fn bad_pow_cmpct_scores_and_asks_for_nothing() {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-pow");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let floor = hub.chain_work().unwrap().to_be_bytes();
    hub.set_minimum_chain_work(Some(floor));
    assert!(hub.meets_minimum_chain_work());
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
        .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let (out_tx, mut out_rx) = peer_out_channel();

    let bad = bad_pow_cmpct_on_tip(&hub);
    assert_eq!(bad.short_ids.len(), 1);
    assert!(!hub.header_claimed_pow_ok(&bad.header));
    let plain = live_peer(&peers, 18510, 30, true);
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(plain.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: bad.clone(),
        }),
    )
    .await;
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "bad compact proof of work scores like a bad block"
    );
    assert!(
        plain.stop.load(Ordering::SeqCst),
        "a plain peer is disconnected"
    );
    assert!(
        follow.pending_headers.is_empty(),
        "bad proof of work must not enter pending headers"
    );
    assert!(
        plain.best_known().is_none(),
        "bad proof of work must not update best known"
    );
    let rejected = take_msgs(&mut out_rx);
    assert!(
        !rejected
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetBlockTxn(_))),
        "a rejected compact must not ask for blocktxn"
    );
    assert!(
        !rejected
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetHeaders(_))),
        "a rejected compact must not ask for headers"
    );

    peers.set_noban(true);
    let noban = live_peer(&peers, 18511, 31, true);
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(noban.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: bad.clone(),
        }),
    )
    .await;
    assert_eq!(follow.ban_score, 0, "a noban peer gathers no score");
    assert!(!noban.stop.load(Ordering::SeqCst));
    peers.set_noban(false);

    let manual = live_peer_as(&peers, 18512, 32, rbitcoin_net::peers::PeerConnType::Manual);
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(manual.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock { compact_block: bad }),
    )
    .await;
    assert_eq!(follow.ban_score, 0, "a manual peer gathers no score");
    assert!(!manual.stop.load(Ordering::SeqCst));

    hub.confirm_empty_regtest(100).unwrap();
    assert_eq!(hub.tip_height(), Some(101));
    let cb = hub
        .query
        .reconstruct_block_at_height(rbitcoin_primitives::Height(1))
        .unwrap()
        .txdata
        .into_iter()
        .next()
        .unwrap();
    let spend = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cb.compute_txid(),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_9999_9000),
            script_pubkey: op_true(),
        }],
    };
    let spend_id = spend.compute_txid();
    mp.admit(&spend).expect("mature coinbase spend");
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let block =
        rbitcoin_consensus::mine_regtest_paying(prev, time, height, op_true(), vec![spend]);
    let hsi = HeaderAndShortIds::from_block(&block, 7, 2, &[0]).unwrap();
    assert_eq!(hsi.short_ids.len(), 1);
    assert!(hub.header_claimed_pow_ok(&hsi.header));
    let peer = live_peer(&peers, 18513, 33, true);
    peer.set_hb_to(true);
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock { compact_block: hsi }),
    )
    .await;
    assert_eq!(hub.tip_height(), Some(102));
    assert!(!mp.contains(&spend_id));
    assert_eq!(follow.ban_score, 0);
    let _ = std::fs::remove_dir_all(dir);
}

/// Next-tip compact with one short id and a nonce that fails proof of work.
fn bad_pow_cmpct_on_tip(hub: &rbitcoin_net::chain::ChainHub) -> bitcoin::bip152::HeaderAndShortIds {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let prev = hub.tip_hash().unwrap();
    let time = hub.tip_header().unwrap().time.saturating_add(1);
    let height = hub.tip_height().unwrap().saturating_add(1);
    let extra = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x44; 32]),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: op_true(),
        }],
    };
    let block = rbitcoin_consensus::mine_regtest_paying(prev, time, height, op_true(), vec![extra]);
    let mut hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    let target = bitcoin::Target::from_compact(hsi.header.bits);
    loop {
        hsi.header.nonce = hsi.header.nonce.wrapping_add(1);
        if hsi.header.validate_pow(target).is_err() {
            break;
        }
    }
    hsi
}

/// A connecting batch under the floor is neither stored nor fetched.
#[tokio::test]
async fn below_floor_headers_are_not_stored_or_fetched() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("below-floor");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let (src_dir, src) = rbitcoin_net::chain::tiny_regtest_hub_labeled("below-floor-src");
    let src = std::sync::Arc::new(src);
    src.ensure_genesis().unwrap();
    src.mine(3, op_true(), vec![]).unwrap();
    hub.set_minimum_chain_work(Some(work_floor(0xff)));
    assert!(!hub.meets_minimum_chain_work());
    let hdrs: Vec<_> = (1..=3u32).map(|h| header_at(&src, h)).collect();
    let peer = live_peer(&peers, 18601, 41, false);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(hdrs.clone()),
    )
    .await;
    assert!(
        peer.best_known().is_none(),
        "a low-work batch does not become the peer's best known"
    );
    assert!(
        asked_blocks(&mut out_rx).is_empty(),
        "below-floor headers are not fetched"
    );
    assert_eq!(side_tips(&hub), 0, "below-floor headers are not stored");
    peers.set_noban(true);
    // The stamp is whole seconds of the hub clock. Pin it so a second
    // boundary between the push and the assert cannot move the expected value.
    let stamp_at = 1_700_000_000;
    peers.set_mock_now(stamp_at);
    let noban = live_peer(&peers, 18602, 42, false);
    let mut follow_nb = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow_nb,
        Some(noban.as_ref()),
        NetworkMessage::Headers(hdrs),
    )
    .await;
    assert!(
        side_tips(&hub) > 0,
        "a noban peer still persists a below-floor chain"
    );
    assert_eq!(
        noban.last_block_announcement.load(Ordering::Relaxed),
        stamp_at,
        "a noban peer stamps its accepted heavier below-floor header"
    );
    peers.set_noban(false);
    let _ = std::fs::remove_dir_all(dir);
    let _ = std::fs::remove_dir_all(src_dir);
}

/// A header that does not connect through pending headers is still ignored
/// while our chain is under the floor, and does not answer our getheaders.
/// A header on an earlier best-chain block does answer it.
#[tokio::test]
async fn below_floor_header_answers_getheaders_only_on_our_chain() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("below-floor-disc");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(2, op_true(), vec![]).unwrap();
    let tip_parent = hub.tip_header().unwrap().prev_blockhash;
    hub.set_minimum_chain_work(Some(work_floor(0xff)));
    assert!(!hub.meets_minimum_chain_work());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18621, 61, false);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let orphan = regtest_header_chain(BlockHash::from_byte_array([0x11; 32]), 1);
    peer.note_awaiting_headers();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(orphan),
    )
    .await;
    assert_eq!(side_tips(&hub), 0);
    assert!(asked_blocks(&mut out_rx).is_empty());
    assert!(
        peer.is_awaiting_headers(),
        "an unconnecting header does not answer our getheaders"
    );
    let fork = regtest_header_chain(tip_parent, 1);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(fork),
    )
    .await;
    assert!(
        !peer.is_awaiting_headers(),
        "a header on an earlier best-chain block answers our getheaders"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Pending already holds the cap, and the next full batch still connects.
/// That is 8_000 + 2_000 headers. The batch stays in RAM under the floor
/// and still answers our getheaders.
#[tokio::test]
async fn full_pending_below_floor_batch_answers_getheaders() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("below-floor-cap");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    hub.set_minimum_chain_work(Some([0xff; 32]));
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18622, 62, false);
    let (out_tx, _out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let batch = MAX_HEADERS_RESULTS as u32;
    let mut prev = hub.tip_hash().unwrap();
    // The next `on_headers` is the batch under test. The cap is already in the map.
    let setup = regtest_header_chain(prev, MAX_PENDING_HEADERS as u32);
    fill_pending(&mut follow, &setup);
    prev = setup.last().unwrap().block_hash();
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    peer.note_awaiting_headers();
    let chain = regtest_header_chain(prev, batch);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(chain),
    )
    .await;
    assert_eq!(side_tips(&hub), 0, "the batch stays under the floor");
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    assert!(
        !peer.is_awaiting_headers(),
        "a low-work batch that connects in RAM answers our getheaders"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Headers with real regtest proof-of-work, not accepted blocks. Accepting
/// two thousand blocks is a full connect per height.
fn regtest_header_chain(prev: BlockHash, n: u32) -> Vec<bitcoin::block::Header> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = prev;
    for i in 1..=n {
        let mut header = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([i as u8; 32]),
            time: 1_600_000_000 + i * 600,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        rbitcoin_consensus::grind_regtest_pow(&mut header);
        prev = header.block_hash();
        out.push(header);
    }
    out
}

/// A full batch under minimum chain work is ignored and not paged.
/// The next header, sent on its own, is stored once the path crosses the floor.
#[tokio::test]
async fn below_floor_full_batch_does_not_page() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("below-floor-full");
    let hub = ChainHub::new(q, ChainParams::regtest(), Milestone::NONE);
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let n = MAX_HEADERS_RESULTS as u32;
    let chain = regtest_header_chain(hub.tip_hash().unwrap(), n + 1);
    let base = hub.chain_work().unwrap();
    let below = rbitcoin_net::most_work::sum_work(
        std::iter::once(base).chain(chain[..n as usize].iter().map(|h| h.work())),
    )
    .unwrap()
    .to_be_bytes();
    let floor = rbitcoin_net::most_work::sum_work(std::iter::once(base).chain(chain.iter().map(|h| h.work())))
        .unwrap()
        .to_be_bytes();
    assert!(below < floor, "the full batch is still under the next header");
    hub.set_minimum_chain_work(Some(floor));
    let first = chain[..n as usize].to_vec();
    let peer = live_peer(&peers, 18611, 51, false);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(first),
    )
    .await;
    assert!(peer.best_known().is_none());
    assert_eq!(side_tips(&hub), 0, "the below-floor batch is not stored");
    let mut locators = Vec::new();
    for msg in take_msgs(&mut out_rx) {
        if let NetworkMessage::GetHeaders(gh) = msg {
            locators.push(gh.locator_hashes);
        }
    }
    assert!(
        locators.is_empty(),
        "a refused below-floor batch does not ask for the next page"
    );
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![chain[n as usize]]),
    )
    .await;
    assert!(
        side_tips(&hub) > 0,
        "the chain is stored once pending work crosses the floor"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A side block three days behind the best header is still served. Every
/// `+` and `/` rewrite of the 30-day limit is shorter than three days.
#[test]
fn three_day_side_block_is_served() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("stale-serve");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let t0 = 1_700_000_000u32;
    hub.clock.set_mock(i64::from(t0));
    let old = rbitcoin_consensus::mine_regtest_paying(gen, t0, 1, op_true(), vec![]);
    hub.accept_block(old.clone()).unwrap();
    let old_hash = old.block_hash();
    run_on_tip_accept(|| hub.invalidate_block_inner(old_hash)).unwrap();
    let t1 = t0 + 3 * 24 * 60 * 60;
    hub.clock.set_mock(i64::from(t1));
    let tip = rbitcoin_consensus::mine_regtest_paying(gen, t1, 1, op_true(), vec![]);
    hub.accept_block(tip).unwrap();
    assert!(!hub.is_connected(&old_hash));
    let served =
        headers_reply_for_getheaders(&hub, &GetHeadersMessage::new(vec![], old_hash)).unwrap();
    assert_eq!(
        served.len(),
        1,
        "a side block three days behind the tip is served"
    );
    assert_eq!(served[0].block_hash(), old_hash);
    let _ = std::fs::remove_dir_all(dir);
}

/// The store has no tip. `getheaders` is answered from the recent body cache.
#[test]
fn getheaders_serves_cached_bodies_when_the_store_has_no_tip() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cache-serve");
    assert!(hub.tip_height().is_none());
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    hub.cache.push_best(0, genesis.clone());
    let mut prev = genesis.block_hash();
    let mut time = genesis.header.time;
    let mut hashes = vec![prev];
    for h in 1..=3u32 {
        time = time.saturating_add(600);
        let block = rbitcoin_consensus::mine_regtest_paying(prev, time, h, op_true(), vec![]);
        prev = block.block_hash();
        hashes.push(prev);
        hub.cache.push_best(h, block);
    }
    let stop = hashes[2];
    let served = headers_reply_for_getheaders(
        &hub,
        &GetHeadersMessage::new(vec![hashes[0]], stop),
    )
    .unwrap();
    assert_eq!(served.len(), 2, "headers start after the locator and stop at the hash");
    assert_eq!(served[0].block_hash(), hashes[1]);
    assert_eq!(served[1].block_hash(), stop);
    let _ = std::fs::remove_dir_all(dir);
}

/// Noting a later block must not forget the earlier ask. A second peer
/// announcing the same headers does not fetch the first body again.
#[tokio::test]
async fn a_later_ask_keeps_the_earlier_block() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("asked-keep");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let gen = hub.tip_hash().unwrap();
    let t = hub.tip_header().unwrap().time.saturating_add(1);
    let a = rbitcoin_consensus::mine_regtest_paying(gen, t, 1, op_true(), vec![]);
    let b = rbitcoin_consensus::mine_regtest_paying(a.block_hash(), t.saturating_add(1), 2, op_true(), vec![]);
    let peer = live_peer(&peers, 18601, 40, false);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![a.header, b.header]),
    )
    .await;
    let first = asked_blocks(&mut out_rx);
    assert!(
        first.contains(&a.block_hash()) && first.contains(&b.block_hash()),
        "both bodies are fetched once, got {first:?}"
    );

    let peer2 = live_peer(&peers, 18602, 41, false);
    let (out2, mut rx2) = peer_out_channel();
    let mut follow2 = PeerFollowState::new();
    push(
        &hub,
        &out2,
        &mut follow2,
        Some(peer2.as_ref()),
        NetworkMessage::Headers(vec![a.header, b.header]),
    )
    .await;
    let second = asked_blocks(&mut rx2);
    assert!(
        !second.contains(&a.block_hash()),
        "the first body stays asked after the later one is noted, got {second:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Regtest-PoW headers on `parent`, timed after it.
fn regtest_headers_after(parent: &bitcoin::block::Header, n: u32) -> Vec<bitcoin::block::Header> {
    let mut out = Vec::with_capacity(n as usize);
    let mut prev = *parent;
    for i in 1..=n {
        let mut header = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev.block_hash(),
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x70 ^ i as u8; 32]),
            time: prev.time + 1,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff),
            nonce: 0,
        };
        rbitcoin_consensus::grind_regtest_pow(&mut header);
        prev = header;
        out.push(header);
    }
    out
}

/// A peer's parked headers are scored once per message, not once per item.
/// Duplicates of one tip, every hash on a chain, a disjoint chain, forks off
/// a shared prefix, a re-sent chain, a body we already have, and a compact
/// block under `-minimumchainwork` each cost items plus parked headers. A
/// header that does not connect reads nothing from the header store.
#[tokio::test]
async fn parked_headers_are_walked_once_per_message() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-walk-once");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let have = hub.query.reconstruct_block_at_height(Height(1)).unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18621, 61, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let trunk = regtest_header_chain(BlockHash::from_byte_array([0xab; 32]), 150);
    let other = regtest_header_chain(BlockHash::from_byte_array([0xcd; 32]), 50);
    for chain in [&trunk, &other] {
        push(
            &hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(chain.clone()),
        )
        .await;
    }
    let mut forks = Vec::new();
    let _ = hub.take_stored_header_lookups();
    for at in (0..trunk.len()).step_by(10) {
        let fork = regtest_headers_after(&trunk[at], 1);
        push(
            &hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(fork.clone()),
        )
        .await;
        forks.extend(fork);
    }
    let lookups = hub.take_stored_header_lookups();
    assert!(
        lookups <= 4 * forks.len() as u64,
        "a one-header fork that does not connect is not walked in the store: {lookups} reads"
    );
    let parked = follow.pending_headers.len() as u64;
    assert_eq!(parked, 215, "every chain and fork is parked");
    assert!(peer.best_known().is_none(), "a parked chain is not best known");

    let mut items = vec![Inventory::Block(trunk[149].block_hash()); 300];
    for h in trunk.iter().chain(&other).chain(&forks) {
        items.push(Inventory::WitnessBlock(h.block_hash()));
    }
    let _ = hub.take_path_work_steps();
    on_inv(&hub, &out_tx, &mut follow, Some(peer.as_ref()), &items).unwrap();
    let steps = hub.take_path_work_steps();
    assert!(
        steps <= 3 * (items.len() as u64 + parked),
        "an inv scores each parked header once: {steps} steps for {} items",
        items.len()
    );
    assert!(peer.best_known().is_none());

    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(trunk.clone()),
    )
    .await;
    let steps = hub.take_path_work_steps();
    assert!(
        steps <= 3 * (trunk.len() as u64 + parked),
        "re-sent parked headers score the chain once: {steps} steps"
    );

    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Block(have),
    )
    .await;
    let steps = hub.take_path_work_steps();
    assert!(
        steps <= 4 * parked,
        "a body we have scores every parked leaf once: {steps} steps"
    );

    hub.set_minimum_chain_work(Some([0x7f; 32]));
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    let mut block = orphan_body(BlockHash::from_byte_array([0xef; 32]), 0);
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        }),
    )
    .await;
    assert!(follow.pending_headers.contains_key(&block.block_hash()));
    let steps = hub.take_path_work_steps();
    assert!(
        steps <= 4 * (parked + 1),
        "under the work floor a compact block scores each parked header once: {steps} steps"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A parked chain that later connects becomes best known through `inv`, and
/// an indexed lower block does not replace it. Many items naming that chain
/// score it once.
#[tokio::test]
async fn parked_chain_that_connects_becomes_best_known() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-walk-connects");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(2, op_true(), vec![]).unwrap();
    let tip = hub.tip_header().unwrap();
    let low = hub.query.reconstruct_block_at_height(Height(1)).unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18622, 62, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let chain = regtest_headers_after(&tip, 40);
    let last = chain[39].block_hash();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(chain[1..].to_vec()),
    )
    .await;
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &[Inventory::Block(last)],
    )
    .unwrap();
    assert!(
        peer.best_known().is_none(),
        "a chain that does not connect is not best known"
    );
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![chain[0]]),
    )
    .await;
    assert_eq!(peer.best_known(), Some(chain[0].block_hash()));
    let parked = follow.pending_headers.len() as u64;
    let mut items = vec![Inventory::Block(last); 200];
    items.extend(chain.iter().map(|h| Inventory::Block(h.block_hash())));
    items.push(Inventory::Block(low.block_hash()));
    let _ = hub.take_path_work_steps();
    on_inv(&hub, &out_tx, &mut follow, Some(peer.as_ref()), &items).unwrap();
    let steps = hub.take_path_work_steps();
    assert_eq!(
        peer.best_known(),
        Some(last),
        "the connected parked tip is best known; a lower indexed block does not replace it"
    );
    assert!(
        steps <= 3 * (items.len() as u64 + parked),
        "the connected chain is scored once: {steps} steps"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Header-only forks the store holds are outside the pending cap. A memo
/// keeps a bounded number of their hashes, and scores every leaf above them
/// as a memo that keeps them all does.
#[tokio::test]
async fn path_work_memo_keeps_a_bounded_number_of_stored_headers() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-walk-stored-cap");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let tip = hub.tip_header().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18624, 64, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let mut pending = std::collections::HashMap::new();
    let mut leaves = Vec::new();
    for fork in 0..3u8 {
        let mut first = regtest_headers_after(&tip, 1)[0];
        first.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x40 + fork; 32]);
        first.nonce = 0;
        rbitcoin_consensus::grind_regtest_pow(&mut first);
        let mut stored = vec![first];
        stored.extend(regtest_headers_after(&first, 5));
        let top = stored[5];
        push(
            &hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(stored),
        )
        .await;
        assert!(hub.header_of(&top.block_hash()).is_some());
        assert!(!hub.is_connected(&top.block_hash()));
        let leaf = regtest_headers_after(&top, 1)[0];
        pending.insert(leaf.block_hash(), leaf);
        leaves.push(leaf.block_hash());
    }

    let mut all = rbitcoin_net::peer::PathWorkMemo::default();
    let mut capped = rbitcoin_net::peer::PathWorkMemo::with_stored_cap(4);
    for leaf in &leaves {
        let work = all.work_of_header_path(&hub, &pending, *leaf);
        assert!(work.is_some(), "a leaf on a stored fork reaches our chain");
        assert_eq!(capped.work_of_header_path(&hub, &pending, *leaf), work);
    }
    assert_eq!(
        all.entries(),
        leaves.len() + 18,
        "every stored header walked is kept under the default cap"
    );
    assert!(
        capped.entries() <= leaves.len() + 4,
        "a capped memo keeps the parked leaves and four stored headers: {}",
        capped.entries()
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Eviction asks one memo whether a tip fails claimed proof of work and then
/// for that tip's work. The failure walk must not spend the stored-header
/// slots the work walk needs, or every later leaf re-walks the fork.
#[tokio::test]
async fn failure_walk_does_not_spend_the_work_walk_cache() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-walk-split-cap");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let tip = hub.tip_header().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18625, 65, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let stored_n = 20u32;
    let stored = regtest_headers_after(&tip, stored_n);
    let top = stored[stored.len() - 1];
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(stored),
    )
    .await;
    assert!(hub.header_of(&top.block_hash()).is_some());
    assert!(!hub.is_connected(&top.block_hash()));
    let mut pending = std::collections::HashMap::new();
    let mut leaves = Vec::new();
    for n in 0..30u32 {
        let mut leaf = regtest_headers_after(&top, 1)[0];
        let mut merkle = [0x61u8; 32];
        merkle[..4].copy_from_slice(&n.to_le_bytes());
        leaf.merkle_root = bitcoin::TxMerkleNode::from_byte_array(merkle);
        leaf.nonce = 0;
        rbitcoin_consensus::grind_regtest_pow(&mut leaf);
        pending.insert(leaf.block_hash(), leaf);
        leaves.push(leaf.block_hash());
    }
    let mut expect = rbitcoin_net::peer::PathWorkMemo::default();
    let mut want = Vec::with_capacity(leaves.len());
    for leaf in &leaves {
        want.push(expect.work_of_header_path(&hub, &pending, *leaf));
    }
    let cap = 22;
    let mut memo = rbitcoin_net::peer::PathWorkMemo::with_stored_cap(cap);
    let _ = hub.take_path_work_steps();
    for (leaf, work) in leaves.iter().zip(&want) {
        assert!(
            !memo.path_fails_claimed_pow(&hub, &pending, *leaf),
            "stored headers already passed claimed proof of work"
        );
        assert_eq!(memo.work_of_header_path(&hub, &pending, *leaf), *work);
    }
    let steps = hub.take_path_work_steps();
    let bound = 4 * (leaves.len() as u64 + u64::from(stored_n));
    assert!(
        steps <= bound,
        "a stored fork that fits in the cap is scored once per walk: {steps} steps, bound {bound}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Fill `follow`'s pending map to the cap with headers whose parents are
/// unknown.
fn fill_pending_orphans(follow: &mut PeerFollowState, like: &bitcoin::block::Header) {
    let mut leaf = 0u32;
    while follow.pending_headers.len() < MAX_PENDING_HEADERS {
        let mut merkle = [0x6bu8; 32];
        merkle[..4].copy_from_slice(&leaf.to_le_bytes());
        let mut hdr = *like;
        hdr.prev_blockhash = bitcoin::BlockHash::from_byte_array([0x77; 32]);
        hdr.merkle_root = bitcoin::TxMerkleNode::from_byte_array(merkle);
        hdr.time = like.time + 1;
        rbitcoin_consensus::grind_regtest_pow(&mut hdr);
        follow.pending_headers.insert(hdr.block_hash(), hdr);
        leaf += 1;
    }
}

/// Bytes of the entries of a full pending map. A copy of its table is
/// about twice that.
fn pending_map_bytes() -> usize {
    std::mem::size_of::<(bitcoin::BlockHash, bitcoin::block::Header)>() * MAX_PENDING_HEADERS
}

/// Compact block whose header is `header`. The coinbase is only there so
/// the short-id encoding has a transaction; the header bytes are `header`.
fn cmpct_of_header(header: &bitcoin::block::Header) -> NetworkMessage {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    let mut block = orphan_body(header.prev_blockhash, header.nonce);
    block.header = *header;
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    NetworkMessage::CmpctBlock(CmpctBlock { compact_block: hsi })
}

/// Send `msg` and return the largest allocation this thread asked for, and
/// how many asks had the size of `table`, the pending map's own table: a
/// copy of the map asks for exactly that. The header job runs on this
/// thread for a hub with no shared handle.
async fn asks_for(
    hub: &rbitcoin_net::chain::ChainHub,
    out_tx: &PeerOutTx,
    follow: &mut PeerFollowState,
    peer: &rbitcoin_net::peers::LivePeer,
    table: usize,
    msg: NetworkMessage,
) -> (usize, usize) {
    crate::alloc_count::watch(table);
    let _ = crate::alloc_count::take_largest();
    push(hub, out_tx, follow, Some(peer), msg).await;
    (
        crate::alloc_count::take_largest(),
        crate::alloc_count::take_hits(),
    )
}

/// A headers message does not copy the peer's pending map: against a full
/// map of 8,000 headers, a one-header batch that does not connect asks for
/// nothing the size of that map's table, above the work floor or under it.
/// A compact block on our tip does not copy it either.
#[tokio::test]
async fn headers_message_does_not_copy_the_pending_map() {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pending-no-copy");
    // Not `into_arc`: with no shared handle the header job runs here.
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let tip = hub.tip_header().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18624, 64, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let _ = crate::alloc_count::take_largest();
    fill_pending_orphans(&mut follow, &tip);
    let table = crate::alloc_count::take_largest();
    let entries = pending_map_bytes();
    for (case, floor) in [("above the floor", None), ("under the floor", Some([0x7f; 32]))] {
        hub.set_minimum_chain_work(floor);
        let mut stray = tip;
        stray.prev_blockhash = bitcoin::BlockHash::from_byte_array([0x78; 32]);
        stray.time = tip.time + 2;
        stray.nonce = u32::from(floor.is_some());
        rbitcoin_consensus::grind_regtest_pow(&mut stray);
        let (largest, copies) = asks_for(
            &hub,
            &out_tx,
            &mut follow,
            &peer,
            table,
            NetworkMessage::Headers(vec![stray]),
        )
        .await;
        assert_eq!(copies, 0, "{case}: a {table} B ask copied the map");
        assert!(largest < entries / 8, "{case}: largest ask {largest} B against a {entries} B map");
        assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS, "{case}");
    }
    // A compact block on our tip reaches the header job.
    hub.set_minimum_chain_work(None);
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    let mut block = orphan_body(tip.block_hash(), 0);
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    let (_, copies) = asks_for(
        &hub,
        &out_tx,
        &mut follow,
        &peer,
        table,
        NetworkMessage::CmpctBlock(CmpctBlock { compact_block: hsi }),
    )
    .await;
    assert_eq!(copies, 0, "compact block: a {table} B ask copied the map");
    let _ = std::fs::remove_dir_all(dir);
}

/// A chain of 8,000 parked headers is admitted by `headers` messages, not
/// written straight into the map. One new header on its tip, and a resend
/// of that tip, must cost the batch: a handful of path-work steps and no
/// allocation on the scale of the parked map. That holds with no work
/// floor, with a floor this chain meets, and with a floor it does not.
#[tokio::test]
async fn one_header_on_a_parked_chain_does_not_walk_it() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-chain-one");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18626, 66, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let chain = regtest_header_chain(
        BlockHash::from_byte_array([0x7a; 32]),
        MAX_PENDING_HEADERS as u32,
    );
    for batch in chain.chunks(MAX_HEADERS_RESULTS) {
        push(
            &hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(batch.to_vec()),
        )
        .await;
    }
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    assert!(peer.best_known().is_none(), "a parked chain is not best known");
    let entries = pending_map_bytes();
    let tip = *chain.last().unwrap();
    let extension = regtest_headers_after(&tip, 1);
    let floors = [
        ("no floor", None),
        ("floor met", Some([0u8; 32])),
        ("floor not met", Some([0x7f; 32])),
    ];
    for (floor_name, floor) in floors {
        hub.set_minimum_chain_work(floor);
        for (kind, headers) in [
            ("new header", extension.clone()),
            ("parked tip", vec![tip]),
        ] {
            let _ = hub.take_path_work_steps();
            let (largest, _) = asks_for(
                &hub,
                &out_tx,
                &mut follow,
                &peer,
                entries,
                NetworkMessage::Headers(headers),
            )
            .await;
            let steps = hub.take_path_work_steps();
            assert!(
                steps <= 64,
                "{floor_name} / {kind}: {steps} path-work steps"
            );
            assert!(
                largest < entries / 8,
                "{floor_name} / {kind}: largest ask {largest} B against a {entries} B map"
            );
            assert!(
                peer.best_known().is_none(),
                "{floor_name} / {kind}: a parked chain is not best known"
            );
        }
    }
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    // A compact block on that tip is the same bound. No work floor still
    // walks the chain today (`keep_pending_connecting_paths`, then the
    // body fetch). A floor this node does not meet walks it from
    // `any_header_path_meets_minwork`, which `block` uses as well.
    follow.send_cmpct = true;
    follow.cmpct_version = 2;
    for (floor_name, floor) in [("no floor", None), ("floor not met", Some([0x7f; 32]))] {
        hub.set_minimum_chain_work(floor);
        let _ = hub.take_path_work_steps();
        let (largest, _) = asks_for(
            &hub,
            &out_tx,
            &mut follow,
            &peer,
            entries,
            cmpct_of_header(&tip),
        )
        .await;
        let steps = hub.take_path_work_steps();
        assert!(
            steps <= 64,
            "{floor_name} / compact block: {steps} path-work steps"
        );
        assert!(
            largest < entries / 8,
            "{floor_name} / compact block: largest ask {largest} B against a {entries} B map"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Park the child before the page that connects its parent, under a work
/// floor so that page is not stored. The child's mark is rooted at that
/// parent, and the parent arrives with its own parent already parked, so
/// the known-parent drop does not see it. One more header on the child
/// still reaches this node's tip and answers getheaders.
#[tokio::test]
async fn a_later_connecting_page_clears_parked_marks() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-chain-join");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    hub.set_minimum_chain_work(Some([0x7f; 32]));
    assert!(!hub.meets_minimum_chain_work());
    let tip = hub.tip_header().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18627, 67, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let chain = regtest_headers_after(&tip, 3);
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![chain[2]]),
    )
    .await;
    assert!(peer.best_known().is_none(), "the child does not connect yet");
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![chain[0], chain[1]]),
    )
    .await;
    let extension = regtest_headers_after(&chain[2], 1);
    peer.note_awaiting_headers();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(extension),
    )
    .await;
    assert!(
        !peer.is_awaiting_headers(),
        "a header on the parked child answers getheaders once its parent arrives"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Two headers parked before their parent are marked at that parent. The
/// parent, parked next, is marked at its own unknown parent. Once another
/// peer stores that header, a header on the first two reaches it through
/// both marks, connects, and is stored.
#[tokio::test]
async fn a_chain_parked_out_of_order_connects_once_its_root_is_known() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-root-chain");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let tip = hub.tip_header().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18628, 68, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let chain = regtest_headers_after(&tip, 5);
    for page in [vec![chain[2]], vec![chain[3]], vec![chain[1]]] {
        push(
            &hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(page),
        )
        .await;
    }
    let other = live_peer(&peers, 18629, 69, true);
    let (other_tx, _other_rx) = peer_out_channel();
    push(
        &hub,
        &other_tx,
        &mut PeerFollowState::new(),
        Some(other.as_ref()),
        NetworkMessage::Headers(vec![chain[0]]),
    )
    .await;
    assert!(hub.knows_header(&chain[0].block_hash()));
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![chain[4]]),
    )
    .await;
    assert!(
        hub.knows_header(&chain[4].block_hash()),
        "a header on the parked chain connects once its root is known"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Newest-first, each message is the parent of the headers already parked.
/// Rewriting every descendant on that admit copies the parked set. The last
/// header of an 8,000-header chain must stay inside the one-batch bound,
/// and one more header on the leaf must still stop at the mark.
#[tokio::test]
async fn newest_first_park_does_not_copy_the_descendant_set() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-chain-newest");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18628, 68, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let chain = regtest_header_chain(
        BlockHash::from_byte_array([0x7b; 32]),
        MAX_PENDING_HEADERS as u32,
    );
    let entries = pending_map_bytes();
    // Every parent is still unknown, so none of these admits connect.
    // `chain[0]` is the oldest and is sent once, below, so its admit is the one measured.
    for hdr in chain.iter().rev().take(chain.len() - 1) {
        push(
            &hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            NetworkMessage::Headers(vec![*hdr]),
        )
        .await;
    }
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS - 1);
    let (largest, _) = asks_for(
        &hub,
        &out_tx,
        &mut follow,
        &peer,
        entries,
        NetworkMessage::Headers(vec![chain[0]]),
    )
    .await;
    assert!(
        largest < entries / 8,
        "newest-first admit copied the descendant set: {largest} B against a {entries} B map"
    );
    assert_eq!(follow.pending_headers.len(), MAX_PENDING_HEADERS);
    let tip = *chain.last().unwrap();
    let extension = regtest_headers_after(&tip, 1);
    let _ = hub.take_path_work_steps();
    let (largest, _) = asks_for(
        &hub,
        &out_tx,
        &mut follow,
        &peer,
        entries,
        NetworkMessage::Headers(extension),
    )
    .await;
    let steps = hub.take_path_work_steps();
    assert!(
        steps <= 64,
        "newest-first leaf: {steps} path-work steps"
    );
    assert!(
        largest < entries / 8,
        "newest-first leaf: largest ask {largest} B against a {entries} B map"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A connecting batch at the cap stages its evictions in the map and puts
/// them back when it still does not fit: 7,000 parked ancestors of its
/// parent stay, 1,000 headers that fail proof of work go, and 2,000 more
/// would still overflow. The map is as it was, and no step copied it. The
/// eviction's path-work memo and the batch's path walk are map-sized here,
/// so this pins copies by the map's exact table size.
#[tokio::test]
async fn refused_room_for_a_batch_restores_the_pending_map() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pending-no-copy-evict");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let tip = hub.tip_header().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18625, 65, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let trunk = regtest_headers_after(&tip, 7_000);
    let _ = crate::alloc_count::take_largest();
    for hdr in &trunk {
        follow.pending_headers.insert(hdr.block_hash(), *hdr);
    }
    let mut leaf = 0u32;
    while follow.pending_headers.len() < MAX_PENDING_HEADERS {
        let mut hdr = tip;
        hdr.prev_blockhash = bitcoin::BlockHash::from_byte_array([0x79; 32]);
        hdr.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x5c; 32]);
        hdr.nonce = leaf;
        // Mainnet's target: these headers do not meet the work they claim.
        hdr.bits = bitcoin::CompactTarget::from_consensus(0x1d00ffff);
        follow.pending_headers.insert(hdr.block_hash(), hdr);
        leaf += 1;
    }
    let table = crate::alloc_count::take_largest();
    let before = follow.pending_headers.clone();
    let batch = regtest_headers_after(trunk.last().unwrap(), 2_000);
    let (_, copies) = asks_for(
        &hub,
        &out_tx,
        &mut follow,
        &peer,
        table,
        NetworkMessage::Headers(batch),
    )
    .await;
    assert_eq!(copies, 0, "a {table} B ask copied the map");
    assert!(follow.pending_headers == before, "the refused batch left the map as it was");
    let _ = std::fs::remove_dir_all(dir);
}

/// A connecting batch that needs room in a full pending map scores each
/// parked fork once, however many leaves share its trunk.
#[tokio::test]
async fn full_pending_map_eviction_walks_each_header_once() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-walk-evict");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(1, op_true(), vec![]).unwrap();
    let tip = hub.tip_header().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18623, 63, true);
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let trunk = regtest_headers_after(&tip, 100);
    let trunk_tip = trunk[99];
    for hdr in &trunk {
        follow.pending_headers.insert(hdr.block_hash(), *hdr);
    }
    let mut leaf = 0u32;
    while follow.pending_headers.len() < MAX_PENDING_HEADERS {
        let mut merkle = [0x5au8; 32];
        merkle[..4].copy_from_slice(&leaf.to_le_bytes());
        let mut hdr = trunk_tip;
        hdr.prev_blockhash = trunk_tip.block_hash();
        hdr.merkle_root = bitcoin::TxMerkleNode::from_byte_array(merkle);
        hdr.time = trunk_tip.time + 1;
        hdr.nonce = 0;
        rbitcoin_consensus::grind_regtest_pow(&mut hdr);
        follow.pending_headers.insert(hdr.block_hash(), hdr);
        leaf += 1;
    }
    let mut lighter = trunk[0];
    lighter.merkle_root = bitcoin::TxMerkleNode::from_byte_array([0x33; 32]);
    rbitcoin_consensus::grind_regtest_pow(&mut lighter);
    let _ = hub.take_path_work_steps();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        NetworkMessage::Headers(vec![lighter]),
    )
    .await;
    let steps = hub.take_path_work_steps();
    assert!(
        steps <= 6 * MAX_PENDING_HEADERS as u64,
        "eviction walks each parked header a fixed number of times: {steps} steps"
    );
    assert!(
        follow.pending_headers.contains_key(&trunk_tip.block_hash()),
        "a heavier connected fork is not evicted for a lighter batch"
    );
    let _ = std::fs::remove_dir_all(dir);
}
