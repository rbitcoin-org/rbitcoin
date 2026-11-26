use crate::Admit;
use crate::Mine;
use bitcoin::bip152::{BlockTransactions, BlockTransactionsRequest, HeaderAndShortIds};
use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage, Inventory};
use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock, GetBlockTxn, SendCmpct};
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::script::ScriptBuf;
use bitcoin::BlockHash;
use bitcoin::Network;
use rbitcoin_net::cache::BlockCache;
use rbitcoin_net::chain::ChainHub;
use rbitcoin_net::codec::{FramedMessage, MAX_HEADERS_RESULTS, MAX_INV_SIZE, MAX_LOCATOR_SZ};
use rbitcoin_net::error::NetError;
use rbitcoin_net::peer::*;
use rbitcoin_net::peers::{CappedSet, PeerOut};
use rbitcoin_net::seeds::AddrMan;
use rbitcoin_net::send_queue::{peer_out_channel, PeerOutRx, PeerOutTx, Queued};
use rbitcoin_net::tip_accept::run_on_tip_accept;
use rbitcoin_primitives::Height;
use rbitcoin_query::Query;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::broadcast;

use rbitcoin_consensus::{ChainParams, Milestone};

/// A message charged exactly `n` bytes, `n` at least 64 KiB.
fn charged_msg(n: usize) -> NetworkMessage {
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            script_sig: ScriptBuf::from_bytes(vec![0; n - 55]),
            ..Default::default()
        }],
        output: vec![],
    };
    let msg = NetworkMessage::Tx(tx);
    assert_eq!(rbitcoin_net::peers::outbound_msg_bytes(&msg), n);
    msg
}

/// `n` bytes on `peer`'s send queue that no writer drains. Dropping the
/// receiver is the writer finishing them.
fn hold_send_bytes(peer: &rbitcoin_net::peers::LivePeer, n: usize) -> PeerOutRx {
    let (tx, rx) = peer.send_queue().channel();
    tx.send(charged_msg(n)).unwrap();
    rx
}

/// `n` served bodies on `peer`'s send queue that no writer drains.
fn hold_serve_slots(peer: &rbitcoin_net::peers::LivePeer, n: usize) -> PeerOutRx {
    let (tx, rx) = peer.send_queue().channel();
    for _ in 0..n {
        tx.send(PeerOut::Encoded(Vec::new())).unwrap();
    }
    rx
}

fn served_block(q: Queued) -> bitcoin::Block {
    match q.into_out() {
        PeerOut::Encoded(bytes) => {
            assert_eq!(bytes.first().copied(), Some(2), "v2 block short id");
            bitcoin::consensus::encode::deserialize(&bytes[1..]).expect("served block payload")
        }
        PeerOut::Served(NetworkMessage::Block(b)) => b,
        other => panic!("expected served block, got {other:?}"),
    }
}

fn frame_for(msg: NetworkMessage) -> FramedMessage {
    let magic = Magic::from(Network::Regtest);
    let raw = RawNetworkMessage::new(magic, msg);
    let full = serialize(&raw);
    let command: [u8; 12] = full[4..16].try_into().unwrap();
    let payload = full[24..].to_vec();
    FramedMessage {
        magic,
        command,
        payload,
    }
}

#[test]
fn p2p_serve_line_names_tx_bytes_wall() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("serve-line");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let (served_n, served_bytes) = rbitcoin_net::serve_perf::serve_perf_totals();
    let _ = rbitcoin_net::serve_perf::sample_reset_serve_perf();
    let encoded = encode_served_block(&hub.cache, &hub.query, &gen, true)
        .unwrap()
        .expect("genesis Class A body");
    assert_eq!(encoded.first().copied(), Some(2), "v2 block short id");
    let s = rbitcoin_net::serve_perf::sample_reset_serve_perf();
    assert!(s.n >= 1, "{s:?}");
    assert!(s.bytes > 1, "{s:?}");
    assert!(s.tx_count >= 1, "{s:?}");
    let (served_n_after, served_bytes_after) = rbitcoin_net::serve_perf::serve_perf_totals();
    assert!(
        served_n_after > served_n && served_bytes_after > served_bytes.max(1),
        "running serve totals move with the window: before=({served_n},{served_bytes}) after=({served_n_after},{served_bytes_after}) window={s:?}"
    );
    let line = rbitcoin_net::serve_perf::format_serve_perf(&s);
    assert!(
        !line.contains("p2p: serve"),
        "per-block p2p: serve is not the 5s helper: {line}"
    );
    assert!(line.contains("serve n="), "{line}");
    assert!(line.contains("bytes="), "{line}");
    assert!(line.contains("tx="), "{line}");
    assert!(!line.contains("ntx="), "{line}");
    assert!(line.contains("avg_us="), "{line}");
    assert!(line.contains("max_us="), "{line}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn misbehavior_disconnect_log_is_not_banlist() {
    let line = misbehavior_disconnect_log("7", 100);
    assert_eq!(
        line,
        format!("p2p: 7 misbehavior 100 ≥ {BAN_SCORE_THRESHOLD} — disconnect")
    );
    assert!(
        !line.to_ascii_lowercase().contains("ban score"),
        "disconnect log is not banlist language: {line}"
    );
}

#[test]
fn store_not_found_is_soft_session_error() {
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "store: record not found".into()
    )));
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "consensus: store: record not found".into()
    )));
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "StoreError::NotFound for fk".into()
    )));
    assert!(net_error_is_store_not_found(&NetError::Consensus(
        "NOT FOUND".into()
    )));
    assert!(!net_error_is_store_not_found(&NetError::Consensus(
        "corrupt record: multi-spender".into()
    )));
    assert!(!net_error_is_store_not_found(&NetError::Protocol(
        "unknown parent"
    )));
    assert!(!net_error_is_store_not_found(&NetError::Timeout));
    assert!(!net_error_is_store_not_found(&NetError::Io(
        std::io::Error::other("x")
    )));
}

#[test]
fn from_this_peer_insert_caps_and_keeps_latest() {
    use bitcoin::hashes::Hash;
    let mut m = CappedSet::new();
    let cap = 4usize;
    for i in 0u8..6 {
        m.insert(bitcoin::Txid::from_byte_array([i; 32]), cap);
        assert!(m.len() <= cap, "len {}", m.len());
    }
    assert_eq!(m.len(), cap);
    assert!(m.contains_key(&bitcoin::Txid::from_byte_array([5u8; 32])));
    assert!(m.contains_key(&bitcoin::Txid::from_byte_array([2u8; 32])));
    assert!(
        !m.contains_key(&bitcoin::Txid::from_byte_array([0u8; 32])),
        "oldest origin txid must roll off"
    );
    assert!(!m.contains_key(&bitcoin::Txid::from_byte_array([1u8; 32])));
    assert_eq!(FROM_THIS_PEER_CAP, 50_000);
}

#[test]
fn capped_set_reinsert_keeps_insertion_order() {
    use bitcoin::hashes::Hash;
    let mut m = CappedSet::new();
    let cap = 3usize;
    let id = |i: u8| bitcoin::Txid::from_byte_array([i; 32]);
    m.insert(id(0), cap);
    m.insert(id(1), cap);
    m.insert(id(2), cap);
    m.insert(id(0), cap);
    m.insert(id(3), cap);
    assert_eq!(m.len(), cap);
    assert!(
        !m.contains_key(&id(0)),
        "re-insert must not refresh FIFO; oldest insertion still rolls"
    );
    assert!(m.contains_key(&id(1)));
    assert!(m.contains_key(&id(2)));
    assert!(m.contains_key(&id(3)));
}

#[test]
fn tip_follow_locator_empty_store_has_genesis_zero() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("empty");
    let loc = tip_follow_locator(&hub);
    assert!(!loc.is_empty());
    assert_eq!(loc.last().unwrap().to_byte_array(), [0u8; 32]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn tip_follow_locator_includes_tip_after_genesis() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("gen");
    hub.ensure_genesis().unwrap();
    let loc = tip_follow_locator(&hub);
    assert!(!loc.is_empty());
    assert_eq!(loc[0], hub.tip_hash().unwrap());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ibd_connect_does_not_start_headers_sync() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-no-sync");
    hub.ensure_genesis().unwrap();
    assert!(hub.in_ibd(), "regtest genesis is older than 24h");
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let session = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (tx, mut rx) = peer_out_channel();
    assert!(
        maybe_queue_initial_getheaders(&tx, &hub, &session),
        "IBD still asks the one headers peer for the stored tip"
    );
    match rx.try_recv().unwrap().expect_msg() {
        bitcoin::p2p::message::NetworkMessage::GetHeaders(gh) => {
            assert!(
                gh.locator_hashes.contains(&hub.tip_hash().unwrap()),
                "the locator names the stored tip"
            );
        }
        other => panic!("expected getheaders, got {other:?}"),
    }
    let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8334);
    let mut ver2 = ver.clone();
    ver2.nonce = 2;
    let session2 = peers.register(
        addr2,
        addr2,
        &ver2,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (tx2, mut rx2) = peer_out_channel();
    assert!(
        !maybe_queue_initial_getheaders(&tx2, &hub, &session2),
        "a second connecting peer does not start another headers sync"
    );
    assert!(rx2.try_recv().is_err());

    // Leaving IBD is a tip inside 24h, which is also when Core allows every
    // connecting peer to start headers sync. The peer that already started
    // during IBD does not start again.
    let tip_time = u64::from(hub.tip_header().unwrap().time);
    let fresh = tip_time.saturating_add(60);
    peers.set_mock_now(fresh);
    hub.clock.set_mock(i64::try_from(fresh).unwrap());
    assert!(!hub.in_ibd(), "a fresh tip leaves IBD");
    let addr3 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8335);
    let mut ver3 = ver.clone();
    ver3.nonce = 3;
    let session3 = peers.register(
        addr3,
        addr3,
        &ver3,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (tx3, mut rx3) = peer_out_channel();
    assert!(
        maybe_queue_initial_getheaders(&tx3, &hub, &session3),
        "after IBD a connecting peer still starts headers sync"
    );
    assert!(matches!(
        rx3.try_recv().unwrap().expect_msg(),
        bitcoin::p2p::message::NetworkMessage::GetHeaders(_)
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ignored_full_header_batch_does_not_page() {
    use bitcoin::block::{Header, Version};
    use bitcoin::CompactTarget;
    use bitcoin::TxMerkleNode;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-no-page");
    hub.ensure_genesis().unwrap();
    hub.set_minimum_chain_work(Some([0xff; 32]));
    let mut prev = hub.tip_hash().unwrap();
    let mut headers = Vec::with_capacity(MAX_HEADERS_RESULTS);
    for i in 0..MAX_HEADERS_RESULTS {
        let hdr = Header {
            version: Version::TWO,
            prev_blockhash: prev,
            merkle_root: TxMerkleNode::from_byte_array([i as u8; 32]),
            time: 1_700_000_000 + i as u32,
            bits: CompactTarget::from_consensus(0x207fffff),
            nonce: i as u32,
        };
        prev = hdr.block_hash();
        headers.push(hdr);
    }
    let (tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(on_headers(&hub, &tx, &mut follow, None, &headers))
        .unwrap();
    assert!(
        rx.try_recv().is_err(),
        "an ignored 2,000-header batch does not ask for the next page"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn ibd_unknown_block_inv_does_not_getheaders() {
    use bitcoin::p2p::message_blockdata::Inventory;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("ibd-no-inv");
    hub.ensure_genesis().unwrap();
    assert!(hub.in_ibd());
    let (tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let unknown = BlockHash::from_byte_array([0x44; 32]);
    on_inv(&hub, &tx, &mut follow, None, &[Inventory::Block(unknown)]).unwrap();
    assert!(
        matches!(
            rx.try_recv().unwrap().expect_msg(),
            bitcoin::p2p::message::NetworkMessage::GetHeaders(_)
        ),
        "an unknown block inv during IBD still asks for headers"
    );
    assert!(
        hub.header_inv_challenge_pending(),
        "an unknown block inv during IBD challenges the header walk"
    );

    hub.set_max_tip_age_secs(u64::MAX);
    assert!(!hub.in_ibd());
    on_inv(
        &hub,
        &tx,
        &mut follow,
        None,
        &[Inventory::Block(BlockHash::from_byte_array([0x45; 32]))],
    )
    .unwrap();
    assert!(matches!(
        rx.try_recv().unwrap().expect_msg(),
        bitcoin::p2p::message::NetworkMessage::GetHeaders(_)
    ));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_sync_locator_from_unknown_starts_at_that_hash() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("loc-unk");
    hub.ensure_genesis().unwrap();
    let start = BlockHash::from_byte_array([0xab; 32]);
    let loc = headers_sync_locator(&hub, Some(start));
    assert_eq!(loc[0], start);
    assert_eq!(loc.last().copied(), hub.tip_hash());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn headers_sync_locator_from_mid_height_starts_there() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("loc-mid");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let hashes = hub
        .mine(3, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let mid = hashes[0];
    let loc = headers_sync_locator(&hub, Some(mid));
    assert_eq!(loc[0], mid);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn should_poll_peer_headers_skips_behind_and_weaker_fork() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("poll-skip");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    assert!(should_poll_peer_headers(&hub, None));
    hub.mine(3, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub.tip_hash().unwrap();
    assert!(
        should_poll_peer_headers(&hub, Some(tip)),
        "at our tip: still poll in case they have a new block"
    );
    assert!(
        !should_poll_peer_headers(&hub, Some(gen)),
        "best-known on our chain behind tip cannot supply headers after our locator"
    );
    assert!(
        should_poll_peer_headers(&hub, Some(BlockHash::from_byte_array([0xee; 32]))),
        "unknown best-known still poll until we can classify the branch"
    );
    let mut fork = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: gen,
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x22; 32]),
        time: 1_300_000_000,
        bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
        nonce: 99,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut fork);
    hub.ensure_header(&fork).unwrap();
    assert!(
        !should_poll_peer_headers(&hub, Some(fork.block_hash())),
        "persisted weaker fork cannot beat our tip"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A session that connects to a tip already in place does not inv that tip.
#[tokio::test]
async fn session_start_does_not_announce_a_quiet_tip() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("quiet-tip");
    let hub = hub.into_arc();
    hub.ensure_genesis().unwrap();
    hub.mine(3, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    assert_eq!(hub.tip_height(), Some(3));
    let tip = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let mut sess = open_decode_session(Arc::clone(&hub), &peers, 18470, Some(tip)).await;
    assert_eq!(sess.live.header_marks().0, None);
    assert!(
        !block_invs_before_pong(&mut sess, 1).await.contains(&tip),
        "a connect to a tip already in place sends no block inv"
    );
    assert_eq!(sess.live.header_marks().0, None);
    sess.session.abort();
    let _ = std::fs::remove_dir_all(dir);
}

/// A block mined after the handshake snapshot is offered once, as an inv.
/// That inv does not move the header cursor. Offering the same tip again
/// sends nothing.
#[tokio::test]
async fn session_start_announces_a_tip_mined_during_handshake() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("moved-tip");
    let hub = hub.into_arc();
    hub.ensure_genesis().unwrap();
    let at_handshake = hub.tip_hash().unwrap();
    hub.mine(3, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub.tip_hash().unwrap();
    assert_ne!(at_handshake, tip);
    let peers = rbitcoin_net::peers::PeerHub::new();
    let mut sess = open_decode_session(Arc::clone(&hub), &peers, 18471, Some(at_handshake)).await;
    let invs = block_invs_before_pong(&mut sess, 1).await;
    assert_eq!(
        invs.iter().filter(|h| **h == tip).count(),
        1,
        "a tip mined during the handshake is one block inv"
    );
    assert_eq!(
        sess.live.header_marks().0,
        None,
        "an inv does not count as a header the peer has"
    );
    assert_eq!(sess.live.last_tip_offered(), Some(tip));
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let closed = announce_unsent_tip(
        hub.as_ref(),
        &out_tx,
        &mut follow,
        Some(sess.live.as_ref()),
        Some(at_handshake),
    )
    .await
    .unwrap();
    assert!(!closed);
    assert!(
        out_rx.try_recv().is_err(),
        "the same tip is not offered twice"
    );
    sess.session.abort();
    let _ = std::fs::remove_dir_all(dir);
}

/// A tip already queued on the receiver when the session starts is announced
/// once. The header cursor stays empty, and a second offer sends nothing.
#[tokio::test]
async fn queued_tip_before_session_start_is_one_inv() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("queued-tip");
    hub.ensure_genesis().unwrap();
    let at_handshake = hub.tip_hash().unwrap();
    let hub = hub.into_arc();
    let tip_rx = hub.subscribe_tips();
    hub.mine(1, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip = hub.tip_hash().unwrap();
    assert_ne!(at_handshake, tip);
    let peers = rbitcoin_net::peers::PeerHub::new();
    let mut sess = open_decode_session_with(
        Arc::clone(&hub),
        &peers,
        18473,
        Some(at_handshake),
        Some(tip_rx),
    )
    .await;
    let invs = block_invs_before_pong(&mut sess, 1).await;
    assert_eq!(
        invs.iter().filter(|h| **h == tip).count(),
        1,
        "a tip queued before the session starts is one block inv"
    );
    assert_eq!(
        sess.live.header_marks().0,
        None,
        "an inv does not count as a header the peer has"
    );
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let closed = announce_unsent_tip(
        hub.as_ref(),
        &out_tx,
        &mut follow,
        Some(sess.live.as_ref()),
        Some(at_handshake),
    )
    .await
    .unwrap();
    assert!(!closed);
    assert!(
        out_rx.try_recv().is_err(),
        "the same tip is not offered twice"
    );
    sess.session.abort();
    let _ = std::fs::remove_dir_all(dir);
}

/// An inv with an empty header cursor is the tip we offered. A burst of
/// tips that are not descendants of that inv waits out the batch and leaves
/// as one announcement. The header cursor stays empty.
#[tokio::test]
async fn inv_then_non_descendant_waits_out_the_batch() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-batch");
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().unwrap();
    let hub = hub.into_arc();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let mut sess = open_decode_session(Arc::clone(&hub), &peers, 18472, Some(genesis)).await;
    let _ = block_invs_before_pong(&mut sess, 1).await;
    assert_eq!(
        sess.live.last_tip_offered(),
        None,
        "a quiet connect offers nothing"
    );
    hub.mine(1, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let offered = hub.tip_hash().unwrap();
    let mut invs = block_invs_until(&mut sess, offered).await;
    invs.extend(block_invs_before_pong(&mut sess, 2).await);
    assert_eq!(
        invs.iter().filter(|h| **h == offered).count(),
        1,
        "the first tip is one inv"
    );
    assert_eq!(sess.live.header_marks().0, None);
    assert_eq!(
        sess.live.last_tip_offered(),
        Some(offered),
        "an inv is the tip we offered"
    );
    run_on_tip_accept(|| hub.invalidate_block_inner(offered)).unwrap();
    let early = collect_block_invs(&mut sess.reader, sess.magic, Duration::from_millis(120)).await;
    assert!(
        early.is_empty(),
        "a non-descendant tip waits out the batch, got {early:?}"
    );
    // Another coinbase script: inside the same second, the same script would
    // rebuild `offered`, which is invalidated.
    hub.mine(1, bitcoin::ScriptBuf::from_bytes(vec![0x52]), vec![])
        .unwrap();
    let next = hub.tip_hash().unwrap();
    assert_ne!(next, offered);
    let mut later = block_invs_until(&mut sess, next).await;
    later.extend(block_invs_before_pong(&mut sess, 3).await);
    assert_eq!(
        later,
        vec![next],
        "the burst is one announcement of the final tip"
    );
    assert_eq!(
        sess.live.header_marks().0,
        None,
        "an inv does not set the header cursor"
    );
    sess.session.abort();
    let _ = std::fs::remove_dir_all(dir);
}

/// A child of an inv is a descendant, so it is announced at once.
#[tokio::test]
async fn child_of_an_inv_is_not_held() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-child");
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().unwrap();
    let hub = hub.into_arc();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let mut sess = open_decode_session(Arc::clone(&hub), &peers, 18474, Some(genesis)).await;
    let _ = block_invs_before_pong(&mut sess, 1).await;
    let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.mine(1, script.clone(), vec![]).unwrap();
    let offered = hub.tip_hash().unwrap();
    let mut invs = block_invs_until(&mut sess, offered).await;
    invs.extend(block_invs_before_pong(&mut sess, 2).await);
    assert_eq!(invs.iter().filter(|h| **h == offered).count(), 1);
    assert_eq!(sess.live.header_marks().0, None);
    hub.mine(1, script, vec![]).unwrap();
    let child = hub.tip_hash().unwrap();
    assert_ne!(child, offered);
    let early = collect_block_invs(&mut sess.reader, sess.magic, Duration::from_millis(150)).await;
    assert_eq!(
        early,
        vec![child],
        "a child of the inv goes out before the reorg batch"
    );
    assert_eq!(sess.live.header_marks().0, None);
    sess.session.abort();
    let _ = std::fs::remove_dir_all(dir);
}

/// getheaders that ends on the reorg tip is the offer the next block follows.
/// After the reorg batch has already ended, that child goes out at once.
#[tokio::test]
async fn getheaders_of_a_reorg_tip_does_not_hold_its_child() {
    use rbitcoin_net::v2::write_v2_msg;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("gh-reorg-child");
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().unwrap();
    let hub = hub.into_arc();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let mut sess = open_decode_session(Arc::clone(&hub), &peers, 18479, Some(genesis)).await;
    let _ = block_invs_before_pong(&mut sess, 7).await;
    write_v2_msg(&mut sess.writer, NetworkMessage::SendHeaders)
        .await
        .unwrap();
    write_v2_msg(&mut sess.writer, NetworkMessage::Ping(1))
        .await
        .unwrap();
    wait_pong(&mut sess.reader, sess.magic, 1).await;
    let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.mine(1, script.clone(), vec![]).unwrap();
    let parent = hub.tip_hash().unwrap();
    let parent_hdrs = header_tips_until(&mut sess.reader, sess.magic, parent).await;
    assert!(
        parent_hdrs.contains(&parent),
        "the parent is announced, got {parent_hdrs:?}"
    );
    hub.mine(1, script.clone(), vec![]).unwrap();
    let offered = hub.tip_hash().unwrap();
    let offered_hdrs = header_tips_until(&mut sess.reader, sess.magic, offered).await;
    assert!(
        offered_hdrs.contains(&offered),
        "the child is announced, got {offered_hdrs:?}"
    );
    assert_eq!(sess.live.last_tip_offered(), Some(offered));
    run_on_tip_accept(|| hub.invalidate_block_inner(offered)).unwrap();
    assert_eq!(hub.tip_hash(), Some(parent));
    write_v2_msg(
        &mut sess.writer,
        NetworkMessage::GetHeaders(GetHeadersMessage::new(
            vec![genesis],
            BlockHash::from_byte_array([0u8; 32]),
        )),
    )
    .await
    .unwrap();
    let reply_deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        assert!(
            std::time::Instant::now() < reply_deadline,
            "getheaders should answer with the reorg tip"
        );
        let tips =
            collect_header_tips(&mut sess.reader, sess.magic, Duration::from_millis(50)).await;
        if sess.live.header_marks().0 == Some(parent) && tips.contains(&parent) {
            break;
        }
    }
    // A reorg tip stays in `pending_tip` for `TIP_ANNOUNCE_BATCH`. A block
    // mined inside that window is held with it. The batch is closed once
    // that interval has passed and a short read sees no further headers.
    // This deadline starts here. The getheaders loop may already have used
    // most of `reply_deadline`.
    let parent_at = std::time::Instant::now();
    let batch_deadline = parent_at + Duration::from_secs(2);
    loop {
        assert!(
            std::time::Instant::now() < batch_deadline,
            "reorg headers kept arriving past the deadline"
        );
        let more =
            collect_header_tips(&mut sess.reader, sess.magic, Duration::from_millis(20)).await;
        if more.is_empty() && parent_at.elapsed() >= rbitcoin_net::peer::TIP_ANNOUNCE_BATCH {
            break;
        }
    }
    // Another coinbase script: inside the same second, the same script would
    // rebuild `offered`, which is invalidated.
    hub.mine(1, bitcoin::ScriptBuf::from_bytes(vec![0x52]), vec![])
        .unwrap();
    let child = hub.tip_hash().unwrap();
    assert_ne!(child, offered);
    assert_ne!(child, parent);
    let early = collect_header_tips(&mut sess.reader, sess.magic, Duration::from_millis(150)).await;
    assert!(
        early.contains(&child),
        "a child of the headers we just sent goes out before another reorg batch, got {early:?}"
    );
    sess.session.abort();
    let _ = std::fs::remove_dir_all(dir);
}

/// A getheaders reply that ends on the parent of our tip is still the offer.
/// The tip itself is then not held. A header on another branch is not an
/// ancestor of the tip, so it is not recorded.
#[tokio::test]
async fn getheaders_parent_of_the_tip_is_the_offer() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("gh-parent-offer");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.mine(1, script.clone(), vec![]).unwrap();
    let parent = hub.tip_hash().unwrap();
    hub.mine(1, script, vec![]).unwrap();
    let child = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18480);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 80,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let session = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let stale = BlockHash::from_byte_array([0x11; 32]);
    session.note_last_tip_offered(stale);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    on_getheaders(
        &hub,
        &out_tx,
        &mut follow,
        Some(&session),
        &GetHeadersMessage::new(vec![], parent),
    )
    .await
    .unwrap();
    let NetworkMessage::Headers(sent) = out_rx.try_recv().unwrap().expect_msg() else {
        panic!("getheaders should answer with headers");
    };
    assert_eq!(sent.last().unwrap().block_hash(), parent);
    assert_eq!(
        session.last_tip_offered(),
        Some(parent),
        "a reply that ends on the parent of the tip is the offer"
    );
    let child_ev = Ok(rbitcoin_net::chain::TipEvent {
        height: hub.tip_height().unwrap(),
        hash: child,
        header: hub.tip_header().unwrap(),
        reorg_branch_len: 0,
    });
    assert!(
        !tip_is_reorg_vs_sent(&hub, Some(&session), &child_ev),
        "the tip is a child of the headers we sent"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A getheaders reply that ends on the parent does not replace a newer offer.
/// A reorg off that newer block still waits.
#[tokio::test]
async fn getheaders_keeps_a_newer_offer() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("gh-keep-newer");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.mine(1, script.clone(), vec![]).unwrap();
    let parent = hub.tip_hash().unwrap();
    hub.mine(1, script, vec![]).unwrap();
    let child = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18481);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 81,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let session = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    session.note_last_tip_offered(child);
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    on_getheaders(
        &hub,
        &out_tx,
        &mut follow,
        Some(&session),
        &GetHeadersMessage::new(vec![], parent),
    )
    .await
    .unwrap();
    let NetworkMessage::Headers(sent) = out_rx.try_recv().unwrap().expect_msg() else {
        panic!("getheaders should answer with headers");
    };
    assert_eq!(sent.last().unwrap().block_hash(), parent);
    assert_eq!(
        session.last_tip_offered(),
        Some(child),
        "a headers reply does not replace a newer offer"
    );
    run_on_tip_accept(|| hub.invalidate_block_inner(child)).unwrap();
    let parent_time = hub.tip_header().unwrap().time;
    let sibling_block = rbitcoin_consensus::mine_empty_regtest(
        parent,
        parent_time.saturating_add(2),
        hub.tip_height().unwrap().saturating_add(1),
    );
    hub.accept_received_block(sibling_block).unwrap();
    let sibling = hub.tip_hash().unwrap();
    assert_ne!(sibling, child);
    assert_ne!(sibling, parent);
    let sibling_ev = Ok(rbitcoin_net::chain::TipEvent {
        height: hub.tip_height().unwrap(),
        hash: sibling,
        header: hub.tip_header().unwrap(),
        reorg_branch_len: 1,
    });
    assert!(
        tip_is_reorg_vs_sent(&hub, Some(&session), &sibling_ev),
        "a reorg off the newer offer still waits"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// An empty getheaders reply to a locator that names none of our blocks
/// marks nothing, so the tip announcement still goes out. Below minimum
/// chain work every reply is empty and, as in Core, marks nothing.
#[tokio::test]
async fn getheaders_empty_reply_without_a_peer_block_marks_nothing() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("gh-empty-mark");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().unwrap();
    let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.mine(1, script, vec![]).unwrap();
    let tip = hub.tip_hash().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let register = |port: u16, nonce: u64| {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let ver = VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce,
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        )
    };
    let (out_tx, mut out_rx) = peer_out_channel();

    let session = register(18482, 82);
    let mut follow = PeerFollowState::new();
    follow.wants_headers = true;
    let unknown = BlockHash::from_byte_array([0x22; 32]);
    on_getheaders(
        &hub,
        &out_tx,
        &mut follow,
        Some(&session),
        &GetHeadersMessage::new(vec![], unknown),
    )
    .await
    .unwrap();
    let NetworkMessage::Headers(sent) = out_rx.try_recv().unwrap().expect_msg() else {
        panic!("getheaders should answer with headers");
    };
    assert!(sent.is_empty(), "an unknown stop hash has no header");
    assert_eq!(
        session.header_marks().0,
        None,
        "an empty reply to a locator that names no block marks nothing"
    );
    let ev = Ok(rbitcoin_net::chain::TipEvent {
        height: hub.tip_height().unwrap(),
        hash: tip,
        header: hub.tip_header().unwrap(),
        reorg_branch_len: 0,
    });
    on_tip_event(&hub, &out_tx, &mut follow, Some(&session), ev)
        .await
        .unwrap();
    let NetworkMessage::Headers(announced) = out_rx.try_recv().unwrap().expect_msg() else {
        panic!("the tip should be announced with headers");
    };
    assert_eq!(announced.last().map(|h| h.block_hash()), Some(tip));

    hub.set_minimum_chain_work(Some([0xff; 32]));
    let behind = register(18484, 84);
    on_getheaders(
        &hub,
        &out_tx,
        &mut PeerFollowState::new(),
        Some(&behind),
        &GetHeadersMessage::new(vec![genesis], BlockHash::all_zeros()),
    )
    .await
    .unwrap();
    let NetworkMessage::Headers(sent) = out_rx.try_recv().unwrap().expect_msg() else {
        panic!("getheaders should answer with headers");
    };
    assert!(
        sent.is_empty(),
        "below minimum chain work the reply is empty"
    );
    assert_eq!(
        behind.header_marks().0,
        None,
        "an empty reply below minimum chain work marks nothing"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A block that connects while an empty getheaders reply is built is still
/// announced. The reply marks the locator block the walk met, not the newer
/// tip.
#[tokio::test]
async fn getheaders_announces_a_block_connected_during_the_reply() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("gh-connect-during");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let script = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    hub.mine(1, script, vec![]).unwrap();
    let walked = hub.tip_hash().unwrap();
    let walked_header = hub.tip_header().unwrap();
    // The child is in the cache only. `tip_hash()` reads it, and the store
    // walk still ends at `walked`: the state a connect during the walk leaves.
    let child_height = hub.tip_height().unwrap() + 1;
    let child = rbitcoin_consensus::mine_empty_regtest(
        walked,
        walked_header.time.saturating_add(1),
        child_height,
    );
    let child_header = child.header;
    let child_hash = child.block_hash();
    hub.cache.push_best(child_height, child);
    assert_eq!(hub.tip_hash(), Some(child_hash));
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18486);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 86,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let session = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.wants_headers = true;

    on_getheaders(
        &hub,
        &out_tx,
        &mut follow,
        Some(&session),
        &GetHeadersMessage::new(vec![walked], BlockHash::all_zeros()),
    )
    .await
    .unwrap();
    let NetworkMessage::Headers(sent) = out_rx.try_recv().unwrap().expect_msg() else {
        panic!("getheaders should answer with headers");
    };
    assert!(sent.is_empty(), "the store walk ends at the locator");
    assert_eq!(
        session.header_marks().0,
        Some(walked),
        "the reply marks the block the walk met"
    );

    let ev = Ok(rbitcoin_net::chain::TipEvent {
        height: child_height,
        hash: child_hash,
        header: child_header,
        reorg_branch_len: 0,
    });
    on_tip_event(&hub, &out_tx, &mut follow, Some(&session), ev)
        .await
        .unwrap();
    let NetworkMessage::Headers(announced) = out_rx.try_recv().unwrap().expect_msg() else {
        panic!("the block that connected during the reply should be announced");
    };
    assert_eq!(announced.last().map(|h| h.block_hash()), Some(child_hash));
    let _ = std::fs::remove_dir_all(dir);
}

async fn collect_header_tips(
    reader: &mut rbitcoin_net::v2::V2Reader,
    magic: Magic,
    wait: Duration,
) -> Vec<BlockHash> {
    use rbitcoin_net::v2::read_v2_frame;
    let deadline = std::time::Instant::now() + wait;
    let mut hashes = Vec::new();
    while std::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let frame = match tokio::time::timeout(left, read_v2_frame(reader, magic)).await {
            Ok(Ok(frame)) => frame,
            _ => break,
        };
        if let NetworkMessage::Headers(headers) = frame.decode().payload() {
            if let Some(last) = headers.last() {
                hashes.push(last.block_hash());
            }
        }
    }
    hashes
}

async fn collect_block_invs(
    reader: &mut rbitcoin_net::v2::V2Reader,
    magic: Magic,
    wait: Duration,
) -> Vec<BlockHash> {
    use rbitcoin_net::v2::read_v2_frame;
    let deadline = std::time::Instant::now() + wait;
    let mut hashes = Vec::new();
    while std::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let frame = match tokio::time::timeout(left, read_v2_frame(reader, magic)).await {
            Ok(Ok(frame)) => frame,
            _ => break,
        };
        if let NetworkMessage::Inv(inv) = frame.decode().payload() {
            for item in inv {
                if let Inventory::Block(h) = item {
                    hashes.push(*h);
                }
            }
        }
    }
    hashes
}

/// Send `Ping(nonce)` and return the block hashes of every inv the session
/// writes before its pong. Replies leave on one queue in order, so an inv
/// queued before the session read the ping is in the list. This is the
/// "nothing else was sent" read without a fixed quiet window.
async fn block_invs_before_pong(sess: &mut DecodeSession, nonce: u64) -> Vec<BlockHash> {
    use rbitcoin_net::v2::{read_v2_frame, write_v2_msg};
    write_v2_msg(&mut sess.writer, NetworkMessage::Ping(nonce))
        .await
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut hashes = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let frame = tokio::time::timeout(left, read_v2_frame(&mut sess.reader, sess.magic))
            .await
            .expect("pong within 2 s")
            .unwrap();
        if frame_is_pong(&frame, nonce) {
            return hashes;
        }
        if let NetworkMessage::Inv(inv) = frame.decode().payload() {
            for item in inv {
                if let Inventory::Block(h) = item {
                    hashes.push(*h);
                }
            }
        }
    }
}

/// Read until a block inv names `want`, then return every block hash the
/// invs named up to and including it.
async fn block_invs_until(sess: &mut DecodeSession, want: BlockHash) -> Vec<BlockHash> {
    use rbitcoin_net::v2::read_v2_frame;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut hashes = Vec::new();
    while !hashes.contains(&want) {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let frame = tokio::time::timeout(left, read_v2_frame(&mut sess.reader, sess.magic))
            .await
            .unwrap_or_else(|_| panic!("block inv {want} within 2 s, got {hashes:?}"))
            .unwrap();
        if let NetworkMessage::Inv(inv) = frame.decode().payload() {
            for item in inv {
                if let Inventory::Block(h) = item {
                    hashes.push(*h);
                }
            }
        }
    }
    hashes
}

/// Read until a headers message ends at `want`. Returns the last hash of
/// each headers message read.
async fn header_tips_until(
    reader: &mut rbitcoin_net::v2::V2Reader,
    magic: Magic,
    want: BlockHash,
) -> Vec<BlockHash> {
    use rbitcoin_net::v2::read_v2_frame;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut hashes = Vec::new();
    while !hashes.contains(&want) {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let frame = tokio::time::timeout(left, read_v2_frame(reader, magic))
            .await
            .unwrap_or_else(|_| panic!("headers ending at {want} within 2 s, got {hashes:?}"))
            .unwrap();
        if let NetworkMessage::Headers(headers) = frame.decode().payload() {
            if let Some(last) = headers.last() {
                hashes.push(last.block_hash());
            }
        }
    }
    hashes
}

#[test]
fn live_follow_dec_on_drop() {
    let c = Arc::new(AtomicUsize::new(2));
    {
        let _g = LiveFollowDec(Some(c.clone()));
        assert_eq!(c.load(Ordering::SeqCst), 2);
    }
    assert_eq!(c.load(Ordering::SeqCst), 1);
    let _ = LiveFollowDec(None);
}

#[test]
fn local_service_flags_include_network_witness_v2() {
    let f = local_service_flags(false, None);
    assert!(f.has(ServiceFlags::NETWORK));
    assert!(f.has(ServiceFlags::WITNESS));
    assert!(f.has(ServiceFlags::P2P_V2));
}

#[test]
fn local_service_flags_pruned_are_limited_not_network() {
    let f = local_service_flags(true, None);
    assert!(f.has(ServiceFlags::NETWORK_LIMITED));
    assert!(!f.has(ServiceFlags::NETWORK));
    assert!(f.has(ServiceFlags::WITNESS));
    assert!(f.has(ServiceFlags::P2P_V2));
}

#[test]
fn compact_filter_bit_stays_on_the_node_that_caught_up() {
    use bitcoin::p2p::ServiceFlags;
    let quiet = crate::peers::PeerHub::new();
    let caught_up = crate::peers::PeerHub::new();
    caught_up.set_compact_filters_service(true);
    assert!(
        !local_service_flags(false, Some(&quiet)).has(ServiceFlags::COMPACT_FILTERS),
        "a neighbor catching up must not advertise filters for this node"
    );
    assert!(local_service_flags(false, Some(&caught_up)).has(ServiceFlags::COMPACT_FILTERS));
    assert!(
        !local_service_flags(false, None).has(ServiceFlags::COMPACT_FILTERS),
        "no session table means this node has not caught filters up"
    );
}

#[test]
fn rand_nonce_changes() {
    let a = rand_nonce();
    let b = rand_nonce();
    // Counter component makes back-to-back nonces distinct.
    assert_ne!(a, b);
}

#[test]
fn block_for_peer_empty_store_none() {
    let (dir, q) = rbitcoin_query::testutil::tiny_query_labeled("block-none");
    let cache = BlockCache::new();
    let miss = BlockHash::from_byte_array([0xab; 32]);
    assert!(block_for_peer(&cache, &q, &miss).unwrap().is_none());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn cmpct_helpers_without_mempool_and_queue_out_closed() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-none");
    hub.ensure_genesis().unwrap();
    assert!(hub.mempool().is_none());

    // Closed channel → Protocol error.
    let (tx, rx) = peer_out_channel();
    drop(rx);
    assert!(tx.send(NetworkMessage::Verack).is_err());
    assert!(queue_getheaders(&tx, &hub, None, false, None).is_err());

    // headers_for_peer empty store after genesis still returns (tip exists).
    use bitcoin::p2p::message_blockdata::GetHeadersMessage;
    let gh = GetHeadersMessage::new(
        vec![hub.tip_hash().unwrap()],
        BlockHash::from_byte_array([0u8; 32]),
    );
    let hdrs = headers_for_peer(hub.cache.as_ref(), hub.query.as_ref(), &gh).unwrap();
    // Beyond tip: empty headers is fine.
    assert!(hdrs.is_empty() || !hdrs.is_empty());

    // drain_pending empty is a no-op.
    let mut pb = PendingBlocks::new();
    let mut ph = HashMap::new();
    let (tx, _rx) = peer_out_channel();
    drain_pending_now(
        &hub,
        &tx,
        &mut pb,
        &mut ph,
        &mut RequestedBlocks::default(),
        false,
    )
    .unwrap();

    // Invalid tip-extending body must not kill the session (001).
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let tip = hub.tip_hash().unwrap();
    let tip_block = hub
        .query
        .reconstruct_block_by_hash(&tip.to_byte_array())
        .unwrap()
        .expect("tip body");
    let coinbase = Transaction {
        version: TxVersion::ONE,
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
    // Second tx spends a nonexistent prevout → consensus reject.
    let junk = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0xab; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut bad = bitcoin::Block {
        header: Header {
            version: BlockVersion::from_consensus(4),
            prev_blockhash: tip,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
            time: tip_block.header.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase, junk],
    };
    bad.header.merkle_root = bad.compute_merkle_root().unwrap();
    let target = bitcoin::Target::from_compact(bad.header.bits);
    for nonce in 0..200_000u32 {
        bad.header.nonce = nonce;
        if bad.header.validate_pow(target).is_ok() {
            break;
        }
    }
    let bh = bad.block_hash();
    pb.insert(bh, bad.clone(), None);
    let (tx, _rx) = peer_out_channel();
    drain_pending_now(
        &hub,
        &tx,
        &mut pb,
        &mut ph,
        &mut RequestedBlocks::default(),
        false,
    )
    .expect("invalid block must not end session");
    assert!(
        hub.is_block_invalid(&bh),
        "consensus-invalid body must be cached as failed"
    );

    let _ = std::fs::remove_dir_all(dir);
}

/// A regtest hub with a mempool and 102 blocks to OP_TRUE, so blocks
/// 103 and 104 can each spend a mature coinbase: block `n` spends
/// coinbase `n`. Their spends are not in the mempool, so a compact
/// announce of either waits on `blocktxn`.
fn compact_spend_pair(
    label: &str,
) -> (
    rbitcoin_query::testutil::TempDir,
    ChainHub,
    [bitcoin::Block; 2],
) {
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(mp).is_ok());
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let mut time = hub.tip_header().unwrap().time + 1;
    let mut coinbases = Vec::new();
    for height in 1..=102u32 {
        let b = rbitcoin_consensus::mine_regtest_paying(
            hub.tip_hash().unwrap(),
            time,
            height,
            op_true.clone(),
            vec![],
        );
        coinbases.push(b.txdata[0].compute_txid());
        hub.accept_block(b).unwrap();
        time += 1;
    }
    let spend = |i: usize| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbases[i],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_0000_0000),
            script_pubkey: op_true.clone(),
        }],
    };
    let a = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        time,
        103,
        op_true.clone(),
        vec![spend(0)],
    );
    let b = rbitcoin_consensus::mine_regtest_paying(
        a.block_hash(),
        time + 1,
        104,
        op_true.clone(),
        vec![spend(1)],
    );
    (dir, hub, [a, b])
}

/// `p2p_compactblocks.py` stalling peer: a peer's partial for a block that
/// connected through another peer must not hold its one pending slot, or the
/// peer's next compact becomes a full getdata and its blocktxn is ignored.
/// Core drops every peer's in-flight entry once the block is received.
#[tokio::test]
async fn partial_for_a_block_connected_elsewhere_frees_the_slot() {
    use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds};
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let (dir, hub, [a, b]) = compact_spend_pair("cmpct-stale-partial");

    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18447);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let stalling = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    stalling.hb_to.store(true, Ordering::Relaxed);
    let cmpct = |blk: &bitcoin::Block| CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(blk, 0xbeef, 2, &[]).unwrap(),
    };

    on_cmpctblock(
        &hub,
        &out_tx,
        &mut follow,
        Some(stalling.as_ref()),
        &cmpct(&a),
    )
    .await
    .unwrap();
    assert!(matches!(
        out_rx.try_recv().unwrap().expect_msg(),
        NetworkMessage::GetBlockTxn(_)
    ));
    hub.accept_block(a.clone()).unwrap();
    assert_eq!(
        hub.tip_hash(),
        Some(a.block_hash()),
        "A arrived from another peer"
    );

    on_cmpctblock(
        &hub,
        &out_tx,
        &mut follow,
        Some(stalling.as_ref()),
        &cmpct(&b),
    )
    .await
    .unwrap();
    let mut sent = Vec::new();
    while let Ok(m) = out_rx.try_recv() {
        sent.push(m.expect_msg());
    }
    assert!(
        sent.iter()
            .any(|m| matches!(m, NetworkMessage::GetBlockTxn(g) if g.txs_request.block_hash == b.block_hash())),
        "the stale partial for A must not turn B into a full getdata: {sent:?}"
    );
    on_blocktxn(
        &hub,
        &out_tx,
        &mut follow,
        Some(stalling.as_ref()),
        &BlockTransactions {
            block_hash: b.block_hash(),
            transactions: vec![b.txdata[1].clone()],
        },
    )
    .await
    .unwrap();
    assert_eq!(hub.tip_hash(), Some(b.block_hash()), "blocktxn completes B");
    let _ = std::fs::remove_dir_all(dir);
}

async fn heartbeat_once(
    hub: &ChainHub,
    out_tx: &PeerOutTx,
    follow: &mut PeerFollowState,
    peer: &rbitcoin_net::peers::LivePeer,
) {
    on_heartbeat(
        hub,
        out_tx,
        follow,
        Some(peer),
        &mut None,
        &mut None,
        &mut None,
        false,
        false,
    )
    .await
    .unwrap();
}

/// A block frame already read, still waiting on a decode permit, must not
/// lose its getdata. The heartbeat used to drain `requested_blocks` on the
/// 10s stall clock before that frame was applied.
#[tokio::test]
async fn queued_decode_holds_block_requests_across_heartbeat() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("decode-hold-getdata");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = outbound_test_peer(&peers, 18449);
    let (out_tx, mut out_rx) = peer_out_channel();
    let hash = BlockHash::from_byte_array([0x44; 32]);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(&hub, hash);
    let mut since =
        Some(std::time::Instant::now() - BLOCK_GETDATA_TIMEOUT - Duration::from_secs(1));
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        true,
        true,
    )
    .await
    .unwrap();
    assert!(
        follow.requested_blocks.contains(&hash),
        "a queued decode must keep the getdata"
    );
    assert!(
        hub.already_have_or_asked_block(&hash),
        "asked_blocks must stay until the frame is applied"
    );
    assert!(
        sent(&mut out_rx)
            .iter()
            .all(|m| !matches!(m, NetworkMessage::GetData(_))),
        "the stall path must not send another getdata"
    );
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        false,
        false,
    )
    .await
    .unwrap();
    assert!(
        follow.requested_blocks.is_empty(),
        "once the decode queue is empty the stall clock still expires"
    );
    assert!(!hub.already_have_or_asked_block(&hash));
    let _ = std::fs::remove_dir_all(dir.path());
}

/// A `blocktxn` queued behind a front held for the send budget is already
/// off the socket. The front no longer waits to decode, so the timeout
/// gates run, but the 10s request expiry must not forget the pending
/// compact before that `blocktxn` is applied.
#[tokio::test]
async fn held_front_keeps_a_queued_blocktxn_pending() {
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::blockdata::constants::genesis_block;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("held-front-blocktxn");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = outbound_test_peer(&peers, 18481);
    let block = genesis_block(Network::Regtest);
    let hash = block.block_hash();
    let mut follow = PeerFollowState::new();
    follow.pending_cmpct.insert(
        hash,
        PendingCmpct {
            hsi: HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[]).unwrap(),
            partial: rbitcoin_net::compact::CmpctPartial {
                slots: Vec::new(),
                txids: Vec::new(),
                missing: vec![1],
            },
            fill: None,
            since: std::time::Instant::now() - BLOCK_GETDATA_TIMEOUT - Duration::from_secs(1),
        },
    );
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut since = None;
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        false,
        true,
    )
    .await
    .unwrap();
    assert!(
        follow.pending_cmpct.contains_key(&hash),
        "a blocktxn behind the held front must stay pending"
    );
    assert!(
        sent(&mut out_rx)
            .iter()
            .all(|m| !matches!(m, NetworkMessage::GetData(_))),
        "the held first frame must not expire the compact into a full getdata"
    );
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        false,
        false,
    )
    .await
    .unwrap();
    assert!(
        !follow.pending_cmpct.contains_key(&hash),
        "an empty decode queue still expires the compact"
    );
    assert!(
        sent(&mut out_rx)
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetData(_))),
        "the expired compact asks for the full body"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

/// Past the 10s getdata stall, a hash the download timer still owns stays
/// in flight, so the ping suspend holds. The peer drops when that window
/// reaches one block interval, not at the stall clock.
#[tokio::test]
async fn getdata_stall_keeps_a_hash_the_download_timer_owns() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("getdata-keeps-window");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let asked = peers.now_secs();
    peers.set_mock_now(asked);
    let peer = outbound_test_peer(&peers, 18451);
    let hash = BlockHash::from_byte_array([0x46; 32]);
    peer.note_blocks_requested(&[hash]);
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(&hub, hash);
    let (out_tx, _out_rx) = peer_out_channel();
    let mut since =
        Some(std::time::Instant::now() - BLOCK_GETDATA_TIMEOUT - Duration::from_secs(1));
    for _ in 0..2 {
        on_heartbeat(
            &hub,
            &out_tx,
            &mut follow,
            Some(peer.as_ref()),
            &mut since,
            &mut None,
            &mut None,
            false,
            false,
        )
        .await
        .unwrap();
    }
    assert!(
        follow.requested_blocks.contains(&hash),
        "the stall clock forgot a hash the download timer still owns"
    );
    assert!(
        hub.already_have_or_asked_block(&hash),
        "asked_blocks dropped while the download window was open"
    );
    assert!(
        !peer.stop.load(Ordering::SeqCst),
        "the peer disconnected inside the download window"
    );
    let interval = hub.params.btc.pow_target_spacing;
    peers.set_mock_now(asked.saturating_add(interval).saturating_add(1));
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        false,
        false,
    )
    .await
    .unwrap();
    assert!(
        peer.stop.load(Ordering::SeqCst),
        "the block-interval timeout did not disconnect"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

/// The block-download window must not drop a peer whose body is already in
/// `decode_q`. That frame is still the oldest block in flight.
#[tokio::test]
async fn queued_decode_holds_the_block_download_window() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("decode-hold-download");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let start = 1_700_000_000_u64;
    peers.set_mock_now(start);
    let peer = outbound_test_peer(&peers, 18450);
    let hash = BlockHash::from_byte_array([0x45; 32]);
    peer.note_blocks_requested(&[hash]);
    let interval = hub.params.btc.pow_target_spacing;
    peers.set_mock_now(start + interval + 1);
    let (out_tx, _out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(&hub, hash);
    let mut since = None;
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        true,
        true,
    )
    .await
    .unwrap();
    assert!(
        !peer.stop.load(Ordering::Relaxed),
        "a queued body must not trip the download timeout"
    );
    assert!(
        hub.already_have_or_asked_block(&hash),
        "the ask stays until the frame is applied"
    );
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        false,
        false,
    )
    .await
    .unwrap();
    assert!(
        peer.stop.load(Ordering::Relaxed),
        "an empty decode queue still times the window out"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

/// A pong the peer already sent can sit unread while heavy frames wait on
/// a decode permit. That wait must not trip the ping timeout.
#[tokio::test]
async fn queued_decode_holds_the_ping_timeout() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("decode-hold-ping");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let start = 1_700_000_000_u64;
    peers.set_mock_now(start);
    let peer = outbound_test_peer(&peers, 18451);
    peer.ping_nonce_sent.store(1, Ordering::Relaxed);
    peer.ping_start_secs.store(start, Ordering::Relaxed);
    // Past `-peertimeout`, the post-block minute, and the twenty-minute
    // ping, with nothing in the block-download window.
    peers.set_mock_now(start + 20 * 60 + 61);
    let (out_tx, _out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let mut since = None;
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        true,
        true,
    )
    .await
    .unwrap();
    assert!(
        !peer.stop.load(Ordering::Relaxed),
        "a queued decode must not trip the ping timeout"
    );
    on_heartbeat(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &mut since,
        &mut None,
        &mut None,
        false,
        false,
    )
    .await
    .unwrap();
    assert!(
        peer.stop.load(Ordering::Relaxed),
        "an empty decode queue still times the ping out"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

/// One peer, then the next, on a chain that is still at genesis. A block
/// sitting in `decode_q` holds the ping behind it, still applies when
/// disconnect wakes the session, does not take headers sync on the way out,
/// and a heavy queue past the cap ends the session. Each beat waits until
/// that peer's decode queue has taken the frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn queued_decode_keeps_the_block_ahead_of_ping_and_disconnect() {
    use bitcoin::blockdata::constants::genesis_block;
    use rbitcoin_net::chain::TipEvent;
    use rbitcoin_net::v2::write_v2_msg;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("decode-queue-journey");
    hub.ensure_genesis().unwrap();
    let hub = hub.into_arc();
    let mut held = hold_decode_permits().await;

    // Tip announce runs before `-minimumchainwork` is raised. Disconnect
    // closes the writer while the body is still queued.
    {
        let peers = rbitcoin_net::peers::PeerHub::new();
        let mut s = open_decode_session(Arc::clone(&hub), &peers, 18461, hub.tip_hash()).await;
        drain_startup(&mut s.reader, s.magic).await;
        write_v2_msg(
            &mut s.writer,
            NetworkMessage::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            }),
        )
        .await
        .unwrap();
        let mut block = genesis_block(Network::Regtest);
        block.header.prev_blockhash = BlockHash::from_byte_array([0x11; 32]);
        let hash = block.block_hash();
        write_v2_msg(&mut s.writer, NetworkMessage::Block(block))
            .await
            .unwrap();
        wait_decode_enqueued(&s.live, 1).await;
        let tip_hash = hub.tip_hash().expect("genesis tip");
        let header = hub.tip_header().expect("genesis header");
        let _ = hub.tip_tx.send(TipEvent {
            height: 0,
            hash: tip_hash,
            header,
            reorg_branch_len: 0,
        });
        assert!(peers.disconnect_id(s.live.id), "the peer is registered");
        assert!(
            !s.live.take_block_from_peer(&hash),
            "the body stays queued while every decode permit is held"
        );
        drop(held);
        wait_block_applied(&s.live, &hash).await;
        s.session.abort();
        held = hold_decode_permits().await;
    }

    hub.set_minimum_chain_work(Some([0xff; 32]));

    // Ping stays behind the block. The same session then fills the heavy
    // queue and the cap ends it.
    {
        let peers = rbitcoin_net::peers::PeerHub::new();
        let mut s = open_decode_session(Arc::clone(&hub), &peers, 18462, hub.tip_hash()).await;
        drain_startup(&mut s.reader, s.magic).await;
        let nonce = 0x51a7_0001_u64;
        write_v2_msg(
            &mut s.writer,
            NetworkMessage::Block(genesis_block(Network::Regtest)),
        )
        .await
        .unwrap();
        write_v2_msg(&mut s.writer, NetworkMessage::Ping(nonce))
            .await
            .unwrap();
        wait_decode_enqueued(&s.live, 2).await;
        assert_no_pong(&mut s.reader, s.magic, nonce).await;
        drop(held);
        wait_pong(&mut s.reader, s.magic, nonce).await;
        held = hold_decode_permits().await;

        let blocks = DECODE_Q_MAX_FRAMES + 1;
        let genesis = genesis_block(Network::Regtest);
        for _ in 0..blocks {
            write_v2_msg(&mut s.writer, NetworkMessage::Block(genesis.clone()))
                .await
                .unwrap();
        }
        wait_decode_enqueued(&s.live, 2 + blocks).await;
        drop(held);
        tokio::time::timeout(Duration::from_secs(8), s.session)
            .await
            .expect("a full heavy decode queue must end the session")
            .expect("session join");
        held = hold_decode_permits().await;
    }

    // disconnect_id applies a block already off the socket.
    {
        let peers = rbitcoin_net::peers::PeerHub::new();
        let mut s = open_decode_session(Arc::clone(&hub), &peers, 18463, hub.tip_hash()).await;
        drain_startup(&mut s.reader, s.magic).await;
        let block = genesis_block(Network::Regtest);
        let hash = block.block_hash();
        let before = s.live.decode_enqueued();
        write_v2_msg(&mut s.writer, NetworkMessage::Block(block))
            .await
            .unwrap();
        wait_decode_enqueued(&s.live, before + 1).await;
        assert!(peers.disconnect_id(s.live.id), "the peer is registered");
        assert!(
            !s.live.take_block_from_peer(&hash),
            "the body stays queued while every decode permit is held"
        );
        drop(held);
        wait_block_applied(&s.live, &hash).await;
        s.session.abort();
        held = hold_decode_permits().await;
    }

    // A ping queued behind that block must not take headers sync as the
    // session drains.
    {
        let peers = rbitcoin_net::peers::PeerHub::new();
        let mut s = open_decode_session(Arc::clone(&hub), &peers, 18464, hub.tip_hash()).await;
        drain_startup(&mut s.reader, s.magic).await;
        assert!(s.live.can_serve_blocks());
        let before = s.live.decode_enqueued();
        let block = genesis_block(Network::Regtest);
        write_v2_msg(&mut s.writer, NetworkMessage::Block(block))
            .await
            .unwrap();
        wait_decode_enqueued(&s.live, before + 1).await;
        write_v2_msg(&mut s.writer, NetworkMessage::Ping(1))
            .await
            .unwrap();
        wait_decode_enqueued(&s.live, before + 2).await;
        let slots = peers.headers_sync_peers.load(Ordering::Relaxed);
        let downloading = peers.peers_downloading_from.load(Ordering::Relaxed);
        let started = s.live.is_sync_started();
        let session_id = s.live.id;
        assert!(peers.disconnect_id(s.live.id), "the peer is registered");
        assert!(
            peers.get(s.live.id).is_some(),
            "disconnect hides the peer and leaves the row until the session ends"
        );
        assert_eq!(
            s.live.is_sync_started(),
            started,
            "disconnect must not release headers sync"
        );
        assert_eq!(peers.headers_sync_peers.load(Ordering::Relaxed), slots);
        drop(held);
        drop(s.writer);
        tokio::time::timeout(Duration::from_secs(5), s.session)
            .await
            .expect("session drains")
            .expect("session task");
        assert_eq!(
            s.live.is_sync_started(),
            started,
            "a queued ping must not start headers sync on the way out"
        );
        assert_eq!(
            peers.headers_sync_peers.load(Ordering::Relaxed),
            slots,
            "the drain must not take a headers-sync slot"
        );
        assert_eq!(
            peers.peers_downloading_from.load(Ordering::Relaxed),
            downloading
        );
        peers.unregister(session_id);
        assert!(
            !s.live.is_sync_started(),
            "the session unregister releases headers sync once"
        );
        assert_eq!(peers.headers_sync_peers.load(Ordering::Relaxed), 0);
        assert_eq!(peers.peers_downloading_from.load(Ordering::Relaxed), 0);
    }

    let _ = std::fs::remove_dir_all(dir.path());
}

async fn hold_decode_permits() -> Vec<tokio::sync::OwnedSemaphorePermit> {
    let n = rbitcoin_net::block_decode_permits();
    let sem = rbitcoin_net::msg_decode::block_decode_semaphore().clone();
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        held.push(sem.clone().acquire_owned().await.expect("decode permit"));
    }
    held
}

async fn wait_decode_enqueued(peer: &rbitcoin_net::peers::LivePeer, n: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while peer.decode_enqueued() < n {
        assert!(
            std::time::Instant::now() < deadline,
            "queued {} decode frames, wanted {n}",
            peer.decode_enqueued()
        );
        tokio::task::yield_now().await;
    }
}

async fn drain_startup(reader: &mut rbitcoin_net::v2::V2Reader, magic: Magic) {
    use rbitcoin_net::v2::read_v2_frame;
    let drain = async {
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(40), read_v2_frame(reader, magic)).await
        {
        }
    };
    tokio::time::timeout(Duration::from_secs(2), drain)
        .await
        .expect("startup frames drain");
}

fn frame_is_pong(frame: &FramedMessage, nonce: u64) -> bool {
    frame.is_pong()
        && frame.payload.len() >= 8
        && u64::from_le_bytes(frame.payload[..8].try_into().unwrap()) == nonce
}

async fn assert_no_pong(reader: &mut rbitcoin_net::v2::V2Reader, magic: Magic, nonce: u64) {
    use rbitcoin_net::v2::read_v2_frame;
    let deadline = std::time::Instant::now() + Duration::from_millis(20);
    while std::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(left, read_v2_frame(reader, magic)).await {
            Ok(Ok(frame)) => assert!(
                !frame_is_pong(&frame, nonce),
                "pong went out while the earlier block was still queued"
            ),
            _ => break,
        }
    }
}

async fn wait_getblocktxn(
    reader: &mut rbitcoin_net::v2::V2Reader,
    magic: Magic,
    hash: BlockHash,
) -> Vec<u64> {
    use rbitcoin_net::v2::read_v2_frame;
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(left, read_v2_frame(reader, magic)).await {
            Ok(Ok(frame)) => {
                if let NetworkMessage::GetBlockTxn(g) = frame.decode().into_payload() {
                    if g.txs_request.block_hash == hash {
                        return g.txs_request.indexes;
                    }
                }
            }
            _ => break,
        }
    }
    panic!("no getblocktxn for {hash}");
}

async fn assert_no_getdata_for(
    reader: &mut rbitcoin_net::v2::V2Reader,
    magic: Magic,
    hash: BlockHash,
    wait: Duration,
) {
    use rbitcoin_net::v2::read_v2_frame;
    let deadline = std::time::Instant::now() + wait;
    while std::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(left, read_v2_frame(reader, magic)).await {
            Ok(Ok(frame)) => {
                if let NetworkMessage::GetData(inv) = frame.decode().into_payload() {
                    assert!(
                        !inv.iter().any(|i| {
                            matches!(i, Inventory::WitnessBlock(h) | Inventory::CompactBlock(h) if *h == hash)
                        }),
                        "a queued blocktxn was expired into a full getdata"
                    );
                }
            }
            _ => break,
        }
    }
}

async fn wait_pong(reader: &mut rbitcoin_net::v2::V2Reader, magic: Magic, nonce: u64) {
    use rbitcoin_net::v2::read_v2_frame;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match tokio::time::timeout(left, read_v2_frame(reader, magic)).await {
            Ok(Ok(frame)) if frame_is_pong(&frame, nonce) => return,
            Ok(Ok(_)) => {}
            _ => break,
        }
    }
    panic!("pong must follow the queued block once a decode permit is free");
}

async fn wait_block_applied(peer: &rbitcoin_net::peers::LivePeer, hash: &BlockHash) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if peer.take_block_from_peer(hash) {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("disconnect must apply a block already taken off the socket");
}

struct DecodeSession {
    live: Arc<rbitcoin_net::peers::LivePeer>,
    reader: rbitcoin_net::v2::V2Reader,
    writer: rbitcoin_net::v2::V2Writer,
    session: tokio::task::JoinHandle<()>,
    magic: Magic,
}

async fn open_decode_session(
    hub: Arc<ChainHub>,
    peers: &Arc<rbitcoin_net::peers::PeerHub>,
    port: u16,
    tip_at_handshake: Option<BlockHash>,
) -> DecodeSession {
    open_decode_session_with(hub, peers, port, tip_at_handshake, None).await
}

async fn open_decode_session_with(
    hub: Arc<ChainHub>,
    peers: &Arc<rbitcoin_net::peers::PeerHub>,
    port: u16,
    tip_at_handshake: Option<BlockHash>,
    tip_rx: Option<broadcast::Receiver<rbitcoin_net::chain::TipEvent>>,
) -> DecodeSession {
    use rbitcoin_net::v2::open_v2;
    use tokio::net::TcpListener;

    let live = outbound_test_peer(peers, port);
    let magic = Magic::from(Network::Regtest);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let client_magic = magic;
    let client = tokio::spawn(async move {
        let stream = TcpStream::connect(addr).await.unwrap();
        open_v2(stream, client_magic, false).await.unwrap()
    });
    let (server_stream, _) = listener.accept().await.unwrap();
    let (reader, writer, _wire, _shutdown) = open_v2(server_stream, magic, true).await.unwrap();
    let (c_reader, c_writer, _wire, _shutdown) = client.await.unwrap();
    let tip_rx = tip_rx.unwrap_or_else(|| hub.subscribe_tips());
    let session_peer = Arc::clone(&live);
    let session = tokio::spawn(async move {
        let _ = peer_session_with(
            reader.into(),
            writer.into(),
            magic,
            hub,
            tip_rx,
            FollowSessionMeta {
                peer: Some(addr),
                live: None,
                session: Some(session_peer),
                tip_at_handshake,
            },
        )
        .await;
    });
    DecodeSession {
        live,
        reader: c_reader,
        writer: c_writer,
        session,
        magic,
    }
}

fn inbound_test_peer(
    peers: &Arc<rbitcoin_net::peers::PeerHub>,
    port: u16,
) -> Arc<rbitcoin_net::peers::LivePeer> {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    peer.hb_to.store(true, Ordering::Relaxed);
    peer
}

fn outbound_test_peer(
    peers: &Arc<rbitcoin_net::peers::PeerHub>,
    port: u16,
) -> Arc<rbitcoin_net::peers::LivePeer> {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    peer.hb_to.store(true, Ordering::Relaxed);
    peer
}

fn sent(out_rx: &mut PeerOutRx) -> Vec<NetworkMessage> {
    let mut msgs = Vec::new();
    while let Ok(m) = out_rx.try_recv() {
        msgs.push(m.expect_msg());
    }
    msgs
}

fn asked_witness(msgs: &[NetworkMessage], hash: BlockHash) -> bool {
    msgs.iter().any(|m| match m {
        NetworkMessage::GetData(inv) => inv
            .iter()
            .any(|i| matches!(i, Inventory::WitnessBlock(h) if *h == hash)),
        _ => false,
    })
}

/// A high-bandwidth peer that never sends `blocktxn` still holds its own
/// download window, and the node asks another high-bandwidth peer for that
/// body before the block-interval timeout. The silent peer is dropped when
/// its window expires. Dropping it frees the compact slot.
#[tokio::test]
async fn silent_compact_peer_holds_the_ping_then_hits_the_download_timeout() {
    use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds};
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    let (dir, hub, [a, _]) = compact_spend_pair("cmpct-download-timeout");
    let peers = rbitcoin_net::peers::PeerHub::new();
    let start = 1_700_000_000;
    peers.set_mock_now(start);
    let silent = outbound_test_peer(&peers, 18448);
    let other = outbound_test_peer(&peers, 18450);
    let (out_tx, mut out_rx) = peer_out_channel();
    let (other_tx, mut other_rx) = other.open_out();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    heartbeat_once(&hub, &out_tx, &mut follow, &silent).await;
    assert!(
        sent(&mut out_rx)
            .iter()
            .any(|m| matches!(m, NetworkMessage::Ping(_))),
        "the first heartbeat pings the peer"
    );

    let compact = CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(&a, 0xbeef, 2, &[]).unwrap(),
    };
    let hash = a.block_hash();
    // Five minutes before the ping is due, so the download window is still
    // open when it is.
    let asked = start + PING_TIMEOUT_SECS - BLOCK_INTERVAL_SECS / 2;
    peers.set_mock_now(asked);
    on_cmpctblock(&hub, &out_tx, &mut follow, Some(silent.as_ref()), &compact)
        .await
        .unwrap();
    assert!(matches!(
        sent(&mut out_rx).as_slice(),
        [NetworkMessage::GetBlockTxn(_)]
    ));
    assert!(
        asked_witness(&sent(&mut other_rx), hash),
        "another outbound high-bandwidth peer is asked while the first claim is open"
    );
    assert!(follow.requested_blocks.is_empty());
    assert!(!hub.is_block_invalid(&hash));
    peers.set_mock_now(start + PING_TIMEOUT_SECS + 1);
    heartbeat_once(&hub, &out_tx, &mut follow, &silent).await;
    assert!(
        !silent.stop.load(Ordering::SeqCst),
        "a peer whose compact block waits on blocktxn hit the ping timeout"
    );
    peers.set_mock_now(asked + BLOCK_INTERVAL_SECS);
    heartbeat_once(&hub, &out_tx, &mut follow, &silent).await;
    assert!(
        !silent.stop.load(Ordering::SeqCst),
        "the download timeout is strictly after one interval"
    );
    peers.set_mock_now(asked + BLOCK_INTERVAL_SECS + 1);
    heartbeat_once(&hub, &out_tx, &mut follow, &silent).await;
    assert!(
        silent.stop.load(Ordering::SeqCst),
        "a silent compact peer kept its block past the download timeout"
    );

    let mut other_follow = PeerFollowState::new();
    other_follow.cmpct_version = 2;
    peers.unregister(silent.id);
    assert_eq!(peers.peers_downloading_from.load(Ordering::Relaxed), 0);
    on_cmpctblock(
        &hub,
        &other_tx,
        &mut other_follow,
        Some(other.as_ref()),
        &compact,
    )
    .await
    .unwrap();
    assert!(matches!(
        sent(&mut other_rx).as_slice(),
        [NetworkMessage::GetBlockTxn(_)]
    ));
    on_blocktxn(
        &hub,
        &other_tx,
        &mut other_follow,
        Some(other.as_ref()),
        &BlockTransactions {
            block_hash: a.block_hash(),
            transactions: vec![a.txdata[1].clone()],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        hub.tip_hash(),
        Some(a.block_hash()),
        "the other peer completes the block"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A compact body whose witness commitment does not match is not cached as
/// an invalid header. The announcing peer is asked for the full block, and
/// it is not the only one asked.
///
/// On the same chain, a `blocktxn` that completes a body failing its
/// witness commitment is not announced to a high-bandwidth peer. A real
/// completion still is. That `blocktxn` feeds the extra pool, so the real
/// `a` then rebuilds without one; the next block is the `blocktxn` control.
#[tokio::test]
async fn witness_reconstruct_fail_asks_another_peer() {
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;

    let (dir, hub, [a, mut b]) = compact_spend_pair("cmpct-witness-fail");
    let mut spend = a.txdata[1].clone();
    spend.input[0].witness = bitcoin::Witness::from_slice(&[vec![1u8]]);
    let block = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        a.header.time,
        103,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![spend],
    );
    let mut hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[1]).unwrap();
    assert!(hsi.short_ids.is_empty());
    hsi.prefilled_txs[0].tx.input[0].witness = bitcoin::Witness::from_slice(&[vec![2u8; 32]]);
    let hash = hsi.header.block_hash();
    assert_eq!(hash, block.block_hash());

    let peers = rbitcoin_net::peers::PeerHub::new();
    let announcer = inbound_test_peer(&peers, 18451);
    let other = outbound_test_peer(&peers, 18452);
    let (ann_tx, mut ann_rx) = announcer.open_out();
    let (_, mut other_rx) = other.open_out();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    on_cmpctblock(
        &hub,
        &ann_tx,
        &mut follow,
        Some(announcer.as_ref()),
        &CmpctBlock { compact_block: hsi },
    )
    .await
    .unwrap();
    let ann_msgs = sent(&mut ann_rx);
    let other_msgs = sent(&mut other_rx);
    assert!(
        asked_witness(&other_msgs, hash),
        "witness failure asks an outbound peer, announcer sent {ann_msgs:?}"
    );
    assert!(
        !hub.is_block_invalid(&hash),
        "a bad witness reconstruct is not a permanently invalid header"
    );
    assert!(
        asked_witness(&ann_msgs, hash),
        "the announcing peer is asked for the full block"
    );
    assert!(
        hub.already_have_or_asked_block(&hash),
        "the announcing peer keeps the claim"
    );

    let (good_a, bad_a) = witness_committed_pair(&a);
    let hash_a = good_a.block_hash();
    b.header.prev_blockhash = hash_a;
    let (good_b, _) = witness_committed_pair(&b);
    let peers = rbitcoin_net::peers::PeerHub::new();
    let (_target, mut target_rx) = hb_relay_target(&peers, &hub, 18497);

    cmpct_then_blocktxn(&hub, &peers, 18498, &bad_a).await;
    assert!(
        !announced(&sent(&mut target_rx), hash_a),
        "a blocktxn fill that fails its witness commitment is not announced"
    );
    assert_ne!(hub.tip_hash(), Some(hash_a));

    let peer = inbound_test_peer(&peers, 18499);
    let (tx, _rx) = peer.open_out();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    let hsi = HeaderAndShortIds::from_block(&good_a, 0xbeef, 2, &[]).unwrap();
    on_cmpctblock(
        &hub,
        &tx,
        &mut follow,
        Some(peer.as_ref()),
        &CmpctBlock { compact_block: hsi },
    )
    .await
    .unwrap();
    assert!(sent_cmpct(&sent(&mut target_rx), hash_a));
    assert_eq!(hub.tip_hash(), Some(hash_a));

    cmpct_then_blocktxn(&hub, &peers, 18500, &good_b).await;
    assert!(
        sent_cmpct(&sent(&mut target_rx), good_b.block_hash()),
        "a real blocktxn fill is announced"
    );
    assert_eq!(hub.tip_hash(), Some(good_b.block_hash()));
    let _ = std::fs::remove_dir_all(dir);
}

/// `block` with a BIP141 commitment (zero nonce) mined again, and the same
/// block with another coinbase nonce. One hash and one txid merkle root;
/// only the first matches its witness commitment.
fn witness_committed_pair(block: &bitcoin::Block) -> (bitcoin::Block, bitcoin::Block) {
    let mut good = block.clone();
    good.txdata[0].input[0].witness = bitcoin::Witness::from_slice(&[vec![0u8; 32]]);
    rbitcoin_consensus::block::apply_witness_commitment(&mut good);
    rbitcoin_consensus::grind_regtest_pow(&mut good.header);
    let mut bad = good.clone();
    bad.txdata[0].input[0].witness = bitcoin::Witness::from_slice(&[vec![7u8; 32]]);
    assert_eq!(bad.block_hash(), good.block_hash());
    (good, bad)
}

/// A high-bandwidth peer that has the tip and was not sent `hash`.
fn hb_relay_target(
    peers: &Arc<rbitcoin_net::peers::PeerHub>,
    hub: &ChainHub,
    port: u16,
) -> (Arc<rbitcoin_net::peers::LivePeer>, PeerOutRx) {
    hub.mempool().unwrap().set_relay_enabled(true);
    let target = live_peer(peers, port, u64::from(port), false);
    target.set_hb_from(true);
    target.note_best_known(hub.tip_hash().unwrap());
    let (_, rx) = target.open_out();
    (target, rx)
}

fn announced(msgs: &[NetworkMessage], hash: BlockHash) -> bool {
    msgs.iter().any(|m| match m {
        NetworkMessage::CmpctBlock(c) => c.compact_block.header.block_hash() == hash,
        NetworkMessage::Headers(h) => h.iter().any(|h| h.block_hash() == hash),
        NetworkMessage::Inv(inv) => inv
            .iter()
            .any(|i| matches!(i, Inventory::Block(h) | Inventory::WitnessBlock(h) if *h == hash)),
        _ => false,
    })
}

fn sent_cmpct(msgs: &[NetworkMessage], hash: BlockHash) -> bool {
    msgs.iter().any(
        |m| matches!(m, NetworkMessage::CmpctBlock(c) if c.compact_block.header.block_hash() == hash),
    )
}

/// Core relays a compact block only after the body passes its witness
/// commitment. A full block whose coinbase nonce breaks that commitment is
/// not announced, and the real block from another peer still is.
#[tokio::test]
async fn witness_mutated_block_is_not_relayed() {
    let (dir, hub) = open_genesis_announce("relay-wit-block", true);
    let (good, bad) = witness_committed_pair(&hb_tip_child(&hub));
    let hash = good.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let (_target, mut target_rx) = hb_relay_target(&peers, &hub, 18491);

    let liar = outbound_test_peer(&peers, 18492);
    let (liar_tx, _liar_rx) = liar.open_out();
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(&hub, hash);
    on_block(&hub, &liar_tx, &mut follow, Some(liar.as_ref()), &bad)
        .await
        .unwrap();
    assert!(
        !announced(&sent(&mut target_rx), hash),
        "a body that fails its witness commitment is not announced"
    );
    assert_ne!(hub.tip_hash(), Some(hash));

    let honest = outbound_test_peer(&peers, 18493);
    let (honest_tx, _honest_rx) = honest.open_out();
    let mut follow = PeerFollowState::new();
    follow.requested_blocks.ask(&hub, hash);
    on_block(&hub, &honest_tx, &mut follow, Some(honest.as_ref()), &good)
        .await
        .unwrap();
    assert!(
        sent_cmpct(&sent(&mut target_rx), hash),
        "the real block is announced to the high-bandwidth peer"
    );
    assert_eq!(hub.tip_hash(), Some(hash));
    let _ = std::fs::remove_dir_all(dir);
}

/// A compact block that reconstructs to a body failing its witness
/// commitment is not announced. The real compact block still is.
#[tokio::test]
async fn witness_mutated_cmpct_reconstruct_is_not_relayed() {
    let (dir, hub) = open_genesis_announce("relay-wit-cmpct", true);
    let (good, bad) = witness_committed_pair(&hb_tip_child(&hub));
    let hash = good.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let (_target, mut target_rx) = hb_relay_target(&peers, &hub, 18494);

    for (port, block, real) in [(18495, &bad, false), (18496, &good, true)] {
        let peer = inbound_test_peer(&peers, port);
        let (tx, _rx) = peer.open_out();
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;
        let hsi = HeaderAndShortIds::from_block(block, 0xbeef, 2, &[]).unwrap();
        assert!(hsi.short_ids.is_empty(), "the coinbase is the whole block");
        on_cmpctblock(
            &hub,
            &tx,
            &mut follow,
            Some(peer.as_ref()),
            &CmpctBlock { compact_block: hsi },
        )
        .await
        .unwrap();
        let msgs = sent(&mut target_rx);
        if real {
            assert!(sent_cmpct(&msgs, hash), "the real block is announced");
            assert_eq!(hub.tip_hash(), Some(hash));
        } else {
            assert!(
                !announced(&msgs, hash),
                "a reconstruct that fails its witness commitment is not announced"
            );
            assert_ne!(hub.tip_hash(), Some(hash));
        }
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `FillBlock` fails a reconstruct that is mutated and net_processing
/// asks the same peer for the full block, without `Misbehaving`: a short-id
/// collision is not the sender's fault. A manual peer that is the only
/// source must be asked, or the node stays one block behind.
#[tokio::test]
async fn witness_mutated_cmpct_reconstruct_asks_the_same_peer_for_the_block() {
    let (dir, hub) = open_genesis_announce("cmpct-wit-ask-again", true);
    let (good, bad) = witness_committed_pair(&hb_tip_child(&hub));
    let hash = good.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let manual = live_peer_as(&peers, 18487, 87, rbitcoin_net::peers::PeerConnType::Manual);
    let (tx, mut rx) = manual.open_out();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    // The tip `getdata` to a compact v2 peer asked for a compact block.
    follow.requested_blocks.ask(&hub, hash);
    let hsi = HeaderAndShortIds::from_block(&bad, 0xbeef, 2, &[]).unwrap();
    on_cmpctblock(
        &hub,
        &tx,
        &mut follow,
        Some(manual.as_ref()),
        &CmpctBlock { compact_block: hsi },
    )
    .await
    .unwrap();
    let msgs = sent(&mut rx);
    assert!(
        asked_witness(&msgs, hash),
        "the same peer is asked for the full block, got {msgs:?}"
    );
    assert_eq!(follow.ban_score, 0, "a mutated reconstruct is not scored");
    assert!(!manual.stop.load(Ordering::SeqCst), "kept");
    assert!(!hub.is_block_invalid(&hash), "not invalid");
    assert!(follow.requested_blocks.contains(&hash), "still in flight");

    on_block(&hub, &tx, &mut follow, Some(manual.as_ref()), &good)
        .await
        .unwrap();
    assert_eq!(hub.tip_hash(), Some(hash), "the full block connects");
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `NewPoWValidBlock` sends no compact block while segwit is not
/// active at the block's height. The same block is sent once it is.
#[tokio::test]
async fn compact_relay_waits_for_segwit_height() {
    let (dir, mut hub) = open_genesis_announce("relay-segwit-gate", true);
    hub.params
        .apply_test_activation_height("segwit", 2)
        .unwrap();
    let block = hb_tip_child(&hub);
    let hash = block.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let (_target, mut target_rx) = hb_relay_target(&peers, &hub, 18501);
    let from = outbound_test_peer(&peers, 18502);

    relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
    assert!(
        !sent_cmpct(&sent(&mut target_rx), hash),
        "no compact block before segwit is active at its height"
    );

    hub.params
        .apply_test_activation_height("segwit", 1)
        .unwrap();
    relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
    assert!(
        sent_cmpct(&sent(&mut target_rx), hash),
        "the same block is sent once segwit is active at its height"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// `cmpctblock` that waits on one transaction, then the `blocktxn` with it.
async fn cmpct_then_blocktxn(
    hub: &ChainHub,
    peers: &Arc<rbitcoin_net::peers::PeerHub>,
    port: u16,
    block: &bitcoin::Block,
) {
    let peer = inbound_test_peer(peers, port);
    let (tx, mut rx) = peer.open_out();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    let hsi = HeaderAndShortIds::from_block(block, 0xbeef, 2, &[]).unwrap();
    on_cmpctblock(
        hub,
        &tx,
        &mut follow,
        Some(peer.as_ref()),
        &CmpctBlock { compact_block: hsi },
    )
    .await
    .unwrap();
    assert!(
        sent(&mut rx)
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetBlockTxn(_))),
        "the spend is asked by getblocktxn"
    );
    let bt = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![block.txdata[1].clone()],
    };
    on_blocktxn(hub, &tx, &mut follow, Some(peer.as_ref()), &bt)
        .await
        .unwrap();
}

/// A header-path body ask stays with the announcing peer. Another
/// high-bandwidth peer is not asked.
#[tokio::test]
async fn header_download_does_not_fan_out_to_high_bandwidth_peers() {
    let (dir, hub, _) = compact_spend_pair("hdr-no-fanout");
    let tip_time = u64::from(hub.tip_header().unwrap().time);
    hub.clock
        .set_mock(i64::try_from(tip_time).unwrap().saturating_add(1));
    let next = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time.saturating_add(1),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    let hash = next.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let announcer = inbound_test_peer(&peers, 18461);
    let other = outbound_test_peer(&peers, 18462);
    let (ann_tx, mut ann_rx) = announcer.open_out();
    let (_, mut other_rx) = other.open_out();
    let mut follow = PeerFollowState::new();
    on_headers(
        &hub,
        &ann_tx,
        &mut follow,
        Some(announcer.as_ref()),
        &[next.header],
    )
    .await
    .unwrap();
    assert!(
        asked_witness(&sent(&mut ann_rx), hash),
        "the announcing peer is asked for the header's body"
    );
    assert!(
        !asked_witness(&sent(&mut other_rx), hash),
        "a normal body download does not ask another high-bandwidth peer"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The first short-id miss asks one other high-bandwidth peer. A later miss
/// of that same hash does not ask again.
#[tokio::test]
async fn compact_body_is_asked_of_another_peer_once() {
    let (dir, hub, [a, _]) = compact_spend_pair("cmpct-fanout-once");
    let peers = rbitcoin_net::peers::PeerHub::new();
    let announcer = inbound_test_peer(&peers, 18471);
    let other = outbound_test_peer(&peers, 18472);
    let (ann_tx, mut ann_rx) = announcer.open_out();
    let (_, mut other_rx) = other.open_out();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    let hash = a.block_hash();
    on_cmpctblock(
        &hub,
        &ann_tx,
        &mut follow,
        Some(announcer.as_ref()),
        &CmpctBlock {
            compact_block: HeaderAndShortIds::from_block(&a, 0xbeef, 2, &[]).unwrap(),
        },
    )
    .await
    .unwrap();
    let _ = sent(&mut ann_rx);
    assert!(
        asked_witness(&sent(&mut other_rx), hash),
        "the first short-id miss asks another high-bandwidth peer"
    );
    on_blocktxn_unconnectable(&hub, &ann_tx, &mut follow, Some(announcer.as_ref()), hash).unwrap();
    assert!(
        asked_witness(&sent(&mut ann_rx), hash),
        "a failed blocktxn asks the announcing peer for the body"
    );
    assert!(
        !asked_witness(&sent(&mut other_rx), hash),
        "the same hash is not asked of that peer again"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `ProcessCompactBlockTxns` hands a filled body to `ProcessBlock` and
/// does not ask for it again, so an invalid block is fetched from no peer.
/// `FillBlock`'s `READ_STATUS_FAILED` asks the same peer for the full block
/// and keeps it in flight: no other session may claim the body meanwhile.
#[tokio::test]
async fn blocktxn_verdict_is_not_fetched_again_and_a_retry_keeps_its_claim() {
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        absolute::LockTime, Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("blocktxn-ask-claim");
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(mp).is_ok());
    let genesis = hub.tip_header().unwrap();
    let time = genesis.time + 1;
    hub.clock.set_mock(i64::from(time) + 1);
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    // A child of genesis whose one spend is not in the mempool, so its
    // compact block waits on `blocktxn`. The spent output does not exist.
    let child = |tag: u8| {
        let spend = Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([tag; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: op_true.clone(),
            }],
        };
        rbitcoin_consensus::mine_regtest_paying(
            genesis.block_hash(),
            time,
            1,
            op_true.clone(),
            vec![spend],
        )
    };
    let cmpct = |block: &bitcoin::Block| CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(block, 0xbeef, 2, &[]).unwrap(),
    };
    let fill = |block: &bitcoin::Block| BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![block.txdata[1].clone()],
    };
    let peers = rbitcoin_net::peers::PeerHub::new();
    let announcer = inbound_test_peer(&peers, 18475);
    let (ann_tx, mut ann_rx) = announcer.open_out();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;

    let invalid = child(0xab);
    let bad = invalid.block_hash();
    // The tip `getdata` to a compact v2 peer asked for a compact block.
    follow.requested_blocks.ask(&hub, bad);
    on_cmpctblock(
        &hub,
        &ann_tx,
        &mut follow,
        Some(announcer.as_ref()),
        &cmpct(&invalid),
    )
    .await
    .unwrap();
    assert!(
        sent(&mut ann_rx)
            .iter()
            .any(|m| matches!(m, NetworkMessage::GetBlockTxn(_))),
        "the spend is asked by getblocktxn"
    );
    // A high-bandwidth peer that connects while the blocktxn is owed.
    let other = outbound_test_peer(&peers, 18476);
    let (_, mut other_rx) = other.open_out();
    on_blocktxn(
        &hub,
        &ann_tx,
        &mut follow,
        Some(announcer.as_ref()),
        &fill(&invalid),
    )
    .await
    .unwrap();
    assert!(hub.is_block_invalid(&bad), "the filled body is invalid");
    assert!(
        !asked_witness(&sent(&mut ann_rx), bad),
        "the announcer is not asked for the invalid body again"
    );
    assert!(
        !asked_witness(&sent(&mut other_rx), bad),
        "another peer is not asked for the invalid body"
    );
    assert!(
        hub.claim_block_ask(&bad).is_none(),
        "no other session may claim the invalid body"
    );

    let (_, mutated) = witness_committed_pair(&child(0xac));
    let mutated_hash = mutated.block_hash();
    on_cmpctblock(
        &hub,
        &ann_tx,
        &mut follow,
        Some(announcer.as_ref()),
        &cmpct(&mutated),
    )
    .await
    .unwrap();
    let _ = sent(&mut other_rx);
    on_blocktxn(
        &hub,
        &ann_tx,
        &mut follow,
        Some(announcer.as_ref()),
        &fill(&mutated),
    )
    .await
    .unwrap();
    assert!(
        !hub.is_block_invalid(&mutated_hash),
        "a mutated fill is no verdict"
    );
    assert!(
        asked_witness(&sent(&mut ann_rx), mutated_hash),
        "the announcer is asked for the full block"
    );
    assert!(
        hub.claim_block_ask(&mutated_hash).is_none(),
        "the full-block ask holds the body while it is in flight"
    );

    let short = child(0xad);
    let short_hash = short.block_hash();
    on_cmpctblock(
        &hub,
        &ann_tx,
        &mut follow,
        Some(announcer.as_ref()),
        &cmpct(&short),
    )
    .await
    .unwrap();
    let _ = sent(&mut other_rx);
    let none = BlockTransactions {
        block_hash: short_hash,
        transactions: Vec::new(),
    };
    on_blocktxn(&hub, &ann_tx, &mut follow, Some(announcer.as_ref()), &none)
        .await
        .unwrap();
    assert!(
        asked_witness(&sent(&mut ann_rx), short_hash),
        "a blocktxn that cannot fill asks for the full block"
    );
    assert!(
        hub.claim_block_ask(&short_hash).is_none(),
        "that full-block ask holds the body too"
    );

    // A sibling connects, so the session walks its header leaves again.
    let sibling = rbitcoin_consensus::mine_regtest_paying(
        genesis.block_hash(),
        time,
        1,
        ScriptBuf::from_bytes(vec![0x52]),
        Vec::new(),
    );
    on_block(
        &hub,
        &ann_tx,
        &mut follow,
        Some(announcer.as_ref()),
        &sibling,
    )
    .await
    .unwrap();
    assert_eq!(hub.tip_hash(), Some(sibling.block_hash()));
    assert!(
        !asked_witness(&sent(&mut ann_rx), bad),
        "the header path does not fetch the invalid body"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn same_peer_pending_cmpct_does_not_getblocktxn_again() {
    use bitcoin::absolute::LockTime;
    use bitcoin::bip152::HeaderAndShortIds;
    use bitcoin::block::{Header, Version};
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_compact_blocks::CmpctBlock;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use tokio::runtime::Builder;

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-same-peer");
        hub.ensure_genesis().unwrap();
        let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query))
            .unwrap();
        assert!(hub.attach_mempool(mp).is_ok());
        let coinbase = Transaction {
            version: TxVersion::ONE,
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
        let spend = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([0x22; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![1]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut block = bitcoin::Block {
            header: Header {
                version: Version::from_consensus(4),
                prev_blockhash: hub.tip_hash().unwrap(),
                merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
                time: hub.tip_header().unwrap().time + 1,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata: vec![coinbase, spend],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        rbitcoin_consensus::grind_regtest_pow(&mut block.header);
        let hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[]).unwrap();
        let hash = block.block_hash();
        let peers = rbitcoin_net::peers::PeerHub::new();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18446);
        let ver = VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS | ServiceFlags::P2P_V2,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce: 1,
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        let session = peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        );
        let (out_tx, mut out_rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;
        session.hb_to.store(true, Ordering::Relaxed);
        let frame = frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
            compact_block: hsi,
        }));
        handle_peer_frame(frame.clone(), &hub, &out_tx, &mut follow, Some(&session))
            .await
            .unwrap();
        match out_rx.try_recv().expect("first getblocktxn").expect_msg() {
            NetworkMessage::GetBlockTxn(_) => {}
            other => panic!("expected getblocktxn, got {other:?}"),
        }
        handle_peer_frame(frame, &hub, &out_tx, &mut follow, Some(&session))
            .await
            .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "same-peer compact while pending must not getblocktxn again"
        );
        assert!(
            follow.pending_cmpct.contains_key(&hash),
            "first NeedTxn pending must stay"
        );
        assert!(
            peers.try_cmpct_fill_slot(hash, true),
            "same-peer retry must not consume the second inbound fill slot"
        );
        assert!(!peers.try_cmpct_fill_slot(hash, true));
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// BIP339: `wtxidrelay` after verack disconnects, as Core sets `fDisconnect`
/// without a misbehavior score, so a noban peer goes too. The relay mode the
/// handshake fixed does not change.
#[test]
fn wtxidrelay_after_verack_disconnects() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("wtxidrelay-late");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_noban(true);
    let session = live_peer(&peers, 18572, 92, true);
    let (out_tx, _out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(handle_peer_frame(
        frame_for(NetworkMessage::WtxidRelay),
        &hub,
        &out_tx,
        &mut follow,
        Some(session.as_ref()),
    ))
    .expect("wtxidrelay after verack");
    assert!(
        session.stop.load(Ordering::SeqCst),
        "wtxidrelay after verack disconnects"
    );
    assert!(
        !session.wtxid_relay(),
        "the relay mode stays as the handshake fixed it"
    );
    assert_eq!(follow.ban_score, 0, "Core scores no misbehavior for it");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn handle_peer_frame_control_and_inv_paths() {
    use bitcoin::hashes::Hash as _;
    use tokio::runtime::Builder;

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("handle-frame");
        let hub = std::sync::Arc::new(hub);
        hub.ensure_genesis().unwrap();
        let (out_tx, mut out_rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;

        // SendHeaders / SendCmpct / Pong / GetAddr / Ping
        // (MemPool disconnects — covered by bloom_disabled_messages_request_disconnect.)
        // SendAddrV2 after verack disconnects (`p2p_addrv2_relay.py`), and so
        // does WtxidRelay (wtxidrelay_after_verack_disconnects).
        for msg in [
            NetworkMessage::SendHeaders,
            NetworkMessage::SendCmpct(SendCmpct {
                send_compact: true,
                version: 2,
            }),
            NetworkMessage::Pong(7),
            NetworkMessage::GetAddr,
            NetworkMessage::Ping(42),
        ] {
            handle_peer_frame(frame_for(msg), &hub, &out_tx, &mut follow, None)
                .await
                .unwrap();
        }
        assert!(follow.wants_headers);
        assert!(follow.send_cmpct);
        assert_eq!(follow.cmpct_version, 2);

        // Drain outbound: Pong(42) + empty Addr at least.
        let mut saw_pong = false;
        let mut saw_addr = false;
        while let Ok(m) = out_rx.try_recv().map(Queued::expect_msg) {
            match m {
                NetworkMessage::Pong(n) => {
                    assert_eq!(n, 42);
                    saw_pong = true;
                }
                NetworkMessage::Addr(a) => {
                    assert!(a.is_empty());
                    saw_addr = true;
                }
                _ => {}
            }
        }
        assert!(saw_pong);
        assert!(saw_addr);

        // GetHeaders from empty tip-beyond locator.
        use bitcoin::p2p::message_blockdata::GetHeadersMessage;
        let gh = GetHeadersMessage::new(
            vec![hub.tip_hash().unwrap()],
            BlockHash::from_byte_array([0u8; 32]),
        );
        handle_peer_frame(
            frame_for(NetworkMessage::GetHeaders(gh)),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let headers_msg = out_rx.try_recv().unwrap().expect_msg();
        assert!(matches!(headers_msg, NetworkMessage::Headers(_)));

        // Unknown block inv during IBD challenges the walk and asks for
        // headers. No session is attached, so the ask is the inv path's
        // default. Drain it so the headers reply below is the next message.
        let want_h = BlockHash::from_byte_array([0xee; 32]);
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(want_h)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                out_rx.try_recv().unwrap().expect_msg(),
                NetworkMessage::GetHeaders(_)
            ),
            "an unknown block inv during IBD still asks for headers"
        );
        assert!(hub.header_inv_challenge_pending());

        // Headers message inserts pending + issues getdata.
        let gen = hub
            .query
            .wire_header_at_height(rbitcoin_primitives::Height(0))
            .unwrap();
        // A child of genesis that misses its proof of work is not inserted.
        use bitcoin::block::{Header, Version};
        use bitcoin::{CompactTarget, TxMerkleNode};
        let child = Header {
            version: Version::from_consensus(4),
            prev_blockhash: gen.block_hash(),
            merkle_root: TxMerkleNode::from_byte_array([2u8; 32]),
            time: gen.time + 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 1,
        };
        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![child])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            !follow.pending_headers.contains_key(&child.block_hash()),
            "a header the store rejects is not pending"
        );
        let _ = out_rx.try_recv();

        // GetData for known tip block (cache miss → reconstruct).
        let tip = hub.tip_hash().unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WitnessBlock(tip)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert_eq!(served_block(out_rx.try_recv().unwrap()).block_hash(), tip);

        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::CompactBlock(tip)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            out_rx.try_recv().unwrap().expect_msg(),
            NetworkMessage::CmpctBlock(_)
        ));

        use bitcoin::bip152::BlockTransactionsRequest;
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![999],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(follow.ban_score >= BAN_SCORE_THRESHOLD);

        // GetBlockTxn good index 0 (coinbase).
        follow.ban_score = 0;
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![0],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(
            out_rx.try_recv().unwrap().expect_msg(),
            NetworkMessage::BlockTxn(_)
        ));

        // Depth 10 still answers with the transactions. One past that is a full block
        // (`p2p_compactblocks` :635).
        hub.mine(10, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![0],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                out_rx.try_recv().unwrap().expect_msg(),
                NetworkMessage::BlockTxn(_)
            ),
            "getblocktxn at depth 10 still serves the transactions"
        );
        hub.mine(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: BlockTransactionsRequest {
                    block_hash: tip,
                    indexes: vec![0],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            matches!(
                out_rx.try_recv().unwrap().expect_msg(),
                NetworkMessage::Block(_)
            ),
            "getblocktxn past depth 10 must send a full block"
        );

        // Unsolicited BlockTxn → mild ban.
        handle_peer_frame(
            frame_for(NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: BlockHash::from_byte_array([0xdd; 32]),
                    transactions: vec![],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(follow.ban_score >= 5);

        // CmpctBlock without mempool → full getdata fallback.
        let gen_block = hub
            .query
            .reconstruct_block_by_hash(&tip.to_byte_array())
            .unwrap()
            .unwrap();
        let hsi = HeaderAndShortIds::from_block(&gen_block, 9, 2, &[]).unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi,
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        // Already have tip → no getdata; if different hash would request.
        // Genesis is already known so "already have" arm.
        let _ = out_rx.try_recv();

        // Unknown command (including the retired rbtpkg name) is a no-op.
        handle_peer_frame(
            frame_for(NetworkMessage::Unknown {
                command: bitcoin::p2p::message::CommandString::try_from("rbtpkg").unwrap(),
                payload: vec![1, 2, 3],
            }),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();

        handle_peer_frame(
            frame_for(NetworkMessage::SendCmpct(SendCmpct {
                send_compact: false,
                version: 99,
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(follow.send_cmpct); // still true from earlier v2
        assert_eq!(follow.cmpct_version, 2);

        let want2 = BlockHash::from_byte_array([0xcc; 32]);
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::Block(want2)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::GetHeaders(_) => {}
            other => panic!("expected GetHeaders for unknown inv, got {other:?}"),
        }

        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WitnessBlock(
                want2,
            )])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v, vec![Inventory::WitnessBlock(want2)]);
            }
            other => panic!("expected NotFound for unknown block getdata, got {other:?}"),
        }

        // Header row, no body: notfound from the blocking encode, not silence.
        let (gen_fk, gen_rec) = hub
            .query
            .get_header_by_hash(&tip.to_byte_array())
            .unwrap()
            .unwrap();
        let merkle = [0x44u8; 32];
        let version = 4i32;
        let time = gen_rec.timestamp.saturating_add(1);
        let bits = gen_rec.bits;
        let nonce = 9u32;
        let hash = rbitcoin_store::block_header_hash(
            version,
            &tip.to_byte_array(),
            &merkle,
            time,
            bits,
            nonce,
        );
        hub.query
            .put_header(&rbitcoin_store::HeaderRecord {
                prev_fk: gen_fk,
                version,
                timestamp: time,
                bits,
                nonce,
                merkle_root: merkle,
                hash,
                size: 0,
                weight: 0,
            })
            .unwrap();
        let header_only = BlockHash::from_byte_array(hash);
        assert!(hub.knows_header(&header_only), "header row without a body");
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::WitnessBlock(
                header_only,
            )])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v, vec![Inventory::WitnessBlock(header_only)]);
            }
            other => panic!("expected NotFound for header-only getdata, got {other:?}"),
        }

        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(tip)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(out_rx.try_recv().is_err());

        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![Inventory::Block(tip)])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let _ = served_block(out_rx.try_recv().unwrap());

        // Full Block message path: pending + drain_pending (AlreadyHave for tip).
        let gen_block2 = hub
            .query
            .reconstruct_block_by_hash(&tip.to_byte_array())
            .unwrap()
            .unwrap();
        handle_peer_frame(
            frame_for(NetworkMessage::Block(gen_block2)),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        // Tip already confirmed — drain accepts AlreadyHave and may leave empty pending.

        // Tx without mempool is a no-op.
        use bitcoin::absolute::LockTime;
        use bitcoin::script::ScriptBuf;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
        let dummy_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(dummy_tx)),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();

        handle_peer_frame(
            frame_for(NetworkMessage::Unknown {
                command: bitcoin::p2p::message::CommandString::try_from("zzzzzz").unwrap(),
                payload: vec![],
            }),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();

        let _ = std::fs::remove_dir_all(dir);
    });
}

/// Mempool-backed inv/tx/getdata arms + cmpctblocktxn success.
#[test]
fn handle_peer_frame_mempool_tx_and_inv_paths() {
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash as _;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use tokio::runtime::Builder;

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("handle-mp");
        let hub = std::sync::Arc::new(hub);
        hub.ensure_genesis().unwrap();
        let t = hub.tip_header().unwrap().time;
        hub.clock.set_mock(i64::from(t) + 1);
        assert!(!hub.in_ibd(), "tx inv getdata pin is not IBD");
        let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query))
            .unwrap();
        // Enable relay so Inv for txs triggers getdata.
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());

        let (out_tx, mut out_rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;

        let unknown_txid = bitcoin::Txid::from_byte_array([0x42; 32]);
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![
                Inventory::WitnessTransaction(unknown_txid),
                Inventory::WTx(bitcoin::Wtxid::from_byte_array([0x43; 32])),
            ])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::GetData(v) => {
                assert!(!v.is_empty());
            }
            other => panic!("expected GetData for unknown txs, got {other:?}"),
        }

        // GetData for missing tx → notfound (Core ProcessGetData).
        handle_peer_frame(
            frame_for(NetworkMessage::GetData(vec![
                Inventory::WitnessTransaction(unknown_txid),
                Inventory::WTx(bitcoin::Wtxid::from_byte_array([0x43; 32])),
            ])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        match out_rx.try_recv().unwrap().expect_msg() {
            NetworkMessage::NotFound(v) => {
                assert_eq!(v.len(), 2);
            }
            other => panic!("expected batched NotFound, got {other:?}"),
        }
        assert!(out_rx.try_recv().is_err());

        let genesis_txid =
            bitcoin::blockdata::constants::genesis_block(Network::Regtest).txdata[0].compute_txid();
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessTransaction(
                genesis_txid,
            )])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "Class A txid INV must not GETDATA"
        );

        hub.mine(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let mined = hub
            .query
            .reconstruct_block_at_height(rbitcoin_primitives::Height(1))
            .unwrap();
        let cb = &mined.txdata[0];
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![
                Inventory::WitnessTransaction(cb.compute_txid()),
                Inventory::WTx(cb.compute_wtxid()),
            ])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "recent-confirmed INV must not GETDATA"
        );

        // Accept path with invalid prevout — still exercises Tx arm (inserts from_peer).
        let junk = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([1u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![1]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let junk_txid = junk.compute_txid();
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(junk)),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        // Origin map is filled before accept result.
        assert!(follow.from_this_peer.contains_key(&junk_txid));

        // Retired rbtpkg name with mempool + relay: still unknown, no admit
        // even when the payload is the old len-prefixed encoding.
        let pkg_tx = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: bitcoin::Txid::from_byte_array([2u8; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[vec![1]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let pkg_txid = pkg_tx.compute_txid();
        let raw = bitcoin::consensus::encode::serialize(&pkg_tx);
        let mut payload = Vec::with_capacity(4 + raw.len());
        payload.extend_from_slice(&(raw.len() as u32).to_le_bytes());
        payload.extend_from_slice(&raw);
        handle_peer_frame(
            frame_for(NetworkMessage::Unknown {
                command: bitcoin::p2p::message::CommandString::try_from("rbtpkg").unwrap(),
                payload,
            }),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(!follow.from_this_peer.contains_key(&pkg_txid));
        assert_eq!(hub.mempool().unwrap().live_count(), 0);

        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn tx_accept_log_parks_orphans_silences_duplicates() {
    use bitcoin::hashes::Hash;
    let txid = bitcoin::Txid::from_byte_array([1u8; 32]);
    assert_eq!(
        tx_accept_log(&rbitcoin_mempool::AcceptError::Duplicate(txid)),
        TxAcceptLog::Silent
    );
    let e = rbitcoin_mempool::AcceptError::Orphaned {
        txid,
        missing: Default::default(),
        fresh: true,
    };
    assert!(matches!(tx_accept_log(&e), TxAcceptLog::Park(m) if m.is_empty()));
    let again = rbitcoin_mempool::AcceptError::Orphaned {
        txid,
        missing: Default::default(),
        fresh: false,
    };
    assert!(matches!(tx_accept_log(&again), TxAcceptLog::ParentFetch(_)));
    assert_eq!(
        tx_accept_log(&rbitcoin_mempool::AcceptError::Policy("min relay fee")),
        TxAcceptLog::Reject
    );
}

/// Core `m_lazy_recent_rejects`: a second forcerelay send of a rejected tx
/// logs `Not relaying non-mempool` instead of ATMP again (`p2p_permissions`).
fn recent_reject_skips_atmp_on_second_send(via_cidr: bool) {
    use bitcoin::absolute::LockTime;
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::runtime::Builder;

    let coinbase = Transaction {
        version: TxVersion::ONE,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let txid = coinbase.compute_txid();
    let wtxid = coinbase.compute_wtxid();

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let label = if via_cidr {
            "forcerelay-reject"
        } else {
            "always-relay-reject"
        };
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
        hub.ensure_genesis().unwrap();
        let t = hub.tip_header().unwrap().time;
        hub.clock.set_mock(i64::from(t) + 1);
        let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query))
            .unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());

        let peers = rbitcoin_net::peers::PeerHub::new();
        if via_cidr {
            let mut table = rbitcoin_net::net_permissions::NetPermTable::default();
            table.whitelist.push(
                rbitcoin_net::net_permissions::parse_whitelist("forcerelay@127.0.0.1").unwrap(),
            );
            peers.set_net_perms(table);
        } else {
            peers.set_forcerelay_perm(true);
        }
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let ver = VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce: 1,
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        let sess = peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        );
        if via_cidr {
            assert!(sess.has_net_perm(rbitcoin_net::NetPermissionFlags::FORCE_RELAY));
        } else {
            assert!(!sess.has_net_perm(rbitcoin_net::NetPermissionFlags::FORCE_RELAY));
            assert!(sess.session_forcerelay());
        }

        let (out_tx, _out_rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;

        rbitcoin_log::capture_logs(true);
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(coinbase.clone())),
            &hub,
            &out_tx,
            &mut follow,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        let first = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        let needle = format!(
            "txrelay: reject {txid} (wtxid={wtxid}) from peer=0 was not accepted: coinbase"
        );
        assert!(
            first
                .iter()
                .filter(|(level, m)| *level == rbitcoin_log::Level::Info && m.contains(&needle))
                .count()
                == 1,
            "first reject must be one info line, got {first:?}"
        );
        assert!(
            !first
                .iter()
                .any(|(level, m)| *level == rbitcoin_log::Level::Debug
                    && m.contains("txrelay: reject")),
            "reject must not also log at debug, got {first:?}"
        );

        rbitcoin_log::capture_logs(true);
        handle_peer_frame(
            frame_for(NetworkMessage::Tx(coinbase)),
            &hub,
            &out_tx,
            &mut follow,
            Some(sess.as_ref()),
        )
        .await
        .unwrap();
        let second = rbitcoin_log::take_logs();
        rbitcoin_log::capture_logs(false);
        assert!(
            second.iter().any(|(_, m)| m.contains(&format!(
                "Not relaying non-mempool transaction {txid} (wtxid={wtxid}) from forcerelay peer=0"
            ))),
            "second forcerelay send must skip ATMP, got {second:?}"
        );
        let _ = std::fs::remove_dir_all(dir);
    });
}

#[test]
fn forcerelay_recent_reject_is_not_relayed() {
    recent_reject_skips_atmp_on_second_send(true);
}

#[test]
fn always_relay_recent_reject_is_not_relayed() {
    recent_reject_skips_atmp_on_second_send(false);
}

/// Core `ReceivedTx`: a tx whose wtxid is parked is dropped before
/// validation, with no new announcer. A parked copy whose parent is now
/// pooled is not admitted by a resend. A tx the mempool holds as well is
/// handled as a duplicate, so a forcerelay peer still relays it.
#[test]
fn resent_parked_tx_is_not_validated_again() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::collections::BTreeSet;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("resent-parked");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_header().unwrap();
    let (_tip, time, cbs) = rbitcoin_query::pad_empty_from(
        &hub.query,
        &ChainParams::regtest(),
        hub.tip_hash().unwrap(),
        tip.time,
        1,
        101,
        1,
    );
    hub.clock.set_mock(i64::from(time) + 1);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let spend = |prev: OutPoint, value: u64| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let parent = spend(OutPoint::new(cbs[0], 0), 50_0000_0000 - 10_000);
    let child = spend(
        OutPoint::new(parent.compute_txid(), 0),
        50_0000_0000 - 20_000,
    );
    mp.admit_from(&parent, rbitcoin_net::tx_relay::TxOrigin::Local)
        .expect("the parent pays for itself");
    assert!(mp.lock_write().orphanage.insert_from(
        child.clone(),
        BTreeSet::from([parent.compute_txid()]),
        Some(4),
    ));

    let orphan = spend(
        OutPoint::new(bitcoin::Txid::from_byte_array([0x5a; 32]), 0),
        10_000,
    );
    let missing = BTreeSet::from([orphan.input[0].previous_output.txid]);
    assert!(mp
        .lock_write()
        .orphanage
        .insert_from(orphan.clone(), missing, Some(4)));

    let register = |forcerelay: bool, port: u16| {
        let peers = rbitcoin_net::peers::PeerHub::new();
        peers.set_forcerelay_perm(forcerelay);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let ver = VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce: u64::from(port),
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        let sess = peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        );
        (peers, sess)
    };
    let (_plain_hub, plain) = register(false, 18451);
    let (_force_hub, force) = register(true, 18452);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let send = |tx: &Transaction, peer: &rbitcoin_net::peers::LivePeer| {
        rt.block_on(async {
            let (out_tx, _out_rx) = peer_out_channel();
            let mut follow = PeerFollowState::new();
            handle_peer_frame(
                frame_for(NetworkMessage::Tx(tx.clone())),
                &hub,
                &out_tx,
                &mut follow,
                Some(peer),
            )
            .await
            .unwrap();
        })
    };
    let announcers = |tx: &Transaction| mp.lock_read().orphanage.announcers_of(&tx.compute_wtxid());

    send(&child, plain.as_ref());
    assert!(
        !mp.contains(&child.compute_txid()),
        "a parked wtxid is not validated again"
    );
    assert_eq!(announcers(&child), vec![4]);
    send(&orphan, plain.as_ref());
    assert_eq!(
        announcers(&orphan),
        vec![4],
        "a resent orphan adds no announcer"
    );

    mp.admit_from(&child, rbitcoin_net::tx_relay::TxOrigin::Local)
        .expect("a local submit ignores the orphanage");
    assert_eq!(announcers(&child), vec![4], "still parked");
    rbitcoin_log::capture_logs(true);
    send(&child, force.as_ref());
    let logs = rbitcoin_log::take_logs();
    rbitcoin_log::capture_logs(false);
    let needle = format!("Force relaying tx {}", child.compute_txid());
    assert!(
        logs.iter().any(|(_, m)| m.contains(&needle)),
        "a pooled tx is relayed for a forcerelay peer, got {logs:?}"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `AlreadyHaveTx` asks the mempool, not the orphanage, by txid, and
/// `AddTxAnnouncement` adds no orphan announcer for a tx with no missing
/// parent. A child in the mempool that is also parked, beside a parked
/// different witness, is neither requested nor given a new announcer.
#[test]
fn inv_of_a_pooled_tx_that_is_also_parked_is_not_requested() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-pooled-parked");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_header().unwrap();
    let (_tip, time, cbs) = rbitcoin_query::pad_empty_from(
        &hub.query,
        &ChainParams::regtest(),
        hub.tip_hash().unwrap(),
        tip.time,
        1,
        101,
        1,
    );
    hub.clock.set_mock(i64::from(time) + 1);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let spend = |prev: OutPoint, value: u64, witness: Witness| Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prev,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let parent = spend(
        OutPoint::new(cbs[0], 0),
        50_0000_0000 - 10_000,
        Witness::new(),
    );
    let pout = OutPoint::new(parent.compute_txid(), 0);
    let child = spend(pout, 50_0000_0000 - 20_000, Witness::new());
    let child_bad = spend(pout, 50_0000_0000 - 20_000, Witness::from_slice(&[[1u8]]));
    for tx in [&child, &child_bad] {
        let err = mp
            .admit_from(tx, rbitcoin_net::tx_relay::TxOrigin::Relay(Some(4)))
            .unwrap_err();
        assert!(
            matches!(err, rbitcoin_mempool::AcceptError::Orphaned { .. }),
            "{err:?}"
        );
    }
    mp.accept_package(&[parent, child.clone()])
        .expect("the package admits the parked child");
    let parked = mp
        .lock_read()
        .orphanage
        .announcers_of(&child.compute_wtxid());
    assert_eq!(parked, vec![4], "the admitted child is still parked");

    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18450);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 9,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    let (out_tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let unknown = bitcoin::Txid::from_byte_array([7; 32]);
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &[Inventory::WitnessTransaction(unknown)],
    )
    .unwrap();
    assert_eq!(
        sole_getdata(&mut rx),
        vec![Inventory::WitnessTransaction(unknown)],
        "this peer's inv of an unknown tx is requested"
    );
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &[Inventory::WTx(child.compute_wtxid())],
    )
    .unwrap();
    assert_eq!(
        mp.lock_read()
            .orphanage
            .announcers_of(&child.compute_wtxid()),
        vec![4],
        "an inv of a pooled tx adds no orphan announcer"
    );
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
        &[Inventory::WitnessTransaction(child.compute_txid())],
    )
    .unwrap();
    assert!(
        rx.try_recv().is_err(),
        "a txid in the mempool is not requested, whatever is parked"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `AlreadyHaveTx`: a tx in `m_lazy_recent_rejects` is not requested
/// when another peer announces it, by txid or by wtxid
/// (`p2p_orphan_handling.py` `test_orphan_inherit_rejection`).
#[test]
fn recent_reject_is_not_requested_from_other_peers() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    use tokio::runtime::Builder;

    // Rejected before its inputs are looked up, as Core's CheckTransaction
    // does, so its child finds a recent-reject parent rather than a coin.
    let spend = TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::from_byte_array([9; 32]),
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    let parent = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![spend.clone(), spend],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let txid = parent.compute_txid();
    let wtxid = parent.compute_wtxid();

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("reject-inv-other-peer");
        hub.ensure_genesis().unwrap();
        let t = hub.tip_header().unwrap().time;
        hub.clock.set_mock(i64::from(t) + 1);
        let mp = rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query))
            .unwrap();
        mp.set_relay_enabled(true);
        assert!(hub.attach_mempool(mp).is_ok());

        let peers = rbitcoin_net::peers::PeerHub::new();
        let register = |port: u16, nonce: u64| {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            let ver = VersionMessage {
                version: 70016,
                services: ServiceFlags::NETWORK,
                timestamp: 0,
                receiver: Address::new(&addr, ServiceFlags::NONE),
                sender: Address::new(&addr, ServiceFlags::NONE),
                nonce,
                user_agent: "/rbitcoin:test/".into(),
                start_height: 0,
                relay: true,
            };
            peers.register(
                addr,
                addr,
                &ver,
                false,
                rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
            )
        };
        let sender = register(18444, 1);
        let by_txid = register(18445, 2);
        let by_wtxid = register(18446, 3);

        async fn getdata_for(
            hub: &ChainHub,
            peer: &rbitcoin_net::peers::LivePeer,
            item: Inventory,
        ) -> Vec<Inventory> {
            let (out_tx, mut out_rx) = peer_out_channel();
            let mut follow = PeerFollowState::new();
            handle_peer_frame(
                frame_for(NetworkMessage::Inv(vec![item])),
                hub,
                &out_tx,
                &mut follow,
                Some(peer),
            )
            .await
            .unwrap();
            let mut want = Vec::new();
            while let Ok(out) = out_rx.try_recv() {
                if let NetworkMessage::GetData(v) = out.expect_msg() {
                    want.extend(v);
                }
            }
            want
        }

        let unknown = bitcoin::Txid::from_byte_array([7; 32]);
        assert_eq!(
            getdata_for(&hub, &by_txid, Inventory::Transaction(unknown)).await,
            vec![Inventory::WitnessTransaction(unknown)],
            "an unknown tx is requested"
        );

        // A segwit child of the rejected parent: its txid is not its wtxid, so
        // only the txid entry it inherits from the parent can match an inv by
        // txid.
        let child = Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid, vout: 0 },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::from_slice(&[[1u8]]),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let child_txid = child.compute_txid();
        assert_ne!(
            child_txid.to_byte_array(),
            child.compute_wtxid().to_byte_array()
        );

        let (out_tx, _out_rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        for tx in [parent, child] {
            handle_peer_frame(
                frame_for(NetworkMessage::Tx(tx)),
                &hub,
                &out_tx,
                &mut follow,
                Some(sender.as_ref()),
            )
            .await
            .unwrap();
        }

        assert_eq!(
            getdata_for(&hub, &by_txid, Inventory::Transaction(txid)).await,
            vec![],
            "a rejected tx is not requested by txid"
        );
        assert_eq!(
            getdata_for(&hub, &by_txid, Inventory::Transaction(child_txid)).await,
            vec![],
            "the segwit child of a rejected tx is not requested by txid"
        );
        // A txid ask waits while a wtxid-relay peer is connected, so the
        // txid checks above come first: a delayed ask is also an empty getdata.
        by_wtxid.set_wtxid_relay();
        assert_eq!(
            getdata_for(&hub, &by_wtxid, Inventory::WTx(wtxid)).await,
            vec![],
            "a rejected tx is not requested by wtxid"
        );
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// Compact fill with a live mempool hub must not `list_live` every body.
#[test]
fn cmpct_helpers_with_mempool_skip_list_live() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    };

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-mp");
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(mp).is_ok());
    assert!(hub.mempool().is_some());

    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[vec![1]]),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let mut block = bitcoin::Block {
        header: Header {
            version: Version::from_consensus(4),
            prev_blockhash: hub.tip_hash().unwrap(),
            merkle_root: TxMerkleNode::from_byte_array([0u8; 32]),
            time: hub.tip_header().unwrap().time + 1,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![
            Transaction {
                version: TxVersion::ONE,
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
            },
            spend.clone(),
        ],
    };
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    rbitcoin_consensus::grind_regtest_pow(&mut block.header);

    let hsi = HeaderAndShortIds::from_block(&block, 0xbeef, 2, &[]).unwrap();
    // Mempool present but empty live → Some(missing) not None.
    let missing = match try_reconstruct_cmpct(&hub, &hsi, 2) {
        Some(CmpctReconstruct::NeedTxn(p, _)) => p.missing().to_vec(),
        other => panic!("expected NeedTxn, got {other:?}"),
    };
    assert_eq!(missing, vec![1]); // spend short-id missing
    let mp = hub.mempool().unwrap();
    let _ = mp.sample_reset_perf();
    let _ = try_reconstruct_cmpct(&hub, &hsi, 2);
    let fill = mp.sample_reset_perf();
    assert_eq!(
        fill.list_live, 0,
        "compact fill must not list_live/clone every body (got {})",
        fill.list_live
    );

    use bitcoin::bip152::BlockTransactions;
    use bitcoin::p2p::message_compact_blocks::{BlockTxn, CmpctBlock};
    use tokio::runtime::Builder;
    let hsi_ok = hsi.clone();
    let hsi_fail = hsi.clone();
    let spend_ok = spend.clone();
    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (out_tx, mut out_rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi_fail,
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let _ = out_rx.try_recv().expect("getblocktxn");
        handle_peer_frame(
            frame_for(NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: block.block_hash(),
                    transactions: vec![],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(follow.ban_score >= 10, "solicited bad blocktxn bans");
        match out_rx
            .try_recv()
            .expect("a failed blocktxn asks this peer for the body")
            .expect_msg()
        {
            NetworkMessage::GetData(inv) => assert_eq!(
                inv,
                vec![Inventory::WitnessBlock(block.block_hash())],
                "a failed blocktxn is followed by a full-block getdata on this peer"
            ),
            other => panic!("expected getdata, got {other:?}"),
        }
        let ban_after_fail = follow.ban_score;
        handle_peer_frame(
            frame_for(NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: block.block_hash(),
                    transactions: vec![],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert_eq!(
            follow.ban_score,
            ban_after_fail + 5,
            "late blocktxn after fail is mild"
        );
    });
    rt.block_on(async {
        let (out_tx, mut out_rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;
        handle_peer_frame(
            frame_for(NetworkMessage::CmpctBlock(CmpctBlock {
                compact_block: hsi_ok,
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let gbt = match out_rx.try_recv().expect("getblocktxn").expect_msg() {
            NetworkMessage::GetBlockTxn(g) => g,
            other => panic!("expected getblocktxn, got {other:?}"),
        };
        assert_eq!(gbt.txs_request.indexes, vec![1]);
        handle_peer_frame(
            frame_for(NetworkMessage::BlockTxn(BlockTxn {
                transactions: BlockTransactions {
                    block_hash: block.block_hash(),
                    transactions: vec![spend_ok],
                },
            })),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        assert!(
            follow.pending_cmpct.is_empty(),
            "blocktxn apply must consume the pending compact"
        );
    });

    let _ = std::fs::remove_dir_all(dir);
}

/// Tip-follow receive: max-work fork held then applied via `accept_received_block`.
#[test]
fn p2p_side_chain_reorgs_via_held_bodies() {
    use bitcoin::absolute::LockTime;
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::script::ScriptBuf;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{
        Amount, CompactTarget, OutPoint, Sequence, Target, Transaction, TxIn, TxOut, Witness,
    };

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pending-reorg");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();

    let coinbase = |height: u32| {
        let mut ss = rbitcoin_consensus::bip34_height_script(height);
        while ss.len() < 2 {
            ss.push(0x00);
        }
        Transaction {
            version: TxVersion::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(ss),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    };
    let mine = |prev: BlockHash, time: u32, height: u32| {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = bitcoin::Block {
            header: Header {
                version: BlockVersion::from_consensus(4),
                prev_blockhash: prev,
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0u8; 32]),
                time,
                bits,
                nonce: 0,
            },
            txdata: vec![coinbase(height)],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = Target::from_compact(bits);
        for nonce in 0..u32::MAX {
            block.header.nonce = nonce;
            if block.header.validate_pow(target).is_ok() {
                break;
            }
        }
        block
    };

    // Main tip height 2 (times near genesis MTP window).
    let b1 = mine(gen, 1_300_000_100, 1);
    hub.accept_block(b1.clone()).unwrap();
    let b2 = mine(b1.block_hash(), 1_300_000_200, 2);
    hub.accept_block(b2.clone()).unwrap();
    assert_eq!(hub.tip_height(), Some(2));

    // Pending: short side from gen (1 block) + long side from gen (4 blocks).
    let short = mine(gen, 1_300_001_000, 1);
    let mut long = Vec::new();
    let mut p = gen;
    for (i, h) in (1..=4u32).enumerate() {
        let b = mine(p, 1_300_002_000 + i as u32 * 600, h);
        p = b.block_hash();
        long.push(b);
    }
    // Short side first (held, weaker), then the longer fork one body at a time
    // — same order a peer `block` message stream would deliver.
    hub.accept_received_block(short).unwrap();
    for b in &long {
        hub.accept_received_block(b.clone()).unwrap();
    }
    assert_eq!(
        hub.tip_height(),
        Some(4),
        "must reorg onto longer held branch"
    );
    assert_eq!(hub.tip_hash().unwrap(), long[3].block_hash());
    assert!(hub.held_body(&long[3].block_hash()).is_none());
    const {
        assert!(MAX_PENDING_BLOCKS_FOR_TEST >= 128);
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn inv_of_already_asked_block_does_not_getdata() {
    // p2p_sendheaders Part 2: test_node announces headers (we getdata),
    // then inv_node re-invs the same hashes. One getdata in flight globally.
    use bitcoin::script::ScriptBuf;
    use rbitcoin_primitives::Height;
    use tokio::runtime::Builder;

    fn drain_block_getdata(rx: &mut PeerOutRx) -> Vec<BlockHash> {
        let mut hashes = Vec::new();
        while let Ok(m) = rx.try_recv().map(Queued::expect_msg) {
            if let NetworkMessage::GetData(inv) = m {
                for i in inv {
                    if let Inventory::Block(h)
                    | Inventory::WitnessBlock(h)
                    | Inventory::CompactBlock(h) = i
                    {
                        hashes.push(h);
                    }
                }
            }
        }
        hashes
    }

    let rt = Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let (src_dir, src) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-asked-src");
        let src = Arc::new(src);
        src.ensure_genesis().unwrap();
        src.mine(1, ScriptBuf::from_bytes(vec![0x51]), vec![])
            .unwrap();
        let hdr = src.query.wire_header_at_height(Height(1)).unwrap();
        let hash = hdr.block_hash();

        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-asked-dst");
        hub.ensure_genesis().unwrap();

        let (out_tx, mut out_rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;

        handle_peer_frame(
            frame_for(NetworkMessage::Headers(vec![hdr])),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
        let first = drain_block_getdata(&mut out_rx);
        assert_eq!(first, vec![hash], "header announce must getdata once");
        assert!(hub.already_have_or_asked_block(&hash));

        // Second peer: empty local requested set, same hub (asked_blocks).
        let (out_tx2, mut out_rx2) = peer_out_channel();
        let mut follow2 = PeerFollowState::new();
        handle_peer_frame(
            frame_for(NetworkMessage::Inv(vec![Inventory::WitnessBlock(hash)])),
            &hub,
            &out_tx2,
            &mut follow2,
            None,
        )
        .await
        .unwrap();
        let second = drain_block_getdata(&mut out_rx2);
        assert!(
            second.is_empty(),
            "duplicate inv must not getdata, got {second:?}"
        );

        let _ = std::fs::remove_dir_all(src_dir);
        let _ = std::fs::remove_dir_all(dir);
    });
}

/// `p2p_nobloomfilter_messages.py`: mempool/filter* disconnect when bloom off.
#[test]
fn bloom_disabled_messages_request_disconnect() {
    use bitcoin::p2p::message_bloom::FilterAdd;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("bloom-off");
    hub.ensure_genesis().unwrap();
    let (out_tx, _out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let msgs = [
        NetworkMessage::MemPool,
        NetworkMessage::FilterClear,
        NetworkMessage::FilterAdd(FilterAdd { data: vec![0xcc] }),
    ];
    for msg in msgs {
        follow.ban_score = 0;
        rt.block_on(async {
            handle_peer_frame(frame_for(msg), &hub, &out_tx, &mut follow, None)
                .await
                .unwrap();
        });
        assert!(
            follow.ban_score >= BAN_SCORE_THRESHOLD,
            "bloom-off message must punish-disconnect (ban={})",
            follow.ban_score
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// An `addr`, `addrv2`, locator, `cfheaders` or `getblocktxn` frame that
/// claims more items than its bytes can hold is refused before the decoder
/// sizes a vector from that count, and scores like any oversize frame.
#[test]
fn short_counted_frames_disconnect_before_decode() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("short-counted");
    hub.ensure_genesis().unwrap();
    let (out_tx, _out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // 0xfe 0x00 0x09 0x3d 0x00 is a compact-size of 4_000_000.
    let huge = [0xfe, 0x00, 0x09, 0x3d, 0x00];
    for (command, prefix) in [
        (*b"addr\0\0\0\0\0\0\0\0", 0),
        (*b"addrv2\0\0\0\0\0\0", 0),
        (*b"getheaders\0\0", 4),
        (*b"getblocks\0\0\0", 4),
        (*b"cfheaders\0\0\0", 65),
        (*b"getblocktxn\0", 32),
    ] {
        let mut payload = vec![0u8; prefix];
        payload.extend_from_slice(&huge);
        payload.extend_from_slice(&[0u8; 64]);
        let frame = FramedMessage {
            magic: Magic::from(Network::Regtest),
            command,
            payload,
        };
        follow.ban_score = 0;
        let r = rt.block_on(handle_peer_frame(frame, &hub, &out_tx, &mut follow, None));
        assert!(
            matches!(r, Err(NetError::MessageTooLarge(4_000_000))),
            "{command:?}: got {r:?}"
        );
        assert!(
            follow.ban_score >= BAN_SCORE_THRESHOLD,
            "{command:?}: ban={}",
            follow.ban_score
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// `p2p_invalid_locator.py`: getheaders/getblocks with locator > MAX_LOCATOR_SZ disconnect.
#[test]
fn oversize_locator_request_disconnect() {
    use bitcoin::p2p::message_blockdata::{GetBlocksMessage, GetHeadersMessage};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("locator-oversize");
    hub.ensure_genesis().unwrap();
    let (out_tx, _out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.cmpct_version = 2;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let stop = BlockHash::from_byte_array([0u8; 32]);
    let oversize: Vec<BlockHash> = (0..=MAX_LOCATOR_SZ)
        .map(|i| BlockHash::from_byte_array([i as u8; 32]))
        .collect();
    assert_eq!(oversize.len(), MAX_LOCATOR_SZ + 1);
    let within: Vec<BlockHash> = oversize[..MAX_LOCATOR_SZ].to_vec();

    for msg in [
        NetworkMessage::GetHeaders(GetHeadersMessage::new(oversize.clone(), stop)),
        NetworkMessage::GetBlocks(GetBlocksMessage::new(oversize.clone(), stop)),
    ] {
        follow.ban_score = 0;
        rt.block_on(async {
            handle_peer_frame(frame_for(msg), &hub, &out_tx, &mut follow, None)
                .await
                .unwrap();
        });
        assert!(
            follow.ban_score >= BAN_SCORE_THRESHOLD,
            "oversize locator must punish-disconnect (ban={})",
            follow.ban_score
        );
    }

    // Exactly MAX_LOCATOR_SZ stays connected (ban untouched).
    follow.ban_score = 0;
    rt.block_on(async {
        handle_peer_frame(
            frame_for(NetworkMessage::GetHeaders(GetHeadersMessage::new(
                within, stop,
            ))),
            &hub,
            &out_tx,
            &mut follow,
            None,
        )
        .await
        .unwrap();
    });
    assert_eq!(follow.ban_score, 0, "max-sized locator must not disconnect");

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn desirable_service_flags_match_core() {
    let full = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    let pruned = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
    let none = ServiceFlags::NONE;
    let net_only = ServiceFlags::NETWORK;
    let wit_only = ServiceFlags::WITNESS;
    let limited_wit = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
    let limited_wit_v2 = limited_wit | ServiceFlags::P2P_V2;

    assert_eq!(desirable_service_flags(none, 0), full);
    assert_eq!(desirable_service_flags(net_only, 0), full);
    assert_eq!(desirable_service_flags(wit_only, 0), full);
    assert_eq!(desirable_service_flags(full, 0), full);
    assert!(!has_all_desirable_service_flags(none, 0));
    assert!(!has_all_desirable_service_flags(net_only, 0));
    assert!(!has_all_desirable_service_flags(wit_only, 0));
    assert!(has_all_desirable_service_flags(full, 0));

    assert_eq!(desirable_service_flags(limited_wit, 150), full);
    assert!(!has_all_desirable_service_flags(limited_wit, 150));
    assert_eq!(desirable_service_flags(limited_wit, 138), pruned);
    assert!(has_all_desirable_service_flags(limited_wit, 138));
    assert!(has_all_desirable_service_flags(limited_wit_v2, 138));
}

#[test]
fn expect_services_from_conn_matches_core() {
    use rbitcoin_net::peers::PeerConnType;
    assert!(!expect_services_from_conn(PeerConnType::Inbound));
    assert!(!expect_services_from_conn(PeerConnType::Manual));
    assert!(!expect_services_from_conn(PeerConnType::Feeler));
    assert!(expect_services_from_conn(PeerConnType::OutboundFullRelay));
    assert!(expect_services_from_conn(PeerConnType::BlockRelay));
    assert!(expect_services_from_conn(PeerConnType::AddrFetch));
}

#[test]
fn min_peer_proto_version_hides_an_unspecified_addr() {
    assert_eq!(rbitcoin_net::peer::MIN_PEER_PROTO_VERSION, 31800);
    let hidden = rbitcoin_net::peer::hidden_addr_from();
    let zero = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
    assert_eq!(
        hidden,
        bitcoin::p2p::address::Address::new(&zero, bitcoin::p2p::ServiceFlags::NONE)
    );
}

#[test]
fn pending_blocks_insert_evicts_at_cap() {
    let mut pending = PendingBlocks::new();
    let bits = bitcoin::CompactTarget::from_consensus(0x207f_ffff);
    let mut hashes = Vec::new();
    for i in 0u32..(MAX_PENDING_BLOCKS_FOR_TEST as u32 + 1) {
        let mut b = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        b.header.merkle_root = bitcoin::TxMerkleNode::from_byte_array({
            let mut m = [0u8; 32];
            m[0] = (i >> 24) as u8;
            m[1] = (i >> 16) as u8;
            m[2] = (i >> 8) as u8;
            m[3] = i as u8;
            m
        });
        b.header.bits = bits;
        let h = b.block_hash();
        hashes.push(h);
        pending.insert(h, b, None);
    }
    assert_eq!(pending.keys().len(), MAX_PENDING_BLOCKS_FOR_TEST);
    assert!(
        !pending.contains_key(&hashes[0]),
        "cap eviction must drop the oldest insert, not HashMap::keys().next()"
    );
    assert!(pending.contains_key(&hashes[MAX_PENDING_BLOCKS_FOR_TEST]));
}

#[test]
fn pending_block_over_four_megabytes_is_not_parked() {
    let mut pending = PendingBlocks::new();
    let mut exact = block_with_wire_len(4_000_000);
    exact.header.nonce = 1;
    let exact_h = exact.block_hash();
    pending.insert(exact_h, exact, None);
    assert!(
        pending.contains_key(&exact_h),
        "a 4_000_000-byte body is parked"
    );
    let mut over = block_with_wire_len(4_000_000);
    over.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0u8; 4_000_001]);
    over.header.nonce = 2;
    let h = over.block_hash();
    pending.insert(h, over, None);
    assert!(!pending.contains_key(&h));
    assert!(pending.contains_key(&exact_h));
}

fn block_with_wire_len(n: usize) -> bitcoin::Block {
    let mut b = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut len = n;
    for _ in 0..6 {
        b.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![0u8; len]);
        let got = b.total_size();
        if got == n {
            return b;
        }
        if got > n {
            len = len.saturating_sub(got - n);
        } else {
            len = len.saturating_add(n - got);
        }
    }
    panic!("wire len {n} landed on {}", b.total_size());
}

#[test]
fn announced_tip_is_hopeless_less_and_288_behind() {
    use std::cmp::Ordering;
    assert!(announced_tip_is_hopeless(
        964_000,
        961_638,
        Some(Ordering::Less)
    ));
    assert!(!announced_tip_is_hopeless(
        964_000,
        963_900,
        Some(Ordering::Less)
    ));
    assert!(!announced_tip_is_hopeless(
        964_000,
        961_638,
        Some(Ordering::Greater)
    ));
    assert!(!announced_tip_is_hopeless(100, 1, Some(Ordering::Less)));
    assert!(!announced_tip_is_hopeless(
        964_000,
        961_638,
        Some(Ordering::Equal)
    ));
    assert!(!announced_tip_is_hopeless(964_000, 961_638, None));
}

struct ServeSession {
    _dir: rbitcoin_query::testutil::TempDir,
    hub: std::sync::Arc<rbitcoin_net::chain::ChainHub>,
    hashes: Vec<BlockHash>,
    _peers: std::sync::Arc<rbitcoin_net::peers::PeerHub>,
    sess: std::sync::Arc<rbitcoin_net::peers::LivePeer>,
}

fn serve_session(label: &str, blocks: u32) -> ServeSession {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let hashes = hub
        .mine(blocks, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    assert_eq!(hashes.len(), blocks as usize);
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let sess = peers.register(
        addr,
        addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    ServeSession {
        _dir: dir,
        hub,
        hashes,
        _peers: peers,
        sess,
    }
}

fn getdata_frame(hashes: &[BlockHash]) -> FramedMessage {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    use bitcoin::p2p::message_blockdata::Inventory;
    let inv = hashes.iter().map(|h| Inventory::WitnessBlock(*h)).collect();
    let magic = Magic::from(bitcoin::Network::Regtest);
    let full = serialize(&RawNetworkMessage::new(magic, NetworkMessage::GetData(inv)));
    FramedMessage {
        magic,
        command: full[4..16].try_into().unwrap(),
        payload: full[24..].to_vec(),
    }
}

/// Stand-in for the session writer mid-batch: everything queued so far,
/// still charged, with the `notfound` rows split from the served bodies.
fn take_queued(out_rx: &mut PeerOutRx) -> (Vec<Queued>, Vec<Vec<Inventory>>) {
    let mut bodies = Vec::new();
    let mut notfound = Vec::new();
    while let Ok(out) = out_rx.try_recv() {
        match out.out() {
            PeerOut::Msg(NetworkMessage::NotFound(inv)) => notfound.push(inv.clone()),
            _ => bodies.push(out),
        }
    }
    (bodies, notfound)
}

/// The writer finishes `queued`, releasing each charge.
fn served_hashes(queued: Vec<Queued>) -> Vec<BlockHash> {
    queued
        .into_iter()
        .map(|out| served_block(out).block_hash())
        .collect()
}

/// Core `ProcessGetData` stops on a full send buffer, sends the `notfound`
/// it collected, and returns to the message loop with the rest queued. A
/// getdata past the served-body cap hands the reader back the same way.
/// Once the writer drains, the rest is served in order and no hash is
/// dropped. A silent drop held the requester's getdata until its 30 s
/// stall kick.
#[test]
fn getdata_past_serve_cap_waits_for_writer() {
    use std::time::Duration;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("serve-cap-waits", 20);
        let (out_tx, mut out_rx) = s.sess.open_out();
        let mut follow = PeerFollowState::new();
        let unknown = BlockHash::from_byte_array([7u8; 32]);
        let ask: Vec<BlockHash> = std::iter::once(unknown).chain(s.hashes.clone()).collect();
        tokio::time::timeout(
            Duration::from_secs(10),
            handle_peer_frame(
                getdata_frame(&ask),
                &s.hub,
                &out_tx,
                &mut follow,
                Some(s.sess.as_ref()),
            ),
        )
        .await
        .expect("a getdata past the serve cap returns to the session loop")
        .unwrap();
        let (first, notfound) = take_queued(&mut out_rx);
        assert_eq!(first.len(), MAX_SERVE_BLOCKS, "the 17th waits");
        assert_eq!(
            notfound,
            vec![vec![Inventory::WitnessBlock(unknown)]],
            "the notfound collected before the pause is sent"
        );
        assert_eq!(s.sess.serve_inflight(), MAX_SERVE_BLOCKS);

        let mut served = served_hashes(first);
        serve_getdata_tail(&s.hub, &out_tx, &mut follow, Some(s.sess.as_ref()))
            .await
            .unwrap();
        let (rest, notfound) = take_queued(&mut out_rx);
        assert!(notfound.is_empty(), "no notfound for blocks we hold");
        served.extend(served_hashes(rest));
        assert_eq!(
            served, s.hashes,
            "every requested block is served once, in order"
        );
    });
}

fn getblocktxn_frame(hash: BlockHash, indexes: Vec<u64>) -> FramedMessage {
    use bitcoin::consensus::encode::serialize;
    use bitcoin::p2p::message::RawNetworkMessage;
    let msg = NetworkMessage::GetBlockTxn(GetBlockTxn {
        txs_request: BlockTransactionsRequest {
            block_hash: hash,
            indexes,
        },
    });
    let magic = Magic::from(bitcoin::Network::Regtest);
    let full = serialize(&RawNetworkMessage::new(magic, msg));
    FramedMessage {
        magic,
        command: full[4..16].try_into().unwrap(),
        payload: full[24..].to_vec(),
    }
}

/// A `getblocktxn` for a block we hold, while the writer is already past
/// the send budget, queues nothing and keeps the request. After the writer
/// drains, that request is served as a `blocktxn` or a full block, charged
/// at its real size, and it holds a serve slot.
#[test]
fn getblocktxn_over_send_budget_waits_for_writer() {
    use std::time::Duration;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("gbtxn-budget-waits", 12);
        let tip = *s.hashes.last().unwrap();
        let deep = s.hashes[0];
        let (out_tx, mut out_rx) = s.sess.open_out();
        let mut follow = PeerFollowState::new();
        let earlier = rbitcoin_net::peers::PEER_SEND_BUDGET + 1;
        let held = hold_send_bytes(&s.sess, earlier);
        tokio::time::timeout(
            Duration::from_secs(10),
            handle_peer_frame(
                getblocktxn_frame(tip, vec![0]),
                &s.hub,
                &out_tx,
                &mut follow,
                Some(s.sess.as_ref()),
            ),
        )
        .await
        .expect("a getblocktxn past the send budget returns to the session loop")
        .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "getblocktxn past the send budget is not queued"
        );
        assert_eq!(
            s.sess.send_queued(),
            earlier,
            "a paused getblocktxn reconstructs nothing"
        );
        assert!(
            !follow.getblocktxn_tail.is_empty(),
            "the request stays until the writer drains"
        );

        drop(held);
        serve_getblocktxn_tail(&s.hub, &out_tx, &mut follow, Some(s.sess.as_ref()))
            .await
            .unwrap();
        let served = out_rx
            .try_recv()
            .expect("drain serves the parked getblocktxn");
        assert!(
            served.out().holds_serve_slot(),
            "a getblocktxn reply holds a serve slot"
        );
        let charged = rbitcoin_net::peers::outbound_queued_bytes(served.out());
        let msg = match served.out() {
            PeerOut::Msg(m) | PeerOut::Served(m) => m,
            PeerOut::Encoded(_) => panic!("getblocktxn reply is not a pre-encoded getdata body"),
        };
        match msg {
            NetworkMessage::BlockTxn(bt) => {
                let n = bitcoin::consensus::encode::serialize(&bt.transactions).len();
                assert!(n > 64, "blocktxn is not the 64-byte fallback");
                assert_eq!(charged, n);
            }
            NetworkMessage::Block(b) => {
                assert!(b.total_size() > 64);
                assert_eq!(charged, b.total_size());
            }
            other => panic!("expected blocktxn or block, got {other:?}"),
        }
        assert_eq!(s.sess.send_queued(), charged);
        assert_eq!(s.sess.serve_inflight(), 1);
        assert!(follow.getblocktxn_tail.is_empty());
        drop(served);

        // Depth > 10 is the full block, on the same slot and byte charge.
        handle_peer_frame(
            getblocktxn_frame(deep, vec![0]),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();
        let deep_out = out_rx.try_recv().expect("deep getblocktxn");
        assert!(deep_out.out().holds_serve_slot());
        match deep_out.out() {
            PeerOut::Served(NetworkMessage::Block(b)) => assert_eq!(b.block_hash(), deep),
            other => panic!("depth past 10 is a full block, got {other:?}"),
        }

        // An empty getblocktxn asks for nothing. Core drops the peer before
        // it reads the block (bitcoin/bitcoin#35832).
        handle_peer_frame(
            getblocktxn_frame(deep, vec![]),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();
        assert!(
            out_rx.try_recv().is_err(),
            "an empty getblocktxn sends nothing back"
        );
        assert!(follow.getblocktxn_tail.is_empty());
        assert!(
            s.sess.stop.load(Ordering::SeqCst),
            "an empty getblocktxn drops the peer"
        );

        // The peer never reads. Further requests stop at the serve cap
        // instead of reconstructing without bound.
        let queued_before = s.sess.send_queued();
        let mut unread = Vec::new();
        for _ in 0..MAX_SERVE_BLOCKS + 4 {
            handle_peer_frame(
                getblocktxn_frame(tip, vec![0]),
                &s.hub,
                &out_tx,
                &mut follow,
                Some(s.sess.as_ref()),
            )
            .await
            .unwrap();
            let Ok(reply) = out_rx.try_recv() else {
                break;
            };
            unread.push(reply);
        }
        assert_eq!(
            unread.len(),
            MAX_SERVE_BLOCKS - 1,
            "the 17th getblocktxn waits"
        );
        assert_eq!(s.sess.serve_inflight(), MAX_SERVE_BLOCKS);
        assert_eq!(follow.getblocktxn_tail.len(), 1);
        assert!(s.sess.send_queued() > queued_before);
        assert!(
            s.sess.send_queued() <= rbitcoin_net::peers::PEER_SEND_BUDGET,
            "small blocktxn replies stay inside the byte budget at the slot cap"
        );
    });
}

/// Archive reconstruct for `getblocktxn` runs on the blocking pool. A
/// connection task named `tokio-rt-worker` still receives the reply.
#[test]
fn getblocktxn_reconstruct_is_off_the_connection_task() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("gbtxn-reactor", 1);
        let tip = *s.hashes.last().unwrap();
        let (out_tx, mut out_rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        handle_peer_frame(
            getblocktxn_frame(tip, vec![0]),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();
        assert!(matches!(
            out_rx.try_recv().unwrap().expect_msg(),
            NetworkMessage::BlockTxn(_)
        ));
    });
}

/// `blocktxn` shares the send budget at its real payload size. The 64-byte
/// fallback let a peer that never reads queue far more than 4 MiB.
#[test]
fn blocktxn_outbound_bytes_are_the_payload() {
    use bitcoin::bip152::BlockTransactions;
    use bitcoin::consensus::encode::serialize;
    let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let txns = BlockTransactions {
        block_hash: block.block_hash(),
        transactions: vec![block.txdata[0].clone()],
    };
    let payload = serialize(&txns).len();
    assert!(payload > 64, "a coinbase blocktxn is not the fallback size");
    assert_eq!(
        rbitcoin_net::peers::outbound_msg_bytes(&NetworkMessage::BlockTxn(BlockTxn {
            transactions: txns
        })),
        payload
    );
}

/// A reply already past the send budget pauses the whole getdata. It does
/// not drop it.
#[test]
fn getdata_over_send_budget_waits_for_writer() {
    use std::time::Duration;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("serve-budget-waits", 3);
        let held = hold_send_bytes(&s.sess, rbitcoin_net::peers::PEER_SEND_BUDGET + 1);
        let (out_tx, mut out_rx) = s.sess.open_out();
        let mut follow = PeerFollowState::new();
        tokio::time::timeout(
            Duration::from_secs(10),
            handle_peer_frame(
                getdata_frame(&s.hashes),
                &s.hub,
                &out_tx,
                &mut follow,
                Some(s.sess.as_ref()),
            ),
        )
        .await
        .expect("a getdata past the send budget returns to the session loop")
        .unwrap();
        assert!(out_rx.try_recv().is_err(), "served past the send budget");
        drop(held);
        serve_getdata_tail(&s.hub, &out_tx, &mut follow, Some(s.sess.as_ref()))
            .await
            .unwrap();
        let (got, notfound) = take_queued(&mut out_rx);
        assert!(notfound.is_empty());
        assert_eq!(served_hashes(got), s.hashes);
    });
}

/// A compact tip announce holds no serve slot. A deep `getblocktxn` full
/// block does, and shares the cap with getdata bodies. Writing the
/// announces does not open a slot, so a paused getdata never queues more
/// than `MAX_SERVE_BLOCKS` bodies.
#[test]
fn uncounted_bodies_do_not_open_serve_slots() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let s = serve_session("serve-slot-uncounted", 20);
        let (out_tx, mut out_rx) = s.sess.open_out();
        let mut follow = PeerFollowState::new();
        let tip = *s.hashes.last().unwrap();
        for _ in 0..3 {
            let announce = cmpct_announce_msg(&s.hub, &tip, 2).expect("cmpct announce");
            out_tx.send(announce).unwrap();
        }
        handle_peer_frame(
            getblocktxn_frame(s.hashes[0], vec![0]),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();
        handle_peer_frame(
            getdata_frame(&s.hashes),
            &s.hub,
            &out_tx,
            &mut follow,
            Some(s.sess.as_ref()),
        )
        .await
        .unwrap();

        let (queued, _) = take_queued(&mut out_rx);
        let (slots, uncounted): (Vec<_>, Vec<_>) = queued
            .into_iter()
            .partition(|out| out.out().holds_serve_slot());
        assert_eq!(uncounted.len(), 3, "three announces hold no serve slot");
        assert_eq!(
            slots.len(),
            MAX_SERVE_BLOCKS,
            "the getblocktxn block shares the serve cap with getdata"
        );
        assert!(
            matches!(
                slots.first().map(Queued::out),
                Some(PeerOut::Served(NetworkMessage::Block(_)))
            ),
            "the deep getblocktxn block is the first served body"
        );
        drop(uncounted);
        serve_getdata_tail(&s.hub, &out_tx, &mut follow, Some(s.sess.as_ref()))
            .await
            .unwrap();
        let (more, _) = take_queued(&mut out_rx);
        assert!(
            more.is_empty(),
            "writing an announce must not let a getdata body past the serve cap"
        );
    });
}

/// The wait that resumes a paused getdata ends when the session is told
/// to disconnect, or when its writer is gone.
#[tokio::test]
async fn paused_getdata_ends_on_disconnect_or_dead_writer() {
    use std::time::Duration;
    let s = serve_session("serve-pause-ends", 0);
    let _slots = hold_serve_slots(&s.sess, MAX_SERVE_BLOCKS);
    let (out_tx, _out_rx) = s.sess.open_out();
    let stop = async {
        tokio::task::yield_now().await;
        s.sess.request_disconnect();
    };
    let (room, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(s.sess.wait_serve_room(&out_tx), stop)
    })
    .await
    .expect("disconnect must end a paused getdata");
    assert!(!room);

    let s = serve_session("serve-pause-dead-writer", 0);
    let _slots = hold_serve_slots(&s.sess, MAX_SERVE_BLOCKS);
    let (out_tx, out_rx) = s.sess.open_out();
    let gone = async move {
        tokio::task::yield_now().await;
        drop(out_rx);
    };
    let (room, ()) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(s.sess.wait_serve_room(&out_tx), gone)
    })
    .await
    .expect("a dead writer must end a paused getdata");
    assert!(!room);

    // The dying writer frees the bodies it still held. That is not room.
    for round in 0..16 {
        let s = serve_session(&format!("serve-pause-dead-full-writer-{round}"), 0);
        let (out_tx, out_rx) = s.sess.open_out();
        for _ in 0..MAX_SERVE_BLOCKS {
            out_tx.send(PeerOut::Encoded(Vec::new())).unwrap();
        }
        let gone = async move {
            tokio::task::yield_now().await;
            drop(out_rx);
        };
        let (room, ()) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(s.sess.wait_serve_room(&out_tx), gone)
        })
        .await
        .expect("a dead writer must end a paused getdata");
        assert!(!room, "round {round}: a closed writer has no serve room");
    }
}

/// A node with `blocks` mined and a raw BIP324 client for each `agents`
/// entry, each paired with the node's session for it.
struct PausedServe {
    dir: std::path::PathBuf,
    node: rbitcoin_net::P2PNode,
    hashes: Vec<BlockHash>,
    clients: Vec<(V2PlainSession, Arc<rbitcoin_net::peers::LivePeer>)>,
}

async fn paused_serve(label: &str, blocks: u32, agents: &[&str]) -> PausedServe {
    paused_serve_with(label, blocks, agents, false).await
}

/// [`paused_serve`] with the basic block filter index on when `filters`.
async fn paused_serve_with(
    label: &str,
    blocks: u32,
    agents: &[&str],
    filters: bool,
) -> PausedServe {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-{label}-{n}"));
    std::fs::create_dir_all(&dir).unwrap();
    let query = Query::open_or_create_tiny(dir.join("store")).unwrap();
    query.set_block_filter_index(filters).unwrap();
    let node = rbitcoin_net::P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        query,
        ChainParams::regtest(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(serve)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let hashes = node
        .hub
        .mine(blocks, bitcoin::ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    node.peers.set_mock_now(node.peers.now_secs());
    let mut clients = Vec::new();
    for agent in agents {
        let stream = TcpStream::connect(node.local_addr).await.unwrap();
        let raw = V2PlainSession::outbound_regtest(stream, agent, Duration::from_secs(5))
            .await
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let sess = loop {
            let live = node.peers.live_peers();
            if let Some(p) = live.into_iter().find(|p| p.subver == *agent) {
                break p;
            }
            assert!(std::time::Instant::now() < deadline, "{agent} session");
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        clients.push((raw, sess));
    }
    PausedServe {
        dir,
        node,
        hashes,
        clients,
    }
}

async fn next_peer_msg(raw: &mut V2PlainSession) -> Result<NetworkMessage, NetError> {
    let contents = raw.read_contents().await?;
    let frame = rbitcoin_net::v2::parse_v2_contents(Magic::REGTEST, &contents)?;
    Ok(frame.decode().payload().clone())
}

async fn write_peer_msg(raw: &mut V2PlainSession, msg: NetworkMessage) {
    raw.write_contents(&rbitcoin_net::v2::encode_v2_contents(msg).unwrap())
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mapped_external_endpoint_is_announced_as_ipv4_at_the_public_port() {
    let mut t = paused_serve(
        "external-endpoint",
        0,
        &["/rbitcoin:test(external-endpoint)/"],
    )
    .await;
    let (raw, sess) = &mut t.clients[0];
    let announced = tokio::time::timeout(Duration::from_secs(5), async {
        while !matches!(next_peer_msg(raw).await.unwrap(), NetworkMessage::Ping(_)) {}
        let listen_port = t.node.local_addr.port();
        let public_port = if listen_port == 28333 { 28334 } else { 28333 };
        t.node.peers.set_listen_port(listen_port);
        t.node.peers.set_external_endpoints(
            [
                "42.42.42.42",
                "8.8.8.8",
                &format!("[::ffff:42.42.42.42]:{public_port}"),
            ]
            .map(|address| address.parse().unwrap())
            .to_vec(),
        );
        sess.queue_self_announce_if_due();
        loop {
            if let NetworkMessage::AddrV2(addrs) = next_peer_msg(raw).await.unwrap() {
                return (addrs, public_port);
            }
        }
    })
    .await;
    raw.close();
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    let (addrs, public_port) = announced.expect("read the external addrv2 announcement");
    assert_eq!(addrs.len(), 1);
    assert_eq!(
        addrs[0].addr,
        bitcoin::p2p::address::AddrV2::Ipv4(Ipv4Addr::new(42, 42, 42, 42))
    );
    assert_eq!(addrs[0].port, public_port);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rate_limited_block_request_disconnects_without_waiting_for_another_message() {
    let mut t = paused_serve("rate-request", 1, &["/rbitcoin:test(rate-request)/"]).await;
    let (raw, _) = &mut t.clients[0];
    // The handshake is outside the rate window; send no follow-session replies.
    for _ in 0..rbitcoin_net::peer_dos::DEFAULT_MAX_MSGS_PER_SEC {
        write_peer_msg(raw, NetworkMessage::Ping(7)).await;
    }
    write_peer_msg(raw, getdata_msg(&t.hashes)).await;
    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match next_peer_msg(raw).await {
                Err(_) => return true,
                Ok(NetworkMessage::Block(_)) => return false,
                Ok(_) => {}
            }
        }
    })
    .await;
    raw.close();
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        matches!(closed, Ok(true)),
        "an over-budget block request must close the session, not disappear: {closed:?}"
    );
}

/// A follow session that has asked for one block body it will never get.
async fn serve_with_open_ask(label: &str) -> (PausedServe, BlockHash) {
    let mut t = paused_serve(label, 1, &["/rbitcoin:test(open-ask)/"]).await;
    let tip = t.node.hub.tip_header().unwrap();
    let mut child = bitcoin::block::Header {
        version: bitcoin::block::Version::from_consensus(4),
        prev_blockhash: tip.block_hash(),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0x33; 32]),
        time: tip.time + 1,
        bits: tip.bits,
        nonce: 0,
    };
    rbitcoin_consensus::grind_regtest_pow(&mut child);
    let hash = announce_and_wait_for_ask(&mut t, child).await;
    (t, hash)
}

/// The first client announces `header`; returns once the node asks it for
/// the body.
async fn announce_and_wait_for_ask(
    t: &mut PausedServe,
    header: bitcoin::block::Header,
) -> BlockHash {
    let hash = header.block_hash();
    announce_and_wait_for(t, 0, vec![header], hash).await;
    hash
}

/// Client `client` announces `headers`; returns once the node asks it for
/// `hash`.
async fn announce_and_wait_for(
    t: &mut PausedServe,
    client: usize,
    headers: Vec<bitcoin::block::Header>,
    hash: BlockHash,
) {
    let (raw, _) = &mut t.clients[client];
    write_peer_msg(raw, NetworkMessage::Headers(headers)).await;
    let asked = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkMessage::GetData(inv) = next_peer_msg(raw).await.unwrap() {
                if inv.iter().any(|i| {
                    matches!(i, Inventory::WitnessBlock(h) | Inventory::CompactBlock(h) if *h == hash)
                }) {
                    return;
                }
            }
        }
    })
    .await;
    assert!(asked.is_ok(), "the header announce must ask for its body");
    assert!(t.node.hub.already_have_or_asked_block(&hash));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_follow_session_releases_its_block_asks() {
    let (mut t, hash) = serve_with_open_ask("closed-asks").await;
    t.clients[0].0.close();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while !t.node.peers.live_peers().is_empty() {
        assert!(std::time::Instant::now() < deadline, "closed session");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let still_asked = t.node.hub.already_have_or_asked_block(&hash);
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        !still_asked,
        "a disconnect must release the session's body asks for other peers"
    );
}

/// `disconnectnode`, inbound eviction, and stale-tip replacement abort the
/// session task instead of letting it return.
#[tokio::test]
async fn aborted_follow_session_releases_its_block_asks() {
    let (mut t, hash) = serve_with_open_ask("abort-asks").await;
    assert!(t.node.peers.disconnect_id(t.clients[0].1.id));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while t.node.hub.already_have_or_asked_block(&hash) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let still_asked = t.node.hub.already_have_or_asked_block(&hash);
    t.clients[0].0.close();
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        !still_asked,
        "an aborted session must release its body asks for other peers"
    );
}

/// A body that arrives while its chain is below `-minimumchainwork` is
/// parked in the session, still asked. When that session closes, another
/// peer must be free to fetch the body once the chain meets the floor.
#[tokio::test]
async fn closed_session_releases_a_body_parked_below_minimum_chain_work() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parked-ask");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_header().unwrap();
    let block = rbitcoin_consensus::mine_regtest_paying(
        tip.block_hash(),
        tip.time + 1,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
        Vec::new(),
    );
    let hash = block.block_hash();
    let mut follow = PeerFollowState::new();
    assert!(follow.requested_blocks.claim(&hub, hash));
    hub.set_minimum_chain_work(Some([0xff; 32]));
    let (tx, _rx) = peer_out_channel();
    on_block(&hub, &tx, &mut follow, None, &block)
        .await
        .unwrap();
    assert_eq!(hub.tip_hash(), Some(tip.block_hash()), "parked");
    assert!(
        hub.already_have_or_asked_block(&hash),
        "a parked body stays asked while its session lives"
    );
    drop(follow);
    assert!(
        !hub.already_have_or_asked_block(&hash),
        "a closed session must release the ask of a body it parked"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Unknown BIP324 short id on a live follow session counts as `*other*`
/// and the peer stays up (Core `test_msgtype`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_v2_short_id_counts_other_and_stays() {
    let mut t = paused_serve("bad-short-id", 0, &["/rbitcoin:test(badtype)/"]).await;
    let (raw, sess) = &mut t.clients[0];
    let id = sess.id;
    let first_ping = loop {
        if let NetworkMessage::Ping(n) = next_peer_msg(raw).await.unwrap() {
            break n;
        }
    };
    write_peer_msg(raw, NetworkMessage::Pong(first_ping)).await;
    // short id 99 + compact-size string "d" (Core `msg_unrecognized`).
    let unknown = [99u8, 1, b'd'];
    raw.write_contents(&unknown).await.unwrap();
    raw.write_contents(&unknown).await.unwrap();
    let want = rbitcoin_net::v2::v2_msg_bytes(unknown.len()) * 2;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let other = loop {
        let snap = t.node.peers.snapshot();
        let n = snap
            .iter()
            .find(|p| p.id == id)
            .and_then(|p| p.bytesrecv_per_msg.get("*other*"))
            .copied();
        if n == Some(want) {
            break want;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "unknown short id was not counted as *other*, last={n:?}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    assert_eq!(other, want);
    write_peer_msg(raw, NetworkMessage::Ping(9)).await;
    let pong = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let NetworkMessage::Pong(n) = next_peer_msg(raw).await.unwrap() {
                return n;
            }
        }
    })
    .await
    .expect("session stays up after an unknown short id");
    assert_eq!(pong, 9);
    assert!(t.node.peers.snapshot().iter().any(|p| p.id == id));
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// Wait until the node's row for peer `id` counts exactly `want` bytes of
/// `cmd` in `bytesrecv_per_msg`.
async fn wait_bytes_recv(node: &rbitcoin_net::P2PNode, id: u64, cmd: &str, want: u64) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let got = node
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.id == id)
            .and_then(|p| p.bytesrecv_per_msg.get(cmd).copied());
        if got == Some(want) {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "bytesrecv_per_msg[{cmd}] want {want}, last {got:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A v2 peer's `bytesrecv_per_msg` counts each message as its decrypted
/// contents plus the 20-byte cipher expansion, as Core does, not payload
/// plus the v1 24-byte header. A short id is one byte of type and the long
/// form is `0x00` and a 12-byte command. A ping sent in the long form counts
/// its 13 type bytes: the count follows the contents on the wire, not the
/// short-id table.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_messages_count_contents_plus_cipher_expansion() {
    let mut t = paused_serve("v2-recv-bytes", 0, &["/rbitcoin:test(v2bytes)/"]).await;
    let (raw, sess) = &mut t.clients[0];
    let id = sess.id;
    wait_bytes_recv(&t.node, id, "verack", 13 + 20).await;

    write_peer_msg(raw, NetworkMessage::Ping(7)).await;
    wait_bytes_recv(&t.node, id, "ping", 1 + 8 + 20).await;

    write_peer_msg(raw, NetworkMessage::SendHeaders).await;
    wait_bytes_recv(&t.node, id, "sendheaders", 13 + 20).await;

    let mut long_ping = vec![0u8];
    long_ping.extend_from_slice(b"ping\0\0\0\0\0\0\0\0");
    long_ping.extend_from_slice(&8u64.to_le_bytes());
    raw.write_contents(&long_ping).await.unwrap();
    wait_bytes_recv(&t.node, id, "ping", (1 + 8 + 20) + (13 + 8 + 20)).await;

    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// The `version` a v2 peer sent counts at its own length, so two peers with
/// different user agents read different sizes. The payload is 85 fixed bytes,
/// the length byte of the user agent, and the user agent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn v2_version_counts_the_length_the_peer_sent() {
    let agents = [
        "/rbitcoin:test(v2a)/",
        "/rbitcoin:test(v2-longer-agent-string)/",
    ];
    let t = paused_serve("v2-version-bytes", 0, &agents).await;
    for (agent, (_, sess)) in agents.iter().zip(&t.clients) {
        let want = (13 + 85 + 1 + agent.len() + 20) as u64;
        wait_bytes_recv(&t.node, sess.id, "version", want).await;
    }

    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// Made-up long-form commands all count under one `*other*` key, so a peer
/// cannot grow `bytesrecv_per_msg` with fresh names (Core
/// `ALL_NET_MESSAGE_TYPES`).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unknown_commands_share_one_other_key() {
    let mut t = paused_serve("made-up-cmds", 0, &["/rbitcoin:test(madeup)/"]).await;
    let (raw, sess) = &mut t.clients[0];
    let id = sess.id;
    let first_ping = loop {
        if let NetworkMessage::Ping(n) = next_peer_msg(raw).await.unwrap() {
            break n;
        }
    };
    write_peer_msg(raw, NetworkMessage::Pong(first_ping)).await;
    let names: [&[u8; 12]; 3] = [b"madeup000001", b"madeup000002", b"madeup000003"];
    for name in names {
        // Long encoding: 0, 12-byte command, then a 2-byte payload.
        let mut contents = vec![0u8];
        contents.extend_from_slice(name);
        contents.extend_from_slice(&[7, 7]);
        raw.write_contents(&contents).await.unwrap();
    }
    write_peer_msg(raw, NetworkMessage::Ping(9)).await;
    let pong = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            if let NetworkMessage::Pong(n) = next_peer_msg(raw).await.unwrap() {
                return n;
            }
        }
    })
    .await
    .expect("session stays up after made-up commands");
    assert_eq!(pong, 9);
    let snap = t.node.peers.snapshot();
    let row = snap.iter().find(|p| p.id == id).expect("peer row");
    for name in ["madeup000001", "madeup000002", "madeup000003"] {
        assert!(
            !row.bytesrecv_per_msg.contains_key(name),
            "{name} got its own key: {:?}",
            row.bytesrecv_per_msg.keys().collect::<Vec<_>>()
        );
    }
    assert_eq!(
        row.bytesrecv_per_msg.get("*other*").copied(),
        Some(3 * (13 + 2 + 20))
    );
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

fn getdata_msg(hashes: &[BlockHash]) -> NetworkMessage {
    NetworkMessage::GetData(hashes.iter().map(|h| Inventory::WitnessBlock(*h)).collect())
}

async fn wait_session_read(
    node: &rbitcoin_net::P2PNode,
    sess: &rbitcoin_net::peers::LivePeer,
    cmd: &str,
) {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let read = node
            .peers
            .snapshot()
            .into_iter()
            .find(|p| p.id == sess.id)
            .is_some_and(|p| p.bytesrecv_per_msg.contains_key(cmd));
        if read {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "session never read {cmd}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A mock-time jump runs the session heartbeat without waiting out
/// [`SESSION_HEARTBEAT`]. The runtime clock is paused after the first ping,
/// so that 50 ms sleep cannot complete on its own.
#[tokio::test(flavor = "current_thread")]
async fn mock_time_wakes_the_session_heartbeat() {
    let mut t = paused_serve("mock-wakes-heartbeat", 0, &["/rbitcoin:test(wake)/"]).await;
    let (raw, sess) = &mut t.clients[0];
    loop {
        if let NetworkMessage::Ping(_) = next_peer_msg(raw).await.unwrap() {
            break;
        }
    }
    let now = t.node.peers.now_secs();
    tokio::time::pause();
    t.node.peers.set_mock_now(now + 20 * 60 + 61);
    let started = std::time::Instant::now();
    let woke = loop {
        if sess.stop.load(Ordering::SeqCst) {
            break true;
        }
        if started.elapsed() >= Duration::from_millis(30) {
            break false;
        }
        tokio::task::yield_now().await;
    };
    tokio::time::resume();
    assert!(woke, "mock time did not wake the session heartbeat");
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// Core's ping timeout runs while `ProcessGetData` is paused on
/// `fPauseSend`. A session paused on a getdata tail, or on its send budget,
/// still runs the heartbeat: a peer that never reads hits the ping timeout
/// and is disconnected. It is not held with no timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_session_still_times_out_a_silent_peer() {
    let mut t = paused_serve(
        "serve-pause-ping-timeout",
        20,
        &["/rbitcoin:test(slots)/", "/rbitcoin:test(budget)/"],
    )
    .await;
    let (slots_raw, slots) = &mut t.clients[0];
    let _slots = hold_serve_slots(slots, MAX_SERVE_BLOCKS);
    write_peer_msg(slots_raw, getdata_msg(&t.hashes)).await;
    wait_session_read(&t.node, slots, "getdata").await;
    let (_, budget) = &t.clients[1];
    let _budget = hold_send_bytes(budget, 2 * rbitcoin_net::peers::PEER_SEND_BUDGET);
    wait_heartbeat_lap(&t.node.peers, "paused session did not heartbeat").await;

    let now = t.node.peers.now_secs();
    t.node.peers.set_mock_now(now + 20 * 60 + 61);
    for (raw, sess) in &mut t.clients {
        let closed = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                match next_peer_msg(raw).await {
                    Err(_) => return,
                    Ok(NetworkMessage::Block(_)) => {
                        panic!("{} was served while paused", sess.subver)
                    }
                    Ok(_) => {}
                }
            }
        })
        .await;
        assert!(
            closed.is_ok(),
            "{} was not dropped by the ping timeout",
            sess.subver
        );
    }
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

const PING_TIMEOUT_SECS: u64 = 20 * 60;
const POST_BLOCK_PONG_GRACE_SECS: u64 = 60;

/// The next `on_heartbeat` is the wait. The caller asserts the peer row.
async fn wait_heartbeat_lap(peers: &rbitcoin_net::peers::PeerHub, why: &str) {
    let laps = peers.heartbeat_laps();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while peers.heartbeat_laps() <= laps {
        assert!(std::time::Instant::now() < deadline, "{why}");
        tokio::task::yield_now().await;
    }
}

/// `wait_send_budget` has armed `send_resume` and is still over budget.
async fn wait_send_parked(peer: &rbitcoin_net::peers::LivePeer, why: &str) {
    let parked = peer.send_budget_parks();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while peer.send_budget_parks() == parked {
        assert!(std::time::Instant::now() < deadline, "{why}");
        tokio::task::yield_now().await;
    }
}

/// Proves the session is still up: one heartbeat has run, then it answers a ping.
async fn assert_session_answers(
    peers: &rbitcoin_net::peers::PeerHub,
    raw: &mut V2PlainSession,
    nonce: u64,
    why: &str,
) {
    wait_heartbeat_lap(peers, why).await;
    write_peer_msg(raw, NetworkMessage::Ping(nonce)).await;
    let pong = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match next_peer_msg(raw).await {
                Ok(NetworkMessage::Pong(n)) if n == nonce => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await;
    assert!(matches!(pong, Ok(true)), "{why}: {pong:?}");
}

/// The session is listed before it sends its handshake ping. A clock jump
/// that lands first stamps that ping at the jumped time, so wait for it.
async fn wait_ping_outstanding(sess: &rbitcoin_net::peers::LivePeer) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while sess.ping_nonce_sent.load(Ordering::Relaxed) == 0 {
        assert!(
            std::time::Instant::now() < deadline,
            "the session never sent its ping"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// True once a heartbeat ran on `sess` and passed both timeouts: an
/// RPC-queued ping goes out only when neither the block download timeout
/// nor the ping timeout fired. That ping restarts the ping clock.
async fn heartbeat_keeps(sess: &rbitcoin_net::peers::LivePeer) -> bool {
    let before = sess.ping_nonce_sent.load(Ordering::Relaxed);
    sess.queue_ping();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if sess.stop.load(Ordering::SeqCst) {
            return false;
        }
        if sess.ping_nonce_sent.load(Ordering::Relaxed) != before {
            return true;
        }
        assert!(std::time::Instant::now() < deadline, "no heartbeat ran");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn session_closes(raw: &mut V2PlainSession) -> bool {
    tokio::time::timeout(Duration::from_secs(10), async {
        while next_peer_msg(raw).await.is_ok() {}
    })
    .await
    .is_ok()
}

/// `client` sends `block`; returns once it connects.
async fn deliver(t: &mut PausedServe, client: usize, block: bitcoin::Block) {
    let hash = block.block_hash();
    let (raw, _) = &mut t.clients[client];
    write_peer_msg(raw, NetworkMessage::Block(block)).await;
    // The tip-accept lane is one per process, so this connect queues behind
    // other tests' jobs (a 10k-header invalidate holds it for seconds on CI).
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while t.node.hub.tip_hash() != Some(hash) {
        assert!(
            std::time::Instant::now() < deadline,
            "served block connects"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// `count` empty blocks on the node's tip.
fn chain_on_tip(t: &PausedServe, count: u32) -> Vec<bitcoin::Block> {
    let tip = t.node.hub.tip_header().unwrap();
    let height = t.node.hub.tip_height().unwrap();
    let mut prev = tip.block_hash();
    (1..=count)
        .map(|i| {
            let b = rbitcoin_consensus::mine_empty_regtest(prev, tip.time + i, height + i);
            prev = b.block_hash();
            b
        })
        .collect()
}

/// bitcoin/bitcoin#36080: a peer answers our block requests before our
/// ping, so on a slow link it can miss the ping timeout without being at
/// fault. The peer has two blocks in flight and serves one; the oldest
/// leaving restarts the block download window, so with the other still in
/// flight it is up past twenty minutes without answering the ping.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_timeout_waits_while_a_block_is_in_flight() {
    let mut t = paused_serve("ping-inflight", 1, &["/rbitcoin:test(slow)/"]).await;
    wait_ping_outstanding(&t.clients[0].1).await;
    let start = t.node.peers.now_secs();
    t.node.peers.set_mock_now(start + BLOCK_INTERVAL_SECS - 100);
    let blocks = chain_on_tip(&t, 2);
    let last = blocks[1].block_hash();
    announce_and_wait_for(&mut t, 0, blocks.iter().map(|b| b.header).collect(), last).await;
    t.node.peers.set_mock_now(start + PING_TIMEOUT_SECS - 200);
    deliver(&mut t, 0, blocks[0].clone()).await;
    t.node.peers.set_mock_now(start + PING_TIMEOUT_SECS + 1);
    let peers = Arc::clone(&t.node.peers);
    let (raw, _) = &mut t.clients[0];
    assert_session_answers(
        &peers,
        raw,
        7,
        "a peer with a block in flight hit the ping timeout",
    )
    .await;
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// Core does not restart the twenty minutes once the peer's blocks are in.
/// The peer gets one minute after the last block it delivered to answer
/// the ping, and is disconnected after that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_timeout_applies_a_minute_after_the_last_block() {
    let mut t = paused_serve("ping-grace", 1, &["/rbitcoin:test(grace)/"]).await;
    wait_ping_outstanding(&t.clients[0].1).await;
    let start = t.node.peers.now_secs();
    let asked_at = start + PING_TIMEOUT_SECS - BLOCK_INTERVAL_SECS / 2;
    t.node.peers.set_mock_now(asked_at);
    let block = chain_on_tip(&t, 1).remove(0);
    announce_and_wait_for_ask(&mut t, block.header).await;
    t.node.peers.set_mock_now(start + PING_TIMEOUT_SECS + 1);
    let peers = Arc::clone(&t.node.peers);
    let (raw, _) = &mut t.clients[0];
    assert_session_answers(
        &peers,
        raw,
        7,
        "a peer with a block in flight hit the ping timeout",
    )
    .await;

    deliver(&mut t, 0, block).await;
    // The tip is published on the accept lane before this session records
    // `last_block`. A mock jump in that gap would start the grace minute at
    // the jumped clock.
    let sess = Arc::clone(&t.clients[0].1);
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let delivered = loop {
        let now = t.node.peers.now_secs();
        let stamped = sess.last_block.load(Ordering::Relaxed);
        if stamped == now && stamped != 0 {
            break stamped;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the delivered block was not stamped on the peer"
        );
        tokio::task::yield_now().await;
    };
    t.node
        .peers
        .set_mock_now(delivered + POST_BLOCK_PONG_GRACE_SECS);
    let (raw, _) = &mut t.clients[0];
    assert_session_answers(
        &peers,
        raw,
        8,
        "the peer lost its minute to answer the ping",
    )
    .await;

    t.node
        .peers
        .set_mock_now(delivered + POST_BLOCK_PONG_GRACE_SECS + 1);
    let closed = session_closes(raw).await;
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        closed,
        "the unanswered ping must time out after the grace minute"
    );
}

/// A witness-block `getdata`, then a ping, on a live session. The block
/// must be on the wire before that ping's pong. Core's `send_and_ping`
/// returns on the pong and treats the earlier reply as already received.
#[tokio::test(flavor = "current_thread")]
async fn getdata_reply_precedes_pong_for_a_later_ping() {
    let mut t = paused_serve(
        "reply-before-pong",
        1,
        &["/rbitcoin:test(reply-before-pong)/"],
    )
    .await;
    let hash = *t.hashes.last().expect("mined block");
    let nonce = 0x1483_u64;
    let (raw, _) = &mut t.clients[0];
    write_peer_msg(raw, getdata_msg(&[hash])).await;
    write_peer_msg(raw, NetworkMessage::Ping(nonce)).await;
    let mut saw_block = false;
    let mut saw_pong = false;
    let mut order = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while tokio::time::Instant::now() < deadline {
        let msg = match tokio::time::timeout(Duration::from_secs(3), next_peer_msg(raw)).await {
            Ok(Ok(msg)) => msg,
            Ok(Err(e)) => {
                order.push(format!("read-error:{e}"));
                break;
            }
            Err(_) => {
                order.push("idle".to_string());
                break;
            }
        };
        match msg {
            NetworkMessage::Block(block) if block.block_hash() == hash => {
                saw_block = true;
                order.push("block".to_string());
            }
            NetworkMessage::Pong(n) if n == nonce => {
                saw_pong = true;
                order.push("pong".to_string());
                break;
            }
            NetworkMessage::Ping(n) => order.push(format!("ping:{n}")),
            NetworkMessage::Headers(h) => order.push(format!("headers:{}", h.len())),
            NetworkMessage::GetHeaders(_) => order.push("getheaders".to_string()),
            NetworkMessage::Inv(v) => order.push(format!("inv:{}", v.len())),
            NetworkMessage::SendCmpct(_) => order.push("sendcmpct".to_string()),
            NetworkMessage::FeeFilter(_) => order.push("feefilter".to_string()),
            NetworkMessage::NotFound(_) => order.push("notfound".to_string()),
            other => order.push(format!("{other:?}").chars().take(40).collect()),
        }
    }
    raw.close();
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        saw_block && saw_pong,
        "the getdata block must arrive before the pong for the later ping; order={order:?}"
    );
}

/// Sends `msg`, then a ping; returns once the pong shows `msg` was read.
async fn send_and_sync(raw: &mut V2PlainSession, msg: NetworkMessage, nonce: u64) {
    write_peer_msg(raw, msg).await;
    write_peer_msg(raw, NetworkMessage::Ping(nonce)).await;
    let pong = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match next_peer_msg(raw).await {
                Ok(NetworkMessage::Pong(n)) if n == nonce => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await;
    assert!(
        matches!(pong, Ok(true)),
        "session read the message: {pong:?}"
    );
}

/// Core starts the grace minute at the last **new** block. A peer that
/// re-sends the tip it already gave us, as a compact block or a full one,
/// with nothing in flight, does not hold off the twenty-minute timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resent_tip_does_not_hold_off_the_ping_timeout() {
    use bitcoin::bip152::HeaderAndShortIds;

    let mut t = paused_serve(
        "ping-resent-tip",
        1,
        &[
            "/rbitcoin:test(resend-cmpct)/",
            "/rbitcoin:test(resend-block)/",
        ],
    )
    .await;
    for (_, sess) in &t.clients {
        wait_ping_outstanding(sess).await;
    }
    let tip = t.node.hub.block_at_height(1).unwrap().unwrap();
    let start = t.node.peers.now_secs();
    t.node
        .peers
        .set_mock_now(start + PING_TIMEOUT_SECS - POST_BLOCK_PONG_GRACE_SECS / 2);
    let compact = NetworkMessage::CmpctBlock(CmpctBlock {
        compact_block: HeaderAndShortIds::from_block(&tip, 0xbeef, 2, &[]).unwrap(),
    });
    send_and_sync(&mut t.clients[0].0, compact, 7).await;
    send_and_sync(&mut t.clients[1].0, NetworkMessage::Block(tip), 8).await;

    t.node.peers.set_mock_now(start + PING_TIMEOUT_SECS + 1);
    let mut held = Vec::new();
    for (raw, sess) in &mut t.clients {
        if !session_closes(raw).await {
            held.push(sess.subver.clone());
        }
    }
    assert!(
        held.is_empty(),
        "re-sending the tip held off the ping timeout: {held:?}"
    );
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// With nothing in flight the ping timeout is the twenty minutes alone; the
/// grace minute only follows a delivered block.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ping_timeout_without_blocks_in_flight_is_twenty_minutes() {
    let mut t = paused_serve("ping-idle", 1, &["/rbitcoin:test(idle)/"]).await;
    wait_ping_outstanding(&t.clients[0].1).await;
    let now = t.node.peers.now_secs();
    t.node.peers.set_mock_now(now + PING_TIMEOUT_SECS + 1);
    let (raw, _) = &mut t.clients[0];
    let closed = session_closes(raw).await;
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
    assert!(
        closed,
        "an idle peer that never answers the ping must time out"
    );
}

const BLOCK_INTERVAL_SECS: u64 = 600;

/// Waits until the session for `sess` has ended and released what it held.
async fn wait_unregistered(t: &PausedServe, sess: &rbitcoin_net::peers::LivePeer) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while t.node.peers.live_peers().iter().any(|p| p.id == sess.id) {
        assert!(std::time::Instant::now() < deadline, "session never ended");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Client `client` answers the node's outstanding ping.
async fn answer_ping(t: &mut PausedServe, client: usize) {
    let (raw, sess) = &mut t.clients[client];
    let nonce = sess.ping_nonce_sent.load(Ordering::Relaxed);
    assert_ne!(nonce, 0, "no ping to answer");
    write_peer_msg(raw, NetworkMessage::Pong(nonce)).await;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while sess.ping_nonce_sent.load(Ordering::Relaxed) == nonce {
        assert!(std::time::Instant::now() < deadline, "pong not read");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// `server` announces `block` and serves it; returns once it connects.
async fn serve_from(t: &mut PausedServe, server: usize, block: bitcoin::Block) {
    let hash = block.block_hash();
    announce_and_wait_for(t, server, vec![block.header], hash).await;
    deliver(t, server, block).await;
}

/// Core's block download timeout: a peer that leaves a block in flight for
/// one block interval, plus half of one per other peer we are downloading
/// from, is disconnected. Its asks are released, so a third peer that
/// announces the same bodies is asked for them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_download_timeout_hands_the_body_to_another_peer() {
    let mut t = paused_serve(
        "block-timeout",
        1,
        &[
            "/rbitcoin:test(holder-a)/",
            "/rbitcoin:test(holder-b)/",
            "/rbitcoin:test(late-holder)/",
            "/rbitcoin:test(server)/",
        ],
    )
    .await;
    for (_, sess) in &t.clients {
        wait_ping_outstanding(sess).await;
    }
    let tip = t.node.hub.tip_header().unwrap();
    let height = t.node.hub.tip_height().unwrap();
    let x = rbitcoin_consensus::mine_empty_regtest(tip.block_hash(), tip.time + 1, height + 1);
    let y = rbitcoin_consensus::mine_empty_regtest(x.block_hash(), tip.time + 2, height + 2);
    announce_and_wait_for(&mut t, 0, vec![x.header], x.block_hash()).await;
    announce_and_wait_for(&mut t, 1, vec![x.header, y.header], y.block_hash()).await;
    let now = t.node.peers.now_secs();
    let two_peers = BLOCK_INTERVAL_SECS * 3 / 2;

    t.node.peers.set_mock_now(now + BLOCK_INTERVAL_SECS + 1);
    for (_, sess) in &t.clients[..2] {
        assert!(
            heartbeat_keeps(sess).await,
            "with two peers downloading the timeout is 1.5 intervals"
        );
    }
    t.node.peers.set_mock_now(now + two_peers);
    for (_, sess) in &t.clients[..2] {
        assert!(
            heartbeat_keeps(sess).await,
            "the timeout is strictly after the window"
        );
    }
    t.node.peers.set_mock_now(now + two_peers + 1);
    for i in 0..2 {
        let (raw, sess) = &mut t.clients[i];
        let sess = Arc::clone(sess);
        assert!(
            session_closes(raw).await,
            "{} kept its blocks past the timeout",
            sess.subver
        );
        wait_unregistered(&t, &sess).await;
    }

    // The dropped holders no longer count: one peer downloading is one interval.
    answer_ping(&mut t, 3).await;
    announce_and_wait_for(&mut t, 2, vec![x.header], x.block_hash()).await;
    let asked = t.node.peers.now_secs();
    t.node.peers.set_mock_now(asked + BLOCK_INTERVAL_SECS + 1);
    let (raw, late) = &mut t.clients[2];
    let late = Arc::clone(late);
    assert!(
        session_closes(raw).await,
        "a lone holder outlived one interval"
    );
    wait_unregistered(&t, &late).await;

    serve_from(&mut t, 3, x).await;
    serve_from(&mut t, 3, y).await;
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// Core appends a second getdata behind the paused one and serves both in
/// order. While the first is paused the session keeps pinging, and once
/// the writer has room the tail is served before the next getdata.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_getdata_tail_is_served_before_the_next_getdata() {
    let mut t = paused_serve("serve-pause-order", 22, &["/rbitcoin:test(order)/"]).await;
    let (raw, sess) = &mut t.clients[0];
    let first_ping = loop {
        if let NetworkMessage::Ping(n) = next_peer_msg(raw).await.unwrap() {
            break n;
        }
    };
    write_peer_msg(raw, NetworkMessage::Pong(first_ping)).await;
    wait_session_read(&t.node, sess, "pong").await;

    let slots = hold_serve_slots(sess, MAX_SERVE_BLOCKS);
    let (a, b) = t.hashes.split_at(20);
    write_peer_msg(raw, getdata_msg(a)).await;
    write_peer_msg(raw, getdata_msg(b)).await;
    wait_session_read(&t.node, sess, "getdata").await;

    let now = t.node.peers.now_secs();
    t.node.peers.set_mock_now(now + 121);
    let pinged = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match next_peer_msg(raw).await.unwrap() {
                NetworkMessage::Ping(_) => return,
                NetworkMessage::Block(_) => {
                    panic!("a block was served while the getdata was paused")
                }
                _ => {}
            }
        }
    })
    .await;
    assert!(
        pinged.is_ok(),
        "the heartbeat pings while the getdata is paused"
    );

    drop(slots);
    let served = tokio::time::timeout(Duration::from_secs(10), async {
        let mut got = Vec::new();
        while got.len() < t.hashes.len() {
            if let NetworkMessage::Block(b) = next_peer_msg(raw).await.unwrap() {
                got.push(b.block_hash());
            }
        }
        got
    })
    .await
    .expect("the paused tail and the next getdata are served");
    assert_eq!(served, t.hashes, "tail first, then the next getdata");
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// A `getcfilters` whose replies pass the send budget is not cut short: the
/// session parks the rest, reads nothing meanwhile, and sends every filter
/// in order once the writer drains.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn getcfilters_past_the_send_budget_is_answered_in_full() {
    let mut t = paused_serve_with("serve-cfilters", 22, &["/rbitcoin:test(cf)/"], true).await;
    let (raw, sess) = &mut t.clients[0];
    let held = hold_send_bytes(sess, rbitcoin_net::peers::PEER_SEND_BUDGET);
    let req = bitcoin::p2p::message_filter::GetCFilters {
        filter_type: 0,
        start_height: 0,
        stop_hash: *t.hashes.last().unwrap(),
    };
    write_peer_msg(raw, NetworkMessage::GetCFilters(req)).await;
    let first = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let NetworkMessage::CFilter(f) = next_peer_msg(raw).await.unwrap() {
                return f.block_hash;
            }
        }
    })
    .await
    .expect("the filter that crosses the budget is sent");
    drop(held);
    let got = tokio::time::timeout(Duration::from_secs(10), async {
        let mut got = vec![first];
        while got.len() < t.hashes.len() + 1 {
            if let NetworkMessage::CFilter(f) = next_peer_msg(raw).await.unwrap() {
                got.push(f.block_hash);
            }
        }
        got
    })
    .await
    .expect("every filter of the range is sent");
    assert_eq!(&got[1..], &t.hashes[..], "in height order after genesis");
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

#[tokio::test(flavor = "current_thread")]
async fn handshake_timeout_after_silence() {
    use std::net::SocketAddr;
    use tokio::net::{TcpListener, TcpStream};

    assert_eq!(HANDSHAKE_TIMEOUT, Duration::from_secs(60));
    // The bound is `tokio::time::timeout`. Pause so the clock, not a sleep, is the wait.
    tokio::time::pause();

    async fn bind_pair() -> (TcpStream, TcpStream, SocketAddr, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        (client, server, addr, peer)
    }

    async fn expect_handshake_timeout<T>(
        fut: impl std::future::Future<Output = Result<T, NetError>>,
        limit: Duration,
        still: &str,
        done: &str,
    ) {
        tokio::pin!(fut);
        std::future::poll_fn(|cx| match fut.as_mut().poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Ready(()),
            std::task::Poll::Ready(_) => panic!("{still}"),
        })
        .await;
        // Paused clock. The handshake bound was armed by the poll above.
        tokio::time::sleep(limit).await;
        match std::future::poll_fn(|cx| fut.as_mut().poll(cx)).await {
            Err(NetError::Timeout) => {}
            Err(e) => panic!("{done}: expected Timeout, got {e}"),
            Ok(_) => panic!("{done}"),
        }
    }

    let limit = Duration::from_millis(50);
    let (client, server, addr, peer) = bind_pair().await;
    let _silent_in = client;
    expect_handshake_timeout(
        connect_and_handshake_timed(
            limit,
            server,
            Magic::REGTEST,
            addr,
            peer,
            0,
            true,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        ),
        limit,
        "must still wait during inbound handshake",
        "silence past the bound must end inbound handshake",
    )
    .await;

    let (client, server, addr, _) = bind_pair().await;
    let _silent_out = server;
    expect_handshake_timeout(
        connect_and_handshake_timed(
            limit,
            client,
            Magic::REGTEST,
            addr,
            addr,
            0,
            false,
            "/rbitcoin:test/",
            HandshakePolicy::plain(),
        ),
        limit,
        "must still wait during outbound handshake",
        "silence past the bound must end outbound handshake",
    )
    .await;

    let (client, server, addr, _) = bind_pair().await;
    let _silent_feeler = server;
    let feeler_peers = crate::peers::PeerHub::new();
    expect_handshake_timeout(
        run_feeler_timed(
            limit,
            client,
            Magic::REGTEST,
            addr,
            addr,
            0,
            "/rbitcoin:test/",
            feeler_peers.as_ref(),
        ),
        limit,
        "must still wait during feeler",
        "silence past the bound must end feeler",
    )
    .await;
    tokio::time::resume();

    let (client, server, _, _) = bind_pair().await;
    let _silent_plain = server;
    match V2PlainSession::outbound_regtest(client, "/rbitcoin:test/", Duration::from_millis(50))
        .await
    {
        Err(NetError::Timeout) => {}
        Err(e) => panic!("expected Timeout, got {e}"),
        Ok(_) => panic!("plain session succeeded on a silent peer"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn read_peer_version_v2_drops_non_handshake_by_command() {
    use bitcoin::p2p::message::CommandString;
    use rbitcoin_net::v2::{open_v2, read_v2_frame, write_v2_msg};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let bind_addr = listener.local_addr().expect("addr");
    let peers = rbitcoin_net::peers::PeerHub::new();

    let client_early = TcpStream::connect(bind_addr).await.expect("connect");
    let (server_early, their_early) = listener.accept().await.expect("accept");
    let peers_early = Arc::clone(&peers);
    let server_task = tokio::spawn(async move {
        inbound_connect_and_handshake(
            server_early,
            Magic::REGTEST,
            bind_addr,
            their_early,
            0,
            "/rbitcoin:test/",
            &peers_early,
            bind_addr,
        )
        .await
    });
    let (mut r_early, mut w_early, _, _) = open_v2(client_early, Magic::REGTEST, false)
        .await
        .expect("client open_v2");
    write_v2_msg(&mut w_early, NetworkMessage::Verack)
        .await
        .expect("write early verack");
    assert!(read_v2_frame(&mut r_early, Magic::REGTEST).await.is_err());
    match server_task.await.expect("server join") {
        Err(NetError::Protocol("verack before version")) => {}
        Ok(_) => panic!("verack before version must fail"),
        Err(e) => panic!("expected verack before version, got {e}"),
    }

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let version = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 42,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let mut bogus_block = vec![0u8; 80];
    bogus_block.push(0xff);
    bogus_block.extend_from_slice(&u64::MAX.to_le_bytes());
    let mut bogus_tx = vec![2, 0, 0, 0, 0xff];
    bogus_tx.extend_from_slice(&u64::MAX.to_le_bytes());

    let client = TcpStream::connect(bind_addr).await.expect("connect");
    let (server, their) = listener.accept().await.expect("accept");
    let peers_ok = Arc::clone(&peers);
    let ok_task = tokio::spawn(async move {
        inbound_connect_and_handshake(
            server,
            Magic::REGTEST,
            bind_addr,
            their,
            0,
            "/rbitcoin:test/",
            &peers_ok,
            bind_addr,
        )
        .await
    });
    let (mut r, mut w, _, _) = open_v2(client, Magic::REGTEST, false)
        .await
        .expect("client open_v2");
    for (cmd, payload) in [("block", bogus_block), ("tx", bogus_tx), ("ping", vec![1])] {
        write_v2_msg(
            &mut w,
            NetworkMessage::Unknown {
                command: CommandString::try_from_static(cmd).expect(cmd),
                payload,
            },
        )
        .await
        .expect("write pre-version frame");
    }
    write_v2_msg(&mut w, NetworkMessage::Version(version))
        .await
        .expect("write version");
    loop {
        let frame = read_v2_frame(&mut r, Magic::REGTEST)
            .await
            .expect("server handshake frame");
        if framed_cmd(&frame) == "verack" {
            break;
        }
    }
    write_v2_msg(&mut w, NetworkMessage::Verack)
        .await
        .expect("write verack");
    let (got_version, _, _, _, _) = ok_task
        .await
        .expect("server join")
        .expect("handshake must succeed");
    assert_eq!(got_version.nonce, 42);
}

#[tokio::test(flavor = "current_thread")]
async fn run_feeler_inner_drops_non_version_by_command() {
    use bitcoin::p2p::message::CommandString;
    use rbitcoin_net::v2::{open_v2, read_v2_frame, write_v2_msg};

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let version = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 42,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let mut bogus_block = vec![0u8; 80];
    bogus_block.push(0xff);
    bogus_block.extend_from_slice(&u64::MAX.to_le_bytes());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let bind_addr = listener.local_addr().expect("addr");
    let client = TcpStream::connect(bind_addr).await.expect("connect");
    let (server, _) = listener.accept().await.expect("accept");

    let peer_task = tokio::spawn(async move {
        let (mut r, mut w, _, _) = open_v2(server, Magic::REGTEST, true)
            .await
            .expect("server open_v2");
        let frame = read_v2_frame(&mut r, Magic::REGTEST)
            .await
            .expect("feeler version");
        assert_eq!(framed_cmd(&frame), "version");
        write_v2_msg(
            &mut w,
            NetworkMessage::Unknown {
                command: CommandString::try_from_static("block").expect("block"),
                payload: bogus_block,
            },
        )
        .await
        .expect("write oversize-count block");
        write_v2_msg(&mut w, NetworkMessage::Version(version))
            .await
            .expect("write version");
        (r, w)
    });

    let peers = rbitcoin_net::peers::PeerHub::new();
    let res = run_feeler_inner(
        client,
        Magic::REGTEST,
        bind_addr,
        bind_addr,
        0,
        "/rbitcoin:test/",
        peers.as_ref(),
    )
    .await;
    let _keep = peer_task.await.expect("peer task");
    res.expect("feeler must ignore non-version frames by command");
}

/// GetData witness bytes must leave the writer before a queued header flood.
#[test]
fn outbound_write_batch_sends_getdata_before_headers() {
    let (tx, mut rx) = peer_out_channel();
    tx.send(PeerOut::Msg(NetworkMessage::Headers(vec![])))
        .unwrap();
    tx.send(PeerOut::Encoded(vec![2, 0xaa])).unwrap();
    tx.send(PeerOut::Msg(NetworkMessage::Ping(7))).unwrap();
    tx.send(PeerOut::Msg(NetworkMessage::Headers(vec![])))
        .unwrap();
    let first = rx.try_recv().expect("first");
    let batch = take_outbound_write_batch(first, &mut rx);
    assert!(
        matches!(batch[0].out(), PeerOut::Msg(NetworkMessage::Ping(7))),
        "ping before serve and announces"
    );
    assert!(
        matches!(batch[1].out(), PeerOut::Encoded(_)),
        "getdata body before headers"
    );
    assert_eq!(batch.len(), 4);
}

// `tcp_has_peer_fin` needs POLLRDHUP; off Linux it always reports no FIN.
#[cfg(target_os = "linux")]
#[test]
fn snapshot_omits_peer_after_tcp_fin() {
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use rbitcoin_net::peers::{PeerConnType, PeerHub};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
    use std::time::Duration;

    let hub = PeerHub::new();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:0.1.0(testnode0)/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = hub.register(addr, addr, &ver, true, PeerConnType::Inbound);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let la = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(la).unwrap();
    let (server, _) = listener.accept().unwrap();
    peer.attach_tcp_shutdown(server.try_clone().unwrap());
    assert_eq!(hub.snapshot().len(), 1);
    {
        use std::io::Write;
        client.write_all(&[0xab]).unwrap();
    }
    client.shutdown(Shutdown::Both).unwrap();
    let mut saw = false;
    for _ in 0..50 {
        if peer.tcp_fin() {
            saw = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(saw, "cloned fd must see FIN even with unread bytes");
    assert!(
        hub.snapshot().is_empty(),
        "getpeerinfo must omit a FIN'd session (mempool_reorg disconnect_nodes 5s)"
    );
    drop(client);
    drop(server);
}

/// Burst tip advances (> tip broadcast capacity) must still reach a follow peer
/// without waiting for the 120s headers poll (`sync_blocks` is 60s).
#[tokio::test(flavor = "current_thread")]
async fn tip_burst_past_broadcast_capacity_still_syncs_peer() {
    use bitcoin::ScriptBuf;
    use rbitcoin_net::P2PNode;
    use std::time::Duration;

    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-tip-burst-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create_tiny(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create_tiny(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let mut na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(burst-a)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(burst-b)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();

    na.follow_from(nb.local_addr).await.unwrap();
    // Each side must have the reply to its initial getheaders while both tips
    // are genesis. A reply built after the burst would sync B, and a broken
    // lagged announce would still pass.
    let read_headers = |n: &P2PNode| {
        n.peers
            .snapshot()
            .iter()
            .any(|p| p.bytesrecv_per_msg.contains_key("headers"))
    };
    let mut linked = false;
    for _ in 0..500 {
        if na.follow_live_count() >= 1 && read_headers(&na) && read_headers(&nb) {
            assert_eq!(na.tip_height().unwrap_or(0), 0, "miner tip before burst");
            assert_eq!(nb.tip_height().unwrap_or(0), 0, "peer tip before burst");
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(linked, "follow session must be live before tip burst");

    // Capacity is 64. The runtime has one thread, so the sync generate below
    // cannot be interleaved with the session tasks: the ring overflows and the
    // announce task sees Lagged instead of every TipEvent. On a multi-thread
    // runtime the sessions raced the miner and B was flooded with per-block
    // traffic it could not decode in time under load ("decode queue full").
    const BURST: u32 = 80;
    na.hub
        .mine(BURST, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let want = na.tip_height().unwrap();
    assert!(want >= BURST, "miner tip {want}");

    let mut peer_tip = nb.tip_height().unwrap_or(0);
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while peer_tip < want && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
        peer_tip = nb.tip_height().unwrap_or(0);
    }
    na.shutdown().await;
    nb.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        peer_tip, want,
        "peer must catch tip after Lagged burst within 45s"
    );
}
/// Core `disconnect_nodes` waits ≤5s for the far side's `getpeerinfo` to drop us.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_clears_far_side_getpeerinfo_within_5s() {
    use rbitcoin_net::P2PNode;
    use std::time::Duration;

    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-disc-far-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create_tiny(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create_tiny(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let mut na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode0)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode1)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();

    na.follow_from(nb.local_addr).await.unwrap();
    let mut linked = false;
    for _ in 0..100 {
        let a_sees = na
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode1"));
        let b_sees = nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"));
        if a_sees && b_sees {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(linked, "both sides must list each other before disconnect");

    let peer_id = na
        .peers
        .snapshot()
        .into_iter()
        .find(|p| p.subver.contains("testnode1"))
        .map(|p| p.id)
        .expect("outbound peer id");
    assert!(na.peers.disconnect_id(peer_id));
    assert!(
        na.peers.snapshot().is_empty(),
        "local getpeerinfo clears immediately"
    );

    let mut far_clear = false;
    for _ in 0..100 {
        if !nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"))
        {
            far_clear = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        far_clear,
        "far side getpeerinfo must drop us within 5s (Core disconnect_nodes)"
    );

    na.shutdown().await;
    nb.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

/// `mempool_reorg` disconnect_nodes after generate+sync — far side must still
/// clear within 5s even if the session was just busy accepting tip blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn disconnect_after_tip_sync_clears_far_side_within_5s() {
    use bitcoin::ScriptBuf;
    use rbitcoin_net::P2PNode;
    use std::time::Duration;

    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rbitcoin-disc-tip-{n}"));
    std::fs::create_dir_all(dir.join("a")).unwrap();
    std::fs::create_dir_all(dir.join("b")).unwrap();
    let qa = Query::open_or_create_tiny(dir.join("a/store")).unwrap();
    let qb = Query::open_or_create_tiny(dir.join("b/store")).unwrap();
    let params = ChainParams::regtest();
    let mut na = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qa,
        params.clone(),
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode0)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    let nb = P2PNode::start_with_agent(
        "127.0.0.1:0".parse().unwrap(),
        qb,
        params,
        Milestone::NONE,
        "/rbitcoin:0.1.0(testnode1)/".into(),
        rbitcoin_net::DEFAULT_MAX_INBOUND,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();

    na.follow_from(nb.local_addr).await.unwrap();
    let mut linked = false;
    for _ in 0..100 {
        let a_sees = na
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode1"));
        let b_sees = nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"));
        if a_sees && b_sees {
            linked = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(linked, "both sides must list each other before generate");

    const BURST: u32 = 3;
    na.hub
        .mine(BURST, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let want = na.tip_height().unwrap();
    // The tip-accept lane is one per process, so the far side's connect
    // queues behind other tests' jobs (a 10k-header reconsider holds it for
    // over 10 s on CI).
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while nb.tip_height().unwrap_or(0) < want {
        assert!(
            std::time::Instant::now() < deadline,
            "far side must sync tip before disconnect"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let peer_id = na
        .peers
        .snapshot()
        .into_iter()
        .find(|p| p.subver.contains("testnode1"))
        .map(|p| p.id)
        .expect("outbound peer id");
    assert!(na.peers.disconnect_id(peer_id));

    let mut far_clear = false;
    for _ in 0..100 {
        if !nb
            .peers
            .snapshot()
            .iter()
            .any(|p| p.subver.contains("testnode0"))
        {
            far_clear = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        far_clear,
        "far side getpeerinfo must drop us within 5s after tip sync (mempool_reorg)"
    );

    na.shutdown().await;
    nb.shutdown().await;
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn on_tx_announce_none_lagged_closed_are_ok() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("tx-ann-empty");
    let (out_tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    assert!(on_tx_announce(&hub, &out_tx, &follow, None, None).is_ok());
    assert!(on_tx_announce(
        &hub,
        &out_tx,
        &follow,
        None,
        Some(Err(broadcast::error::RecvError::Lagged(1))),
    )
    .is_ok());
    assert!(on_tx_announce(
        &hub,
        &out_tx,
        &follow,
        None,
        Some(Err(broadcast::error::RecvError::Closed)),
    )
    .is_ok());

    use bitcoin::hashes::Hash;
    use bitcoin::Txid;
    use std::sync::Arc;
    let txid = Txid::from_byte_array([0x11; 32]);
    let ann = rbitcoin_net::tx_relay::MempoolAnnounce {
        txid,
        replaced: Vec::new(),
        replaced_scripthashes: Vec::new(),
        scripthashes: Vec::new(),
        outpoints: Default::default(),
    };
    assert!(on_tx_announce(&hub, &out_tx, &follow, None, Some(Ok(ann.clone()))).is_ok());

    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    assert!(on_tx_announce(&hub, &out_tx, &follow, None, Some(Ok(ann.clone()))).is_ok());

    follow.from_this_peer.insert(txid, FROM_THIS_PEER_CAP);
    assert!(on_tx_announce(&hub, &out_tx, &follow, None, Some(Ok(ann))).is_ok());
    let _ = std::fs::remove_dir_all(dir);
}

/// Each `headers` message persists the pending path from the last stored
/// header, not the whole path again. Re-checking stored fork headers walks
/// their ancestors on every message, so a long fork made each message slower
/// (`feature_bip68_sequence.py` took 10 s for one message at 244 pending).
#[test]
fn persist_pending_path_starts_after_the_last_stored_header() {
    use bitcoin::ScriptBuf;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("persist-path");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.mine(20, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let fork_at = hub
        .query
        .wire_header_at_height(rbitcoin_primitives::Height(10))
        .unwrap();
    let mut pending = HashMap::new();
    let mut prev = fork_at.block_hash();
    let mut time = fork_at.time + 1;
    let mut last = prev;
    for height in 11..=50u32 {
        let h = rbitcoin_consensus::mine_regtest_paying(
            prev,
            time,
            height,
            ScriptBuf::from_bytes(vec![0x52]),
            vec![],
        )
        .header;
        prev = h.block_hash();
        last = prev;
        time += 1;
        pending.insert(prev, h);
    }
    let _ = persist_pending_header_path(&hub, &pending, last);
    assert!(hub.knows_header(&last), "the fork path is stored");

    let next = rbitcoin_consensus::mine_regtest_paying(
        last,
        time,
        51,
        ScriptBuf::from_bytes(vec![0x52]),
        vec![],
    )
    .header;
    pending.insert(next.block_hash(), next);
    let _ = hub.take_header_contextual_checks();
    let _ = persist_pending_header_path(&hub, &pending, next.block_hash());
    assert!(hub.knows_header(&next.block_hash()));
    assert_eq!(
        hub.take_header_contextual_checks(),
        1,
        "only the new header is checked, not the stored fork path"
    );
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn inv_and_getdata_at_cap_stay_one_past_disconnects() {
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-cap");
    hub.ensure_genesis().unwrap();
    let (out_tx, _rx) = peer_out_channel();
    let block = Inventory::CompactBlock(hub.tip_hash().unwrap());
    let at_cap = vec![block; MAX_INV_SIZE];
    let mut follow = PeerFollowState::new();
    on_inv(&hub, &out_tx, &mut follow, None, &at_cap).unwrap();
    assert_eq!(
        follow.ban_score, 0,
        "exactly {MAX_INV_SIZE} inv items stay connected"
    );
    let mut over = at_cap;
    over.push(block);
    let mut follow = PeerFollowState::new();
    on_inv(&hub, &out_tx, &mut follow, None, &over).unwrap();
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "one past the inv cap disconnects"
    );

    let tx = Inventory::WitnessTransaction(Txid::from_byte_array([0x22; 32]));
    let at_cap = vec![tx; MAX_INV_SIZE];
    let mut follow = PeerFollowState::new();
    serve_getdata(&hub, &out_tx, &mut follow, None, at_cap.clone())
        .await
        .unwrap();
    assert_eq!(
        follow.ban_score, 0,
        "exactly {MAX_INV_SIZE} getdata items are served"
    );
    let mut over = at_cap;
    over.push(tx);
    let mut follow = PeerFollowState::new();
    serve_getdata(&hub, &out_tx, &mut follow, None, over)
        .await
        .unwrap();
    assert!(
        follow.ban_score >= BAN_SCORE_THRESHOLD,
        "one past the getdata cap disconnects"
    );
    let _ = std::fs::remove_dir_all(dir);
}
#[tokio::test]
async fn over_budget_reader_waits_until_one_byte_is_written() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let _at_cap = hold_send_bytes(&peer, rbitcoin_net::peers::PEER_SEND_BUDGET);
    let (one_more, mut past_cap) = peer.send_queue().channel();
    one_more.send(PeerOut::Encoded(vec![0])).unwrap();
    let waiting = std::sync::Arc::clone(&peer);
    let wait = tokio::spawn(async move { waiting.wait_send_budget().await });
    wait_send_parked(&peer, "an over-budget reader never parked").await;
    assert!(
        !wait.is_finished(),
        "an over-budget reader must be parked before the writer drains"
    );
    drop(past_cap.try_recv());
    tokio::time::timeout(std::time::Duration::from_secs(1), wait)
        .await
        .expect("writing back to the cap wakes the reader")
        .unwrap();
}

/// `fPauseSend`: an over-budget session does not read. A ping sent while only
/// the send budget is blown gets no pong until the writer drains.
#[tokio::test]
async fn over_budget_session_does_not_read_a_ping() {
    use std::time::Duration;
    let mut t = paused_serve("serve-pause-read", 1, &["/rbitcoin:test(budget-read)/"]).await;
    let (raw, sess) = &mut t.clients[0];
    let held = hold_send_bytes(sess, 2 * rbitcoin_net::peers::PEER_SEND_BUDGET);
    wait_send_parked(sess, "over-budget session never paused").await;
    write_peer_msg(raw, NetworkMessage::Ping(7)).await;
    let peers = sess.peer_hub().expect("session hub");
    wait_heartbeat_lap(&peers, "paused session did not heartbeat after the ping").await;
    let ping = sess
        .snapshot(0)
        .bytesrecv_per_msg
        .get("ping")
        .copied()
        .unwrap_or(0);
    assert_eq!(ping, 0, "over-budget session must not read the ping");
    drop(held);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let NetworkMessage::Pong(7) = next_peer_msg(raw).await.unwrap() {
                return;
            }
        }
    })
    .await
    .expect("draining the send budget lets the session read the ping");
    t.node.shutdown().await;
    let _ = std::fs::remove_dir_all(&t.dir);
}

/// A decoded non-block frame held for the send budget is still in
/// `decode_q`, but it is not a frame waiting to decode behind a permit.
/// The writer can be stuck forever on a peer that stops reading, so that
/// hold must not suspend the ping timeout. The heartbeat has to drop the
/// session even though the queue is non-empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_non_block_frame_does_not_suspend_the_ping_timeout() {
    use bitcoin::blockdata::constants::genesis_block;
    use rbitcoin_net::v2::write_v2_msg;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("held-front-timeout");
    hub.ensure_genesis().unwrap();
    let hub = hub.into_arc();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let start = 1_700_000_000_u64;
    peers.set_mock_now(start);
    let held = hold_decode_permits().await;
    let mut s = open_decode_session(Arc::clone(&hub), &peers, 18480, hub.tip_hash()).await;
    drain_startup(&mut s.reader, s.magic).await;

    // A heavy block holds the decode queue, so the ping behind it is queued
    // instead of applied directly. The budget flips before that front is
    // polled: the block still applies, then the ping is put back.
    let before = s.live.decode_enqueued();
    let block = genesis_block(Network::Regtest);
    let hash = block.block_hash();
    write_v2_msg(&mut s.writer, NetworkMessage::Block(block))
        .await
        .unwrap();
    wait_decode_enqueued(&s.live, before + 1).await;
    let nonce = 0x51a7_0002_u64;
    write_v2_msg(&mut s.writer, NetworkMessage::Ping(nonce))
        .await
        .unwrap();
    wait_decode_enqueued(&s.live, before + 2).await;
    let _budget = hold_send_bytes(&s.live, 2 * rbitcoin_net::peers::PEER_SEND_BUDGET);
    assert!(s.live.send_over_budget());
    drop(held);
    wait_block_applied(&s.live, &hash).await;
    assert_no_pong(&mut s.reader, s.magic, nonce).await;
    assert!(
        !s.session.is_finished(),
        "the held ping ended the session before the timeout"
    );

    let now = peers.now_secs();
    peers.set_mock_now(now + PING_TIMEOUT_SECS + POST_BLOCK_PONG_GRACE_SECS + 1);
    tokio::time::timeout(Duration::from_secs(5), &mut s.session)
        .await
        .expect("a held non-block frame must not hold the ping timeout")
        .expect("session task");
    assert!(
        s.live.stop.load(Ordering::SeqCst),
        "the ping timeout disconnected the stalled writer"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

/// The held frame can be a ping with a `blocktxn` still behind it. The
/// timeout gates run, but the 10s request expiry must leave that pending
/// compact alone until the disconnect drain applies the `blocktxn`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn held_front_keeps_a_queued_blocktxn_until_the_drain() {
    use bitcoin::bip152::{BlockTransactions, HeaderAndShortIds};
    use bitcoin::blockdata::constants::genesis_block;
    use rbitcoin_net::v2::write_v2_msg;

    let (dir, hub, [a, _]) = compact_spend_pair("held-front-cmpct");
    let hub = hub.into_arc();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let start = 1_700_000_000_u64;
    peers.set_mock_now(start);
    let mut s = open_decode_session(Arc::clone(&hub), &peers, 18482, hub.tip_hash()).await;
    drain_startup(&mut s.reader, s.magic).await;
    write_v2_msg(
        &mut s.writer,
        NetworkMessage::SendCmpct(SendCmpct {
            send_compact: true,
            version: 2,
        }),
    )
    .await
    .unwrap();
    let hsi = HeaderAndShortIds::from_block(&a, 0xbeef, 2, &[]).unwrap();
    write_v2_msg(
        &mut s.writer,
        NetworkMessage::CmpctBlock(CmpctBlock { compact_block: hsi }),
    )
    .await
    .unwrap();
    let indexes = wait_getblocktxn(&mut s.reader, s.magic, a.block_hash()).await;

    // Hold decodes, then queue a heavy filler, the ping, and the blocktxn
    // in wire order. Once the budget flips the filler applies, the ping is
    // held, and the blocktxn stays behind it.
    let held = hold_decode_permits().await;
    let before = s.live.decode_enqueued();
    let filler = genesis_block(Network::Regtest);
    let filler_hash = filler.block_hash();
    write_v2_msg(&mut s.writer, NetworkMessage::Block(filler))
        .await
        .unwrap();
    wait_decode_enqueued(&s.live, before + 1).await;
    let nonce = 0x51a7_0003_u64;
    write_v2_msg(&mut s.writer, NetworkMessage::Ping(nonce))
        .await
        .unwrap();
    wait_decode_enqueued(&s.live, before + 2).await;
    let blocktxn = BlockTransactions {
        block_hash: a.block_hash(),
        transactions: indexes
            .iter()
            .map(|i| a.txdata[*i as usize].clone())
            .collect(),
    };
    write_v2_msg(
        &mut s.writer,
        NetworkMessage::BlockTxn(BlockTxn {
            transactions: blocktxn,
        }),
    )
    .await
    .unwrap();
    wait_decode_enqueued(&s.live, before + 3).await;
    let _budget = hold_send_bytes(&s.live, 2 * rbitcoin_net::peers::PEER_SEND_BUDGET);
    drop(held);
    wait_block_applied(&s.live, &filler_hash).await;
    assert_no_pong(&mut s.reader, s.magic, nonce).await;
    assert!(
        !s.session.is_finished(),
        "the held ping ended the session before the expiry"
    );
    // Request expiry reads the real clock, so this cannot age the pending
    // compact without a 10s sleep. `held_front_keeps_a_queued_blocktxn_pending`
    // backdates one and pins that a queued frame suspends expiry. What is
    // left here is the drain: the held blocktxn is not expired into a full
    // getdata and still applies when the front is released.
    assert_no_getdata_for(
        &mut s.reader,
        s.magic,
        a.block_hash(),
        Duration::from_millis(250),
    )
    .await;
    assert!(
        s.live.held_front_queued(),
        "the held front must still feed decode_queued to the heartbeat"
    );

    let now = peers.now_secs();
    peers.set_mock_now(now + PING_TIMEOUT_SECS + POST_BLOCK_PONG_GRACE_SECS + 1);
    tokio::time::timeout(Duration::from_secs(5), &mut s.session)
        .await
        .expect("the held ping must still time the writer out")
        .expect("session task");
    assert_eq!(
        hub.tip_hash(),
        Some(a.block_hash()),
        "the drain applies the queued blocktxn"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

fn inbound_peer(
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
) -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 1));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    )
}

/// A preferred tx-download peer (outbound full relay): its tx invs are
/// asked at once, with no `NONPREF_PEER_TX_DELAY`.
fn preferred_peer(
    peers: &std::sync::Arc<rbitcoin_net::peers::PeerHub>,
    port: u16,
) -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: u64::from(port),
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    peers.register(
        addr,
        addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    )
}

#[test]
fn inbound_netgroup_is_fixed_at_accept() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let mk = |ip: [u8; 4]| {
        let addr = std::net::SocketAddr::from((ip, 1));
        let ver = bitcoin::p2p::message_network::VersionMessage {
            version: 70016,
            services: bitcoin::p2p::ServiceFlags::NETWORK,
            timestamp: 0,
            receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
            sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
            nonce: u64::from(ip[3]),
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        )
    };
    let a = mk([1, 2, 3, 4]);
    let b = mk([1, 2, 9, 9]);
    let c = mk([1, 3, 0, 1]);
    assert_eq!(a.netgroup(), b.netgroup(), "same /16 is one group");
    assert_ne!(
        a.netgroup(),
        c.netgroup(),
        "a different /16 is another group"
    );
    assert_eq!(
        a.netgroup(),
        rbitcoin_net::eviction::eviction_netgroup(a.addr)
    );
}

const ORDINARY_BIND: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8333);

// The reconnect refusal after a misbehavior disconnect has no default journey:
// default harness peers dial from loopback, which `ip_skips_discourage`
// exempts. These units own it in default CI (TESTING.md witness table,
// "Inbound discourage").
#[test]
fn misbehavior_disconnect_refuses_the_same_address() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let now = 1_700_000_000u64;
    peers.set_mock_now(now);
    let addr = std::net::SocketAddr::from(([9, 9, 9, 9], 8333));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 9,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut score = 0u32;
    punish_disconnect(&mut score, Some(peer.as_ref()));
    let other_port = std::net::SocketAddr::from(([9, 9, 9, 9], 9999));
    assert!(
        peers.inbound_discouraged(other_port, ORDINARY_BIND),
        "a misbehavior disconnect refuses that address"
    );
    peers.set_mock_now(now + 86_400 - 1);
    assert!(
        peers.inbound_discouraged(addr, ORDINARY_BIND),
        "the refusal lasts a day"
    );
    peers.set_mock_now(now + 86_400);
    assert!(
        !peers.inbound_discouraged(addr, ORDINARY_BIND),
        "the refusal ends after a day"
    );
}

#[test]
fn misbehavior_disconnect_does_not_refuse_loopback() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_000);
    let addr = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 8333));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut score = 0u32;
    punish_disconnect(&mut score, Some(peer.as_ref()));
    assert!(
        score >= BAN_SCORE_THRESHOLD,
        "a loopback peer is still disconnected"
    );
    let other_port = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 18444));
    assert!(
        !peers.inbound_discouraged(other_port, ORDINARY_BIND),
        "one loopback disconnect must not refuse every local connection"
    );
}

/// An onion session's VERSION socket is `0.0.0.0`. The refusal is the
/// `NetAddr`, and a later session with that net is discouraged.
#[test]
fn overlay_misbehavior_discourages_that_net() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_000);
    let onion = rbitcoin_net::NetAddr::Onion {
        pk: [9; 32],
        port: 8333,
    };
    let sock = std::net::SocketAddr::from(([0, 0, 0, 0], 8333));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&sock, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&sock, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 9,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register_net(
        sock,
        onion,
        sock,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let mut score = 0u32;
    punish_disconnect(&mut score, Some(peer.as_ref()));
    assert!(
        peers.net_discouraged(onion),
        "a misbehavior disconnect refuses that overlay net"
    );
    assert!(
        !peers.inbound_discouraged(sock, ORDINARY_BIND),
        "0.0.0.0 must not become a clearnet refusal"
    );
}

/// The refusal is the onion or I2P identity. Another port is the same peer.
#[test]
fn overlay_refusal_ignores_the_port() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_000);
    let onion = |port| rbitcoin_net::NetAddr::Onion { pk: [9; 32], port };
    let key = rbitcoin_net::peers::DiscourageKey::from_net(onion(8333)).unwrap();
    peers.note_misbehavior_key(key);
    assert!(peers.net_discouraged(onion(8333)));
    assert!(
        peers.net_discouraged(onion(9735)),
        "the same onion on another port is still refused"
    );
    assert!(!peers.net_discouraged(rbitcoin_net::NetAddr::Onion {
        pk: [8; 32],
        port: 9735,
    }));
    let i2p = |port| rbitcoin_net::NetAddr::I2p {
        dest: [7; 32],
        port,
    };
    peers.note_misbehavior_key(rbitcoin_net::peers::DiscourageKey::from_net(i2p(0)).unwrap());
    assert!(
        peers.net_discouraged(i2p(8333)),
        "the same I2P destination on another port is still refused"
    );
}

#[test]
fn threshold_exit_refuses_the_address_without_punish_disconnect() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let now = 1_700_000_100u64;
    peers.set_mock_now(now);
    let addr = std::net::SocketAddr::from(([8, 8, 4, 4], 8333));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 4,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let err = threshold_disconnect(Some(peer.as_ref()));
    assert!(matches!(
        err,
        rbitcoin_net::error::NetError::Protocol("peer misbehavior threshold")
    ));
    let other_port = std::net::SocketAddr::from(([8, 8, 4, 4], 9999));
    assert!(
        peers.inbound_discouraged(other_port, ORDINARY_BIND),
        "a rate-limit or score-threshold exit refuses that address"
    );

    peers.set_noban(true);
    let noban = peers.register(
        std::net::SocketAddr::from(([1, 2, 3, 4], 8333)),
        std::net::SocketAddr::from(([1, 2, 3, 4], 8333)),
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::Inbound,
    );
    let _ = threshold_disconnect(Some(noban.as_ref()));
    assert!(
        !peers.inbound_discouraged(std::net::SocketAddr::from(([1, 2, 3, 4], 1)), ORDINARY_BIND),
        "noban is not recorded"
    );
    peers.set_noban(false);

    // Core never discourages a manual peer.
    let manual_addr = std::net::SocketAddr::from(([5, 6, 7, 8], 8333));
    let manual = peers.register(
        manual_addr,
        manual_addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::Manual,
    );
    let _ = threshold_disconnect(Some(manual.as_ref()));
    let mut score = 0u32;
    punish_disconnect(&mut score, Some(manual.as_ref()));
    assert!(
        manual.stop.load(std::sync::atomic::Ordering::SeqCst),
        "a protocol violation drops a manual peer"
    );
    assert!(
        !peers.inbound_discouraged(std::net::SocketAddr::from(([5, 6, 7, 8], 1)), ORDINARY_BIND),
        "a manual peer is not recorded"
    );
}

#[test]
fn second_rate_limit_disconnect_from_an_address_discourages_it() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let now = 1_700_000_200u64;
    peers.set_mock_now(now);
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            bitcoin::p2p::ServiceFlags::NONE,
        ),
        sender: bitcoin::p2p::address::Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            bitcoin::p2p::ServiceFlags::NONE,
        ),
        nonce: 5,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let flood = |addr: std::net::SocketAddr| {
        let peer = peers.register(
            addr,
            addr,
            &ver,
            true,
            rbitcoin_net::peers::PeerConnType::Inbound,
        );
        rate_limit_disconnect(Some(peer.as_ref()))
    };

    let first = std::net::SocketAddr::from(([7, 7, 7, 7], 8333));
    assert!(matches!(
        flood(first),
        rbitcoin_net::error::NetError::Protocol("peer rate limit")
    ));
    assert!(
        !peers.inbound_discouraged(first, ORDINARY_BIND),
        "one rate-limit disconnect does not refuse the address"
    );
    assert!(matches!(
        flood(std::net::SocketAddr::from(([7, 7, 7, 7], 9999))),
        rbitcoin_net::error::NetError::Protocol("peer misbehavior threshold")
    ));
    assert!(
        peers.inbound_discouraged(first, ORDINARY_BIND),
        "a second rate-limit disconnect from that address refuses it"
    );

    let slow = std::net::SocketAddr::from(([7, 7, 7, 8], 8333));
    let _ = flood(slow);
    peers.set_mock_now(now + rbitcoin_net::peers::PeerHub::RATE_STRIKE_SECS);
    let _ = flood(slow);
    assert!(
        !peers.inbound_discouraged(slow, ORDINARY_BIND),
        "a strike older than the window does not count"
    );
}

#[test]
fn exempt_peer_rate_limit_leaves_no_strike_on_its_address() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_700_000_300);
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            bitcoin::p2p::ServiceFlags::NONE,
        ),
        sender: bitcoin::p2p::address::Address::new(
            &std::net::SocketAddr::from(([0, 0, 0, 0], 0)),
            bitcoin::p2p::ServiceFlags::NONE,
        ),
        nonce: 6,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let flood = |addr: std::net::SocketAddr, conn: rbitcoin_net::peers::PeerConnType| {
        let peer = peers.register(addr, addr, &ver, false, conn);
        rate_limit_disconnect(Some(peer.as_ref()))
    };

    let manual = std::net::SocketAddr::from(([6, 6, 6, 6], 8333));
    let _ = flood(manual, rbitcoin_net::peers::PeerConnType::Manual);
    let noban = std::net::SocketAddr::from(([6, 6, 6, 7], 8333));
    peers.set_noban(true);
    let _ = flood(noban, rbitcoin_net::peers::PeerConnType::Inbound);
    peers.set_noban(false);
    for exempt in [manual, noban] {
        let again = std::net::SocketAddr::from((exempt.ip(), 9999));
        assert!(
            matches!(
                flood(again, rbitcoin_net::peers::PeerConnType::Inbound),
                rbitcoin_net::error::NetError::Protocol("peer rate limit")
            ),
            "{exempt}: an exempt overflow leaves no strike for the next peer"
        );
        assert!(!peers.inbound_discouraged(again, ORDINARY_BIND));
    }
}

/// A full getdata window of 1 MB bodies is more than a second of the byte
/// budget. A peer that serves it at link speed stays connected. A second
/// frame with a requested header still counts while the ask is open (a
/// body that decodes as `Unknown`, or one parked on a missing parent), and
/// so does an unsolicited body. Once those asks close, a new ask for the
/// same hash is exempt again.
#[test]
fn requested_block_bodies_stay_off_the_tip_follow_rate_window() {
    use rbitcoin_net::peer_dos::{PeerRateLimiter, DEFAULT_MAX_BYTES_PER_SEC};

    const BODY: usize = 1_000_080;
    assert!((MAX_SERVE_BLOCKS * BODY) as u64 > DEFAULT_MAX_BYTES_PER_SEC);
    let body = |nonce: u32| {
        let mut payload = vec![0u8; BODY];
        payload[76..80].copy_from_slice(&nonce.to_le_bytes());
        FramedMessage {
            magic: Magic::from(Network::Regtest),
            command: *b"block\0\0\0\0\0\0\0",
            payload,
        }
    };
    let window: Vec<FramedMessage> = (0..MAX_SERVE_BLOCKS as u32).map(body).collect();
    let asks: Vec<BlockHash> = window
        .iter()
        .map(|f| f.block_hash_from_header().unwrap())
        .collect();
    let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("rate-asks");
    let mut follow = PeerFollowState::new();
    for h in &asks {
        follow.requested_blocks.ask(&hub, *h);
    }
    let mut rate = PeerRateLimiter::default_limits();
    for (i, f) in window.iter().enumerate() {
        assert!(
            note_frame_rate(&mut rate, &mut follow, f),
            "requested body {i} must not hit the rate limit"
        );
    }
    let resends_fit = window
        .iter()
        .all(|f| note_frame_rate(&mut rate, &mut follow, f));
    assert!(!resends_fit, "a resent requested body still counts");

    follow.requested_blocks = RequestedBlocks::default();
    let mut rate = PeerRateLimiter::default_limits();
    let unsolicited_fits = (0..MAX_SERVE_BLOCKS as u32)
        .map(|i| body(MAX_SERVE_BLOCKS as u32 + i))
        .all(|f| note_frame_rate(&mut rate, &mut follow, &f));
    assert!(!unsolicited_fits, "unsolicited bodies still count");

    for h in &asks {
        follow.requested_blocks.ask(&hub, *h);
    }
    let mut rate = PeerRateLimiter::default_limits();
    let reasked_fits = window
        .iter()
        .all(|f| note_frame_rate(&mut rate, &mut follow, f));
    assert!(reasked_fits, "a new ask for the same hash is exempt again");
}

#[test]
fn evicted_netgroup_waits_less_than_a_day_and_the_set_is_capped() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let now = 1_800_000_000u64;
    peers.set_mock_now(now);
    let group = rbitcoin_net::eviction::eviction_netgroup("8.8.1.1:1".parse().unwrap());
    peers.note_slot_evict(group);
    let same = "8.8.9.9:8333".parse().unwrap();
    assert!(
        peers.inbound_discouraged(same, ORDINARY_BIND),
        "a netgroup that just lost a slot is refused"
    );
    peers.set_mock_now(now + 600 - 1);
    assert!(
        peers.inbound_discouraged(same, ORDINARY_BIND),
        "the netgroup wait holds until ten minutes"
    );
    peers.set_mock_now(now + 600);
    assert!(
        !peers.inbound_discouraged(same, ORDINARY_BIND),
        "the netgroup wait is ten minutes"
    );
    // At the cap a new entry evicts the one that expires first (the oldest),
    // so a flood cannot switch the pause off (Core's rolling filter).
    for i in 0..rbitcoin_net::peers::PeerHub::DISCOURAGE_CAP {
        peers.set_mock_now(if i == 0 { now - 1 } else { now });
        let a = (i / 256) as u8;
        let b = (i % 256) as u8;
        let slot = std::net::SocketAddr::from(([a, b, 1, 1], 1));
        peers.note_slot_evict(rbitcoin_net::eviction::eviction_netgroup(slot));
    }
    let overflow = std::net::SocketAddr::from(([255, 255, 1, 1], 1));
    peers.note_slot_evict(rbitcoin_net::eviction::eviction_netgroup(overflow));
    assert!(
        peers.inbound_discouraged(overflow, ORDINARY_BIND),
        "a new netgroup past the cap is stored"
    );
    let oldest = std::net::SocketAddr::from(([0, 0, 1, 1], 1));
    assert!(
        !peers.inbound_discouraged(oldest, ORDINARY_BIND),
        "the oldest netgroup rolls out"
    );
    peers.set_mock_now(now + 100);
    let refreshed = std::net::SocketAddr::from(([0, 1, 1, 1], 1));
    peers.note_slot_evict(rbitcoin_net::eviction::eviction_netgroup(refreshed));
    peers.set_mock_now(now + 600);
    assert!(
        peers.inbound_discouraged(refreshed, ORDINARY_BIND),
        "a netgroup already stored is refreshed at the cap"
    );
    for i in 0..rbitcoin_net::peers::PeerHub::DISCOURAGE_CAP {
        peers.set_mock_now(if i == 0 { now - 1 } else { now });
        let ip = std::net::Ipv4Addr::from(i as u32);
        peers.note_misbehavior_addr(std::net::IpAddr::V4(ip));
    }
    let extra = std::net::SocketAddr::from(([255, 255, 255, 254], 1));
    peers.note_misbehavior_addr(extra.ip());
    assert!(
        peers.inbound_discouraged(extra, ORDINARY_BIND),
        "past the cap a new address is still discouraged"
    );
    let first = std::net::SocketAddr::from((std::net::Ipv4Addr::from(0u32), 1));
    assert!(
        !peers.inbound_discouraged(first, ORDINARY_BIND),
        "the oldest address rolls out"
    );
    let second = std::net::SocketAddr::from((std::net::Ipv4Addr::from(1u32), 1));
    assert!(
        peers.inbound_discouraged(second, ORDINARY_BIND),
        "the rest stay until they expire"
    );
}

/// The rate-strike map rolls too: at the cap a new address still records
/// its strike, so its second rate-limit disconnect escalates, and the
/// oldest strike rolls out.
#[test]
fn rate_strikes_roll_at_the_cap() {
    use rbitcoin_net::peers::{DiscourageKey, PeerHub};
    let peers = PeerHub::new();
    let now = 1_800_000_000;
    let key = |i: u32| DiscourageKey::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(i)));
    for i in 0..PeerHub::DISCOURAGE_CAP as u32 {
        peers.set_mock_now(if i == 0 { now - 1 } else { now });
        assert!(!peers.note_rate_strike(key(i)));
    }
    let new = key(u32::MAX);
    assert!(!peers.note_rate_strike(new), "the first strike is recorded");
    assert!(peers.note_rate_strike(new), "the second strike escalates");
    assert!(
        !peers.note_rate_strike(key(0)),
        "the oldest strike rolled out"
    );
    assert!(peers.note_rate_strike(key(2)), "the rest stay");
}

/// A full inbound table evicts one peer and pauses that netgroup. The pause
/// must not refuse outbound dials to the rest of the prefix.
#[test]
fn slot_evict_does_not_block_an_outbound_dial() {
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_800_000_000);
    let evicted = "8.8.1.1:8333".parse().unwrap();
    peers.note_slot_evict(rbitcoin_net::netgroup::slot_pause_group(evicted));
    let neighbor: std::net::SocketAddr = "8.8.9.9:8333".parse().unwrap();
    assert!(
        peers.inbound_discouraged(neighbor, ORDINARY_BIND),
        "the slot wait still refuses another inbound from that /16"
    );
    assert!(
        !peers.net_discouraged(rbitcoin_net::NetAddr::Ip(neighbor)),
        "the slot wait must not refuse an outbound dial in that /16"
    );
    let cjdns_ip = std::net::Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1);
    let cjdns_sock = std::net::SocketAddr::from((cjdns_ip, 8333));
    peers.note_slot_evict(rbitcoin_net::netgroup::slot_pause_group(cjdns_sock));
    assert!(
        peers.inbound_discouraged(cjdns_sock, ORDINARY_BIND),
        "the slot wait still refuses another inbound from that cjdns /32"
    );
    assert!(
        !peers.net_discouraged(rbitcoin_net::NetAddr::Cjdns {
            ip: cjdns_ip,
            port: 8333,
        }),
        "the slot wait must not refuse an outbound cjdns dial in that group"
    );
    peers.note_misbehavior_addr(neighbor.ip());
    assert!(
        peers.net_discouraged(rbitcoin_net::NetAddr::Ip(neighbor)),
        "a misbehavior key still refuses an outbound dial to that address"
    );
}

/// An inbound peer's tx inv is not asked at once (Core
/// `NONPREF_PEER_TX_DELAY`). The heartbeat sweep asks it once the delay has
/// passed, so inbound announcements are still fetched.
#[tokio::test]
async fn inbound_tx_inv_is_asked_after_the_nonpref_delay() {
    use bitcoin::hashes::Hash;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inbound-tx-delay");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(10_000);
    let peer = inbound_peer(&peers);
    peer.set_wtxid_relay();
    let (out_tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let wtxid = bitcoin::Wtxid::from_byte_array([0x5a; 32]);
    let getdata = |rx: &mut PeerOutRx| {
        let mut want = Vec::new();
        while let Ok(out) = rx.try_recv() {
            if let NetworkMessage::GetData(v) = out.expect_msg() {
                want.extend(v);
            }
        }
        want
    };
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        &[Inventory::WTx(wtxid)],
    )
    .unwrap();
    rbitcoin_net::peer::queue_due_parent_getdata(&hub, &peer, &out_tx);
    assert!(getdata(&mut rx).is_empty(), "an inbound announcer waits");
    peers.set_mock_now(10_000 + rbitcoin_net::tx_relay::NONPREF_PEER_TX_DELAY_SECS);
    rbitcoin_net::peer::queue_due_parent_getdata(&hub, &peer, &out_tx);
    assert_eq!(getdata(&mut rx), vec![Inventory::WTx(wtxid)]);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn inv_getdata_charges_send_budget() {
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-budget");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    assert!(!hub.in_ibd(), "tx inv getdata pin is not IBD");
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = preferred_peer(&peers, 2);
    let (out_tx, _rx) = peer.open_out();
    let mut follow = PeerFollowState::new();
    let tx = Inventory::WitnessTransaction(Txid::from_byte_array([0x42; 32]));
    on_inv(&hub, &out_tx, &mut follow, Some(&peer), &[tx]).unwrap();
    assert!(
        peer.send_queued() > 0,
        "inv getdata must charge the send budget"
    );
    let _ = std::fs::remove_dir_all(dir);
}

fn relay_hub(label: &str) -> (rbitcoin_query::testutil::TempDir, ChainHub) {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    (dir, hub)
}

fn sole_getdata(rx: &mut PeerOutRx) -> Vec<Inventory> {
    let NetworkMessage::GetData(items) = rx.try_recv().expect("one getdata").expect_msg() else {
        panic!("expected getdata");
    };
    assert!(rx.try_recv().is_err(), "one inv sends one getdata");
    items
}

/// Core #35878: a tx id repeated inside one INV is handled once. `tx` and
/// `witness-tx` share the txid set; a `wtx` with the same bytes is a
/// different id and is kept.
#[tokio::test]
async fn inv_drops_repeated_tx_ids_within_one_message() {
    use bitcoin::{Txid, Wtxid};

    let (dir, hub) = relay_hub("inv-dedupe");
    let t = Txid::from_byte_array([0x61; 32]);
    let w = Wtxid::from_byte_array([0x77; 32]);
    let w_same_bytes = Wtxid::from_byte_array([0x61; 32]);
    let (out_tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let _ = hub.mempool().unwrap().sample_reset_perf();
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        None,
        &[
            Inventory::WitnessTransaction(t),
            Inventory::Transaction(t),
            Inventory::WTx(w),
            Inventory::WTx(w),
            Inventory::WTx(w_same_bytes),
        ],
    )
    .unwrap();
    assert_eq!(
        sole_getdata(&mut rx),
        vec![
            Inventory::WitnessTransaction(t),
            Inventory::WTx(w),
            Inventory::WTx(w_same_bytes),
        ],
        "each id once; a wtxid equal to a txid's bytes is still asked"
    );
    assert_eq!(
        hub.mempool().unwrap().sample_reset_perf().inv_tx,
        3,
        "the inv meter counts each id once"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// The repeat filter is scoped to one INV message.
#[tokio::test]
async fn inv_repeat_filter_resets_per_message() {
    use bitcoin::Wtxid;

    let (dir, hub) = relay_hub("inv-dedupe-scope");
    let w = Wtxid::from_byte_array([0x78; 32]);
    let (out_tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    for round in 0..2 {
        on_inv(&hub, &out_tx, &mut follow, None, &[Inventory::WTx(w)]).unwrap();
        assert_eq!(
            sole_getdata(&mut rx),
            vec![Inventory::WTx(w)],
            "round {round}: a later inv asks again"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// A notfound for the in-flight wtxid makes the waiting announcer due now.
#[tokio::test]
async fn notfound_makes_the_waiting_wtxid_peer_due() {
    use bitcoin::hashes::Hash;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("wtx-notfound");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    // A fixed clock: `noted` and the note read the same second.
    peers.set_mock_now(1_000_000);
    let peer1 = preferred_peer(&peers, 2);
    let peer2 = preferred_peer(&peers, 3);
    let wtxid = bitcoin::Wtxid::from_byte_array([0xef; 32]);
    let inv = [Inventory::WTx(wtxid)];
    let noted = peer1.clock_now();
    let (tx1, mut rx1) = peer_out_channel();
    let (tx2, _rx2) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    on_inv(&hub, &tx1, &mut follow, Some(&peer1), &inv).unwrap();
    on_inv(&hub, &tx2, &mut follow, Some(&peer2), &inv).unwrap();
    assert!(matches!(
        rx1.try_recv().unwrap().expect_msg(),
        NetworkMessage::GetData(_)
    ));
    handle_peer_inventory_msg(
        &NetworkMessage::NotFound(vec![Inventory::WTx(wtxid)]),
        &hub,
        &tx1,
        &mut follow,
        Some(&peer1),
    )
    .unwrap();
    let mp = hub.mempool().unwrap();
    let due = mp.take_due_parent_getdata(peer2.id, noted);
    assert_eq!(
        due.len(),
        1,
        "notfound from the in-flight peer makes the waiter due immediately"
    );
    assert!(due[0].wtxid);
    assert_eq!(due[0].hash, wtxid.to_byte_array());
    let _ = std::fs::remove_dir_all(dir);
}

/// `notfound` for a txid inventory (with or without witness) clears that request.
#[tokio::test]
async fn notfound_for_txid_inventory_wakes_the_waiter() {
    use bitcoin::hashes::Hash;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("txid-notfound");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    // A fixed clock: `noted` and the note read the same second.
    peers.set_mock_now(1_000_000);
    for (n, witness) in [(0xab_u8, false), (0xcd, true)] {
        let peer1 = preferred_peer(&peers, 2);
        let peer2 = preferred_peer(&peers, 3);
        let txid = bitcoin::Txid::from_byte_array([n; 32]);
        let item = if witness {
            Inventory::WitnessTransaction(txid)
        } else {
            Inventory::Transaction(txid)
        };
        let noted = peer1.clock_now();
        let (tx1, mut rx1) = peer_out_channel();
        let (tx2, _rx2) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        on_inv(&hub, &tx1, &mut follow, Some(&peer1), &[item]).unwrap();
        on_inv(&hub, &tx2, &mut follow, Some(&peer2), &[item]).unwrap();
        assert!(matches!(
            rx1.try_recv().unwrap().expect_msg(),
            NetworkMessage::GetData(_)
        ));
        handle_peer_inventory_msg(
            &NetworkMessage::NotFound(vec![item]),
            &hub,
            &tx1,
            &mut follow,
            Some(&peer1),
        )
        .unwrap();
        let due = hub
            .mempool()
            .unwrap()
            .take_due_parent_getdata(peer2.id, noted);
        assert_eq!(due.len(), 1, "txid notfound makes the waiter due");
        assert!(!due[0].wtxid);
        assert_eq!(due[0].hash, txid.to_byte_array());
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// Two inbound peers announce the same unknown wtxid. Only the first is
/// asked. The second stays queued until that request's interval ends.
#[tokio::test]
async fn second_wtxid_inv_waits_while_first_request_is_inflight() {
    use bitcoin::hashes::Hash;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("wtx-one-inflight");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    assert!(!hub.in_ibd(), "wtxid inv getdata pin is not IBD");
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer1 = preferred_peer(&peers, 2);
    let peer2 = preferred_peer(&peers, 3);
    let wtxid = bitcoin::Wtxid::from_byte_array([0xee; 32]);
    let inv = [Inventory::WTx(wtxid)];
    let noted = peer1.clock_now();
    let (tx1, mut rx1) = peer_out_channel();
    let (tx2, mut rx2) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    on_inv(&hub, &tx1, &mut follow, Some(&peer1), &inv).unwrap();
    on_inv(&hub, &tx2, &mut follow, Some(&peer2), &inv).unwrap();
    match rx1.try_recv().unwrap().expect_msg() {
        NetworkMessage::GetData(v) => {
            assert_eq!(v, vec![Inventory::WTx(wtxid)]);
        }
        other => panic!("first announcer must be asked, got {other:?}"),
    }
    assert!(
        rx2.try_recv().is_err(),
        "a second announcer is not asked while the first request is in flight"
    );
    let mp = hub.mempool().unwrap();
    let due = mp.take_due_parent_getdata(
        peer2.id,
        noted.saturating_add(rbitcoin_net::tx_relay::GETDATA_TX_INTERVAL_SECS + 2),
    );
    assert_eq!(
        due.len(),
        1,
        "after the interval the waiting peer is selected"
    );
    assert!(due[0].wtxid);
    assert_eq!(due[0].hash, wtxid.to_byte_array());
    let _ = std::fs::remove_dir_all(dir);
}

/// Rows other peers hold under their own cap do not skip a fresh peer's
/// announcement: it is recorded and asked for in the same inv as its block
/// and its already-asked hash.
#[tokio::test]
async fn other_peers_rows_do_not_skip_a_fresh_announcement() {
    use bitcoin::hashes::Hash;
    use bitcoin::Txid;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parent-other-peers");
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    assert!(!hub.in_ibd(), "parent-row inv pin is not IBD");
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let mp = hub.mempool().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = preferred_peer(&peers, 2);
    let keep = [0x42; 32];
    assert_eq!(
        mp.note_inv_tx_requested(
            rbitcoin_net::tx_relay::InvSource::new(peer.id, true),
            keep,
            1_000,
            false
        ),
        rbitcoin_net::tx_relay::ParentNote::RequestNow
    );
    let per_peer = rbitcoin_net::tx_relay::parent_req::MAX_PARENT_ANN_PER_PEER as u32 - 100;
    let mut n = 0u32;
    for filler in 1..=41u64 {
        for _ in 0..per_peer {
            let mut hash = [0u8; 32];
            hash[..4].copy_from_slice(&n.to_le_bytes());
            hash[31] = 0xf1;
            mp.note_inv_tx_requested(
                rbitcoin_net::tx_relay::InvSource::new(peer.id.saturating_add(filler), true),
                hash,
                1_000,
                true,
            );
            n += 1;
        }
    }
    let (out_tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let block = Inventory::Block(BlockHash::from_byte_array([0x91; 32]));
    let kept = Inventory::WitnessTransaction(Txid::from_byte_array(keep));
    let fresh = Inventory::WitnessTransaction(Txid::from_byte_array([0x77; 32]));
    on_inv(
        &hub,
        &out_tx,
        &mut follow,
        Some(&peer),
        &[block, kept, fresh],
    )
    .unwrap();
    assert_eq!(
        follow.ban_score, 0,
        "other peers' rows are not this peer's misbehavior"
    );
    let mut saw_headers = false;
    let mut getdata = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        match msg.expect_msg() {
            NetworkMessage::GetHeaders(_) => saw_headers = true,
            NetworkMessage::GetData(v) => getdata = v,
            other => panic!("unexpected inv follow-up: {other:?}"),
        }
    }
    assert!(saw_headers, "block inv still requests headers");
    assert_eq!(
        getdata,
        vec![fresh],
        "the in-flight hash is not asked again, and the fresh one is asked"
    );
    let fresh_txid = Txid::from_byte_array([0x77; 32]);
    assert_eq!(
        mp.announcer_peers_for(&fresh_txid, &bitcoin::Wtxid::from_byte_array([0x77; 32])),
        vec![peer.id],
        "the fresh announcement is recorded"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A regtest hub out of IBD with relay on, so `on_inv` asks for announced txs.
fn enable_tx_inv(dir: &impl AsRef<std::path::Path>, hub: &ChainHub) {
    hub.ensure_genesis().unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(
        dir.as_ref().join("mp"),
        std::sync::Arc::clone(&hub.query),
    )
    .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    assert!(!hub.in_ibd(), "tx announcements are asked for outside IBD");
}

/// The items `on_inv` puts in its getdata after `peer` announces `items`.
fn getdata_after_inv(
    hub: &ChainHub,
    peer: &rbitcoin_net::peers::LivePeer,
    items: &[Inventory],
) -> Vec<Inventory> {
    let (out_tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    on_inv(hub, &out_tx, &mut follow, Some(peer), items).unwrap();
    let mut getdata = Vec::new();
    while let Ok(msg) = rx.try_recv() {
        if let NetworkMessage::GetData(v) = msg.expect_msg() {
            getdata = v;
        }
    }
    getdata
}

fn announced_hash(i: u32) -> [u8; 32] {
    let mut h = [0xb7; 32];
    h[..4].copy_from_slice(&i.to_le_bytes());
    h
}

/// Core `OVERLOADED_PEER_TX_DELAY`: a peer that already has
/// `MAX_PEER_TX_REQUEST_IN_FLIGHT` requests outstanding and no relay
/// permission is not asked for one more at once, so an honest announcer of
/// the same transaction can answer first.
#[tokio::test]
async fn overloaded_peer_waits_before_it_is_asked_for_one_more() {
    use rbitcoin_net::tx_relay::{MAX_PEER_TX_REQUEST_IN_FLIGHT, OVERLOADED_PEER_TX_DELAY_SECS};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("overloaded-peer");
    enable_tx_inv(&dir, &hub);
    let mp = hub.mempool().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_000);
    let peer = preferred_peer(&peers, 2);
    let window: Vec<Inventory> = (0..MAX_PEER_TX_REQUEST_IN_FLIGHT as u32)
        .map(|i| Inventory::WTx(bitcoin::Wtxid::from_byte_array(announced_hash(i))))
        .collect();
    assert_eq!(
        getdata_after_inv(&hub, &peer, &window),
        window,
        "a peer with room in its window is asked at once"
    );
    let extra = announced_hash(MAX_PEER_TX_REQUEST_IN_FLIGHT as u32);
    let extra_inv = Inventory::WTx(bitcoin::Wtxid::from_byte_array(extra));
    assert!(
        getdata_after_inv(&hub, &peer, &[extra_inv]).is_empty(),
        "a peer with a full window is not asked at once"
    );
    assert!(
        mp.take_due_parent_getdata(peer.id, 1_000 + OVERLOADED_PEER_TX_DELAY_SECS - 1)
            .is_empty(),
        "not before the overloaded delay ends"
    );
    let due = mp.take_due_parent_getdata(peer.id, 1_000 + OVERLOADED_PEER_TX_DELAY_SECS);
    assert_eq!(due.len(), 1, "asked when the delay ends");
    assert_eq!(due[0].hash, extra);
    assert!(due[0].wtxid);
    let _ = std::fs::remove_dir_all(dir);
}

/// A peer with the relay permission is never overloaded (Core
/// `m_relay_permissions`), however many requests it has outstanding.
#[tokio::test]
async fn relay_permitted_peer_is_asked_at_once_past_a_full_window() {
    use rbitcoin_net::tx_relay::MAX_PEER_TX_REQUEST_IN_FLIGHT;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("relay-perm-window");
    enable_tx_inv(&dir, &hub);
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_000);
    peers.set_relay_perm(true);
    let peer = preferred_peer(&peers, 2);
    let window: Vec<Inventory> = (0..MAX_PEER_TX_REQUEST_IN_FLIGHT as u32)
        .map(|i| Inventory::WTx(bitcoin::Wtxid::from_byte_array(announced_hash(i))))
        .collect();
    assert_eq!(getdata_after_inv(&hub, &peer, &window), window);
    let extra = Inventory::WTx(bitcoin::Wtxid::from_byte_array(announced_hash(
        MAX_PEER_TX_REQUEST_IN_FLIGHT as u32,
    )));
    assert_eq!(
        getdata_after_inv(&hub, &peer, &[extra]),
        vec![extra],
        "the relay permission keeps a full window from delaying the ask"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Core `TXID_RELAY_DELAY`: a txid announcement waits while any wtxid-relay
/// peer is connected, so a wtxid announcer of the same transaction wins.
/// With no wtxid-relay peer, or for a wtxid announcement, it does not wait.
#[tokio::test]
async fn txid_announcement_waits_while_a_wtxid_relay_peer_is_connected() {
    use rbitcoin_net::tx_relay::TXID_RELAY_DELAY_SECS;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("txid-relay-delay");
    enable_tx_inv(&dir, &hub);
    let mp = hub.mempool().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    peers.set_mock_now(1_000);
    let txid_peer = preferred_peer(&peers, 2);
    let alone = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(announced_hash(1)));
    assert_eq!(
        getdata_after_inv(&hub, &txid_peer, &[alone]),
        vec![alone],
        "no wtxid-relay peer is connected: asked at once"
    );

    let wtxid_peer = preferred_peer(&peers, 3);
    wtxid_peer.set_wtxid_relay();
    let waits = announced_hash(2);
    let waits_inv = Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(waits));
    assert!(
        getdata_after_inv(&hub, &txid_peer, &[waits_inv]).is_empty(),
        "a wtxid-relay peer is connected: the txid announcement waits"
    );
    assert!(mp
        .take_due_parent_getdata(txid_peer.id, 1_000 + TXID_RELAY_DELAY_SECS - 1)
        .is_empty());
    let due = mp.take_due_parent_getdata(txid_peer.id, 1_000 + TXID_RELAY_DELAY_SECS);
    assert_eq!(due.len(), 1, "asked when the delay ends");
    assert_eq!(due[0].hash, waits);
    assert!(!due[0].wtxid);

    let by_wtxid = Inventory::WTx(bitcoin::Wtxid::from_byte_array(announced_hash(3)));
    assert_eq!(
        getdata_after_inv(&hub, &wtxid_peer, &[by_wtxid]),
        vec![by_wtxid],
        "a wtxid announcement never waits for the txid delay"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// `unregister` forgets a peer's rows before the peer leaves the live list.
/// An orphan's other announcer seen in that gap takes no parent row, so no
/// row outlives its session.
#[tokio::test]
async fn forgotten_announcer_takes_no_orphan_parent_row() {
    use bitcoin::hashes::Hash;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("parent-forgotten");
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let mp = hub.mempool().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let sender = inbound_peer(&peers);
    let gone = inbound_peer(&peers);
    assert_ne!(sender.id, gone.id);
    let parent = bitcoin::Txid::from_byte_array([0x55; 32]);
    let orphan = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::new(parent, 0),
            ..Default::default()
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    let wtxid = orphan.compute_wtxid();
    assert_eq!(
        mp.note_inv_tx_requested(
            rbitcoin_net::tx_relay::InvSource::new(gone.id, true),
            wtxid.to_byte_array(),
            1_000,
            true
        ),
        rbitcoin_net::tx_relay::ParentNote::RequestNow
    );
    mp.forget_parent_anns_for_peer(gone.id);
    assert!(peers.get(gone.id).is_some(), "still on the live list");
    schedule_orphan_parent_getdata(mp, &orphan, Some(&sender), &[gone.id]);
    assert_eq!(
        mp.announcer_peers_for(&parent, &bitcoin::Wtxid::from_byte_array([0x55; 32])),
        vec![sender.id],
        "the forgotten announcer has no row left to clean"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// 1001 due wtxids drain under the global count cap, and each INV charges
/// the send budget.
#[tokio::test(flavor = "current_thread")]
async fn tx_inv_drains_one_thousand_under_the_count_cap() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-batch");
    let hub = std::sync::Arc::new(hub);
    hub.ensure_genesis().unwrap();
    hub.confirm_empty_regtest(101).unwrap();
    let t = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(t) + 1);
    assert!(!hub.in_ibd(), "tx inv batch pin is not IBD");
    let coinbase = hub
        .query
        .reconstruct_block_at_height(rbitcoin_primitives::Height(1))
        .unwrap()
        .txdata[0]
        .clone();
    let each = coinbase.output[0].value.to_sat() / 2 / 1001;
    assert!(each > 2_000, "coinbase must fund 1001 spends");
    let fanout = bitcoin::Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: coinbase.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: (0..1001)
            .map(|_| TxOut {
                value: Amount::from_sat(each),
                script_pubkey: op_true(),
            })
            .collect(),
    };
    hub.mine(1, op_true(), vec![fanout.clone()]).unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    assert!(hub.attach_mempool(mp).is_ok());
    let mempool = hub.mempool().unwrap();
    let parent = fanout.compute_txid();
    for vout in 0..1001u32 {
        let child = bitcoin::Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint { txid: parent, vout },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(each - 1_000),
                script_pubkey: op_true(),
            }],
        };
        mempool
            .admit(&child)
            .unwrap_or_else(|e| panic!("accept vout {vout}: {e}"));
    }
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 9));
    let ver = bitcoin::p2p::message_network::VersionMessage {
        version: 70016,
        services: bitcoin::p2p::ServiceFlags::NETWORK,
        timestamp: 0,
        receiver: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        sender: bitcoin::p2p::address::Address::new(&addr, bitcoin::p2p::ServiceFlags::NONE),
        nonce: 9,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    let peer = peers.register(
        addr,
        addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    );
    let (out_tx, mut rx) = peer.open_out();
    let before = peer.send_queued();
    let mut unread = Vec::new();
    let mut total = 0usize;
    for step in 0..40 {
        if step > 0 {
            let now = u64::from(t) + 1 + step * 10;
            hub.clock.set_mock(now as i64);
            mempool.note_mock_now(now);
        }
        queue_due_tx_invs(&hub, peer.as_ref(), &CappedSet::new(), &out_tx);
        while let Ok(q) = rx.try_recv() {
            let PeerOut::Msg(NetworkMessage::Inv(v)) = q.out() else {
                panic!("expected inv, got {:?}", q.out());
            };
            assert!(
                v.len() <= 490,
                "a full count bucket releases 490, got {}",
                v.len()
            );
            total += v.len();
            unread.push(q);
        }
        if total == 1001 {
            break;
        }
    }
    assert_eq!(
        total, 1001,
        "every accepted tx is announced as tokens refill"
    );
    assert!(
        peer.send_queued() > before,
        "batched inv must charge the send budget"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// FNV-1a of the address bytes. Duplicated here so a broken mixer in
/// `addr_relay_key` cannot satisfy the assertion by changing both sides.
fn addr_key_oracle(msg: &bitcoin::p2p::address::AddrV2Message) -> u64 {
    let raw = bitcoin::consensus::encode::serialize(msg);
    let mut h = 0xcbf29ce484222325u64;
    for b in raw {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[test]
fn invalid_script_is_scored_and_policy_is_not() {
    use rbitcoin_mempool::AcceptError;
    assert_eq!(
        rbitcoin_net::peer::tx_reject_ban_score(&AcceptError::Script("script false".into())),
        10
    );
    assert_eq!(
        rbitcoin_net::peer::tx_reject_ban_score(&AcceptError::Policy("min relay fee")),
        0
    );
}

include!("../peer_catchup_journey.rs");
include!("../peer_hostile_journey.rs");
include!("../peer_tip_announce_journey.rs");
include!("../peer_header_dos_journey.rs");
include!("../peer_blocksonly_journey.rs");

/// A headers batch and a getheaders reply must not read or write the store
/// on the session worker.
#[test]
fn headers_store_runs_off_the_reactor() {
    use bitcoin::block::{Header, Version};
    use bitcoin::p2p::message_blockdata::GetHeadersMessage;
    use bitcoin::CompactTarget;
    use bitcoin::TxMerkleNode;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("headers-off-reactor");
    hub.ensure_genesis().unwrap();
    let prev = hub.tip_hash().unwrap();
    let hdr = Header {
        version: Version::TWO,
        prev_blockhash: prev,
        merkle_root: TxMerkleNode::from_byte_array([1u8; 32]),
        time: 1_700_000_000,
        bits: CompactTarget::from_consensus(0x207fffff),
        nonce: 1,
    };
    let hub = hub.into_arc();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, _rx) = peer_out_channel();
            let mut follow = PeerFollowState::new();
            let gh = GetHeadersMessage::new(vec![], BlockHash::from_byte_array([0u8; 32]));
            on_getheaders(&hub, &out_tx, &mut follow, None, &gh)
                .await
                .expect("getheaders");
            on_headers(&hub, &out_tx, &mut follow, None, &[hdr])
                .await
                .expect("headers");
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// Inbound compact reconstruction must not run on the session worker.
#[test]
fn inbound_cmpct_reconstruct_runs_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-recon-off-reactor");
    hub.ensure_genesis().unwrap();
    let block = block_for_peer(&hub.cache, &hub.query, &hub.tip_hash().unwrap())
        .unwrap()
        .expect("genesis");
    let hash = block.block_hash();
    let hsi = HeaderAndShortIds::from_block(&block, 1, 2, &[0]).unwrap();
    // A live node holds the hub in an `Arc`, so accept awaits the tip lane.
    let hub = hub.into_arc();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, _rx) = peer_out_channel();
            let mut follow = PeerFollowState::new();
            follow.requested_blocks.ask(&hub, hash);
            on_cmpctblock_reconstruct(&hub, &out_tx, &mut follow, None, &hsi, hash)
                .await
                .expect("reconstruct");
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// A store error on an announced tip wtxid is `notfound`, not a dropped peer.
#[test]
fn announced_wtx_store_error_is_notfound() {
    let miss = announced_wtx_from_reconstruct(Err(NetError::Consensus("disk".into())));
    assert!(miss.is_none(), "a store error is notfound");
    assert!(announced_wtx_from_reconstruct(Ok(None)).is_none());
    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let hit = announced_wtx_from_reconstruct(Ok(Some(tx))).expect("tx kept");
    assert!(hit.input.is_empty());
}

/// A failed compact-relay blocking job is a protocol error, not a missing body.
#[tokio::test]
async fn cmpct_relay_join_failure_is_protocol() {
    let joined = tokio::task::spawn_blocking(|| -> Option<NetworkMessage> {
        panic!("short ids");
    })
    .await;
    let err = map_cmpct_relay_join(joined).expect_err("join failure");
    assert!(err.to_string().contains("cmpct relay join failed"), "{err}");
}

/// A headers batch already taken off the socket is stored when the send
/// budget is spent. The locator latch clears and nothing else is queued.
#[tokio::test]
async fn over_budget_headers_are_stored_without_a_follow_up() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-over-budget");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18510, 31, false);
    peer.note_awaiting_headers();
    let _budget = hold_send_bytes(&peer, rbitcoin_net::peers::PEER_SEND_BUDGET + 1);
    assert!(peer.send_over_budget());
    let header = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time.saturating_add(600),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    )
    .header;
    let hash = header.block_hash();
    let (out_tx, mut out_rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    handle_decoded_peer_msg(
        RawNetworkMessage::new(
            Magic::from(Network::Regtest),
            NetworkMessage::Headers(vec![header]),
        ),
        &hub,
        &out_tx,
        &mut follow,
        Some(peer.as_ref()),
    )
    .await
    .expect("headers");
    assert!(!peer.is_awaiting_headers(), "the locator latch clears");
    assert!(
        out_rx.try_recv().is_err(),
        "no getdata or getheaders while the send budget is spent"
    );
    assert!(hub.header_of(&hash).is_some(), "the header is stored");
    assert!(
        !hub.already_have_or_asked_block(&hash),
        "an unsent body is not left in flight"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A closed writer fails the getdata. The claim from that attempt is released
/// so another peer can ask.
#[tokio::test]
async fn failed_body_queue_releases_the_ask() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-ask-release");
    hub.ensure_genesis().unwrap();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let peer = live_peer(&peers, 18511, 32, false);
    let header = rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time.saturating_add(600),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    )
    .header;
    let hash = header.block_hash();
    let (out_tx, out_rx) = peer_out_channel();
    drop(out_rx);
    let mut follow = PeerFollowState::new();
    let err = on_headers(&hub, &out_tx, &mut follow, Some(peer.as_ref()), &[header])
        .await
        .expect_err("closed writer");
    assert!(err.to_string().contains("peer write half closed"), "{err}");
    assert!(!hub.already_have_or_asked_block(&hash));
    assert!(!follow.requested_blocks.contains(&hash));
    assert!(hub.header_of(&hash).is_some(), "the header is stored");
    let _ = std::fs::remove_dir_all(&dir);
}

fn hb_tip_child(hub: &rbitcoin_net::chain::ChainHub) -> bitcoin::Block {
    rbitcoin_consensus::mine_regtest_paying(
        hub.tip_hash().unwrap(),
        hub.tip_header().unwrap().time.saturating_add(600),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    )
}

/// No offered high-bandwidth peer means the compact build does not run.
/// `from` has a live hub, so this reaches the offer filter. The build
/// persists the header, so its absence shows the build was skipped.
#[test]
fn hb_relay_skips_the_build_when_no_peer_is_offered_it() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-relay-no-peer");
    hub.ensure_genesis().unwrap();
    hub.set_prefill_compact(true);
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18520, 41, false);
    let quiet = live_peer(&peers, 18521, 42, false);
    quiet.note_best_known(hub.tip_hash().unwrap());
    let block = hb_tip_child(&hub);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(
        !hub.knows_header(&block.block_hash()),
        "a peer that was not offered the block does not persist its header"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Outbound compact push follows transaction relay. A fresh tip with relay
/// still off has nothing in the pool for the next block, so an offered peer
/// gets a header path instead. IBD and `-blocksonly` do not push one either.
#[tokio::test]
async fn compact_push_follows_tx_relay() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-push-pack");
    hub.ensure_genesis().unwrap();
    hub.set_prefill_compact(true);
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(
        dir.path().join("mp"),
        std::sync::Arc::clone(&hub.query),
    )
    .unwrap();
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    assert!(hub.in_ibd());
    assert!(!mp.relay_enabled());
    let genesis = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18530, 51, false);
    let target = live_peer(&peers, 18531, 52, false);
    target.set_hb_from(true);
    target.note_best_known(genesis);
    let (_, mut out_rx) = target.open_out();
    relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
    assert!(
        out_rx.try_recv().is_err(),
        "IBD does not push a compact block"
    );

    hub.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    assert!(!hub.in_ibd());
    relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
    assert!(
        out_rx.try_recv().is_err(),
        "a fresh tip does not push a compact block while tx relay is off"
    );
    mp.set_relay_enabled(true);
    relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
    assert!(
        matches!(
            out_rx.try_recv().map(Queued::expect_msg),
            Ok(NetworkMessage::CmpctBlock(_))
        ),
        "tx relay pushes a compact block"
    );
    assert!(
        out_rx.try_recv().is_err(),
        "one compact block, not a fee filter"
    );
    assert!(mp.relay_enabled(), "a compact push does not clear tx relay");

    let (bo_dir, bo) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-push-bo");
    bo.ensure_genesis().unwrap();
    bo.set_prefill_compact(true);
    bo.set_blocks_only(true);
    bo.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    let bo_mp = rbitcoin_net::tx_relay::MempoolHub::open(
        bo_dir.path().join("mp"),
        std::sync::Arc::clone(&bo.query),
    )
    .unwrap();
    assert!(bo.attach_mempool(std::sync::Arc::clone(&bo_mp)).is_ok());
    let bo_tip = bo.tip_hash().unwrap();
    let bo_block = hb_tip_child(&bo);
    let bo_peers = rbitcoin_net::peers::PeerHub::new();
    let bo_from = live_peer(&bo_peers, 18532, 53, false);
    let bo_target = live_peer(&bo_peers, 18533, 54, false);
    bo_target.set_hb_from(true);
    bo_target.note_best_known(bo_tip);
    let (_, mut bo_rx) = bo_target.open_out();
    relay_new_pow_valid_block(&bo, &bo_block, Some(bo_from.as_ref())).await;
    assert!(
        bo_rx.try_recv().is_err(),
        "blocksonly does not push a compact block"
    );
    assert!(!bo_mp.relay_enabled());
}

/// The compact announce goes out before connect. A high-bandwidth peer that
/// answers at once still gets the missing transaction. A peer that did not
/// ask for high-bandwidth is not offered the block.
#[test]
fn hb_compact_announce_serves_the_missing_tx() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-serves");
    hub.ensure_genesis().unwrap();
    let genesis = hub.tip_hash().unwrap();
    for _ in 0..=MAX_GETBLOCKTXN_DEPTH {
        hub.accept_block(hb_tip_child(&hub)).unwrap();
    }
    let tip_h = hub.tip_height().unwrap();
    assert!(
        tip_h > MAX_GETBLOCKTXN_DEPTH,
        "the getblocktxn depth fallback is in range"
    );
    let deep = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: genesis,
            indexes: vec![0],
        },
        tip_h,
    )
    .expect("deep getblocktxn");
    assert!(
        matches!(deep, Some(GetBlockTxnServe::Block(_))),
        "a connected block older than the depth is the full block"
    );
    let deep_cmpct = compact_serve_outcome(&hub.cache, &hub.query, &genesis, tip_h, 2, vec![0])
        .expect("deep compact getdata");
    assert!(
        matches!(deep_cmpct, CompactServe::Full(_)),
        "a connected block older than the compact depth is the full block"
    );
    hub.set_prefill_compact(true);
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(
        dir.path().join("mp"),
        std::sync::Arc::clone(&hub.query),
    )
    .unwrap();
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    hub.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    mp.set_relay_enabled(true);
    let tip = hub.tip_hash().unwrap();
    let extra = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let block = rbitcoin_consensus::mine_regtest_paying(
        tip,
        hub.tip_header().unwrap().time.saturating_add(600),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![extra.clone()],
    );
    let hash = block.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18540, 61, false);
    let target = live_peer(&peers, 18541, 62, false);
    target.set_hb_from(true);
    target.note_best_known(tip);
    let quiet = live_peer(&peers, 18542, 63, false);
    quiet.note_best_known(tip);
    let (_, mut out_rx) = target.open_out();
    let (_, mut quiet_rx) = quiet.open_out();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(
        matches!(
            out_rx.try_recv().map(Queued::expect_msg),
            Ok(NetworkMessage::CmpctBlock(_))
        ),
        "the high-bandwidth peer is announced the compact block"
    );
    assert!(
        quiet_rx.try_recv().is_err(),
        "a peer that did not ask for high-bandwidth is not announced this block"
    );
    assert!(!hub.has_block(&hash), "the announce races the body write");
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![1],
        },
        hub.tip_height().unwrap(),
    )
    .expect("getblocktxn");
    let Some(GetBlockTxnServe::Txns(bt)) = reply else {
        panic!("the missing transaction is served before the body is connected");
    };
    assert_eq!(bt.transactions.len(), 1);
    assert_eq!(bt.transactions[0].compute_txid(), extra.compute_txid());
    let encoded = encode_served_block(&hub.cache, &hub.query, &hash, true)
        .expect("getdata")
        .expect("full-block getdata serves the announced body");
    assert_eq!(encoded.first().copied(), Some(2), "v2 block short id");
    let served: bitcoin::Block =
        bitcoin::consensus::encode::deserialize(&encoded[1..]).expect("served block");
    assert_eq!(served.txdata[1].compute_txid(), extra.compute_txid());
    let staged = compact_serve_outcome(
        &hub.cache,
        &hub.query,
        &hash,
        hub.tip_height().unwrap(),
        2,
        vec![0],
    )
    .expect("compact getdata");
    assert!(
        matches!(staged, CompactServe::Cmpct(_)),
        "a staged tip child stays a compact block when the tip is past the compact depth"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A sibling wins the tip after the compact announce. Accept of the announced
/// block does not connect it, and the store still cannot reconstruct it.
#[test]
fn hb_announce_stays_servable_when_a_sibling_wins() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-weaker");
    hub.ensure_genesis().unwrap();
    for _ in 0..=MAX_GETBLOCKTXN_DEPTH {
        hub.accept_block(hb_tip_child(&hub)).unwrap();
    }
    assert!(hub.tip_height().unwrap() > MAX_GETBLOCKTXN_DEPTH);
    hub.set_prefill_compact(true);
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(
        dir.path().join("mp"),
        std::sync::Arc::clone(&hub.query),
    )
    .unwrap();
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    hub.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    mp.set_relay_enabled(true);
    let tip = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let hash = block.block_hash();
    let coinbase = block.txdata[0].compute_txid();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18543, 64, false);
    let target = live_peer(&peers, 18544, 65, false);
    target.set_hb_from(true);
    target.note_best_known(tip);
    let (_, mut out_rx) = target.open_out();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(
        matches!(
            out_rx.try_recv().map(Queued::expect_msg),
            Ok(NetworkMessage::CmpctBlock(_))
        ),
        "the high-bandwidth peer is announced the compact block"
    );
    hub.drop_held(hash);
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .expect("getblocktxn after drop_held");
    let Some(GetBlockTxnServe::Txns(bt)) = reply else {
        panic!("dropping the hold must not forget the announced body");
    };
    assert_eq!(bt.transactions[0].compute_txid(), coinbase);
    let sibling = rbitcoin_consensus::mine_regtest_paying(
        tip,
        hub.tip_header().unwrap().time.saturating_add(1200),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    hub.accept_block(sibling).expect("sibling connects");
    let weaker = rt
        .block_on(accept_received_from_peer(&hub, block, Some(from.as_ref())))
        .expect("announced sibling is not a peer fault");
    assert_eq!(
        weaker,
        rbitcoin_net::chain::AcceptOutcome::IgnoredWeaker,
        "the announced block lost the tip"
    );
    assert!(
        !hub.has_block(&hash),
        "the announced sibling is not connected"
    );
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .expect("getblocktxn after the weaker accept");
    let Some(GetBlockTxnServe::Txns(bt)) = reply else {
        panic!("a weaker accept must not forget the announced body");
    };
    assert_eq!(bt.transactions[0].compute_txid(), coinbase);
    run_on_tip_accept(|| hub.invalidate_block_inner(hash))
        .expect("the lost block can be invalidated");
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .expect("getblocktxn after invalidate");
    assert!(reply.is_none(), "an invalidated block is not served");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Accept of the announced block can return `Accepted` because a different
/// held branch connected. That result must not drop the staged body.
#[test]
fn hb_announce_stays_servable_when_another_held_branch_connects() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-other-branch");
    hub.ensure_genesis().unwrap();
    for _ in 0..=MAX_GETBLOCKTXN_DEPTH {
        hub.accept_block(hb_tip_child(&hub)).unwrap();
    }
    assert!(hub.tip_height().unwrap() > MAX_GETBLOCKTXN_DEPTH);
    let fork_h = hub.tip_height().unwrap().saturating_sub(1);
    let fork = hub
        .block_at_height(fork_h)
        .unwrap()
        .expect("parent of the tip");
    let base = hub.tip_header().unwrap().time;
    let spk = ScriptBuf::from_bytes(vec![0x51]);
    let p1 = rbitcoin_consensus::mine_regtest_paying(
        fork.block_hash(),
        base.saturating_add(600),
        fork_h.saturating_add(1),
        spk.clone(),
        vec![],
    );
    let p2 = rbitcoin_consensus::mine_regtest_paying(
        p1.block_hash(),
        base.saturating_add(1200),
        fork_h.saturating_add(2),
        spk.clone(),
        vec![],
    );
    let p3 = rbitcoin_consensus::mine_regtest_paying(
        p2.block_hash(),
        base.saturating_add(1800),
        fork_h.saturating_add(3),
        spk,
        vec![],
    );
    hub.hold_unconnected_body(p1);
    hub.hold_unconnected_body(p2);
    hub.hold_unconnected_body(p3);
    hub.set_prefill_compact(true);
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(
        dir.path().join("mp"),
        std::sync::Arc::clone(&hub.query),
    )
    .unwrap();
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    hub.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    mp.set_relay_enabled(true);
    let tip = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let hash = block.block_hash();
    let coinbase = block.txdata[0].compute_txid();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18545, 66, false);
    let target = live_peer(&peers, 18546, 67, false);
    target.set_hb_from(true);
    target.note_best_known(tip);
    let (_, mut out_rx) = target.open_out();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(
        matches!(
            out_rx.try_recv().map(Queued::expect_msg),
            Ok(NetworkMessage::CmpctBlock(_))
        ),
        "the high-bandwidth peer is announced the compact block"
    );
    let sibling = rbitcoin_consensus::mine_regtest_paying(
        tip,
        hub.tip_header().unwrap().time.saturating_add(1200),
        hub.tip_height().unwrap().saturating_add(1),
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    assert_ne!(sibling.block_hash(), hash);
    hub.accept_block(sibling).expect("sibling connects");
    let outcome = rt
        .block_on(accept_received_from_peer(&hub, block, Some(from.as_ref())))
        .expect("announced block is not a peer fault");
    assert!(
        matches!(outcome, rbitcoin_net::chain::AcceptOutcome::Accepted { .. }),
        "a heavier held branch connects, got {outcome:?}"
    );
    assert!(
        !hub.has_block(&hash),
        "the announced block was not the one that connected"
    );
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .expect("getblocktxn after the other branch");
    let Some(GetBlockTxnServe::Txns(bt)) = reply else {
        panic!("accepting a different branch must not forget the announced body");
    };
    assert_eq!(bt.transactions[0].compute_txid(), coinbase);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A compact announce of a block the clock still calls too new stays
/// servable. The failure is not a permanent reject.
#[test]
fn hb_announce_stays_servable_when_the_block_is_too_new() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-too-new");
    hub.ensure_genesis().unwrap();
    hub.set_prefill_compact(true);
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(
        dir.path().join("mp"),
        std::sync::Arc::clone(&hub.query),
    )
    .unwrap();
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    hub.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    mp.set_relay_enabled(true);
    let tip = hub.tip_hash().unwrap();
    let now = hub.tip_header().unwrap().time;
    hub.clock.set_mock(i64::from(now));
    let block = rbitcoin_consensus::mine_regtest_paying(
        tip,
        now.saturating_add(600),
        1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    let hash = block.block_hash();
    let coinbase = block.txdata[0].compute_txid();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18547, 68, false);
    let target = live_peer(&peers, 18548, 69, false);
    target.set_hb_from(true);
    target.note_best_known(tip);
    let (_, mut out_rx) = target.open_out();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(
        matches!(
            out_rx.try_recv().map(Queued::expect_msg),
            Ok(NetworkMessage::CmpctBlock(_))
        ),
        "the high-bandwidth peer is announced the compact block"
    );
    // The header was acceptable when it was announced. The clock then sits
    // more than two hours behind that stamp, which is not a permanent reject.
    hub.clock.set_mock(i64::from(now) - 3 * 3600);
    let err = rt
        .block_on(accept_received_from_peer(&hub, block, Some(from.as_ref())))
        .expect_err("the block is still too new");
    let msg = err
        .consensus_rules()
        .map(rbitcoin_consensus::block_reject_reason)
        .unwrap_or_else(|| panic!("expected a rule failure, got {err:?}"));
    assert!(msg.contains("time-too-new"), "got {msg}");
    assert!(!hub.is_block_invalid(&hash));
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .expect("getblocktxn after time-too-new");
    let Some(GetBlockTxnServe::Txns(bt)) = reply else {
        panic!("a not-yet-valid timestamp must not forget the announced body");
    };
    assert_eq!(bt.transactions[0].compute_txid(), coinbase);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The parent was invalidated after the compact announce. `bad-prevblk` is
/// not a mark on this hash, and the staged body still answers `getblocktxn`.
#[test]
fn hb_announce_stays_servable_when_the_parent_is_invalid() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-bad-prev");
    hub.ensure_genesis().unwrap();
    hub.accept_block(hb_tip_child(&hub)).unwrap();
    hub.set_prefill_compact(true);
    let mp = rbitcoin_net::tx_relay::MempoolHub::open(
        dir.path().join("mp"),
        std::sync::Arc::clone(&hub.query),
    )
    .unwrap();
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    hub.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    mp.set_relay_enabled(true);
    let tip = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let hash = block.block_hash();
    let coinbase = block.txdata[0].compute_txid();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18549, 70, false);
    let target = live_peer(&peers, 18550, 71, false);
    target.set_hb_from(true);
    target.note_best_known(tip);
    let (_, mut out_rx) = target.open_out();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(
        matches!(
            out_rx.try_recv().map(Queued::expect_msg),
            Ok(NetworkMessage::CmpctBlock(_))
        ),
        "the high-bandwidth peer is announced the compact block"
    );
    run_on_tip_accept(|| hub.invalidate_block_inner(tip)).expect("parent can be invalidated");
    let still = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .expect("getblocktxn after the parent is invalidated");
    assert!(
        matches!(still, Some(GetBlockTxnServe::Txns(_))),
        "invalidating the parent does not drop the announced body"
    );
    let err = rt
        .block_on(accept_received_from_peer(&hub, block, Some(from.as_ref())))
        .expect_err("the parent is invalid");
    let msg = match &err {
        rbitcoin_net::error::NetError::Consensus(m) => m.clone(),
        other => panic!("expected bad-prevblk, got {other:?}"),
    };
    assert!(msg.contains("bad-prevblk"), "got {msg}");
    assert!(
        !hub.invalid_blocks().contains(&hash),
        "bad-prevblk must not mark the announced hash"
    );
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .expect("getblocktxn after bad-prevblk");
    let Some(GetBlockTxnServe::Txns(bt)) = reply else {
        panic!("bad-prevblk must not forget the announced body");
    };
    assert_eq!(bt.transactions[0].compute_txid(), coinbase);
    let _ = std::fs::remove_dir_all(&dir);
}

fn hb_relay_ready(
    hub: &rbitcoin_net::chain::ChainHub,
    dir: &std::path::Path,
) -> std::sync::Arc<rbitcoin_net::tx_relay::MempoolHub> {
    hub.set_prefill_compact(true);
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), std::sync::Arc::clone(&hub.query))
            .unwrap();
    assert!(hub.attach_mempool(std::sync::Arc::clone(&mp)).is_ok());
    hub.finished_ibd
        .store(true, std::sync::atomic::Ordering::Release);
    mp.set_relay_enabled(true);
    mp
}

/// The lost compact block is still the requested transactions while it is
/// near the tip. Once the winning chain is more than ten blocks past its
/// height, `getblocktxn` and compact `getdata` are the full block.
#[test]
fn hb_announce_ages_out_of_the_compact_window() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-ages");
    hub.ensure_genesis().unwrap();
    let _mp = hb_relay_ready(&hub, dir.path());
    let tip = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let hash = block.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18551, 72, false);
    let target = live_peer(&peers, 18552, 73, false);
    target.set_hb_from(true);
    target.note_best_known(tip);
    let (_, mut out_rx) = target.open_out();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(matches!(
        out_rx.try_recv().map(Queued::expect_msg),
        Ok(NetworkMessage::CmpctBlock(_))
    ));
    let sibling = rbitcoin_consensus::mine_regtest_paying(
        tip,
        hub.tip_header().unwrap().time.saturating_add(1200),
        1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    hub.accept_block(sibling).unwrap();
    let near = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .unwrap();
    assert!(
        matches!(near, Some(GetBlockTxnServe::Txns(_))),
        "a one-block-deep loser is still the requested transactions"
    );
    // Height 1 at tip 7 is depth 6: compact is already the full block,
    // getblocktxn is not. Treating the height as 0 would already be a
    // full getblocktxn here only at a higher tip; tip 11 is that split.
    while hub.tip_height().unwrap() < MAX_CMPCTBLOCK_DEPTH + 2 {
        hub.accept_block(hb_tip_child(&hub)).unwrap();
    }
    assert_eq!(hub.tip_height().unwrap(), 7);
    let mid_tx = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .unwrap();
    assert!(
        matches!(mid_tx, Some(GetBlockTxnServe::Txns(_))),
        "depth 6 is still the requested transactions"
    );
    let mid_cmpct = compact_serve_outcome(
        &hub.cache,
        &hub.query,
        &hash,
        hub.tip_height().unwrap(),
        2,
        vec![0],
    )
    .unwrap();
    assert!(
        matches!(mid_cmpct, CompactServe::Full(_)),
        "depth 6 is past the compact window"
    );
    while hub.tip_height().unwrap() < MAX_GETBLOCKTXN_DEPTH + 1 {
        hub.accept_block(hb_tip_child(&hub)).unwrap();
    }
    assert_eq!(hub.tip_height().unwrap(), 11);
    let still = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .unwrap();
    assert!(
        matches!(still, Some(GetBlockTxnServe::Txns(_))),
        "depth 10 is not yet the full block"
    );
    hub.accept_block(hb_tip_child(&hub)).unwrap();
    assert_eq!(hub.tip_height().unwrap(), 12);
    assert!(!hub.has_block(&hash));
    let aged = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .unwrap();
    assert!(
        matches!(aged, Some(GetBlockTxnServe::Block(_))),
        "a loser more than ten below the tip is the full block"
    );
    let cmpct = compact_serve_outcome(
        &hub.cache,
        &hub.query,
        &hash,
        hub.tip_height().unwrap(),
        2,
        vec![0],
    )
    .unwrap();
    assert!(
        matches!(cmpct, CompactServe::Full(_)),
        "a loser more than five below the tip is not a compact block"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A one-block reorg disconnects the announced block's parent. The served
/// height is still two (confirmed genesis plus two steps). That stays a
/// transaction reply at tip 11 and tip 12, where height 0 and height 1
/// would already be the full block, and becomes the full block at tip 13.
#[test]
fn hb_announce_ages_after_its_parent_is_disconnected() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-reorg-age");
    hub.ensure_genesis().unwrap();
    let _mp = hb_relay_ready(&hub, dir.path());
    hub.accept_block(hb_tip_child(&hub)).unwrap();
    let parent = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let hash = block.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18557, 78, false);
    let target = live_peer(&peers, 18558, 79, false);
    target.set_hb_from(true);
    target.note_best_known(parent);
    let (_, mut out_rx) = target.open_out();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(matches!(
        out_rx.try_recv().map(Queued::expect_msg),
        Ok(NetworkMessage::CmpctBlock(_))
    ));
    let genesis = hub.block_at_height(0).unwrap().expect("genesis");
    let base = hub.tip_header().unwrap().time;
    let spk = ScriptBuf::from_bytes(vec![0x52]);
    let c1 = rbitcoin_consensus::mine_regtest_paying(
        genesis.block_hash(),
        base.saturating_add(600),
        1,
        spk.clone(),
        vec![],
    );
    let c2 = rbitcoin_consensus::mine_regtest_paying(
        c1.block_hash(),
        base.saturating_add(1200),
        2,
        spk,
        vec![],
    );
    hub.accept_branch(&[std::sync::Arc::new(c1), std::sync::Arc::new(c2)])
        .expect("heavier branch connects");
    assert!(!hub.is_connected(&parent), "the parent left the best chain");
    assert!(!hub.has_block(&hash));
    assert_eq!(hub.tip_height().unwrap(), 2);
    let req = |tip: u32| {
        getblocktxn_reply(
            &hub.cache,
            &hub.query,
            BlockTransactionsRequest {
                block_hash: hash,
                indexes: vec![0],
            },
            tip,
        )
        .unwrap()
    };
    while hub.tip_height().unwrap() < MAX_GETBLOCKTXN_DEPTH + 1 {
        hub.accept_block(hb_tip_child(&hub)).unwrap();
    }
    assert_eq!(hub.tip_height().unwrap(), 11);
    assert!(
        matches!(req(11), Some(GetBlockTxnServe::Txns(_))),
        "height 2 is still the transactions at tip 11; height 0 would be the full block"
    );
    hub.accept_block(hb_tip_child(&hub)).unwrap();
    assert_eq!(hub.tip_height().unwrap(), 12);
    assert!(
        matches!(req(12), Some(GetBlockTxnServe::Txns(_))),
        "depth 10 is not yet the full block"
    );
    hub.accept_block(hb_tip_child(&hub)).unwrap();
    assert_eq!(hub.tip_height().unwrap(), 13);
    assert!(
        matches!(req(13), Some(GetBlockTxnServe::Block(_))),
        "a disconnected parent does not keep the loser in the transaction reply"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The confirmed ancestor of this side body is past the walk cap, and the
/// body's own height is the tip. Height 0 would already be the full block.
#[test]
fn hb_announce_long_side_chain_is_not_height_zero() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-long-side");
    hub.ensure_genesis().unwrap();
    let _mp = hb_relay_ready(&hub, dir.path());
    let genesis = hub.block_at_height(0).unwrap().expect("genesis");
    let base = genesis.header.time;
    for _ in 0..=MAX_GETBLOCKTXN_DEPTH + 1 {
        hub.accept_block(hb_tip_child(&hub)).unwrap();
    }
    let tip = hub.tip_height().unwrap();
    assert_eq!(tip, MAX_GETBLOCKTXN_DEPTH + 2);
    let mut prev = genesis.block_hash();
    let mut side_tip = None;
    let spk = ScriptBuf::from_bytes(vec![0x53]);
    for n in 1..=MAX_GETBLOCKTXN_DEPTH + 2 {
        let block = rbitcoin_consensus::mine_regtest_paying(
            prev,
            base.saturating_add(n * 600),
            n,
            spk.clone(),
            vec![],
        );
        if n <= MAX_GETBLOCKTXN_DEPTH + 1 {
            hub.ensure_header(&block.header).expect("side header");
        }
        prev = block.block_hash();
        side_tip = Some(block);
    }
    let block = side_tip.expect("side tip");
    let hash = block.block_hash();
    hub.cache.stage_servable(block);
    assert!(!hub.has_block(&hash));
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        tip,
    )
    .unwrap();
    assert!(
        matches!(reply, Some(GetBlockTxnServe::Txns(_))),
        "a side body past the walk cap is not height 0"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A side body a month behind the best header is not served on any path.
#[test]
fn hb_announce_month_old_side_body_is_not_served() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-stale");
    hub.ensure_genesis().unwrap();
    let _mp = hb_relay_ready(&hub, dir.path());
    let t0 = 1_700_000_000u32;
    hub.clock.set_mock(i64::from(t0));
    let tip = hub.tip_hash().unwrap();
    let block = rbitcoin_consensus::mine_regtest_paying(
        tip,
        t0,
        1,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    let hash = block.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18553, 74, false);
    let target = live_peer(&peers, 18554, 75, false);
    target.set_hb_from(true);
    target.note_best_known(tip);
    let (_, mut out_rx) = target.open_out();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(matches!(
        out_rx.try_recv().map(Queued::expect_msg),
        Ok(NetworkMessage::CmpctBlock(_))
    ));
    let sibling = rbitcoin_consensus::mine_regtest_paying(
        tip,
        t0,
        1,
        ScriptBuf::from_bytes(vec![0x51, 0x52]),
        vec![],
    );
    let sibling_hash = sibling.block_hash();
    hub.accept_block(sibling).unwrap();
    let best_time = t0 + rbitcoin_net::chain::STALE_RELAY_AGE_LIMIT_SECS as u32;
    hub.clock.set_mock(i64::from(best_time));
    let ahead = rbitcoin_consensus::mine_regtest_paying(
        sibling_hash,
        best_time,
        2,
        ScriptBuf::from_bytes(vec![0x51]),
        vec![],
    );
    hub.accept_block(ahead).unwrap();
    assert!(!hub.stale_relay_allowed(&hash));
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .unwrap();
    assert!(
        reply.is_none(),
        "getblocktxn is silent for a month-old side body"
    );
    let cmpct = compact_serve_outcome(
        &hub.cache,
        &hub.query,
        &hash,
        hub.tip_height().unwrap(),
        2,
        vec![0],
    )
    .unwrap();
    assert!(
        matches!(cmpct, CompactServe::Missing),
        "compact getdata is silent for a month-old side body"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Connecting the announced block drops the staged copy. The store answers
/// afterwards, including when connect was not this hash's own accept.
#[test]
fn hb_announce_drops_servable_once_connected() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-announce-connected");
    hub.ensure_genesis().unwrap();
    let _mp = hb_relay_ready(&hub, dir.path());
    let tip = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let hash = block.block_hash();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18555, 76, false);
    let target = live_peer(&peers, 18556, 77, false);
    target.set_hb_from(true);
    target.note_best_known(tip);
    let (_, mut out_rx) = target.open_out();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())));
    assert!(matches!(
        out_rx.try_recv().map(Queued::expect_msg),
        Ok(NetworkMessage::CmpctBlock(_))
    ));
    assert!(hub.cache.servable(&hash).is_some());
    hub.accept_block(block).unwrap();
    assert!(hub.has_block(&hash));
    assert!(
        hub.cache.servable(&hash).is_none(),
        "a connected body must not stay staged in front of the store"
    );
    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .unwrap();
    assert!(
        matches!(reply, Some(GetBlockTxnServe::Txns(_))),
        "the store still serves the connected body"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// One offered high-bandwidth peer builds the prefill and short ids off the
/// worker. `assert_not_reactor` panics if that build stays on `tokio-rt-worker`.
#[test]
fn hb_relay_offered_build_runs_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-relay-off-reactor");
    hub.ensure_genesis().unwrap();
    hub.set_prefill_compact(true);
    let genesis = hub.tip_hash().unwrap();
    let block = hb_tip_child(&hub);
    let hub = hub.into_arc();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let from = live_peer(&peers, 18522, 43, false);
    let target = live_peer(&peers, 18523, 44, false);
    target.set_hb_from(true);
    target.note_best_known(genesis);
    let (_, mut out_rx) = target.open_out();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            relay_new_pow_valid_block(&hub, &block, Some(from.as_ref())).await;
            assert!(
                matches!(
                    out_rx.try_recv().map(Queued::expect_msg),
                    Ok(NetworkMessage::CmpctBlock(_))
                ),
                "the offered peer receives the compact block"
            );
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// Compact tip short ids are built with the body load, off the session worker.
#[test]
fn cmpct_tip_announce_shortids_run_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-tip-off-reactor");
    hub.ensure_genesis().unwrap();
    let hub = hub.into_arc();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, mut out_rx) = peer_out_channel();
            let mut follow = PeerFollowState::new();
            follow.send_cmpct = true;
            follow.cmpct_version = 2;
            let ev = rbitcoin_net::chain::TipEvent {
                height: hub.tip_height().unwrap(),
                hash: hub.tip_hash().unwrap(),
                header: hub.tip_header().unwrap(),
                reorg_branch_len: 0,
            };
            on_tip_event(&hub, &out_tx, &mut follow, None, Ok(ev))
                .await
                .expect("tip");
            assert!(
                matches!(
                    out_rx.try_recv().map(Queued::expect_msg),
                    Ok(NetworkMessage::CmpctBlock(_))
                ),
                "genesis tip is a compact announcement"
            );
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

fn panic_text(err: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = err.downcast_ref::<String>() {
        return s.clone();
    }
    if let Some(s) = err.downcast_ref::<&str>() {
        return (*s).to_string();
    }
    String::new()
}

/// Compact serve, getblocktxn, and an announced tip wtxid each read the
/// block on the worker. That read is the reactor check.
#[test]
fn served_block_read_is_the_reactor_check() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("serve-reactor-check");
    hub.ensure_genesis().unwrap();
    let hash = hub.tip_hash().unwrap();
    let cache = Arc::clone(&hub.cache);
    let query = Arc::clone(&hub.query);
    let wtxid = bitcoin::Wtxid::from_byte_array([1u8; 32]);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let name = std::thread::current().name().unwrap_or("").to_string();
            assert!(
                name.starts_with("tokio-rt-worker"),
                "spawned task must run on a tokio worker, got {name:?}"
            );
            let assert_block_read = |err: Box<dyn std::any::Any + Send>| {
                let text = panic_text(err);
                assert!(
                    text.contains("block reconstruct"),
                    "the block read is the reactor check, got {text}"
                );
            };
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = compact_serve_outcome(cache.as_ref(), query.as_ref(), &hash, 0, 2, vec![0]);
            }))
            .expect_err("compact serve on tokio-rt-worker panics");
            assert_block_read(err);
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = getblocktxn_reply(
                    cache.as_ref(),
                    query.as_ref(),
                    BlockTransactionsRequest {
                        block_hash: hash,
                        indexes: vec![0],
                    },
                    0,
                );
            }))
            .expect_err("getblocktxn on tokio-rt-worker panics");
            assert_block_read(err);
            let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = tx_from_stored_block(cache.as_ref(), query.as_ref(), &hash, &wtxid);
            }))
            .expect_err("tip wtxid on tokio-rt-worker panics");
            assert_block_read(err);
        })
        .await
        .expect("worker")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// Compact getdata and an announced tip wtxid reconstruct off the reactor.
/// `assert_not_reactor` panics when `block_for_peer` runs on `tokio-rt-worker`.
#[test]
fn compact_and_wtxid_serve_run_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("compact-off-reactor");
    hub.ensure_genesis().unwrap();
    let hash = hub.tip_hash().unwrap();
    let block = block_for_peer(&hub.cache, &hub.query, &hash)
        .unwrap()
        .expect("genesis body");
    let wtxid = block.txdata[0].compute_wtxid();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let session = live_peer(&peers, 18450, 11, false);
    session.set_wtxid_relay();
    session.note_announced_tx(block.txdata[0].compute_txid(), wtxid);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        let hub = hub;
        tokio::spawn(async move {
            let (out_tx, mut out_rx) = peer_out_channel();
            let mut follow = PeerFollowState::new();
            follow.cmpct_version = 2;
            serve_getdata(
                &hub,
                &out_tx,
                &mut follow,
                Some(session.as_ref()),
                vec![Inventory::CompactBlock(hash)],
            )
            .await
            .expect("compact serve");
            assert!(
                matches!(
                    out_rx.try_recv().map(Queued::expect_msg),
                    Ok(NetworkMessage::CmpctBlock(_))
                ),
                "genesis getdata is a compact block"
            );
            let mut follow = PeerFollowState::new();
            serve_getdata(
                &hub,
                &out_tx,
                &mut follow,
                Some(session.as_ref()),
                vec![Inventory::WTx(wtxid)],
            )
            .await
            .expect("wtxid serve");
            assert!(
                matches!(
                    out_rx.try_recv().map(Queued::expect_msg),
                    Ok(NetworkMessage::Tx(_))
                ),
                "announced wtxid comes from the tip block"
            );
            let missing = bitcoin::BlockHash::from_byte_array([9u8; 32]);
            serve_getdata(
                &hub,
                &out_tx,
                &mut follow,
                Some(session.as_ref()),
                vec![Inventory::CompactBlock(missing)],
            )
            .await
            .expect("missing compact is not a session error");
            assert!(
                out_rx.try_recv().is_err(),
                "a header-less hash stays silent"
            );
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// Several announced wtxid getdatas, including ones the tip does not contain,
/// walk that tip once. A later getdata for the same tip does not walk again.
#[test]
fn announced_wtxid_getdata_scans_the_tip_once() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("tip-wtx-once");
    hub.ensure_genesis().unwrap();
    let hash = hub.tip_hash().unwrap();
    let block = block_for_peer(&hub.cache, &hub.query, &hash)
        .unwrap()
        .expect("genesis body");
    let real = block.txdata[0].compute_wtxid();
    let _ = hub.cache.take_body_loads();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let session = live_peer(&peers, 18570, 90, false);
    session.set_wtxid_relay();
    session.note_announced_tx(block.txdata[0].compute_txid(), real);
    let missing: Vec<bitcoin::Wtxid> = (1..5u8)
        .map(|n| {
            let mut bytes = [0u8; 32];
            bytes[0] = n;
            bitcoin::Wtxid::from_byte_array(bytes)
        })
        .collect();
    for wtxid in &missing {
        session.note_announced_tx(
            bitcoin::Txid::from_byte_array(wtxid.to_byte_array()),
            *wtxid,
        );
    }
    let _ = hub.take_tip_wtx_scans();
    let (out_tx, mut out_rx) = peer_out_channel();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        serve_getdata(
            &hub,
            &out_tx,
            &mut PeerFollowState::new(),
            Some(session.as_ref()),
            vec![
                Inventory::WTx(missing[0]),
                Inventory::WTx(real),
                Inventory::WTx(missing[1]),
                Inventory::WTx(missing[2]),
            ],
        )
        .await
        .expect("first getdata");
        serve_getdata(
            &hub,
            &out_tx,
            &mut PeerFollowState::new(),
            Some(session.as_ref()),
            vec![Inventory::WTx(missing[3])],
        )
        .await
        .expect("second getdata");
    });
    assert_eq!(
        hub.take_tip_wtx_scans(),
        1,
        "one tip builds one wtxid index"
    );
    let mut saw_tx = false;
    let mut notfound = Vec::new();
    while let Ok(msg) = out_rx.try_recv() {
        match Queued::expect_msg(msg) {
            NetworkMessage::Tx(tx) => {
                assert_eq!(tx.compute_wtxid(), real);
                saw_tx = true;
            }
            NetworkMessage::NotFound(items) => notfound.extend(items),
            other => panic!("unexpected getdata reply {other:?}"),
        }
    }
    assert!(saw_tx, "the announced tip transaction is served");
    assert_eq!(
        notfound.len(),
        4,
        "each missing wtxid is notfound: {notfound:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A peer without `wtxidrelay` heard of a tx by txid. When the tx confirms in
/// the tip before its getdata, the tip block still serves it, as Core's
/// `FindTxForGetData`: `MSG_TX` without the witness, `MSG_WITNESS_TX` with.
#[test]
fn announced_txid_getdata_serves_the_tip_tx() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("tip-txid-serve");
    let hub = Arc::new(hub);
    hub.ensure_genesis().unwrap();
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.join("mp"), Arc::clone(&hub.query)).unwrap();
    assert!(hub.attach_mempool(mp).is_ok());
    let op_true = ScriptBuf::from_bytes(vec![0x51]);
    let p2wsh = ScriptBuf::new_p2wsh(&op_true.wscript_hash());
    hub.mine(1, p2wsh.clone(), vec![]).unwrap();
    hub.confirm_empty_regtest(100).unwrap();
    let cb = hub
        .query
        .reconstruct_block_at_height(Height(1))
        .unwrap()
        .txdata[0]
        .clone();
    let spend = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cb.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::from_slice(&[op_true.as_bytes()]),
        }],
        output: vec![TxOut {
            value: cb.output[0].value - Amount::from_sat(10_000),
            script_pubkey: p2wsh,
        }],
    };
    let (txid, wtxid) = (spend.compute_txid(), spend.compute_wtxid());
    let peers = rbitcoin_net::peers::PeerHub::new();
    let session = live_peer(&peers, 18573, 93, false);
    assert_eq!(
        session.claim_announced_tx(txid, wtxid),
        Some(Inventory::Transaction(txid)),
        "a peer without wtxidrelay is announced the txid"
    );
    hub.mine(1, op_true, vec![spend.clone()]).unwrap();
    let _ = hub.take_tip_wtx_scans();
    let (out_tx, mut out_rx) = peer_out_channel();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(serve_getdata(
        &hub,
        &out_tx,
        &mut PeerFollowState::new(),
        Some(session.as_ref()),
        vec![
            Inventory::Transaction(txid),
            Inventory::WitnessTransaction(txid),
        ],
    ))
    .expect("getdata");
    let mut served = Vec::new();
    while let Ok(msg) = out_rx.try_recv() {
        served.push(Queued::expect_msg(msg));
    }
    let mut bare = spend.clone();
    bare.input[0].witness.clear();
    assert_eq!(
        served,
        vec![NetworkMessage::Tx(bare), NetworkMessage::Tx(spend)],
        "MSG_TX serves the tip tx without its witness, MSG_WITNESS_TX with it"
    );
    assert_eq!(
        hub.take_tip_wtx_scans(),
        1,
        "both items share one tip index"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A stored side block a month behind the best header is not reconstructed
/// for a full-block getdata, a compact getdata, or getblocktxn. The tip still is.
#[test]
fn month_old_side_block_is_not_rebuilt_for_getdata() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("stale-getdata-nobody");
    hub.ensure_genesis().unwrap();
    let gen = hub.tip_hash().unwrap();
    let t0 = 1_700_000_000u32;
    hub.clock.set_mock(i64::from(t0));
    let side = rbitcoin_consensus::mine_empty_regtest(gen, t0, 1);
    let side_hash = side.block_hash();
    hub.accept_block(side).unwrap();
    run_on_tip_accept(|| hub.invalidate_block_inner(side_hash)).unwrap();
    let best_time = t0 + rbitcoin_net::chain::STALE_RELAY_AGE_LIMIT_SECS as u32;
    hub.clock.set_mock(i64::from(best_time));
    let tip = rbitcoin_consensus::mine_empty_regtest(gen, best_time, 1);
    let tip_hash = tip.block_hash();
    hub.accept_block(tip).unwrap();
    assert!(!hub.stale_relay_allowed(&side_hash));
    assert!(hub.header_of(&side_hash).is_some());
    let _ = hub.cache.take_body_loads();

    let (out_tx, mut out_rx) = peer_out_channel();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let served = serve_getdata_full_block(&hub, &out_tx, &side_hash, true)
            .await
            .unwrap();
        assert_eq!(
            served,
            FullBlockReply::Withheld,
            "a known stale block is silent, not notfound"
        );
    });
    assert!(
        out_rx.try_recv().is_err(),
        "no block bytes for the stale body"
    );
    assert_eq!(
        hub.cache.take_body_loads(),
        0,
        "full getdata must not read a body it will not relay"
    );

    let cmpct = compact_serve_outcome(
        &hub.cache,
        &hub.query,
        &side_hash,
        hub.tip_height().unwrap(),
        2,
        vec![0],
    )
    .unwrap();
    assert!(matches!(cmpct, CompactServe::Missing));
    assert_eq!(
        hub.cache.take_body_loads(),
        0,
        "compact getdata must not read it either"
    );

    let reply = getblocktxn_reply(
        &hub.cache,
        &hub.query,
        BlockTransactionsRequest {
            block_hash: side_hash,
            indexes: vec![0],
        },
        hub.tip_height().unwrap(),
    )
    .unwrap();
    assert!(reply.is_none(), "getblocktxn is silent for the stale body");
    assert_eq!(
        hub.cache.take_body_loads(),
        0,
        "getblocktxn must not read it either"
    );

    rt.block_on(async {
        let served = serve_getdata_full_block(&hub, &out_tx, &tip_hash, true)
            .await
            .unwrap();
        assert_eq!(
            served,
            FullBlockReply::Queued,
            "the connected tip is served"
        );
    });
    assert!(
        out_rx.try_recv().map(served_block).is_ok(),
        "the tip body is queued"
    );
    assert_eq!(hub.cache.take_body_loads(), 1, "the tip body is read once");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Core `PrepareBlockFilterRequest`: start past stop, or a range of 1000+
/// cfilters / 2000+ cfheaders, disconnects instead of being clamped.
#[test]
fn headers_poll_expires_a_stale_tx_off_the_tokio_worker() {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version as TxVersion;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-poll-expire");
    hub.ensure_genesis().unwrap();
    let tip = hub.tip_header().unwrap();
    let (_tip, _time, cbs) = rbitcoin_query::pad_empty_from(
        &hub.query,
        &ChainParams::regtest(),
        hub.tip_hash().unwrap(),
        tip.time,
        1,
        101,
        1,
    );
    let mp =
        rbitcoin_net::tx_relay::MempoolHub::open(dir.path().join("mp"), Arc::clone(&hub.query))
            .unwrap();
    mp.set_relay_enabled(true);
    let tx = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: cbs[0],
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - 1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    let tid = tx.compute_txid();
    mp.admit(&tx).expect("admit");
    assert_eq!(mp.live_count(), 1);
    mp.set_expiry_hours(1);
    mp.note_mock_now(mp.relay_now_secs() + 3600 + 5);
    assert!(hub.attach_mempool(Arc::clone(&mp)).is_ok());
    let mp_wait = Arc::clone(&mp);

    // The worker name is what `assert_not_reactor` checks. Inline expiry panics here.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, _rx) = peer_out_channel();
            on_headers_poll(&hub, &out_tx, None);
        })
        .await
        .expect("headers poll task")
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while mp_wait.live_count() != 0 {
        if Instant::now() > deadline {
            panic!("headers poll left the expired tx live");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!mp.contains(&tid));
}

/// Compact-filter requests read the store on the blocking pool, not on the
/// session's `tokio-rt-worker` (`assert_not_reactor` panics there), and the
/// replies still go out.
#[test]
fn compact_filter_requests_read_the_store_off_the_reactor() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cfilter-off-reactor");
    hub.query.set_block_filter_index(true).unwrap();
    hub.ensure_genesis().unwrap();
    let heights = hub.query.index_heights(0, 0, None).unwrap();
    let window = hub.query.read_index_window(&heights).unwrap();
    let filter = hub.query.basic_filter_from_window(&window, 0).unwrap();
    hub.query
        .commit_window_filters(0, &[(filter, heights[0].header_fk)])
        .unwrap();
    let hub = hub.into_arc();
    let genesis = hub.tip_hash().unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("tokio-rt-worker")
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async move {
        tokio::spawn(async move {
            let (out_tx, mut out_rx) = peer_out_channel();
            let mut follow = PeerFollowState::new();
            for msg in [
                NetworkMessage::GetCFHeaders(bitcoin::p2p::message_filter::GetCFHeaders {
                    filter_type: 0,
                    start_height: 0,
                    stop_hash: genesis,
                }),
                NetworkMessage::GetCFilters(bitcoin::p2p::message_filter::GetCFilters {
                    filter_type: 0,
                    start_height: 0,
                    stop_hash: genesis,
                }),
                NetworkMessage::GetCFCheckpt(bitcoin::p2p::message_filter::GetCFCheckpt {
                    filter_type: 0,
                    stop_hash: genesis,
                }),
            ] {
                handle_peer_frame(frame_for(msg), &hub, &out_tx, &mut follow, None)
                    .await
                    .expect("filter request");
            }
            let mut got = Vec::new();
            while let Ok(out) = out_rx.try_recv() {
                got.push(out.expect_msg());
            }
            assert!(
                matches!(
                    got.as_slice(),
                    [
                        NetworkMessage::CFHeaders(_),
                        NetworkMessage::CFilter(_),
                        NetworkMessage::CFCheckpt(_)
                    ]
                ),
                "{got:?}"
            );
        })
        .await
        .expect("reactor task")
    });
    let _ = std::fs::remove_dir_all(&dir);
}

/// [`on_compact_filters`] on a one-off runtime. A stack hub runs the
/// filter read inline.
fn serve_filters(
    hub: &ChainHub,
    tx: &PeerOutTx,
    session: Option<&rbitcoin_net::peers::LivePeer>,
    msg: NetworkMessage,
) -> Result<(), NetError> {
    let mut follow = PeerFollowState::new();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(on_compact_filters(msg, hub, tx, &mut follow, session))
}

#[test]
fn compact_filter_ranges_past_core_limits_disconnect() {
    assert!(compact_filter_range(5, 4, MAX_GETCFILTERS).is_err());
    assert!(compact_filter_range(0, 999, MAX_GETCFILTERS).is_ok());
    assert!(compact_filter_range(0, 1000, MAX_GETCFILTERS).is_err());
    assert!(compact_filter_range(1, 2000, MAX_GETCFHEADERS).is_ok());
    assert!(compact_filter_range(0, 2000, MAX_GETCFHEADERS).is_err());

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cf-stop");
    hub.query.set_block_filter_index(true).unwrap();
    hub.ensure_genesis().unwrap();
    let heights = hub.query.index_heights(0, 0, None).unwrap();
    let window = hub.query.read_index_window(&heights).unwrap();
    let filter = hub.query.basic_filter_from_window(&window, 0).unwrap();
    assert_eq!(
        hub.query
            .commit_window_filters(0, &[(filter, heights[0].header_fk)])
            .unwrap(),
        1,
        "genesis basic filter must be sealed before a peer can read it"
    );
    let tip = hub.tip_hash().unwrap();
    let (tx, mut rx) = peer_out_channel();
    let headers = bitcoin::p2p::message_filter::GetCFHeaders {
        filter_type: 0,
        start_height: 0,
        stop_hash: tip,
    };
    serve_filters(
        &hub,
        &tx,
        None,
        NetworkMessage::GetCFHeaders(headers.clone()),
    )
    .unwrap();
    match rx.try_recv().expect("cfheaders").into_out() {
        rbitcoin_net::peers::PeerOut::Msg(NetworkMessage::CFHeaders(m)) => {
            assert_eq!(m.previous_filter_header.as_byte_array(), &[0u8; 32]);
            assert_eq!(m.filter_hashes.len(), 1, "{m:?}");
        }
        other => panic!("expected cfheaders, got {other:?}"),
    }
    let typed = bitcoin::p2p::message_filter::GetCFilters {
        filter_type: 1,
        start_height: 0,
        stop_hash: tip,
    };
    serve_filters(&hub, &tx, None, NetworkMessage::GetCFilters(typed.clone())).unwrap();
    assert!(rx.try_recv().is_err(), "a non-basic filter is silence");
    hub.query.set_block_filter_index(false).unwrap();
    let basic = bitcoin::p2p::message_filter::GetCFilters {
        filter_type: 0,
        start_height: 0,
        stop_hash: tip,
    };
    serve_filters(&hub, &tx, None, NetworkMessage::GetCFilters(basic.clone())).unwrap();
    assert!(rx.try_recv().is_err(), "filters off is silence");
    let _ = std::fs::remove_dir_all(dir);
}

fn outbound_peer() -> Arc<rbitcoin_net::peers::LivePeer> {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18444));
    let ver = VersionMessage {
        version: bitcoin::p2p::PROTOCOL_VERSION,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: true,
    };
    peers.register(
        addr,
        addr,
        &ver,
        false,
        rbitcoin_net::peers::PeerConnType::OutboundFullRelay,
    )
}

/// One `getcfilters` queues the filter that crosses the 4 MiB budget and
/// parks the rest of its range on the session's tail. The peer starts on
/// the cap, so the first filter is the one that crosses.
#[test]
fn getcfilters_parks_the_rest_after_the_filter_that_crosses_the_send_budget() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cf-budget");
    let hub = std::sync::Arc::new(hub);
    hub.query.set_block_filter_index(true).unwrap();
    hub.ensure_genesis().unwrap();
    hub.mine(2, ScriptBuf::from_bytes(vec![0x51]), vec![])
        .unwrap();
    let tip_h = hub.tip_height().unwrap();
    let peer = outbound_peer();
    let _at_cap = hold_send_bytes(&peer, rbitcoin_net::peers::PEER_SEND_BUDGET);
    assert!(
        !peer.send_over_budget(),
        "the cap itself is still inside the budget"
    );
    let (tx, mut rx) = peer.open_out();
    let mut follow = PeerFollowState::new();
    let req = bitcoin::p2p::message_filter::GetCFilters {
        filter_type: 0,
        start_height: 0,
        stop_hash: hub.tip_hash().unwrap(),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            on_compact_filters(
                NetworkMessage::GetCFilters(req.clone()),
                &hub,
                &tx,
                &mut follow,
                Some(peer.as_ref()),
            )
            .await?;
            // A second request already decoded behind the first waits
            // unbuilt, so the session holds one request's replies.
            on_compact_filters(
                NetworkMessage::GetCFilters(req),
                &hub,
                &tx,
                &mut follow,
                Some(peer.as_ref()),
            )
            .await
        })
        .unwrap();
    assert!(peer.send_over_budget());
    let mut n = 0usize;
    while let Ok(msg) = rx.try_recv().map(Queued::into_out) {
        match msg {
            PeerOut::Msg(NetworkMessage::CFilter(_)) => n += 1,
            other => panic!("expected cfilter, got {other:?}"),
        }
    }
    assert_eq!(n, 1, "only the filter that crosses the budget is queued");
    assert_eq!(
        follow.cfilter_tail.len(),
        tip_h as usize,
        "the rest of the first range is parked, and nothing of the second"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A stop under height 1,000 queues an empty checkpoint message. Height
/// 1,000 queues that one filter header. The stride past the first
/// checkpoint stays in the store table test
/// `checkpoint_headers_are_every_thousandth_slot`.
#[test]
fn getcfcheckpt_returns_a_header_every_thousand_heights() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cf-checkpt");
    hub.query.set_block_filter_index(true).unwrap();
    hub.ensure_genesis().unwrap();
    hub.confirm_empty_regtest(999).unwrap();
    assert_eq!(hub.tip_height().unwrap(), 999);
    let (tx, mut rx) = peer_out_channel();
    let below = bitcoin::p2p::message_filter::GetCFCheckpt {
        filter_type: 0,
        stop_hash: hub.tip_hash().unwrap(),
    };
    serve_filters(&hub, &tx, None, NetworkMessage::GetCFCheckpt(below.clone())).unwrap();
    match rx.try_recv().expect("cfcheckpt below 1000").into_out() {
        PeerOut::Msg(NetworkMessage::CFCheckpt(m)) => {
            assert!(
                m.filter_headers.is_empty(),
                "a stop under 1000 has no checkpoint"
            );
        }
        other => panic!("expected cfcheckpt, got {other:?}"),
    }
    hub.confirm_empty_regtest(1).unwrap();
    assert_eq!(hub.tip_height().unwrap(), 1_000);
    assert_eq!(hub.query.basic_filter_hwm().unwrap(), Some(1_000));
    let rows = hub
        .query
        .basic_filter_hashes_and_headers(1_000, 1_000)
        .unwrap()
        .expect("sealed range");
    let (tx, mut rx) = peer_out_channel();
    let req = bitcoin::p2p::message_filter::GetCFCheckpt {
        filter_type: 0,
        stop_hash: hub.tip_hash().unwrap(),
    };
    serve_filters(&hub, &tx, None, NetworkMessage::GetCFCheckpt(req.clone())).unwrap();
    match rx.try_recv().expect("cfcheckpt").into_out() {
        PeerOut::Msg(NetworkMessage::CFCheckpt(m)) => {
            assert_eq!(m.filter_headers, vec![rows[0].1]);
        }
        other => panic!("expected cfcheckpt, got {other:?}"),
    }
    assert!(rx.try_recv().is_err(), "one checkpoint message");
    let _ = std::fs::remove_dir_all(dir);
}

fn addrfetch_peer() -> Arc<rbitcoin_net::peers::LivePeer> {
    let peers = rbitcoin_net::peers::PeerHub::new();
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18445));
    let ver = VersionMessage {
        version: bitcoin::p2p::PROTOCOL_VERSION,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&addr, ServiceFlags::NONE),
        sender: Address::new(&addr, ServiceFlags::NONE),
        nonce: 1,
        user_agent: "/rbitcoin:test/".into(),
        start_height: 0,
        relay: false,
    };
    peers.register(
        addr,
        addr,
        &ver,
        true,
        rbitcoin_net::peers::PeerConnType::AddrFetch,
    )
}

/// Tip-follow queues one pong. That message keeps the nonce from the claim.
/// Later pings replace the stored nonce. The writer sends the queued nonce,
/// then one pong for the stored nonce. Draining the one queued charge
/// returns the send budget to its previous value. Nonce 0 is a real nonce.
#[test]
fn one_charged_pong_keeps_the_queued_nonce() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pong-one");
    hub.ensure_genesis().unwrap();
    let peer = addrfetch_peer();
    let (tx, mut rx) = peer.open_out();
    let mut follow = PeerFollowState::new();
    let before = peer.send_queued();
    on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), 1).unwrap();
    on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), 0).unwrap();
    for n in 2..100_000u64 {
        on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), n).unwrap();
    }
    let mut queued = Vec::new();
    let mut pongs = Vec::new();
    while let Ok(q) = rx.try_recv() {
        match q.out() {
            PeerOut::Msg(NetworkMessage::Pong(n)) => pongs.push(*n),
            other => panic!("a ping queues only a pong, got {other:?}"),
        }
        queued.push(q);
    }
    assert_eq!(pongs.len(), 1, "pings coalesce to one pong");
    assert_eq!(
        pongs[0], 1,
        "the queued pong keeps the nonce from its claim"
    );
    assert_eq!(
        peer.pong_nonce(),
        99_999,
        "later pings replace the stored nonce"
    );
    let charge = rbitcoin_net::peers::outbound_msg_bytes(&NetworkMessage::Pong(0));
    assert_eq!(peer.send_queued().saturating_sub(before), charge);
    assert_eq!(
        peer.finish_pong_write(pongs[0]),
        Some(99_999),
        "the writer sends 1, then queues this nonce"
    );
    drop(queued);
    assert_eq!(
        peer.send_queued(),
        before,
        "the write subtracts that one charge"
    );
    assert_eq!(peer.finish_pong_write(99_999), None);

    on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), 7).unwrap();
    peer.store_pong_nonce(8);
    assert_eq!(
        peer.finish_pong_write(7),
        Some(8),
        "a ping during the write is claimed for the writer"
    );
    assert!(
        rx.try_recv().is_ok(),
        "the ping that opened the slot queued one pong"
    );
    assert!(
        rx.try_recv().is_err(),
        "the nonce stored during the write does not queue another pong"
    );

    let fast = addrfetch_peer();
    let (fast_tx, mut fast_rx) = fast.open_out();
    let fast_before = fast.send_queued();
    queue_pong(Some(fast.as_ref()), &fast_tx, 4).unwrap();
    queue_pong(Some(fast.as_ref()), &fast_tx, 0).unwrap();
    assert_eq!(
        fast.send_queued() - fast_before,
        charge,
        "the fast path charges one pong"
    );
    match fast_rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::Pong(4))) => {}
        other => panic!("the queued pong keeps nonce 4, got {other:?}"),
    }
    assert_eq!(fast.pong_nonce(), 0, "the later ping stored nonce 0");

    let (bare_tx, mut bare_rx) = peer_out_channel();
    on_ping(&hub, &bare_tx, &mut follow, None, 1).unwrap();
    on_ping(&hub, &bare_tx, &mut follow, None, 2).unwrap();
    assert!(matches!(
        bare_rx.try_recv().map(Queued::into_out),
        Ok(PeerOut::Msg(NetworkMessage::Pong(1)))
    ));
    assert!(matches!(
        bare_rx.try_recv().map(Queued::into_out),
        Ok(PeerOut::Msg(NetworkMessage::Pong(2)))
    ));
    let _ = std::fs::remove_dir_all(dir);
}

/// Drive `run_writer_task` on a v1 socket. `peer` is the session the writer
/// requeues a later pong onto, through the same channel it is draining.
async fn messages_from_writer(
    peer: &Arc<rbitcoin_net::peers::LivePeer>,
    prepare: impl FnOnce(&PeerOutTx),
    want: usize,
) -> Vec<NetworkMessage> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let (_read, write) = server.into_split();
    let magic = Magic::from(Network::Regtest);
    let wire = rbitcoin_net::WireBytes::new();
    let writer = rbitcoin_net::v1::PeerWriter::V1(rbitcoin_net::v1::V1Writer::new(
        wire.count_write(write),
        magic,
    ));
    let (tx, rx) = peer.open_out();
    prepare(&tx);
    let task = tokio::spawn(run_writer_task(writer, rx, Some(Arc::clone(peer))));
    let mut reader = rbitcoin_net::v1::V1Reader::new(client);
    let mut out = Vec::new();
    while out.len() < want {
        match tokio::time::timeout(Duration::from_secs(2), reader.read_frame(magic, |_| Ok(())))
            .await
        {
            Ok(Ok(frame)) => out.push(frame.decode().into_payload()),
            Ok(Err(e)) => panic!("writer socket closed early: {e}"),
            Err(_) => break,
        }
    }
    // `open_out` keeps a sender on the peer, and the writer task holds this peer, so
    // dropping only the local sender leaves `recv` waiting out the timeout.
    peer.clear_out_tx();
    drop(tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), task).await;
    out
}

fn wire_pongs(wire: &[NetworkMessage]) -> Vec<u64> {
    wire.iter()
        .filter_map(|msg| match msg {
            NetworkMessage::Pong(n) => Some(*n),
            _ => None,
        })
        .collect()
}

/// `getpeerinfo.bytessent_per_msg` counts what the writer put on the wire,
/// per command. A v1 writer counts payload plus Core's 24-byte header; the v2
/// rule is `session_start_messages_count_in_bytes_sent`. A pre-encoded
/// getdata block counts as `block`.
#[tokio::test(flavor = "current_thread")]
async fn writer_counts_bytes_sent_per_message() {
    let peer = addrfetch_peer();
    let block = bitcoin::constants::genesis_block(Network::Regtest);
    let block_len = serialize(&block).len() as u64;
    let encoded = rbitcoin_net::v2::encode_v2_contents(NetworkMessage::Block(block)).unwrap();
    let wire = messages_from_writer(
        &peer,
        |tx| {
            tx.send(PeerOut::Msg(NetworkMessage::Ping(7))).unwrap();
            tx.send(PeerOut::Msg(NetworkMessage::GetData(Vec::new())))
                .unwrap();
            tx.send(PeerOut::Msg(NetworkMessage::GetData(Vec::new())))
                .unwrap();
            tx.send(PeerOut::Encoded(encoded)).unwrap();
        },
        4,
    )
    .await;
    assert_eq!(wire.len(), 4, "every queued message is written: {wire:?}");
    let sent = peer.snapshot(0).bytessent_per_msg;
    let want: HashMap<String, u64> = [
        ("ping", 8 + 24),
        ("getdata", 2 * (1 + 24)),
        ("block", block_len + 24),
    ]
    .into_iter()
    .map(|(cmd, n)| (cmd.to_owned(), n))
    .collect();
    assert_eq!(sent, want, "bytessent_per_msg after the writer ran");
}

/// Only a write that succeeded is counted. The far side resets the
/// connection after the ping, so the getdata queued next fails and stays
/// out of `bytessent_per_msg`.
#[tokio::test(flavor = "current_thread")]
async fn writer_does_not_count_a_failed_write() {
    use tokio::io::AsyncReadExt;
    let peer = addrfetch_peer();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let (mut read, write) = server.into_split();
    let magic = Magic::from(Network::Regtest);
    let wire = rbitcoin_net::WireBytes::new();
    let writer = rbitcoin_net::v1::PeerWriter::V1(rbitcoin_net::v1::V1Writer::new(
        wire.count_write(write),
        magic,
    ));
    let (tx, rx) = peer_out_channel();
    let task = tokio::spawn(run_writer_task(writer, rx, Some(Arc::clone(&peer))));
    tx.send(PeerOut::Msg(NetworkMessage::Ping(7))).unwrap();
    let mut reader = rbitcoin_net::v1::V1Reader::new(&mut client);
    let frame = tokio::time::timeout(Duration::from_secs(2), reader.read_frame(magic, |_| Ok(())))
        .await
        .expect("ping written")
        .unwrap();
    assert!(matches!(
        frame.decode().into_payload(),
        NetworkMessage::Ping(7)
    ));
    // A zero linger makes the drop send RST. Once the read half sees it,
    // the next write fails.
    client.set_zero_linger().unwrap();
    drop(client);
    let mut buf = [0u8; 1];
    let closed = tokio::time::timeout(Duration::from_secs(2), read.read(&mut buf)).await;
    assert!(
        matches!(closed, Ok(Ok(0)) | Ok(Err(_))),
        "reset must reach the server socket: {closed:?}"
    );
    tx.send(PeerOut::Msg(NetworkMessage::GetData(Vec::new())))
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("a failed write ends the writer task")
        .unwrap();
    let sent = peer.snapshot(0).bytessent_per_msg;
    assert_eq!(sent.get("ping"), Some(&(8 + 24)), "{sent:?}");
    assert_eq!(
        sent.get("getdata"),
        None,
        "a failed write is not counted: {sent:?}"
    );
}

/// Core `nSendSize` counts every queued message and subtracts what the
/// socket took. A getheaders written ahead of a reply still on the socket
/// does not lift the send budget: the reader stays paused until the reply
/// drains.
#[tokio::test(flavor = "current_thread")]
async fn getheaders_written_ahead_keeps_a_queued_reply_charged() {
    use tokio::io::AsyncReadExt;
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("sendq-ahead");
    hub.ensure_genesis().unwrap();
    let peer = addrfetch_peer();
    // Small socket buffers hold the reply mid-write until this side reads.
    let listener = tokio::net::TcpSocket::new_v4().unwrap();
    listener.set_send_buffer_size(4096).unwrap();
    listener.bind((Ipv4Addr::LOCALHOST, 0).into()).unwrap();
    let listener = listener.listen(1).unwrap();
    let client = tokio::net::TcpSocket::new_v4().unwrap();
    client.set_recv_buffer_size(4096).unwrap();
    let mut client = client
        .connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (server, _) = listener.accept().await.unwrap();
    let (_read, write) = server.into_split();
    let magic = Magic::from(Network::Regtest);
    let writer = rbitcoin_net::v1::PeerWriter::V1(rbitcoin_net::v1::V1Writer::new(
        rbitcoin_net::WireBytes::new().count_write(write),
        magic,
    ));
    let (tx, rx) = peer.open_out();

    queue_getheaders(&tx, &hub, Some(peer.as_ref()), true, None).unwrap();
    let before = peer.send_queued();
    let rows = rbitcoin_net::peers::PEER_SEND_BUDGET / 36 + 1;
    let inv = vec![Inventory::WTx(bitcoin::Wtxid::all_zeros()); rows];
    for chunk in inv.chunks(MAX_INV_SIZE) {
        tx.send(NetworkMessage::Inv(chunk.to_vec())).unwrap();
    }
    let reply = peer.send_queued() - before;
    assert!(peer.send_over_budget(), "the reply crosses the budget");

    let task = tokio::spawn(run_writer_task(writer, rx, Some(Arc::clone(&peer))));
    let mut head = [0u8; 24];
    let read = async {
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[4..14], b"getheaders", "getheaders is written first");
        let len = u32::from_le_bytes(head[16..20].try_into().unwrap()) as usize;
        client.read_exact(&mut vec![0u8; len]).await.unwrap();
        // The writer settles one message before it starts the next frame.
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[4..7], b"inv", "the reply is on the socket");
    };
    tokio::time::timeout(Duration::from_secs(2), read)
        .await
        .expect("writer frames");
    assert!(
        peer.send_queued() >= reply,
        "the reply is still queued: {} of {reply} bytes charged",
        peer.send_queued()
    );
    assert!(
        peer.send_over_budget(),
        "the reader stays paused while the reply is queued"
    );
    task.abort();
    peer.clear_out_tx();
    let _ = std::fs::remove_dir_all(dir);
}

/// The session start writes `sendheaders`, `sendcmpct`, the first `ping`
/// and, when relay is on or IBD runs, `feefilter` before the writer task
/// runs. Those count in `bytessent_per_msg` too, as a v2 peer's contents
/// plus the 20-byte cipher expansion: `sendheaders` has no short id, so it
/// is a 13-byte type and no payload.
#[tokio::test]
async fn session_start_messages_count_in_bytes_sent() {
    use rbitcoin_net::v2::read_v2_frame;
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("start-sent");
    hub.ensure_genesis().unwrap();
    let hub = hub.into_arc();
    let peers = rbitcoin_net::peers::PeerHub::new();
    let mut sess = open_decode_session(Arc::clone(&hub), &peers, 18496, None).await;
    let mut seen = HashSet::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !["sendheaders", "sendcmpct", "ping"]
        .iter()
        .all(|c| seen.contains(*c))
    {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let frame = tokio::time::timeout(left, read_v2_frame(&mut sess.reader, sess.magic))
            .await
            .expect("session start frames")
            .unwrap();
        seen.insert(frame.decode().payload().cmd().to_owned());
    }
    // Counted after the write returns, which can trail the read here.
    let mut sent = HashMap::new();
    while std::time::Instant::now() < deadline {
        sent = sess.live.snapshot(0).bytessent_per_msg;
        if ["sendheaders", "sendcmpct", "ping"]
            .iter()
            .all(|c| sent.contains_key(*c))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(sent.get("sendheaders"), Some(&(13 + 20)), "{sent:?}");
    assert_eq!(sent.get("sendcmpct"), Some(&(1 + 9 + 20)), "{sent:?}");
    assert_eq!(sent.get("ping"), Some(&(1 + 8 + 20)), "{sent:?}");
    if seen.contains("feefilter") {
        assert_eq!(sent.get("feefilter"), Some(&(1 + 8 + 20)), "{sent:?}");
    }
    sess.session.abort();
    let _ = std::fs::remove_dir_all(dir);
}

/// The writer puts the nonce from the queued pong on the wire. A newer
/// nonce stored on the session is a second pong, after replies that were
/// already queued past the 64-message batch.
#[tokio::test(flavor = "current_thread")]
async fn writer_sends_the_queued_pong_then_a_later_nonce_behind_the_replies() {
    let peer = addrfetch_peer();
    peer.store_pong_nonce(0);
    let only = messages_from_writer(
        &peer,
        |tx| tx.send(PeerOut::Msg(NetworkMessage::Pong(4))).unwrap(),
        2,
    )
    .await;
    assert_eq!(
        wire_pongs(&only),
        vec![4, 0],
        "nonce 0 on the session must not replace the queued pong; it is answered after it"
    );

    let peer = addrfetch_peer();
    peer.store_pong_nonce(2);
    let wire = messages_from_writer(
        &peer,
        |tx| {
            tx.send(PeerOut::Msg(NetworkMessage::Pong(1))).unwrap();
            for _ in 0..100 {
                tx.send(PeerOut::Msg(NetworkMessage::GetData(Vec::new())))
                    .unwrap();
            }
        },
        102,
    )
    .await;
    let getdata = wire
        .iter()
        .filter(|msg| matches!(msg, NetworkMessage::GetData(_)))
        .count();
    let pong_2 = wire
        .iter()
        .position(|msg| matches!(msg, NetworkMessage::Pong(2)));
    let last_reply = wire
        .iter()
        .rposition(|msg| matches!(msg, NetworkMessage::GetData(_)));
    assert_eq!(
        getdata,
        100,
        "all 100 replies are written, pongs={:?}",
        wire_pongs(&wire)
    );
    assert_eq!(
        wire_pongs(&wire),
        vec![1, 2],
        "the queued nonce stays 1; nonce 2 is a later pong"
    );
    assert!(
        pong_2.is_some() && last_reply.is_some() && pong_2 > last_reply,
        "pong 2 must follow every reply, pong_2={pong_2:?} last_reply={last_reply:?}"
    );

    // Bytes already queued ahead of the pongs stay charged after both
    // pongs are written.
    let peer = addrfetch_peer();
    let baseline = 1 << 20;
    let _queued = hold_send_bytes(&peer, baseline);
    let charged = messages_from_writer(
        &peer,
        |tx| {
            queue_pong(Some(peer.as_ref()), tx, 1).unwrap();
            peer.store_pong_nonce(2);
        },
        2,
    )
    .await;
    assert_eq!(
        wire_pongs(&charged),
        vec![1, 2],
        "the charged pong keeps nonce 1; nonce 2 is written after it"
    );
    assert_eq!(
        peer.send_queued(),
        baseline,
        "both pongs are charged and then subtracted, so the baseline remains"
    );
}

/// A ping while either serve tail still has work does not queue its pong.
/// The pong follows the replies, and only once both tails are empty. A
/// second ping replaces the parked nonce.
#[tokio::test(flavor = "current_thread")]
async fn ping_pong_waits_until_both_serve_tails_are_empty() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pong-tail");
    hub.ensure_genesis().unwrap();
    let peer = addrfetch_peer();
    let (tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.getdata_tail.push_back(Inventory::Error);
    follow.getblocktxn_tail.push_back(BlockTransactionsRequest {
        block_hash: BlockHash::from_byte_array([0u8; 32]),
        indexes: vec![0],
    });
    on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), 11).unwrap();
    on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), 12).unwrap();
    assert!(
        rx.try_recv().is_err(),
        "a ping must not queue its pong while a getdata or getblocktxn tail is pending"
    );
    serve_getdata_tail(&hub, &tx, &mut follow, Some(peer.as_ref()))
        .await
        .unwrap();
    assert!(
        follow.getdata_tail.is_empty(),
        "the getdata item was served"
    );
    assert!(
        rx.try_recv().is_err(),
        "the pong still waits while the getblocktxn tail is pending"
    );
    serve_getblocktxn_tail(&hub, &tx, &mut follow, Some(peer.as_ref()))
        .await
        .unwrap();
    match rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::Pong(12))) => {}
        other => panic!("the later parked ping is the one pong, got {other:?}"),
    }
    assert!(rx.try_recv().is_err(), "one pong for the parked pings");

    on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), 13).unwrap();
    assert_eq!(peer.pong_nonce(), 13);
    assert!(
        rx.try_recv().is_err(),
        "a later ping replaces the nonce of the pong that is not written yet"
    );
    assert_eq!(
        peer.finish_pong_write(12),
        Some(13),
        "the writer sends the parked nonce, then this later one"
    );
    assert_eq!(peer.finish_pong_write(13), None);
    on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), 14).unwrap();
    match rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::Pong(14))) => {}
        other => panic!("a ping with both tails empty queues its pong, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// A ping parked behind only a getdata tail. The flush at the end of
/// `serve_getdata_tail` is what queues the pong, after that tail's reply.
#[tokio::test(flavor = "current_thread")]
async fn ping_pong_follows_a_getdata_tail_alone() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pong-getdata");
    hub.ensure_genesis().unwrap();
    let peer = addrfetch_peer();
    let (tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow
        .getdata_tail
        .push_back(Inventory::WitnessBlock(BlockHash::from_byte_array(
            [9u8; 32],
        )));
    on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), 21).unwrap();
    assert!(
        rx.try_recv().is_err(),
        "the pong stays parked while the getdata tail is the only tail pending"
    );
    serve_getdata_tail(&hub, &tx, &mut follow, Some(peer.as_ref()))
        .await
        .unwrap();
    assert!(
        follow.getdata_tail.is_empty(),
        "the getdata item was served"
    );
    match rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::NotFound(_))) => {}
        other => panic!("the missing block is a notfound before the pong, got {other:?}"),
    }
    match rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::Pong(21))) => {}
        other => panic!("the parked ping is queued after that notfound, got {other:?}"),
    }
    assert!(rx.try_recv().is_err(), "one pong for the parked ping");
    let _ = std::fs::remove_dir_all(dir);
}

/// A ping parked behind a getblocktxn for a block we hold. The flush at
/// the end of `serve_getblocktxn_tail` queues the pong after that reply.
#[tokio::test(flavor = "current_thread")]
async fn ping_pong_follows_a_getblocktxn_reply() {
    let s = serve_session("pong-gbtxn", 1);
    let hash = *s.hashes.last().expect("mined block");
    let peer = addrfetch_peer();
    let (tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    follow.getblocktxn_tail.push_back(BlockTransactionsRequest {
        block_hash: hash,
        indexes: vec![0],
    });
    on_ping(&s.hub, &tx, &mut follow, Some(peer.as_ref()), 31).unwrap();
    assert!(
        rx.try_recv().is_err(),
        "the pong stays parked while the getblocktxn tail is pending"
    );
    serve_getblocktxn_tail(&s.hub, &tx, &mut follow, Some(peer.as_ref()))
        .await
        .unwrap();
    assert!(
        follow.getblocktxn_tail.is_empty(),
        "the getblocktxn was served"
    );
    let reply = rx
        .try_recv()
        .expect("the getblocktxn reply is queued before the pong")
        .into_out();
    match &reply {
        PeerOut::Served(NetworkMessage::BlockTxn(bt)) => {
            assert_eq!(bt.transactions.block_hash, hash);
        }
        PeerOut::Served(NetworkMessage::Block(block)) => {
            assert_eq!(block.block_hash(), hash);
        }
        other => panic!("expected the served getblocktxn reply before the pong, got {other:?}"),
    }
    match rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::Pong(31))) => {}
        other => panic!("the parked pong follows that reply, got {other:?}"),
    }
    assert!(rx.try_recv().is_err(), "one pong for the parked ping");
}

/// Bytes after the 8-byte nonce used to decode as `Unknown` and get no pong.
#[test]
fn ping_with_bytes_after_the_nonce_still_gets_a_pong() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pong-extra");
    hub.ensure_genesis().unwrap();
    let peer = addrfetch_peer();
    let (tx, mut rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let nonce = 0x1122_3344_5566_7788u64;
    let mut payload = nonce.to_le_bytes().to_vec();
    payload.push(0xff);
    let msg = NetworkMessage::Unknown {
        command: bitcoin::p2p::message::CommandString::try_from("ping").unwrap(),
        payload,
    };
    assert!(
        handle_peer_control_msg(&msg, &hub, &tx, &mut follow, Some(peer.as_ref())).unwrap(),
        "a ping with extra bytes is still a ping"
    );
    match rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::Pong(n))) => {
            assert_eq!(n, nonce, "the pong uses the first eight bytes");
        }
        other => panic!("extra bytes after a ping nonce must still be answered, got {other:?}"),
    }
    let short = NetworkMessage::Unknown {
        command: bitcoin::p2p::message::CommandString::try_from("ping").unwrap(),
        payload: vec![1, 2, 3],
    };
    assert!(
        !handle_peer_control_msg(&short, &hub, &tx, &mut follow, Some(peer.as_ref())).unwrap(),
        "a ping shorter than eight bytes is not answered"
    );
    assert!(rx.try_recv().is_err(), "a short ping queues no pong");
    let _ = std::fs::remove_dir_all(dir);
}

/// A pong that waited in `decode_q` decodes as `Unknown` when the payload
/// is not exactly eight bytes. The read arm still passes those bytes to
/// `on_pong`. This arm must too, or a matching nonce leaves the ping up
/// until the timeout.
#[test]
fn pong_with_extra_or_short_bytes_still_updates_the_ping() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pong-unknown");
    hub.ensure_genesis().unwrap();
    let peer = addrfetch_peer();
    let (tx, _rx) = peer_out_channel();
    let mut follow = PeerFollowState::new();
    let nonce = 0x99u64;
    peer.ping_nonce_sent.store(nonce, Ordering::Relaxed);
    let mut payload = nonce.to_le_bytes().to_vec();
    payload.push(0xff);
    let long = NetworkMessage::Unknown {
        command: bitcoin::p2p::message::CommandString::try_from("pong").unwrap(),
        payload,
    };
    assert!(
        handle_peer_control_msg(&long, &hub, &tx, &mut follow, Some(peer.as_ref())).unwrap(),
        "a pong with extra bytes is still a pong"
    );
    assert_eq!(
        peer.ping_nonce_sent.load(Ordering::Relaxed),
        0,
        "a long pong whose first eight bytes match must clear the outstanding ping"
    );
    peer.ping_nonce_sent.store(nonce, Ordering::Relaxed);
    let short = NetworkMessage::Unknown {
        command: bitcoin::p2p::message::CommandString::try_from("pong").unwrap(),
        payload: vec![1, 2, 3],
    };
    assert!(
        handle_peer_control_msg(&short, &hub, &tx, &mut follow, Some(peer.as_ref())).unwrap(),
        "a short pong is still a pong"
    );
    assert_eq!(
        peer.ping_nonce_sent.load(Ordering::Relaxed),
        0,
        "a short pong must clear the outstanding ping"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// A ping that lands after a write batch was taken does not rewrite the
/// pong in that batch. Its pong is queued behind a reply already waiting.
#[test]
fn later_ping_pong_waits_behind_a_reply_already_queued() {
    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pong-later");
    hub.ensure_genesis().unwrap();
    let peer = addrfetch_peer();
    let (tx, mut rx) = peer.open_out();
    let mut follow = PeerFollowState::new();
    on_ping(&hub, &tx, &mut follow, Some(peer.as_ref()), 1).unwrap();
    let queued = match rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::Pong(n))) => n,
        other => panic!("the first ping queues one pong, got {other:?}"),
    };
    assert_eq!(queued, 1);
    tx.send(PeerOut::Msg(NetworkMessage::GetData(vec![])))
        .unwrap();
    peer.store_pong_nonce(2);
    requeue_later_pong(peer.as_ref(), queued);
    match rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::GetData(_))) => {}
        other => {
            panic!("the reply already queued must stay ahead of the later pong, got {other:?}")
        }
    }
    match rx.try_recv().map(Queued::into_out) {
        Ok(PeerOut::Msg(NetworkMessage::Pong(2))) => {}
        other => panic!("the later ping must still be answered, got {other:?}"),
    }
    assert!(rx.try_recv().is_err());
    let _ = std::fs::remove_dir_all(dir);
}

mod log_text_tests;

/// Core `ProcessMessage` ADDR/ADDRV2: the `getaddr` an addr-fetch session
/// sends buys `MAX_ADDR_TO_SEND` more addresses. The reply, v1 or v2, is
/// learned and not relayed (`m_getaddr_sent`). More than one address ends the
/// session without misbehavior; a one-address self-announce does not.
#[tokio::test]
async fn addrfetch_learns_the_getaddr_reply_then_disconnects() {
    use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use std::sync::atomic::Ordering;

    let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("addrfetch-reply");
    let peers = rbitcoin_net::peers::PeerHub::new();
    let book = std::sync::Arc::new(std::sync::Mutex::new(rbitcoin_net::seeds::AddrMan::new()));
    peers.set_addrman(std::sync::Arc::clone(&book));
    let register = |port: u16, typ: rbitcoin_net::peers::PeerConnType| {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let ver = VersionMessage {
            version: bitcoin::p2p::PROTOCOL_VERSION,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce: 0,
            user_agent: "/rbitcoin:test/".into(),
            start_height: 0,
            relay: true,
        };
        peers.register(addr, addr, &ver, false, typ)
    };
    let neighbor = register(18459, rbitcoin_net::peers::PeerConnType::OutboundFullRelay);
    neighbor.set_wants_addrv2();
    let (_, mut relayed) = neighbor.open_out();
    let book_len = || book.lock().unwrap().len();
    let routable = |i: u32| AddrV2::Ipv4(std::net::Ipv4Addr::from(0x0b00_0001 + (i << 16)));

    let seed = register(18460, rbitcoin_net::peers::PeerConnType::AddrFetch);
    let (out_tx, _out_rx) = peer_out_channel();
    assert!(maybe_queue_addrfetch_getaddr(&out_tx, &seed));
    let time = seed.clock_now() as u32;
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(seed.as_ref()),
        NetworkMessage::AddrV2(vec![AddrV2Message {
            time,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(std::net::Ipv4Addr::new(9, 9, 9, 9)),
            port: 8333,
        }]),
    )
    .await;
    assert_eq!(book_len(), 1, "a self-announce is learned");
    assert_eq!(
        peers.addrfetch_replies(),
        0,
        "a self-announce is not the reply"
    );
    assert!(
        !seed.stop.load(Ordering::SeqCst),
        "one address is not the reply"
    );
    let reply = (0..MAX_ADDR_TO_SEND as u32)
        .map(|i| AddrV2Message {
            time,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            addr: routable(i),
            port: 18444,
        })
        .collect();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(seed.as_ref()),
        NetworkMessage::AddrV2(reply),
    )
    .await;
    let learned = book_len() - 1;
    assert!(
        learned >= MAX_ADDR_TO_SEND * 9 / 10,
        "the getaddr reply is learned past one token: {learned}"
    );
    assert!(
        seed.stop.load(Ordering::SeqCst),
        "the reply ends addr-fetch"
    );
    assert_eq!(follow.ban_score, 0, "a getaddr reply is not misbehavior");
    assert_eq!(peers.addrfetch_replies(), 1);
    assert!(
        relayed.try_recv().is_err(),
        "an addr-fetch reply is not relayed"
    );

    let v1_seed = register(18461, rbitcoin_net::peers::PeerConnType::AddrFetch);
    assert!(maybe_queue_addrfetch_getaddr(&out_tx, &v1_seed));
    let before = book_len();
    let v1 = |last: u8| {
        let addr = std::net::SocketAddr::from(([12, 0, 0, last], 18444));
        (time, Address::new(&addr, ServiceFlags::NETWORK))
    };
    let mut follow = PeerFollowState::new();
    push(
        &hub,
        &out_tx,
        &mut follow,
        Some(v1_seed.as_ref()),
        NetworkMessage::Addr(vec![v1(1), v1(2)]),
    )
    .await;
    assert!(book_len() > before, "a v1 getaddr reply is learned");
    assert!(
        v1_seed.stop.load(Ordering::SeqCst),
        "a v1 reply ends addr-fetch"
    );
    assert_eq!(follow.ban_score, 0, "a v1 getaddr reply is not misbehavior");
    assert_eq!(peers.addrfetch_replies(), 2);
    assert!(
        relayed.try_recv().is_err(),
        "a v1 addr-fetch reply is not relayed"
    );
    let _ = std::fs::remove_dir_all(dir.path());
}

#[cfg(test)]
mod service_and_addr_tokens {
    use super::*;
    /// Handshake requires these bits (`has_all_desirable_service_flags`).
    /// NETWORK_LIMITED covers a tip younger than 144 blocks.
    #[test]
    fn limited_service_stops_at_one_day_of_blocks() {
        let offered = ServiceFlags::NETWORK_LIMITED | ServiceFlags::WITNESS;
        let full = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
        assert_eq!(desirable_service_flags(offered, 143), offered);
        assert_eq!(desirable_service_flags(offered, 144), full);
        let mut pruned = ServiceFlags::NETWORK_LIMITED;
        pruned.add(ServiceFlags::WITNESS);
        pruned.add(ServiceFlags::P2P_V2);
        assert_eq!(local_service_flags(true, None), pruned);
    }

    /// The pre-version handshake log names the command (`non_version_before_handshake_log`).
    #[test]
    fn command_label_stops_at_the_nul() {
        let mut cmd = [0u8; 12];
        cmd[..7].copy_from_slice(b"version");
        assert_eq!(command_label(&cmd), "version");
    }
}

#[cfg(test)]
mod walk_depth_pins {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;
    use rbitcoin_primitives::Height;

    fn mine(
        hub: rbitcoin_net::chain::ChainHub,
        nblocks: u32,
    ) -> std::sync::Arc<rbitcoin_net::chain::ChainHub> {
        let hub = std::sync::Arc::new(hub);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(hub.generate_to_script_for_rpc_async(
                nblocks,
                bitcoin::ScriptBuf::from_bytes(vec![0x51]),
                vec![],
                false,
            ))
            .unwrap();
        hub
    }

    /// `pending_walk` and `header_announcement_connects` stop after this many steps.
    #[test]
    fn pending_walk_stops_past_one_headers_batch() {
        assert_eq!(PENDING_WALK_LIMIT, 10_001);
    }

    /// Handshake service flags use this depth (`has_all_desirable_service_flags`).
    #[test]
    fn depth_is_one_block_after_one_spacing() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("depth-one-spacing");
        hub.clock.set_mock(1_700_000_000);
        let hub = mine(hub, 1);
        let tip = hub.tip_header().expect("tip");
        hub.clock.set_mock(i64::from(tip.time) + 600);
        assert_eq!(approximate_best_block_depth(&hub), 1);
    }

    /// `getheaders` continues from this locator (`queue_getheaders`).
    #[test]
    fn locator_steps_by_one_then_doubles() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("locator-double");
        let hub = mine(hub, 40);
        let heights = [40u32, 39, 38, 37, 36, 35, 34, 33, 32, 31, 29, 25, 17, 1, 0];
        let expected: Vec<BlockHash> = heights
            .iter()
            .map(|h| {
                let (_height, rec) = hub
                    .query
                    .header_at_height(Height(*h))
                    .unwrap()
                    .expect("header");
                BlockHash::from_byte_array(rec.hash)
            })
            .collect();
        assert_eq!(locator_from_height(&hub, 40), expected);
    }
}

#[cfg(test)]
mod peer_queue_pins {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::{Block, BlockHash};

    fn bare_block(n: u8) -> Block {
        Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::from_byte_array([n; 32]),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([n; 32]),
                time: u32::from(n),
                bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
                nonce: u32::from(n),
            },
            txdata: vec![],
        }
    }

    /// `values` walks the map. `remove` drops that hash from the FIFO.
    #[test]
    fn peer_queue_pending_remove_keeps_the_other() {
        let mut pending = PendingBlocks::new();
        let first = bare_block(1);
        let second = bare_block(2);
        let a = first.block_hash();
        let b = second.block_hash();
        pending.insert(a, first, None);
        pending.insert(b, second, None);
        assert_eq!(pending.values().count(), 2);
        pending.remove(&a);
        assert_eq!(pending.fifo.iter().copied().collect::<Vec<_>>(), vec![b]);
        assert_eq!(pending.values().count(), 1);
    }

    /// A pong is last in the batch. Headers and inv stay ahead of it.
    #[test]
    fn peer_queue_pong_sorts_after_headers() {
        let pong = PeerOut::Msg(NetworkMessage::Pong(1));
        let headers = PeerOut::Msg(NetworkMessage::Headers(vec![]));
        assert!(outbound_write_rank(&pong) > outbound_write_rank(&headers));
    }

    /// One drain takes at most 64 queued messages.
    #[test]
    fn peer_queue_batch_stops_at_sixty_four() {
        let (tx, mut rx) = peer_out_channel();
        for i in 0..80u64 {
            tx.send(PeerOut::Msg(NetworkMessage::Pong(i))).unwrap();
        }
        let first = rx.try_recv().unwrap();
        let batch = take_outbound_write_batch(first, &mut rx);
        assert_eq!(batch.len(), 64);
    }
}

#[cfg(test)]
mod peer_header_pins {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::BlockHash;
    use std::collections::HashMap;

    /// Bits harder than the regtest pow limit. Claimed proof of work fails.
    fn hdr(prev: BlockHash, n: u32) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([n as u8; 32]),
            time: n,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: n,
        }
    }

    /// The walk returns the hash at the step limit, not the one after it.
    #[test]
    fn peer_header_walk_stops_at_the_limit() {
        let limit = PENDING_WALK_LIMIT;
        let mut prev = BlockHash::from_byte_array([9; 32]);
        let mut pending = HashMap::new();
        let mut hashes = Vec::with_capacity(limit + 1);
        for i in 0..=limit {
            let header = hdr(prev, i as u32);
            let hash = header.block_hash();
            pending.insert(hash, header);
            hashes.push(hash);
            prev = hash;
        }
        let (join, steps) = pending_walk(&pending, hashes[limit]);
        assert_eq!(steps, limit as u32);
        assert_eq!(join, hashes[0]);
    }

    /// A held body is a header we know. Walking its pending parent must not
    /// hide that.
    #[test]
    fn peer_header_held_prev_connects() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-connect");
        let header = hdr(BlockHash::from_byte_array([4; 32]), 8);
        let known = header.block_hash();
        hub.hold_body(
            std::sync::Arc::new(bitcoin::Block {
                header,
                txdata: vec![],
            }),
            false,
        );
        let mut pending = HashMap::new();
        pending.insert(known, header);
        assert!(header_announcement_connects(&hub, &pending, known));
    }

    /// Ten seconds is already late. The ask is dropped.
    #[test]
    fn peer_header_expire_at_the_timeout() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hdr-expire");
        let hash = BlockHash::from_byte_array([6; 32]);
        let mut requested = RequestedBlocks::default();
        requested.ask(&hub, hash);
        let start = std::time::Instant::now() - BLOCK_GETDATA_TIMEOUT;
        let mut since = Some(start);
        assert!(maybe_expire_block_requests(
            &mut requested,
            &mut since,
            start + BLOCK_GETDATA_TIMEOUT,
            None,
        ));
        assert!(requested.is_empty());
    }
}

#[cfg(test)]
mod peer_session_pins {
    use super::*;
    use bitcoin::hashes::Hash;
    use bitcoin::p2p::address::Address;
    use bitcoin::p2p::message::NetworkMessage;
    use bitcoin::p2p::message_blockdata::Inventory;
    use bitcoin::p2p::message_network::VersionMessage;
    use bitcoin::p2p::ServiceFlags;
    use bitcoin::BlockHash;
    use rbitcoin_net::peers::{PeerConnType, PeerHub, PeerOut};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn version() -> VersionMessage {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        VersionMessage {
            version: 70016,
            services: ServiceFlags::NETWORK,
            timestamp: 0,
            receiver: Address::new(&addr, ServiceFlags::NONE),
            sender: Address::new(&addr, ServiceFlags::NONE),
            nonce: 1,
            user_agent: "/rbitcoin:0.1.0/".into(),
            start_height: 0,
            relay: true,
        }
    }

    fn peer(
        kind: PeerConnType,
    ) -> (
        std::sync::Arc<PeerHub>,
        std::sync::Arc<rbitcoin_net::peers::LivePeer>,
    ) {
        let peers = PeerHub::new();
        peers.set_mock_now(1_000);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let live = peers.register(addr, addr, &version(), false, kind);
        (peers, live)
    }

    fn inbound() -> std::sync::Arc<rbitcoin_net::peers::LivePeer> {
        let peers = PeerHub::new();
        peers.set_mock_now(1_000);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        peers.register(addr, addr, &version(), true, PeerConnType::Inbound)
    }

    fn asked_headers(
        hub: &rbitcoin_net::chain::ChainHub,
        session: Option<&rbitcoin_net::peers::LivePeer>,
    ) -> bool {
        let (tx, mut rx) = peer_out_channel();
        on_headers_poll(hub, &tx, session);
        matches!(
            rx.try_recv()
                .map(rbitcoin_net::send_queue::Queued::into_out),
            Ok(PeerOut::Msg(NetworkMessage::GetHeaders(_)))
        )
    }

    /// Addr-fetch is not polled. A full-relay peer with no best header is.
    #[test]
    fn peer_session_polls_full_relay_not_addrfetch() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("poll");
        let (_peers, addrfetch) = peer(PeerConnType::AddrFetch);
        assert!(!asked_headers(&hub, Some(&addrfetch)));
        let (_peers, full) = peer(PeerConnType::OutboundFullRelay);
        assert!(asked_headers(&hub, Some(&full)));
    }

    /// The addr-fetch session is still inside the window at exactly 300s.
    #[test]
    fn peer_session_addrfetch_expires_after_three_hundred() {
        let (peers, live) = peer(PeerConnType::AddrFetch);
        peers.set_mock_now(1_000 + ADDRFETCH_TIMEOUT_SECS);
        assert!(!addrfetch_timed_out(&live));
        peers.set_mock_now(1_001 + ADDRFETCH_TIMEOUT_SECS);
        assert!(addrfetch_timed_out(&live));
    }

    /// A pong that cannot be queued must release the claim.
    #[test]
    fn peer_session_failed_pong_releases_the_claim() {
        let (_peers, live) = peer(PeerConnType::OutboundFullRelay);
        live.store_pong_nonce(7);
        assert!(live.claim_pong_send());
        requeue_later_pong(&live, 1);
        assert!(live.claim_pong_send());
    }

    /// An outbound peer is not counted. An inbound peer is counted only while
    /// relay is on, and that same peer is not offered its own inbound inv.
    #[test]
    fn peer_session_inbound_gate_needs_relay() {
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("tx-gate");
        let pool_dir = dir.path().join("pool");
        std::fs::create_dir_all(&pool_dir).expect("pool dir");
        let mp = rbitcoin_net::tx_relay::MempoolHub::open_with_weight_persist(
            &pool_dir,
            hub.query.clone(),
            400_000,
            false,
        )
        .expect("mempool");
        let txid = bitcoin::Txid::from_byte_array([1; 32]);
        let (_peers, outbound) = peer(PeerConnType::OutboundFullRelay);
        mp.set_relay_enabled(true);
        assert!(!tx_announce_inbound_gated(&outbound, &mp, &txid));
        let inn = inbound();
        mp.set_relay_enabled(false);
        assert!(!tx_announce_inbound_gated(&inn, &mp, &txid));
        mp.set_relay_enabled(true);
        assert!(tx_announce_inbound_gated(&inn, &mp, &txid));
    }

    /// A matching pong clears the outstanding ping.
    #[test]
    fn peer_wire_pong_clears_the_nonce() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("pong-arm");
        let (_peers, live) = peer(PeerConnType::OutboundFullRelay);
        live.ping_nonce_sent
            .store(9, std::sync::atomic::Ordering::Relaxed);
        live.ping_start_secs
            .store(1, std::sync::atomic::Ordering::Relaxed);
        let (tx, _rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        assert!(handle_peer_control_msg(
            &NetworkMessage::Pong(9),
            &hub,
            &tx,
            &mut follow,
            Some(&live),
        )
        .unwrap());
        assert_eq!(
            live.ping_nonce_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    /// The chain locator is the tip. The error fallback would append zeros.
    #[test]
    fn peer_wire_locator_is_the_tip() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("locator-tip");
        hub.ensure_genesis().expect("genesis");
        let tip = hub.tip_hash().expect("tip");
        assert_eq!(tip_follow_locator(&hub), vec![tip]);
    }

    fn saw_getdata(rx: &mut PeerOutRx) -> bool {
        loop {
            match rx
                .try_recv()
                .map(rbitcoin_net::send_queue::Queued::into_out)
            {
                Ok(PeerOut::Msg(NetworkMessage::GetData(_))) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }

    /// IBD keeps transaction relay off even when the pool would relay.
    #[test]
    fn peer_inv_during_ibd_does_not_fetch_a_tx() {
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-ibd");
        assert!(hub.in_ibd());
        let pool_dir = dir.path().join("pool");
        std::fs::create_dir_all(&pool_dir).expect("pool dir");
        let mp = rbitcoin_net::tx_relay::MempoolHub::open_with_weight_persist(
            &pool_dir,
            hub.query.clone(),
            400_000,
            false,
        )
        .expect("mempool");
        mp.set_relay_enabled(true);
        if hub.attach_mempool(mp).is_err() {
            panic!("attach");
        }
        let (_peers, live) = peer(PeerConnType::OutboundFullRelay);
        let (tx, mut rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        on_inv(
            &hub,
            &tx,
            &mut follow,
            Some(&live),
            &[Inventory::Transaction(bitcoin::Txid::from_byte_array(
                [7; 32],
            ))],
        )
        .unwrap();
        assert!(!saw_getdata(&mut rx));
        assert_eq!(follow.ban_score, 0);
    }

    /// A block already held as a pending header is not a new header walk.
    #[test]
    fn peer_inv_pending_header_needs_no_headers() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-pend");
        let hash = BlockHash::from_byte_array([9; 32]);
        let mut follow = PeerFollowState::new();
        follow.pending_headers.insert(
            hash,
            bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
        );
        assert!(!on_inv_block_needs_headers(&hub, &follow, None, &hash));
    }

    fn mine_to(hub: &rbitcoin_net::chain::ChainHub, height: u32) {
        let spk = bitcoin::script::ScriptBuf::from_bytes(vec![0x51]);
        while hub.tip_height().unwrap_or(0) < height {
            let prev = hub.tip_hash().expect("tip");
            let time = hub.tip_header().expect("tip header").time.saturating_add(1);
            let next = hub.tip_height().expect("height").saturating_add(1);
            let block =
                rbitcoin_consensus::mine_regtest_paying(prev, time, next, spk.clone(), vec![]);
            hub.accept_block(block).expect("extend");
        }
    }

    /// Genesis is not an unknown parent. A block at the tip is not low work.
    /// Once the tip is far ahead, the old height-1 block is.
    #[test]
    fn peer_block_unrequested_skip_keeps_genesis_and_low_work() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("skip-block");
        let mut follow = PeerFollowState::new();
        let skipped =
            on_block_unrequested_skip(&hub, &mut follow, None, &genesis, genesis.block_hash())
                .unwrap();
        assert!(!skipped, "genesis is not an unrequested skip");
        assert_eq!(follow.ban_score, 0);
        hub.ensure_genesis().expect("genesis");
        mine_to(&hub, 1);
        let child = hub.block_at_height(1).unwrap().expect("height 1");
        let mut follow = PeerFollowState::new();
        let skipped =
            on_block_unrequested_skip(&hub, &mut follow, None, &child, child.block_hash()).unwrap();
        assert!(!skipped, "the tip child is not below the anti-DoS work");
        mine_to(&hub, 147);
        let old = hub.block_at_height(1).unwrap().expect("height 1");
        let mut follow = PeerFollowState::new();
        let skipped =
            on_block_unrequested_skip(&hub, &mut follow, None, &old, old.block_hash()).unwrap();
        assert!(skipped, "height 1 is low work once the tip is far ahead");
    }

    fn saw_inv(rx: &mut PeerOutRx) -> bool {
        loop {
            match rx
                .try_recv()
                .map(rbitcoin_net::send_queue::Queued::into_out)
            {
                Ok(PeerOut::Msg(NetworkMessage::Inv(_))) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    }

    /// A compact tip with headers off does not also send an inv.
    #[test]
    fn peer_tip_compact_without_headers_sends_no_inv() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("tip-cmpct");
        hub.ensure_genesis().expect("genesis");
        let hash = hub.tip_hash().expect("tip");
        let header = hub.tip_header().expect("header");
        let ev = rbitcoin_net::chain::TipEvent {
            height: hub.tip_height().expect("height"),
            hash,
            header,
            reorg_branch_len: 0,
        };
        let mut follow = PeerFollowState::new();
        follow.send_cmpct = true;
        follow.cmpct_version = 2;
        let (tx, mut rx) = peer_out_channel();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(on_tip_event(&hub, &tx, &mut follow, None, Ok(ev)))
            .unwrap();
        assert!(
            !saw_inv(&mut rx),
            "compact announce is the only tip message"
        );
    }

    /// A tip this peer already sent is still recorded when the offer was skipped.
    #[test]
    fn peer_tip_unsent_records_a_skipped_offer() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("tip-unsent");
        hub.ensure_genesis().expect("genesis");
        let tip = hub.tip_hash().expect("tip");
        let (_peers, live) = peer(PeerConnType::OutboundFullRelay);
        live.note_block_from_peer(tip);
        let (tx, _rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(announce_unsent_tip(
            &hub,
            &tx,
            &mut follow,
            Some(&live),
            None,
        ))
        .unwrap();
        assert_eq!(live.last_tip_offered(), Some(tip));
    }

    /// A tip event for the current tip keeps its reorg length.
    #[test]
    fn peer_tip_event_keeps_a_long_reorg() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("tip-reorg-len");
        hub.ensure_genesis().expect("genesis");
        let hash = hub.tip_hash().expect("tip");
        let header = hub.tip_header().expect("header");
        let ev = rbitcoin_net::chain::TipEvent {
            height: hub.tip_height().expect("height"),
            hash,
            header,
            reorg_branch_len: MAX_BLOCKS_TO_ANNOUNCE + 1,
        };
        let got = tip_event_for_announce(Ok(ev), &hub);
        let super::TipRecvAnnounce::Announce(got) = got else {
            panic!("the current tip is announced");
        };
        assert!(got.reorg_branch_len > MAX_BLOCKS_TO_ANNOUNCE);
    }

    fn pow_header(
        hub: &rbitcoin_net::chain::ChainHub,
        prev: BlockHash,
        time: u32,
    ) -> bitcoin::block::Header {
        let mut header = bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(4),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_byte_array([8; 32]),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        for nonce in 0..1_000_000u32 {
            header.nonce = nonce;
            if hub.header_claimed_pow_ok(&header) {
                return header;
            }
        }
        panic!("regtest header");
    }

    /// A month-old side header with only a staged body is withheld, not missing.
    #[test]
    fn peer_serve_stale_staged_body_is_withheld() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("serve-stale");
        hub.ensure_genesis().expect("genesis");
        let genesis = hub.tip_hash().expect("genesis");
        let gtime = hub.tip_header().expect("genesis header").time;
        let spk = bitcoin::script::ScriptBuf::from_bytes(vec![0x51]);
        let far = gtime.saturating_add(31 * 24 * 60 * 60);
        let main = rbitcoin_consensus::mine_regtest_paying(genesis, far, 1, spk, vec![]);
        hub.accept_block(main).expect("advance the tip");
        let side = pow_header(&hub, genesis, gtime.saturating_add(1));
        let hash = side.block_hash();
        let side_time = side.time;
        hub.ensure_header(&side).expect("side header");
        hub.cache.stage_servable(bitcoin::Block {
            header: side,
            txdata: Vec::new(),
        });
        assert!(
            !hub.cache.has_body(&hash),
            "staged body is not a stored body"
        );
        assert!(hub.cache.has_servable(&hash), "staged");
        assert!(
            !hub.query
                .is_block_archived(&hash.to_byte_array())
                .expect("archive"),
            "header-only is not archived"
        );
        let stored = hub
            .query
            .get_header_by_hash(&hash.to_byte_array())
            .expect("header read");
        assert!(stored.is_some(), "side header is stored");
        let height = hub
            .query
            .height_of_hash(&hash.to_byte_array())
            .expect("height");
        assert!(height.is_none(), "fork height {height:?}");
        let tip_time = hub.tip_header().expect("tip header").time;
        assert!(
            u64::from(tip_time).saturating_sub(u64::from(side_time))
                >= rbitcoin_net::chain::STALE_RELAY_AGE_LIMIT_SECS,
            "tip {tip_time} side {side_time}"
        );
        let (tx, _rx) = peer_out_channel();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let served = rt
            .block_on(serve_getdata_full_block(&hub, &tx, &hash, false))
            .expect("serve");
        assert_eq!(served, FullBlockReply::Withheld);
    }

    fn open_pool(
        label: &str,
    ) -> (
        rbitcoin_query::testutil::TempDir,
        rbitcoin_net::chain::ChainHub,
        std::sync::Arc<rbitcoin_net::tx_relay::MempoolHub>,
    ) {
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled(label);
        let pool_dir = dir.path().join("pool");
        std::fs::create_dir_all(&pool_dir).expect("pool dir");
        let mp = rbitcoin_net::tx_relay::MempoolHub::open_with_weight_persist(
            &pool_dir,
            hub.query.clone(),
            400_000,
            false,
        )
        .expect("mempool");
        (dir, hub, mp)
    }

    fn wtx_invs(rx: &mut PeerOutRx) -> Vec<bitcoin::Wtxid> {
        let mut out = Vec::new();
        while let Ok(msg) = rx
            .try_recv()
            .map(rbitcoin_net::send_queue::Queued::into_out)
        {
            let PeerOut::Msg(NetworkMessage::Inv(items)) = msg else {
                continue;
            };
            for item in items {
                let Inventory::WTx(w) = item else {
                    panic!("tx inv is a wtxid");
                };
                out.push(w);
            }
        }
        out
    }

    fn spend_height(hub: &rbitcoin_net::chain::ChainHub, height: u32) -> bitcoin::Transaction {
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};
        let coinbase = hub
            .query
            .reconstruct_block_at_height(rbitcoin_primitives::Height(height))
            .expect("coinbase")
            .txdata[0]
            .compute_txid();
        bitcoin::Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: coinbase,
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_9999_0000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    /// Relay-off still announces a local unbroadcast tx. An aged tx is
    /// announced without a clock tick. Inv'ing a later tx makes an older one
    /// servable.
    #[test]
    fn peer_tx_inv_queue_announces_due_work() {
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("inv-queue");
        hub.ensure_genesis().expect("genesis");
        hub.confirm_empty_regtest(101).expect("mature coinbase");
        let pool_dir = dir.path().join("pool");
        std::fs::create_dir_all(&pool_dir).expect("pool dir");
        let mp = rbitcoin_net::tx_relay::MempoolHub::open_with_weight_persist(
            &pool_dir,
            hub.query.clone(),
            400_000,
            false,
        )
        .expect("mempool");
        mp.set_relay_enabled(false);
        let now = 1_700_000_000u64;
        mp.note_mock_now(now);
        if hub.attach_mempool(std::sync::Arc::clone(&mp)).is_err() {
            panic!("attach");
        }
        let older_tx = spend_height(&hub, 1);
        let older = older_tx.compute_txid();
        let older_w = older_tx.compute_wtxid();
        mp.accept_with_utxo(
            &older_tx,
            &mp.utxo_provider(),
            rbitcoin_net::tx_relay::TxOrigin::Relay(None),
            rbitcoin_net::tx_relay::AcceptPath::Relay,
            &[],
        )
        .expect("older");
        mp.note_unbroadcast(older);
        let (out_tx, mut out_rx) = peer_out_channel();
        let (_peers, local) = peer(PeerConnType::OutboundFullRelay);
        local.set_wtxid_relay();
        queue_due_tx_invs(
            &hub,
            &local,
            &rbitcoin_net::peers::CappedSet::new(),
            &out_tx,
        );
        assert_eq!(
            wtx_invs(&mut out_rx),
            vec![older_w],
            "relay off still announces the unbroadcast tx"
        );

        mp.set_relay_enabled(true);
        mp.note_mock_now(now + 30);
        let (_peers, aged) = peer(PeerConnType::OutboundFullRelay);
        aged.set_wtxid_relay();
        queue_due_tx_invs(&hub, &aged, &rbitcoin_net::peers::CappedSet::new(), &out_tx);
        assert_eq!(
            wtx_invs(&mut out_rx),
            vec![older_w],
            "an aged tx is announced without a clock tick"
        );

        let newer_tx = spend_height(&hub, 2);
        let newer_w = newer_tx.compute_wtxid();
        mp.accept_with_utxo(
            &newer_tx,
            &mp.utxo_provider(),
            rbitcoin_net::tx_relay::TxOrigin::Relay(None),
            rbitcoin_net::tx_relay::AcceptPath::Relay,
            &[],
        )
        .expect("newer");
        let mut from = rbitcoin_net::peers::CappedSet::new();
        from.insert(older, 8);
        let (_peers, live) = peer(PeerConnType::OutboundFullRelay);
        live.set_wtxid_relay();
        queue_due_tx_invs(&hub, &live, &from, &out_tx);
        assert_eq!(
            wtx_invs(&mut out_rx),
            vec![newer_w],
            "the tx this peer sent is not inv'd back"
        );
        let (serve_tx, mut serve_rx) = peer_out_channel();
        let served = serve_mempool_getdata(
            &hub,
            &serve_tx,
            Some(&live),
            &Inventory::WTx(older_tx.compute_wtxid()),
            Some(older_tx),
        )
        .expect("getdata");
        assert!(
            served,
            "an older tx becomes servable once a later one is inv'd"
        );
        match serve_rx
            .try_recv()
            .map(rbitcoin_net::send_queue::Queued::into_out)
        {
            Ok(PeerOut::Msg(NetworkMessage::Tx(tx))) => assert_eq!(tx.compute_txid(), older),
            other => panic!("served the older tx, got {other:?}"),
        }
    }

    fn cmpct_of(block: &bitcoin::Block) -> bitcoin::p2p::message_compact_blocks::CmpctBlock {
        bitcoin::p2p::message_compact_blocks::CmpctBlock {
            compact_block: bitcoin::bip152::HeaderAndShortIds::from_block(block, 1, 2, &[])
                .expect("compact"),
        }
    }

    fn push_cmpct(
        hub: &rbitcoin_net::chain::ChainHub,
        live: &rbitcoin_net::peers::LivePeer,
        block: &bitcoin::Block,
    ) -> Vec<NetworkMessage> {
        let mut follow = PeerFollowState::new();
        follow.cmpct_version = 2;
        let (tx, mut rx) = peer_out_channel();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(on_cmpctblock(
            hub,
            &tx,
            &mut follow,
            Some(live),
            &cmpct_of(block),
        ))
        .expect("compact");
        let mut msgs = Vec::new();
        while let Ok(item) = rx
            .try_recv()
            .map(rbitcoin_net::send_queue::Queued::into_out)
        {
            if let PeerOut::Msg(msg) = item {
                msgs.push(msg);
            }
        }
        msgs
    }

    /// A heavier compact header is stamped. An equal-work sibling is not.
    /// A deep-chain compact child of genesis is ignored.
    #[test]
    fn peer_cmpct_stamps_heavier_and_ignores_low_work() {
        let (dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("cmpct-stamp");
        hub.ensure_genesis().expect("genesis");
        hub.confirm_empty_regtest(160).expect("deep tip");
        let tip = hub.tip_header().expect("tip");
        let spk = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
        let heavier = rbitcoin_consensus::mine_regtest_paying(
            tip.block_hash(),
            tip.time.saturating_add(1),
            161,
            spk.clone(),
            vec![],
        );
        let (_peers, live) = peer(PeerConnType::OutboundFullRelay);
        let _ = push_cmpct(&hub, &live, &heavier);
        assert_eq!(
            live.last_block_announcement
                .load(std::sync::atomic::Ordering::Relaxed),
            1_000,
            "a heavier compact header is stamped"
        );
        let sibling = rbitcoin_consensus::mine_regtest_paying(
            tip.prev_blockhash,
            tip.time.saturating_add(1),
            160,
            spk.clone(),
            vec![],
        );
        assert!(
            !header_is_stored(&hub, &sibling.block_hash()),
            "the equal-work sibling is a new header"
        );
        let (_peers, side) = peer(PeerConnType::OutboundFullRelay);
        let _ = push_cmpct(&hub, &side, &sibling);
        assert!(
            header_is_stored(&hub, &sibling.block_hash()),
            "equal-work sibling header is stored"
        );
        assert_eq!(
            side.last_block_announcement
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "an equal-work sibling is not stamped"
        );
        let (_peers, again) = peer(PeerConnType::OutboundFullRelay);
        let _ = push_cmpct(&hub, &again, &heavier);
        assert_eq!(
            again
                .last_block_announcement
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a header we already have is not stamped again"
        );
        let genesis = hub
            .query
            .wire_header_at_height(rbitcoin_primitives::Height(0))
            .expect("genesis header");
        let low = rbitcoin_consensus::mine_regtest_paying(
            genesis.block_hash(),
            genesis.time.saturating_add(1),
            1,
            spk,
            vec![],
        );
        let (_peers, deep) = peer(PeerConnType::OutboundFullRelay);
        assert!(
            hub.header_below_anti_dos(&low.header),
            "the genesis child is below the anti-dos line"
        );
        let msgs = push_cmpct(&hub, &deep, &low);
        assert!(
            msgs.is_empty(),
            "a low-work compact block is ignored, got {msgs:?}"
        );
        assert!(
            !header_is_stored(&hub, &low.block_hash()),
            "an ignored low-work compact header is not stored"
        );
        assert_eq!(
            deep.last_block_announcement
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
        let _ = std::fs::remove_dir_all(dir.path());
    }

    /// The peer who announced the orphan is asked for the missing parent.
    /// The peer who delivered the orphan is not asked twice.
    #[test]
    fn peer_orphan_parent_ask_goes_to_the_other_announcer() {
        let (_dir, _hub, mp) = open_pool("orphan-ask");
        let peers = PeerHub::new();
        peers.set_mock_now(5_000);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18444);
        let here = peers.register(
            addr,
            addr,
            &version(),
            false,
            PeerConnType::OutboundFullRelay,
        );
        let other_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18445);
        let other = peers.register(
            other_addr,
            other_addr,
            &version(),
            false,
            PeerConnType::OutboundFullRelay,
        );
        mp.note_inv_tx_requested(
            rbitcoin_net::tx_relay::InvSource::new(other.id, true),
            [1; 32],
            5_000,
            false,
        );
        let parent = bitcoin::Txid::from_byte_array([9; 32]);
        use bitcoin::absolute::LockTime;
        use bitcoin::transaction::Version as TxVersion;
        use bitcoin::{Amount, OutPoint, Sequence, TxIn, TxOut, Witness};
        let tx = bitcoin::Transaction {
            version: TxVersion::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent,
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        schedule_orphan_parent_getdata(&mp, &tx, Some(here.as_ref()), &[other.id]);
        let anns = mp.announcer_peers_for(&parent, &tx.compute_wtxid());
        assert!(
            anns.contains(&other.id),
            "the other announcer is asked for the missing parent, got {anns:?}"
        );
    }

    /// `read_frame` takes the payload off the BIP324 stream.
    #[test]
    fn peer_wire_session_pin_read_frame() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let magic = bitcoin::p2p::Magic::from(bitcoin::Network::Regtest);
            let listener = rbitcoin_net::listen::bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = listener.local_addr().unwrap();
            let (go, wrote) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.unwrap();
                let (_reader, mut writer, _, _) =
                    rbitcoin_net::v2::open_v2(sock, magic, true).await.unwrap();
                rbitcoin_net::v2::write_v2_contents(&mut writer, b"one-frame".to_vec())
                    .await
                    .unwrap();
                let _ = go.send(());
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            });
            let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut sess = super::V2PlainSession::outbound_bip324(sock).await.unwrap();
            wrote.await.unwrap();
            sess.read_frame().await.expect("frame");
            let again =
                tokio::time::timeout(std::time::Duration::from_millis(400), sess.read_contents())
                    .await;
            assert!(
                again.is_err(),
                "read_frame already took the only payload, got {again:?}"
            );
            server.abort();
        });
    }

    /// A magic-prefixed ellswift key on a session that is already stopping
    /// returns at once. It does not park until the handshake deadline.
    #[test]
    fn peer_wire_session_pin_stopped_ellswift() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let magic = bitcoin::p2p::Magic::from(bitcoin::Network::Regtest);
            let listener = rbitcoin_net::listen::bind_tcp("127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = listener.local_addr().unwrap();
            let peers = PeerHub::new();
            peers.set_peer_timeout_secs(2);
            let peers_task = std::sync::Arc::clone(&peers);
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let our = stream.local_addr().unwrap();
                let their = stream.peer_addr().unwrap();
                inbound_connect_and_handshake(
                    stream,
                    magic,
                    our,
                    their,
                    0,
                    "/rbitcoin:test/",
                    &peers_task,
                    our,
                )
                .await
            });
            let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let sess = loop {
                if let Some(s) = peers.live_peers().into_iter().next() {
                    break s;
                }
                if std::time::Instant::now() > deadline {
                    panic!("connecting session was not registered");
                }
                tokio::task::yield_now().await;
            };
            sess.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let started = std::time::Instant::now();
            let mut key = [0u8; 64];
            key[..4].copy_from_slice(&magic.to_bytes());
            use tokio::io::AsyncWriteExt;
            client.write_all(&key).await.unwrap();
            let joined = tokio::time::timeout(std::time::Duration::from_secs(5), server)
                .await
                .expect("handshake task")
                .unwrap();
            let elapsed = started.elapsed();
            assert!(
                elapsed < std::time::Duration::from_millis(900),
                "a stopped session must not park on ellswift, elapsed {elapsed:?}"
            );
            match joined {
                Err(rbitcoin_net::error::NetError::Timeout) => {}
                Err(e) => panic!("ellswift on a stopped session is a timeout, got {e}"),
                Ok(_) => panic!("ellswift on a stopped session must not finish the handshake"),
            }
        });
    }

    fn frame_for(msg: NetworkMessage) -> rbitcoin_net::codec::FramedMessage {
        let magic = bitcoin::p2p::Magic::from(bitcoin::Network::Regtest);
        let raw = bitcoin::p2p::message::RawNetworkMessage::new(magic, msg);
        let full = bitcoin::consensus::encode::serialize(&raw);
        let command: [u8; 12] = full[4..16].try_into().unwrap();
        rbitcoin_net::codec::FramedMessage {
            magic,
            command,
            payload: full[24..].to_vec(),
        }
    }

    struct Queued(std::collections::VecDeque<rbitcoin_net::codec::FramedMessage>);

    impl rbitcoin_net::v1::FrameRead for Queued {
        fn read_frame(
            &mut self,
            _magic: bitcoin::p2p::Magic,
        ) -> impl std::future::Future<
            Output = Result<rbitcoin_net::codec::FramedMessage, rbitcoin_net::error::NetError>,
        > + Send {
            let next = self.0.pop_front();
            async move { next.ok_or(rbitcoin_net::error::NetError::Protocol("eof")) }
        }
    }

    fn version_at(v: u32) -> VersionMessage {
        let mut msg = version();
        msg.version = v;
        msg
    }

    /// 31800 is the oldest version we speak. One below is obsolete.
    #[test]
    fn peer_hs_min_version_is_accepted() {
        let magic = bitcoin::p2p::Magic::from(bitcoin::Network::Regtest);
        let policy = HandshakePolicy::plain();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut ok = Queued(
            vec![frame_for(NetworkMessage::Version(version_at(
                MIN_PEER_PROTO_VERSION as u32,
            )))]
            .into(),
        );
        let got = rt
            .block_on(read_peer_version(&mut ok, magic, &policy))
            .expect("minimum version");
        assert_eq!(got.version, MIN_PEER_PROTO_VERSION as u32);
        let mut old = Queued(
            vec![frame_for(NetworkMessage::Version(version_at(
                (MIN_PEER_PROTO_VERSION - 1) as u32,
            )))]
            .into(),
        );
        let err = rt
            .block_on(read_peer_version(&mut old, magic, &policy))
            .expect_err("below the minimum");
        assert!(matches!(
            err,
            rbitcoin_net::error::NetError::Protocol("obsolete version")
        ));
    }

    /// A wtxid preface before verack still finishes the handshake.
    #[test]
    fn peer_hs_wtxid_then_verack_finishes() {
        let magic = bitcoin::p2p::Magic::from(bitcoin::Network::Regtest);
        let mut reader = Queued(
            vec![
                frame_for(NetworkMessage::WtxidRelay),
                frame_for(NetworkMessage::Verack),
            ]
            .into(),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(wait_peer_verack(
            &mut reader,
            magic,
            &HandshakePolicy::plain(),
            WTXID_RELAY_VERSION,
        ))
        .expect("verack");
    }

    /// Expiring the last block ask clears the window.
    #[test]
    fn peer_hb_last_ask_clears_the_window() {
        let (_dir, hub) = rbitcoin_net::chain::tiny_regtest_hub_labeled("hb-window");
        let (_peers, live) = peer(PeerConnType::OutboundFullRelay);
        let (tx, _rx) = peer_out_channel();
        let mut follow = PeerFollowState::new();
        follow
            .requested_blocks
            .ask(&hub, BlockHash::from_byte_array([7; 32]));
        let mut since = Some(std::time::Instant::now() - BLOCK_GETDATA_TIMEOUT);
        let mut announces = None;
        let mut flushes = None;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(on_heartbeat(
            &hub,
            &tx,
            &mut follow,
            Some(&live),
            &mut since,
            &mut announces,
            &mut flushes,
            false,
            false,
        ))
        .unwrap();
        assert!(follow.requested_blocks.is_empty());
        assert!(since.is_none());
    }
}
