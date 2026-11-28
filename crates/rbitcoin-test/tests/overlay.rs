//! Labeled overlay-functional journeys over private Tor / i2pd / cjdns meshes.
//!
//! Default `cargo test` never builds this binary. Run only via
//! `./scripts/overlay-functional/run.sh`.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::Magic;
use bitcoin::Amount;
use rbitcoin_net::{peer::V2PlainSession, socks::socks5_connect_domain, v2::read_v2_frame};
use rbitcoin_net::{NetAddr, OnlyNet};
use rbitcoin_node::{NodeConfig, NodeError, P2pListen};
use rbitcoin_primitives::Network;
use rbitcoin_test::jsonrpc::write_rpc_token;
use rbitcoin_test::mine::spend_anyone_can_spend;
use rbitcoin_test::overlay::{
    base_node, control_gate, ephemeral_addr, handshaken_peer_on_network, i2p_b32_from_dest,
    jsonrpc, jsonrpc_try, localaddresses, require_env, restart_daemon, socks_electrum_rpc,
    socks_http_get, spawn_node, wait_file, wait_hs_desc_uploaded, wait_i2p_stream, wait_jsonrpc,
    wait_onion_port, wait_p2p_onion, wait_peer_network, wait_socks_onion, OverlayEnv,
};
use rbitcoin_test::TempDir;
use serde_json::json;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

fn tor_b(env: &OverlayEnv, datadir: &std::path::Path, rpc: SocketAddr) -> NodeConfig {
    write_rpc_token(datadir);
    let mut cfg = base_node(datadir);
    cfg.listen.p2p = P2pListen::Off;
    cfg.listen.listen_onion = true;
    cfg.tor.control = Some(env.tor_control);
    cfg.tor.cookie = Some(env.tor_cookie.clone());
    cfg.rpc.listen = Some(rpc);
    cfg
}

fn tor_a(
    env: &OverlayEnv,
    datadir: &std::path::Path,
    rpc: SocketAddr,
    onion: &str,
    port: u16,
) -> NodeConfig {
    write_rpc_token(datadir);
    let mut cfg = base_node(datadir);
    cfg.listen.p2p = P2pListen::Off;
    cfg.listen.proxy = Some(env.tor_socks);
    cfg.listen.only_net = vec![OnlyNet::Onion];
    cfg.listen.connect = vec![format!("{onion}:{port}").parse::<NetAddr>().unwrap()];
    cfg.rpc.listen = Some(rpc);
    cfg
}

async fn generate_n(rpc: SocketAddr, n: u32) {
    let r = jsonrpc(rpc, "generate", json!([n])).await;
    assert!(r["error"].is_null(), "generate: {r}");
}

async fn read_self_announcement(stream: TcpStream) -> (V2PlainSession, Vec<NetAddr>) {
    let mut peer =
        V2PlainSession::outbound_regtest(stream, "/overlay-bind-test/", Duration::from_secs(5))
            .await
            .unwrap();
    let addresses = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let frame = read_v2_frame(&mut peer.reader, Magic::REGTEST)
                .await
                .unwrap();
            if let NetworkMessage::AddrV2(rows) = frame.decode().into_payload() {
                return rows
                    .iter()
                    .map(|row| NetAddr::from_addrv2(row).unwrap())
                    .collect();
            }
        }
    })
    .await
    .expect("P2P self-announcement");
    (peer, addresses)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_automatic_listener_reports_an_occupied_backend() {
    let env = require_env();
    let dir = TempDir::new().unwrap();
    let rpc = ephemeral_addr();
    let ordinary_port = Network::Regtest.default_p2p_port();
    let ordinary = SocketAddr::from(([127, 0, 0, 1], ordinary_port));
    let backend = SocketAddr::from(([127, 0, 0, 1], ordinary_port + 1));
    let _occupied = tokio::net::TcpListener::bind(backend)
        .await
        .expect("reserve the regtest Tor backend");
    let mut cfg = tor_b(&env, dir.path(), rpc);
    cfg.listen.p2p = P2pListen::Auto;

    let Err(NodeError::Init(message)) =
        tokio::time::timeout(Duration::from_secs(30), rbitcoin_node::run_p2p(cfg.clone()))
            .await
            .expect("node startup deadline")
    else {
        panic!("startup must fail on the occupied implicit Tor listener");
    };
    assert!(
        message.contains(&format!("Unable to open implicit Tor listener {backend}")),
        "{message}"
    );
    assert!(
        message.contains(&format!("--listen {ordinary}"))
            && message.contains("--listen ADDR:PORT=onion"),
        "{message}"
    );

    cfg.apply_kv("listen", &ordinary.to_string()).unwrap();
    let node = spawn_node(cfg, rpc).await;
    let checks = tokio::spawn(async move {
        let direct = TcpStream::connect(ordinary).await.unwrap();
        let _direct =
            V2PlainSession::outbound_regtest(direct, "/tor-port-recovery/", Duration::from_secs(5))
                .await
                .expect("ordinary P2P after recovery");
        let (onion, port) = wait_p2p_onion(rpc, Duration::from_secs(90)).await;
        assert_eq!(port, ordinary_port);
        wait_socks_onion(env.tor_socks, &onion, port, Duration::from_secs(90)).await;
        let forwarded = tokio::time::timeout(
            Duration::from_secs(15),
            socks5_connect_domain(env.tor_socks, &onion, port, None),
        )
        .await
        .expect("Tor SOCKS deadline")
        .unwrap();
        let _forwarded = V2PlainSession::outbound_regtest(
            forwarded,
            "/tor-port-recovery/",
            Duration::from_secs(5),
        )
        .await
        .expect("Tor P2P while the default backend is still occupied");
        wait_jsonrpc(
            rpc,
            "getpeerinfo",
            json!([]),
            Duration::from_secs(5),
            |reply| {
                let Some(rows) = reply["result"].as_array() else {
                    return false;
                };
                let binds: Vec<_> = rows
                    .iter()
                    .filter(|row| row["inbound"] == true)
                    .filter_map(|row| row["addrbind"].as_str()?.parse::<SocketAddr>().ok())
                    .collect();
                binds.contains(&ordinary)
                    && binds
                        .iter()
                        .any(|addr| *addr != ordinary && *addr != backend)
            },
        )
        .await;
    })
    .await;
    node.stop().await;
    checks.expect("ordinary and Tor P2P recovery");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_onion_two_node_v2() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    let direct = ephemeral_addr();
    let mut cfg = tor_b(&env, b_dir.path(), b_rpc);
    cfg.listen.p2p = P2pListen::Socket(direct);
    cfg.listen.discover = true;
    let public_ip = "93.184.216.34:18444";
    cfg.apply_kv("external_ip", public_ip).unwrap();
    cfg.apply_kv("net_permission", "relay@127.0.0.1").unwrap();
    let b = spawn_node(cfg, b_rpc).await;
    generate_n(b_rpc, 3).await;
    let (onion, port) = wait_p2p_onion(b_rpc, Duration::from_secs(90)).await;
    wait_socks_onion(env.tor_socks, &onion, port, Duration::from_secs(90)).await;

    let a = spawn_node(tor_a(&env, a_dir.path(), a_rpc, &onion, port), a_rpc).await;
    // Keep both nodes outside the task so an assertion cannot skip shutdown.
    let checks = tokio::spawn(async move {
        wait_jsonrpc(
            a_rpc,
            "getblockcount",
            json!([]),
            Duration::from_secs(90),
            |v| v["result"] == 3,
        )
        .await;
        let peers = wait_peer_network(a_rpc, "onion", false, Duration::from_secs(30)).await;
        let row = &peers["result"].as_array().unwrap()[0];
        assert_eq!(row["network"], "onion", "{peers}");
        assert_eq!(row["inbound"], false, "{peers}");
        assert_eq!(row["transport_protocol_type"], "v2", "{peers}");
        assert!(row["addr"].as_str().unwrap().contains(".onion"), "{peers}");
        assert_ne!(row["addr"], "0.0.0.0", "{peers}");

        let bin = wait_peer_network(b_rpc, "onion", true, Duration::from_secs(30)).await;
        let brow = handshaken_peer_on_network(&bin, "onion", true).expect("B inbound");
        assert_eq!(brow["transport_protocol_type"], "v2", "{bin}");
        let tor_bind: SocketAddr = brow["addrbind"].as_str().unwrap().parse().unwrap();
        assert!(tor_bind.ip().is_loopback() && tor_bind.is_ipv4());
        assert_ne!(tor_bind, direct, "{bin}");
        assert_eq!(brow["permissions"], json!([]), "{bin}");

        let tor_stream = socks5_connect_domain(env.tor_socks, &onion, port, None)
            .await
            .unwrap();
        let (_tor_peer, tor_announce) = read_self_announcement(tor_stream).await;
        assert_eq!(
            tor_announce,
            [format!("{onion}:{port}").parse::<NetAddr>().unwrap()]
        );
        let direct_stream = TcpStream::connect(direct).await.unwrap();
        let (_direct_peer, direct_announce) = read_self_announcement(direct_stream).await;
        assert_eq!(direct_announce, [public_ip.parse::<NetAddr>().unwrap()]);
        let live = jsonrpc(b_rpc, "getpeerinfo", json!([])).await;
        let direct_peer = live["result"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["addrbind"] == direct.to_string())
            .expect("ordinary inbound peer");
        assert_eq!(direct_peer["network"], "not_publicly_routable", "{live}");
        assert_eq!(direct_peer["permissions"], json!(["relay"]), "{live}");
    })
    .await;

    let (a_stopped, b_stopped) = tokio::join!(tokio::spawn(a.stop()), tokio::spawn(b.stop()));
    checks.expect("Tor and direct P2P checks");
    a_stopped.expect("stop node A");
    b_stopped.expect("stop node B");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_wallet_hs_electrum_esplora() {
    let env = require_env();
    let dir = TempDir::new().unwrap();
    let rpc = ephemeral_addr();
    let electrum = ephemeral_addr();
    let esplora = ephemeral_addr();

    write_rpc_token(dir.path());
    let mut cfg = tor_b(&env, dir.path(), rpc);
    cfg.listen.electrum = Some(electrum);
    cfg.listen.esplora = Some(rbitcoin_esplora::EsploraListen::Tcp(esplora));
    cfg.electrum_onion = true;
    cfg.esplora_onion = true;
    cfg.shindex = true;
    let node = spawn_node(cfg, rpc).await;
    generate_n(rpc, 1).await;

    let e_host = wait_onion_port(rpc, electrum.port(), Duration::from_secs(90)).await;
    wait_socks_onion(
        env.tor_socks,
        &e_host,
        electrum.port(),
        Duration::from_secs(90),
    )
    .await;
    let s_host = wait_onion_port(rpc, esplora.port(), Duration::from_secs(90)).await;
    wait_socks_onion(
        env.tor_socks,
        &s_host,
        esplora.port(),
        Duration::from_secs(90),
    )
    .await;

    let features = socks_electrum_rpc(
        env.tor_socks,
        &e_host,
        electrum.port(),
        "server.features",
        json!([]),
    )
    .await;
    let hosts = &features["result"]["hosts"];
    assert!(
        hosts
            .get(&e_host)
            .is_some_and(|h| h["tcp_port"] == electrum.port()),
        "features.hosts: {features}"
    );
    assert!(
        hosts.get(&e_host).and_then(|h| h.get("ssl_port")).is_none(),
        "ssl_port must stay unset: {features}"
    );

    let (st, body) =
        socks_http_get(env.tor_socks, &s_host, esplora.port(), "/blocks/tip/height").await;
    assert_eq!(st, 200, "esplora GET {body}");
    assert_eq!(body.trim(), "1", "tip height: {body}");

    node.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i2p_sam_two_node() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    write_rpc_token(b_dir.path());
    let mut cfg_b = base_node(b_dir.path());
    cfg_b.listen.p2p = P2pListen::Socket(ephemeral_addr());
    cfg_b.listen.i2p_sam = Some(env.i2p_sam_b);
    cfg_b.listen.i2p_accept_incoming = true;
    cfg_b.listen.only_net = vec![OnlyNet::I2p];
    cfg_b.rpc.listen = Some(b_rpc);
    let b = spawn_node(cfg_b, b_rpc).await;
    generate_n(b_rpc, 3).await;

    let dest = wait_file(
        &b_dir.path().join("i2p").join("p2p.priv"),
        Duration::from_secs(180),
    )
    .await;
    let again = std::fs::read_to_string(b_dir.path().join("i2p").join("p2p.priv")).unwrap();
    assert_eq!(dest, again.trim(), "persistent dest round-trip");
    let b32 = i2p_b32_from_dest(&dest);
    let info = jsonrpc(b_rpc, "getnetworkinfo", json!([])).await;
    let published = localaddresses(&info)
        .iter()
        .find(|r| {
            r["address"]
                .as_str()
                .is_some_and(|a| a.ends_with(".b32.i2p"))
        })
        .unwrap_or_else(|| panic!("i2p local address missing: {info}"));
    assert_eq!(published["address"], b32, "{info}");
    assert_eq!(published["port"], 0, "SAM 3.1 port is 0: {info}");
    let dest_addr: NetAddr = format!("{b32}:0").parse().unwrap();
    wait_i2p_stream(env.i2p_sam, &b32, Duration::from_secs(180)).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    write_rpc_token(a_dir.path());
    let mut cfg_a = base_node(a_dir.path());
    cfg_a.listen.p2p = P2pListen::Off;
    cfg_a.listen.i2p_sam = Some(env.i2p_sam);
    cfg_a.listen.only_net = vec![OnlyNet::I2p];
    cfg_a.listen.connect = vec![dest_addr];
    cfg_a.rpc.listen = Some(a_rpc);
    let a = spawn_node(cfg_a, a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(180),
        |v| v["result"] == 3,
    )
    .await;
    let peers = wait_peer_network(a_rpc, "i2p", false, Duration::from_secs(60)).await;
    assert_eq!(peers["result"][0]["network"], "i2p", "{peers}");
    assert_eq!(
        peers["result"][0]["transport_protocol_type"], "v2",
        "{peers}"
    );
    let addr = peers["result"][0]["addr"].as_str().unwrap_or("");
    assert!(
        addr.starts_with(&b32) && addr.ends_with(":0"),
        "dialed peer must be the published dest: {peers}"
    );
    let addrv2 = peers["result"][0]["bytesrecv_per_msg"]["addrv2"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        addrv2 > 0,
        "inbound I2P node must addrv2 its destination: {peers}"
    );

    a.stop().await;
    b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cjdns_tun_two_node() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    let b_p2p = {
        let l = std::net::TcpListener::bind((env.cjdns_b, 0)).unwrap_or_else(|e| {
            panic!("bind {} (TUN missing?): {e}", env.cjdns_b);
        });
        l.local_addr().unwrap()
    };
    let a_p2p = {
        let l = std::net::TcpListener::bind((env.cjdns_a, 0)).unwrap_or_else(|e| {
            panic!("bind {} (TUN missing?): {e}", env.cjdns_a);
        });
        l.local_addr().unwrap()
    };

    write_rpc_token(b_dir.path());
    let mut cfg_b = base_node(b_dir.path());
    cfg_b.listen.p2p = P2pListen::Socket(b_p2p);
    cfg_b.listen.cjdns_reachable = true;
    cfg_b.listen.discover = true;
    cfg_b.listen.only_net = vec![OnlyNet::Cjdns];
    cfg_b.rpc.listen = Some(b_rpc);
    let b = spawn_node(cfg_b.clone(), b_rpc).await;
    generate_n(b_rpc, 3).await;

    write_rpc_token(a_dir.path());
    let mut cfg_a = base_node(a_dir.path());
    cfg_a.listen.p2p = P2pListen::Socket(a_p2p);
    cfg_a.listen.cjdns_reachable = true;
    cfg_a.listen.discover = true;
    cfg_a.listen.only_net = vec![OnlyNet::Cjdns];
    cfg_a.listen.connect = vec![NetAddr::from_str(&b_p2p.to_string()).unwrap()];
    cfg_a.rpc.listen = Some(a_rpc);
    let a = spawn_node(cfg_a, a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(30),
        |v| v["result"] == 3,
    )
    .await;
    let peers = wait_peer_network(a_rpc, "cjdns", false, Duration::from_secs(20)).await;
    assert_eq!(peers["result"][0]["network"], "cjdns", "{peers}");
    assert_eq!(
        peers["result"][0]["transport_protocol_type"], "v2",
        "{peers}"
    );
    let bin = wait_peer_network(b_rpc, "cjdns", true, Duration::from_secs(20)).await;
    assert!(
        bin["result"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["inbound"] == true && p["network"] == "cjdns"),
        "{bin}"
    );
    let binfo = jsonrpc(b_rpc, "getnetworkinfo", json!([])).await;
    assert!(
        localaddresses(&binfo)
            .iter()
            .any(|r| { r["address"] == env.cjdns_b.to_string() && r["port"] == b_p2p.port() }),
        "cjdns listen must be a local address: {binfo}"
    );
    let ainfo = jsonrpc(a_rpc, "getnetworkinfo", json!([])).await;
    assert!(
        localaddresses(&ainfo)
            .iter()
            .any(|r| { r["address"] == env.cjdns_a.to_string() && r["port"] == a_p2p.port() }),
        "cjdns listen must be a local address: {ainfo}"
    );

    a.stop().await;
    b.stop().await;

    cfg_b.listen.only_net = vec![OnlyNet::Ipv4];
    let b = spawn_node(cfg_b, b_rpc).await;
    let inbound = tokio::spawn(async move {
        let socket = TcpSocket::new_v6().unwrap();
        socket.bind(SocketAddr::from((env.cjdns_a, 0))).unwrap();
        let stream = tokio::time::timeout(Duration::from_secs(5), socket.connect(b_p2p))
            .await
            .expect("connect to restarted CJDNS listener")
            .unwrap();
        let source = stream.local_addr().unwrap().to_string();
        let info = wait_jsonrpc(
            b_rpc,
            "getpeerinfo",
            json!([]),
            Duration::from_secs(5),
            |info| info["result"][0]["addr"] == source,
        )
        .await;
        info["result"][0].clone()
    })
    .await;
    b.stop().await;
    let row = inbound.expect("CJDNS inbound remains visible with --only-net=ipv4");
    assert_eq!(row["inbound"], true, "{row}");
    assert_eq!(row["version"], 0, "{row}");
    assert_eq!(row["network"], "not_publicly_routable", "{row}");
}

#[test]
fn hs_desc_uploaded_line_is_the_stored_event() {
    let id = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv";
    assert!(rbitcoin_test::overlay::hs_desc_uploaded(
        &format!("650 HS_DESC UPLOADED {id} NO_AUTH $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        id
    ));
    assert!(!rbitcoin_test::overlay::hs_desc_uploaded(
        &format!("650 HS_DESC UPLOAD {id} NO_AUTH $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        id
    ));
    assert!(!rbitcoin_test::overlay::hs_desc_uploaded(
        &format!("650 HS_DESC FAILED {id} NO_AUTH $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        id
    ));
    assert!(!rbitcoin_test::overlay::hs_desc_uploaded(
        "650 HS_DESC UPLOADED other NO_AUTH",
        id
    ));
}

#[tokio::test]
async fn control_gate_holds_a_new_connection_until_release() {
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let up_addr = upstream.local_addr().unwrap();
    let gate = control_gate(up_addr).await;
    gate.hold();
    let mut client = tokio::net::TcpStream::connect(gate.listen).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(150), upstream.accept())
            .await
            .is_err(),
        "a held gate forwarded the node's control connection"
    );
    gate.release();
    let (mut up, _) = tokio::time::timeout(Duration::from_secs(2), upstream.accept())
        .await
        .expect("release")
        .unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    up.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ping");
    drop(up);
    let n = tokio::time::timeout(Duration::from_secs(2), client.read(&mut buf[..1]))
        .await
        .expect("upstream close")
        .unwrap();
    assert_eq!(n, 0, "the node must see the control connection close");
}

#[tokio::test]
async fn uploaded_watch_returns_only_after_the_subscription_drops() {
    use rbitcoin_node::tor_control::{hmac_sha256, SAFECOOKIE_CLIENT_KEY, SAFECOOKIE_SERVER_KEY};
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;

    let dir = TempDir::new().unwrap();
    let cookie_path = dir.path().join("cookie");
    std::fs::write(&cookie_path, [9u8; 32]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let id = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv";
    let event =
        format!("650 HS_DESC UPLOADED {id} NO_AUTH $AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n");

    let early = std::sync::Arc::new(tokio::sync::Notify::new());
    let early_sent = std::sync::Arc::clone(&early);
    // The original subscription stays up until the test has seen that its
    // UPLOADED did not finish the watch. A timer here can expire during that
    // check and deliver the replacement event too soon.
    let close_original = std::sync::Arc::new(tokio::sync::Notify::new());
    let close_original_bg = std::sync::Arc::clone(&close_original);
    let event_bg = event.clone();
    let cookie_bg = cookie_path.clone();
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        drop(sock);

        let (sock, _) = listener.accept().await.unwrap();
        let mut write = speak_until_setevents(sock, &cookie_bg).await;
        write.write_all(event_bg.as_bytes()).await.unwrap();
        early_sent.notify_one();
        close_original_bg.notified().await;
        drop(write);

        let (sock, _) = listener.accept().await.unwrap();
        let mut write = speak_until_setevents(sock, &cookie_bg).await;
        write.write_all(event_bg.as_bytes()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
    });

    let attached = std::sync::Arc::new(tokio::sync::Notify::new());
    let resumed = std::sync::Arc::new(tokio::sync::Notify::new());
    let attached_w = std::sync::Arc::clone(&attached);
    let resumed_w = std::sync::Arc::clone(&resumed);
    let mut watch = tokio::spawn(async move {
        wait_hs_desc_uploaded(
            addr,
            &cookie_path,
            id,
            Duration::from_secs(5),
            &attached_w,
            &resumed_w,
        )
        .await;
    });
    tokio::time::timeout(Duration::from_secs(3), attached.notified())
        .await
        .expect("attached");
    early.notified().await;
    tokio::select! {
        _ = &mut watch => panic!("watch treated the original tor's UPLOADED as the restart"),
        _ = tokio::time::sleep(Duration::from_millis(250)) => {}
    }
    close_original.notify_one();
    tokio::time::timeout(Duration::from_secs(3), resumed.notified())
        .await
        .expect("resumed");
    tokio::time::timeout(Duration::from_secs(3), &mut watch)
        .await
        .expect("post-drop UPLOADED")
        .expect("watch");

    async fn speak_until_setevents(
        sock: tokio::net::TcpStream,
        cookie_path: &std::path::Path,
    ) -> tokio::net::tcp::OwnedWriteHalf {
        let cookie = std::fs::read(cookie_path).unwrap();
        let (read, mut write) = sock.into_split();
        let mut lines = BufReader::new(read).lines();
        let mut nonces = None;
        while let Ok(Some(line)) = lines.next_line().await {
            if let Some(hex) = line.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
                let client = decode_hex32(hex.trim());
                let server = [7u8; 32];
                nonces = Some((client, server));
                let mut mat = cookie.clone();
                mat.extend_from_slice(&client);
                mat.extend_from_slice(&server);
                let hash = hmac_sha256(SAFECOOKIE_SERVER_KEY, &mat);
                let reply = format!(
                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                    rbitcoin_primitives::hex_encode(hash),
                    rbitcoin_primitives::hex_encode(server)
                );
                write.write_all(reply.as_bytes()).await.unwrap();
                continue;
            }
            let reply = if line.starts_with("PROTOCOLINFO") {
                "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE\r\n250 OK\r\n"
            } else if let Some(hex) = line.strip_prefix("AUTHENTICATE ") {
                let (client, server) = nonces.expect("AUTHCHALLENGE");
                let mut mat = cookie.clone();
                mat.extend_from_slice(&client);
                mat.extend_from_slice(&server);
                let want = hmac_sha256(SAFECOOKIE_CLIENT_KEY, &mat);
                if hex.trim() == rbitcoin_primitives::hex_encode(want) {
                    "250 OK\r\n"
                } else {
                    "515 Authentication failed\r\n"
                }
            } else if line.starts_with("GETINFO version") {
                "250-version=0.4.9.16\r\n250 OK\r\n"
            } else if line.starts_with("SETEVENTS") {
                write.write_all(b"250 OK\r\n").await.unwrap();
                break;
            } else {
                "250 OK\r\n"
            };
            write.write_all(reply.as_bytes()).await.unwrap();
        }
        write
    }

    fn decode_hex32(s: &str) -> [u8; 32] {
        let bytes = rbitcoin_primitives::hex_decode(s).unwrap();
        bytes.try_into().unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tor_onion_comes_back_after_tor_restarts() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    let gate = control_gate(env.tor_control).await;
    let mut cfg = tor_b(&env, b_dir.path(), b_rpc);
    cfg.tor.control = Some(gate.listen);
    let b = spawn_node(cfg, b_rpc).await;
    generate_n(b_rpc, 3).await;
    let (onion, port) = wait_p2p_onion(b_rpc, Duration::from_secs(90)).await;
    wait_socks_onion(env.tor_socks, &onion, port, Duration::from_secs(90)).await;

    let service_id = onion.strip_suffix(".onion").unwrap_or(&onion).to_string();
    let (control, cookie) = (env.tor_control, env.tor_cookie.clone());
    let attached = std::sync::Arc::new(tokio::sync::Notify::new());
    let resumed = std::sync::Arc::new(tokio::sync::Notify::new());
    let attached_watch = std::sync::Arc::clone(&attached);
    let resumed_watch = std::sync::Arc::clone(&resumed);
    let uploaded = tokio::spawn(async move {
        wait_hs_desc_uploaded(
            control,
            &cookie,
            &service_id,
            Duration::from_secs(90),
            &attached_watch,
            &resumed_watch,
        )
        .await;
    });
    tokio::time::timeout(Duration::from_secs(30), attached.notified())
        .await
        .expect("HS_DESC watch on the tor about to restart");
    gate.hold();
    let release = gate.clone();
    let resumed_release = std::sync::Arc::clone(&resumed);
    tokio::spawn(async move {
        resumed_release.notified().await;
        release.release();
    });
    restart_daemon(&env.tor_restart).await;
    let again = wait_p2p_onion(b_rpc, Duration::from_secs(90)).await;
    assert_eq!(
        again,
        (onion.clone(), port),
        "the same onion after the restart"
    );
    uploaded.await.expect("HS_DESC upload watch");
    wait_socks_onion(env.tor_socks, &onion, port, Duration::from_secs(90)).await;

    let a = spawn_node(tor_a(&env, a_dir.path(), a_rpc, &onion, port), a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(90),
        |v| v["result"] == 3,
    )
    .await;
    wait_peer_network(a_rpc, "onion", false, Duration::from_secs(30)).await;

    a.stop().await;
    b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn i2p_destination_comes_back_after_i2pd_restarts() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    write_rpc_token(b_dir.path());
    let mut cfg_b = base_node(b_dir.path());
    cfg_b.listen.p2p = P2pListen::Socket(ephemeral_addr());
    cfg_b.listen.i2p_sam = Some(env.i2p_sam_b);
    cfg_b.listen.i2p_accept_incoming = true;
    cfg_b.listen.only_net = vec![OnlyNet::I2p];
    cfg_b.rpc.listen = Some(b_rpc);
    let b = spawn_node(cfg_b, b_rpc).await;
    generate_n(b_rpc, 3).await;
    let dest = wait_file(
        &b_dir.path().join("i2p").join("p2p.priv"),
        Duration::from_secs(180),
    )
    .await;
    let b32 = i2p_b32_from_dest(&dest);
    wait_i2p_stream(env.i2p_sam, &b32, Duration::from_secs(180)).await;

    restart_daemon(&env.i2p_restart_b).await;
    wait_jsonrpc(
        b_rpc,
        "getnetworkinfo",
        json!([]),
        Duration::from_secs(180),
        |v| localaddresses(v).iter().any(|r| r["address"] == b32),
    )
    .await;
    wait_i2p_stream(env.i2p_sam, &b32, Duration::from_secs(180)).await;
    tokio::time::sleep(Duration::from_secs(2)).await;

    write_rpc_token(a_dir.path());
    let mut cfg_a = base_node(a_dir.path());
    cfg_a.listen.p2p = P2pListen::Off;
    cfg_a.listen.i2p_sam = Some(env.i2p_sam);
    cfg_a.listen.only_net = vec![OnlyNet::I2p];
    cfg_a.listen.connect = vec![format!("{b32}:0").parse().unwrap()];
    cfg_a.rpc.listen = Some(a_rpc);
    let a = spawn_node(cfg_a, a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(180),
        |v| v["result"] == 3,
    )
    .await;
    wait_peer_network(a_rpc, "i2p", false, Duration::from_secs(60)).await;

    a.stop().await;
    b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cjdns_listener_works_after_cjdroute_restarts() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();
    let b_p2p = std::net::TcpListener::bind((env.cjdns_b, 0))
        .and_then(|l| l.local_addr())
        .unwrap_or_else(|e| panic!("bind {} (TUN missing?): {e}", env.cjdns_b));
    let a_p2p = std::net::TcpListener::bind((env.cjdns_a, 0))
        .and_then(|l| l.local_addr())
        .unwrap_or_else(|e| panic!("bind {} (TUN missing?): {e}", env.cjdns_a));

    write_rpc_token(b_dir.path());
    let mut cfg_b = base_node(b_dir.path());
    cfg_b.listen.p2p = P2pListen::Socket(b_p2p);
    cfg_b.listen.cjdns_reachable = true;
    cfg_b.listen.only_net = vec![OnlyNet::Cjdns];
    cfg_b.rpc.listen = Some(b_rpc);
    let b = spawn_node(cfg_b, b_rpc).await;
    generate_n(b_rpc, 3).await;

    write_rpc_token(a_dir.path());
    let mut cfg_a = base_node(a_dir.path());
    cfg_a.listen.p2p = P2pListen::Socket(a_p2p);
    cfg_a.listen.cjdns_reachable = true;
    cfg_a.listen.only_net = vec![OnlyNet::Cjdns];
    cfg_a.listen.connect = vec![NetAddr::from_str(&b_p2p.to_string()).unwrap()];
    cfg_a.rpc.listen = Some(a_rpc);
    let a = spawn_node(cfg_a, a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(60),
        |v| v["result"] == 3,
    )
    .await;
    let before = wait_peer_network(b_rpc, "cjdns", true, Duration::from_secs(20)).await;
    let before_ids: Vec<u64> = before["result"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["inbound"] == true)
        .filter_map(|p| p["id"].as_u64())
        .collect();

    restart_daemon(&env.cjdns_restart_b).await;

    let peers = jsonrpc(a_rpc, "getpeerinfo", json!([])).await;
    for p in peers["result"].as_array().unwrap() {
        jsonrpc(a_rpc, "disconnectnode", json!(["", p["id"]])).await;
    }
    generate_n(b_rpc, 2).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(90),
        |v| v["result"] == 5,
    )
    .await;
    wait_jsonrpc(
        b_rpc,
        "getpeerinfo",
        json!([]),
        Duration::from_secs(30),
        |v| {
            v["result"].as_array().is_some_and(|rows| {
                rows.iter().any(|p| {
                    p["inbound"] == true
                        && p["network"] == "cjdns"
                        && p["id"].as_u64().is_some_and(|id| !before_ids.contains(&id))
                })
            })
        },
    )
    .await;

    a.stop().await;
    b.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ephemeral_socks_isolated_broadcast() {
    let env = require_env();
    let b_dir = TempDir::new().unwrap();
    let a_dir = TempDir::new().unwrap();
    let b_rpc = ephemeral_addr();
    let a_rpc = ephemeral_addr();

    let b = spawn_node(tor_b(&env, b_dir.path(), b_rpc), b_rpc).await;
    generate_n(b_rpc, 101).await;
    let (onion, port) = wait_p2p_onion(b_rpc, Duration::from_secs(90)).await;
    wait_socks_onion(env.tor_socks, &onion, port, Duration::from_secs(90)).await;

    let a = spawn_node(tor_a(&env, a_dir.path(), a_rpc, &onion, port), a_rpc).await;
    wait_jsonrpc(
        a_rpc,
        "getblockcount",
        json!([]),
        Duration::from_secs(90),
        |v| v["result"] == 101,
    )
    .await;
    wait_peer_network(a_rpc, "onion", false, Duration::from_secs(30)).await;

    let hash = jsonrpc(b_rpc, "getblockhash", json!([1])).await["result"]
        .as_str()
        .unwrap()
        .to_string();
    let blk = jsonrpc(b_rpc, "getblock", json!([hash, 2])).await;
    let coinbase = blk["result"]["tx"][0]["txid"].as_str().unwrap();
    let txid = bitcoin::Txid::from_str(coinbase).unwrap();
    let spend = spend_anyone_can_spend(txid, 0, Amount::from_sat(4_999_990_000));
    let hex = serialize_hex(&spend);
    let sent = jsonrpc(a_rpc, "sendrawtransaction", json!([hex])).await;
    assert!(sent["error"].is_null(), "sendrawtransaction: {sent}");
    let want = spend.compute_txid().to_string();

    tokio::time::sleep(Duration::from_millis(400)).await;
    let standing = jsonrpc(a_rpc, "getpeerinfo", json!([])).await;
    for p in standing["result"].as_array().unwrap() {
        let inv = p["bytessent_per_msg"]
            .get("inv")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        assert_eq!(inv, 0, "standing session must not INV local tx: {standing}");
    }

    wait_jsonrpc(
        b_rpc,
        "getrawmempool",
        json!([]),
        Duration::from_secs(90),
        |v| {
            v["result"]
                .as_array()
                .is_some_and(|m| m.iter().any(|t| t == &want))
        },
    )
    .await;

    a.stop().await;
    b.stop().await;
}

#[tokio::test]
#[should_panic(expected = "rpc getblockcount json:")]
async fn jsonrpc_try_panics_when_the_body_is_not_json() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 2048];
        let _ = sock.read(&mut buf).await;
        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope";
        sock.write_all(resp).await.unwrap();
    });
    let _ = jsonrpc_try(addr, "getblockcount", serde_json::json!([])).await;
}
