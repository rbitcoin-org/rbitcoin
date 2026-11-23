//! Asmap files an operator drops in the datadir, checked from one node.
//!
//! Inbound clients are raw BIP324 sockets bound on `127.0.0.0/8`. No second
//! node, no DNS seeds, no outbound dial.

use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::ServiceFlags;
use rbitcoin_net::V2PlainSession;
use rbitcoin_test::journey_node::JourneyNode;
use rbitcoin_test::jsonrpc::write_rpc_token;
use rbitcoin_test::{llvm_cov_wall, TestDatadir};
use serde_json::{json, Value};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

async fn published_listener(datadir: &Path, name: &str) -> SocketAddr {
    rbitcoin_node::run::wait_published_listener(datadir, name, Duration::from_secs(20)).await
}

async fn jsonrpc(addr: SocketAddr, method: &str, params: Value) -> Value {
    rbitcoin_test::jsonrpc::jsonrpc(addr, method, params).await
}

async fn handshake(bind_ip: Ipv4Addr, to: SocketAddr, agent: &str) -> V2PlainSession {
    let sock = tokio::net::TcpSocket::new_v4().expect("v4 socket");
    sock.bind(SocketAddr::new(IpAddr::V4(bind_ip), 0))
        .unwrap_or_else(|e| panic!("bind {bind_ip}: {e}"));
    let stream = tokio::time::timeout(Duration::from_secs(5), sock.connect(to))
        .await
        .unwrap_or_else(|_| panic!("connect {bind_ip} to {to} timed out"))
        .unwrap_or_else(|e| panic!("connect {bind_ip} to {to}: {e}"));
    let mut raw = V2PlainSession::outbound_bip324(stream)
        .await
        .expect("bip324");
    let ver = VersionMessage {
        version: 70016,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp: 0,
        receiver: Address::new(&to, ServiceFlags::NONE),
        sender: Address::new(&to, ServiceFlags::NONE),
        nonce: u64::from(bind_ip.octets()[3]),
        user_agent: agent.into(),
        start_height: 0,
        relay: true,
    };
    for msg in [NetworkMessage::Version(ver), NetworkMessage::Verack] {
        raw.write_contents(&rbitcoin_net::encode_v2_contents(msg).expect("encode"))
            .await
            .expect("write handshake");
    }
    raw
}

fn mapped_as(rows: &Value, ip: Ipv4Addr) -> u64 {
    let prefix = format!("{ip}:");
    let row = rows
        .as_array()
        .unwrap_or_else(|| panic!("getpeerinfo is not a list: {rows}"))
        .iter()
        .find(|row| {
            row["addr"]
                .as_str()
                .is_some_and(|addr| addr.starts_with(&prefix))
        })
        .unwrap_or_else(|| panic!("no peer {ip} in {rows}"));
    row["mapped_as"]
        .as_u64()
        .unwrap_or_else(|| panic!("peer {ip} has no mapped_as: {row}"))
}

async fn wait_peers(rpc: SocketAddr, n: usize) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let info = jsonrpc(rpc, "getpeerinfo", json!([])).await;
        let count = info["result"].as_array().map(|a| a.len()).unwrap_or(0);
        if count >= n {
            return info["result"].clone();
        }
        if Instant::now() >= deadline {
            panic!("expected {n} peers, got {info}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// The operator CLI binary (`journey-node`), for tests that read its output.
pub(crate) fn node_bin() -> PathBuf {
    // Cargo 1.95 keeps the hyphen in `CARGO_BIN_EXE_journey-node`.
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_journey-node"));
    assert!(
        bin.is_file(),
        "operator CLI missing at {} (journey-node is rbitcoin_node::process_main)",
        bin.display()
    );
    bin
}

#[test]
fn journey_node_ignores_a_decoy_target_dir() {
    if std::env::var_os("RBITCOIN_DECOY_TARGET").is_some() {
        assert_eq!(
            node_bin(),
            PathBuf::from(env!("CARGO_BIN_EXE_journey-node")),
            "spawn path followed CARGO_TARGET_DIR instead of the bin cargo built"
        );
        return;
    }
    let exe = std::env::current_exe().expect("test executable");
    let out = Command::new(exe)
        .env("CARGO_TARGET_DIR", "/no/such/mutants-target")
        .env("RBITCOIN_DECOY_TARGET", "1")
        .arg("asmap_journey::journey_node_ignores_a_decoy_target_dir")
        .arg("--exact")
        .output()
        .expect("re-exec test binary");
    assert!(
        out.status.success(),
        "decoy CARGO_TARGET_DIR changed the journey-node path\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn spawn_node(dir: &Path, extra: &[&str]) -> JourneyNode {
    let mut cmd = Command::new(node_bin());
    cmd.arg("--datadir")
        .arg(dir)
        .arg("--network")
        .arg("regtest")
        .arg("--no-seeds")
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--rpc-listen")
        .arg("127.0.0.1:0")
        .arg("--log-level")
        .arg("info")
        .arg("--milestone")
        .arg("0");
    cmd.args(extra);
    JourneyNode::spawn(cmd)
}

fn assert_stderr_opened(text: &str, len: usize, digest: &str) {
    assert!(
        text.contains(&format!("({len} bytes, digest {digest})")),
        "opened line missing from process stderr: {text}"
    );
    assert!(
        !text.contains("Sanity check of asmap file"),
        "a valid asmap was refused: {text}"
    );
}

/// Loopback peers report the ASN from `{datadir}/ip_asn.dat`, then a relative
/// `--asmap` of a lone return maps the same peer to ASN 1.
#[tokio::test(flavor = "multi_thread")]
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "binds 127.0.0.2 and .3; only Linux routes all of 127.0.0.0/8 on lo"
)]
async fn asmap_loopback_peers_report_their_asn() {
    let wall = llvm_cov_wall(20, 60);
    let fut = async {
        let td = TestDatadir::new().unwrap();
        let dir = td.path();
        std::fs::write(dir.join("ip_asn.dat"), rbitcoin_net::LOOPBACK_ASMAP).unwrap();
        write_rpc_token(&dir);
        let node = spawn_node(&dir, &[]);
        let rpc = published_listener(&dir, "rpc").await;
        let p2p = published_listener(&dir, "p2p").await;
        let _a = handshake(Ipv4Addr::new(127, 0, 0, 1), p2p, "/asmap-1/").await;
        let _b = handshake(Ipv4Addr::new(127, 0, 0, 2), p2p, "/asmap-2/").await;
        let _c = handshake(Ipv4Addr::new(127, 0, 0, 3), p2p, "/asmap-3/").await;
        let rows = wait_peers(rpc, 3).await;
        assert_eq!(mapped_as(&rows, Ipv4Addr::new(127, 0, 0, 1)), 1, "{rows}");
        assert_eq!(mapped_as(&rows, Ipv4Addr::new(127, 0, 0, 2)), 2, "{rows}");
        assert_eq!(mapped_as(&rows, Ipv4Addr::new(127, 0, 0, 3)), 9, "{rows}");
        let stderr = node.stop(rpc, llvm_cov_wall(10, 30)).await;
        assert_stderr_opened(&stderr, rbitcoin_net::LOOPBACK_ASMAP.len(), "0d2045c8");

        let td = TestDatadir::new().unwrap();
        let dir = td.path();
        std::fs::write(dir.join("asn1.dat"), rbitcoin_net::LONE_RETURN_ASMAP).unwrap();
        write_rpc_token(&dir);
        let node = spawn_node(&dir, &["--asmap", "asn1.dat"]);
        let rpc = published_listener(&dir, "rpc").await;
        let p2p = published_listener(&dir, "p2p").await;
        let _peer = handshake(Ipv4Addr::new(127, 0, 0, 1), p2p, "/asmap-lone/").await;
        let rows = wait_peers(rpc, 1).await;
        assert_eq!(mapped_as(&rows, Ipv4Addr::new(127, 0, 0, 1)), 1, "{rows}");
        let stderr = node.stop(rpc, llvm_cov_wall(10, 30)).await;
        assert_stderr_opened(&stderr, 3, "709e80c8");
    };
    tokio::time::timeout(wall, fut).await.unwrap_or_else(|_| {
        panic!("asmap_loopback_peers_report_their_asn wall timeout ({wall:?})")
    });
}

fn assert_stderr_refused(text: &str, phrase: &str) {
    assert!(
        text.contains(phrase),
        "missing {phrase:?} on process stderr: {text}"
    );
    assert!(
        !text.contains("Opened asmap file"),
        "a refused asmap loaded: {text}"
    );
}

/// One datadir, one `rbitcoin-node --max-run-secs 0`. Exit success is not
/// enough: the warning on stderr is the refusal.
async fn boot_refused(dir: &Path, file: &str, phrase: &str) {
    let node = spawn_node(dir, &["--asmap", file, "--max-run-secs", "0"]);
    let stderr = node.wait_exit(llvm_cov_wall(10, 30)).await;
    assert_stderr_refused(&stderr, phrase);
}

/// One rejected bytecode and a missing path. Each is its own process. The
/// other rejected bytecodes are `asmap_rejected_bytecodes_fail_sanity`.
#[tokio::test(flavor = "multi_thread")]
async fn asmap_refused_file_uses_prefix_netgroups() {
    let wall = llvm_cov_wall(20, 60);
    let fut = async {
        let td = TestDatadir::new().unwrap();
        let dir = td.path();
        std::fs::write(
            dir.join("second-default.dat"),
            rbitcoin_net::ASMAP_SECOND_DEFAULT,
        )
        .unwrap();
        boot_refused(&dir, "second-default.dat", "Sanity check of asmap file").await;

        let td = TestDatadir::new().unwrap();
        boot_refused(&td.path(), "no-such-asmap", "Failed to open asmap file").await;
    };
    tokio::time::timeout(wall, fut).await.unwrap_or_else(|_| {
        panic!("asmap_refused_file_uses_prefix_netgroups wall timeout ({wall:?})")
    });
}
