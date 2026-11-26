//! Helpers for the labeled overlay-functional journeys (real private meshes).

use rbitcoin_node::NodeConfig;
use rbitcoin_primitives::Network;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

pub const RPC_BEARER: &str = "Bearer pass";

pub struct OverlayEnv {
    pub tor_socks: SocketAddr,
    pub tor_control: SocketAddr,
    pub tor_cookie: PathBuf,
    pub i2p_sam: SocketAddr,
    pub i2p_sam_b: SocketAddr,
    pub cjdns_a: std::net::Ipv6Addr,
    pub cjdns_b: std::net::Ipv6Addr,
    pub tor_restart: PathBuf,
    pub i2p_restart_b: PathBuf,
    pub cjdns_restart_b: PathBuf,
}

pub fn require_env() -> OverlayEnv {
    OverlayEnv {
        tor_socks: req_addr("OVERLAY_TOR_SOCKS"),
        tor_control: req_addr("OVERLAY_TOR_CONTROL"),
        tor_cookie: PathBuf::from(req("OVERLAY_TOR_COOKIE")),
        i2p_sam: req_addr("OVERLAY_I2P_SAM"),
        i2p_sam_b: req_addr("OVERLAY_I2P_SAM_B"),
        cjdns_a: req("OVERLAY_CJDNS_A")
            .parse()
            .unwrap_or_else(|e| panic!("OVERLAY_CJDNS_A: {e}")),
        cjdns_b: req("OVERLAY_CJDNS_B")
            .parse()
            .unwrap_or_else(|e| panic!("OVERLAY_CJDNS_B: {e}")),
        tor_restart: PathBuf::from(req("OVERLAY_TOR_RESTART")),
        i2p_restart_b: PathBuf::from(req("OVERLAY_I2P_RESTART_B")),
        cjdns_restart_b: PathBuf::from(req("OVERLAY_CJDNS_RESTART_B")),
    }
}

pub async fn restart_daemon(script: &Path) {
    let script = script.to_path_buf();
    let out = tokio::task::spawn_blocking(move || {
        std::process::Command::new("bash").arg(&script).output()
    })
    .await
    .unwrap()
    .unwrap_or_else(|e| panic!("restart script: {e}"));
    assert!(
        out.status.success(),
        "restart script failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn req(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} is unset; run via ./scripts/overlay-functional/run.sh"))
}

fn req_addr(name: &str) -> SocketAddr {
    req(name).parse().unwrap_or_else(|e| panic!("{name}: {e}"))
}

pub fn ephemeral_addr() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

pub fn base_node(datadir: &Path) -> NodeConfig {
    let mut cfg = NodeConfig::default()
        .with_datadir(datadir)
        .with_network(Network::Regtest)
        .with_tiny_heads();
    cfg.listen.use_seeds = false;
    cfg.listen.discover = false;
    cfg.max_tip_age_secs = Some(u64::MAX);
    cfg
}

pub struct NodeProc {
    rpc: SocketAddr,
    handle: Option<JoinHandle<Result<(), rbitcoin_node::NodeError>>>,
}

impl NodeProc {
    pub async fn stop(mut self) {
        let _ = jsonrpc(self.rpc, "stop", serde_json::json!([])).await;
        let handle = self.handle.take().expect("stop once");
        match tokio::time::timeout(Duration::from_secs(15), handle).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(e))) => panic!("run_p2p: {e}"),
            Ok(Err(e)) => panic!("run_p2p join: {e}"),
            Err(_) => panic!("run_p2p did not exit after stop"),
        }
    }
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

pub async fn spawn_node(cfg: NodeConfig, rpc: SocketAddr) -> NodeProc {
    // Dedicated blocking pool thread: `run_p2p` does tip-accept on the
    // future that `block_on` polls. Tokio names spawn_blocking threads
    // `tokio-rt-worker`; BlockingRegion is the same seam as live P2P tests.
    let handle = tokio::task::spawn_blocking(move || {
        let _block = rbitcoin_net::BlockingRegion::enter();
        tokio::runtime::Handle::current().block_on(rbitcoin_node::run_p2p(cfg))
    });
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if handle.is_finished() {
            match handle.await {
                Ok(Ok(())) => panic!("run_p2p exited before rpc {rpc}"),
                Ok(Err(e)) => panic!("run_p2p: {e}"),
                Err(e) => panic!("run_p2p join: {e}"),
            }
        }
        if TcpStream::connect(rpc).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if handle.is_finished() {
                match handle.await {
                    Ok(Ok(())) => panic!("run_p2p exited after rpc {rpc}"),
                    Ok(Err(e)) => panic!("run_p2p: {e}"),
                    Err(e) => panic!("run_p2p join: {e}"),
                }
            }
            return NodeProc {
                rpc,
                handle: Some(handle),
            };
        }
        if Instant::now() >= deadline {
            panic!("listeners not up ({rpc})");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn jsonrpc(addr: SocketAddr, method: &str, params: Value) -> Value {
    crate::jsonrpc::jsonrpc(addr, method, params).await
}

#[doc(hidden)]
pub async fn jsonrpc_try(addr: SocketAddr, method: &str, params: Value) -> Result<Value, String> {
    crate::jsonrpc::try_jsonrpc(addr, method, params)
        .await
        .map_err(|e| format!("rpc connect: {e}"))
}

pub async fn wait_jsonrpc(
    addr: SocketAddr,
    method: &str,
    params: Value,
    wall: Duration,
    ok: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + wall;
    loop {
        let last = match jsonrpc_try(addr, method, params.clone()).await {
            Ok(v) if ok(&v) => return v,
            Ok(v) => v.to_string(),
            Err(e) => e,
        };
        if Instant::now() >= deadline {
            panic!("{method} wall {wall:?}: {last}");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

pub fn localaddresses(info: &Value) -> &[Value] {
    info["result"]["localaddresses"]
        .as_array()
        .expect("localaddresses")
}

pub fn onion_host(row: &Value) -> Option<&str> {
    row["address"].as_str().filter(|s| s.ends_with(".onion"))
}

pub async fn wait_p2p_onion(rpc: SocketAddr, wall: Duration) -> (String, u16) {
    let info = wait_jsonrpc(rpc, "getnetworkinfo", serde_json::json!([]), wall, |v| {
        localaddresses(v)
            .iter()
            .any(|r| onion_host(r).is_some() && r["port"] == Network::Regtest.default_p2p_port())
    })
    .await;
    for row in localaddresses(&info) {
        if let Some(host) = onion_host(row) {
            if row["port"] == Network::Regtest.default_p2p_port() {
                return (host.to_string(), Network::Regtest.default_p2p_port());
            }
        }
    }
    panic!("p2p onion missing: {info}");
}

/// `650 HS_DESC UPLOADED <service_id> …` — not `UPLOAD`, which is only the attempt.
pub fn hs_desc_uploaded(line: &str, service_id: &str) -> bool {
    let mut parts = line.split_whitespace();
    parts.next() == Some("650")
        && parts.next() == Some("HS_DESC")
        && parts.next() == Some("UPLOADED")
        && parts.next() == Some(service_id)
}

/// Where the HS_DESC watch is relative to the tor the caller is about to kill.
///
/// A connect or `SETEVENTS` miss while `Attaching` is not that kill. Only the
/// close of the subscription moves to `Dropped`, and only then does `UPLOADED`
/// count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HsDescWatch {
    Attaching,
    Subscribed,
    Dropped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HsDescWatchEvent {
    /// Auth or `SETEVENTS` failed before this connection was subscribed.
    Miss,
    Subscribed,
    /// The subscribed control connection closed.
    Closed,
}

fn hs_desc_watch_advance(phase: HsDescWatch, event: HsDescWatchEvent) -> HsDescWatch {
    match (phase, event) {
        (HsDescWatch::Attaching, HsDescWatchEvent::Subscribed) => HsDescWatch::Subscribed,
        (HsDescWatch::Subscribed, HsDescWatchEvent::Closed) => HsDescWatch::Dropped,
        (phase, _) => phase,
    }
}

/// Block until Tor reports `HS_DESC UPLOADED` for `service_id` on a control
/// connection opened after the previous one dropped.
///
/// `attached` fires once `SETEVENTS HS_DESC` is live, so the caller can restart
/// tor only after this watch is on the process it is about to kill. `resumed`
/// fires when a later connection has subscribed after that one closed.
///
/// Tor 0.4.9 does not replay `HS_DESC`. The caller holds the node's control
/// port until `resumed`, so `ADD_ONION` cannot finish an upload before this
/// subscription. The service descriptor cache is not that signal: Tor fills it
/// before any directory stores the descriptor. A SOCKS connect in that gap
/// fetches the descriptor still stored from the process that just died.
pub async fn wait_hs_desc_uploaded(
    addr: SocketAddr,
    cookie: &Path,
    service_id: &str,
    wall: Duration,
    attached: &tokio::sync::Notify,
    resumed: &tokio::sync::Notify,
) {
    use rbitcoin_node::tor_control::{TorAuth, TorControl};
    let deadline = Instant::now() + wall;
    let attempt = Duration::from_millis(250);
    let mut phase = HsDescWatch::Attaching;
    let mut told_attached = false;
    loop {
        if Instant::now() >= deadline {
            panic!("HS_DESC UPLOADED {service_id} wall {wall:?}");
        }
        let mut ctl = match tokio::time::timeout(
            attempt,
            TorControl::connect_and_auth(addr, TorAuth::Cookie(cookie.to_path_buf()), attempt),
        )
        .await
        {
            Ok(Ok(ctl)) => ctl,
            _ => {
                phase = hs_desc_watch_advance(phase, HsDescWatchEvent::Miss);
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if ctl.command("SETEVENTS HS_DESC").await.is_err() {
            phase = hs_desc_watch_advance(phase, HsDescWatchEvent::Miss);
            continue;
        }
        let before = phase;
        phase = hs_desc_watch_advance(phase, HsDescWatchEvent::Subscribed);
        if before == HsDescWatch::Attaching && !told_attached {
            attached.notify_one();
            told_attached = true;
        }
        if before == HsDescWatch::Dropped {
            resumed.notify_one();
        }
        let mut lines = ctl.reader.lines();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                panic!("HS_DESC UPLOADED {service_id} wall {wall:?}");
            }
            match tokio::time::timeout(left, lines.next_line()).await {
                Ok(Ok(Some(line))) => {
                    if phase == HsDescWatch::Dropped && hs_desc_uploaded(line.trim(), service_id) {
                        return;
                    }
                }
                Ok(Ok(None)) | Ok(Err(_)) => {
                    phase = hs_desc_watch_advance(phase, HsDescWatchEvent::Closed);
                    break;
                }
                Err(_) => panic!("HS_DESC UPLOADED {service_id} wall {wall:?}"),
            }
        }
    }
}

/// Forwards control-port bytes to `upstream`. [`ControlGate::hold`] keeps a new
/// connection here until [`ControlGate::release`], so the node cannot
/// `ADD_ONION` on the replacement tor before the upload watch has subscribed.
#[derive(Clone)]
pub struct ControlGate {
    pub listen: SocketAddr,
    hold: tokio::sync::watch::Sender<bool>,
    _task: Arc<AbortJoin>,
}

struct AbortJoin(Mutex<Option<JoinHandle<()>>>);

impl Drop for AbortJoin {
    fn drop(&mut self) {
        if let Some(task) = self.0.lock().expect("control gate").take() {
            task.abort();
        }
    }
}

struct AbortConn(JoinHandle<()>);

impl Drop for AbortConn {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn control_gate(upstream: SocketAddr) -> ControlGate {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap_or_else(|e| panic!("control gate: {e}"));
    let listen = listener
        .local_addr()
        .unwrap_or_else(|e| panic!("control gate: {e}"));
    let (hold, held) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(async move {
        let mut conns = Vec::new();
        loop {
            let Ok((down, _)) = listener.accept().await else {
                break;
            };
            conns.retain(|conn: &AbortConn| !conn.0.is_finished());
            let mut held = held.clone();
            conns.push(AbortConn(tokio::spawn(async move {
                while *held.borrow() {
                    if held.changed().await.is_err() {
                        return;
                    }
                }
                let Ok(up) = TcpStream::connect(upstream).await else {
                    return;
                };
                let (mut dr, mut dw) = down.into_split();
                let (mut ur, mut uw) = up.into_split();
                // A finished copy has to close the other write half. Otherwise
                // the node keeps the dead control session and never republishes.
                let to_up = async move {
                    let _ = tokio::io::copy(&mut dr, &mut uw).await;
                    let _ = uw.shutdown().await;
                };
                let to_down = async move {
                    let _ = tokio::io::copy(&mut ur, &mut dw).await;
                    let _ = dw.shutdown().await;
                };
                tokio::join!(to_up, to_down);
            })));
        }
    });
    ControlGate {
        listen,
        hold,
        _task: Arc::new(AbortJoin(Mutex::new(Some(task)))),
    }
}

impl ControlGate {
    pub fn hold(&self) {
        self.hold.send(true).ok();
    }

    pub fn release(&self) {
        self.hold.send(false).ok();
    }
}

/// SOCKS domain CONNECT until the onion TCP port accepts (HSDir / ADD_ONION ready).
pub async fn wait_socks_onion(proxy: SocketAddr, host: &str, port: u16, wall: Duration) {
    let deadline = Instant::now() + wall;
    loop {
        let dialer = rbitcoin_net::Dialer::socks(proxy, true);
        match dialer.connect_domain(host, port).await {
            Ok(_) => return,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("SOCKS onion {host}:{port} wall {wall:?}: {e}");
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// SAM STREAM CONNECT until the dest accepts (leaseset published on the private mesh).
/// One throwaway session, then drop it before the product node uses this SAM.
pub async fn wait_i2p_stream(sam: SocketAddr, dest_b32: &str, wall: Duration) {
    let deadline = Instant::now() + wall;
    let session = loop {
        match rbitcoin_net::I2pSam::connect(sam, rbitcoin_net::SAM_RETRY_TEST).await {
            Ok(s) => break s,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("I2P session {sam} wall {wall:?}: {e}");
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    loop {
        match session.stream_connect(dest_b32).await {
            Ok(_) => return,
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!("I2P STREAM {dest_b32} wall {wall:?}: {e}");
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

pub async fn wait_onion_port(rpc: SocketAddr, port: u16, wall: Duration) -> String {
    let info = wait_jsonrpc(rpc, "getnetworkinfo", serde_json::json!([]), wall, |v| {
        localaddresses(v)
            .iter()
            .any(|r| onion_host(r).is_some() && r["port"] == port)
    })
    .await;
    for row in localaddresses(&info) {
        if onion_host(row).is_some() && row["port"] == port {
            return onion_host(row).unwrap().to_string();
        }
    }
    panic!("onion port {port} missing: {info}");
}

pub async fn wait_peer_network(rpc: SocketAddr, net: &str, inbound: bool, wall: Duration) -> Value {
    wait_jsonrpc(rpc, "getpeerinfo", serde_json::json!([]), wall, |v| {
        handshaken_peer_on_network(v, net, inbound).is_some()
    })
    .await
}

pub fn handshaken_peer_on_network<'a>(
    info: &'a Value,
    net: &str,
    inbound: bool,
) -> Option<&'a Value> {
    info["result"].as_array()?.iter().find(|row| {
        row["network"] == net
            && row["inbound"] == inbound
            && row["version"].as_u64().is_some_and(|version| version > 0)
    })
}

pub use crate::i2p_dest::i2p_b32_from_dest;

pub async fn socks_http_get(proxy: SocketAddr, host: &str, port: u16, path: &str) -> (u16, String) {
    let dialer = rbitcoin_net::Dialer::socks(proxy, true);
    let mut stream = dialer
        .connect_domain(host, port)
        .await
        .unwrap_or_else(|e| panic!("SOCKS {host}:{port}: {e}"));
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    (status, body)
}

pub async fn socks_electrum_rpc(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    method: &str,
    params: Value,
) -> Value {
    let dialer = rbitcoin_net::Dialer::socks(proxy, true);
    let mut stream = dialer
        .connect_domain(host, port)
        .await
        .unwrap_or_else(|e| panic!("SOCKS electrum {host}:{port}: {e}"));
    let req = serde_json::json!({"id":1,"jsonrpc":"2.0","method":method,"params":params})
        .to_string()
        + "\n";
    stream.write_all(req.as_bytes()).await.unwrap();
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .await
        .expect("electrum read");
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("electrum {method}: {e} body={line}"))
}

pub async fn wait_file(path: &Path, wall: Duration) -> String {
    let deadline = Instant::now() + wall;
    loop {
        if let Ok(s) = std::fs::read_to_string(path) {
            let t = s.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
        if Instant::now() >= deadline {
            panic!("missing {} after {wall:?}", path.display());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
