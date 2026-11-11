//! A heavier header chain whose bodies are never served must not hold IBD
//! below the best chain whose bodies it can get. Core keeps connecting the
//! honest chain while the header-only branch sits in its block index.
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::p2p::{message::NetworkMessage, message_blockdata::Inventory, Magic};
use bitcoin::Block;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_ibd::ibd::IbdConfig;
use rbitcoin_net::peer::{connect_and_handshake_timed, HandshakePolicy};
use rbitcoin_net::service::P2PNode;
use rbitcoin_net::v2::{read_v2_frame, write_v2_msg};
use rbitcoin_query::Query;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::Notify;

/// Honest tip height.
const N: u32 = 40;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Withhold {
    /// No reply to getdata for a withheld block.
    Silent,
    /// `notfound` for a withheld block.
    NotFound,
    /// `notfound`, then an `inv` for the top of the chain it already
    /// announced, so the refusal looks stale.
    NotFoundReannounce,
    /// Close the connection after the fork headers go out, and stay gone.
    Disconnect,
}

enum Cmd {
    Headers(Vec<Header>),
    ReleaseHeld,
    Close,
}

struct Peer {
    name: &'static str,
    chain: Mutex<Vec<Block>>,
    /// Highest height a getheaders reply reaches.
    header_cap: AtomicU32,
    /// Bodies at or above this height are never served.
    withhold_from: u32,
    mode: Withhold,
    /// Body held until `ReleaseHeld` (u32::MAX: none).
    hold: AtomicU32,
    cmds: Mutex<VecDeque<Cmd>>,
    notify: Notify,
    gone: AtomicBool,
    parked: AtomicUsize,
    bodies: AtomicUsize,
    withheld_asks: AtomicUsize,
    unknown_asks: AtomicUsize,
    connects: AtomicUsize,
    getheaders: AtomicUsize,
}

impl Peer {
    fn new(
        name: &'static str,
        chain: Vec<Block>,
        header_cap: u32,
        withhold_from: u32,
        mode: Withhold,
    ) -> Arc<Self> {
        Arc::new(Self {
            name,
            chain: Mutex::new(chain),
            header_cap: AtomicU32::new(header_cap),
            withhold_from,
            mode,
            hold: AtomicU32::new(u32::MAX),
            cmds: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            gone: AtomicBool::new(false),
            parked: AtomicUsize::new(0),
            bodies: AtomicUsize::new(0),
            withheld_asks: AtomicUsize::new(0),
            unknown_asks: AtomicUsize::new(0),
            connects: AtomicUsize::new(0),
            getheaders: AtomicUsize::new(0),
        })
    }

    fn send(&self, cmd: Cmd) {
        self.cmds.lock().unwrap().push_back(cmd);
        self.notify.notify_one();
    }

    fn stats(&self) -> String {
        format!(
            "{}: connects={} getheaders={} bodies={} withheld_asks={} unknown_asks={} gone={}",
            self.name,
            self.connects.load(Ordering::SeqCst),
            self.getheaders.load(Ordering::SeqCst),
            self.bodies.load(Ordering::SeqCst),
            self.withheld_asks.load(Ordering::SeqCst),
            self.unknown_asks.load(Ordering::SeqCst),
            self.gone.load(Ordering::SeqCst),
        )
    }
}

async fn serve_one(
    listener: &TcpListener,
    peer: &Arc<Peer>,
) -> Result<(), rbitcoin_net::error::NetError> {
    let (stream, remote) = listener.accept().await?;
    if peer.gone.load(Ordering::SeqCst) {
        return Ok(());
    }
    peer.connects.fetch_add(1, Ordering::SeqCst);
    let local = stream.local_addr()?;
    let start_height = {
        let top = peer.chain.lock().unwrap().len() as u32 - 1;
        top.min(peer.header_cap.load(Ordering::SeqCst)) as i32
    };
    let (_, mut reader, mut writer, _, _shutdown) = connect_and_handshake_timed(
        Duration::from_secs(5),
        stream,
        Magic::REGTEST,
        local,
        remote,
        start_height,
        true,
        "/withheld-fork/",
        HandshakePolicy::plain(),
    )
    .await?;
    let mut pending: VecDeque<Block> = VecDeque::new();
    let mut parked: Vec<Block> = Vec::new();
    let mut sends = tokio::time::interval(Duration::from_millis(5));
    loop {
        let frame = tokio::select! {
            _ = sends.tick(), if !pending.is_empty() => {
                let block = pending.pop_front().unwrap();
                write_v2_msg(&mut writer, NetworkMessage::Block(block)).await?;
                peer.bodies.fetch_add(1, Ordering::SeqCst);
                continue;
            }
            _ = peer.notify.notified() => {
                let cmds: Vec<Cmd> = peer.cmds.lock().unwrap().drain(..).collect();
                for cmd in cmds {
                    match cmd {
                        Cmd::Headers(headers) => {
                            eprintln!("{} sends {} unsolicited header(s)", peer.name, headers.len());
                            write_v2_msg(&mut writer, NetworkMessage::Headers(headers)).await?;
                        }
                        Cmd::ReleaseHeld => {
                            peer.hold.store(u32::MAX, Ordering::SeqCst);
                            pending.extend(parked.drain(..));
                        }
                        Cmd::Close => {
                            peer.gone.store(true, Ordering::SeqCst);
                            return Ok(());
                        }
                    }
                }
                continue;
            }
            result = read_v2_frame(&mut reader, Magic::REGTEST) => result?,
        };
        let message = rbitcoin_net::msg_decode::decode_framed_offload(frame).await?;
        match message.payload() {
            NetworkMessage::GetHeaders(request) => {
                peer.getheaders.fetch_add(1, Ordering::SeqCst);
                let cap = peer.header_cap.load(Ordering::SeqCst) as usize;
                let headers: Vec<Header> = {
                    let chain = peer.chain.lock().unwrap();
                    let top = cap.min(chain.len() - 1);
                    let start = chain[..=top]
                        .iter()
                        .rposition(|b| request.locator_hashes.contains(&b.block_hash()))
                        .map_or(1, |h| h + 1);
                    chain[start.min(top + 1)..=top]
                        .iter()
                        .map(|b| b.header)
                        .take(2000)
                        .collect()
                };
                write_v2_msg(&mut writer, NetworkMessage::Headers(headers)).await?;
            }
            NetworkMessage::GetData(inventory) => {
                let mut missing = Vec::new();
                for item in inventory {
                    let (Inventory::Block(hash) | Inventory::WitnessBlock(hash)) = item else {
                        continue;
                    };
                    let found = {
                        let chain = peer.chain.lock().unwrap();
                        chain
                            .iter()
                            .position(|b| b.block_hash() == *hash)
                            .map(|h| (h as u32, chain[h].clone()))
                    };
                    let Some((height, block)) = found else {
                        // Core sends nothing for a block it does not have.
                        peer.unknown_asks.fetch_add(1, Ordering::SeqCst);
                        continue;
                    };
                    if height >= peer.withhold_from {
                        peer.withheld_asks.fetch_add(1, Ordering::SeqCst);
                        if matches!(peer.mode, Withhold::NotFound | Withhold::NotFoundReannounce) {
                            missing.push(*item);
                        }
                        continue;
                    }
                    if height == peer.hold.load(Ordering::SeqCst) {
                        peer.parked.fetch_add(1, Ordering::SeqCst);
                        parked.push(block);
                        continue;
                    }
                    pending.push_back(block);
                }
                if !missing.is_empty() {
                    write_v2_msg(&mut writer, NetworkMessage::NotFound(missing)).await?;
                    if peer.mode == Withhold::NotFoundReannounce {
                        let top = peer.chain.lock().unwrap().last().unwrap().block_hash();
                        write_v2_msg(
                            &mut writer,
                            NetworkMessage::Inv(vec![Inventory::Block(top)]),
                        )
                        .await?;
                    }
                }
            }
            NetworkMessage::Ping(nonce) => {
                write_v2_msg(&mut writer, NetworkMessage::Pong(*nonce)).await?
            }
            _ => {}
        }
    }
}

fn spawn_peer(listener: TcpListener, peer: Arc<Peer>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while !peer.gone.load(Ordering::SeqCst) {
            if let Err(e) = serve_one(&listener, &peer).await {
                eprintln!("{} connection ended: {e}", peer.name);
            }
        }
        // Dropping the listener refuses every redial.
    })
}

fn extend(chain: &mut Vec<Block>, to: u32, salt: u32) {
    while (chain.len() as u32) <= to {
        let prev = chain.last().unwrap();
        let height = chain.len() as u32;
        chain.push(rbitcoin_consensus::mine_empty_regtest(
            prev.block_hash(),
            prev.header.time + 600 + salt,
            height,
        ));
    }
}

fn honest_chain(n: u32) -> Vec<Block> {
    let mut chain = vec![bitcoin::blockdata::constants::genesis_block(
        bitcoin::Network::Regtest,
    )];
    extend(&mut chain, n, 0);
    chain
}

/// `honest[..=fork]` then fork blocks through `top`.
fn fork_chain(honest: &[Block], fork: u32, top: u32) -> Vec<Block> {
    let mut chain = honest[..=fork as usize].to_vec();
    extend(&mut chain, top, 1);
    chain
}

struct Rig {
    node: P2PNode,
    _dir: rbitcoin_store::testutil::TempDir,
    trace: Mutex<Vec<(u128, Option<u32>)>>,
    t0: Instant,
}

impl Rig {
    fn note(&self) -> Option<u32> {
        let tip = self.node.tip_height();
        let mut trace = self.trace.lock().unwrap();
        if trace.last().map(|t| t.1) != Some(tip) {
            trace.push((self.t0.elapsed().as_millis(), tip));
        }
        tip
    }

    /// Wait until the tip is `hash` at `height`, sampling the trace.
    async fn reach(
        &self,
        height: u32,
        hash: bitcoin::BlockHash,
        budget: Duration,
    ) -> Option<Duration> {
        let start = Instant::now();
        while start.elapsed() < budget {
            if self.note() == Some(height) && self.node.hub.tip_hash() == Some(hash) {
                return Some(start.elapsed());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }

    async fn idle(&self, d: Duration) {
        let start = Instant::now();
        while start.elapsed() < d {
            self.note();
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn trace(&self) -> String {
        self.trace
            .lock()
            .unwrap()
            .iter()
            .map(|(ms, tip)| format!("{ms}ms:{tip:?}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

async fn start_node(dir: rbitcoin_store::testutil::TempDir) -> Rig {
    let node = P2PNode::start(
        "127.0.0.1:0".parse().unwrap(),
        Query::open_or_create_tiny(dir.join("store")).unwrap(),
        ChainParams::regtest(),
        Milestone::NONE,
        rbitcoin_net::REDIAL_INTERVAL_TEST,
    )
    .await
    .unwrap();
    Rig {
        node,
        _dir: dir,
        trace: Mutex::new(Vec::new()),
        t0: Instant::now(),
    }
}

fn cfg() -> IbdConfig {
    let mut cfg = IbdConfig::for_test();
    cfg.target_peers = 2;
    cfg.window = 64;
    cfg.per_peer = 16;
    cfg.connect_timeout = Duration::from_secs(5);
    cfg.peerless = rbitcoin_ibd::Peerless::Redial {
        cap: Duration::from_millis(100),
    };
    cfg
}

#[derive(Clone, Copy, Debug)]
enum Shape {
    /// The node confirms through N-1, then the attacker sends unsolicited
    /// headers N-1'..N+3' that fork at N-2.
    RewindUnsolicited,
    /// The attacker answers the first getheaders with its fork chain.
    ForkFromStart,
    /// The attacker's headers extend the honest tip: N+1'..N+3'.
    ExtendsHonestTip,
}

/// Returns (reached honest N and stayed there, report).
async fn run(shape: Shape, mode: Withhold) -> (bool, String) {
    let dir = rbitcoin_store::testutil::TempDir::labeled("withheld-fork").unwrap();
    let rig = start_node(dir).await;
    let honest_blocks = honest_chain(N);
    let (fork_at, attacker_cap) = match shape {
        Shape::RewindUnsolicited => (N - 2, N - 2),
        Shape::ForkFromStart => (N - 2, N + 3),
        Shape::ExtendsHonestTip => (N, N + 3),
    };
    let attacker_blocks = fork_chain(&honest_blocks, fork_at, N + 3);
    let honest = Peer::new(
        "honest",
        honest_blocks.clone(),
        u32::MAX,
        u32::MAX,
        Withhold::Silent,
    );
    let attacker = Peer::new(
        "attacker",
        attacker_blocks.clone(),
        attacker_cap,
        fork_at + 1,
        mode,
    );
    if matches!(shape, Shape::RewindUnsolicited) {
        honest.hold.store(N, Ordering::SeqCst);
    }
    let hl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let al = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addrs = [hl.local_addr().unwrap(), al.local_addr().unwrap()].map(rbitcoin_net::NetAddr::Ip);
    let hs = spawn_peer(hl, honest.clone());
    let at = spawn_peer(al, attacker.clone());
    let cancel = Arc::new(AtomicBool::new(false));
    let sync = rbitcoin_ibd::sync_cancellable(&rig.node, &addrs, cfg(), Some(cancel.clone()));
    let mut report = Vec::new();
    let mut reached = false;
    let control = async {
        let honest_tip = honest_blocks[N as usize].block_hash();
        if matches!(shape, Shape::RewindUnsolicited) {
            let ok = rig
                .reach(
                    N - 1,
                    honest_blocks[(N - 1) as usize].block_hash(),
                    Duration::from_secs(30),
                )
                .await;
            report.push(format!("phase0 confirmed N-1={} {:?}", N - 1, ok));
            while honest.parked.load(Ordering::SeqCst) == 0 {
                rig.note();
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            attacker.header_cap.store(N + 3, Ordering::SeqCst);
            attacker.send(Cmd::Headers(
                attacker_blocks[(fork_at + 1) as usize..]
                    .iter()
                    .map(|b| b.header)
                    .collect(),
            ));
            if mode == Withhold::Disconnect {
                tokio::time::sleep(Duration::from_millis(500)).await;
                attacker.send(Cmd::Close);
            }
            // The fork headers rewind the tip to the fork point first.
            let fork_tip = honest_blocks[fork_at as usize].block_hash();
            let rewound = rig.reach(fork_at, fork_tip, Duration::from_secs(10)).await;
            report.push(format!("phase1 rewound to the fork point {rewound:?}"));
            honest.send(Cmd::ReleaseHeld);
        }
        // The honest tip, held for 2 s. Fork headers that land after it
        // connects rewind it again until the fork is retired.
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut got = None;
        while !reached && Instant::now() < deadline {
            got = rig.reach(N, honest_tip, deadline.saturating_duration_since(Instant::now())).await;
            if got.is_none() {
                break;
            }
            rig.idle(Duration::from_secs(2)).await;
            reached = rig.node.hub.tip_hash() == Some(honest_tip);
        }
        let attacker_top = attacker_blocks[(N + 3) as usize]
            .block_hash()
            .to_byte_array();
        report.push(format!(
            "attacker top header stored={}",
            matches!(
                rig.node.query.get_header_by_hash(&attacker_top),
                Ok(Some(_))
            )
        ));
        report.push(format!(
            "phase2 honest N={N} reached={:?} tip_now={:?} | {} | {}",
            got,
            rig.node.tip_height(),
            honest.stats(),
            attacker.stats()
        ));
        report.push(format!("trace {}", rig.trace()));
        cancel.store(true, Ordering::SeqCst);
    };
    let _ = tokio::time::timeout(Duration::from_secs(200), async {
        tokio::join!(sync, control)
    })
    .await;
    hs.abort();
    at.abort();
    rig.node.shutdown().await;
    let report = format!("shape={shape:?} mode={mode:?}\n  {}", report.join("\n  "));
    eprintln!("{report}");
    (reached, report)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_rewind_silent() {
    let (reached, report) = run(Shape::RewindUnsolicited, Withhold::Silent).await;
    assert!(reached, "IBD did not reach the honest tip\n{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_rewind_notfound() {
    let (reached, report) = run(Shape::RewindUnsolicited, Withhold::NotFound).await;
    assert!(reached, "IBD did not reach the honest tip\n{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_rewind_notfound_reannounced() {
    let (reached, report) = run(Shape::RewindUnsolicited, Withhold::NotFoundReannounce).await;
    assert!(reached, "IBD did not reach the honest tip\n{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_rewind_disconnect() {
    let (reached, report) = run(Shape::RewindUnsolicited, Withhold::Disconnect).await;
    assert!(reached, "IBD did not reach the honest tip\n{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_from_start_silent() {
    let (reached, report) = run(Shape::ForkFromStart, Withhold::Silent).await;
    assert!(reached, "IBD did not reach the honest tip\n{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_from_start_notfound() {
    let (reached, report) = run(Shape::ForkFromStart, Withhold::NotFound).await;
    assert!(reached, "IBD did not reach the honest tip\n{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_extends_honest_tip() {
    let (reached, report) = run(Shape::ExtendsHonestTip, Withhold::Silent).await;
    assert!(reached, "IBD did not reach the honest tip\n{report}");
}

/// Rewind the node to N-2 with the rewind shape, stop it while the fork's
/// headers are stored and its bodies are not, reopen the same store, and run
/// catch-up again.
async fn run_restart(with_attacker: bool) -> (bool, String) {
    let dir = rbitcoin_store::testutil::TempDir::labeled("withheld-fork-restart").unwrap();
    let rig = start_node(dir).await;
    let honest_blocks = honest_chain(N);
    let attacker_blocks = fork_chain(&honest_blocks, N - 2, N + 3);
    let honest = Peer::new(
        "honest",
        honest_blocks.clone(),
        u32::MAX,
        u32::MAX,
        Withhold::Silent,
    );
    let attacker = Peer::new(
        "attacker",
        attacker_blocks.clone(),
        N - 2,
        N - 1,
        Withhold::Silent,
    );
    honest.hold.store(N, Ordering::SeqCst);
    let hl = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let al = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addrs = [hl.local_addr().unwrap(), al.local_addr().unwrap()].map(rbitcoin_net::NetAddr::Ip);
    let hs = spawn_peer(hl, honest.clone());
    let at = spawn_peer(al, attacker.clone());
    let mut report = Vec::new();
    {
        let cancel = Arc::new(AtomicBool::new(false));
        let sync = rbitcoin_ibd::sync_cancellable(&rig.node, &addrs, cfg(), Some(cancel.clone()));
        let control = async {
            let _ = rig
                .reach(
                    N - 1,
                    honest_blocks[(N - 1) as usize].block_hash(),
                    Duration::from_secs(30),
                )
                .await;
            while honest.parked.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            attacker.header_cap.store(N + 3, Ordering::SeqCst);
            attacker.send(Cmd::Headers(
                attacker_blocks[(N - 1) as usize..]
                    .iter()
                    .map(|b| b.header)
                    .collect(),
            ));
            let fork_tip = honest_blocks[(N - 2) as usize].block_hash();
            let rewound = rig.reach(N - 2, fork_tip, Duration::from_secs(10)).await;
            honest.send(Cmd::ReleaseHeld);
            report.push(format!(
                "first run: rewound {rewound:?} tip={:?}",
                rig.node.tip_height()
            ));
            cancel.store(true, Ordering::SeqCst);
        };
        let (res, ()) = tokio::join!(sync, control);
        report.push(format!("first run sync={res:?}"));
    }
    let Rig {
        node, _dir: dir, ..
    } = rig;
    node.shutdown().await;
    if !with_attacker {
        attacker.send(Cmd::Close);
        at.abort();
    }
    let rig = start_node(dir).await;
    report.push(format!("reopened tip={:?}", rig.node.tip_height()));
    let addrs2: Vec<rbitcoin_net::NetAddr> = if with_attacker {
        addrs.to_vec()
    } else {
        addrs[..1].to_vec()
    };
    let cancel = Arc::new(AtomicBool::new(false));
    let mut cfg2 = cfg();
    cfg2.target_peers = addrs2.len();
    let sync = rbitcoin_ibd::sync_cancellable(&rig.node, &addrs2, cfg2, Some(cancel.clone()));
    let mut reached = false;
    let control = async {
        let got = rig
            .reach(
                N,
                honest_blocks[N as usize].block_hash(),
                Duration::from_secs(90),
            )
            .await;
        reached = got.is_some();
        report.push(format!(
            "restart with_attacker={with_attacker}: reached N={got:?} tip={:?} | {} | {}",
            rig.node.tip_height(),
            honest.stats(),
            attacker.stats()
        ));
        report.push(format!("trace {}", rig.trace()));
        cancel.store(true, Ordering::SeqCst);
    };
    let (res, ()) = tokio::join!(sync, control);
    report.push(format!("restart sync={res:?}"));
    hs.abort();
    at.abort();
    rig.node.shutdown().await;
    let report = format!(
        "restart with_attacker={with_attacker}\n  {}",
        report.join("\n  ")
    );
    eprintln!("{report}");
    (reached, report)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_restart_honest_only() {
    let (reached, report) = run_restart(false).await;
    assert!(
        reached,
        "restarted IBD did not reach the honest tip\n{report}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_restart_both_peers() {
    let (reached, report) = run_restart(true).await;
    assert!(
        reached,
        "restarted IBD did not reach the honest tip\n{report}"
    );
}
