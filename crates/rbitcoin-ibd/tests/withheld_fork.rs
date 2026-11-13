//! A heavier header chain whose bodies are never served must not hold IBD
//! below the best chain whose bodies it can get. Core keeps connecting the
//! honest chain while the header-only branch sits in its block index.
use bitcoin::block::Header;
use bitcoin::hashes::Hash;
use bitcoin::p2p::{message::NetworkMessage, message_blockdata::Inventory, Magic};
use bitcoin::Block;
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_ibd::ibd::header_walk::WITHHELD_WINDOW_SECS;
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
    /// An honest heavier peer that did not have the first block yet:
    /// `notfound` and an `inv` of its top once, then it serves every block.
    NotFoundOnce,
    /// Close the connection after the fork headers go out, and stay gone.
    Disconnect,
    /// Serve the fork's first block, then nothing.
    ServesFirst,
    /// Serve the fork's first two blocks, which out-work the confirmed
    /// chain above the fork point, then close and stay gone.
    ProvesThenLeaves,
}

enum Cmd {
    Headers(Vec<Header>),
    /// Send these bodies unrequested.
    Blocks(Vec<Block>),
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
    refused_once: AtomicBool,
    /// After its first connection drops it stays gone, as the cooldown on a
    /// stall-kicked address keeps it out in production.
    one_connection: AtomicBool,
    /// First height of this peer's own fork (u32::MAX: none).
    fork_from: u32,
    fork_sent: AtomicUsize,
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
            refused_once: AtomicBool::new(false),
            one_connection: AtomicBool::new(false),
            fork_from: match mode {
                Withhold::ServesFirst => withhold_from.saturating_sub(1),
                Withhold::ProvesThenLeaves => withhold_from.saturating_sub(2),
                _ => withhold_from,
            },
            fork_sent: AtomicUsize::new(0),
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
    let mut reannounce_at: Option<tokio::time::Instant> = None;
    loop {
        let frame = tokio::select! {
            _ = tokio::time::sleep_until(reannounce_at.unwrap_or_else(tokio::time::Instant::now)), if reannounce_at.is_some() => {
                reannounce_at = None;
                let fork: Vec<Header> = peer.chain.lock().unwrap()[peer.fork_from as usize..]
                    .iter()
                    .map(|b| b.header)
                    .collect();
                write_v2_msg(&mut writer, NetworkMessage::Headers(fork)).await?;
                continue;
            }
            _ = sends.tick(), if !pending.is_empty() => {
                let block = pending.pop_front().unwrap();
                let fork_block = {
                    let chain = peer.chain.lock().unwrap();
                    chain
                        .iter()
                        .position(|b| b.block_hash() == block.block_hash())
                        .is_some_and(|h| h as u32 >= peer.fork_from)
                };
                write_v2_msg(&mut writer, NetworkMessage::Block(block)).await?;
                peer.bodies.fetch_add(1, Ordering::SeqCst);
                if fork_block
                    && peer.fork_sent.fetch_add(1, Ordering::SeqCst) + 1 == 2
                    && peer.mode == Withhold::ProvesThenLeaves
                {
                    peer.gone.store(true, Ordering::SeqCst);
                    return Ok(());
                }
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
                        Cmd::Blocks(blocks) => {
                            for block in blocks {
                                write_v2_msg(&mut writer, NetworkMessage::Block(block)).await?;
                            }
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
                let missing = answer_getdata(peer, inventory, &mut pending, &mut parked);
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
                    if peer.mode == Withhold::NotFoundOnce {
                        // It gets the block a little later and announces
                        // its chain again.
                        reannounce_at =
                            Some(tokio::time::Instant::now() + Duration::from_millis(200));
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

/// Queue, park, or refuse each block a getdata names. Returns the hashes to
/// answer `notfound`.
fn answer_getdata(
    peer: &Peer,
    inventory: &[Inventory],
    pending: &mut VecDeque<Block>,
    parked: &mut Vec<Block>,
) -> Vec<Inventory> {
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
        let once = peer.mode == Withhold::NotFoundOnce;
        if height >= peer.withhold_from
            && (!once || !peer.refused_once.swap(true, Ordering::SeqCst))
        {
            peer.withheld_asks.fetch_add(1, Ordering::SeqCst);
            if matches!(
                peer.mode,
                Withhold::NotFound | Withhold::NotFoundReannounce | Withhold::NotFoundOnce
            ) {
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
    missing
}

fn spawn_peer(listener: TcpListener, peer: Arc<Peer>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while !peer.gone.load(Ordering::SeqCst) {
            if let Err(e) = serve_one(&listener, &peer).await {
                eprintln!("{} connection ended: {e}", peer.name);
            }
            if peer.one_connection.load(Ordering::SeqCst)
                && peer.connects.load(Ordering::SeqCst) > 0
            {
                peer.gone.store(true, Ordering::SeqCst);
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
    /// While waiting in `reach`, move the node clock one withheld window
    /// every half second, so a retire does not wait out real time. Nothing
    /// re-admits a withheld chain on a timer.
    fast_clock: AtomicBool,
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
        let mut bumped = Instant::now();
        while start.elapsed() < budget {
            if self.note() == Some(height) && self.node.hub.tip_hash() == Some(hash) {
                return Some(start.elapsed());
            }
            if self.fast_clock.load(Ordering::SeqCst)
                && bumped.elapsed() >= Duration::from_millis(500)
            {
                let clock = &self.node.hub.clock;
                clock.set_mock((clock.now_secs() + WITHHELD_WINDOW_SECS) as i64);
                bumped = Instant::now();
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
        fast_clock: AtomicBool::new(false),
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

/// Returns (reached the expected tip and stayed there, report): the honest
/// tip N, or the fork's top for a peer that serves it.
async fn run(shape: Shape, mode: Withhold) -> (bool, String) {
    let dir = rbitcoin_store::testutil::TempDir::labeled("withheld-fork").unwrap();
    let rig = start_node(dir).await;
    // A silent withholder is dropped by the real stall floor, and a peer
    // that serves after one notfound must not need a moved clock.
    // A withholder that is the first header peer is a candidate no fork
    // offer replaces: it is retired one stall window after nobody can serve
    // its next block, on a node clock this test moves.
    let fast = matches!(shape, Shape::ForkFromStart);
    rig.fast_clock.store(fast, Ordering::SeqCst);
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
        match mode {
            Withhold::ServesFirst => fork_at + 2,
            Withhold::ProvesThenLeaves => fork_at + 3,
            _ => fork_at + 1,
        },
        mode,
    );
    if matches!(shape, Shape::RewindUnsolicited) {
        honest.hold.store(N, Ordering::SeqCst);
    }
    if matches!(shape, Shape::ForkFromStart) {
        attacker.one_connection.store(true, Ordering::SeqCst);
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
        let (target_h, target) = match mode {
            Withhold::NotFoundOnce => (N + 3, attacker_blocks[(N + 3) as usize].block_hash()),
            Withhold::ProvesThenLeaves => (N, attacker_blocks[N as usize].block_hash()),
            _ => (N, honest_blocks[N as usize].block_hash()),
        };
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
            // The fork's blocks are asked for; the tip stays until they
            // are served.
            let asked = Instant::now();
            while attacker.withheld_asks.load(Ordering::SeqCst) == 0
                && attacker.fork_sent.load(Ordering::SeqCst) < 2
                && !attacker.gone.load(Ordering::SeqCst)
                && asked.elapsed() < Duration::from_secs(3)
            {
                rig.note();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            report.push(format!(
                "phase1 fork asked after {:?}, tip={:?}",
                asked.elapsed(),
                rig.node.tip_height()
            ));
            // A served fork is taken while the honest body is still held,
            // so catch-up has not finished on the honest chain.
            if matches!(mode, Withhold::ProvesThenLeaves | Withhold::NotFoundOnce) {
                let taken = rig.reach(target_h, target, Duration::from_secs(10)).await;
                report.push(format!("served fork taken {taken:?}"));
            }
            honest.send(Cmd::ReleaseHeld);
        }
        // The expected tip, held for 500 ms. Fork headers that land after
        // the honest tip connects rewind it again until the fork is retired.
        let deadline = Instant::now() + Duration::from_secs(90);
        let mut got = None;
        while !reached && Instant::now() < deadline {
            got = rig
                .reach(
                    target_h,
                    target,
                    deadline.saturating_duration_since(Instant::now()),
                )
                .await;
            if got.is_none() {
                break;
            }
            rig.idle(Duration::from_millis(500)).await;
            reached = rig.node.hub.tip_hash() == Some(target);
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

/// A heavier chain whose peer answers `notfound` once, because it has the
/// header and not the body yet, and then serves it, is still adopted while
/// a peer on the old chain is connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heavier_fork_served_after_one_notfound_is_adopted() {
    let (reached, report) = run(Shape::RewindUnsolicited, Withhold::NotFoundOnce).await;
    assert!(reached, "IBD did not reach the heavier tip\n{report}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_extends_honest_tip() {
    let (reached, report) = run(Shape::ExtendsHonestTip, Withhold::Silent).await;
    assert!(reached, "IBD did not reach the honest tip\n{report}");
}

/// Confirm through N-1 with the fork's headers stored and none of its
/// bodies, stop, reopen the same store, and run catch-up again: the resume
/// seed must not rewind onto the stored fork.
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
        Withhold::NotFound,
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
            rig.idle(Duration::from_millis(300)).await;
            // Leave the fork's headers in the store, as tip-follow or an
            // older node would have, with none of its bodies.
            let fork_headers: Vec<Header> = attacker_blocks[(N - 1) as usize..]
                .iter()
                .map(|b| b.header)
                .collect();
            let stored = rig
                .node
                .hub
                .ensure_headers_batch(&fork_headers)
                .map(|f| f.len());
            honest.send(Cmd::ReleaseHeld);
            report.push(format!(
                "first run: fork headers stored {stored:?} tip={:?}",
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
    rig.fast_clock.store(true, Ordering::SeqCst);
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

/// The rewind shape: the node confirms through N-1 with the honest body N
/// held back, then the attacker announces N-1'..N+3' (fork at N-2) and
/// withholds every fork body. `then` runs with the node, the peers and both
/// chains once the attacker's headers are out.
async fn rewind_scene<F, Fut>(label: &str, then: F) -> String
where
    F: FnOnce(Arc<Rig>, Arc<Peer>, Arc<Peer>, Vec<Block>, Vec<Block>) -> Fut,
    Fut: std::future::Future<Output = Vec<String>>,
{
    let dir = rbitcoin_store::testutil::TempDir::labeled(label).unwrap();
    let rig = Arc::new(start_node(dir).await);
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
    let cancel = Arc::new(AtomicBool::new(false));
    let sync = rbitcoin_ibd::sync_cancellable(&rig.node, &addrs, cfg(), Some(cancel.clone()));
    let control = async {
        let mut report = Vec::new();
        let ok = rig
            .reach(
                N - 1,
                honest_blocks[(N - 1) as usize].block_hash(),
                Duration::from_secs(30),
            )
            .await;
        report.push(format!("confirmed N-1 {ok:?}"));
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
        report.extend(
            then(
                Arc::clone(&rig),
                Arc::clone(&honest),
                Arc::clone(&attacker),
                honest_blocks.clone(),
                attacker_blocks.clone(),
            )
            .await,
        );
        report.push(format!("{} | {}", honest.stats(), attacker.stats()));
        report.push(format!("trace {}", rig.trace()));
        cancel.store(true, Ordering::SeqCst);
        report
    };
    let (_, report) = tokio::join!(sync, control);
    hs.abort();
    at.abort();
    let Ok(rig) = Arc::try_unwrap(rig) else {
        panic!("the scene still holds the node");
    };
    rig.node.shutdown().await;
    let report = format!("{label}\n  {}", report.join("\n  "));
    eprintln!("{report}");
    report
}

/// Header records alone never move the tip: long after the attacker's
/// headers, with the node clock past any hold, the attacker announces its
/// fork again and the tip stays on the honest chain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_reannounced_much_later_does_not_rewind() {
    let report = rewind_scene(
        "withheld-fork-later",
        |rig, honest, attacker, hb, ab| async move {
            let mut report = Vec::new();
            // The fork headers land before the honest body does.
            rig.idle(Duration::from_secs(1)).await;
            report.push(format!(
                "1 s after the fork headers tip={:?}",
                rig.node.tip_height()
            ));
            rig.fast_clock.store(true, Ordering::SeqCst);
            honest.send(Cmd::ReleaseHeld);
            let honest_tip = hb[N as usize].block_hash();
            let got = rig.reach(N, honest_tip, Duration::from_secs(60)).await;
            report.push(format!("honest tip {got:?}"));
            let clock = &rig.node.hub.clock;
            clock.set_mock((clock.now_secs() + 700) as i64);
            attacker.send(Cmd::Headers(
                ab[(N - 1) as usize..].iter().map(|b| b.header).collect(),
            ));
            rig.idle(Duration::from_millis(1500)).await;
            report.push(format!(
                "after +700 s and the re-announce: tip={:?} honest={}",
                rig.node.tip_height(),
                rig.node.hub.tip_hash() == Some(honest_tip)
            ));
            report.push(if rig.node.hub.tip_hash() == Some(honest_tip) {
                "STAYED".into()
            } else {
                "MOVED".into()
            });
            report
        },
    )
    .await;
    assert!(
        report.contains("STAYED"),
        "the fork moved the tip\n{report}"
    );
}

/// A peer that has the fork's blocks and sends them unrequested proves the
/// fork: it out-works the confirmed chain with those blocks, so the tip moves
/// onto it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unrequested_fork_blocks_prove_the_fork() {
    let report = rewind_scene(
        "withheld-fork-pushed",
        |rig, honest, _attacker, _hb, ab| async move {
            let mut report = Vec::new();
            tokio::time::sleep(Duration::from_millis(500)).await;
            honest.send(Cmd::Blocks(ab[(N - 1) as usize..=N as usize].to_vec()));
            let fork_tip = ab[N as usize].block_hash();
            let got = rig.reach(N, fork_tip, Duration::from_secs(20)).await;
            report.push(if got.is_some() {
                "PROVED".into()
            } else {
                format!("not proved, tip={:?}", rig.node.tip_height())
            });
            report
        },
    )
    .await;
    assert!(
        report.contains("PROVED"),
        "the pushed fork blocks did not move the tip\n{report}"
    );
}

/// A peer that serves the fork's first block and then withholds does not
/// move the tip: one block does not out-work the confirmed chain above the
/// fork point.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withheld_fork_after_its_first_block_does_not_rewind() {
    let (reached, report) = run(Shape::RewindUnsolicited, Withhold::ServesFirst).await;
    assert!(reached, "IBD did not reach the honest tip\n{report}");
}

/// A peer that serves the blocks that out-work the confirmed chain and then
/// leaves still gets its fork taken: the served bodies are held, so the
/// rewind and confirm do not need it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn served_fork_is_taken_after_its_peer_leaves() {
    let (reached, report) = run(Shape::RewindUnsolicited, Withhold::ProvesThenLeaves).await;
    assert!(reached, "IBD did not reach the served fork\n{report}");
}
