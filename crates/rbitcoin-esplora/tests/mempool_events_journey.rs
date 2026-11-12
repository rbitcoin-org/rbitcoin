fn op_true_spend(cb: [u8; 32], fee: u64) -> bitcoin::Transaction {
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: bitcoin::Txid::from_byte_array(cb),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000 - fee),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

async fn post_tx(addr: SocketAddr, tx: &bitcoin::Transaction) {
    let hex = bitcoin::consensus::encode::serialize_hex(tx);
    let (st, body) = http_post(addr, "/tx", hex.as_bytes()).await;
    assert_eq!(st, 200, "POST /tx: {body}");
}

async fn events_json(addr: SocketAddr, query: &str) -> (u16, Value) {
    let (st, body) = http_get(addr, &format!("/mempool/events{query}")).await;
    let v = serde_json::from_str(&body).unwrap_or_else(|_| json!({ "raw": body }));
    (st, v)
}

fn seqs(page: &Value) -> Vec<u64> {
    page["events"]
        .as_array()
        .unwrap_or_else(|| panic!("no events: {page}"))
        .iter()
        .map(|e| e["seq"].as_u64().unwrap())
        .collect()
}

/// Wait until `n` polls are parked. A notify, not a sleep.
async fn parked(park: &rbitcoin_esplora::mempool_events::EventPark, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let notified = park.notified();
        if park.parked() >= n {
            return;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "no parked poll");
        let _ = tokio::time::timeout(left, notified).await;
    }
}

fn noise(n: usize) -> impl Iterator<Item = rbitcoin_net::mempool_events::PoolChange> {
    use bitcoin::hashes::Hash;
    (0..n).map(|i| rbitcoin_net::mempool_events::PoolChange::Removed {
        txid: bitcoin::Txid::from_byte_array([(i % 251) as u8; 32]),
        reason: rbitcoin_net::mempool_events::RemovalReason::Block,
    })
}

/// Probe, read, page with `limit`, park until an admit, ride across a new
/// tip, and answer 410 for a cursor the ring no longer holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_events_follow_admits_and_replacements() {
    let (dir, q) = temp_query("esplora-mempool-events");
    let q = Arc::new(q);
    let hub = rbitcoin_net::MempoolHub::open(dir.join("mp"), Arc::clone(&q)).unwrap();
    hub.set_relay_enabled(true);
    let mut cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    cfg.limits.idle_timeout = Duration::from_secs(10);
    let handle = run_esplora(cfg, Arc::clone(&q), Some(Arc::clone(&hub)))
        .await
        .expect("listen");
    let addr = handle.local_addr;
    let mut pad = HttpPad {
        q,
        hub: Arc::clone(&hub),
        addr,
        cbs: Vec::new(),
        hashes: Vec::new(),
        tip_fk: Fk::NULL,
    };
    for _ in 0..101u32 {
        pad.connect(vec![]);
    }

    let (st, probe) = events_json(addr, "").await;
    assert_eq!(st, 200, "{probe}");
    let epoch = probe["epoch"].as_str().expect("epoch").to_string();
    assert_eq!(epoch.len(), 16, "{probe}");
    assert_eq!(probe["next"], 1);
    assert_eq!(probe["events"], json!([]));

    let (st, idle) = events_json(addr, "?from=1&wait=0").await;
    assert_eq!(st, 200);
    assert_eq!((idle["next"].clone(), idle["events"].clone()), (json!(1), json!([])));

    let a = op_true_spend(pad.cbs[0], 1_000);
    post_tx(addr, &a).await;
    let (st, one) = events_json(addr, "?from=1").await;
    assert_eq!(st, 200, "{one}");
    let vsize = a.weight().to_wu().div_ceil(4);
    let added = &one["events"][0];
    assert_eq!(added["seq"], 1);
    assert_eq!(added["type"], "added");
    assert_eq!(added["txid"], display_txid(a.compute_txid()));
    assert_eq!(added["fee"], 1_000);
    assert_eq!(added["weight"], a.weight().to_wu());
    assert_eq!(added["vsize"], vsize);
    assert!(added["time"].as_u64().is_some(), "{added}");
    assert_eq!(one["next"], 2);
    assert_eq!(one["epoch"], epoch.as_str());

    let a2 = op_true_spend(pad.cbs[0], 50_000);
    post_tx(addr, &a2).await;
    post_tx(addr, &op_true_spend(pad.cbs[1], 1_000)).await;
    let (_, head) = events_json(addr, "?from=1&limit=2").await;
    assert_eq!(seqs(&head), vec![1, 2]);
    assert_eq!(head["next"], 3, "the cursor follows the last event sent");
    let gone = &head["events"][1];
    assert_eq!(gone["type"], "removed");
    assert_eq!(gone["reason"], "replaced");
    assert_eq!(gone["txid"], display_txid(a.compute_txid()));
    assert_eq!(gone["by"], display_txid(a2.compute_txid()));
    let (_, rest) = events_json(addr, "?from=3").await;
    assert_eq!(seqs(&rest), vec![3, 4]);
    assert_eq!(rest["next"], 5);

    let poll = tokio::spawn(async move { events_json(addr, "?from=5&wait=20000").await });
    parked(&handle.events_park, 1).await;
    // A new tip while the poll is parked: this route pins no chain view.
    pad.connect(vec![]);
    let c = op_true_spend(pad.cbs[2], 1_000);
    post_tx(addr, &c).await;
    let (st, woke) = poll.await.unwrap();
    assert_eq!(st, 200, "{woke}");
    assert_eq!(seqs(&woke), vec![5]);
    assert_eq!(woke["events"][0]["txid"], display_txid(c.compute_txid()));
    assert_eq!(woke["next"], 6);

    let (st, ahead) = events_json(addr, "?from=7").await;
    assert_eq!(st, 410, "{ahead}");
    assert_eq!(ahead, json!({"epoch": epoch, "oldest": 1, "next": 6}));

    hub.events().record(noise(rbitcoin_net::mempool_events::EVENT_RING_CAP));
    let (st, old) = events_json(addr, "?from=1").await;
    assert_eq!(st, 410, "{old}");
    assert_eq!(old["oldest"], 6);
    assert_eq!(
        old["next"],
        6 + rbitcoin_net::mempool_events::EVENT_RING_CAP as u64
    );

    let (st, _) = http_get(addr, "/mempool/events?from=nope").await;
    assert_eq!(st, 400);
    handle.shutdown().await;
}

/// Parked polls are capped at half the listener. Over the cap a poll is not
/// parked. A poll that does not wait needs no parking slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mempool_events_park_cap_and_unix_listener() {
    let (dir, q) = temp_query("esplora-mempool-park");
    let (h0, cb0) = coinbase(0, Fk::NULL, None);
    q.connect_block(Height(0), &h0, &[cb0]).unwrap();
    let q = Arc::new(q);
    let hub = rbitcoin_net::MempoolHub::open(dir.join("mp"), Arc::clone(&q)).unwrap();
    let mut cfg = EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest);
    cfg.limits.max_connections = 2;
    cfg.limits.idle_timeout = Duration::from_secs(10);
    let handle = run_esplora(cfg, Arc::clone(&q), Some(Arc::clone(&hub)))
        .await
        .expect("listen");
    let addr = handle.local_addr;

    let held = tokio::spawn(async move { events_json(addr, "?from=1&wait=20000").await });
    parked(&handle.events_park, 1).await;
    let (st, raw, body) = http_get_raw(addr, "/mempool/events?from=1&wait=20000").await;
    assert_eq!(st, 503, "{body}");
    assert_eq!(header_value(&raw, "retry-after").as_deref(), Some("1"));
    let (st, now) = events_json(addr, "?from=1&wait=0").await;
    assert_eq!(st, 200, "{now}");
    assert_eq!(now["events"], json!([]));

    hub.events().record(noise(1));
    let (st, woke) = held.await.unwrap();
    assert_eq!(st, 200, "{woke}");
    assert_eq!(seqs(&woke), vec![1]);
    assert_eq!(woke["events"][0]["reason"], "block");
    handle.shutdown().await;

    let bare = run_esplora(
        EsploraConfig::with_network("127.0.0.1:0".parse().unwrap(), Network::Regtest),
        Arc::clone(&q),
        None,
    )
    .await
    .expect("listen");
    let (st, _) = http_get(bare.local_addr, "/mempool/events").await;
    assert_eq!(st, 503, "no mempool, no event log");
    bare.shutdown().await;

    #[cfg(unix)]
    {
        let sock_dir = rbitcoin_query::testutil::TempDir::for_socket().expect("temp dir");
        let sock = sock_dir.path().join("esplora.sock");
        let cfg = EsploraConfig::with_listen(EsploraListen::Unix(sock.clone()), Network::Regtest);
        let unix = run_esplora(cfg, Arc::clone(&q), Some(Arc::clone(&hub)))
            .await
            .expect("unix listen");
        let mut stream = tokio::net::UnixStream::connect(&sock).await.unwrap();
        let req = "GET /mempool/events HTTP/1.1\r\nHost: api\r\nConnection: close\r\n\r\n";
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.unwrap();
        let text = String::from_utf8_lossy(&buf);
        assert!(text.starts_with("HTTP/1.1 200"), "{text}");
        let body: Value = serde_json::from_str(text.split("\r\n\r\n").nth(1).unwrap()).unwrap();
        assert_eq!(body["next"], 2);
        unix.shutdown().await;
    }
}
