//! I2P SAM v3 STREAM CONNECT / FORWARD (system router, not SOCKS).

use crate::error::NetError;
use bitcoin::hashes::{sha256, Hash};
use rbitcoin_log::{debug, info, warn};
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};

/// Pause before a SAM retry. Thirty-two session attempts are about 16s, so a
/// router that is not accepting yet still comes up. Callers pass this into
/// [`I2pSam::connect`]. The suite passes [`SAM_RETRY_TEST`].
pub const SAM_RETRY: std::time::Duration = std::time::Duration::from_millis(500);
/// What the suite passes so a retryable SAM error stays at the old debug cadence.
#[doc(hidden)]
pub const SAM_RETRY_TEST: std::time::Duration = std::time::Duration::from_millis(50);

#[doc(hidden)]
pub static INSTALLED: Mutex<Option<Installed>> = Mutex::new(None);

#[doc(hidden)]
pub struct Installed {
    pub dialer: I2pDialer,
    rebuild: mpsc::Sender<RebuildAsk>,
}

struct RebuildAsk {
    failed: String,
    reply: oneshot::Sender<Option<I2pDialer>>,
}

pub struct I2pSam {
    pub sam_addr: SocketAddr,
    pub session_id: String,
    pub destination: String,
    pub forward_port: Option<u16>,
    /// Pause before a retryable SAM error is tried again.
    pub retry: std::time::Duration,
    pub _control: TcpStream,
    pub _forward: Option<TcpStream>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct I2pDialer {
    pub sam_addr: SocketAddr,
    pub session_id: String,
    pub destination: String,
    pub forward_port: Option<u16>,
    /// Pause before a retryable stream error is tried again.
    pub retry: std::time::Duration,
}

fn install_kept(dialer: I2pDialer, rebuild: mpsc::Sender<RebuildAsk>) {
    *INSTALLED.lock().unwrap_or_else(|e| e.into_inner()) = Some(Installed { dialer, rebuild });
}

pub async fn stream_connect_installed(dest_b32: &str) -> Result<TcpStream, NetError> {
    let (first, rebuild) = {
        let installed = INSTALLED.lock().unwrap_or_else(|e| e.into_inner());
        let kept = installed.as_ref().ok_or_else(no_dialer)?;
        (kept.dialer.clone(), kept.rebuild.clone())
    };
    match first.stream_connect(dest_b32).await {
        Ok(s) => Ok(s),
        Err(e) if session_dead(&e) => {
            let (reply, answer) = oneshot::channel();
            let ask = RebuildAsk {
                failed: first.session_id.clone(),
                reply,
            };
            if rebuild.send(ask).await.is_err() {
                return Err(e);
            }
            match answer.await {
                Ok(Some(fresh)) => fresh.stream_connect(dest_b32).await,
                _ => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

fn no_dialer() -> NetError {
    NetError::Encode("i2p dial requires SAM (--i2p-sam)".into())
}

#[doc(hidden)]
pub fn installed() -> Result<I2pDialer, NetError> {
    INSTALLED
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|s| s.dialer.clone())
        .ok_or_else(no_dialer)
}

/// Error from the SAM TCP connect that opens a stream. A refused local
/// port uses this text. It must not contain `STREAM CONNECT:`, which
/// `session_dead` treats as a dead installed session.
#[doc(hidden)]
pub fn sam_dial_error(err: &std::io::Error) -> NetError {
    NetError::Encode(format!("i2p sam dial: {err}"))
}

#[doc(hidden)]
pub fn session_dead(err: &NetError) -> bool {
    if stream_socket_dead(err) {
        return true;
    }
    match err {
        NetError::Io(_) | NetError::Disconnected => true,
        NetError::Encode(s) => {
            let up = s.to_ascii_uppercase();
            up.contains("INVALID_ID")
                || up.contains("CONNECTION CLOSED")
                || up.contains("STREAM CONNECT:")
        }
        _ => false,
    }
}

/// i2pd closed the SAM TCP socket. The session id is gone; retrying
/// STREAM CONNECT on it only repeats the reset.
#[doc(hidden)]
pub fn stream_socket_dead(err: &NetError) -> bool {
    match err {
        NetError::Encode(s) => {
            let l = s.to_ascii_lowercase();
            l.contains("broken pipe") || l.contains("connection reset")
        }
        _ => false,
    }
}

#[doc(hidden)]
pub fn sam_retry(err: &NetError) -> bool {
    match err {
        NetError::Io(_) | NetError::Disconnected => true,
        NetError::Encode(s) => {
            let l = s.to_ascii_lowercase();
            l.contains("broken pipe")
                || l.contains("connection reset")
                || l.contains("connection closed")
                || l.contains("i2p sam connect")
                || l.contains("early eof")
                || l.contains("unexpected eof")
        }
        _ => false,
    }
}

#[doc(hidden)]
pub fn stream_retry(err: &NetError) -> bool {
    match err {
        NetError::Io(_) | NetError::Disconnected => true,
        NetError::Encode(s) => {
            let l = s.to_ascii_lowercase();
            l.contains("early eof")
                || l.contains("unexpected eof")
                || l.contains("broken pipe")
                || l.contains("connection reset")
                || l.contains("connection closed")
                || l.contains("cant_reach")
                || l.contains("timeout")
        }
        _ => false,
    }
}

#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn clear_installed() {
    *INSTALLED.lock().unwrap_or_else(|e| e.into_inner()) = None;
}

impl I2pSam {
    pub async fn connect(
        sam_addr: SocketAddr,
        retry: std::time::Duration,
    ) -> Result<Self, NetError> {
        Self::connect_session(sam_addr, None, retry).await
    }

    pub async fn connect_persistent(
        sam_addr: SocketAddr,
        dest_path: &Path,
        retry: std::time::Duration,
    ) -> Result<Self, NetError> {
        let stored = match std::fs::read_to_string(dest_path) {
            Ok(s) => {
                let s = s.trim();
                if s.is_empty() {
                    None
                } else {
                    Some(s.to_string())
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => {
                return Err(NetError::Encode(format!(
                    "i2p dest {}: {e}",
                    dest_path.display()
                )));
            }
        };
        let (sam, dest) = Self::connect_session_dest(sam_addr, stored.as_deref(), retry).await?;
        if stored.is_none() {
            write_dest_file(dest_path, &dest)?;
        }
        Ok(sam)
    }

    pub async fn connect_session(
        sam_addr: SocketAddr,
        dest: Option<&str>,
        retry: std::time::Duration,
    ) -> Result<Self, NetError> {
        let (sam, _) = Self::connect_session_dest(sam_addr, dest, retry).await?;
        Ok(sam)
    }

    pub async fn connect_session_dest(
        sam_addr: SocketAddr,
        dest: Option<&str>,
        retry: std::time::Duration,
    ) -> Result<(Self, String), NetError> {
        let mut last = None;
        for _ in 0..32 {
            match Self::connect_session_dest_once(sam_addr, dest, retry).await {
                Ok(v) => return Ok(v),
                Err(e) if sam_retry(&e) => {
                    last = Some(e);
                    tokio::time::sleep(retry).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.expect("sam retry"))
    }

    pub async fn connect_session_dest_once(
        sam_addr: SocketAddr,
        dest: Option<&str>,
        retry: std::time::Duration,
    ) -> Result<(Self, String), NetError> {
        let mut control = TcpStream::connect(sam_addr)
            .await
            .map_err(|e| NetError::Encode(format!("i2p sam connect {sam_addr}: {e}")))?;
        hello(&mut control).await?;
        let session_id = fresh_session_id();
        let dest_arg = dest.unwrap_or("TRANSIENT");
        write_line(&mut control, &session_create_line(&session_id, dest_arg)).await?;
        let reply = read_line(&mut control).await?;
        if !reply.to_ascii_uppercase().contains("RESULT=OK") {
            return Err(NetError::Encode(format!("i2p sam session: {reply}")));
        }
        let destination = sam_kv(&reply, "DESTINATION")
            .ok_or_else(|| {
                NetError::Encode(format!("i2p sam session missing DESTINATION: {reply}"))
            })?
            .to_string();
        Ok((
            Self {
                sam_addr,
                session_id,
                destination: destination.clone(),
                forward_port: None,
                retry,
                _control: control,
                _forward: None,
            },
            destination,
        ))
    }

    pub async fn stream_connect(&self, dest_b32: &str) -> Result<TcpStream, NetError> {
        self.dialer().stream_connect(dest_b32).await
    }

    pub fn dialer(&self) -> I2pDialer {
        I2pDialer {
            sam_addr: self.sam_addr,
            session_id: self.session_id.clone(),
            destination: self.destination.clone(),
            forward_port: self.forward_port,
            retry: self.retry,
        }
    }

    /// BIP155 address of this session. Port is 0: SAM 3.1 does not use ports.
    pub fn local_netaddr(&self) -> Result<crate::NetAddr, NetError> {
        i2p_addr_from_sam_b64(&self.destination)
    }

    async fn closed(&mut self) {
        let (control, forward) = (&mut self._control, &mut self._forward);
        let mut control_buf = [0u8; 256];
        let mut forward_buf = [0u8; 256];
        loop {
            let open = tokio::select! {
                read = control.read(&mut control_buf) => matches!(read, Ok(n) if n > 0),
                read = async {
                    match forward.as_mut() {
                        Some(forward) => forward.read(&mut forward_buf).await,
                        None => std::future::pending().await,
                    }
                } => matches!(read, Ok(n) if n > 0),
            };
            if !open {
                return;
            }
        }
    }

    pub async fn stream_forward(&mut self, port: u16) -> Result<(), NetError> {
        let mut last = None;
        for _ in 0..24 {
            match self.stream_forward_once(port).await {
                Ok(s) => {
                    self.forward_port = Some(port);
                    self._forward = Some(s);
                    return Ok(());
                }
                Err(e) if stream_socket_dead(&e) => {
                    last = Some(e);
                    let (sam, _) = Self::connect_session_dest(
                        self.sam_addr,
                        Some(&self.destination),
                        self.retry,
                    )
                    .await?;
                    *self = sam;
                }
                Err(e) if stream_retry(&e) => {
                    last = Some(e);
                    tokio::time::sleep(self.retry).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.expect("forward retry"))
    }

    pub async fn stream_forward_once(&self, port: u16) -> Result<TcpStream, NetError> {
        let mut s = TcpStream::connect(self.sam_addr)
            .await
            .map_err(|e| NetError::Encode(format!("i2p sam forward connect: {e}")))?;
        hello(&mut s).await?;
        write_line(
            &mut s,
            &format!(
                "STREAM FORWARD ID={} PORT={port} HOST=127.0.0.1 SILENT=true",
                self.session_id
            ),
        )
        .await?;
        let reply = read_line(&mut s).await?;
        if !reply.to_ascii_uppercase().contains("RESULT=OK") {
            return Err(NetError::Encode(format!("i2p sam forward: {reply}")));
        }
        Ok(s)
    }
}

impl I2pDialer {
    pub async fn stream_connect(&self, dest_b32: &str) -> Result<TcpStream, NetError> {
        let mut last = None;
        for _ in 0..24 {
            match self.stream_connect_once(dest_b32).await {
                Ok(s) => return Ok(s),
                Err(e) if stream_socket_dead(&e) => return Err(e),
                Err(e) if stream_retry(&e) => {
                    last = Some(e);
                    tokio::time::sleep(self.retry).await;
                }
                Err(e) => return Err(e),
            }
        }
        Err(last.expect("stream retry"))
    }

    pub async fn stream_connect_once(&self, dest_b32: &str) -> Result<TcpStream, NetError> {
        let mut s = TcpStream::connect(self.sam_addr)
            .await
            .map_err(|e| sam_dial_error(&e))?;
        hello(&mut s).await?;
        write_line(
            &mut s,
            &format!(
                "STREAM CONNECT ID={} DESTINATION={}",
                self.session_id, dest_b32
            ),
        )
        .await?;
        let reply = read_line(&mut s).await?;
        if !reply.to_ascii_uppercase().contains("RESULT=OK") {
            return Err(NetError::Encode(format!("i2p sam stream: {reply}")));
        }
        Ok(s)
    }
}

pub const I2P_RETRY_START: std::time::Duration = std::time::Duration::from_secs(1);
pub const I2P_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct I2pBackoff {
    pub first: std::time::Duration,
    pub max: std::time::Duration,
}

impl I2pBackoff {
    pub const CORE: Self = Self {
        first: I2P_RETRY_START,
        max: I2P_RETRY_MAX,
    };
}

pub fn next_i2p_retry(wait: std::time::Duration, backoff: I2pBackoff) -> std::time::Duration {
    (wait + backoff.first).min(backoff.max)
}

pub enum I2pRole {
    Listen(std::sync::Arc<crate::PeerHub>),
    Dial,
    Wallet,
}

pub struct I2pKeeper {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for I2pKeeper {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl I2pKeeper {
    pub fn spawn(sam: I2pSam, role: I2pRole, backoff: I2pBackoff) -> Self {
        let (asks, rx) = mpsc::channel(8);
        if !matches!(role, I2pRole::Wallet) {
            install_kept(sam.dialer(), asks.clone());
        }
        let task = tokio::spawn(keep(sam, role, asks, rx, backoff));
        Self { task }
    }
}

async fn keep(
    sam: I2pSam,
    role: I2pRole,
    asks_tx: mpsc::Sender<RebuildAsk>,
    mut asks: mpsc::Receiver<RebuildAsk>,
    backoff: I2pBackoff,
) {
    let (sam_addr, destination, forward_port, retry) = (
        sam.sam_addr,
        sam.destination.clone(),
        sam.forward_port,
        sam.retry,
    );
    let mut live = Some(sam);
    let mut up_since = tokio::time::Instant::now();
    let mut wait = backoff.first;
    let mut retry_at = up_since;
    loop {
        let ask = match live.as_mut() {
            Some(sam) => tokio::select! {
                () = sam.closed() => {
                    warn!("i2p sam {sam_addr}: session {} closed; rebuilding it", sam.session_id);
                    went_down(&role);
                    live = None;
                    let sleep = wait_after_loss(wait, backoff, up_since);
                    retry_at = tokio::time::Instant::now() + sleep;
                    wait = next_i2p_retry(sleep, backoff);
                    continue;
                }
                ask = asks.recv() => ask,
            },
            None => tokio::select! {
                () = tokio::time::sleep_until(retry_at) => {
                    live = restore(sam_addr, destination.clone(), forward_port, retry, &role, asks_tx.clone()).await;
                    if live.is_some() {
                        up_since = tokio::time::Instant::now();
                    } else {
                        retry_at = tokio::time::Instant::now() + wait;
                        wait = next_i2p_retry(wait, backoff);
                    }
                    continue;
                }
                ask = asks.recv() => ask,
            },
        };
        let Some(ask) = ask else {
            continue;
        };
        if live
            .as_ref()
            .is_some_and(|sam| sam.session_id == ask.failed)
        {
            warn!(
                "i2p sam {sam_addr}: session {} is gone; rebuilding it",
                ask.failed
            );
            went_down(&role);
            live = None;
            let sleep = wait_after_loss(wait, backoff, up_since);
            retry_at = tokio::time::Instant::now() + sleep;
            wait = next_i2p_retry(sleep, backoff);
        }
        if live.is_none() {
            live = restore(
                sam_addr,
                destination.clone(),
                forward_port,
                retry,
                &role,
                asks_tx.clone(),
            )
            .await;
            if live.is_some() {
                up_since = tokio::time::Instant::now();
            }
        }
        let _ = ask.reply.send(live.as_ref().map(I2pSam::dialer));
    }
}

#[doc(hidden)]
pub fn wait_after_loss(
    wait: std::time::Duration,
    backoff: I2pBackoff,
    up_since: tokio::time::Instant,
) -> std::time::Duration {
    if up_since.elapsed() >= backoff.max {
        backoff.first
    } else {
        wait
    }
}

fn went_down(role: &I2pRole) {
    if let I2pRole::Listen(peers) = role {
        peers.set_p2p_i2p_down(true);
    }
}

async fn restore(
    sam_addr: SocketAddr,
    destination: String,
    forward_port: Option<u16>,
    retry: std::time::Duration,
    role: &I2pRole,
    asks_tx: mpsc::Sender<RebuildAsk>,
) -> Option<I2pSam> {
    let sam = match rebuild_session(sam_addr, &destination, forward_port, retry).await {
        Ok(sam) => sam,
        Err(e) => {
            debug!("i2p sam {sam_addr}: rebuild failed: {e}");
            return None;
        }
    };
    if !matches!(role, I2pRole::Wallet) {
        install_kept(sam.dialer(), asks_tx);
    }
    if let I2pRole::Listen(peers) = role {
        peers.set_p2p_i2p_down(false);
    }
    info!("i2p sam {sam_addr}: session {} rebuilt", sam.session_id);
    Some(sam)
}

async fn rebuild_session(
    sam_addr: SocketAddr,
    destination: &str,
    forward_port: Option<u16>,
    retry: std::time::Duration,
) -> Result<I2pSam, NetError> {
    let (mut sam, _) =
        I2pSam::connect_session_dest_once(sam_addr, Some(destination), retry).await?;
    if let Some(port) = forward_port {
        let forward = sam.stream_forward_once(port).await?;
        sam.forward_port = Some(port);
        sam._forward = Some(forward);
    }
    Ok(sam)
}

// Ed25519 (7), not the SAM DSA_SHA1 default. leaseSetEncType 6 is ML-KEM-768
// hybrid and 4 is ECIES-X25519, as in Core. Java I2P rejects a third type (6,4,0).
// No tunnel length: the router's setting applies (three hops by default), as
// in Core. A one-hop tunnel lets a single relay link our IP to a destination.
#[doc(hidden)]
pub fn session_create_line(session_id: &str, dest_arg: &str) -> String {
    let sig = if dest_arg.eq_ignore_ascii_case("TRANSIENT") {
        " SIGNATURE_TYPE=7"
    } else {
        ""
    };
    format!(
        "SESSION CREATE STYLE=STREAM ID={session_id} DESTINATION={dest_arg}{sig} \
         i2cp.leaseSetEncType=6,4 inbound.quantity=1 outbound.quantity=1"
    )
}

// Public Destination is 387 bytes plus the cert length at bytes 385–386.
// The trailing private key is not part of the BIP155 hash.
pub fn i2p_addr_from_sam_b64(dest_b64: &str) -> Result<crate::NetAddr, NetError> {
    let raw = decode_i2p_b64(dest_b64.trim())?;
    let public = i2p_public_destination(&raw)?;
    let digest = sha256::Hash::hash(public);
    Ok(crate::NetAddr::I2p {
        dest: *digest.as_byte_array(),
        port: 0,
    })
}

#[doc(hidden)]
pub fn i2p_public_destination(raw: &[u8]) -> Result<&[u8], NetError> {
    const DEST_LEN_BASE: usize = 387;
    const CERT_LEN_POS: usize = 385;
    if raw.len() < CERT_LEN_POS + 2 {
        return Err(NetError::Encode(format!(
            "i2p destination too short ({})",
            raw.len()
        )));
    }
    let cert_len = u16::from_be_bytes([raw[CERT_LEN_POS], raw[CERT_LEN_POS + 1]]) as usize;
    let dest_len = DEST_LEN_BASE + cert_len;
    if dest_len > raw.len() {
        return Err(NetError::Encode(format!(
            "i2p certificate length {cert_len} needs {dest_len} bytes, have {}",
            raw.len()
        )));
    }
    Ok(&raw[..dest_len])
}

#[doc(hidden)]
pub fn decode_i2p_b64(s: &str) -> Result<Vec<u8>, NetError> {
    let mut bytes = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut n = 0u32;
    for c in s.chars() {
        if c == '=' {
            break;
        }
        let v = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '-' | '+' => 62,
            '~' | '/' => 63,
            _ => {
                return Err(NetError::Encode(format!(
                    "i2p destination base64 contains {c:?}"
                )));
            }
        };
        // `v` is six bits, so it does not overlap the shifted accumulator.
        acc = (acc << 6) + v;
        n += 6;
        if n >= 8 {
            n -= 8;
            bytes.push((acc >> n) as u8);
        }
    }
    Ok(bytes)
}

/// I2P destination alphabet (`A–Z`, `a–z`, `0–9`, `-`, `~`). No padding.
#[cfg(debug_assertions)]
#[doc(hidden)]
pub fn i2p_b64_encode(raw: &[u8]) -> String {
    const ALPH: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~";
    let mut out = String::new();
    let mut i = 0;
    while i < raw.len() {
        let b0 = raw[i];
        let b1 = if i + 1 < raw.len() { raw[i + 1] } else { 0 };
        let b2 = if i + 2 < raw.len() { raw[i + 2] } else { 0 };
        out.push(ALPH[(b0 >> 2) as usize] as char);
        // The two pieces occupy different bits of the index.
        out.push(ALPH[(((b0 & 3) << 4) + (b1 >> 4)) as usize] as char);
        if i + 1 < raw.len() {
            out.push(ALPH[(((b1 & 15) << 2) + (b2 >> 6)) as usize] as char);
        }
        if i + 2 < raw.len() {
            out.push(ALPH[(b2 & 63) as usize] as char);
        }
        i += 3;
    }
    out
}

#[doc(hidden)]
pub fn sam_kv<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    line.split_whitespace().find_map(|tok| {
        // Router text: a char across the `=` index is no key, not a panic.
        let (k, v) = tok.split_at_checked(prefix.len())?;
        k.eq_ignore_ascii_case(&prefix).then_some(v)
    })
}

#[doc(hidden)]
pub fn write_dest_file(path: &Path, dest: &str) -> Result<(), NetError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| NetError::Encode(format!("i2p dest dir {}: {e}", parent.display())))?;
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| NetError::Encode(format!("i2p dest {}: {e}", path.display())))?;
    writeln!(f, "{dest}")
        .map_err(|e| NetError::Encode(format!("i2p dest {}: {e}", path.display())))?;
    Ok(())
}

#[doc(hidden)]
pub fn fresh_session_id() -> String {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("CSPRNG for SAM session id");
    let mut id = String::from("rbtc");
    for x in b {
        id.push_str(&format!("{x:02x}"));
    }
    id
}

pub async fn hello(s: &mut TcpStream) -> Result<(), NetError> {
    write_line(s, "HELLO VERSION MIN=3.1 MAX=3.3").await?;
    let reply = read_line(s).await?;
    let up = reply.to_ascii_uppercase();
    if !up.starts_with("HELLO REPLY") || !up.contains("RESULT=OK") {
        return Err(NetError::Encode(format!("i2p sam hello: {reply}")));
    }
    Ok(())
}

pub async fn write_line(s: &mut TcpStream, line: &str) -> Result<(), NetError> {
    // i2pd's handshake read accepts a HELLO segment that has no newline, then
    // treats the following byte as the next command. A lone `\n` is a malformed
    // message and it closes the socket, so the command and its newline are one write.
    let mut framed = Vec::with_capacity(line.len() + 1);
    framed.extend_from_slice(line.as_bytes());
    framed.push(b'\n');
    s.write_all(&framed)
        .await
        .map_err(|e| NetError::Encode(format!("i2p sam write: {e}")))?;
    s.flush()
        .await
        .map_err(|e| NetError::Encode(format!("i2p sam write: {e}")))
}

pub async fn read_line(s: &mut TcpStream) -> Result<String, NetError> {
    let mut buf = Vec::new();
    loop {
        let mut b = [0u8; 1];
        s.read_exact(&mut b)
            .await
            .map_err(|e| NetError::Encode(format!("i2p sam read: {e}")))?;
        if b[0] == b'\n' {
            break;
        }
        if b[0] != b'\r' {
            buf.push(b[0]);
        }
        if buf.len() > 16 * 1024 {
            return Err(NetError::Encode("i2p sam read: line too long".into()));
        }
    }
    String::from_utf8(buf).map_err(|e| NetError::Encode(format!("i2p sam read: {e}")))
}
