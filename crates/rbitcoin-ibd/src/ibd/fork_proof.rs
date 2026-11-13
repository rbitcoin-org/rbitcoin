//! Proof that peers serve a heavier fork before IBD switches to it.
//!
//! IBD follows a heavier header chain by rewinding the confirmed tip to the
//! fork point ([`super::reorg`]). Core never makes a chain its tip before it
//! has that chain's blocks. Here a fork that would replace the download
//! candidate stays headers until peers have served the shortest prefix of it
//! whose work beats this node's chain with data above the fork point. Each
//! body is checked against its header (hash and merkle root). Served bodies
//! are kept in RAM, up to [`MAX_BYTES`], until the download path takes them;
//! one served past that still counts, and the path fetches it again after the
//! switch. A fork nobody serves never moves the tip or the download path, and
//! a peer that serves part of the prefix and then withholds leaves both where
//! they were.

use bitcoin::block::Header;
use bitcoin::{Block, BlockHash, Work};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

/// Forks proved at once. A third drops a fork nobody has served a block of,
/// the lightest first.
pub const MAX_FORKS: usize = 2;
/// Asks in flight for one fork, so a fork nobody serves cannot hold the asks
/// another fork's peers are answering.
pub const MAX_ASKS_PER_FORK: usize = 16;
/// Longest prefix proved: the deepest rewind above the work floor
/// ([`super::reorg::REWIND_MAX_DEPTH`]) plus the block that out-works it.
pub const MAX_BLOCKS: usize = super::reorg::REWIND_MAX_DEPTH as usize + 1;
/// Served bodies kept across every fork, beside the body queue. At least 16
/// full mainnet blocks.
pub const MAX_BYTES: u64 = 64 << 20;
/// How long catch-up waits for the walk to take a served fork it handed
/// back before it may finish without it.
pub const HANDOFF: Duration = Duration::from_secs(5);

/// One fork whose prefix is being proved.
#[derive(Debug)]
pub struct Fork {
    pub fork_hash: BlockHash,
    pub fork_height: u32,
    /// Linked headers after the fork point, oldest first.
    pub headers: Vec<Header>,
    /// How many of `headers` must be served.
    pub need: usize,
    /// Chain work at the last header.
    pub work: Work,
    /// The peer whose headers these are, when one sent them.
    pub peer: Option<usize>,
    /// Prefix blocks a peer served, each checked against its header.
    served: HashSet<BlockHash>,
    /// The served bodies kept for the path.
    bodies: HashMap<BlockHash, Vec<u8>>,
    /// The headers went back through the walk once the prefix was served.
    handed: bool,
    /// When they went back.
    handed_at: Option<Instant>,
    /// The walk took this fork. Its bodies wait for the path; it is never
    /// handed back again.
    taken: bool,
}

impl Fork {
    fn prefix(&self) -> impl Iterator<Item = BlockHash> + '_ {
        self.headers.iter().take(self.need).map(|h| h.block_hash())
    }

    fn proven(&self) -> bool {
        self.need > 0 && self.prefix().all(|h| self.served.contains(&h))
    }

    fn first(&self) -> Option<BlockHash> {
        self.headers.first().map(|h| h.block_hash())
    }

    fn bytes(&self) -> u64 {
        self.bodies.values().map(|b| b.len() as u64).sum()
    }
}

/// A prefix block to ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wanted {
    pub hash: BlockHash,
    /// The peer that sent the fork, asked first.
    pub peer: Option<usize>,
    /// The fork's last header: a peer that announced it has the chain.
    pub top: Option<BlockHash>,
    /// The fork's first header, which names it.
    pub fork: BlockHash,
}

#[derive(Debug, Default)]
pub struct ForkProofs {
    forks: Vec<Fork>,
    bytes: u64,
}

impl ForkProofs {
    /// Hold `headers`, which fork at `fork_hash` (`fork_height`), until
    /// peers have served the first `need` of them.
    #[allow(clippy::too_many_arguments)] // one fork's identity, kept flat
    pub fn offer(
        &mut self,
        fork_hash: BlockHash,
        fork_height: u32,
        headers: &[Header],
        need: usize,
        work: Work,
        peer: Option<usize>,
    ) {
        let Some(first) = headers.first().map(|h| h.block_hash()) else {
            return;
        };
        let need = need.min(headers.len());
        if let Some(f) = self.find_mut(fork_hash, first) {
            if headers.len() > f.headers.len() {
                f.headers = headers.to_vec();
                f.work = work;
            }
            if need != f.need && !f.taken {
                f.need = need;
                f.handed = false;
            }
            if peer.is_some() {
                f.peer = peer;
            }
            return;
        }
        self.forks.push(Fork {
            fork_hash,
            fork_height,
            headers: headers.to_vec(),
            need,
            work,
            peer,
            served: HashSet::new(),
            bodies: HashMap::new(),
            handed: false,
            handed_at: None,
            taken: false,
        });
        if self.forks.len() > MAX_FORKS {
            let victim = (0..self.forks.len())
                .min_by_key(|&i| (!self.forks[i].served.is_empty(), self.forks[i].work));
            if let Some(i) = victim {
                let gone = self.forks.remove(i);
                self.bytes = self.bytes.saturating_sub(gone.bytes());
            }
        }
    }

    fn find_mut(&mut self, fork_hash: BlockHash, first: BlockHash) -> Option<&mut Fork> {
        self.forks.iter_mut().find(|f| {
            f.fork_hash == fork_hash && f.headers.first().map(|h| h.block_hash()) == Some(first)
        })
    }

    /// Peers have served the first `need` of `headers`, which fork at
    /// `fork_hash`.
    pub fn is_proven(&self, fork_hash: BlockHash, headers: &[Header], need: usize) -> bool {
        let Some(first) = headers.first().map(|h| h.block_hash()) else {
            return false;
        };
        let Some(f) = self.forks.iter().find(|f| {
            f.fork_hash == fork_hash && f.headers.first().map(|h| h.block_hash()) == Some(first)
        }) else {
            return false;
        };
        need > 0
            && need <= headers.len()
            && headers[..need]
                .iter()
                .all(|h| f.served.contains(&h.block_hash()))
    }

    /// The walk took the fork `headers` start, at `fork_hash`.
    pub fn note_taken(&mut self, fork_hash: BlockHash, headers: &[Header]) {
        if let Some(first) = headers.first().map(|h| h.block_hash()) {
            if let Some(f) = self.find_mut(fork_hash, first) {
                f.taken = true;
                f.handed = true;
            }
        }
    }

    /// Prefix blocks no peer has served yet, heaviest fork first, each with
    /// the peer that sent the fork and the fork's last header.
    pub fn wanted(&self) -> Vec<Wanted> {
        let mut order: Vec<&Fork> = self.forks.iter().collect();
        order.sort_by_key(|f| std::cmp::Reverse(f.work));
        order
            .into_iter()
            .flat_map(|f| {
                let top = f.headers.last().map(|h| h.block_hash());
                let fork = f.first().unwrap_or(f.fork_hash);
                f.prefix()
                    .filter(|h| !f.served.contains(h))
                    .map(move |hash| Wanted {
                        hash,
                        peer: f.peer,
                        top,
                        fork,
                    })
            })
            .collect()
    }

    pub fn wants(&self, hash: &BlockHash) -> bool {
        self.forks
            .iter()
            .any(|f| !f.served.contains(hash) && f.prefix().any(|h| h == *hash))
    }

    /// Count `payload` as served when it is the prefix block `hash` names,
    /// with the transactions its header commits to. The body is kept while
    /// the kept bodies stay within [`MAX_BYTES`]. True when newly served.
    pub fn accept(&mut self, hash: BlockHash, payload: Vec<u8>) -> bool {
        if !self.wants(&hash) {
            return false;
        }
        let Ok(block) = bitcoin::consensus::deserialize::<Block>(&payload) else {
            return false;
        };
        if block.block_hash() != hash || !block.check_merkle_root() {
            return false;
        }
        let len = payload.len() as u64;
        let fits = self.bytes.saturating_add(len) <= MAX_BYTES;
        let Some(f) = self
            .forks
            .iter_mut()
            .find(|f| !f.served.contains(&hash) && f.prefix().any(|h| h == hash))
        else {
            return false;
        };
        f.served.insert(hash);
        if fits {
            f.bodies.insert(hash, payload);
            self.bytes = self.bytes.saturating_add(len);
        }
        true
    }

    /// The heaviest fork whose prefix was served and not yet handed back:
    /// its peer and headers, to go through the walk again.
    pub fn take_ready(&mut self) -> Option<(Option<usize>, BlockHash, Vec<Header>)> {
        let f = self
            .forks
            .iter_mut()
            .filter(|f| !f.handed && f.proven())
            .max_by_key(|f| f.work)?;
        f.handed = true;
        f.handed_at = Some(Instant::now());
        Some((f.peer, f.fork_hash, f.headers.clone()))
    }

    /// The first header of each fork whose prefix was served.
    pub fn proven_roots(&self) -> Vec<BlockHash> {
        self.forks
            .iter()
            .filter(|f| f.proven())
            .filter_map(|f| f.first())
            .collect()
    }

    /// A served body for `hash`, for the body queue.
    pub fn take_body(&mut self, hash: &BlockHash) -> Option<Vec<u8>> {
        for f in &mut self.forks {
            if let Some(body) = f.bodies.remove(hash) {
                self.bytes = self.bytes.saturating_sub(body.len() as u64);
                return Some(body);
            }
        }
        None
    }

    /// Hashes of served bodies not yet taken.
    pub fn held(&self) -> Vec<BlockHash> {
        self.forks
            .iter()
            .flat_map(|f| f.bodies.keys().copied())
            .collect()
    }

    /// Drop forks `keep` rejects, with their bodies.
    pub fn retain(&mut self, mut keep: impl FnMut(&Fork) -> bool) {
        let mut freed = 0u64;
        self.forks.retain(|f| {
            let kept = keep(f);
            if !kept {
                freed = freed.saturating_add(f.bytes());
            }
            kept
        });
        self.bytes = self.bytes.saturating_sub(freed);
    }

    /// Whether the walk took `f` and the path took every body it held.
    pub fn spent(f: &Fork) -> bool {
        f.taken && f.bodies.is_empty()
    }

    /// A served fork went back through the walk within [`HANDOFF`] and the
    /// walk has not taken it yet.
    pub fn handing_off(&self) -> bool {
        self.forks
            .iter()
            .any(|f| f.handed && !f.taken && f.handed_at.is_some_and(|at| at.elapsed() < HANDOFF))
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn is_empty(&self) -> bool {
        self.forks.is_empty()
    }
}

/// Length of the shortest prefix of `headers` whose work beats `ours`.
pub fn prefix_beating(headers: &[Header], ours: Work) -> Option<usize> {
    let mut acc = Work::from_be_bytes([0; 32]);
    for (i, h) in headers.iter().enumerate() {
        acc = acc + h.work();
        if acc > ours {
            return Some(i + 1);
        }
    }
    None
}
