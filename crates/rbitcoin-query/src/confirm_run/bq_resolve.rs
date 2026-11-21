//! BQ-ahead TipOnly parent resolve (lookup wave).
//!
//! Pack/hold uses enqueue-stamped Σ inputs (no `Block` decode). Emit runs one
//! `Store::get_fk_by_txid_batch_cancellable` (TipOnly) across the selected
//! heights (soft **64000** inputs / hard **1080** blocks). The confirm cancel
//! is asked before each sealed segment and each identity shot. Hits ride the
//! wave as
//! [`crate::BatchParentIds`] (fk + body_range + spent_range). Does not
//! claim, structure, or stamp. Creates above the wave's drain+fence snapshot
//! ([`UndrainedCreates`]: this wave's, and earlier waves' of the same re-arm
//! generation) are omitted from TipOnly need.

use super::*;
use crate::{BatchParentIds, IdMap, ResolvedWire, TxPrecompute, TxidHasher, U32Map, U64Map};
use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::{BuildHasher, BuildHasherDefault};
use std::sync::Arc;

/// Hard cap on BQ heights in one TipOnly wave (~1 week of 10-minute blocks).
///
/// Load packs **8000** inputs / **144** blocks. Lookup stays at least 4× the
/// block cap so early-IBD waves are fat enough that one skeleton covers many
/// heights. Soft stop is Σ `tx.input`
/// ([`BQ_RESOLVE_WAVE_MAX_INPUTS`]), include-overshoot, same shape as load.
/// Fat-era 64 k inputs is ~16 blocks → ~20 layers at `ready≈330`.
pub const BQ_RESOLVE_WAVE_MAX_BLOCKS: usize = 1080;
/// Soft max Σ `tx.input` per lookup wave (8× load's 8000; overshoot included).
pub const BQ_RESOLVE_WAVE_MAX_INPUTS: u32 = 64_000;
/// Hard min Σ `tx.input` per lookup wave (same number as load's pack).
///
/// Hold a thinner collect when more unresolved BQ heights can still join —
/// including `ready=0` / load-frontier / unknown window. Last available
/// thin wave still emits (tip / empty BQ).
pub const BQ_RESOLVE_WAVE_MIN_INPUTS: u32 = 8000;
/// Safety cap so one megablock run cannot stall the wave.
pub const BQ_RESOLVE_WAVE_MAX_KEYS: usize = 256_000;

/// Slots in the [`UndrainedCreates`] table: 2^17 buckets of 8.
#[doc(hidden)]
pub const UNDRAINED_SLOTS: usize = 1 << 20;
/// Heap of the [`UndrainedCreates`] table once lookup has recorded a block:
/// 8 B a slot, 8 MiB.
#[doc(hidden)]
pub const UNDRAINED_TABLE_BYTES: usize = UNDRAINED_SLOTS * std::mem::size_of::<u64>();

const BUCKET_SLOTS: usize = 8;
const BUCKETS: usize = UNDRAINED_SLOTS / BUCKET_SLOTS;
/// A slot is a 40-bit txid tag above a 24-bit level.
const LEVEL_BITS: u32 = 24;
const LEVEL_MASK: u64 = (1 << LEVEL_BITS) - 1;

/// What a slot stores for the height that created a txid: the height plus
/// one, so a zero slot is empty. `None` past the 24 bits a slot keeps.
fn level(height: u32) -> Option<u32> {
    height
        .checked_add(1)
        .filter(|&level| u64::from(level) <= LEVEL_MASK)
}

fn slot_level(slot: u64) -> u32 {
    (slot & LEVEL_MASK) as u32
}

/// One cache line of slots.
#[derive(Clone, Copy, Default)]
#[repr(align(64))]
struct Bucket([u64; BUCKET_SLOTS]);

/// Creates of blocks this lookup thread has decoded that the `tx.head`
/// drain and the fence have not passed.
///
/// A prev txid the set holds is not TipOnly need. Load binds it from
/// in-flight, which keeps every pack at or above a wave's drain+fence
/// snapshot until that wave's last batch has read it. The set holds only
/// heights above the same snapshot. Load clears in-flight when the re-arm
/// generation changes, and the set empties on the same change. Holding a
/// txid only removes a key from the store read. It binds nothing, and a
/// txid the set does not hold is read as before.
///
/// The set is one fixed table of [`UNDRAINED_SLOTS`] slots in 64 B buckets
/// of 8, [`UNDRAINED_TABLE_BYTES`] in all. A slot is a 40-bit tag of the
/// txid and the 24-bit `level` of the height that created it. The bucket
/// and the tag come from the whole txid hashed with SipHash-1-3 under a
/// random key of this set's own, so a txid that shares a slot with another
/// cannot be built offline. Nothing is removed by itself: a slot whose
/// height the snapshot has reached is dead, and an insert takes a dead or
/// empty slot, or else overwrites the lowest height in the bucket. Heights
/// die in the order they were inserted, so that is the oldest create, and
/// spends of it are read from `tx.head` as before.
///
/// Two txids with one tag in one bucket answer as one. A prev held that way
/// is in neither in-flight nor the wave's skeleton, and load reads it from
/// `tx.head` ([`crate::stamp_external_parents`]).
///
/// `S` is the keyed hash. A test can give one that collides on purpose.
pub struct UndrainedCreates<S = RandomState> {
    gen: Option<u32>,
    hasher: S,
    /// Empty until the first block is recorded.
    table: Box<[Bucket]>,
    /// A level at or below it is dead.
    dead_through: u32,
    /// No live slot is above this level.
    top: u32,
}

impl Default for UndrainedCreates {
    fn default() -> Self {
        Self::with_hasher(RandomState::new())
    }
}

impl<S> std::fmt::Debug for UndrainedCreates<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UndrainedCreates")
            .field("gen", &self.gen)
            .field("heap_bytes", &self.heap_bytes())
            .field("dead_through", &self.dead_through)
            .field("top", &self.top)
            .finish()
    }
}

impl<S> UndrainedCreates<S> {
    /// An empty set that places txids with `hasher`.
    #[doc(hidden)]
    pub fn with_hasher(hasher: S) -> Self {
        Self {
            gen: None,
            hasher,
            table: Box::default(),
            dead_through: 0,
            top: 0,
        }
    }

    /// Heap the set holds: the table, once a block has been recorded.
    #[doc(hidden)]
    pub fn heap_bytes(&self) -> usize {
        std::mem::size_of_val(&*self.table)
    }
}

impl<S: BuildHasher> UndrainedCreates<S> {
    /// The bucket and the tag of `txid`.
    fn place(&self, txid: &[u8; 32]) -> (usize, u64) {
        use std::hash::Hasher;
        let mut hasher = self.hasher.build_hasher();
        hasher.write(txid);
        let hash = hasher.finish();
        ((hash as usize) & (BUCKETS - 1), hash >> LEVEL_BITS)
    }

    /// A live slot in `bucket` carries `tag`.
    fn bucket_holds(&self, bucket: usize, tag: u64) -> bool {
        self.table[bucket]
            .0
            .iter()
            .any(|&slot| slot >> LEVEL_BITS == tag && slot_level(slot) > self.dead_through)
    }

    /// A create of `txid` is recorded at a height above the last snapshot.
    #[doc(hidden)]
    pub fn holds(&self, txid: &[u8; 32]) -> bool {
        if self.table.is_empty() {
            return false;
        }
        let (bucket, tag) = self.place(txid);
        self.bucket_holds(bucket, tag)
    }

    /// [`Self::holds`] for each of `txids`, in order. Every txid is hashed
    /// before any bucket is read, so the bucket reads do not wait on one
    /// another's hash.
    #[doc(hidden)]
    pub fn holds_each(&self, txids: &[[u8; 32]]) -> Vec<bool> {
        if self.table.is_empty() {
            return vec![false; txids.len()];
        }
        let places: Vec<(usize, u64)> = txids.iter().map(|txid| self.place(txid)).collect();
        places
            .into_iter()
            .map(|(bucket, tag)| self.bucket_holds(bucket, tag))
            .collect()
    }

    /// Empty the set unless it was filled under re-arm generation `gen`.
    #[doc(hidden)]
    pub fn rearm(&mut self, gen: u32) {
        if self.gen == Some(gen) {
            return;
        }
        self.gen = Some(gen);
        self.table.fill(Bucket::default());
        self.dead_through = 0;
        self.top = 0;
    }

    /// Mark the heights a drain+fence snapshot has reached dead. `None`
    /// keeps all.
    #[doc(hidden)]
    pub fn drop_through(&mut self, hi: Option<u32>) {
        let Some(hi) = hi else {
            return;
        };
        let through = level(hi).unwrap_or(LEVEL_MASK as u32);
        self.dead_through = self.dead_through.max(through);
    }

    /// Record the block decoded at `height`. It replaces that height and
    /// every height above it: lookup decodes in ascending order, so a
    /// height seen again means the rows from there up were queued again.
    #[doc(hidden)]
    pub fn note_block(&mut self, height: u32, txids: impl IntoIterator<Item = [u8; 32]>) {
        self.forget_from(height);
        let Some(level) = level(height) else {
            return;
        };
        if self.table.is_empty() {
            self.table = vec![Bucket::default(); BUCKETS].into_boxed_slice();
        }
        let places: Vec<(usize, u64)> = txids.into_iter().map(|txid| self.place(&txid)).collect();
        for (bucket, tag) in places {
            self.insert(bucket, tag, level);
        }
        self.top = self.top.max(level);
    }

    /// Put `tag` at `level` in `bucket`: over a live slot with that tag,
    /// else in the first dead or empty slot, else over the lowest level.
    fn insert(&mut self, bucket: usize, tag: u64, level: u32) {
        let dead_through = self.dead_through;
        let slots = &mut self.table[bucket].0;
        let mut free = None;
        let mut oldest = (u32::MAX, 0);
        for (i, &slot) in slots.iter().enumerate() {
            let at = slot_level(slot);
            if at <= dead_through {
                free.get_or_insert(i);
            } else if slot >> LEVEL_BITS == tag {
                free = Some(i);
                break;
            } else if at < oldest.0 {
                oldest = (at, i);
            }
        }
        slots[free.unwrap_or(oldest.1)] = (tag << LEVEL_BITS) | u64::from(level);
    }

    /// Forget `height` and every height above it, in one pass over the
    /// table when any of them is recorded.
    fn forget_from(&mut self, height: u32) {
        let Some(from) = level(height) else {
            return;
        };
        if self.top < from {
            return;
        }
        for bucket in self.table.iter_mut() {
            for slot in bucket.0.iter_mut() {
                if slot_level(*slot) >= from {
                    *slot = 0;
                }
            }
        }
        self.top = from - 1;
    }
}

/// One wave's TipOnly need and the prevs left out of it.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct WaveKeys {
    pub need: HashSet<[u8; 32], BuildHasherDefault<TxidHasher>>,
    /// One entry per input whose prev was in the skip set at collect.
    pub skipped: Vec<[u8; 32]>,
}

impl WaveKeys {
    /// Move every skipped prev that `skip` no longer holds back into the
    /// need. Returns the inputs still left out.
    #[doc(hidden)]
    pub fn readmit<S: BuildHasher>(&mut self, skip: &UndrainedCreates<S>) -> u32 {
        let mut left_out = 0u32;
        let held = skip.holds_each(&self.skipped);
        for (prev, held) in self.skipped.drain(..).zip(held) {
            if held {
                left_out = left_out.saturating_add(1);
            } else {
                self.need.insert(prev);
            }
        }
        left_out
    }
}

/// Stop before another height once the key cap is hit and this wave already
/// has a height. An empty `done` still emits the height that filled the cap.
#[doc(hidden)]
pub fn stop_for_key_cap(n_keys: usize, done: usize) -> bool {
    n_keys >= BQ_RESOLVE_WAVE_MAX_KEYS && done > 0
}

/// Soft window at least one day of blocks, and the queue has not filled it.
#[doc(hidden)]
pub fn wave_queue_still_filling(win: u32, queued: u32) -> bool {
    win >= 144 && queued < win
}

/// More BQ heights than this wave, or the queue is still filling that window.
#[doc(hidden)]
pub fn wave_more_remain(selected: usize, requested: usize, filling: bool) -> bool {
    selected < requested || filling
}

/// Same include-overshoot rule as load `pack_stop_after`: stop after the
/// block that crosses the soft input budget or hits the hard height cap.
#[inline]
pub fn bq_resolve_wave_stop_after(
    sum_inputs: u32,
    n_blocks: usize,
    soft_max_inputs: u32,
    hard_max_blocks: usize,
) -> bool {
    n_blocks >= hard_max_blocks || sum_inputs > soft_max_inputs
}

#[allow(clippy::too_many_arguments)] // call-site args stay unbundled
/// Hold a short wave while the BQ is fat so lookup does not mint one layer
/// per newly fetched block.
///
/// `ready` is BQ depth. `soft_win` is the 1-min confirm window (`bq soft=n/win`).
/// `path_lo` is the load frontier (store tip+1). `first_unresolved` is the
/// lowest collected height (already sorted by `BlockQueue::unresolved_heights`).
///
/// Never hold (above the input floor) when the first unresolved height sits
/// in the load-facing half of the window (`first - path_lo ≤ win/2`) — that
/// is the block load is about to claim. O(1): two subtracts, no extra queue
/// walk. `soft_win == 0` (rate unknown) skips only the fat-BQ short hold.
///
/// `more_remain`: more unresolved BQ heights can still join this layer.
/// [`BQ_RESOLVE_WAVE_MIN_INPUTS`] holds a thin far wave; it does **not**
/// hold when `first_unresolved == path_lo` (load's next tip block).
#[inline]
pub fn bq_resolve_wave_hold_partial(
    ready: u32,
    soft_win: u32,
    sum_inputs: u32,
    n_blocks: usize,
    path_lo: u32,
    first_unresolved: u32,
    more_remain: bool,
    max_inputs: u32,
    max_blocks: usize,
) -> bool {
    if n_blocks == 0 {
        return false;
    }
    let at_max = bq_resolve_wave_stop_after(sum_inputs, n_blocks, max_inputs, max_blocks);
    if at_max {
        return false;
    }
    if sum_inputs < BQ_RESOLVE_WAVE_MIN_INPUTS && more_remain && first_unresolved != path_lo {
        return true;
    }
    if soft_win == 0 {
        return false;
    }
    if first_unresolved.saturating_sub(path_lo) <= soft_win / 2 {
        return false;
    }
    ready > soft_win / 2
}

/// Decoded heights from one lookup wave (BQ rows parked as resolved until take).
pub struct BqResolveWave {
    pub stats: BqResolveWaveStats,
    pub items: Vec<(u32, [u8; 32], ResolvedWire)>,
    /// [`Query::drain_and_fence_hi`] immediately before this wave's TipOnly read.
    pub drain_fence_hi: Option<u32>,
    /// TipOnly hits for this wave, shared by every load chunk.
    pub parent_ids: BatchParentIds,
    /// `(height, hash)` of a raw row that did not decode. The wave stops
    /// there and the row is already off the body queue; the caller rejects
    /// the hash as soft wire so another peer can serve it.
    pub undecodable: Option<(u32, [u8; 32])>,
}

/// Outcome of one TipOnly wave over BQ-ready heights.
#[derive(Debug, Default, Clone, Copy)]
pub struct BqResolveWaveStats {
    pub heights: u32,
    pub keys: u32,
    pub hits: u32,
    pub work_ns: u64,
    /// `consensus_decode` of still-raw BQ payloads (this wave).
    pub decode_ns: u64,
    /// `from_tx_wire` on payload slices (`precompute=`).
    pub precompute_ns: u64,
    /// `push_resolve_keys` (this wave).
    pub collect_ns: u64,
    /// TipOnly `get_fk_by_txid_batch_cancellable` (this wave).
    pub head_ns: u64,
    /// TipOnly `create.loc` fill is inside [`Self::head_ns`] (`idx_ns`): one
    /// batch after the sealed walk, not on the held probe ring.
    pub spent_ns: u64,
    /// Inputs whose prev stayed out of the TipOnly need: its create is
    /// above this wave's drain+fence snapshot.
    pub undrained_skip: u32,
}

/// Push external prev_txids (+ pre-BIP34 create txids) into the wave TipOnly set.
///
/// Spend keys record every non-coinbase prev (including the ones `skip`
/// holds) so a later load chunk can bind in-flight. A prev `skip` holds goes
/// to [`WaveKeys::skipped`], not the need.
#[doc(hidden)]
pub fn push_resolve_keys<S: BuildHasher>(
    params: &ChainParams,
    height: u32,
    block: &Block,
    pres: &[TxPrecompute],
    skip: &UndrainedCreates<S>,
    keys: &mut WaveKeys,
    n_inputs: u32,
) -> Vec<[u8; 32]> {
    let bip34 = params.bip34_active_at(height);
    let mut spends = Vec::with_capacity(n_inputs as usize);
    let mut bip30 = Vec::new();
    for (tx, p) in block.txdata.iter().zip(pres.iter()) {
        for inp in &tx.input {
            if inp.previous_output.is_null() {
                continue;
            }
            let prev = inp.previous_output.txid.to_byte_array();
            if prev == [0u8; 32] {
                continue;
            }
            spends.push(prev);
        }
        if !bip34 {
            bip30.push(p.txid);
        }
    }
    for (prev, held) in spends.iter().zip(skip.holds_each(&spends)) {
        if held {
            keys.skipped.push(*prev);
        } else {
            keys.need.insert(*prev);
        }
    }
    for (txid, held) in bip30.iter().zip(skip.holds_each(&bip30)) {
        if !held {
            keys.need.insert(*txid);
        }
    }
    // One key per parent txid: inputs spending the same parent share it.
    spends.sort_unstable();
    spends.dedup();
    spends
}

/// TipOnly-resolve external parents for `heights` still on the BQ.
///
/// Skips missing / already-complete heights. Stops at the first raw row
/// that does not decode, dequeues it, and names it in
/// [`BqResolveWave::undecodable`]. Marks each
/// processed height resolve-complete even when some keys miss (same-batch /
/// in-flight remainder is load's job). Connected-only (fence) resolve.
/// `max_blocks` / `max_inputs` cap emit (remaining loadq). `undrained` is
/// the calling lookup thread's set, carried from wave to wave.
pub fn confirm_bq_resolve_wave_capped<S: BuildHasher>(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    heights: &[u32],
    max_blocks: usize,
    max_inputs: u32,
    undrained: &mut UndrainedCreates<S>,
) -> Result<BqResolveWave, ConfirmError> {
    let t0 = Instant::now();
    // The caller read the generation before it selected heights and takes
    // this wave's rows under that value. A re-arm between its read and this
    // one fills the set under the new generation from the old selection,
    // and the take then fails. The next wave starts at or below those
    // heights, and a height walked again replaces itself and every height
    // above it.
    undrained.rearm(query.lookup_taken_gen());
    let mut stats = BqResolveWaveStats::default();
    let mut done: Vec<u32> = Vec::new();
    let mut keys = WaveKeys::default();
    let mut wires: Vec<(u32, [u8; 32], ResolvedWire)> = Vec::new();

    let intake = query.block_queue_wave_intake(heights);
    let mut n_inputs_at: U32Map<u32> = U32Map::default();
    let mut header_fk_at: U32Map<u64> = U32Map::default();
    let mut sender_at: U32Map<u64> = U32Map::default();
    let raw_h: HashSet<u32> = intake
        .raw
        .into_iter()
        .map(|(h, n, fk, sender)| {
            n_inputs_at.insert(h, n);
            header_fk_at.insert(h, fk);
            if let Some(s) = sender {
                sender_at.insert(h, s);
            }
            h
        })
        .collect();
    let mut resolved_by_h: HashMap<u32, ResolvedWire> = HashMap::new();
    for (h, wire) in intake.resolved {
        n_inputs_at.insert(h, wire.n_inputs);
        resolved_by_h.insert(h, wire);
    }

    let mut selected: Vec<u32> = Vec::new();
    let mut sum_inputs = 0u32;
    for &h in heights {
        if !raw_h.contains(&h) && !resolved_by_h.contains_key(&h) {
            continue;
        }
        let n = n_inputs_at.get(&h).copied().unwrap_or(0);
        selected.push(h);
        sum_inputs = sum_inputs.saturating_add(n);
        if bq_resolve_wave_stop_after(sum_inputs, selected.len(), max_inputs, max_blocks) {
            break;
        }
    }

    if let Some(&first) = selected.first() {
        let path_lo = query
            .tip_height()
            .map(|h| h.0.saturating_add(1))
            .unwrap_or(0);
        let win = query.soft_confirm_window();
        let filling = wave_queue_still_filling(win, query.block_queue_count() as u32);
        let more_remain = wave_more_remain(selected.len(), heights.len(), filling);
        if bq_resolve_wave_hold_partial(
            query.block_queue_count() as u32,
            query.soft_confirm_window(),
            sum_inputs,
            selected.len(),
            path_lo,
            first,
            more_remain,
            max_inputs,
            max_blocks,
        ) {
            stats.work_ns = t0.elapsed().as_nanos() as u64;
            query.confirm_stats().note_wave_decode(
                stats.decode_ns,
                stats.precompute_ns,
                stats.collect_ns,
                stats.head_ns,
                stats.spent_ns,
            );
            return Ok(BqResolveWave {
                stats,
                items: Vec::new(),
                drain_fence_hi: None,
                parent_ids: BatchParentIds::default(),
                undecodable: None,
            });
        }
    }

    let mut undecodable = None;
    for &h in &selected {
        if stop_for_key_cap(keys.need.len(), done.len()) {
            break;
        }
        let hash = query.block_queue_hash_at_height(h).unwrap_or([0u8; 32]);
        let (block, pres) = if let Some(wire) = resolved_by_h.remove(&h) {
            wires.push((h, hash, wire.clone()));
            (Arc::clone(&wire.block), Arc::clone(&wire.pres))
        } else if raw_h.contains(&h) {
            let Ok(Some(payload)) = query.block_queue_raw_payload(h) else {
                continue;
            };
            let t_dec = Instant::now();
            let decoded = crate::decode_block_precomputes(
                &payload[..],
                !crate::milestone_gate::skips_on_query(milestone, query, h, &hash),
            );
            let wall = t_dec.elapsed().as_nanos() as u64;
            let Some((block, pres_vec, pre_ns)) = decoded else {
                // A row that never decodes would hold this height in hand
                // forever: drop it so the hash is fetched again.
                stats.decode_ns = stats.decode_ns.saturating_add(wall);
                query.block_queue_dequeue_height(h)?;
                undecodable = Some((h, hash));
                break;
            };
            stats.decode_ns = stats.decode_ns.saturating_add(wall.saturating_sub(pre_ns));
            stats.precompute_ns = stats.precompute_ns.saturating_add(pre_ns);
            let pres = Arc::<[TxPrecompute]>::from(pres_vec);
            let block = Arc::new(block);
            wires.push((
                h,
                hash,
                ResolvedWire::stamped(
                    Arc::clone(&block),
                    Arc::clone(&pres),
                    n_inputs_at.get(&h).copied().unwrap_or(0),
                    header_fk_at.get(&h).copied().unwrap_or(0),
                    sender_at.get(&h).copied(),
                ),
            ));
            (block, pres)
        } else {
            continue;
        };
        let t_col = Instant::now();
        undrained.note_block(h, pres.iter().map(|p| p.txid));
        let spends = push_resolve_keys(
            params,
            h,
            block.as_ref(),
            pres.as_ref(),
            undrained,
            &mut keys,
            n_inputs_at.get(&h).copied().unwrap_or(0),
        );
        stats.collect_ns = stats
            .collect_ns
            .saturating_add(t_col.elapsed().as_nanos() as u64);
        if let Some((_, _, w)) = wires.last_mut() {
            w.spend_keys = Arc::from(spends);
            // The raw row is dead once decoded. Promote now so its bytes do
            // not wait on the TipOnly read below.
            let charge = w.block.total_size() as u64;
            query
                .block_queue_promote_wave(vec![(h, w.clone(), charge)])
                .map_err(ConfirmError::from)?;
        }
        done.push(h);
    }

    let t_settle = Instant::now();
    let drain_fence_hi = query.drain_and_fence_hi();
    undrained.drop_through(drain_fence_hi);
    stats.undrained_skip = keys.readmit(undrained);
    stats.collect_ns = stats
        .collect_ns
        .saturating_add(t_settle.elapsed().as_nanos() as u64);
    stats.keys = keys.need.len() as u32;
    let mut layer = IdMap::default();
    let mut spent = U64Map::default();
    let mut n_out = U64Map::default();
    let need: Vec<[u8; 32]> = keys.need.into_iter().collect();
    let t_head = Instant::now();

    if let Some(&hi) = selected.last() {
        query.note_lookup_tiponly_start(hi);
    }

    if !need.is_empty() {
        let rows = query
            .store()
            .get_fk_by_txid_batch_cancellable(&need, &|| query.confirm_cancelled())
            .map_err(ConfirmError::from)?;
        for (txid, row) in rows {
            if let Some((fk, pair)) = row {
                layer.insert(txid, (fk, pair.txout));
                if let Some(id) = fk.get() {
                    spent.insert(id, pair.spent);
                    n_out.insert(id, pair.n_out);
                }
            }
        }
    }
    stats.head_ns = t_head.elapsed().as_nanos() as u64;
    stats.hits = layer.len() as u32;
    stats.spent_ns = 0;
    let parent_ids = BatchParentIds {
        ids: Arc::new(layer),
        spent: Arc::new(spent),
        n_out: Arc::new(n_out),
    };

    stats.heights = wires.len() as u32;
    stats.work_ns = t0.elapsed().as_nanos() as u64;
    query.confirm_stats().note_wave_decode(
        stats.decode_ns,
        stats.precompute_ns,
        stats.collect_ns,
        stats.head_ns,
        stats.spent_ns,
    );
    query
        .confirm_stats()
        .note_wave_undrained_skip(u64::from(stats.undrained_skip));
    Ok(BqResolveWave {
        stats,
        items: wires,
        drain_fence_hi,
        parent_ids,
        undecodable,
    })
}

/// Take one load batch: move `lookup_taken_hi` to its last height, then
/// dequeue its BQ rows. `gen` is [`Query::lookup_taken_gen`] when the wave
/// was selected. After a re-arm the mark stays at the re-arm and this
/// returns `false` with the rows still queued, so the caller must not send
/// the batch: lookup selects those rows again.
pub fn take_wave_items_for_load(
    query: &Query,
    items: &[(u32, [u8; 32], ResolvedWire)],
    gen: u32,
) -> Result<bool, ConfirmError> {
    let Some(&(last, _, _)) = items.last() else {
        return Ok(true);
    };
    if !query.advance_lookup_taken_hi(gen, last) {
        return Ok(false);
    }
    for (h, _, _) in items {
        query
            .block_queue_dequeue_height(*h)
            .map_err(ConfirmError::from)?;
    }
    Ok(true)
}
