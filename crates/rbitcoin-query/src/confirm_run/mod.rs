//! Multi-block confirm orchestrator (IBD / tip Class C path).
//!
//! **Primary height-ordered pipeline** (raw wire → validated tip):
//! ```text
//! LOOKUP STAGE (ibd-confirm-lookup OS thread):
//!   BQ decode + TipOnly parent ids (no structure / plan_batch)
//! LOAD STAGE (ibd-confirm-load OS thread):
//!   structure + plan_batch (binds carried BQ keys) + pin denserels → assemble
//!   (uses intake wire; **no Class-A wire rebuild**)
//! SCRIPTS STAGE (`ibd-confirm` OS thread publishes waves; `rbtc-scripts-*` steal):
//!   script verify on one wave, then live filter/tweak jobs on a second.
//!   No Query, no disk. No coordinator threads. The next batch starts when
//!   both waves are fully claimed.
//! WRITE STAGE (ibd-confirm-write OS thread, FIFO):
//!   Class A commit (if plan) + structural + class_c + spend annotate + tip GC.
//!   The `tx.head` insert runs here after annotate.
//! ```
//! IBD pipelines lookup(N+1) ∥ load(N) ∥ scripts(N−1) ∥ write(N−2). One Class A appender.
//!
//! [`confirm_wire_run`] is the unified entry (tests / tip / IBD).
//!
//! **Scripts purity:** [`confirm_scripts_phase`] is pure
//! [`LoadedBatch`] → [`ScriptOkBatch`]. IBD [`drive_script_waves_with`] publishes
//! the next batch when both waves have nothing left to claim, then writes
//! in height order once both waves have finished. Steal workers unpark the
//! publisher when a wave completes.

use crate::block_pipeline::{assemble_block_prevouts, structural_validate_spends};
use crate::header_read::validate_header_hashed;
use crate::ConfirmError;
use crate::{FkMap, Query, U32Map, U64Map};
use bitcoin::hashes::Hash;
use bitcoin::Block;
use rbitcoin_consensus::block::{block_has_witness_from_pres, ScriptCheckJob, ValidationContext};
use rbitcoin_consensus::header::pow_hash_meets_target;
use rbitcoin_consensus::{ChainParams, ConsensusError, Milestone};
use rbitcoin_primitives::Height;
use rbitcoin_store::StoreError;
use std::cell::Cell;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

#[doc(hidden)]
pub mod bq_resolve;
#[doc(hidden)]
pub mod index;
#[doc(hidden)]
pub mod lookup;
#[doc(hidden)]
pub mod phases;
#[doc(hidden)]
pub mod pin;
#[doc(hidden)]
pub mod scripts;
#[doc(hidden)]
pub mod write;

pub use bq_resolve::{
    confirm_bq_resolve_wave_capped, take_wave_items_for_load, BqResolveWave, UndrainedCreates,
    BQ_RESOLVE_WAVE_MAX_BLOCKS, BQ_RESOLVE_WAVE_MAX_INPUTS,
};
#[doc(hidden)]
pub use lookup::{confirm_archive_kind, ConfirmArchiveKind};
pub use lookup::{
    confirm_wire_load_from_plan, confirm_wire_lookup_stamp, parent_missing_from_chain,
    ParentPinStamp, PlanStampOutcome, WireBlockIn,
};
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use phases::expected_bits_extending;
#[doc(hidden)]
pub use phases::post_commit;
use phases::{assemble_run, Assembled};
#[cfg(debug_assertions)]
#[doc(hidden)]
pub use pin::ensure_spend_abs_layouts;
#[doc(hidden)]
pub use pin::{collect_spend_abs_after_fill, pin_for_wire_batch};
pub use scripts::{confirm_scripts_phase, drive_script_waves_with, Inflight};
pub use write::finish_post_commit;
pub use write::{
    confirm_write_phase, confirm_write_phase_or_return, finish_post_commit_hashes,
    replay_spend_annotations,
};
#[doc(hidden)]
pub use write::{
    fill_planned_create_layout_after_commit, write_batch_vs_tip, write_height_needed,
    WriteBatchVsTip,
};
/// One height resolved for the confirm wave (header + Class A body fks).
#[doc(hidden)]
pub struct BodyMeta {
    pub height: Height,
    pub hash: [u8; 32],
    pub header_fk: rbitcoin_primitives::Fk,
    pub header_rec: rbitcoin_store::HeaderRecord,
    pub tx_fks: Vec<rbitcoin_primitives::Fk>,
    /// Create txids for this block — **exactly one** `compute_txid` per entry
    /// at structure/entry (plan or archived load). Assemble must use these only.
    pub txids: Vec<[u8; 32]>,
    /// Same walk as `txids` (lookup/structure). Script jobs reuse these.
    pub pres: std::sync::Arc<[crate::TxPrecompute]>,
}

/// Assemble output for one height (held through scripts → write).
#[doc(hidden)]
pub struct Prepared {
    pub height: Height,
    pub header_fk: rbitcoin_primitives::Fk,
    pub tx_fks: Vec<rbitcoin_primitives::Fk>,
    pub jobs: Vec<ScriptCheckJob>,
    /// `(prev_txid, vout, spending_tx_fk, create_tx_fk, vin)`.
    pub spends: Vec<(
        [u8; 32],
        u32,
        rbitcoin_primitives::Fk,
        rbitcoin_primitives::Fk,
        u32,
    )>,
    /// Total fees from assemble (for structural coinbase subsidy check).
    pub fees: i64,
    pub check_scripts: bool,
    pub time: u32,
    pub bits: bitcoin::CompactTarget,
    /// Header hash of this block (prev-link for the next height in the run).
    pub hash: [u8; 32],
    /// Create txids from structure. BIP30 looks these up and does not hash again.
    pub txids: Vec<[u8; 32]>,
    /// Prev-block MTP from assemble (`mtp_at(height-1)`). Write BIP68 uses this
    /// instead of `ConfirmParentCache::get_header_plan`.
    pub prev_mtp: u32,
}

/// Txids already consensus-script-verified under tip-era softforks (live mempool
/// after accept). Empty = verify all jobs (IBD). Passed through load → scripts only.
pub type ScriptPreverified = std::collections::HashSet<[u8; 32]>;

/// Pipeline context so lookup(N+1) can run while write(N) has not advanced tip.
///
/// Load thread owns reserved create-fk HWM and the in-flight map from
/// batches sitting in load→scripts→write queues. Write remains sole Class A
/// appender and applies batches in height order.
#[derive(Clone, Debug)]
pub struct WireLoadPipeline<'a> {
    /// Expected first height of this batch (store tip+1, or last loaded + 1).
    pub path_lo: u32,
    /// Parent of `path_lo` when ahead of store tip (last wire hash of prior loaded batch).
    pub parent_hash: Option<[u8; 32]>,
    /// Inclusive create-fk start for [`Query::archive_plan_batch_from_wire`].
    pub next_tx_start: u64,
    /// Prior uncommitted packs (load-thread map; stamp/pin borrow).
    pub in_flight: &'a crate::InFlight,
    /// Lookup-filled parent identity for this load batch (IBD skeleton).
    pub skeleton: Option<crate::BatchParentIds>,
    /// External prev_txids from the BQ input walk (IBD skeleton stamp; no second wire collect).
    pub carried_need: Vec<[u8; 32]>,
    /// BQ `header_fk` per block (empty = stamp ensure/put). Length matches `carried_header_hashes`.
    /// Ensure skip requires the stored header at this fk to match the wire hash.
    pub carried_header_fks: Vec<rbitcoin_primitives::Fk>,
    /// BQ header hashes aligned with [`Self::carried_header_fks`].
    pub carried_header_hashes: Vec<[u8; 32]>,
}

/// Wire + assemble complete; script jobs still attached (not yet verified).
///
/// `Send` so IBD can hand off load → scripts threads.
/// Sparse spent-filtered parents ride on the batch (not tip-GCed).
/// When `archive_plan` is `Some`, commit stage appends Class A before
/// structural / annotate (single ordered commit era).
pub struct LoadedBatch {
    pub prepared: Vec<Prepared>,
    /// Shared wire (Arc) so load→scripts→write does not deep-clone full blocks.
    pub wire_blocks: Vec<Arc<Block>>,
    /// Per-batch pin map: load → assemble → write structural, then drop.
    pub batch_parents: crate::BatchParents,
    /// Mempool preverified txids for scripts stage (tip follow); empty on IBD.
    pub script_preverified: ScriptPreverified,
    /// Planned Class A write from wire lookup/load (committed in write stage).
    pub archive_plan: Option<crate::ArchiveWritePlan>,
    /// Indexes to assemble. Copied from `index_live` at load.
    pub index_want: index::IndexWant,
    pub stats: Arc<crate::ConfirmStats>,
    /// Waive bit from [`confirm_waive`] at load. The script wave keeps every
    /// warn-and-apply fault only when this is set. Flag-off stays false.
    pub trust_peer: bool,
    /// Lookup and load warns. [`ScriptOkBatch::trust_script_warns`] carries
    /// them to the write.
    pub trust_warns: Vec<(u32, rbitcoin_consensus::ConsensusError)>,
    /// The bodies' decoded-heap charges ([`crate::ResolvedWire::heap`]),
    /// held until the write drops the batch so the script and write queues
    /// are metered.
    pub holds: Vec<Arc<crate::process_mem_stats::HeapCharge>>,
}

/// Script-verified batch ready for ordered commit (Class A + structural + C).
///
/// `Send` so IBD can hand off scripts → write.
pub struct ScriptOkBatch {
    pub prepared: Vec<Prepared>,
    pub wire_blocks: Vec<Arc<Block>>,
    pub batch_parents: crate::BatchParents,
    pub archive_plan: Option<crate::ArchiveWritePlan>,
    /// Filter bytes and tweak vecs for this batch. Empty when the indexes are off.
    pub index_seal: index::IndexSeal,
    /// Warns held until this batch connects. Logged only after the write succeeds.
    pub trust_script_warns: Vec<(u32, rbitcoin_consensus::ConsensusError)>,
    /// [`LoadedBatch::holds`], given back when the write drops the batch.
    pub holds: Vec<Arc<crate::process_mem_stats::HeapCharge>>,
}

/// One item on the confirm-write channel.
///
/// [`ConfirmWriteMsg::ClearArchived`] is the archived-body clear. The write
/// thread joins the in-flight tip flush, then clears. IBD orchestration does
/// not store that image.
///
/// `Batch` stays unboxed: this channel already moved the batch by value.
#[allow(clippy::large_enum_variant)]
pub enum ConfirmWriteMsg {
    Batch(ScriptOkBatch),
    ClearArchived {
        hash: [u8; 32],
        reply: std::sync::mpsc::Sender<Result<bool, rbitcoin_store::StoreError>>,
    },
}

/// Outcome of load: batch ready for scripts + pure work wall.
pub struct ConfirmLoadOutcome {
    pub batch: LoadedBatch,
    /// Full load wall (Class A + parent pin + resolve → assemble).
    pub work_ns: u64,
}

/// Outcome of the scripts stage: ready batch + pure script wall.
pub struct ConfirmScriptOutcome {
    pub batch: ScriptOkBatch,
    /// Script-wave completion offset from batch start.
    pub work_ns: u64,
    /// Index-wave completion offset from the same batch start. Zero when the
    /// batch has no index jobs. Not [`Self::idx_asm_ns`].
    pub index_done_ns: u64,
    /// Filter and tweak execution only: first index job start through index-wave
    /// completion. Not time spent queued behind the script wave.
    pub idx_asm_ns: u64,
}

/// LOAD STAGE from **raw wire blocks** (unified height-ordered pipeline).
///
/// One-shot path (tests / tip-follow) runs lookup+load together:
/// - Structure / PoW checks, ensure headers
/// - Stamp Class A create fks **without** committing
/// - Pin external parents once (denserels); same-batch from plan
/// - Assemble using **intake wire** (no Class-A wire rebuild)
///
/// The plan rides on [`LoadedBatch::archive_plan`] and is committed in write.
///
/// `pipeline`: when `Some`, first height may be ahead of store tip (lookup(N+1)
/// while write(N) in flight). Use reserved create-fk HWM + in-flight creates.
pub fn confirm_wire_load_phase(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[(Height, Block)],
    preverified: &ScriptPreverified,
) -> Result<ConfirmLoadOutcome, ConfirmError> {
    confirm_wire_load_phase_pipelined(query, params, milestone, blocks, preverified, None)
}

#[doc(hidden)]
pub fn wire_blocks_to_arcs(query: &Query, blocks: &[(Height, Block)]) -> Vec<WireBlockIn> {
    let t = Instant::now();
    let arcs = blocks
        .iter()
        .map(|(h, b)| {
            let pres = query.block_queue_resolved(h.0).map(|w| Arc::clone(&w.pres));
            (*h, Arc::new(b.clone()), pres)
        })
        .collect();
    let ns = t.elapsed().as_nanos() as u64;
    if ns > 0 {
        crate::note_confirm(&query.confirm_stats().phase_prep_wire_arc_ns, ns);
    }
    arcs
}

/// Like [`confirm_wire_load_phase`] with optional pipeline caches for load-ahead.
///
/// One-shot load is stamp + [`confirm_wire_load_from_plan`] (same as IBD after
/// BQ TipOnly). `Arc` conversion is timed as `PREP_WIRE_ARC_NS`.
pub fn confirm_wire_load_phase_pipelined(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[(Height, Block)],
    preverified: &ScriptPreverified,
    pipeline: Option<&WireLoadPipeline>,
) -> Result<ConfirmLoadOutcome, ConfirmError> {
    rbitcoin_consensus::block::reject_confirm_batch(
        &blocks.iter().map(|(h, _)| h.0).collect::<Vec<_>>(),
    )?;
    let arcs = wire_blocks_to_arcs(query, blocks);
    let stamped = confirm_wire_lookup_stamp(query, params, milestone, &arcs, pipeline)?;
    confirm_wire_load_from_plan(query, params, milestone, stamped, pipeline, preverified)
}

/// Unified wire → tip (lookup+load + scripts + write). Primary production entry.
pub fn confirm_wire_run(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[(Height, Block)],
) -> Result<Vec<rbitcoin_primitives::Fk>, ConfirmError> {
    let arcs: Vec<WireBlockIn> = blocks
        .iter()
        .map(|(h, b)| (*h, Arc::new(b.clone()), None))
        .collect();
    confirm_wire_run_preverified(query, params, milestone, &arcs, &ScriptPreverified::new())
}

/// Like [`confirm_wire_run`] with mempool script preverified set.
///
/// **Tip-follow / one-shot:** lookup stamp (create_fk + parent body ranges;
/// never `tx.body`) → load pin denserels by range → scripts → write.
///
/// Parent create_fk + body_range + identity are **lookup promises**. Load only
/// reads `tx.body` denserels. Soft spentness recovery for wrong pin identity
/// is not a substitute for a correct lookup/load.
pub fn confirm_wire_run_preverified(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    blocks: &[WireBlockIn],
    preverified: &ScriptPreverified,
) -> Result<Vec<rbitcoin_primitives::Fk>, ConfirmError> {
    rbitcoin_consensus::block::reject_empty_confirm_batch(blocks.is_empty())?;
    let trust = confirm_waive(query);
    let guard = trust.then(rbitcoin_consensus::TrustCollect::enter);
    let result = (|| {
        let stamped = confirm_wire_lookup_stamp(query, params, milestone, blocks, None)?;
        let mat =
            confirm_wire_load_from_plan(query, params, milestone, stamped, None, preverified)?;
        // Tip path: hold the index wave until scripts pass, so a rejected
        // block never spends index work.
        let inf = Inflight::start_deferred_index(mat.batch, 0).map_err(|(e, _)| e)?;
        let (ok, _) = inf.finish()?;
        confirm_write_phase(query, params, milestone, ok.batch)
    })();
    // Flag-off never drains: that allocates on the valid-block path.
    if trust {
        let warns = rbitcoin_consensus::drain_warnings();
        let stop_at = rbitcoin_consensus::current_block_height();
        drop(guard);
        log_trust_block_faults(blocks, &warns, result.as_ref().err(), stop_at);
    }
    result
}

/// Two equal-work tip candidates, scripted together: the first to pass strict
/// scripts and commit is the tip; the other is reported as the loser.
pub struct PairRun {
    /// Index of the candidate that won (0 = first argument).
    pub winner: usize,
    pub fks: Vec<rbitcoin_primitives::Fk>,
    /// Hash of the candidate that did not win.
    pub loser: [u8; 32],
    /// The loser's failure when it failed rather than losing the race.
    pub loser_error: Option<ConfirmError>,
}

/// The pair failed. `error`/`hash` is the preferred candidate's failure, or a
/// local fault that must surface. `other` is the sibling's failure when it
/// also failed, so the caller can mark it separately.
pub struct PairFailure {
    pub error: ConfirmError,
    pub hash: [u8; 32],
    pub other: Option<(ConfirmError, [u8; 32])>,
}

fn ordered_failure(
    win_idx: usize,
    win: (ConfirmError, [u8; 32]),
    lose: (ConfirmError, [u8; 32]),
) -> Box<PairFailure> {
    Box::new(if win_idx == 0 {
        PairFailure {
            error: win.0,
            hash: win.1,
            other: Some(lose),
        }
    } else {
        PairFailure {
            error: lose.0,
            hash: lose.1,
            other: Some(win),
        }
    })
}

fn preferred_failure(
    a: (ConfirmError, [u8; 32]),
    b: Option<(ConfirmError, [u8; 32])>,
) -> Box<PairFailure> {
    Box::new(PairFailure {
        error: a.0,
        hash: a.1,
        other: b,
    })
}

/// Puts a withdrawn loser back in the pool if the winner's write unwinds
/// before the loser is cancelled or republished.
struct RePublishLoser<'a>(&'a Arc<rbitcoin_consensus::script_pool::Wave>);

impl Drop for RePublishLoser<'_> {
    fn drop(&mut self) {
        if !self.0.failed.load(std::sync::atomic::Ordering::Acquire) {
            rbitcoin_consensus::script_pool::publish_wave(self.0);
        }
    }
}

fn pair_load(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    block: &WireBlockIn,
    pre: &ScriptPreverified,
) -> Result<LoadedBatch, ConfirmError> {
    let stamped = lookup::confirm_wire_lookup_stamp_no_plan(
        query,
        params,
        milestone,
        std::slice::from_ref(block),
        None,
    )?;
    Ok(confirm_wire_load_from_plan(query, params, milestone, stamped, None, pre)?.batch)
}

/// Finish scripts, publish the deferred index wave, clear the pair's
/// parent-cache slot, and write. The loser is unpublished before this call,
/// so the index wave is the only tip wave in the pool. `phase` is the hub's
/// script flag: readers stop skipping the RPC wait once the write starts.
#[allow(clippy::too_many_arguments)]
fn pair_write_started(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    height: u32,
    inf: Inflight,
    phase: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Vec<rbitcoin_primitives::Fk>, ConfirmError> {
    let mut inf = inf.finish_scripts()?;
    inf.start_index()?;
    let (ok, _) = inf.finish_index()?;
    // Neither candidate may be left as this height's parent plan: the store
    // has the winner after the write, and `assemble_parent_mtp_and_bits`
    // reads the cache before the store.
    query.confirm_parent_cache().clear_height(height);
    if let Some(flag) = phase {
        flag.store(false, std::sync::atomic::Ordering::Release);
    }
    confirm_write_phase(query, params, milestone, ok.batch)
}

fn note_pair_loser(run: PairRun) -> PairRun {
    if let Some(e) = &run.loser_error {
        rbitcoin_log::debug!(
            Query,
            "tip pair: {} lost: {e}",
            bitcoin::BlockHash::from_byte_array(run.loser)
        );
    }
    run
}

#[allow(clippy::too_many_arguments)]
fn run_pair_loads(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    a_in: &WireBlockIn,
    a_pre: &ScriptPreverified,
    b_in: &WireBlockIn,
    b_pre: &ScriptPreverified,
    a: LoadedBatch,
    b: LoadedBatch,
    phase: Option<&std::sync::atomic::AtomicBool>,
) -> Result<PairRun, Box<PairFailure>> {
    use rbitcoin_consensus::script_pool::{link_pair, unlink_pair};
    let height = a.prepared.first().map(|p| p.height.0).unwrap_or(0);
    let hash_a = a.prepared.first().map(|p| p.hash).unwrap_or([0; 32]);
    let hash_b = b.prepared.first().map(|p| p.hash).unwrap_or([0; 32]);
    // A start can fail without a wave: a batch with exactly one script job
    // runs it inline. Handle that per candidate, never as the pair's error.
    let started_a = Inflight::start_deferred_index_held(a, 0);
    let started_b = Inflight::start_deferred_index_held(b, 0);
    let (a, b) = match (started_a, started_b) {
        (Ok(a), Ok(b)) => (a, b),
        (Ok(a), Err((e, _))) => {
            a.publish_scripts();
            return match pair_write_started(query, params, milestone, height, a, phase) {
                Ok(fks) => Ok(note_pair_loser(PairRun {
                    winner: 0,
                    fks,
                    loser: hash_b,
                    loser_error: Some(e),
                })),
                Err(ea) => Err(preferred_failure((ea, hash_a), Some((e, hash_b)))),
            };
        }
        (Err((e, _)), Ok(b)) => {
            b.publish_scripts();
            return match pair_write_started(query, params, milestone, height, b, phase) {
                Ok(fks) => Ok(note_pair_loser(PairRun {
                    winner: 1,
                    fks,
                    loser: hash_a,
                    loser_error: Some(e),
                })),
                Err(eb) => Err(preferred_failure((e, hash_a), Some((eb, hash_b)))),
            };
        }
        (Err((ea, _)), Err((eb, _))) => {
            return Err(preferred_failure((ea, hash_a), Some((eb, hash_b))));
        }
    };
    let (wa, wb) = (a.script_wave_arc(), b.script_wave_arc());
    let paired = match (&wa, &wb) {
        (Some(x), Some(y)) => {
            link_pair(x, y);
            true
        }
        _ => false,
    };
    // Publish only after the link: a wave woken before `pair` is set would
    // take a full pool of chunks.
    a.publish_scripts();
    b.publish_scripts();
    // First strict script verdict wins. Both ready prefers `a`. The pool
    // unparks a registered publisher when a wave completes; register this
    // thread so the wait is event-driven, not a poll.
    struct PairPublisher;
    impl Drop for PairPublisher {
        fn drop(&mut self) {
            rbitcoin_consensus::script_pool::set_script_publisher(None);
        }
    }
    rbitcoin_consensus::script_pool::set_script_publisher(Some(std::thread::current()));
    let _publisher = PairPublisher;
    let first = loop {
        if a.script_is_complete() {
            break 0usize;
        }
        if b.script_is_complete() {
            break 1usize;
        }
        std::thread::park();
    };
    if paired {
        if let (Some(x), Some(y)) = (&wa, &wb) {
            unlink_pair(x, y);
        }
    }
    let (win, lose, win_idx) = if first == 0 { (a, b, 0) } else { (b, a, 1) };
    let (win_hash, lose_hash) = if win_idx == 0 {
        (hash_a, hash_b)
    } else {
        (hash_b, hash_a)
    };
    let (lose_in, lose_pre) = if win_idx == 0 {
        (b_in, b_pre)
    } else {
        (a_in, a_pre)
    };
    let lose_wave = lose.script_wave_arc();
    match win.finish_scripts() {
        Ok(win) => {
            // Stop the loser from claiming through the winner's index and
            // write without cancelling the verdicts a promotion may reuse.
            // The guard re-publishes it on a panic before `cancel_scripts`.
            let _republish = lose_wave.as_ref().map(|w| {
                rbitcoin_consensus::script_pool::unpublish_fg(w);
                RePublishLoser(w)
            });
            match pair_write_started(query, params, milestone, height, win, phase) {
                Ok(fks) => {
                    lose.cancel_scripts();
                    Ok(note_pair_loser(PairRun {
                        winner: win_idx,
                        fks,
                        loser: lose_hash,
                        loser_error: None,
                    }))
                }
                Err(e) => {
                    // The winner may have appended Class A, so the loser's
                    // plan base moved. Keep the verdicts that already ran and
                    // re-stamp with them skipped. Re-publish the loser first:
                    // it was withheld from the pool for the winner's write,
                    // so its remaining chunks can never be claimed otherwise.
                    if let Some(w) = &lose_wave {
                        rbitcoin_consensus::script_pool::publish_wave(w);
                    }
                    if let Some(flag) = phase {
                        flag.store(true, std::sync::atomic::Ordering::Release);
                    }
                    let promoted = (|| {
                        let pre = match lose.finish_scripts() {
                            Ok(lose) => {
                                let mut pre = lose_pre.clone();
                                if !lose.batch.trust_peer {
                                    for p in &lose.batch.prepared {
                                        pre.extend(p.txids.iter().copied());
                                    }
                                }
                                pre
                            }
                            Err(e2) => return Err(e2),
                        };
                        let re = pair_load(query, params, milestone, lose_in, &pre)?;
                        let inf = Inflight::start_deferred_index(re, 0).map_err(|(e2, _)| e2)?;
                        pair_write_started(query, params, milestone, height, inf, phase)
                    })();
                    match promoted {
                        Ok(fks) => Ok(note_pair_loser(PairRun {
                            winner: 1 - win_idx,
                            fks,
                            loser: win_hash,
                            loser_error: Some(e),
                        })),
                        Err(e2) => Err(ordered_failure(win_idx, (e, win_hash), (e2, lose_hash))),
                    }
                }
            }
        }
        Err(e) => match pair_write_started(query, params, milestone, height, lose, phase) {
            Ok(fks) => Ok(note_pair_loser(PairRun {
                winner: 1 - win_idx,
                fks,
                loser: win_hash,
                loser_error: Some(e),
            })),
            Err(e2) => Err(ordered_failure(win_idx, (e, win_hash), (e2, lose_hash))),
        },
    }
}

/// Lookup, load, script, and write two equal-work candidates. Both script
/// waves are published together and capped at half the pool while the other
/// still claims. The first to pass strict scripts and commit is the tip.
#[allow(clippy::too_many_arguments)]
pub fn confirm_wire_run_pair_preverified(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    a: &WireBlockIn,
    a_pre: &ScriptPreverified,
    b: &WireBlockIn,
    b_pre: &ScriptPreverified,
    phase: Option<&std::sync::atomic::AtomicBool>,
) -> Result<PairRun, Box<PairFailure>> {
    let hash_a = a.1.block_hash().to_byte_array();
    let hash_b = b.1.block_hash().to_byte_array();
    let trust = confirm_waive(query);
    let guard = trust.then(rbitcoin_consensus::TrustCollect::enter);
    let result = (|| {
        let la = pair_load(query, params, milestone, a, a_pre);
        let lb = pair_load(query, params, milestone, b, b_pre);
        match (la, lb) {
            (Ok(x), Ok(y)) => {
                run_pair_loads(query, params, milestone, a, a_pre, b, b_pre, x, y, phase)
            }
            (Ok(x), Err(e)) => {
                let height = x.prepared.first().map(|p| p.height.0).unwrap_or(0);
                let inf = match Inflight::start_deferred_index(x, 0) {
                    Ok(inf) => inf,
                    Err((e2, _)) => return Err(preferred_failure((e2, hash_a), Some((e, hash_b)))),
                };
                match pair_write_started(query, params, milestone, height, inf, phase) {
                    Ok(fks) => {
                        let run = PairRun {
                            winner: 0,
                            fks,
                            loser: hash_b,
                            loser_error: Some(e),
                        };
                        Ok(note_pair_loser(run))
                    }
                    Err(ea) => Err(preferred_failure((ea, hash_a), Some((e, hash_b)))),
                }
            }
            (Err(e), Ok(y)) => {
                let height = y.prepared.first().map(|p| p.height.0).unwrap_or(0);
                let inf = match Inflight::start_deferred_index(y, 0) {
                    Ok(inf) => inf,
                    Err((e2, _)) => return Err(preferred_failure((e, hash_a), Some((e2, hash_b)))),
                };
                match pair_write_started(query, params, milestone, height, inf, phase) {
                    Ok(fks) => {
                        let run = PairRun {
                            winner: 1,
                            fks,
                            loser: hash_a,
                            loser_error: Some(e),
                        };
                        Ok(note_pair_loser(run))
                    }
                    Err(eb) => Err(preferred_failure((e, hash_a), Some((eb, hash_b)))),
                }
            }
            (Err(ea), Err(eb)) => Err(preferred_failure((ea, hash_a), Some((eb, hash_b)))),
        }
    })();
    if trust {
        let warns = rbitcoin_consensus::drain_warnings();
        let stop_at = rbitcoin_consensus::current_block_height();
        drop(guard);
        let blocks = [a.clone(), b.clone()];
        log_trust_block_faults(
            &blocks,
            &warns,
            result.as_ref().err().map(|f| &f.error),
            stop_at,
        );
    }
    result
}

thread_local! {
    /// This thread opted into warn-and-apply for the batch it is confirming.
    /// Default is off. [`Query::trust_peer`] does not set it.
    static WAIVE: Cell<bool> = const { Cell::new(false) };
}
/// Waiver for this confirm. One cell read. The mode bit is not consulted.
pub fn confirm_waive(_query: &Query) -> bool {
    WAIVE.with(|c| c.get())
}

/// Set the waive bit for `f` on this thread, then restore the previous value.
/// A panic inside `f` restores the bit too, so the next caller on this thread
/// is not waived just because a connect aborted.
pub fn with_confirm_waive<R>(waive: bool, f: impl FnOnce() -> R) -> R {
    let prev = WAIVE.with(|c| c.replace(waive));
    let _restore = WaiveRestore(prev);
    f()
}

/// Set the cell for `body` only when `waive` is true. False does not write it,
/// so a flag-off confirm does not touch the cell.
pub fn waive_batch<R>(waive: bool, body: impl FnOnce() -> R) -> R {
    if waive {
        with_confirm_waive(true, body)
    } else {
        body()
    }
}

struct WaiveRestore(bool);

impl Drop for WaiveRestore {
    fn drop(&mut self) {
        WAIVE.with(|c| c.set(self.0));
    }
}

/// Collector owned by one confirm stage. Nested calls (the unified wire run
/// already entered) leave this empty so the outer drain logs once.
struct TrustScope {
    guard: Option<rbitcoin_consensus::TrustCollect>,
}

impl TrustScope {
    fn enter(query: &Query) -> Self {
        let guard = (confirm_waive(query) && !rbitcoin_consensus::collecting())
            .then(rbitcoin_consensus::TrustCollect::enter);
        Self { guard }
    }

    /// On `Ok`, return the warns and do not log. The write logs them after
    /// connect. On `Err`, log `not applied` and return nothing.
    ///
    /// `log_applied` is the write stage, which has no later handoff. A scope
    /// that did not enter does not drain, so an outer collector still logs once.
    fn finish(
        self,
        ids: &[(u32, [u8; 32])],
        stopped: Option<&ConfirmError>,
        log_applied: bool,
    ) -> Vec<(u32, rbitcoin_consensus::ConsensusError)> {
        if self.guard.is_none() {
            return Vec::new();
        }
        let warns = rbitcoin_consensus::drain_warnings();
        let stop_at = rbitcoin_consensus::current_block_height();
        drop(self.guard);
        if stopped.is_some() || log_applied {
            log_trust_ids(ids, &warns, stopped, stop_at);
            return Vec::new();
        }
        let fallback = ids.first().map(|(h, _)| *h);
        warns
            .into_iter()
            .map(|(h, err)| (h.or(fallback).unwrap_or(0), err))
            .collect()
    }
}

pub(crate) fn trust_ids_from_wire(blocks: &[WireBlockIn]) -> Vec<(u32, [u8; 32])> {
    blocks
        .iter()
        .map(|(h, b, _)| (h.0, b.block_hash().to_byte_array()))
        .collect()
}

fn log_trust_block_faults(
    blocks: &[WireBlockIn],
    warns: &[(Option<u32>, rbitcoin_consensus::ConsensusError)],
    stopped: Option<&ConfirmError>,
    stop_at: Option<u32>,
) {
    log_trust_ids(&trust_ids_from_wire(blocks), warns, stopped, stop_at);
}

fn log_trust_ids(
    blocks: &[(u32, [u8; 32])],
    warns: &[(Option<u32>, rbitcoin_consensus::ConsensusError)],
    stopped: Option<&ConfirmError>,
    stop_at: Option<u32>,
) {
    let applied = stopped.is_none();
    let fallback = blocks.first().copied();
    let hash_at = |height: u32| -> Option<[u8; 32]> {
        blocks
            .iter()
            .find(|(h, _)| *h == height)
            .map(|(_, hash)| *hash)
    };
    for (height, err) in warns {
        let (h, hash) = match (height, fallback) {
            (Some(h), _) => (
                *h,
                hash_at(*h)
                    .or_else(|| fallback.map(|(_, hash)| hash))
                    .unwrap_or([0; 32]),
            ),
            (None, Some((h, hash))) => (h, hash),
            (None, None) => (0, [0; 32]),
        };
        warn_trust_block(applied, hash, h, err);
    }
    if let Some(ConfirmError::Rules(err)) = stopped {
        let hinted = stop_at.and_then(|h| hash_at(h).map(|hash| (h, hash)));
        let (h, hash) = hinted.or(fallback).unwrap_or((0, [0; 32]));
        warn_trust_block(false, hash, h, err);
    }
}

/// Drain the collector and log one line per fault. Caller drops the guard
/// after this returns so a nested check does not see a stale depth.
pub fn log_collected_header(
    hash: [u8; 32],
    height: u32,
    applied: bool,
    stopped: Option<&rbitcoin_consensus::ConsensusError>,
) {
    let warns = rbitcoin_consensus::drain_warnings();
    for (h, err) in warns {
        warn_trust_block(applied, hash, h.unwrap_or(height), &err);
    }
    if let Some(err) = stopped {
        warn_trust_block(false, hash, height, err);
    }
}

pub fn warn_trust_block(
    applied: bool,
    hash: [u8; 32],
    height: u32,
    err: &rbitcoin_consensus::ConsensusError,
) {
    warn_trust_reason(
        applied,
        hash,
        height,
        &rbitcoin_consensus::block_reject_reason(err),
    );
}

pub fn warn_trust_reason(applied: bool, hash: [u8; 32], height: u32, reason: &str) {
    // Header store and the header walk both check one header. Keep one line
    // per verb: a later apply must not be hidden by an earlier reject.
    if !trust_log_fresh(applied, hash, height, reason) {
        return;
    }
    let verb = if applied { "applied" } else { "not applied" };
    let hash = bitcoin::BlockHash::from_byte_array(hash);
    rbitcoin_log::warn!("trust-peer: {verb} block {hash} height {height}: {reason}");
}

fn trust_log_fresh(applied: bool, hash: [u8; 32], height: u32, reason: &str) -> bool {
    use std::cell::RefCell;
    const CAP: usize = 64;
    type Seen = ([u8; 32], u32, bool, String);
    thread_local! {
        static SEEN: RefCell<Vec<Seen>> = const { RefCell::new(Vec::new()) };
    }
    SEEN.with(|seen| {
        let mut seen = seen.borrow_mut();
        if seen
            .iter()
            .any(|(h, y, verb, r)| *h == hash && *y == height && *verb == applied && r == reason)
        {
            return false;
        }
        if seen.len() == CAP {
            seen.drain(..CAP / 2);
        }
        seen.push((hash, height, applied, reason.to_string()));
        true
    })
}

impl LoadedBatch {
    /// Heights and header hashes in this batch (for events / feed scrub).
    pub fn heights_hashes(&self) -> Vec<(u32, [u8; 32])> {
        self.prepared.iter().map(|p| (p.height.0, p.hash)).collect()
    }

    pub fn len(&self) -> usize {
        self.prepared.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prepared.is_empty()
    }

    /// Approx wire bytes retained in `wire_blocks` (for queue-content size logs).
    pub fn approx_wire_bytes(&self) -> usize {
        self.wire_blocks.iter().map(|b| b.total_size()).sum()
    }

    /// Parent handles in this batch (may share payloads with other batches).
    pub fn parent_count(&self) -> usize {
        self.batch_parents.len()
    }
}

impl ScriptOkBatch {
    /// Heights and header hashes in this batch (for events / feed scrub).
    pub fn heights_hashes(&self) -> Vec<(u32, [u8; 32])> {
        self.prepared.iter().map(|p| (p.height.0, p.hash)).collect()
    }

    pub fn len(&self) -> usize {
        self.prepared.len()
    }

    pub fn is_empty(&self) -> bool {
        self.prepared.is_empty()
    }

    /// Approx wire bytes retained in `wire_blocks` (for queue-content size logs).
    pub fn approx_wire_bytes(&self) -> usize {
        self.wire_blocks.iter().map(|b| b.total_size()).sum()
    }

    /// Parent handles in this batch (may share Arc payloads with other batches).
    pub fn parent_count(&self) -> usize {
        self.batch_parents.len()
    }

    /// Wire blocks in the same order as [`Self::heights_hashes`].
    pub fn wire_blocks(&self) -> &[Arc<Block>] {
        &self.wire_blocks
    }

    /// Wire headers in the same order as [`Self::heights_hashes`].
    pub fn wire_headers(&self) -> Result<Vec<bitcoin::block::Header>, ConfirmError> {
        if self.wire_blocks.len() != self.prepared.len() {
            return Err(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
                "invariant: wire headers length",
            )));
        }
        Ok(self.wire_blocks.iter().map(|b| b.header).collect())
    }

    #[allow(clippy::result_large_err)] // public error enum
    /// Absorb another script-ok batch for write batch (FIFO drain).
    ///
    /// Scripts enqueue height-ordered tip extensions; write drains the channel
    /// and merges so Class A + Class C + annotate run once (fewer tip fsyncs).
    /// Returns `Err(other)` if not a contiguous height extension **or** if
    /// `archive_plan` polarity differs (`Some` vs `None`). Caller writes the
    /// prefix then keeps `other` for the next meta-batch.
    pub fn append_contiguous(&mut self, mut other: Self) -> Result<(), Self> {
        if other.is_empty() {
            return Ok(());
        }
        if self.is_empty() {
            *self = other;
            return Ok(());
        }
        let last_h = self.prepared[self.prepared.len() - 1].height.0;
        let first_h = other.prepared[0].height.0;
        if first_h != last_h.saturating_add(1) {
            return Err(other);
        }
        if self.prepared.len() != self.wire_blocks.len()
            || other.prepared.len() != other.wire_blocks.len()
        {
            return Err(other);
        }
        if self.archive_plan.is_some() != other.archive_plan.is_some() {
            return Err(other);
        }
        let self_f = !self.index_seal.filters.is_empty();
        let other_f = !other.index_seal.filters.is_empty();
        if self_f != other_f {
            return Err(other);
        }
        self.prepared.append(&mut other.prepared);
        self.wire_blocks.append(&mut other.wire_blocks);
        self.holds.append(&mut other.holds);
        self.batch_parents.extend_from(other.batch_parents);
        self.index_seal
            .filters
            .append(&mut other.index_seal.filters);
        self.index_seal.tweaks.append(&mut other.index_seal.tweaks);
        self.trust_script_warns
            .append(&mut other.trust_script_warns);
        if let (Some(dst), Some(src)) = (self.archive_plan.as_mut(), other.archive_plan.take()) {
            dst.append(src);
        }
        Ok(())
    }
}
