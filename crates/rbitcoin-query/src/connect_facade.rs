//! Connect façade. Query loads and writes; consensus decides the block.

use crate::ConfirmError;
use bitcoin::hashes::Hash;
use bitcoin::Block;
use rbitcoin_consensus::block::{validate_block_structure_hashed, ValidationContext};
use rbitcoin_consensus::{ChainParams, Milestone};
use rbitcoin_primitives::Height;
use std::sync::Arc;

use crate::confirm_run;
use crate::connect::ConfirmPrepared;
use crate::{Query, TxPrecompute};
use rbitcoin_store::StoreError;

/// Confirm a contiguous tip-extension run of wire blocks (sync all stages).
///
/// See [`confirm_wire_run`]: lookup → load → scripts → write. IBD uses the split
/// phases for pipeline overlap.
pub use crate::confirm_run::{
    confirm_bq_resolve_wave_capped, confirm_scripts_phase, confirm_wire_load_from_plan,
    confirm_wire_load_phase, confirm_wire_load_phase_pipelined, confirm_wire_lookup_stamp,
    confirm_wire_run, confirm_wire_run_preverified, confirm_write_phase,
    confirm_write_phase_or_return, drive_script_waves_with, finish_post_commit_hashes,
    parent_missing_from_chain, replay_spend_annotations, take_wave_items_for_load, BqResolveWave,
    ConfirmLoadOutcome, ConfirmScriptOutcome, ConfirmWriteMsg, LoadedBatch, PlanStampOutcome,
    ScriptOkBatch, ScriptPreverified, UndrainedCreates, WireBlockIn, WireLoadPipeline,
    BQ_RESOLVE_WAVE_MAX_BLOCKS, BQ_RESOLVE_WAVE_MAX_INPUTS,
};

/// Wake the IBD scripts publisher (`ibd-confirm`) after `scriptq` send or close.
pub use rbitcoin_consensus::unpark_script_publisher;

/// Accept + archive + confirm in one step (genesis / tip extension / tests).
///
/// **Same path as IBD confirm:** structure + header checks, then Class A
/// archive, then [`confirm_wire_run`] (lookup → load pin denserels → scripts →
/// structural → Class C → abs spend annotate). No separate
/// `put_spend_batch_by_create`.
///
/// Idempotent when `height` is already confirmed for this block hash.
/// Full script verify (no mempool skip) — use
/// [`accept_and_connect_block_preverified`] on tip follow with a live mempool.
pub fn accept_and_connect_block(
    query: &Query,
    params: &ChainParams,
    height: Height,
    block: &Block,
    milestone: Milestone,
) -> Result<rbitcoin_primitives::Fk, ConfirmError> {
    accept_and_connect_block_preverified(
        query,
        params,
        height,
        Arc::new(block.clone()),
        milestone,
        &ScriptPreverified::new(),
        None,
    )
}

/// Like [`accept_and_connect_block`], skipping script verify for `preverified`
/// txids (tip follow: live mempool after accept). Reorg disconnect stays outside.
pub fn accept_and_connect_block_preverified(
    query: &Query,
    params: &ChainParams,
    height: Height,
    block: Arc<Block>,
    milestone: Milestone,
    preverified: &ScriptPreverified,
    pres: Option<Arc<[TxPrecompute]>>,
) -> Result<rbitcoin_primitives::Fk, ConfirmError> {
    let hash = block.block_hash().to_byte_array();
    if let Some(h) = query.height_of_hash(&hash).map_err(ConfirmError::from)? {
        if h == height {
            if let Some((fk, _)) = query
                .get_header_by_hash(&hash)
                .map_err(ConfirmError::from)?
            {
                if query.pruned_spill_covers(fk).map_err(ConfirmError::from)? {
                    confirm_run::finish_post_commit(query, height.0, &hash)?;
                    return Ok(fk);
                }
                // Already this tip, but the keep file is gone. The block
                // hash does not cover witness, so check the commitment
                // before this block becomes the kept copy.
                let ctx = ValidationContext::at(params, height, milestone);
                validate_block_structure_hashed(&block, &ctx)?;
                query
                    .note_pruned_archived_seqsigwit(fk, &block)
                    .map_err(ConfirmError::from)?;
                let tx_fks = query
                    .store()
                    .header_txs
                    .get_list(fk)
                    .map_err(ConfirmError::from)?
                    .ok_or(ConfirmError::Store(StoreError::Corrupt(
                        "seqsigwit window miss",
                    )))?;
                query
                    .seal_missing_pruned_spills(&[ConfirmPrepared {
                        height,
                        header_fk: fk,
                        tx_fks,
                        hash,
                    }])
                    .map_err(ConfirmError::from)?;
                confirm_run::finish_post_commit(query, height.0, &hash)?;
                return Ok(fk);
            }
        }
    }

    // Unified height-ordered path: wire → lookup → load (pin+assemble) → scripts →
    // write (Class A + structural + Class C + annotate). No archive-then-reload.
    let fks = confirm_wire_run_preverified(
        query,
        params,
        milestone,
        &[(height, block, pres)],
        preverified,
    )?;
    if let Some(fk) = fks.into_iter().next() {
        return Ok(fk);
    }
    // Write skipped heights ≤ tip (idempotent race). A body we just ran
    // through lookup/load must have a header — missing is an invariant, not
    // a soft NotFound.
    query
        .get_header_by_hash(&hash)
        .map_err(ConfirmError::from)?
        .map(|(fk, _)| fk)
        .ok_or(ConfirmError::Store(rbitcoin_store::StoreError::Corrupt(
            "invariant: confirm write skipped but header missing",
        )))
}

/// Two equal-work tip candidates. Both script waves run together; the first
/// to pass strict scripts and commit is the tip. `height` is `tip + 1` for
/// both. The loser is left to the caller (park or report).
#[allow(clippy::too_many_arguments)]
pub fn accept_and_connect_block_pair_preverified(
    query: &Query,
    params: &ChainParams,
    milestone: Milestone,
    height: Height,
    a: Arc<Block>,
    a_pre: &ScriptPreverified,
    a_pres: Arc<[TxPrecompute]>,
    b: Arc<Block>,
    b_pre: &ScriptPreverified,
    b_pres: Arc<[TxPrecompute]>,
    phase: Option<&std::sync::atomic::AtomicBool>,
) -> Result<confirm_run::PairRun, Box<confirm_run::PairFailure>> {
    let a_in: confirm_run::WireBlockIn = (height, a, Some(a_pres));
    let b_in: confirm_run::WireBlockIn = (height, b, Some(b_pres));
    confirm_run::confirm_wire_run_pair_preverified(
        query, params, milestone, &a_in, a_pre, &b_in, b_pre, phase,
    )
}
