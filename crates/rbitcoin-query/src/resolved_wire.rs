//! Lookup-promoted body-queue wire (decoded `Block` + [`TxPrecompute`]).

use crate::process_mem_stats::{HeapCharge, DECODED};
use crate::TxPrecompute;
use bitcoin::Block;
use std::sync::Arc;

/// Heap a decoded block and its precompute rows hold: a struct per
/// transaction, input and output, each script and witness, and one row per
/// transaction (plus the boxed midstates of a script row).
pub fn decoded_heap_bytes(block: &Block, pres: &[TxPrecompute]) -> u64 {
    use bitcoin::{Transaction, TxIn, TxOut};
    use std::mem::size_of;
    let txs: usize = block
        .txdata
        .iter()
        .map(|tx| {
            let ins: usize = tx
                .input
                .iter()
                .map(|i| i.script_sig.len() + i.witness.size())
                .sum();
            let outs: usize = tx.output.iter().map(|o| o.script_pubkey.len()).sum();
            tx.input.capacity() * size_of::<TxIn>()
                + tx.output.capacity() * size_of::<TxOut>()
                + ins
                + outs
        })
        .sum();
    let boxed = pres
        .iter()
        .filter(|p| matches!(p, TxPrecompute::Script(_)))
        .count()
        * size_of::<rbitcoin_consensus::TxScriptPrecompute>();
    (block.txdata.capacity() * size_of::<Transaction>() + txs + std::mem::size_of_val(pres) + boxed)
        as u64
}

/// Decoded body held after lookup drops the raw frame.
#[derive(Clone, Debug)]
pub struct ResolvedWire {
    pub block: Arc<Block>,
    pub pres: Arc<[TxPrecompute]>,
    /// Σ `tx.input.len()` (enqueue CompactSize or decode). Load-split uses this.
    pub n_inputs: u32,
    /// Class A header row from BQ enqueue. Load-split kinds via `has_body(fk)`.
    pub header_fk: u64,
    /// External prev txid of each input from the BQ input walk (no
    /// coinbase). Prevs lookup left out of TipOnly need stay here so load can
    /// in-flight bind them; the TipOnly keys still drop them.
    pub spend_keys: Arc<[[u8; 32]]>,
    /// Peer id given at BQ enqueue ([`crate::Query::block_queue_offer_from`]).
    pub sender: Option<u64>,
    /// [`decoded_heap_bytes`] on [`DECODED`], shared by every clone like the
    /// block and rows are, and given back when the last clone drops.
    pub heap: Arc<HeapCharge>,
}

impl ResolvedWire {
    /// Stamp `n_inputs` from the decoded block (tests / callers without enqueue meta).
    pub fn new(block: Arc<Block>, pres: Arc<[TxPrecompute]>) -> Self {
        let n_inputs = block
            .txdata
            .iter()
            .map(|tx| tx.input.len() as u32)
            .fold(0u32, u32::saturating_add);
        Self::stamped(block, pres, n_inputs, 0, None)
    }

    /// A decoded body with its enqueue stamps, charged on [`DECODED`].
    pub fn stamped(
        block: Arc<Block>,
        pres: Arc<[TxPrecompute]>,
        n_inputs: u32,
        header_fk: u64,
        sender: Option<u64>,
    ) -> Self {
        let heap = Arc::new(HeapCharge::new(&DECODED, decoded_heap_bytes(&block, &pres)));
        Self {
            block,
            pres,
            n_inputs,
            header_fk,
            spend_keys: Arc::from([]),
            sender,
            heap,
        }
    }
}

/// Lookup snapshot of unresolved heights: still-raw vs already promoted.
///
/// `raw` is **(height, n_inputs, header_fk, sender)** — no payload clone. Lookup
/// packs/holds from the stamped count; decode clones via
/// [`crate::Query::block_queue_raw_payload`] only for heights it emits.
#[derive(Clone, Debug, Default)]
pub struct BlockQueueWaveIntake {
    pub raw: Vec<(u32, u32, u64, Option<u64>)>,
    pub resolved: Vec<(u32, ResolvedWire)>,
}
