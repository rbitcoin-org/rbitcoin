//! Changes to the live graph, in the order the pool made them.
//!
//! The pool records one [`PoolChange`] per graph insert and per graph
//! remove. Its owner drains them while it still holds the pool for write.
//! Records loaded at open and a compact rebuild are not changes.

use bitcoin::Txid;

/// Why a transaction left the pool. Core's `MemPoolRemovalReason` names,
/// plus `rollback` for a staged change this node took back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalReason {
    /// Older than `-mempoolexpiry`.
    Expiry,
    /// Worst chunk dropped for a slot or the weight budget.
    SizeLimit,
    /// No longer valid at the new tip after a disconnect.
    Reorg,
    /// Mined in a connected block.
    Block,
    /// Spends an outpoint a connected block spent.
    Conflict,
    /// A conflicting admit (RBF) took its place.
    Replaced { by: Txid },
    /// A package, a 1p1c pair, or a `testmempoolaccept` dry run took back
    /// what it had admitted, or a replacement that did not commit took this
    /// conflict out. The conflict is added again if it can re-enter.
    Rollback,
}

impl RemovalReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Expiry => "expiry",
            Self::SizeLimit => "sizelimit",
            Self::Reorg => "reorg",
            Self::Block => "block",
            Self::Conflict => "conflict",
            Self::Replaced { .. } => "replaced",
            Self::Rollback => "rollback",
        }
    }
}

/// One graph change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PoolChange {
    /// `weight` is raw. `vsize` is sigop-adjusted, as the mempool RPCs report it.
    Added {
        txid: Txid,
        fee_sat: u64,
        weight: u64,
        vsize: u64,
        time: u64,
    },
    Removed {
        txid: Txid,
        reason: RemovalReason,
    },
}
