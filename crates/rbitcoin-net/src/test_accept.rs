//! `testmempoolaccept`: one row per submitted transaction, in submission
//! order. JSON-RPC, Electrum, and Esplora render the same rows.

use std::collections::HashSet;
use std::sync::Arc;

use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid, Wtxid};
use rbitcoin_consensus::policy::fee_exceeds_max;
use rbitcoin_mempool::{ActiveMempool, TestedMembers, MAX_PACKAGE_WEIGHT};
use rbitcoin_query::{Query, QueryError};

use crate::{AcceptError, AcceptResult, MempoolHub};

pub struct TestAcceptRow {
    pub txid: Txid,
    pub wtxid: Wtxid,
    pub verdict: TestAcceptVerdict,
}

pub enum TestAcceptVerdict {
    Allowed {
        fee_sat: u64,
        weight: u64,
        vsize_bip141: u64,
    },
    /// Core `reject-reason` and `reject-details`.
    Rejected {
        reason: String,
        details: Option<String>,
    },
    /// The whole package failed before any member ran. Core omits `allowed`.
    PackageError(&'static str),
}

impl TestAcceptRow {
    fn of(tx: &Transaction, verdict: TestAcceptVerdict) -> Self {
        Self {
            txid: tx.compute_txid(),
            wtxid: tx.compute_wtxid(),
            verdict,
        }
    }

    fn rejected(tx: &Transaction, reason: &str) -> Self {
        Self::of(
            tx,
            TestAcceptVerdict::Rejected {
                reason: reason.to_string(),
                details: None,
            },
        )
    }

    /// Only an allowed member is a parent for a later one. A member over
    /// `maxfeerate` is not, though it passed every other check.
    fn is_allowed(&self) -> bool {
        matches!(self.verdict, TestAcceptVerdict::Allowed { .. })
    }

    fn admitted(tx: &Transaction, r: &AcceptResult, max_feerate_sat_kvb: u64) -> Self {
        if fee_exceeds_max(r.fee_sat, r.weight, max_feerate_sat_kvb) {
            return Self::rejected(tx, "max-fee-exceeded");
        }
        Self::of(
            tx,
            TestAcceptVerdict::Allowed {
                fee_sat: r.fee_sat,
                weight: r.weight,
                vsize_bip141: tx.vsize() as u64,
            },
        )
    }

    fn refused(tx: &Transaction, e: &AcceptError) -> Self {
        Self::of(
            tx,
            TestAcceptVerdict::Rejected {
                reason: accept_reject_reason(e),
                details: accept_reject_details(e, tx),
            },
        )
    }
}

/// API submit admits versions 1, 2, and 3 (BIP 431 TRUC). P2P admits any
/// `nVersion`.
pub fn submit_tx_version_nonstandard(tx: &Transaction) -> bool {
    !(1..=3).contains(&tx.version.0)
}

/// Two members spend the same outpoint.
pub fn package_has_conflicts(txs: &[Transaction]) -> bool {
    let mut spent = HashSet::new();
    for tx in txs {
        for inp in &tx.input {
            if !spent.insert(inp.previous_output) {
                return true;
            }
        }
    }
    false
}

/// Core `reject-reason` text for a mempool reject.
pub fn accept_reject_reason(e: &impl std::fmt::Display) -> String {
    let owned = e.to_string();
    let s = owned.strip_prefix("policy: ").unwrap_or(owned.as_str());
    if s == "coinbase immature" {
        return "bad-txns-premature-spend-of-coinbase".into();
    }
    if s == "coinbase" {
        return "bad-txns-is-coinbase".into();
    }
    if s.starts_with("missing prevout") || s.starts_with("orphaned ") {
        return "missing-inputs".into();
    }
    if s.starts_with("duplicate ") {
        return "txn-already-in-mempool".into();
    }
    if s == "inputs-duplicate" {
        return "bad-txns-inputs-duplicate".into();
    }
    if s == "not final" {
        return "non-final".into();
    }
    if s == "negative fee" {
        return "bad-txns-in-belowout".into();
    }
    if s == "non-BIP68-final" {
        return "non-BIP68-final".into();
    }
    if s == "rbf insufficient fee" {
        return "insufficient fee".into();
    }
    if s == "rbf insufficient fee (including sibling eviction)" {
        return "insufficient fee (including sibling eviction)".into();
    }
    if s == "min relay fee" {
        return "min relay fee not met".into();
    }
    if s == "mempool min fee" {
        return "mempool min fee not met".into();
    }
    if let Some(rest) = s.strip_prefix("script: ") {
        let rest = rest
            .strip_prefix("script verification failed: ")
            .unwrap_or(rest);
        let paren = rbitcoin_consensus::script_flag_paren(rest);
        return format!("mempool-script-verify-flag-failed ({paren})");
    }
    s.to_string()
}

/// Core `reject-details` for mempool rejects.
fn accept_reject_details(e: &impl std::fmt::Display, tx: &Transaction) -> Option<String> {
    let reason = accept_reject_reason(e);
    if matches!(
        reason.as_str(),
        "txn-already-in-mempool"
            | "txn-same-nonwitness-data-in-mempool"
            | "bip125-replacement-disallowed"
    ) {
        return Some(reason);
    }
    if !reason.starts_with("mempool-script-verify-flag-failed") {
        return None;
    }
    let vin = 0usize;
    let inp = tx.input.get(vin)?;
    let prev = inp.previous_output;
    Some(format!(
        "{reason}, input {vin} of {} (wtxid {}), spending {}:{}",
        tx.compute_txid(),
        tx.compute_wtxid(),
        prev.txid,
        prev.vout
    ))
}

fn confirmed_on_active_chain(query: &Query, tx: &Transaction) -> Result<bool, QueryError> {
    let Some(fk) = query.tx_fk_by_txid_tip(&tx.compute_txid().to_byte_array())? else {
        return Ok(false);
    };
    query.store().is_confirmed_strong(fk)
}

fn package_error(txs: &[Transaction], msg: &'static str) -> Vec<TestAcceptRow> {
    txs.iter()
        .map(|tx| TestAcceptRow::of(tx, TestAcceptVerdict::PackageError(msg)))
        .collect()
}

impl MempoolHub {
    /// Core `IsWellFormedPackage`, in Core's order, then the cluster limit.
    /// Every surface caps the count at 25 before the walk.
    fn test_accept_precheck(&self, txs: &[Transaction]) -> Option<Vec<TestAcceptRow>> {
        if txs.len() < 2 {
            return None;
        }
        let weight: u64 = txs.iter().map(|tx| tx.weight().to_wu()).sum();
        let mut ids = HashSet::new();
        let error = if weight > MAX_PACKAGE_WEIGHT {
            "package-too-large"
        } else if txs.iter().any(|tx| !ids.insert(tx.compute_txid())) {
            "package-contains-duplicates"
        } else if !ActiveMempool::package_is_sorted(txs) {
            "package-not-sorted"
        } else if package_has_conflicts(txs) {
            "conflict-in-package"
        } else if self.package_would_exceed_cluster(txs) {
            "too-large-cluster"
        } else {
            return None;
        };
        Some(package_error(txs, error))
    }

    /// Test-accept `txs` without touching the pool, with script verify
    /// awaited on the caller. Two or more are a package: each member that
    /// passes joins [`TestedMembers`], so a later child sees its parent
    /// without the parent entering the pool.
    pub async fn test_accept_rows_async(
        self: &Arc<Self>,
        txs: Vec<Transaction>,
        max_feerate_sat_kvb: u64,
    ) -> Result<Vec<TestAcceptRow>, QueryError> {
        let hub = Arc::clone(self);
        let txs_c = txs.clone();
        if let Some(rows) = crate::reactor::off_pool(move || hub.test_accept_precheck(&txs_c)).await
        {
            return Ok(rows);
        }
        if txs.len() >= 2 {
            return Ok(self
                .test_accept_package_rows_async(txs, max_feerate_sat_kvb)
                .await);
        }
        let mut out = Vec::with_capacity(txs.len());
        for tx in txs {
            let query = Arc::clone(&self.query);
            let tx_c = tx.clone();
            let known =
                crate::reactor::off_pool_budgeted(move || confirmed_on_active_chain(&query, &tx_c))
                    .await?;
            if known {
                out.push(TestAcceptRow::rejected(&tx, "txn-already-known"));
                continue;
            }
            if submit_tx_version_nonstandard(&tx) {
                out.push(TestAcceptRow::rejected(&tx, "version"));
                continue;
            }
            out.push(match self.test_accept_async(tx.clone(), None).await {
                Ok(r) => TestAcceptRow::admitted(&tx, &r, max_feerate_sat_kvb),
                Err(e) => TestAcceptRow::refused(&tx, &e),
            });
        }
        Ok(out)
    }

    async fn test_accept_package_rows_async(
        self: &Arc<Self>,
        txs: Vec<Transaction>,
        max_feerate_sat_kvb: u64,
    ) -> Vec<TestAcceptRow> {
        let mut tested = Arc::new(TestedMembers::default());
        let mut out = Vec::with_capacity(txs.len());
        for tx in txs {
            if submit_tx_version_nonstandard(&tx) {
                out.push(TestAcceptRow::rejected(&tx, "version"));
                continue;
            }
            let outcome = self
                .test_accept_async(tx.clone(), Some(Arc::clone(&tested)))
                .await;
            let row = match outcome {
                Ok(r) => TestAcceptRow::admitted(&tx, &r, max_feerate_sat_kvb),
                Err(e) => TestAcceptRow::refused(&tx, &e),
            };
            if row.is_allowed() {
                Arc::make_mut(&mut tested).push(Arc::new(tx));
            }
            out.push(row);
        }
        out
    }
}
