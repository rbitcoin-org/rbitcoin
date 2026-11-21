//! Instance-owned confirm window meters (IBD `ibd: perf` JSON).
//!
//! [`Query`](crate::Query) owns one [`ConfirmStats`]. Hot path notes through `&self`.
//! Window sample is field-wise take (swap to 0) — not a process-global last-writer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[inline]
pub fn add(a: &AtomicU64, n: u64) {
    if n > 0 {
        a.fetch_add(n, Ordering::Relaxed);
    }
}

#[inline]
pub fn add_dur(a: &AtomicU64, d: Duration) {
    add(a, d.as_nanos() as u64);
}

macro_rules! confirm_window {
    ($($field:ident),+ $(,)?) => {
        #[derive(Debug)]
        pub struct ConfirmStats {
            $(pub $field: AtomicU64,)+
            last_head_need: AtomicU64,
            last_head_hit: AtomicU64,
            last_miss_n: AtomicU64,
            last_miss_pend: AtomicU64,
            last_miss_on: AtomicU64,
            last_miss_cands: AtomicU64,
            last_miss_txid: [AtomicU64; 4],
            leftover_age0: AtomicU64,
            leftover_age3: AtomicU64,
            leftover_age_n: AtomicU64,
        }

        impl Default for ConfirmStats {
            fn default() -> Self {
                Self {
                    $($field: AtomicU64::new(0),)+
                    last_head_need: AtomicU64::new(0),
                    last_head_hit: AtomicU64::new(0),
                    last_miss_n: AtomicU64::new(0),
                    last_miss_pend: AtomicU64::new(0),
                    last_miss_on: AtomicU64::new(0),
                    last_miss_cands: AtomicU64::new(0),
                    last_miss_txid: [
                        AtomicU64::new(0),
                        AtomicU64::new(0),
                        AtomicU64::new(0),
                        AtomicU64::new(0),
                    ],
                    leftover_age0: AtomicU64::new(0),
                    leftover_age3: AtomicU64::new(0),
                    leftover_age_n: AtomicU64::new(0),
                }
            }
        }

        #[derive(Debug, Default, Clone, Copy)]
        pub struct ConfirmWindow {
            $(pub $field: u64,)+
            pub leftover_age_n: u64,
            pub leftover_cdf0_pct: u64,
            pub leftover_cdf3_pct: u64,
        }

        impl ConfirmStats {
            pub fn take_window(&self) -> ConfirmWindow {
                let leftover_age_n = self.leftover_age_n.swap(0, Ordering::Relaxed);
                let a0 = self.leftover_age0.swap(0, Ordering::Relaxed);
                let a3 = self.leftover_age3.swap(0, Ordering::Relaxed);
                let leftover_cdf0_pct = if leftover_age_n == 0 {
                    0
                } else {
                    a0.saturating_mul(100) / leftover_age_n
                };
                let leftover_cdf3_pct = if leftover_age_n == 0 {
                    0
                } else {
                    a3.saturating_mul(100) / leftover_age_n
                };
                ConfirmWindow {
                    $($field: self.$field.swap(0, Ordering::Relaxed),)+
                    leftover_age_n,
                    leftover_cdf0_pct,
                    leftover_cdf3_pct,
                }
            }
        }
    };
}

confirm_window! {
    load_ns,
    script_ns,
    milestone_gate_ns,
    class_a_ns,
    connect_ns,
    script_jobs,
    script_skip_mempool,
    structural_ns,
    structural_spent_ns,
    structural_spent_abs_ns,
    structural_spent_strong_ns,
    structural_spent_cold_ns,
    structural_spent_pending_ns,
    structural_create_h_ns,
    structural_bip68_ns,
    class_c_ns,
    // Live idx assemble + put, and materialize build + commit. `tip: accept bf=` is this sum.
    blockfilter_ns,
    idx_asm_ns,
    idx_put_ns,
    ensure_layout_ns,
    write_class_c_join_ns,
    // Commit wait for the previous IBD batch's tip flush (`rbtc-tip-flush`).
    write_tip_flush_wait_ns,
    write_drain_join_ns,
    write_dequeue_ns,
    write_plan_take_ns,
    write_create_map_ns,
    write_head_sub_ns,
    ensure_res_hit,
    ensure_cold_n,
    asm_prevout_ns,
    asm_sigop_ns,
    asm_final_ns,
    asm_job_ns,
    asm_in_n,
    asm_prev_batch_n,
    asm_prev_same_n,
    asm_prev_cold_n,
    asm_prev_cold_null_fk_n,
    asm_prev_cold_not_pin_n,
    asm_prev_cold_txid_mismatch_n,
    asm_prev_cold_vout_miss_n,
    utxo_apply_ns,
    spend_annotate_ranged,
    spend_ann_ns,
    spend_ann_n,
    spend_ann_pread_skip,
    spend_durable_ns,
    // Pending spend annotate replayed before a write after a failed one.
    // Nested in utxo_apply_ns (the replay runs post_commit).
    spend_replay_ns,
    // Confirm parked at the spend delta's open edge cap, waiting for a
    // checkpoint to freeze the open notes.
    spend_room_wait_ns,
    // Spend delta checkpoints completed this window.
    spend_ckpt_n,
    spend_ckpt_max_ms,
    spend_notes_ram,
    spend_meta_ns,
    spend_meta_n,
    phase_prep_wire_arc_ns,
    phase_prep_struct_ns,
    phase_prep_header_ns,
    phase_prep_header_skip_n,
    phase_prep_prepare_ns,
    phase_prep_filter_plan_ns,
    phase_blocks,
    load_win_ns,
    load_blocks,
    utxo_parents,
    parent_unique,
    pin_cache_body,
    pin_plan,
    pin_new,
    pin_body_ns,
    plan_pin_ns,
    pin_range_fill_ns,
    pin_recent_outs_ns,
    pin_contract_ns,
    cold_io_ns,
    cold_range_ns,
    cold_range_n,
    cold_range_body_ns,
    cold_range_decode_ns,
    cold_range_extend_n,
    cold_range_body_sqe_n,
    cold_range_guess_full_n,
    body_tx_reads,
    thin_ns,
    thin_edges_ns,
    thin_fill_ns,
    thin_reject_ns,
    parent_pin_ns,
    // class C / SH
    strong_ns,
    scripthash_ns,
    tip_ns,
    sh_collect_ns,
    sh_sort_ns,
    sh_seed_ns,
    sh_body_ns,
    sh_head_ns,
    sh_collect_pin,
    sh_collect_cold,
    sh_create_n,
    sh_unique_n,
    sh_written_n,
    // SH table sync before a durable include_hwm advance (write-behind)
    sh_sync_n,
    sh_sync_ns,
    arch_blocks,
    ext_need,
    head_need,
    head_hit,
    pin_txid_n,
    pin_txid_ns,
    recent_n,
    recent_ns,
    leftover_pend,
    batch_stamp,
    resolved_stamp,
    arch_prep_total_ns,
    arch_prep_struct_ns,
    arch_prep_filter_ns,
    arch_prep_assign_ns,
    arch_prep_collect_ns,
    arch_prep_inflight_ns,
    arch_prep_head_ns,
    arch_prep_head_fk_ns,
    arch_prep_stamp_ns,
    arch_prep_finish_ns,
    arch_prep_publish_ns,
    arch_prep_qwait_ns,
    arch_prep_blocks,
    arch_write_total_ns,
    arch_write_reserve_ns,
    arch_write_body_ns,
    arch_write_head_ns,
    arch_write_spend_ns,
    arch_write_htxs_ns,
    arch_write_txstat_ns,
    arch_write_flush_ns,
    arch_write_blocks,
    lookup_blocks,
    lookup_parents,
    lookup_already,
    lookup_cold,
    lookup_unresolved,
    lookup_total_ns,
    lookup_collect_ns,
    lookup_head_ns,
    lookup_cold_io_ns,
    lookup_decode_ns,
    lookup_precompute_ns,
    lookup_wave_head_ns,
    lookup_wave_spent_ns,
    lookup_undrained_skip,
    stamp_struct_ns,
    stamp_struct_txid_ns,
    stamp_struct_wtxid_ns,
    stamp_struct_walk_ns,
    stamp_prepare_ns,
    stamp_filter_ns,
    stamp_batch_ns,
    // wire reconstruct
    // IBD OS-thread occupancy
    thr_lookup_claim_ns,
    thr_lookup_stamp_ns,
    thr_lookup_other_ns,
    thr_lookup_send_wait_ns,
    thr_load_recv_wait_ns,
    thr_load_pack_ns,
    thr_load_clone_ns,
    thr_load_stamp_ns,
    thr_load_pin_ns,
    thr_load_asm_ns,
    thr_load_prune_ns,
    thr_load_reject_ns,
    thr_load_send_wait_ns,
    thr_script_recv_wait_ns,
    thr_script_work_ns,
    thr_script_send_wait_ns,
    thr_write_recv_wait_ns,
    thr_write_work_ns,
    height_index_full_n,
    height_index_full_headers,
    height_index_delta_n,
}

impl ConfirmWindow {
    pub fn write_phases_sum_ns(&self) -> u64 {
        self.arch_write_reserve_ns
            .saturating_add(self.arch_write_body_ns)
            .saturating_add(self.arch_write_head_ns)
            .saturating_add(self.arch_write_spend_ns)
            .saturating_add(self.arch_write_htxs_ns)
            .saturating_add(self.arch_write_flush_ns)
    }

    pub fn resolve_ns(&self) -> u64 {
        self.arch_prep_inflight_ns
            .saturating_add(self.arch_prep_head_fk_ns)
    }
}

impl ConfirmStats {
    /// One spend checkpoint that committed. Window counters for `ibd: perf`.
    #[inline]
    pub fn note_spend_checkpoint(&self, total_ms: u64, notes_ram: u64) {
        add(&self.spend_ckpt_n, 1);
        self.spend_ckpt_max_ms
            .fetch_max(total_ms, Ordering::Relaxed);
        self.spend_notes_ram.store(notes_ram, Ordering::Relaxed);
    }

    #[inline]
    pub fn add_sh_part(&self, part: &AtomicU64, ns: u64) {
        if ns == 0 {
            return;
        }
        part.fetch_add(ns, Ordering::Relaxed);
        self.scripthash_ns.fetch_add(ns, Ordering::Relaxed);
    }

    pub fn note_resolve_counts(
        &self,
        blocks: u64,
        ext_need: u64,
        head_need: u64,
        head_hit: u64,
        batch_stamp: u64,
        resolved_stamp: u64,
    ) {
        add(&self.arch_blocks, blocks);
        add(&self.ext_need, ext_need);
        add(&self.head_need, head_need);
        add(&self.head_hit, head_hit);
        add(&self.batch_stamp, batch_stamp);
        add(&self.resolved_stamp, resolved_stamp);
        if head_need > 0 {
            self.last_head_need.store(head_need, Ordering::Relaxed);
            self.last_head_hit.store(head_hit, Ordering::Relaxed);
        }
    }

    pub fn last_plan_batch(&self) -> LastPlanBatch {
        LastPlanBatch {
            head_need: self.last_head_need.load(Ordering::Relaxed),
            head_hit: self.last_head_hit.load(Ordering::Relaxed),
        }
    }

    pub fn note_leftover_mix(&self, pend: u64, age0: u64, age3: u64, age_n: u64) {
        add(&self.leftover_pend, pend);
        add(&self.leftover_age0, age0);
        add(&self.leftover_age3, age3);
        add(&self.leftover_age_n, age_n);
    }

    pub fn note_pin_txid(&self, n: u64, ns: u64) {
        add(&self.pin_txid_n, n);
        add(&self.pin_txid_ns, ns);
    }

    pub fn note_recent(&self, n: u64, ns: u64) {
        add(&self.recent_n, n);
        add(&self.recent_ns, ns);
    }

    pub fn note_prep_plan(
        &self,
        assign_ns: u64,
        collect_ns: u64,
        inflight_ns: u64,
        head_fk_ns: u64,
        stamp_ns: u64,
        finish_ns: u64,
    ) {
        add(&self.arch_prep_assign_ns, assign_ns);
        add(&self.arch_prep_collect_ns, collect_ns);
        add(&self.arch_prep_inflight_ns, inflight_ns);
        add(&self.arch_prep_head_fk_ns, head_fk_ns);
        add(&self.arch_prep_head_ns, head_fk_ns);
        add(&self.arch_prep_stamp_ns, stamp_ns);
        add(&self.arch_prep_finish_ns, finish_ns);
    }

    #[allow(clippy::too_many_arguments)] // IO/session args stay unbundled
    pub fn note_write_commit(
        &self,
        total_ns: u64,
        reserve_ns: u64,
        body_ns: u64,
        head_ns: u64,
        spend_ns: u64,
        htxs_ns: u64,
        blocks: u64,
    ) {
        add(&self.arch_write_total_ns, total_ns);
        add(&self.arch_write_reserve_ns, reserve_ns);
        add(&self.arch_write_body_ns, body_ns);
        add(&self.arch_write_head_ns, head_ns);
        add(&self.arch_write_spend_ns, spend_ns);
        add(&self.arch_write_htxs_ns, htxs_ns);
        add(&self.arch_write_blocks, blocks);
    }

    pub fn note_write_txstat(&self, ns: u64) {
        add(&self.arch_write_txstat_ns, ns);
    }

    #[doc(hidden)]
    pub fn miss_on_code(on: Option<&str>) -> u64 {
        match on {
            Some("head") => 1,
            Some("body") => 2,
            Some("idx") => 3,
            Some("fence") => 4,
            _ => 0,
        }
    }

    #[doc(hidden)]
    pub fn miss_on_from_code(code: u64) -> Option<&'static str> {
        match code {
            1 => Some("head"),
            2 => Some("body"),
            3 => Some("idx"),
            4 => Some("fence"),
            _ => None,
        }
    }

    pub fn note_union_miss(
        &self,
        txid: [u8; 32],
        n: u64,
        pending: bool,
        miss_on: Option<&str>,
        miss_cands: u64,
    ) {
        self.last_miss_n.store(n, Ordering::Relaxed);
        self.last_miss_pend
            .store(u64::from(pending), Ordering::Relaxed);
        self.last_miss_on
            .store(Self::miss_on_code(miss_on), Ordering::Relaxed);
        self.last_miss_cands.store(miss_cands, Ordering::Relaxed);
        for (i, slot) in self.last_miss_txid.iter().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&txid[i.saturating_mul(8)..i.saturating_mul(8).saturating_add(8)]);
            slot.store(u64::from_le_bytes(b), Ordering::Relaxed);
        }
    }

    pub fn last_union_miss(&self) -> LastUnionMiss {
        let n = self.last_miss_n.load(Ordering::Relaxed);
        if n == 0 {
            return LastUnionMiss::default();
        }
        let mut txid = [0u8; 32];
        for (i, slot) in self.last_miss_txid.iter().enumerate() {
            let off = i.saturating_mul(8);
            txid[off..off.saturating_add(8)]
                .copy_from_slice(&slot.load(Ordering::Relaxed).to_le_bytes());
        }
        LastUnionMiss {
            n,
            pending: self.last_miss_pend.load(Ordering::Relaxed) != 0,
            txid: Some(txid),
            miss_on: Self::miss_on_from_code(self.last_miss_on.load(Ordering::Relaxed)),
            miss_cands: self.last_miss_cands.load(Ordering::Relaxed),
        }
    }

    pub fn note_stamp(&self, struct_ns: u64, prepare_ns: u64, filter_ns: u64, batch_ns: u64) {
        add(&self.stamp_struct_ns, struct_ns);
        add(&self.stamp_prepare_ns, prepare_ns);
        add(&self.stamp_filter_ns, filter_ns);
        add(&self.stamp_batch_ns, batch_ns);
    }

    pub fn note_struct_parts(&self, txid_ns: u64, wtxid_ns: u64, walk_ns: u64) {
        add(&self.stamp_struct_txid_ns, txid_ns);
        add(&self.stamp_struct_wtxid_ns, wtxid_ns);
        add(&self.stamp_struct_walk_ns, walk_ns);
    }

    pub fn note_wave_decode(
        &self,
        decode_ns: u64,
        precompute_ns: u64,
        collect_ns: u64,
        head_ns: u64,
        spent_ns: u64,
    ) {
        add(&self.lookup_decode_ns, decode_ns);
        add(&self.lookup_precompute_ns, precompute_ns);
        add(&self.lookup_collect_ns, collect_ns);
        add(&self.lookup_wave_head_ns, head_ns);
        add(&self.lookup_wave_spent_ns, spent_ns);
    }

    /// Inputs a lookup wave left out of its TipOnly need.
    pub fn note_wave_undrained_skip(&self, n: u64) {
        add(&self.lookup_undrained_skip, n);
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LastPlanBatch {
    pub head_need: u64,
    pub head_hit: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LastUnionMiss {
    pub n: u64,
    pub pending: bool,
    pub txid: Option<[u8; 32]>,
    pub miss_on: Option<&'static str>,
    pub miss_cands: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TipShSnap {
    pub collect_ns: u64,
    pub sort_ns: u64,
    pub seed_ns: u64,
    pub body_ns: u64,
    pub head_ns: u64,
    /// Table sync before a durable `include_hwm` advance.
    pub sync_ns: u64,
    pub pin: u64,
    pub cold: u64,
    pub creates: u64,
    pub unique: u64,
    pub written: u64,
}
