use rbitcoin_primitives::Fk;
use rbitcoin_store::idx_body_pipeline::*;
use rbitcoin_store::tx_table::{
    decode_packed_tx_outs_with_spender_rels, InputRecord, OutputRecord, TxRecord, TxTable,
};

use std::sync::atomic::{AtomicU64, Ordering};

fn temp_tx() -> (std::path::PathBuf, TxTable) {
    static N: AtomicU64 = AtomicU64::new(0);
    let id = N.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("rbitcoin-idx-body-pipe-{id}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let t = TxTable::create_tiny(&dir).unwrap();
    (dir, t)
}

#[test]
fn group_body_peeks_merges_a_small_hole_inside_the_span_cap() {
    let page = BODY_OS_PAGE;
    let hole = 8 * 1024;
    let a = (page, 32u64);
    let b_off = a.0 + a.1 + hole;
    let grouped = group_body_peeks(&[a, (b_off, 32)]);
    assert_eq!(grouped.len(), 1, "8 KiB hole");
    assert_eq!(grouped[0].2, vec![0, 1]);

    let over = 64 * 1024 + 1;
    let split = group_body_peeks(&[a, (a.0 + a.1 + over, 32)]);
    assert_eq!(split.len(), 2, "hole just over 64 KiB");

    let big = 200 * 1024;
    let wide = group_body_peeks(&[(0, big), (big + hole, 80 * 1024)]);
    assert!(big + hole + 80 * 1024 > 256 * 1024);
    assert_eq!(wide.len(), 2, "span past 256 KiB");

    let straddle = group_body_peeks(&[(page - 8, 16), (page + 100, 16)]);
    assert_eq!(straddle.len(), 1, "two-page straddle");
    assert_eq!(straddle[0].2, vec![0, 1]);
}

#[test]
fn plan_spend_slot_peeks_merges_like_pin_reads() {
    let page = BODY_OS_PAGE;
    let slot = rbitcoin_store::tx_table::OutputRecord::SPENT_SLOT_LEN as u64;
    let near = plan_spend_slot_peeks(&[page, page + slot + 8 * 1024]);
    assert_eq!(near.len(), 1, "8 KiB hole");
    assert_eq!(near[0].members, vec![0, 1]);
    assert_eq!(near[0].off, page);
    assert!(near[0].len >= slot + 8 * 1024);

    let over = plan_spend_slot_peeks(&[page, page + slot + 64 * 1024 + 1]);
    assert_eq!(over.len(), 2, "hole just over 64 KiB");

    let mut wide = Vec::new();
    let mut at = 0u64;
    while at + slot <= 256 * 1024 {
        wide.push(at);
        at += 32 * 1024;
    }
    wide.push(at);
    let split = plan_spend_slot_peeks(&wide);
    assert_eq!(split.len(), 2, "a run past 256 KiB splits");
    assert!(split.iter().all(|g| g.len <= 256 * 1024));

    let same = plan_spend_slot_peeks(&[page + 100, page + 10]);
    assert_eq!(same.len(), 1, "same page, caller order is not file order");
    assert_eq!(same[0].members, vec![1, 0]);
}

#[test]
fn spend_slot_run_closes_when_the_grouper_splits() {
    let page = BODY_OS_PAGE;
    let slot = rbitcoin_store::tx_table::OutputRecord::SPENT_SLOT_LEN as u64;
    let near = [page, page + slot + 8 * 1024];
    let mut run = SpendSlotRun::new();
    assert!(run.accepts_all(&near), "8 KiB hole");
    run.push_all(&near);
    let far = near[1] + slot + 64 * 1024 + 1;
    assert!(!run.accepts_all(&[far]), "hole just over 64 KiB");
    let mut wide = Vec::new();
    wide.extend_from_slice(&near);
    wide.push(far);
    assert_eq!(plan_spend_slot_peeks(&wide).len(), 2);

    let mut stepped = Vec::new();
    let mut at = 0u64;
    while at + slot <= 256 * 1024 {
        stepped.push(at);
        at += 32 * 1024;
    }
    let mut run = SpendSlotRun::new();
    assert!(run.accepts_all(&stepped), "steps inside the span cap");
    run.push_all(&stepped);
    assert!(
        !run.accepts_all(&[at]),
        "the next step past 256 KiB closes the run"
    );

    let reversed = SpendSlotRun::new();
    assert!(
        reversed.accepts_all(&[page + 100, page + 10]),
        "same page, caller order is not file order"
    );
}

fn stamp_txout(t: &TxTable, jobs: &mut [IdxBodyJob]) {
    let fks: Vec<Fk> = jobs.iter().map(|j| Fk(j.id)).collect();
    let pairs = t.create_loc_range_batch(&fks).unwrap();
    for (j, p) in jobs.iter_mut().zip(pairs) {
        if let Some(p) = p {
            if j.range.is_none() {
                j.range = Some(p.txout);
            }
            j.n_out = p.n_out;
        }
    }
}

fn put_n(t: &TxTable, n: u8) -> Vec<Fk> {
    let mut fks = Vec::new();
    for i in 0..n {
        let mut txid = [0u8; 32];
        txid[0] = i.wrapping_add(1);
        let tx = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1 + (i % 3) as u32,
        };
        let inputs = vec![InputRecord {
            prev_txid: [0u8; 32],
            parent: rbitcoin_store::InputParent::Coinbase,
            sequence: u32::MAX,
            script_sig: vec![i],
            witness: vec![],
        }];
        let mut outs = Vec::new();
        for j in 0..(1 + (i % 3)) {
            outs.push(OutputRecord::unspent(j as u64 + 1, vec![0x51, j]));
        }
        fks.push(
            t.put_full_batch_indexed(&[(tx, inputs, outs)], true)
                .unwrap()[0],
        );
    }
    fks
}

#[test]
fn from_fk_and_empty_pipeline() {
    assert!(IdxBodyJob::from_fk(Fk::NULL, None).is_none());
    assert!(IdxBodyJob::from_fk(Fk(0), None).is_none());
    let j = IdxBodyJob::from_fk(Fk(7), Some((16, 8))).unwrap();
    assert_eq!(j.id, 7);
    assert_eq!(j.range, Some((16, 8)));
    let (dir, t) = temp_tx();
    run_idx_body_pipeline(&t.body, &mut [], BodyMode::Full).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_outs_coalesces_same_page_peeks() {
    let (dir, t) = temp_tx();
    let fks = put_n(&t, 8);
    let mut jobs: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
    stamp_txout(&t, &mut jobs);
    let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
    assert!(stats.body_sqe_n >= 1);
    assert!(
        stats.body_sqe_n < jobs.len() as u64,
        "sqe={} jobs={}",
        stats.body_sqe_n,
        jobs.len()
    );
    for j in &jobs {
        assert!(j.ok, "id={}", j.id);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_outs_extends_past_first_page() {
    let (dir, t) = temp_tx();
    let tx = TxRecord {
        txid: [0x7eu8; 32],
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: 1,
    };
    let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let outs = vec![OutputRecord::unspent(1, vec![0x51; 6000])];
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outs)], true)
        .unwrap()[0];
    let (_off, full_len) = t.body_range(fk).unwrap();
    assert!(full_len > 4096, "fixture must exceed first-page cap");
    let mut jobs = vec![IdxBodyJob::new(fk.0, None)];
    stamp_txout(&t, &mut jobs);
    let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
    assert!(jobs[0].ok);
    assert_eq!(jobs[0].body.len() as u64, full_len);
    assert_eq!(stats.extend_n, 0);
    assert_eq!(stats.guess_full_n, 1);
    let (meta, decoded, _) = rbitcoin_store::tx_table::decode_packed_tx_outs_with_spender_rels(
        &jobs[0].body,
        jobs[0].n_out,
    )
    .unwrap();
    assert_eq!(meta.output_count, 1);
    assert_eq!(decoded[0].script.len(), 6000);
    let _ = std::fs::remove_dir_all(&dir);
}

fn fat_many_outs(n_out: u32) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    let tx = TxRecord {
        txid: [0x5au8; 32],
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: n_out,
    };
    let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let mut outs = Vec::with_capacity(n_out as usize);
    outs.push(OutputRecord::unspent(1, vec![0x51]));
    for _ in 1..n_out {
        outs.push(OutputRecord::unspent(1, vec![0x51; 64]));
    }
    (tx, inputs, outs)
}

fn pad_until_page_room(t: &TxTable, room_lo: u64, room_hi: u64) {
    assert!(room_lo >= 1 && room_hi < BODY_OS_PAGE && room_lo <= room_hi);
    let mut salt = 0u8;
    for _ in 0..64 {
        let cur = t.body.body_published_len();
        let into = cur % BODY_OS_PAGE;
        let room = if into == 0 {
            BODY_OS_PAGE
        } else {
            BODY_OS_PAGE - into
        };
        if into != 0 && room >= room_lo && room <= room_hi {
            return;
        }
        salt = salt.wrapping_add(1);
        let mut txid = [0u8; 32];
        txid[0] = 0x11;
        txid[1] = salt;
        let script_len = if room > room_hi.saturating_add(32) {
            (room - room_hi).saturating_sub(16).clamp(1, 4000) as usize
        } else {
            1
        };
        let tx = TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        };
        let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
        let outs = vec![OutputRecord::unspent(1, vec![0x51; script_len])];
        t.put_full_batch_indexed(&[(tx, inputs, outs)], true)
            .unwrap();
    }
    let cur = t.body.body_published_len();
    panic!(
        "pad miss into={} room={} want {room_lo}..={room_hi}",
        cur % BODY_OS_PAGE,
        BODY_OS_PAGE - (cur % BODY_OS_PAGE)
    );
}

#[test]
fn pipeline_outs_guess_full_when_late_vout_likely_spills() {
    let (dir, t) = temp_tx();
    let (tx, inputs, outs) = fat_many_outs(120);
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outs)], true)
        .unwrap()[0];
    let (off, full_len) = t.body_range(fk).unwrap();
    assert!(full_len > 4096, "fixture must exceed first-page cap");
    assert_eq!(outs_first_wave_len(off, full_len, &[119]), full_len);
    let mut jobs = vec![IdxBodyJob::new(fk.0, None)];
    jobs[0].need_vouts = vec![119];
    stamp_txout(&t, &mut jobs);
    let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
    assert!(jobs[0].ok);
    assert_eq!(jobs[0].body.len() as u64, full_len);
    assert_eq!(stats.extend_n, 0);
    assert_eq!(stats.guess_full_n, 1);
    let (_meta, live, _) =
        rbitcoin_store::tx_table::decode_packed_tx_need_outs_with_spender_rels_secret(
            &jobs[0].body,
            jobs[0].n_out,
            &[119],
            None,
        )
        .unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].0, 119);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_outs_guess_full_when_body_starts_near_page_end() {
    let (dir, t) = temp_tx();
    pad_until_page_room(&t, 8, 32);
    let (tx, inputs, outs) = fat_many_outs(80);
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outs)], true)
        .unwrap()[0];
    let (off, full_len) = t.body_range(fk).unwrap();
    let room = BODY_OS_PAGE - (off % BODY_OS_PAGE);
    assert!(room < 40, "room={room}");
    assert!(full_len > 4096);
    assert_eq!(outs_first_wave_len(off, full_len, &[0]), full_len);
    let mut jobs = vec![IdxBodyJob::new(fk.0, None)];
    jobs[0].need_vouts = vec![0];
    stamp_txout(&t, &mut jobs);
    let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
    assert!(jobs[0].ok);
    assert_eq!(jobs[0].body.len() as u64, full_len);
    assert_eq!(stats.extend_n, 0);
    assert_eq!(stats.guess_full_n, 1);
    let (_meta, live, _) =
        rbitcoin_store::tx_table::decode_packed_tx_need_outs_with_spender_rels_secret(
            &jobs[0].body,
            jobs[0].n_out,
            &[0],
            None,
        )
        .unwrap();
    assert_eq!(live.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_outs_peeks_page_remainder_when_k0_fits() {
    let (dir, t) = temp_tx();
    pad_until_page_room(&t, 200, 400);
    let (tx, inputs, outs) = fat_many_outs(80);
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outs)], true)
        .unwrap()[0];
    let (off, full_len) = t.body_range(fk).unwrap();
    let room = BODY_OS_PAGE - (off % BODY_OS_PAGE);
    assert!((200..=400).contains(&room), "room={room}");
    assert!(full_len > 4096);
    let want = outs_first_wave_len(off, full_len, &[0]);
    assert_eq!(want, room);
    assert!(want < full_len);
    let mut jobs = vec![IdxBodyJob::new(fk.0, None)];
    jobs[0].need_vouts = vec![0];
    stamp_txout(&t, &mut jobs);
    let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
    assert!(jobs[0].ok);
    assert_eq!(jobs[0].body.len() as u64, want);
    assert_eq!(stats.extend_n, 0);
    assert_eq!(stats.guess_full_n, 0);
    let (_meta, live, _) =
        rbitcoin_store::tx_table::decode_packed_tx_need_outs_with_spender_rels_secret(
            &jobs[0].body,
            jobs[0].n_out,
            &[0],
            None,
        )
        .unwrap();
    assert_eq!(live.len(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_outs_skips_extend_when_need_fits_first_page() {
    let (dir, t) = temp_tx();
    let (tx, inputs, outs) = fat_many_outs(80);
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outs)], true)
        .unwrap()[0];
    let (off, full_len) = t.body_range(fk).unwrap();
    assert!(full_len > 4096, "fixture must exceed first-page cap");
    let mut jobs = vec![IdxBodyJob::new(fk.0, None)];
    jobs[0].need_vouts = vec![0];
    stamp_txout(&t, &mut jobs);
    let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
    assert!(jobs[0].ok);
    assert_eq!(
        jobs[0].body.len() as u64,
        outs_first_wave_len(off, full_len, &[0])
    );
    assert_eq!(stats.extend_n, 0);
    assert_eq!(stats.guess_full_n, 0);
    let (meta, live, _) =
        rbitcoin_store::tx_table::decode_packed_tx_need_outs_with_spender_rels_secret(
            &jobs[0].body,
            jobs[0].n_out,
            &[0],
            None,
        )
        .unwrap();
    assert_eq!(meta.output_count, 80);
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].0, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_outs_extends_when_need_past_first_page() {
    let (dir, t) = temp_tx();
    let (tx, inputs, outs) = fat_many_outs(80);
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outs)], true)
        .unwrap()[0];
    let (_off, full_len) = t.body_range(fk).unwrap();
    assert!(full_len > 4096, "fixture must exceed first-page cap");
    let mut jobs = vec![IdxBodyJob::new(fk.0, None)];
    jobs[0].need_vouts = vec![79];
    stamp_txout(&t, &mut jobs);
    let stats = run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
    assert!(jobs[0].ok);
    assert_eq!(jobs[0].body.len() as u64, full_len);
    assert_eq!(stats.extend_n, 1);
    assert_eq!(stats.guess_full_n, 0);
    let (_meta, live, _) =
        rbitcoin_store::tx_table::decode_packed_tx_need_outs_with_spender_rels_secret(
            &jobs[0].body,
            jobs[0].n_out,
            &[79],
            None,
        )
        .unwrap();
    assert_eq!(live.len(), 1);
    assert_eq!(live[0].0, 79);
    let _ = std::fs::remove_dir_all(&dir);
}

/// uring / pread body backends produce identical Full payloads.
#[test]
fn pipeline_body_backends_agree() {
    use rbitcoin_store::io_backend::ReadIoBackend;
    let (dir, t) = temp_tx();
    let fks = put_n(&t, 8);
    let mut bodies: Vec<Vec<Vec<u8>>> = Vec::new();
    for backend in [ReadIoBackend::Uring, ReadIoBackend::Pread] {
        let mut jobs: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
        stamp_txout(&t, &mut jobs);
        run_idx_body_pipeline_backend(&t.body, &mut jobs, BodyMode::Full, backend).unwrap();
        let mut batch = Vec::new();
        for j in &jobs {
            assert!(j.ok, "backend={backend:?} id={}", j.id);
            batch.push(j.body.clone());
        }
        bodies.push(batch);
    }
    assert_eq!(bodies[0], bodies[1]);
    let _ = std::fs::remove_dir_all(&dir);
}

const PEEK_LEN: usize = 64;
/// Hole between merged groups: over [`BODY_GROUP_MAX_HOLE`], so they stay apart.
const PEEK_GROUP_STRIDE: u64 = 300 * 1024;

/// A body file holding one 3 MiB patterned script, and the offset where the
/// script's bytes are safely under way.
fn peek_body_file() -> (std::path::PathBuf, TxTable, u64) {
    let (dir, t) = temp_tx();
    let tx = TxRecord {
        txid: [0x6au8; 32],
        version: 1,
        locktime: 0,
        input_count: 1,
        output_count: 1,
    };
    let inputs = vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])];
    let script: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let outs = vec![OutputRecord::unspent(1, script)];
    let fk = t
        .put_full_batch_indexed(&[(tx, inputs, outs)], true)
        .unwrap()[0];
    let (off, _) = t.body_range(fk).unwrap();
    (dir, t, off + 4096)
}

/// Two windows one page apart: one merged group of about two pages.
fn small_group(at: u64) -> [u64; 2] {
    [at, at + 4096]
}

/// Four windows 60 KiB apart: one merged group of about 180 KiB.
fn large_group(at: u64) -> [u64; 4] {
    [at, at + 60 * 1024, at + 120 * 1024, at + 180 * 1024]
}

fn merged_bytes(offs: &[u64]) -> u64 {
    let windows: Vec<(u64, u64)> = offs.iter().map(|o| (*o, PEEK_LEN as u64)).collect();
    group_body_peeks(&windows)
        .iter()
        .filter(|(_, _, members)| members.len() > 1)
        .map(|(_, span, _)| *span)
        .sum()
}

struct PeekWave {
    jobs: Vec<IdxBodyJob>,
    groups: u64,
}

/// One job per window, read with the shipped pread grouper.
fn peek_wave(t: &TxTable, offs: &[u64]) -> PeekWave {
    let mut jobs: Vec<IdxBodyJob> = (0..offs.len())
        .map(|i| IdxBodyJob {
            id: i as u64 + 1,
            range: None,
            body: vec![0u8; PEEK_LEN],
            ok: false,
            need_vouts: Vec::new(),
            n_out: 0,
        })
        .collect();
    let dests: Vec<PeekDest> = offs
        .iter()
        .enumerate()
        .map(|(job, off)| PeekDest {
            job,
            off: *off,
            dest: 0,
            len: PEEK_LEN,
        })
        .collect();
    let fd = t.body.body_read_fd();
    let path = t.body.body_file_path();
    let backend = rbitcoin_store::io_backend::ReadIoBackend::Pread;
    let groups = pread_grouped_peeks(&mut jobs, &dests, fd, path, backend, true).unwrap();
    PeekWave { jobs, groups }
}

fn assert_peeked(t: &TxTable, offs: &[u64], wave: &PeekWave) {
    let file = std::fs::read(t.body.body_file_path()).unwrap();
    for (off, job) in offs.iter().zip(&wave.jobs) {
        let at = *off as usize;
        assert!(job.ok, "window at {off} not read");
        assert_eq!(job.body, file[at..at + PEEK_LEN], "window at {off}");
    }
}

#[test]
fn a_large_span_after_many_small_groups_reads_every_window() {
    let (dir, t, base) = peek_body_file();
    let small: Vec<u64> = (0..17)
        .flat_map(|k| small_group(base + k * PEEK_GROUP_STRIDE))
        .collect();
    let large = large_group(base + 9 * PEEK_GROUP_STRIDE + 8192);

    assert_eq!(peek_wave(&t, &small).groups, 17);
    let first = peek_wave(&t, &large);
    assert_eq!(first.groups, 1);
    assert_peeked(&t, &large, &first);
    let again = peek_wave(&t, &large);
    assert_peeked(&t, &large, &again);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn waves_over_the_bounce_keep_cap_read_every_window() {
    let (dir, t, base) = peek_body_file();
    let one = large_group(base);
    let many: Vec<u64> = (1..=7)
        .flat_map(|k| large_group(base + k * PEEK_GROUP_STRIDE))
        .collect();
    let many_bytes = merged_bytes(&many);
    assert!(many_bytes > 1024 * 1024, "{many_bytes}");

    peek_wave(&t, &one);
    peek_wave(&t, &many);
    let many_again = peek_wave(&t, &many);
    assert_eq!(many_again.groups, 7);
    assert_peeked(&t, &many, &many_again);
    let one_again = peek_wave(&t, &one);
    assert_peeked(&t, &one, &one_again);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wave_past_the_kept_bounce_reads_every_window() {
    let (dir, t, base) = peek_body_file();
    let wave = |groups: u64| -> Vec<u64> {
        (0..groups)
            .flat_map(|k| large_group(base + k * PEEK_GROUP_STRIDE))
            .collect()
    };
    let (three, five) = (wave(3), wave(5));
    let need = merged_bytes(&five);
    assert!(need > merged_bytes(&three) && need <= 1024 * 1024, "{need}");

    peek_wave(&t, &three);
    let grown = peek_wave(&t, &five);
    assert_peeked(&t, &five, &grown);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_reused_bounce_never_fills_a_window_past_a_short_read() {
    let (dir, t, base) = peek_body_file();
    let large = large_group(base);
    peek_wave(&t, &large);

    let file_len = std::fs::metadata(t.body.body_file_path()).unwrap().len();
    let tail = [file_len - 200, file_len - 32];
    let wave = peek_wave(&t, &tail);
    assert_eq!(wave.groups, 1);
    assert_peeked(&t, &tail[..1], &wave);
    assert!(!wave.jobs[1].ok, "a window past EOF read as ok");
    assert_eq!(
        wave.jobs[1].body,
        vec![0u8; PEEK_LEN],
        "stale bounce bytes reached a window past EOF"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_full_matches_record_range_and_decode() {
    let (dir, t) = temp_tx();
    let fks = put_n(&t, 12);
    let (known_off, known_len) = t.body_range(fks[3]).unwrap();
    let mut jobs: Vec<IdxBodyJob> = fks
        .iter()
        .enumerate()
        .map(|(i, fk)| {
            let range = if i == 3 {
                Some((known_off, known_len))
            } else {
                None
            };
            IdxBodyJob::new(fk.0, range)
        })
        .collect();
    jobs.swap(0, 7);
    jobs.swap(2, 10);
    stamp_txout(&t, &mut jobs);
    run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Full).unwrap();
    for j in &jobs {
        assert!(j.ok, "id={}", j.id);
        let seq = t.body_range(Fk(j.id)).unwrap();
        assert_eq!(j.range, Some(seq));
        let (tx, outs, rels) = decode_packed_tx_outs_with_spender_rels(&j.body, j.n_out).unwrap();
        assert_eq!(outs.len(), rels.len());
        assert_eq!(tx.output_count as usize, outs.len());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pipeline_outs_decodes_denserels() {
    let (dir, t) = temp_tx();
    let fks = put_n(&t, 5);
    let mut jobs: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
    stamp_txout(&t, &mut jobs);
    run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Outs).unwrap();
    for j in &jobs {
        assert!(j.ok);
        let (_tx, outs, rels) =
            rbitcoin_store::tx_table::decode_packed_tx_outs_with_spender_rels(&j.body, j.n_out)
                .unwrap();
        assert_eq!(outs.len(), rels.len());
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Pre-known ranges skip idx; remaining jobs still resolve + body-read.
/// Identity: pipeline body bytes match sequential `record_range` + decode.
#[test]
fn pipeline_preknown_range_skips_idx_identity() {
    let (dir, t) = temp_tx();
    let fks = put_n(&t, 8);
    let mut jobs: Vec<IdxBodyJob> = fks
        .iter()
        .enumerate()
        .map(|(i, fk)| {
            let range = if i % 2 == 0 {
                Some(t.body_range(*fk).unwrap())
            } else {
                None
            };
            IdxBodyJob::new(fk.0, range)
        })
        .collect();
    stamp_txout(&t, &mut jobs);
    run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Full).unwrap();
    for j in &jobs {
        assert!(j.ok, "id={}", j.id);
        let seq = t.body_range(Fk(j.id)).unwrap();
        assert_eq!(j.range, Some(seq));
        let (tx, outs, rels) = decode_packed_tx_outs_with_spender_rels(&j.body, j.n_out).unwrap();
        assert_eq!(outs.len(), rels.len());
        assert_eq!(tx.output_count as usize, outs.len());
    }
    // Second wave reuses bulk_io TL ring; results stable.
    let mut jobs2: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
    stamp_txout(&t, &mut jobs2);
    run_idx_body_pipeline(&t.body, &mut jobs2, BodyMode::Full).unwrap();
    for (a, b) in jobs.iter().zip(jobs2.iter()) {
        assert_eq!(a.range, b.range);
        assert_eq!(a.body, b.body);
        assert!(b.ok);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn pre_stamped_range_fills_n_out_from_loc() {
    let (dir, t) = temp_tx();
    let fks = put_n(&t, 3);
    let pair = t.create_loc_range_batch(&[fks[1]]).unwrap()[0].unwrap();
    let mut jobs = [IdxBodyJob::new(fks[1].0, Some(pair.txout))];
    assert_eq!(jobs[0].n_out, 0);
    t.fill_txout_job_ranges(&mut jobs).unwrap();
    assert_eq!(jobs[0].n_out, pair.n_out);
    assert!(jobs[0].n_out >= 1);
    run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Full).unwrap();
    let (tx, outs, _) =
        decode_packed_tx_outs_with_spender_rels(&jobs[0].body, jobs[0].n_out).unwrap();
    assert_eq!(tx.output_count as usize, outs.len());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oob_and_null_ids_not_ok() {
    let (dir, t) = temp_tx();
    let fks = put_n(&t, 2);
    let mut jobs = vec![
        IdxBodyJob::new(0, None),
        IdxBodyJob::new(fks[0].0, None),
        IdxBodyJob::new(99_999, None),
    ];
    stamp_txout(&t, &mut jobs);
    run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Full).unwrap();
    assert!(!jobs[0].ok);
    assert!(jobs[1].ok);
    assert!(!jobs[2].ok);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Synthetic confirm-load-style cold batch: N Class A txs, mixed pre-known
/// ranges, timed multi-wave idx+body. Prints wall µs for evidence capture.
#[test]
fn synthetic_cold_batch_timed_identity() {
    use std::time::Instant;
    let (dir, t) = temp_tx();
    let fks = put_n(&t, 64);
    let mut jobs: Vec<IdxBodyJob> = fks.iter().map(|fk| IdxBodyJob::new(fk.0, None)).collect();
    let t0 = Instant::now();
    stamp_txout(&t, &mut jobs);
    run_idx_body_pipeline(&t.body, &mut jobs, BodyMode::Full).unwrap();
    let cold_us = t0.elapsed().as_micros();
    assert_eq!(jobs.iter().filter(|j| j.ok).count(), fks.len());
    let bodies: Vec<Vec<u8>> = jobs.iter().map(|j| j.body.clone()).collect();
    let ranges: Vec<_> = jobs.iter().map(|j| j.range).collect();

    // Wave 2: all ranges pre-known (skip idx) — confirm pin_new-ish path
    let mut jobs2: Vec<IdxBodyJob> = fks
        .iter()
        .zip(ranges.iter())
        .map(|(fk, r)| IdxBodyJob::new(fk.0, *r))
        .collect();
    let t1 = Instant::now();
    stamp_txout(&t, &mut jobs2);
    run_idx_body_pipeline(&t.body, &mut jobs2, BodyMode::Full).unwrap();
    let warm_us = t1.elapsed().as_micros();
    for (i, j) in jobs2.iter().enumerate() {
        assert!(j.ok, "i={i}");
        assert_eq!(j.body, bodies[i]);
        assert_eq!(j.range, ranges[i]);
    }

    eprintln!(
        "synthetic_cold_batch: n={} cold_full={}us preknown_full={}us uring={}",
        fks.len(),
        cold_us,
        warm_us,
        rbitcoin_store::bulk_io::io_uring_enabled()
    );
    let _ = std::fs::remove_dir_all(&dir);
}
