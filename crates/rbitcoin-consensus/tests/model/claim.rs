//! `in_wave` is published before `next`. A publisher that sees
//! [`Wave::is_complete`] must not free `ctx` under a claim that still applies.

use rbitcoin_consensus::script_pool::{Apply, Wave};
use rbitcoin_consensus::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use rbitcoin_consensus::sync::thread;
use rbitcoin_consensus::ConsensusError;
use std::sync::Arc;

unsafe fn nop(_: *const (), _: usize) -> Result<(), ConsensusError> {
    Ok(())
}

fn one_job_wave() -> Arc<Wave> {
    Arc::new(Wave {
        n: 1,
        chunk: 1,
        next: AtomicUsize::new(0),
        in_wave: AtomicUsize::new(0),
        failed: std::sync::atomic::AtomicBool::new(false),
        first_err: std::sync::Mutex::new(None),
        keep_faults: std::sync::atomic::AtomicBool::new(false),
        faults: std::sync::Mutex::new(Vec::new()),
        apply: Apply {
            f: nop,
            ctx: std::ptr::null(),
        },
        done: std::sync::Mutex::new(false),
        done_cv: std::sync::Condvar::new(),
        pair: std::sync::Mutex::new(None),
        pair_capped: std::sync::atomic::AtomicBool::new(false),
        published: std::sync::atomic::AtomicBool::new(true),
    })
}

#[test]
fn claim_holds_in_wave_before_next_advances() {
    super::engine::check(|| {
        let wave = one_job_wave();
        let freed = Arc::new(AtomicBool::new(false));
        let publishing = Arc::clone(&wave);
        let flag = Arc::clone(&freed);
        let publisher = thread::spawn(move || {
            if publishing.is_complete() {
                flag.store(true, Ordering::Release);
            }
        });
        let claiming = Arc::clone(&wave);
        let flag = Arc::clone(&freed);
        let claimer = thread::spawn(move || {
            if let Some((_, hold)) = Wave::claim_chunk(&claiming) {
                assert!(
                    !flag.load(Ordering::Acquire),
                    "is_complete freed ctx under an in-flight claim"
                );
                drop(hold);
            }
        });
        claimer.join().unwrap();
        publisher.join().unwrap();
    });
}

/// Two claimers race for the only job. The loser may skip on the relaxed
/// `next` hint instead of charging `in_wave`, so it no longer runs the
/// completion notify. The last holder to drop must still mark the wave done.
#[test]
fn losing_claimer_skip_still_completes_the_wave() {
    super::engine::check(|| {
        let wave = one_job_wave();
        let claimers: Vec<_> = (0..2)
            .map(|_| {
                let claiming = Arc::clone(&wave);
                thread::spawn(move || Wave::claim_chunk(&claiming).map(drop).is_some())
            })
            .collect();
        let won = claimers
            .into_iter()
            .map(|c| c.join().unwrap())
            .filter(|w| *w)
            .count();
        assert_eq!(won, 1, "exactly one claimer takes the only job");
        assert!(wave.is_complete());
        assert!(
            *wave.done.lock().unwrap(),
            "no drop marked the wave done after the loser skipped"
        );
    });
}
