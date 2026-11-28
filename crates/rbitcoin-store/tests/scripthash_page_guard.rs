//! Scripthash writes rely on `scripthash.dirty`, not on page-guard marks.
use rbitcoin_primitives::Fk;
use rbitcoin_store::page_guard::{arm_page_guard_group, PAGE};
use rbitcoin_store::scripthash::*;
use rbitcoin_store::Store;

fn tmp() -> rbitcoin_store::testutil::TempDir {
    rbitcoin_store::testutil::TempDir::labeled("sh-pg").expect("temp dir")
}

/// A commit, an unlink, and the deferred empty-head commit arm no
/// `guard/sh-*` mark. Each runs under `scripthash.dirty`, so a crash
/// rebuilds the index and a mark would repair nothing.
#[cfg(debug_assertions)]
#[test]
fn scripthash_writes_arm_no_mark() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    let sh = [0x51u8; 32];
    rbitcoin_store::page_guard::arm_store_mark_trace();
    t.put_create_batch_append(&[
        ScriptHashRecord::from_fk(sh, Fk(1)),
        ScriptHashRecord::from_fk(sh, Fk(2)),
    ])
    .unwrap();
    t.unlink_creates_batch(&[(sh, vec![Fk(2)])]).unwrap();
    t.unlink_creates_batch(&[(sh, vec![Fk(1)])]).unwrap();
    t.commit_deferred_empty_heads().unwrap();
    let marks = rbitcoin_store::page_guard::take_armed_store_marks();
    assert!(
        marks.iter().all(|m| !m.starts_with("guard/sh-")),
        "scripthash armed {marks:?}"
    );
}

/// A `guard/sh-*` mark left by an older build is a scripthash commit that
/// did not finish. Open requests a rebuild and drops the mark without
/// copying its image back.
#[test]
fn open_rebuilds_scripthash_for_a_leftover_sh_mark() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.flush().unwrap();
    }
    let body = sh_ovf_body_path(&dir);
    let rel = body
        .strip_prefix(&*dir)
        .unwrap()
        .to_str()
        .unwrap()
        .replace('\\', "/");
    let image = vec![0xAAu8; PAGE as usize];
    arm_page_guard_group(
        &dir.join("guard/sh-ovf"),
        &[(rel.as_str(), 0, image.as_slice())],
    )
    .unwrap();
    let s = Store::open_tiny(&dir).expect("a leftover sh mark stopped open");
    drop(s);
    assert!(dir.join(SH_REBUILD_NAME).is_file(), "no rebuild requested");
    assert!(!dir.join("guard/sh-ovf").exists(), "the mark stayed");
    let page0 = std::fs::read(&body)
        .map(|b| b[..16].to_vec())
        .unwrap_or_default();
    assert_ne!(page0, vec![0xAAu8; 16], "open copied the image back");
}
