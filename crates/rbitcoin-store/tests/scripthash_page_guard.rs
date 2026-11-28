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
/// did not finish. Open drops the mark without copying its image back and
/// makes sure `scripthash.dirty` is on disk: the index may read as valid
/// and be wrong, so a start with the index on refuses and the operator
/// chooses the rebuild. An index that still decodes is not wiped.
#[test]
fn open_marks_a_leftover_sh_mark_dirty_without_copying_it() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.flush().unwrap();
    }
    let body = sh_ovf_body_path(&dir);
    let before = std::fs::read(&body).unwrap();
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
    assert!(!dir.join("guard/sh-ovf").exists(), "the mark stayed");
    assert!(sh_dirty_marked(&dir), "scripthash.dirty was not written");
    assert!(
        !dir.join(SH_REBUILD_NAME).exists(),
        "a decodable index was wiped"
    );
    let after = std::fs::read(&body).unwrap();
    assert_eq!(
        after[..PAGE as usize],
        before[..PAGE as usize],
        "open copied the image back"
    );
}

/// A `guard/sh-*.tmp` is an arm the old build never renamed into place, not
/// a mark. Open neither marks the index dirty nor rebuilds it for that.
#[test]
fn a_leftover_sh_tmp_is_not_a_mark() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.flush().unwrap();
    }
    std::fs::create_dir_all(dir.join("guard")).unwrap();
    std::fs::write(dir.join("guard/sh-ovf.tmp"), b"partial").unwrap();
    drop(Store::open_tiny(&dir).unwrap());
    assert!(
        !sh_dirty_marked(&dir),
        "an unpublished arm marked the index dirty"
    );
    assert!(
        !dir.join(SH_REBUILD_NAME).exists(),
        "an unpublished arm wiped the index"
    );
}
