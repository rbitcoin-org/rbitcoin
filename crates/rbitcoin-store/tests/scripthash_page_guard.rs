//! Scripthash commits restore torn 4 KiB pages from `store/guard/sh-*`.
use rbitcoin_primitives::Fk;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::file::FILE_HEADER_LEN;
use rbitcoin_store::scripthash::*;
use rbitcoin_store::scripthash_head::ScriptHashHead;
use rbitcoin_store::scripthash_layout::{ShHeadValue, SH_HEAD_SLOT_SIZE};
use rbitcoin_store::scripthash_pages::{SH_PAGE_SIZE, SH_PAGE_STREAM_MAX};
use rbitcoin_store::Store;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

fn tmp() -> rbitcoin_store::testutil::TempDir {
    rbitcoin_store::testutil::TempDir::labeled("sh-pg").expect("temp dir")
}

fn rec(sh: [u8; 32], tx: u64) -> ScriptHashRecord {
    ScriptHashRecord::from_fk(sh, Fk(tx))
}

fn put_create_batch(t: &ScriptHashTable, recs: impl AsRef<[ScriptHashRecord]>) -> usize {
    t.put_create_batch_append(recs.as_ref()).unwrap().0
}

fn create_fks(t: &ScriptHashTable, sh: &[u8; 32]) -> Vec<u64> {
    t.entries(sh).unwrap().iter().map(|(fk, _)| fk.0).collect()
}

fn page_bytes(path: &Path, off: u64) -> Vec<u8> {
    let mut file = std::fs::File::open(path).unwrap();
    let len = file.metadata().unwrap().len();
    let mut buf = vec![0u8; SH_PAGE_SIZE];
    if off >= len {
        return buf;
    }
    let n = ((len - off) as usize).min(SH_PAGE_SIZE);
    file.seek(SeekFrom::Start(off)).unwrap();
    std::io::Read::read_exact(&mut file, &mut buf[..n]).unwrap();
    buf
}

fn tear_bytes(path: &Path, off: u64, n: usize) {
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(off)).unwrap();
    file.write_all(&vec![0xffu8; n]).unwrap();
    file.sync_all().unwrap();
}

fn sh_marks(dir: &Path) -> Vec<std::path::PathBuf> {
    let guard = dir.join("guard");
    let Ok(rd) = std::fs::read_dir(&guard) else {
        return Vec::new();
    };
    let mut out: Vec<_> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("sh-"))
        })
        .collect();
    out.sort();
    out
}

fn neighbor_scripts() -> ([u8; 32], [u8; 32]) {
    let slots = 256u64;
    let mut seen: Vec<(u64, [u8; 32])> = Vec::new();
    for i in 0u16..4096 {
        let sh = script_hash(&i.to_le_bytes());
        let key = rbitcoin_store::scripthash_layout::head_key_from_full(&sh);
        let slot = ScriptHashHead::hash_slot(&key, slots);
        let page = (FILE_HEADER_LEN as u64 + slot * SH_HEAD_SLOT_SIZE as u64) / 4096;
        if let Some((_, other)) = seen.iter().find(|(p, k)| *p == page && *k != sh) {
            return (*other, sh);
        }
        seen.push((page, sh));
    }
    panic!("no two scripts shared an ingest page");
}

/// A suffix unlink whose head-word write mixed a neighbor slot restores it.
#[test]
fn suffix_unlink_restores_a_neighbor_head_word() {
    let dir = tmp();
    let (a, b) = neighbor_scripts();
    let n = SH_PAGE_STREAM_MAX as u64 + 400;
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        let many: Vec<_> = (1..=n).map(|i| rec(a, i)).collect();
        t.put_create_batch_append(&many).unwrap();
        put_create_batch(&t, [rec(b, 1)]);
        t.flush().unwrap();
        let ingest = ingest_path(&dir);
        let off_b = t
            .ingest
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .value_word_offset(&b)
            .unwrap()
            .unwrap();
        t.fail_next_sh_guard_clear();
        let tail: Vec<Fk> = ((n - 399)..=n).map(Fk).collect();
        let err = t.unlink_creates(&a, &tail).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
        assert!(!sh_marks(&dir).is_empty(), "the crash leaves the mark");
        tear_bytes(&ingest, off_b, 8);
        drop(t);
    }
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert!(sh_marks(&dir).is_empty(), "open removes the mark");
    assert_eq!(create_fks(&t, &b), vec![1]);
    assert_eq!(create_fks(&t, &a).len(), n as usize);
}

/// A slab overwrite that mixed the neighbor slab restores that slab.
#[test]
fn slab_overwrite_restores_the_neighbor_slab() {
    let dir = tmp();
    let a = script_hash(&[0x11]);
    let b = script_hash(&[0x12]);
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        put_create_batch(&t, [rec(a, 1), rec(a, 2)]);
        put_create_batch(&t, [rec(b, 1), rec(b, 2)]);
        t.flush().unwrap();
        let ShHeadValue::Slab { off: off_b, .. } = t.head_value(&b).unwrap().unwrap() else {
            panic!("two creates must be a slab");
        };
        let body = t.ovf_file().path().to_path_buf();
        t.fail_next_sh_guard_clear();
        let err = t
            .put_create_batch_append(&[rec(a, 3), rec(a, 4)])
            .unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
        assert!(!sh_marks(&dir).is_empty(), "the crash leaves the mark");
        tear_bytes(&body, off_b, 16);
        drop(t);
    }
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert_eq!(create_fks(&t, &b), vec![1, 2]);
    assert_eq!(create_fks(&t, &a), vec![1, 2]);
}

/// A guard that includes page 0 restores a pre-commit free list.
#[test]
fn page0_guard_restores_the_free_list_and_hides_the_bump() {
    let dir = tmp();
    let path = dir.path().to_path_buf();
    let a = script_hash(&[0x21]);
    let b = script_hash(&[0x22]);
    let freed;
    {
        let s = Store::create_tiny(&path).unwrap();
        put_create_batch(&s.scripthash, [rec(a, 1), rec(a, 2)]);
        let ShHeadValue::Slab { off, .. } = s.scripthash.head_value(&a).unwrap().unwrap() else {
            panic!("two creates must be a slab");
        };
        freed = off;
        put_create_batch(&s.scripthash, [rec(a, 3), rec(a, 4)]);
        s.scripthash.flush().unwrap();
        let free = rbitcoin_store::scripthash::read_alloc_header(s.scripthash.ovf_file())
            .unwrap()
            .0
            .free_head[0];
        assert_eq!(free, freed, "class change did not free the old slab");
        s.scripthash.fail_next_sh_guard_clear();
        let err = s
            .scripthash
            .put_create_batch_append(&[rec(b, 10), rec(b, 11)])
            .unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
        assert!(!sh_marks(&path).is_empty(), "the crash leaves the mark");
        tear_bytes(s.scripthash.ovf_file().path(), 0, SH_PAGE_SIZE);
        drop(s);
    }
    let s = Store::open_tiny(&path).unwrap();
    assert!(sh_marks(&path).is_empty(), "open removes the mark");
    assert!(
        s.scripthash.head_value(&b).unwrap().is_none(),
        "the head names the discarded bump"
    );
    let free = rbitcoin_store::scripthash::read_alloc_header(s.scripthash.ovf_file())
        .unwrap()
        .0
        .free_head[0];
    assert_eq!(
        free, freed,
        "page 0 did not restore the pre-commit free list"
    );
}

/// A wipe leaves no `store/guard/sh-*`.
#[test]
fn wipe_leaves_no_sh_marks() {
    let dir = tmp();
    let t = ScriptHashTable::create_tiny(&dir).unwrap();
    t.fail_next_sh_guard_clear();
    let err = t
        .put_create_batch_append(&[rec(script_hash(&[0x31]), 1)])
        .unwrap_err();
    assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
    assert!(!sh_marks(&dir).is_empty());
    t.reinit_empty_for_cold_materialize().unwrap();
    assert!(sh_marks(&dir).is_empty(), "wipe left a scripthash mark");
}

/// Sealed overflow with a torn page 0 still opens because restore ran first.
#[test]
fn sealed_ovf_torn_page0_opens_after_restore() {
    let dir = tmp();
    let sh = script_hash(&[0x41]);
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        put_create_batch(&t, [rec(sh, 1)]);
        let fillers: Vec<_> = (0..203u32)
            .map(|i| {
                rec(
                    script_hash(&[0x42, (i & 0xff) as u8, (i >> 8) as u8]),
                    10 + u64::from(i),
                )
            })
            .collect();
        t.put_create_batch_append(&fillers).unwrap();
        let extra = (0..=255u8)
            .map(|i| script_hash(&[0x43, i]))
            .find(|k| *k != sh)
            .unwrap();
        t.put_create_batch_append(&[rec(extra, 9000)]).unwrap();
        assert!(t.ingest.lock().unwrap().is_none(), "ingest did not seal");
        let sealed = sealed_ovf_path(&dir, 0);
        assert!(sealed.is_file());
        t.fail_next_sh_guard_clear();
        let err = t.put_create_batch_append(&[rec(sh, 2)]).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
        assert!(!sh_marks(&dir).is_empty(), "the crash leaves the mark");
        tear_bytes(&sealed, 0, 4);
        drop(t);
    }
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert!(
        !t.sealed_ovf.lock().unwrap().is_empty(),
        "restore did not run before sealed magic"
    );
    assert_eq!(create_fks(&t, &sh), vec![1]);
}

/// Two new keys that share a hash slot: the displaced slot can sit on the
/// next 4 KiB page. That page is armed before the empty-table write.
#[test]
fn empty_ingest_collision_restores_the_displaced_page() {
    let slots = rbitcoin_store::scripthash::ingest_oa_slots(rbitcoin_store::HeadScale::Tiny);
    let (a, b, page) = displaced_pair(slots);
    let dir = tmp();
    let ingest = ingest_path(&dir);
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        t.fail_next_sh_guard_clear();
        let err = t
            .put_create_batch_append(&[rec(a, 1), rec(b, 2)])
            .unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
        assert!(ingest.is_file(), "the empty fill created ingest");
        assert!(!sh_marks(&dir).is_empty(), "the crash leaves the mark");
        tear_bytes(&ingest, page, SH_PAGE_SIZE);
        drop(t);
    }
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert!(sh_marks(&dir).is_empty(), "open removes the mark");
    let got = page_bytes(&ingest, page);
    assert_ne!(
        got,
        vec![0xffu8; SH_PAGE_SIZE],
        "the displaced ingest page stayed torn"
    );
    assert!(
        create_fks(&t, &a).is_empty() && create_fks(&t, &b).is_empty(),
        "open kept keys from the failed commit"
    );
}

/// A non-empty ingest places a second key past the first probe. That page
/// is armed before the write.
#[test]
fn nonempty_ingest_collision_restores_the_displaced_page() {
    let slots = rbitcoin_store::scripthash::ingest_oa_slots(rbitcoin_store::HeadScale::Tiny);
    let (a, b, page) = displaced_pair(slots);
    let dir = tmp();
    let ingest = ingest_path(&dir);
    let prior = script_hash(&[0xff, 0xfe, 0xfd]);
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        put_create_batch(&t, [rec(prior, 7)]);
        t.fail_next_sh_guard_clear();
        let err = t
            .put_create_batch_append(&[rec(a, 1), rec(b, 2)])
            .unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
        assert!(!sh_marks(&dir).is_empty(), "the crash leaves the mark");
        tear_bytes(&ingest, page, SH_PAGE_SIZE);
        drop(t);
    }
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert!(sh_marks(&dir).is_empty(), "open removes the mark");
    let got = page_bytes(&ingest, page);
    assert_ne!(
        got,
        vec![0xffu8; SH_PAGE_SIZE],
        "the displaced ingest page stayed torn"
    );
    assert!(create_fks(&t, &a).is_empty() && create_fks(&t, &b).is_empty());
    assert_eq!(create_fks(&t, &prior), vec![7]);
}

/// `ingest.ahead` is the post-image. Open must not replay it over the mark.
#[test]
fn ahead_sidecar_does_not_override_a_restored_ingest() {
    let dir = tmp();
    let a = script_hash(&[0x51]);
    let b = script_hash(&[0x52]);
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        put_create_batch(&t, [rec(a, 1)]);
        let ingest = ingest_path(&dir);
        rbitcoin_store::scripthash_head::fail_next_scripthash_head_flush_after_ahead(&ingest);
        let err = t.put_create_batch_append(&[rec(b, 2)]).unwrap_err();
        assert!(matches!(err, StoreError::Io { .. }), "{err}");
        assert!(!sh_marks(&dir).is_empty(), "the crash leaves the mark");
        drop(t);
    }
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert!(
        t.head_value(&b).unwrap().is_none(),
        "ahead replay published the failed key"
    );
    assert_eq!(create_fks(&t, &a), vec![1]);
}

/// A batch that crosses the seal load does not publish a sealed file while
/// the page guard is still armed.
#[test]
fn seal_waits_until_the_mark_is_clear() {
    let dir = tmp();
    let prior: Vec<_> = (0..204u32)
        .map(|i| rec(script_hash(&i.to_le_bytes()), 1))
        .collect();
    let new_a = script_hash(&[0x61, 0x01]);
    let new_b = script_hash(&[0x61, 0x02]);
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        t.put_create_batch_append(&prior).unwrap();
        assert!(t.ingest.lock().unwrap().is_some(), "204 keys fit");
        t.fail_next_sh_guard_clear();
        let err = t
            .put_create_batch_append(&[rec(new_a, 3), rec(new_b, 4)])
            .unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
        assert!(!sh_marks(&dir).is_empty(), "the crash leaves the mark");
        drop(t);
    }
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert!(t.head_value(&new_a).unwrap().is_none());
    assert!(t.head_value(&new_b).unwrap().is_none());
    assert_eq!(create_fks(&t, &prior[0].scripthash), vec![1]);
}

/// Freeing an extent rewrites every page header. Each of those pages is armed.
#[test]
fn extent_free_restores_an_interior_page() {
    let dir = tmp();
    let a = script_hash(&[0x71]);
    let n = SH_PAGE_STREAM_MAX as u64 + 8;
    let body_off;
    let before;
    {
        let t = ScriptHashTable::create_tiny(&dir).unwrap();
        let many: Vec<_> = (1..=n).map(|i| rec(a, i)).collect();
        t.put_create_batch_append(&many).unwrap();
        let ShHeadValue::Extent { last_page } = t.head_value(&a).unwrap().unwrap() else {
            panic!("the key must be an extent");
        };
        let first = paged_first_from_last(t.ovf_file(), last_page).unwrap();
        assert_ne!(first, last_page, "the chain needs an interior page");
        body_off = first;
        let body = t.ovf_file().path().to_path_buf();
        before = page_bytes(&body, first);
        t.fail_next_sh_guard_clear();
        let err = t.unlink_creates(&a, &[Fk(1)]).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "{err}");
        assert!(!sh_marks(&dir).is_empty(), "the crash leaves the mark");
        tear_bytes(&body, first, 8);
        drop(t);
    }
    let t = ScriptHashTable::open_tiny(&dir).unwrap();
    assert_eq!(page_bytes(t.ovf_file().path(), body_off)[..8], before[..8]);
    assert_eq!(create_fks(&t, &a).len(), n as usize);
}

fn displaced_pair(slots: u64) -> ([u8; 32], [u8; 32], u64) {
    let mut by_slot: Vec<(u64, [u8; 32])> = Vec::new();
    for i in 0u32..20_000 {
        let sh = script_hash(&i.to_le_bytes());
        let key = rbitcoin_store::scripthash_head::ScriptHashHead::to_key(&sh);
        let slot = rbitcoin_store::scripthash_head::ScriptHashHead::hash_slot(&key, slots);
        let off = rbitcoin_store::scripthash_head::ScriptHashHead::slot_file_off(slot);
        let next = (slot + 1) & (slots - 1);
        let next_off = rbitcoin_store::scripthash_head::ScriptHashHead::slot_file_off(next);
        let page = SH_PAGE_SIZE as u64;
        let covers_next =
            (off / page) == (next_off / page) || ((off + 24 - 1) / page) == (next_off / page);
        if covers_next {
            continue;
        }
        if let Some((_, other)) = by_slot.iter().find(|(s, k)| *s == slot && *k != sh) {
            return (*other, sh, (next_off / page) * page);
        }
        by_slot.push((slot, sh));
    }
    panic!("no two scripts collided onto a slot whose next page is unimaged");
}
