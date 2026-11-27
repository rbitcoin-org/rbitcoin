//! A synced Class A tail block torn to zeroes on the next append.
use rbitcoin_primitives::Fk;
use rbitcoin_store::error::StoreError;
use rbitcoin_store::store::Store;
use rbitcoin_store::tx_table::{InputRecord, OutputRecord, TxRecord, TxTable};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

fn tmp() -> std::path::PathBuf {
    let p = rbitcoin_store::testutil::fresh_path("class-a-tail");
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn coinbase(txid: [u8; 32]) -> (TxRecord, Vec<InputRecord>, Vec<OutputRecord>) {
    (
        TxRecord {
            txid,
            version: 1,
            locktime: 0,
            input_count: 1,
            output_count: 1,
        },
        vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
        vec![OutputRecord::unspent(50, vec![0x51])],
    )
}

/// Zero the 4 KiB block that holds the file's published end.
fn zero_published_tail_block(path: &Path) {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut header = [0u8; 16];
    std::io::Read::read_exact(&mut file, &mut header).unwrap();
    let logical = u64::from_le_bytes(header[8..16].try_into().unwrap());
    let block = logical & !4095;
    assert!(
        block >= 4096,
        "tail block {block} includes the file header (logical {logical})"
    );
    file.seek(SeekFrom::Start(block)).unwrap();
    file.write_all(&[0u8; 4096]).unwrap();
    file.sync_all().unwrap();
}

/// 128 creates fill `txid.body` to 4 KiB + 32, so create 128 sits in the
/// partial tail. A later append rewrites that block. Zeroing it is the
/// power cut. Open must still return the synced txid.
#[test]
fn torn_synced_tail_keeps_the_named_txid() {
    let dir = tmp();
    let named = 128u64;
    let txid = [0x80u8; 32];
    {
        let s = Store::create_tiny(&dir).unwrap();
        let batch: Vec<_> = (1..=named)
            .map(|i| {
                let mut id = [i as u8; 32];
                if i == named {
                    id = txid;
                }
                coinbase(id)
            })
            .collect();
        s.put_tx_full_batch_indexed(&batch, false).unwrap();
        s.txs.sync_class_a_named(named).unwrap();
        assert_eq!(s.txs.txids.get(Fk(named)).unwrap(), txid);
        let logical = s.txs.txids.logical_len();
        assert_ne!(
            logical % 4096,
            0,
            "txid.body ends on a block boundary, so the next append does not rewrite a partial tail"
        );
        s.put_tx_full_batch_indexed(&[coinbase([0x81u8; 32])], false)
            .unwrap();
    }
    zero_published_tail_block(&dir.join("txid.body"));
    let s = Store::open_tiny(&dir).unwrap();
    let got = s.txs.txids.get(Fk(named)).unwrap();
    assert_eq!(got, txid, "named txid became {got:?}");
    assert_eq!(s.get_tx(Fk(named)).unwrap().txid, txid);
    let _ = std::fs::remove_dir_all(&dir);
}

const PAGE: usize = 4096;
const TAIL_BYTES: usize = 17 * PAGE;
const FIRST_BYTES: usize = 32 * PAGE;
/// `txid.body` in the Class A sync order.
const TXID_STEM: usize = 9;
/// `spent.body` in the Class A sync order.
const SPENT_STEM: usize = 2;

fn plant_armed(dir: &Path, generation: u64) {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(b"CARM");
    buf.extend_from_slice(&rbitcoin_primitives::SCHEMA_VERSION.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.extend_from_slice(&generation.to_le_bytes());
    let path = dir.join("tear_guard/armed");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, buf).unwrap();
}

fn write_meta_ver(dir: &Path, ver: u16) {
    let mut meta = std::fs::read(dir.join("meta")).unwrap();
    meta[4..6].copy_from_slice(&ver.to_le_bytes());
    std::fs::write(dir.join("meta"), meta).unwrap();
}

fn meta_ver(dir: &Path) -> u16 {
    let meta = std::fs::read(dir.join("meta")).unwrap();
    u16::from_le_bytes(meta[4..6].try_into().unwrap())
}

fn logical_of(path: &Path) -> u64 {
    let mut header = [0u8; 16];
    let mut file = std::fs::File::open(path).unwrap();
    std::io::Read::read_exact(&mut file, &mut header).unwrap();
    u64::from_le_bytes(header[8..16].try_into().unwrap())
}

fn read_at(path: &Path, offset: u64, buf: &mut [u8]) {
    let mut file = std::fs::File::open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    std::io::Read::read_exact(&mut file, buf).unwrap();
}

fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    use bitcoin_hashes::{sha256, Hash, HashEngine};
    let mut eng = sha256::HashEngine::default();
    for part in parts {
        eng.input(part);
    }
    sha256::Hash::from_engine(eng).to_byte_array()
}

fn checksum_tail(buf: &[u8]) -> [u8; 32] {
    sha256_parts(&[&buf[..24], &buf[56..]])
}

/// One tail slot. `images` is `(stem, published, tail_off, prefix)`.
fn plant_tail(path: &Path, generation: u64, named: u64, images: &[(usize, u64, u64, &[u8])]) {
    let mut buf = vec![0u8; TAIL_BYTES];
    buf[0..4].copy_from_slice(b"CAPT");
    buf[4..6].copy_from_slice(&1u16.to_le_bytes());
    buf[6..8].copy_from_slice(&16u16.to_le_bytes());
    buf[8..16].copy_from_slice(&generation.to_le_bytes());
    buf[16..24].copy_from_slice(&named.to_le_bytes());
    for (stem, published, tail_off, image) in images {
        let head = 56 + stem * 16;
        buf[head..head + 8].copy_from_slice(&published.to_le_bytes());
        buf[head + 8..head + 16].copy_from_slice(&tail_off.to_le_bytes());
        let len_at = 312 + stem * 2;
        let n = u16::try_from(image.len()).unwrap();
        buf[len_at..len_at + 2].copy_from_slice(&n.to_le_bytes());
        let page = PAGE + stem * PAGE;
        buf[page..page + image.len()].copy_from_slice(image);
    }
    let sum = checksum_tail(&buf);
    buf[24..56].copy_from_slice(&sum);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, &buf).unwrap();
}

fn plant_first(path: &Path, stem: usize, page: &[u8]) {
    assert_eq!(page.len(), PAGE);
    let mut buf = vec![0u8; FIRST_BYTES];
    let image_at = stem * 2 * PAGE;
    buf[image_at..image_at + PAGE].copy_from_slice(page);
    let commit_at = image_at + PAGE;
    buf[commit_at..commit_at + 4].copy_from_slice(b"CAPF");
    buf[commit_at + 4..commit_at + 6].copy_from_slice(&(stem as u16).to_le_bytes());
    buf[commit_at + 6..commit_at + 8].copy_from_slice(&4096u16.to_le_bytes());
    let image_sum = sha256_parts(&[page]);
    buf[commit_at + 8..commit_at + 40].copy_from_slice(&image_sum);
    let commit_sum = sha256_parts(&[&buf[commit_at..commit_at + 40]]);
    buf[commit_at + 40..commit_at + 72].copy_from_slice(&commit_sum);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, &buf).unwrap();
}

fn zero_page0(path: &Path) {
    let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    file.write_all(&[0u8; PAGE]).unwrap();
    file.sync_all().unwrap();
}

fn synced_txid_past_page(named: u64) -> (std::path::PathBuf, [u8; 32]) {
    let dir = tmp();
    let txid = [0x80u8; 32];
    let s = Store::create_tiny(&dir).unwrap();
    let batch: Vec<_> = (1..=named)
        .map(|i| {
            let mut id = [i as u8; 32];
            if i == named {
                id = txid;
            }
            coinbase(id)
        })
        .collect();
    s.put_tx_full_batch_indexed(&batch, false).unwrap();
    s.txs.sync_class_a_named(named).unwrap();
    let logical = s.txs.txids.logical_len();
    assert!(logical > 4096, "txid.body published {logical}");
    assert_ne!(logical % 4096, 0);
    drop(s);
    (dir, txid)
}

/// A hand-built tail slot is the only copy. Open puts that prefix back.
#[test]
fn torn_tail_restored_from_hand_built_slot() {
    let named = 128u64;
    let (dir, txid) = synced_txid_past_page(named);
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    let off = published & !4095;
    let n = (published - off) as usize;
    let mut image = vec![0u8; n];
    read_at(&body, off, &mut image);
    plant_tail(
        &dir.join("tear_guard/tail.0"),
        1,
        named,
        &[(TXID_STEM, published, off, &image)],
    );
    zero_published_tail_block(&body);
    let s = Store::open_tiny(&dir).unwrap();
    let got = s.txs.txids.get(Fk(named)).unwrap();
    assert_eq!(got, txid, "named txid became {got:?}");
    assert_eq!(s.txs.txids.logical_len(), published);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Page 0 comes back from `first`. The length comes from the tail header,
/// which is newer than the length frozen in that page.
#[test]
fn zeroed_page0_takes_tail_header_length() {
    let named = 128u64;
    let dir = tmp();
    let first_id = [0x11u8; 32];
    let s = Store::create_tiny(&dir).unwrap();
    let batch: Vec<_> = (1..=named)
        .map(|i| {
            let id = if i == 1 { first_id } else { [i as u8; 32] };
            coinbase(id)
        })
        .collect();
    s.put_tx_full_batch_indexed(&batch, false).unwrap();
    s.txs.sync_class_a_named(named).unwrap();
    let body = dir.join("txid.body");
    let mut frozen = [0u8; PAGE];
    read_at(&body, 0, &mut frozen);
    let frozen_len = u64::from_le_bytes(frozen[8..16].try_into().unwrap());
    s.put_tx_full_batch_indexed(&[coinbase([0x81u8; 32])], false)
        .unwrap();
    s.txs.sync_class_a_named(named + 1).unwrap();
    let published = s.txs.txids.logical_len();
    assert!(published > frozen_len);
    drop(s);
    let off = published & !4095;
    let n = (published - off) as usize;
    let mut image = vec![0u8; n];
    read_at(&body, off, &mut image);
    let guard = dir.join("tear_guard");
    plant_first(&guard.join("first"), TXID_STEM, &frozen);
    plant_tail(
        &guard.join("tail.0"),
        1,
        named + 1,
        &[(TXID_STEM, published, off, &image)],
    );
    zero_page0(&body);
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.get(Fk(1)).unwrap(), first_id);
    assert_eq!(s.txs.txids.logical_len(), published);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Both slots fail the checksum and `first` has no commit. A zeroed tail stops open.
#[test]
fn checksum_bad_tail_over_zeroes_refuses_open() {
    let named = 128u64;
    let (dir, _txid) = synced_txid_past_page(named);
    let guard = dir.join("tear_guard");
    std::fs::create_dir_all(&guard).unwrap();
    // CAPT with a bad checksum. A non-CAPT filler is rewritten to generation 0
    // and never reaches the checksum compare.
    plant_tail(
        &guard.join("tail.0"),
        1,
        named,
        &[(TXID_STEM, 4160, 4096, &[0x11u8; 64])],
    );
    plant_tail(
        &guard.join("tail.1"),
        2,
        named,
        &[(TXID_STEM, 4160, 4096, &[0x22u8; 64])],
    );
    for name in ["tail.0", "tail.1"] {
        let path = guard.join(name);
        let mut raw = std::fs::read(&path).unwrap();
        raw[24] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
    }
    std::fs::write(guard.join("first"), vec![0u8; FIRST_BYTES]).unwrap();
    zero_published_tail_block(&dir.join("txid.body"));
    match Store::open_tiny(&dir) {
        Ok(_) => panic!("open kept a zeroed named tail"),
        Err(err) => assert!(
            err.to_string().contains("does not decode"),
            "open kept a zeroed named tail: {err}"
        ),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

fn generation_of(path: &Path) -> u64 {
    let mut buf = [0u8; 16];
    read_at(path, 0, &mut buf);
    u64::from_le_bytes(buf[8..16].try_into().unwrap())
}

fn tail_len_of(path: &Path, stem: usize) -> u16 {
    let mut buf = [0u8; 2];
    read_at(path, (312 + stem * 2) as u64, &mut buf);
    u16::from_le_bytes(buf)
}

fn first_image(path: &Path, stem: usize) -> Vec<u8> {
    let mut buf = vec![0u8; PAGE];
    read_at(path, (stem * 2 * PAGE) as u64, &mut buf);
    buf
}

fn first_commit_checks(path: &Path, stem: usize) -> bool {
    let mut commit = vec![0u8; PAGE];
    read_at(path, (stem * 2 * PAGE + PAGE) as u64, &mut commit);
    if &commit[0..4] != b"CAPF" {
        return false;
    }
    let image = first_image(path, stem);
    let image_sum = sha256_parts(&[&image]);
    if commit[8..40] != image_sum {
        return false;
    }
    let commit_sum = sha256_parts(&[&commit[..40]]);
    commit[40..72] == commit_sum
}

/// The first barrier writes `tail.0` and seals `txid.body`. `spent.body` has no tail image.
#[test]
fn first_barrier_seals_first_and_writes_tail0() {
    let named = 128u64;
    let (dir, txid) = synced_txid_past_page(named);
    let guard = dir.join("tear_guard");
    assert_eq!(generation_of(&guard.join("tail.0")), 1);
    assert_eq!(generation_of(&guard.join("tail.1")), 0);
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    let off = published & !4095;
    let n = (published - off) as usize;
    assert_eq!(tail_len_of(&guard.join("tail.0"), TXID_STEM) as usize, n);
    let mut image = vec![0u8; n];
    read_at(
        &guard.join("tail.0"),
        (PAGE + TXID_STEM * PAGE) as u64,
        &mut image,
    );
    let mut live = vec![0u8; n];
    read_at(&body, off, &mut live);
    assert_eq!(image, live);
    assert!(first_commit_checks(&guard.join("first"), TXID_STEM));
    let spent_len = logical_of(&dir.join("spent.body"));
    let spent_file = std::fs::metadata(dir.join("spent.body")).unwrap().len();
    assert!(
        spent_len > spent_file,
        "spent.body reached its published end"
    );
    assert_eq!(tail_len_of(&guard.join("tail.0"), 2), 0);
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.get(Fk(named)).unwrap(), txid);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A later barrier writes the other slot and leaves the sealed page alone.
#[test]
fn second_barrier_alternates_and_keeps_first() {
    let named = 128u64;
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    let batch: Vec<_> = (1..=named).map(|i| coinbase([i as u8; 32])).collect();
    s.put_tx_full_batch_indexed(&batch, false).unwrap();
    s.txs.sync_class_a_named(named).unwrap();
    let guard = dir.join("tear_guard");
    let tail0 = std::fs::read(guard.join("tail.0")).unwrap();
    let sealed = first_image(&guard.join("first"), TXID_STEM);
    s.put_tx_full_batch_indexed(&[coinbase([0x81u8; 32])], false)
        .unwrap();
    s.txs.sync_class_a_named(named + 1).unwrap();
    assert_eq!(generation_of(&guard.join("tail.1")), 2);
    assert_eq!(std::fs::read(guard.join("tail.0")).unwrap(), tail0);
    assert_eq!(first_image(&guard.join("first"), TXID_STEM), sealed);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A txstat stamp in page 0 does not refresh the sealed image.
#[test]
fn txstat_stamp_does_not_rewrite_first() {
    let dir = tmp();
    let n = 510u64;
    let s = Store::create_tiny(&dir).unwrap();
    let batch: Vec<_> = (1..=n).map(|i| coinbase([i as u8; 32])).collect();
    s.put_tx_full_batch_indexed(&batch, false).unwrap();
    s.txs.sync_class_a_named(n).unwrap();
    assert!(logical_of(&dir.join("txstat.body")) >= 4096);
    let before = first_image(&dir.join("tear_guard/first"), 10);
    s.write_txstat_row(
        Fk(1),
        &rbitcoin_store::TxStatRow {
            fee_sat: 1,
            base: 100,
            wit_extra: 0,
        },
    )
    .unwrap();
    s.txs.sync_class_a_named(n).unwrap();
    assert_eq!(first_image(&dir.join("tear_guard/first"), 10), before);
    drop(s);
    zero_page0(&dir.join("txstat.body"));
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txstat_row(Fk(1)).unwrap(), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Deleting the guard and reopening seals `first` and writes generation 1 before any append.
#[test]
fn reopen_without_guard_seals_before_append() {
    let (dir, _txid) = synced_txid_past_page(128);
    std::fs::remove_dir_all(dir.join("tear_guard")).unwrap();
    let s = Store::open_tiny(&dir).unwrap();
    drop(s);
    let guard = dir.join("tear_guard");
    assert!(first_commit_checks(&guard.join("first"), TXID_STEM));
    assert_eq!(generation_of(&guard.join("tail.0")), 1);
    assert_eq!(generation_of(&guard.join("tail.1")), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tail that still holds bytes is left, including when the slots do not check.
#[test]
fn nonzero_tail_left_in_place() {
    let named = 128u64;
    let (dir, txid) = synced_txid_past_page(named);
    let guard = dir.join("tear_guard");
    std::fs::create_dir_all(&guard).unwrap();
    std::fs::write(guard.join("tail.0"), vec![0x5au8; TAIL_BYTES]).unwrap();
    std::fs::write(guard.join("tail.1"), vec![0x5au8; TAIL_BYTES]).unwrap();
    std::fs::write(guard.join("first"), vec![0u8; FIRST_BYTES]).unwrap();
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.get(Fk(named)).unwrap(), txid);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An append plus a Class A sync does not leave a per-stem `.kept` file.
#[test]
fn append_and_sync_leave_no_kept_sidecar() {
    let named = 128u64;
    let (dir, _txid) = synced_txid_past_page(named);
    let s = Store::open_tiny(&dir).unwrap();
    s.put_tx_full_batch_indexed(&[coinbase([0x81u8; 32])], false)
        .unwrap();
    s.txs.sync_class_a_named(named + 1).unwrap();
    drop(s);
    assert!(!dir.join("txid.body.kept").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A prebuilt `CATK` copy is the only image. Open restores it once and unlinks it.
#[test]
fn leftover_catk_restores_a_zeroed_tail_once() {
    let named = 128u64;
    let (dir, txid) = synced_txid_past_page(named);
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    let off = published & !4095;
    let n = (published - off) as usize;
    let mut image = vec![0u8; n];
    read_at(&body, off, &mut image);
    let mut kept = Vec::new();
    kept.extend_from_slice(b"CATK");
    kept.extend_from_slice(&off.to_le_bytes());
    kept.extend_from_slice(&(n as u32).to_le_bytes());
    kept.extend_from_slice(&image);
    std::fs::write(dir.join("txid.body.kept"), &kept).unwrap();
    zero_published_tail_block(&body);
    // The barrier's slot would also restore this prefix. Wipe it so the copy is the image.
    let guard = dir.join("tear_guard");
    std::fs::write(guard.join("tail.0"), vec![0u8; TAIL_BYTES]).unwrap();
    std::fs::write(guard.join("tail.1"), vec![0u8; TAIL_BYTES]).unwrap();
    std::fs::write(guard.join("first"), vec![0u8; FIRST_BYTES]).unwrap();
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.get(Fk(named)).unwrap(), txid);
    assert!(!dir.join("txid.body.kept").exists());
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `seqsigwit.*` can live in a cold directory. The guard stays on the hot
/// store, and a zeroed cold first page is written back from that guard.
#[test]
fn zeroed_cold_seqsigwit_page0_restores_from_the_hot_guard() {
    let hot = tmp();
    let cold = hot.join("cold-seq");
    std::fs::create_dir_all(&cold).unwrap();
    {
        let s = Store::create_tiny(&hot).unwrap();
        s.put_tx_full_batch_indexed(&[coinbase([0x44u8; 32])], false)
            .unwrap();
        s.txs.sync_class_a_named(1).unwrap();
    }
    // A split open keeps txstat and input next to seqsigwit. The guard stays hot.
    let names: Vec<_> = std::fs::read_dir(&hot)
        .unwrap()
        .map(|ent| ent.unwrap().file_name())
        .filter(|name| {
            let name = name.to_string_lossy();
            name.starts_with("seqsigwit.")
                || name.starts_with("txstat.")
                || name.starts_with("input.")
        })
        .collect();
    assert!(
        names.iter().any(|name| name == "seqsigwit.body"),
        "seqsigwit.body was not created"
    );
    let src = hot.join("seqsigwit.body");
    let before = std::fs::read(&src).unwrap();
    let n = before.len().min(PAGE);
    assert!(n > 0 && before[..n].iter().any(|b| *b != 0));
    for name in &names {
        std::fs::rename(hot.join(name), cold.join(name)).unwrap();
    }
    let cold_body = cold.join("seqsigwit.body");
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&cold_body)
            .unwrap();
        file.write_all(&vec![0u8; n]).unwrap();
        file.sync_all().unwrap();
    }
    let table = rbitcoin_store::tx_table::TxTable::open_seqsigwit(
        &hot,
        &cold,
        rbitcoin_store::HeadOpenOpts::TINY,
        Some(rbitcoin_store::tx_table::OpenedFromStore {
            committed: 1,
            schema: rbitcoin_primitives::SCHEMA_VERSION,
        }),
    )
    .unwrap();
    drop(table);
    assert!(hot.join("tear_guard/first").is_file());
    assert!(hot.join("tear_guard/tail.0").is_file() || hot.join("tear_guard/tail.1").is_file());
    assert!(!cold.join("tear_guard").exists());
    let after = std::fs::read(&cold_body).unwrap();
    assert_eq!(&after[..n], &before[..n]);
    let _ = std::fs::remove_dir_all(&hot);
}

/// A store written before `tear_guard` can have a published tail of zeros.
/// A coinbase edge packs as eight zero bytes, and an unstamped txstat cell is
/// zeros. Open must keep those bytes when no slot exists yet.
#[test]
fn open_without_guard_keeps_a_zero_coinbase_tail() {
    let dir = tmp();
    let n = 511u64;
    {
        let s = Store::create_tiny(&dir).unwrap();
        let batch: Vec<_> = (1..=n).map(|i| coinbase([i as u8; 32])).collect();
        s.put_tx_full_batch_indexed(&batch, false).unwrap();
        s.txs.sync_class_a_named(n).unwrap();
    }
    let input = dir.join("input.body");
    let txstat = dir.join("txstat.body");
    assert!(logical_of(&input) > 4096);
    assert!(logical_of(&txstat) > 4096);
    std::fs::remove_dir_all(dir.join("tear_guard")).unwrap();
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(
        s.input_edges(Fk(n)).unwrap(),
        Some(vec![rbitcoin_store::input::InputEdge::coinbase()])
    );
    assert_eq!(s.txstat_row(Fk(n)).unwrap(), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty seqsigwit is an 8-byte zero pad so loc strides stay monotone.
/// With no tail slot yet, that tail is the data.
#[test]
fn open_without_guard_keeps_a_zero_empty_seqsigwit_tail() {
    let dir = tmp();
    let n = 520u64;
    {
        let t = TxTable::create_tiny(&dir).unwrap();
        let batch: Vec<_> = (1..=n)
            .map(|i| {
                let mut txid = [0u8; 32];
                txid[0] = i as u8;
                txid[1] = (i >> 8) as u8;
                (
                    TxRecord {
                        txid,
                        version: 1,
                        locktime: 0,
                        input_count: 0,
                        output_count: 1,
                    },
                    Vec::new(),
                    vec![OutputRecord::unspent(0, vec![0x51])],
                )
            })
            .collect();
        t.put_full_batch_indexed(&batch, false).unwrap();
        t.flush().unwrap();
        assert!(logical_of(&dir.join("seqsigwit.body")) > 4096);
    }
    let _ = std::fs::remove_dir_all(dir.join("tear_guard"));
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), n);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unspent slots are zero bytes. A pre-schema-30 `spent.body` is filled out
/// to its published end, so the last page is those zeros. With no tail slot
/// yet, open keeps them.
#[test]
fn open_without_guard_keeps_a_zero_unspent_spent_tail() {
    let dir = tmp();
    let n_out = 600u32;
    {
        let t = TxTable::create_tiny(&dir).unwrap();
        t.put_full_batch_indexed(
            &[(
                TxRecord {
                    txid: [0x11; 32],
                    version: 1,
                    locktime: 0,
                    input_count: 1,
                    output_count: n_out,
                },
                vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
                vec![OutputRecord::unspent(1, vec![0x51]); n_out as usize],
            )],
            false,
        )
        .unwrap();
        let end = t.spent.body_published_len();
        assert!(end > 4096);
        drop(t);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("spent.body"))
            .unwrap();
        if file.metadata().unwrap().len() < end {
            file.set_len(end).unwrap();
        }
    }
    let _ = std::fs::remove_dir_all(dir.join("tear_guard"));
    let t = TxTable::open_tiny(&dir).unwrap();
    assert_eq!(t.count(), 1);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `txstat.*` and `input.*` live next to seqsigwit on a split store. A zeroed
/// cold txstat tail comes back from the hot guard.
#[test]
fn zeroed_cold_txstat_tail_restores_from_the_hot_guard() {
    let hot = tmp();
    let cold = hot.join("cold-seq");
    std::fs::create_dir_all(&cold).unwrap();
    let n = 510u64;
    let row = rbitcoin_store::TxStatRow {
        fee_sat: 7,
        base: 100,
        wit_extra: 1,
    };
    {
        let s = Store::create_tiny(&hot).unwrap();
        let batch: Vec<_> = (1..=n).map(|i| coinbase([i as u8; 32])).collect();
        s.put_tx_full_batch_indexed(&batch, false).unwrap();
        s.write_txstat_row(Fk(509), &row).unwrap();
        s.txs.sync_class_a_named(n).unwrap();
    }
    let names: Vec<_> = std::fs::read_dir(&hot)
        .unwrap()
        .map(|ent| ent.unwrap().file_name())
        .filter(|name| {
            let name = name.to_string_lossy();
            name.starts_with("seqsigwit.")
                || name.starts_with("txstat.")
                || name.starts_with("input.")
        })
        .collect();
    for name in &names {
        std::fs::rename(hot.join(name), cold.join(name)).unwrap();
    }
    let body = cold.join("txstat.body");
    let published = logical_of(&body);
    let off = published & !4095;
    assert!(off >= 4096);
    let n_tail = (published - off) as usize;
    let mut before = vec![0u8; n_tail];
    read_at(&body, off, &mut before);
    assert!(before.iter().any(|b| *b != 0));
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&body).unwrap();
        file.seek(SeekFrom::Start(off)).unwrap();
        file.write_all(&vec![0u8; n_tail]).unwrap();
        file.sync_all().unwrap();
    }
    let layout = rbitcoin_store::store::StoreLayout::tiny(&hot).with_cold_dir(&cold);
    let s = Store::open_layout(layout).unwrap();
    assert_eq!(s.txstat_row(Fk(509)).unwrap(), Some(row));
    assert!(hot.join("tear_guard/first").is_file());
    assert!(!cold.join("tear_guard").exists());
    drop(s);
    let _ = std::fs::remove_dir_all(&hot);
}

fn expect_does_not_decode(dir: &Path) {
    match Store::open_tiny(dir) {
        Ok(_) => panic!("open kept a zeroed named page"),
        Err(err) => assert!(
            err.to_string().contains("does not decode"),
            "open kept a zeroed named page: {err}"
        ),
    }
}

/// A sealed `first` image still names the txid tail when both slots fail the
/// checksum. Zeroing page 0 makes the live length 0. Open must stop, and must
/// not publish that zero tail as generation 1.
#[test]
fn sealed_first_and_bad_tails_refuse_a_zeroed_txid_tail() {
    let named = 128u64;
    let (dir, _txid) = synced_txid_past_page(named);
    let body = dir.join("txid.body");
    zero_published_tail_block(&body);
    zero_page0(&body);
    let guard = dir.join("tear_guard");
    for name in ["tail.0", "tail.1"] {
        let path = guard.join(name);
        let mut raw = std::fs::read(&path).unwrap();
        raw[24] ^= 0xff;
        std::fs::write(&path, &raw).unwrap();
    }
    expect_does_not_decode(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `plant_first` writes a valid CAPF checksum. A flipped commit checksum over a
/// zeroed page 0 must still stop open. Deleting the commit compare would
/// restore the image and this open would succeed.
#[test]
fn checksum_bad_first_over_zeroed_page0_refuses_open() {
    let (dir, _txid) = synced_txid_past_page(128);
    let first = dir.join("tear_guard/first");
    let mut raw = std::fs::read(&first).unwrap();
    let commit_at = TXID_STEM * 2 * PAGE + PAGE;
    raw[commit_at + 40] ^= 0xff;
    std::fs::write(&first, &raw).unwrap();
    zero_page0(&dir.join("txid.body"));
    expect_does_not_decode(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The image hash inside an otherwise valid CAPF commit does not match.
/// Deleting that compare would write the image back and this open would succeed.
#[test]
fn image_hash_bad_first_over_zeroed_page0_refuses_open() {
    let (dir, _txid) = synced_txid_past_page(128);
    let first = dir.join("tear_guard/first");
    let mut raw = std::fs::read(&first).unwrap();
    let commit_at = TXID_STEM * 2 * PAGE + PAGE;
    raw[commit_at + 8] ^= 0xff;
    let sum = sha256_parts(&[&raw[commit_at..commit_at + 40]]);
    raw[commit_at + 40..commit_at + 72].copy_from_slice(&sum);
    std::fs::write(&first, &raw).unwrap();
    zero_page0(&dir.join("txid.body"));
    expect_does_not_decode(&dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A checksum-valid slot whose prefix differs from the live tail must not
/// replace those bytes. Deleting the all-zero check in `restore_tail_block`
/// would write `0x11` over the named txid.
#[test]
fn nonzero_tail_is_not_overwritten_by_the_slot() {
    let named = 128u64;
    let (dir, txid) = synced_txid_past_page(named);
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    let off = published & !4095;
    let n = (published - off) as usize;
    let junk = vec![0x11u8; n];
    plant_tail(
        &dir.join("tear_guard/tail.0"),
        3,
        named,
        &[(TXID_STEM, published, off, &junk)],
    );
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.get(Fk(named)).unwrap(), txid);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `first` names a longer length than the tail slot. Open keeps the slot
/// length and puts the zeroed tail back.
#[test]
fn torn_page0_length_does_not_outrun_the_tail_slot() {
    let named = 128u64;
    let (dir, txid) = synced_txid_past_page(named);
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    let off = published & !4095;
    let n = (published - off) as usize;
    let mut tail = vec![0u8; n];
    read_at(&body, off, &mut tail);
    let mut page0 = [0u8; PAGE];
    read_at(&body, 0, &mut page0);
    let torn = published + 4096;
    page0[8..16].copy_from_slice(&torn.to_le_bytes());
    let guard = dir.join("tear_guard");
    plant_first(&guard.join("first"), TXID_STEM, &page0);
    plant_tail(
        &guard.join("tail.0"),
        4,
        named,
        &[(TXID_STEM, published, off, &tail)],
    );
    zero_published_tail_block(&body);
    zero_page0(&body);
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.logical_len(), published);
    assert_eq!(s.txs.txids.get(Fk(named)).unwrap(), txid);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The page-0 tail image names a longer length than the slot header. Open
/// writes the slot length over that image.
#[test]
fn torn_page0_tail_image_keeps_the_slot_length() {
    let dir = tmp();
    let txid = [0x44u8; 32];
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[coinbase(txid)], false)
            .unwrap();
        s.txs.sync_class_a_named(1).unwrap();
    }
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    assert!(published > 16 && published < 4096, "published {published}");
    let n = published as usize;
    let mut image = vec![0u8; n];
    read_at(&body, 0, &mut image);
    // Past this page, so the adopted header asks for a tail the slot does not hold.
    let torn: u64 = 4096 + 32;
    image[8..16].copy_from_slice(&torn.to_le_bytes());
    let file = std::fs::OpenOptions::new().write(true).open(&body).unwrap();
    file.set_len(torn).unwrap();
    file.sync_all().unwrap();
    plant_tail(
        &dir.join("tear_guard/tail.0"),
        4,
        1,
        &[(TXID_STEM, published, 0, &image)],
    );
    std::fs::write(dir.join("tear_guard/first"), vec![0u8; FIRST_BYTES]).unwrap();
    zero_page0(&body);
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.logical_len(), published);
    assert_eq!(s.txs.txids.get(Fk(1)).unwrap(), txid);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Page 0 already holds the slot image, and that image's length is longer
/// than the slot. That is the first restore write without the length write.
/// Open must keep the slot length. The length is not a whole extra txid, so
/// count repair does not put it back.
#[test]
fn torn_page0_image_keeps_the_slot_length_without_a_second_write() {
    let dir = tmp();
    let txid = [0x44u8; 32];
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[coinbase(txid)], false)
            .unwrap();
        s.txs.sync_class_a_named(1).unwrap();
    }
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    assert!(published > 16 && published < 4096, "published {published}");
    let n = published as usize;
    let mut image = vec![0u8; n];
    read_at(&body, 0, &mut image);
    let torn = published + 16;
    image[8..16].copy_from_slice(&torn.to_le_bytes());
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&body).unwrap();
        file.write_all(&image).unwrap();
        file.set_len(torn).unwrap();
        file.sync_all().unwrap();
    }
    plant_tail(
        &dir.join("tear_guard/tail.0"),
        4,
        1,
        &[(TXID_STEM, published, 0, &image)],
    );
    std::fs::write(dir.join("tear_guard/first"), vec![0u8; FIRST_BYTES]).unwrap();
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.logical_len(), published);
    assert_eq!(s.txs.txids.get(Fk(1)).unwrap(), txid);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Bytes past the slot image are a later append. Open must not write the
/// shorter slot length over that page.
#[test]
fn page0_bytes_past_the_slot_image_stay() {
    let dir = tmp();
    let first = [0x44u8; 32];
    let second = [0x55u8; 32];
    {
        let s = Store::create_tiny(&dir).unwrap();
        s.put_tx_full_batch_indexed(&[coinbase(first), coinbase(second)], false)
            .unwrap();
        s.txs.sync_class_a_named(2).unwrap();
    }
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    let first_end = published - 32;
    assert!(first_end > 16 && first_end < published);
    let mut image = vec![0u8; first_end as usize];
    read_at(&body, 0, &mut image);
    image[8..16].copy_from_slice(&published.to_le_bytes());
    plant_tail(
        &dir.join("tear_guard/tail.0"),
        4,
        2,
        &[(TXID_STEM, first_end, 0, &image)],
    );
    std::fs::write(dir.join("tear_guard/first"), vec![0u8; FIRST_BYTES]).unwrap();
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.logical_len(), published);
    assert_eq!(s.txs.txids.get(Fk(1)).unwrap(), first);
    assert_eq!(s.txs.txids.get(Fk(2)).unwrap(), second);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A nonzero mix is the tear `armed` exists to undo. Open copies generation
/// 4 back, including page 0, and does not take the newer slot's bytes.
#[test]
fn armed_nonzero_mix_restores_generation_n_and_ignores_a_newer_slot() {
    let named = 128u64;
    let (dir, txid) = synced_txid_past_page(named);
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    let off = published & !4095;
    let n = (published - off) as usize;
    let mut image = vec![0u8; n];
    read_at(&body, off, &mut image);
    let mut newer = image.clone();
    if !newer.is_empty() {
        newer[0] ^= 0xff;
    }
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&body).unwrap();
        file.seek(SeekFrom::Start(off)).unwrap();
        file.write_all(&vec![0x11u8; n]).unwrap();
        file.seek(SeekFrom::Start(32)).unwrap();
        file.write_all(&[0x11u8; 32]).unwrap();
        file.sync_all().unwrap();
    }
    plant_tail(
        &dir.join("tear_guard/tail.0"),
        4,
        named,
        &[(TXID_STEM, published, off, &image)],
    );
    plant_tail(
        &dir.join("tear_guard/tail.1"),
        9,
        named,
        &[(TXID_STEM, published, off, &newer)],
    );
    plant_armed(&dir, 4);
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.get(Fk(named)).unwrap(), txid);
    assert_eq!(s.txs.txids.get(Fk(1)).unwrap(), [1u8; 32]);
    assert!(!dir.join("tear_guard/armed").exists());
    let mut magic = [0u8; 4];
    read_at(&dir.join("tear_guard/tail.1"), 0, &mut magic);
    assert_eq!(magic, [0, 0, 0, 0], "newer slot must not stay trusted");
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// No `armed` file: a deliberate nonzero mix stays, and a zero tail still
/// comes back from the slot.
#[test]
fn unmarked_nonzero_mix_stays_and_a_zero_tail_still_restores() {
    let named = 128u64;
    let (dir, txid) = synced_txid_past_page(named);
    let body = dir.join("txid.body");
    let published = logical_of(&body);
    let off = published & !4095;
    let n = (published - off) as usize;
    assert!(!dir.join("tear_guard/armed").exists());
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&body).unwrap();
        file.seek(SeekFrom::Start(off)).unwrap();
        file.write_all(&vec![0x11u8; n]).unwrap();
        file.sync_all().unwrap();
    }
    let s = Store::open_tiny(&dir).unwrap();
    let mut got = vec![0u8; n];
    read_at(&body, off, &mut got);
    assert_eq!(got, vec![0x11u8; n]);
    drop(s);
    zero_published_tail_block(&body);
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(s.txs.txids.get(Fk(named)).unwrap(), txid);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The arm rename is refused while meta is 30. A plain open does not
/// promote 30. The append path writes 31 before it renames the mark.
#[test]
fn arm_errors_while_meta_is_30_and_plain_open_does_not_promote() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    write_meta_ver(&dir, 30);
    let err = rbitcoin_store::testutil::arm_class_a_generation(&s.txs, 1)
        .expect_err("arm while meta is 30");
    assert!(matches!(err, StoreError::Rejected(_)));
    assert!(!dir.join("tear_guard/armed").exists());
    assert_eq!(meta_ver(&dir), 30);
    drop(s);
    let s = Store::open_tiny(&dir).unwrap();
    drop(s);
    assert_eq!(meta_ver(&dir), 30);
    assert!(!dir.join("tear_guard/armed").exists());
    let s = Store::open_tiny(&dir).unwrap();
    s.put_tx_full_batch_indexed(&[coinbase([0x22u8; 32])], false)
        .unwrap();
    assert_eq!(meta_ver(&dir), 31);
    assert!(dir.join("tear_guard/armed").is_file());
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An append can latch its failure after a sync passed the latch check at
/// entry and before the sync reads a zero writer count. The sync refuses
/// the seal and leaves `armed` in place.
#[cfg(debug_assertions)]
#[test]
fn sync_refuses_a_failure_latched_before_the_writer_count() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    s.put_tx_full_batch_indexed(&[coinbase([0x44u8; 32])], false)
        .unwrap();
    let armed = dir.join("tear_guard/armed");
    assert!(armed.is_file());
    rbitcoin_store::testutil::set_before_class_a_seal(Some(Box::new(|txs| {
        rbitcoin_store::testutil::latch_class_a_failure(txs);
    })));
    assert!(
        s.txs.sync_class_a_data().is_err(),
        "a sync sealed over a latched append failure"
    );
    assert!(armed.is_file(), "a sync cleared armed over a failed append");
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `write_barrier` on the sync path leaves `armed` while an append is in
/// flight. An idle sync clears it, after the seal.
#[test]
fn write_barrier_does_not_clear_armed_while_an_append_is_in_flight() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    s.put_tx_full_batch_indexed(&[coinbase([0x33u8; 32])], false)
        .unwrap();
    let armed = dir.join("tear_guard/armed");
    assert!(armed.is_file());
    rbitcoin_store::testutil::hold_class_a_append(&s.txs);
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| s.txs.sync_class_a_named(1));
        let start = std::time::Instant::now();
        while start.elapsed() < std::time::Duration::from_millis(200) {
            assert!(
                armed.is_file(),
                "sync cleared armed while an append was in flight"
            );
            assert!(
                !handle.is_finished(),
                "sync returned while an append was in flight"
            );
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        rbitcoin_store::testutil::release_class_a_append(&s.txs);
        handle.join().unwrap().unwrap();
    });
    assert!(
        !armed.exists(),
        "an idle sync clears after the append finishes"
    );
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A mark that names an older generation is replaced in one rename when a
/// newer slot is already sealed. The file is present before and after.
#[test]
fn newer_sealed_slot_replaces_the_armed_mark_in_place() {
    let dir = tmp();
    let s = Store::create_tiny(&dir).unwrap();
    s.put_tx_full_batch_indexed(&[coinbase([0x44u8; 32])], false)
        .unwrap();
    s.txs.sync_class_a_named(1).unwrap();
    assert!(!dir.join("tear_guard/armed").exists());
    plant_armed(&dir, 0);
    s.put_tx_full_batch_indexed(&[coinbase([0x45u8; 32])], false)
        .unwrap();
    let mut raw = [0u8; 16];
    read_at(&dir.join("tear_guard/armed"), 0, &mut raw);
    assert_eq!(&raw[0..4], b"CARM");
    let generation = u64::from_le_bytes(raw[8..16].try_into().unwrap());
    assert!(generation > 0, "the mark still names the empty generation");
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Class A restore does not write `spent.body`. A following fold replay,
/// on the same open, puts the fold image on the mixed page.
#[test]
fn spent_body_is_unchanged_by_class_a_restore_and_fold_replay_wins() {
    let dir = tmp();
    {
        let s = Store::create_tiny(&dir).unwrap();
        let outs = vec![OutputRecord::unspent(50, vec![0x51]); 512];
        s.put_tx_full_batch_indexed(
            &[(
                TxRecord {
                    txid: [0x61u8; 32],
                    version: 1,
                    locktime: 0,
                    input_count: 1,
                    output_count: 512,
                },
                vec![InputRecord::coinbase(u32::MAX, vec![0x01], vec![])],
                outs,
            )],
            false,
        )
        .unwrap();
        s.txs.sync_class_a_named(1).unwrap();
    }
    let body = dir.join("spent.body");
    let published = logical_of(&body);
    assert!(published > 4096, "spent.body published {published}");
    let keep = (published - 4096) as usize;
    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&body).unwrap();
        file.seek(SeekFrom::Start(4096)).unwrap();
        file.write_all(&vec![0xabu8; keep]).unwrap();
        file.sync_all().unwrap();
    }
    let junk = vec![0x11u8; keep];
    plant_tail(
        &dir.join("tear_guard/tail.0"),
        3,
        1,
        &[(SPENT_STEM, published, 4096, &junk)],
    );
    plant_armed(&dir, 3);
    let s = Store::open_tiny(&dir).unwrap();
    drop(s);
    let mut got = vec![0u8; keep];
    read_at(&body, 4096, &mut got);
    assert_eq!(got, vec![0xabu8; keep], "class A restore wrote spent.body");
    assert!(!dir.join("tear_guard/armed").exists());
    let delta = dir.join(rbitcoin_store::spend_delta::SPEND_DELTA_DIR);
    let mut fold = Vec::new();
    fold.extend_from_slice(&rbitcoin_primitives::STORE_MAGIC);
    fold.extend_from_slice(&rbitcoin_primitives::SCHEMA_VERSION.to_le_bytes());
    fold.extend_from_slice(&0u16.to_le_bytes());
    fold.extend_from_slice(&1u32.to_le_bytes());
    fold.extend_from_slice(&4096u64.to_le_bytes());
    fold.extend_from_slice(&vec![0x5au8; PAGE]);
    std::fs::write(
        delta.join(rbitcoin_store::spend_delta::SPEND_DELTA_FOLD_NAME),
        &fold,
    )
    .unwrap();
    let mut commit =
        std::fs::read(delta.join(rbitcoin_store::spend_delta::SPEND_DELTA_COMMIT_NAME)).unwrap();
    commit[8..12].copy_from_slice(&1u32.to_le_bytes());
    std::fs::write(
        delta.join(rbitcoin_store::spend_delta::SPEND_DELTA_COMMIT_NAME),
        &commit,
    )
    .unwrap();
    let s = Store::open_tiny(&dir).unwrap();
    drop(s);
    read_at(&body, 4096, &mut got);
    assert_eq!(got, vec![0x5au8; keep]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A panic inside a Class A append still releases its writer count and
/// latches the failure. A sync on another thread then refuses instead of
/// waiting forever for a writer that is gone.
#[cfg(debug_assertions)]
#[test]
fn a_panicking_append_releases_its_writer_count() {
    let dir = tmp();
    let s = std::sync::Arc::new(Store::create_tiny(&dir).unwrap());
    rbitcoin_store::tx_table::set_after_bodies_for_test(Some(Box::new(|| {
        panic!("injected panic inside a Class A append");
    })));
    let appending = std::sync::Arc::clone(&s);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        appending.put_tx_full_batch_indexed(&[coinbase([0x55u8; 32])], false)
    }));
    assert!(unwound.is_err(), "the hook did not run inside the append");
    let (tx, rx) = std::sync::mpsc::channel();
    let syncing = std::sync::Arc::clone(&s);
    std::thread::spawn(move || {
        let _ = tx.send(syncing.txs.sync_class_a_data().is_err());
    });
    let refused = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("a sync waited for a writer that unwound");
    assert!(refused, "a sync sealed over an append that panicked");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A lower named sync after a higher one seals the higher value. A crash
/// in the next armed append restores that slot and keeps creates 65–128.
#[test]
fn lower_named_sync_seals_the_higher_synced_value() {
    let named = 128u64;
    let dir = tmp();
    let txid = [0x80u8; 32];
    {
        let s = Store::create_tiny(&dir).unwrap();
        let batch: Vec<_> = (1..=named)
            .map(|i| coinbase(if i == named { txid } else { [i as u8; 32] }))
            .collect();
        s.put_tx_full_batch_indexed(&batch, false).unwrap();
        s.txs.sync_class_a_named(named).unwrap();
        s.txs.sync_class_a_named(64).unwrap();
        s.put_tx_full_batch_indexed(&[coinbase([0x81u8; 32])], false)
            .unwrap();
        assert!(dir.join("tear_guard/armed").exists());
    }
    let s = Store::open_tiny(&dir).unwrap();
    assert_eq!(
        rbitcoin_store::tx_table::read_class_a_synced(&dir).unwrap(),
        named
    );
    assert_eq!(s.txs.txids.get(Fk(named)).unwrap(), txid);
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
}
