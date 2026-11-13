use rbitcoin_store::testutil::*;

#[test]
fn copy_store_tree_copies_nested_files() {
    let src = TempDir::labeled("copy-src").unwrap();
    let nested = src.path().join("nested");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("page"), b"store-bytes").unwrap();
    let dst_root = TempDir::labeled("copy-dst").unwrap();
    let dst = dst_root.path().join("out");
    copy_store_tree(src.path(), &dst);
    let got = std::fs::read(dst.join("nested/page")).unwrap();
    assert_eq!(got, b"store-bytes");
}

/// Nothing in this binary opts in, so a test store still flushes.
#[cfg(debug_assertions)]
#[test]
fn tiny_store_leaves_flushes_on() {
    let (_dir, _store) = tiny_store();
    assert!(!rbitcoin_store::durability::flushes_skipped());
}
