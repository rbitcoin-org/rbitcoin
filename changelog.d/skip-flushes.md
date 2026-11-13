Added

- **Test suites can skip file flushes.**
  `cargo test --workspace --features skip-flushes` turns off every
  `sync_all` / `sync_data` in the query, net, rpc, ibd, and journey test
  binaries. On macOS each flush waits on the whole drive, and those suites
  timed out. A node still flushes, and so do a node process a test starts
  and every other test binary.
