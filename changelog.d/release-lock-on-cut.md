Fixed

- **A release cut updates `Cargo.lock`.** `--minor`, `--major`, `--patch`,
  and `--dev-next` rewrite each workspace crate's version in the root lock
  and in the `fuzz` and `script-oracle` locks. A crate that is not a
  workspace member keeps its version, including one that happens to use the
  same version string. The 0.9.0 cut left the workspace crates at `0.8.99`,
  so `cargo build --locked` failed. `release-gate` rejects a lock that still
  names the old version.
