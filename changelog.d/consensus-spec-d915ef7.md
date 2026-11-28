Changed

- **The release gate runs bitcoin-consensus-spec at `d915ef7`.** The
  vectors suite now also checks proof of work and difficulty adjustment on
  every network, signet block solutions, and each network's consensus
  parameters. The corpus adds Core's chain tie-break scenario and the
  spec's mined ones: most work against longest chain, signet blocks without
  a valid solution, and median time past near genesis. Peer-sync serves a
  block's damaged copies before the block. The checks rbitcoin fails are
  named in `scripts/consensus-spec/known-failures.txt` with their reasons.
  None of them changes a verdict on a block that can exist: compact targets
  that are negative, zero or overflowing, the regtest difficulty period, a
  signet check skipped for a block with no parent, and the mainnet script
  exceptions applying on every network.
