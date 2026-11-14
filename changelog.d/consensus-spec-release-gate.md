Added

- **A release tag publishes only after bitcoin-consensus-spec's suites
  pass.** `release.yml` runs the tag against the spec revision in
  `scripts/consensus-spec/pin.env`: script, transaction, sighash, taproot
  and BIP340 verdicts under all 64 consensus flag sets, the Bitcoin Core
  block corpus, a sync of each corpus chain from Bitcoin Core v32.1 over
  P2P, and a sync of each chain from a peer that also serves the blocks
  Core rejects, so the node's own download and validation path meets them. A failure that `scripts/consensus-spec/known-failures.txt`
  does not name stops the GitHub Release. A ship PR runs it first, and
  `release-extra` fails the PR unless it passes. The same run is weekly
  on `master`.
