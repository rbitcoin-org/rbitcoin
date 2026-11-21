Added

- **A release tag publishes only after bitcoin-consensus-spec's vectors,
  corpus and interop suites pass.** `release.yml` runs the tag against the
  spec revision in `scripts/consensus-spec/pin.env`: script, transaction,
  sighash, taproot and BIP340 verdicts under all 64 consensus flag sets,
  the Bitcoin Core block corpus, and a sync of each corpus chain from
  Bitcoin Core v32.1 over P2P. A failure that
  `scripts/consensus-spec/known-failures.txt` does not name stops the
  GitHub Release. A ship PR runs the same three first, and `release-extra`
  fails the PR unless they pass. The weekly run on `master`, and label
  `consensus-spec` on any PR, add peer-sync: a sync of each chain from a
  peer that also serves the blocks Core rejects, so the node's own
  download and validation path meets them. It takes about an hour, so no
  release waits for it.
