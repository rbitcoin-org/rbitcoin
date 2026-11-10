Fixed

- **A datadir created for one signet no longer opens under another.** Every
  signet shares one genesis block, so the stored-genesis check let a datadir
  open under a different `--signet-challenge`, or under the default one.
  `{datadir}/network` now records the network and its P2P message start on
  the first start. A start on another network or challenge refuses with
  `Wrong datadir for network?` before the store opens, before any peer, and
  before RPC serves. A datadir from before this file adopts the started
  network once its stored genesis matches, and logs that it did.
