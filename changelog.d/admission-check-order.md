Fixed

- **Admission asks what needs only the transaction and the tip first.**
  Every admit (P2P, `sendrawtransaction`, `testmempoolaccept`,
  `submitpackage`, Esplora, Electrum) now checks Libre standardness of
  shape and locktime finality before the mempool and the coins, as Core
  does. A non-final transaction with a missing parent is `non-final` and
  no longer parks as an orphan, unless the trusted peer sent it. A package
  member that is non-final or non-standard and clashes with a mempool
  transaction reports that, not `bip125-replacement-disallowed`. A spend
  that fails both BIP68 and coinbase maturity is `non-BIP68-final`.
