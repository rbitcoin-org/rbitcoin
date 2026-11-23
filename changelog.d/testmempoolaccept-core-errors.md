Fixed

- **`testmempoolaccept` reports Core's reject reasons.** RPC
  `testmempoolaccept` and Esplora `POST /txs/test` now give
  `package-too-large` for a package over 404,000 weight units, and
  `package-not-sorted` before `conflict-in-package` when both apply, as
  Core checks order first. A package member already in the mempool is
  `txn-already-in-mempool` (or `txn-same-nonwitness-data-in-mempool`), not
  `bip125-replacement-disallowed`, with Core's `reject-details`. RPC `testmempoolaccept` refuses an empty
  array or more than 25 transactions with Core's `Array must contain between
  1 and 25 transactions.`, and checks that before `maxfeerate`, as Core
  does.
  An input repeated inside one member is that member's
  `bad-txns-inputs-duplicate`, not `conflict-in-package`, here and in
  `submitpackage`.
  A transaction the active chain already holds is `txn-already-known` on
  every admit: a package member now says so, as a single transaction did,
  and so do `submitpackage`, P2P, Esplora and Electrum, where it was
  `missing-inputs` or `bad-txns-inputs-missingorspent`. `sendrawtransaction`
  of one with every output spent is `-26 txn-already-known`, not `-25`.
  A package member that clashes with a pool tx and also fails
  `CheckTransaction`, such as a repeated input, reports the
  `CheckTransaction` reason, not `bip125-replacement-disallowed`.
  A package is `too-large-cluster` only when one cluster it would make with
  the mempool is over the cap. It used to add every member onto every pool
  parent's cluster, so a member that touches none of them failed the
  package.
  Unlike Core, a multi-transaction call does not stop at the first failed
  member: every member still gets its own row.
