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
  Unlike Core, a multi-transaction call does not stop at the first failed
  member: every member still gets its own row.
