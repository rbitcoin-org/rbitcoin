Fixed

- **Esplora `POST /txs/test` tests two or more transactions as a package.**
  mempool/electrs forwards the array to bitcoind `testmempoolaccept`, which
  does. rbitcoin tested each one alone, so a child of a parent in the same
  request failed `missing-inputs`. The route now uses the same checks as
  RPC `testmempoolaccept`. `reject-reason` is Core's text, `vsize` rounds
  up as Core does, `fees` adds `effective-feerate` and
  `effective-includes`, and a package-wide failure such as
  `conflict-in-package` is one row per transaction with `package-error`.
