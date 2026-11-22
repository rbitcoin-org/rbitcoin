Added

- **Electrum `blockchain.transaction.testmempoolaccept`** (protocol 1.7).
  It takes 1 to 25 hex transactions and runs the same checks as RPC
  `testmempoolaccept`, at Core's default `maxfeerate`. Two or more are
  tested as a package, so a child may spend a parent from the same call.
  Each row is `txid`, `wtxid`, `allowed`, and a `reason` when not allowed.
  A package-wide failure has a `reason` and no `allowed`. Nothing is
  admitted. `server.features.protocol_max` stays 1.6.
