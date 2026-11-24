Fixed

- **Electrum `blockchain.transaction.broadcast` and Esplora `POST /tx` refuse a
  transaction with the reason `sendrawtransaction` gives, as electrs forwards
  it from Core.** They answered internal text (`broadcast reject: policy: min
  relay fee`, `orphaned <txid>`, `missing prevout <txid>:0`), so a client that
  matches Core's reason, such as rgb-lib's `min relay fee not met`, missed it.
  Electrum's message is the bare reason. Esplora answers 400
  `sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met"}`.
  A transaction whose outputs are still coins is
  `-27 Transaction outputs already in utxo set` on both, as on RPC (#1904).
