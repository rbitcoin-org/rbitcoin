Fixed

- **Esplora `/scripthash/:hash` takes `sha256(scriptPubKey)` hex in digest
  order, as electrs does.** The path and the `POST /scripthashes/txs` entries
  were read byte-reversed (Electrum's scripthash order), so a client sending
  the electrs, blockstream.info, or mempool.space form got 200 with an empty
  history. This covers `/scripthash/:hash`, `/utxo`, `/txs`, `/txs/chain`,
  `/txs/mempool`, `/txs/summary`, the POST routes, and unix-socket
  `/internal/scripthash/:hash` and `/internal/scripthash/:hash/history`. A
  client that sent the reversed form now gets empty results: send the digest
  unreversed, or use `/address/:address`.
  Electrum is unchanged (#1662).
