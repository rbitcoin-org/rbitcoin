Added

- **`GET /mempool/events` follows the mempool.** A long-poll on the Esplora
  listener (both TCP and unix) returns every add and removal in commit
  order, each with a sequence number. A removal carries Core's reason
  (`expiry`, `sizelimit`, `reorg`, `block`, `conflict`, `replaced` with the
  replacing txid) or `rollback`. Join it to `getrawmempool false true` with
  no gap: snapshot at S, then apply every event from S. A cursor the node no
  longer holds is `410`, and a changed `epoch` means the node restarted;
  either way the client takes a new snapshot. At most half the in-flight
  cap, rounded down, may be parked.
- **`getrawmempool` `mempool_sequence` moves as in Core.** It now advances
  on every add and every removal, including a mined block, and is read
  with the txid list. Before, it moved only when a transaction was
  published.
