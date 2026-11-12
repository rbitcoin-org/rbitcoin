Added

- **`GET /mempool/events` follows the mempool.** A long-poll on the Esplora
  listener (both TCP and unix) returns every add and removal in commit
  order, each with a sequence number. A removal carries Core's reason
  (`expiry`, `sizelimit`, `reorg`, `block`, `conflict`, `replaced` with the
  replacing txid) or `rollback` for a staged change the node took back. To
  anchor it, `getrawmempool false true` now returns `mempool_sequence` as
  in Core: it advances on every add and every removal, including a mined
  block, and is read with the txid list. Snapshot at S, then apply every
  event from S, with no gap. A cursor the node no longer holds is `410`,
  and a changed `epoch` means the node restarted; either way the client
  takes a new snapshot. At most half the in-flight cap, rounded down, may
  be parked. The ring keeps the newest 65,536 changes and is readable by
  anyone who reaches the listener, including an admit the node took back
  (a failed package, or a multi-transaction `testmempoolaccept`).
