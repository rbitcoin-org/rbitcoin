Fixed

- **Open keeps the covered Class A prefix after power loss.** A body header
  shorter than the locator count used to refuse startup. Open now truncates
  to the last create those headers still name, clears `header_txs` ranges
  past that prefix, and shrinks the tip to match. A Class C array torn
  mid-record opens at the last whole row.
- **A `tx.head/` directory with segment files and no `meta` rebuilds.** That
  directory used to refuse as a legacy shard. Open wipes it and rebuilds from
  Class A. A monolithic `tx.head` and a flat `tx.head.meta` still refuse.
- **Small durable files publish through a synced rename.** Store `meta`,
  `store.secret`, `seqsigwit.prune`, `seqsigwit.gap`, mempool `meta`, and `unbroadcast` no
  longer truncate the live name. A short prune file is not a height. Open
  keeps creates the witness locator no longer names, and those creates have
  no scriptSig or witness. Without the prune file, that missing locator
  still drops the block. A short mempool `meta` is quarantined and the
  pool starts empty. `store.secret` is mode 0600 on the temporary
  inode, before the name is published.
- **The next block after a torn witness locator keeps its own witness.**
  Open appends an empty witness row for each create the short locator did
  not name. The following append files its scriptSig on the new create.
  The empty rows are still not a witness after a restart, and the tip stays.
  A later torn locator is its own span, so a witness stored between the
  two fills stays available.
- **Scripthash inclusion stays inside the covered create count.** A watermark
  just above that count unlinks the tail, or rebuilds the head when those
  outputs are gone. A shard offset past its file rebuilds once. A floor that
  already matches the count does not.
