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
  Open appends an empty witness row for each create a short, non-zero
  locator did not name. A locator already cut to zero stays empty, so the
  keep-window rewrite is not handed those rows. A 0-byte prune file is
  only that torn marker, so the following append still writes the witness
  stem. A 4-byte height is prune mode. The empty rows are still not a witness
  after a restart, and the tip stays. Deleting a gap span syncs the store
  directory.
  A later torn locator is its own span, so a witness stored between the
  two fills stays available. A witness locator ahead of the covered create
  count is cut back to that count, and a gap span past it is dropped.
  When that locator already matches, the witness body counter is set
  back to that count and a tail past it is dropped before the next append. A `tx.head` that still has
  `meta` is shortened to that count. Its slots stay, and open does not
  rebuild it from Class A.
- **Scripthash inclusion stays inside the covered create count.** A watermark
  just above that count unlinks the tail when the outputs are still there.
  When those outputs are already gone, the seal falls first and the watermark
  file is replaced with the covered count. The packed head stays. A crash
  between those two writes still has the high watermark, so the next start
  tries again. That repair records the cut span before the watermark moves.
  A later append stores a create at or below the live count when the row
  still ends past that count, and also when the live count has already
  passed the stale end. Creates past the live count drop off the row. The
  new head is synced before the old slab is freed. A reused cut number that
  no longer pays the script stays out of windowed history and does not
  shorten an Esplora page. A shard offset past its file rebuilds once. A
  floor that already matches the count does not.
