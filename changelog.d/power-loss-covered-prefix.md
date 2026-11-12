Fixed

- **Open keeps the covered Class A prefix after power loss.** A body header
  shorter than the locator count used to refuse startup. Open now truncates
  to the last create those headers still name. A short `input.body` header
  cuts `input.loc` to the creates that header still names. The short-input
  probe runs only after that fit, and only when the next row is still inside
  the fitted count. A witness row past the body is not read; the input count
  is the prefix that landed. Open shrinks the tip to match,
  then clears `header_txs` ranges past that prefix. A cut that drops
  creates syncs `(covered, old]` in `spend.recheck` before the Class A
  truncate. `old` is also the highest `header_txs` range end still past
  the kept count, noted before those ranges are cleared. A spender number
  inside one of those spans counts only when that create's input at the
  stored vin still names the parent and vout. Block validation and the
  Electrum spend join use that same check. An unstrong orphan at
  that cut does not keep later confirmed blocks, including when those
  ranges were already cleared. A Class C array torn
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
  locator did not name. A witness body that does not cover the last named
  row is cut back to the last row it still covers before that fill, including
  when the locator count already matches the creates. Open
  refuses when the body covers no witness row. A locator already cut to zero stays empty, so the
  keep-window rewrite is not handed those rows. A 0-byte prune file with
  a positive locator is only that torn marker, so the following append
  still writes the witness stem. A 0-byte file whose locator is already 0
  is the finished cut: open writes a 4-byte height and does not fill empty
  rows. When that cut has no keep-window files, the prune height becomes
  the tip. A missing prefix of an otherwise present window sets the prune
  height to the last missing height, and the files still on disk stay.
  The next block's scriptSig is written to the keep window. A missing tip
  file does not delete the older files. A 4-byte height is prune mode. A positive short locator on that
  height is the prefix that landed, so open drops the creates past it.
  Locator 0 is the finished cut and does not drop the chain. A stem cut in this process is that same finished cut: a body header that still names every create still seals the tip. The empty rows are still not a witness
  after a restart, and the tip stays. Deleting a gap span syncs the store
  directory.
  A later torn locator is its own span, so a witness stored between the
  two fills stays available. A witness locator ahead of the covered create
  count is cut back to that count, and a gap span past it is dropped.
  A 4-byte height drops that span too, including when open does not fill
  empty rows.
  When that locator already matches, the witness body counter is set
  back to that count and a tail past it is dropped before the next append.
  A pruned confirm still writes the keep file from the witness it just
  appended, even when the locator does not name that create. A later
  seal with an empty append cache reads that keep file. A height at or
  below the prune height, and a missing keep file, fail the seal.
  Turning prune on skips an empty pad instead of decoding it as an input. A `tx.head` that still has
  `meta` is shortened to that count. Its slots stay, and open does not
  rebuild it from Class A. A later create that reuses one of those fks
  replaces that slot when the new txid's probe reaches it. A probe that
  stops earlier leaves the old slot, and the new txid still resolves.
- **Scripthash inclusion stays inside the covered create count.** A watermark
  just above that count unlinks the tail when the outputs are still there.
  When those outputs are already gone, the seal falls first and the watermark
  file is replaced with the covered count. A missing include file copies
  SEAL into that watermark before the check, so a seal within a million
  creates of the stem unlinks on this open. A seal farther ahead stays.
  The packed head stays. A crash
  between those two writes still has the high watermark, so the next start
  tries again. A scripthash flush records `scripthash.through` before the
  body sync. Open records `(covered, through]` in `scripthash.recheck` when
  that value is past the create count, including when `include_hwm` is not.
  That repair records the cut span before the watermark moves.
  A later cut that does not meet that span stays its own record. A full
  rebuild removes the file.
  A later append stores a create at or below the live count when the row
  still ends past that count, and also when the live count has already
  passed the stale end. Creates past the live count drop off the row. The
  new head is synced before the old slab is freed. A reused cut number that
  no longer pays the script stays out of windowed history and does not
  shorten an Esplora page. That number also stays out of a height touch,
  a subscription status, and the join create count. With no recheck span,
  that count stays the packed counter. A shard offset past its file rebuilds once. A
  page read past that file's logical end schedules the same rebuild on either
  read backend. A history read of a stale slab does not. Repair of that mismatch
  still does. A
  floor that already matches the count does not.
