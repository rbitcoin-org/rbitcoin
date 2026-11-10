Fixed

- **`--prune-seqsigwit` no longer keeps `seqsigwit.body`.** The flag stores
  scriptSig and witness only for the last 288 heights
  (`store/seqsigwit.window/{height}.bin`, plus the RAM cache). Each height
  file is encrypted with the store secret. Enabling it
  on an archive copies that window out and cuts the stem back to its header.
  A datadir already pruned by an older build has plaintext window files.
  The first open rewrites the keep window from the stem before that cut,
  so those heights still serve. If the witness locator is already empty,
  that open keeps the window files and finishes the cut. A locator that
  stopped short of the creates drops that unpublished tail before the copy.
  Confirming a height that was already
  dropped is a no-op. Resubmitting the tip writes a missing keep file again.
  The height file is synced before the tip commit and before that cut.
  A tip of 288 drops genesis and records pruneheight 0. A shorter chain
  drops nothing. A reorg to a shorter fork does not move that watermark
  backward onto a height whose witness file is already gone. Connecting an
  already archived block again writes that block's scriptSig and witness
  into the height file. A failed spill write does not publish the new tip.
  `store/` is synced once, when `seqsigwit.window` is created. A later
  confirm syncs that window directory and does not sync `store/` again.
  A confirm batch syncs the window directory once, after each height file,
  and before the tip moves, so a crash cannot drop the directory while the
  sidecar and a cut locator remain. Opening a pruned store that already found a short input
  does not also read the witness locator. `txout`, `input`, `txstat`, and
  block filters stay.
  Unpruned nodes still read `seqsigwit.body`.
  Opening a datadir rewrites `store/meta` to schema 27 and syncs that
  directory before a witness cut. A 0.9.0 binary refuses schema 27, including
  a datadir that never pruned witnesses. Schema 22 through 26 still open here.
