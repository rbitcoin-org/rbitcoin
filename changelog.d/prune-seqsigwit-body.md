Fixed

- **`--prune-seqsigwit` no longer keeps `seqsigwit.body`.** The flag stores
  scriptSig and witness only for the last 288 heights
  (`store/seqsigwit.window/{height}.bin`, plus the RAM cache). Each height
  file is encrypted with the store secret. Enabling it
  on an archive copies that window out and cuts the stem back to its header.
  The height file is synced before the tip commit and before that cut.
  A tip of 288 drops genesis and records pruneheight 0. A shorter chain
  drops nothing. A reorg to a shorter fork does not move that watermark
  backward onto a height whose witness file is already gone. Connecting an
  already archived block again writes that block's scriptSig and witness
  into the height file. A failed spill write does not publish the new tip.
  `store/` is synced after `seqsigwit.window` is created, including on each
  spill write, so a crash cannot drop that directory while the sidecar and
  a cut locator remain. `txout`, `input`, `txstat`, and block filters stay.
  Unpruned nodes still read `seqsigwit.body`.
