Fixed

- **`--prune-seqsigwit` no longer keeps `seqsigwit.body`.** The flag stores
  scriptSig and witness only for the last 288 heights
  (`store/seqsigwit.window/{height}.bin`, plus the RAM cache). Enabling it
  on an archive copies that window out and cuts the stem back to its header.
  The height file is synced before the tip commit and before that cut.
  A tip of 288 drops genesis and records pruneheight 0. A shorter chain
  drops nothing. `txout`, `input`, `txstat`, and block filters stay.
  Unpruned nodes still read `seqsigwit.body`.
