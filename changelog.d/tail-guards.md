Changed

- **A torn txstat, filter, tweak, or mempool page restores the committed bytes.**
  Interior `txstat` stamps arm `store/guard/txstat` with the pages above the
  Class A tail before the write. One `guard/blockfilter` or `guard/sp_tweaks`
  mark per put images the shared tail and page 0 after fresh blocks are
  synced. A mempool flush is one `mempool/guard/flush` mark for the body
  tail, new slots, durable deaths, and meta. `tx.head` seal always renames
  `NNNNNN.mlt` into place. The segment meta `mlt` flag says that file must
  exist; an older segment without the flag still loads a missing file as an
  empty map.
