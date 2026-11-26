Fixed

- **A failed step at shutdown no longer leaves `scripthash.dirty` behind.**
  With `--sh-index`, an error in an earlier store flush step (headers, the
  tip seal, a failed IBD tip flush or a missing keep-window file) returned
  before the scripthash sync. So did a failed node task after start, which
  skipped the whole shutdown tail. The next start then refused until a full
  index rebuild. Every shutdown step now runs. A failed one is logged and
  kept as the exit error, and the steps run costliest-first: the scripthash
  index, the chain tip, Class A writeback, the `tx.head` snapshot, the
  mempool, then `peers.dat`. The tip is still not sealed over a failed header
  sync, a failed IBD tip flush or a missing keep-window file.
