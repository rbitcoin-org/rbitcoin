Changed

- **`spent.ovf` publishes its length only after its nodes are synced.** An
  overflow append writes past the durable length and moves only the RAM
  length. A spend checkpoint or store flush syncs the nodes, then writes and
  syncs the length. A crash between them reopens at the last flushed length
  and ignores the bytes past it, so a torn tail is never read as the
  committed list. A failed sync still refuses later flushes until restart.
  No page mark is written.
