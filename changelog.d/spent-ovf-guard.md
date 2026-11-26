Changed

- **A torn `spent.ovf` tail restores the pages from before the append.**
  The first overflow append after a spend sync writes `store/guard/spent.ovf`
  with page 0 and the tail block, then appends. Later appends in that window
  leave the mark in place. The spend sync holds the annotate freeze across
  the data sync and the clear. Open copies the mark back before replay, so
  the torn tail is not the committed list. Marks publish only after store
  `meta` is 31. A table fixture with no `meta` still arms.
