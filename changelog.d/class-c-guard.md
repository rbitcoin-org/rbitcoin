Changed

- **Class C and header flushes publish a forward page-guard mark.**
  `confirmed[]`, `header_txs` first+count, and `strong_tx` share
  `store/guard/class_c`. `header.body` uses `store/guard/header.body`. One
  `header.head` generation and its `.mlt` share `store/guard/header.head`.
  Open copies every named 4 KiB image onto its page before any read of
  those files, then removes the mark. A crash between the two `header_txs`
  columns, or between `header.head` and `header.head.mlt`, cannot leave the
  pair split. Marks publish only after store `meta` is 31. A table fixture
  with no `meta` still arms.
