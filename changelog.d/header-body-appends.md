Changed

- **`header.body` appends with no page images.** A header batch writes its
  rows past the end, syncs, then publishes and syncs the length before the
  head insert. Only the first batch arms `store/guard/header.body`, now an
  empty flag that lets open index rows beside a still-empty head. A failed
  append refuses later header puts until the store reopens.
