Changed

- **A finished scripthash append drops `scripthash.dirty` once that commit is synced.**
  Sorting, seeding, and staging do not mark the index. The commit syncs the
  payloads, every head word it wrote, the free-list links, and the alloc
  header that names those frees, finishes a seal it started, syncs the index
  directories, and then removes the mark. A crash before that still rebuilds.
  An unlink still leaves the mark until `flush`. `scripthash.include_hwm`
  still advances only after that flush.
