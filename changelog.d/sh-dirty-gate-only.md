Changed

- **Scripthash writes keep no page images.** Every scripthash commit,
  unlink, and deferred empty-head commit already runs under
  `scripthash.dirty`, and a crash inside one rebuilds the index, so the
  per-commit `guard/sh-*` images and their syncs are gone. A `guard/sh-*`
  mark left by an earlier development build requests a rebuild at open and
  is removed without being copied back (#2207). The ingest head keeps its
  `.ahead` journal: the cold pack path rewrites it without
  `scripthash.dirty` (#2208).
