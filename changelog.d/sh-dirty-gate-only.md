Changed

- **Scripthash writes keep no page images.** Every scripthash commit,
  unlink, and deferred empty-head commit already runs under
  `scripthash.dirty`, and after a crash inside one a start with the index
  on refuses until it is rebuilt, so the per-commit `guard/sh-*` images and
  their syncs are gone (#2207). A published `guard/sh-*` mark left by an
  earlier development build is dropped without being copied back and marks
  the index dirty, so the operator chooses the rebuild. A dirty index whose
  open fails with `Corrupt` or a bad magic requests the rebuild at open
  instead of stopping it; that rebuild runs without the operator's go-ahead.
  An I/O error still stops the open. The ingest head keeps its `.ahead`
  journal: the cold pack path rewrites it without `scripthash.dirty`
  (#2208).
