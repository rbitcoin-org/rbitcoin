Fixed

- **IBD `headers` and `notfound` frames take the peer's session window.**
  Both are charged to the same messages and bytes budget as any other P2P
  frame before their decode is spawned, so a peer that floods either one is
  disconnected. The one `headers` reply that answers each outstanding
  `getheaders` stays exempt, so header sync is not clipped.
