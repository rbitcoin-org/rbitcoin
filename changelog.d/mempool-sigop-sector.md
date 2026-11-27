Fixed

- **A recomputed mempool sigop cost no longer tears into a wrong value.**
  After a schema 2 migrate, open recomputes each unknown sigop cost and
  writes it back in place. A cost whose 8 bytes crossed a 512-byte sector
  could tear on power loss into a value under the block limit, which the
  next open trusted. Such a cost now stays unknown on disk and is
  recomputed on the next open. A cost inside one sector is still written.
