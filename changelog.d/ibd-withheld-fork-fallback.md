Fixed

- **IBD no longer stalls below a heavier fork whose blocks no peer
  serves.** A peer could send headers for a fork with more work than the
  chain being downloaded and never serve its blocks. The node rewound to
  the fork point and stayed there, also after a restart, while another
  peer served the whole honest chain. When no peer has served the fork's
  next block for one stall window (30 s) and another peer's chain differs
  there, the fork is now dropped (not marked invalid), the download path
  is seeded again from stored headers without it, and the addresses that
  announced it are not believed about that fork for 10 minutes. A peer whose chain
  is known to differ at a block is no longer asked for it, so the honest
  peer is not disconnected for blocks it never had. Finding
  [115](docs/external_findings/115-withheld-heavier-fork.md).
