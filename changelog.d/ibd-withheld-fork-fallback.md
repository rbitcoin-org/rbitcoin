Fixed

- **IBD no longer stalls below a heavier fork whose blocks no peer
  serves.** A peer could send headers for a fork with more work than the
  chain being downloaded and never serve its blocks. The node rewound to
  the fork point and stayed there, also after a restart, while another
  peer served the whole honest chain. When no peer has been able to serve
  the fork's next block for one stall window (30 s) and another peer's
  chain differs there, the fork is now dropped (not marked invalid) for
  10 minutes, whoever announces it, and after that until a live peer
  announces it again. A body for its block ends that at once. The download
  path is seeded again from stored headers without it. A peer whose chain
  is known to differ at a block is no longer asked for it, so the honest
  peer is not disconnected for blocks it never had. Finding
  [115](docs/external_findings/115-withheld-heavier-fork.md).
