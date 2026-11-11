Fixed

- **IBD switches to a heavier fork only after peers serve its blocks.** A
  peer could send headers for a fork with more work than the chain being
  downloaded and never serve its blocks. The node rewound to the fork point
  and stayed there, also after a restart, while another peer served the
  whole honest chain. Now the node first fetches the fork's blocks that
  out-work its own chain above the fork point, checks each against its
  header, and keeps them in memory (at most 64 MiB). Only then does it
  rewind and switch. A fork nobody serves never moves the tip, and a peer
  that serves part of it and then stops cannot hold the tip down. A peer
  whose chain is known to differ at a block is no longer asked for it, so
  the honest peer is not disconnected for blocks it never had. Finding
  [115](docs/external_findings/115-withheld-heavier-fork.md).
