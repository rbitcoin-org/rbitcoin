Security

- **Forwarded I2P and unmarked onion peers no longer lock each other out.**
  With `--i2p-accept-incoming` or an onion `--external-ip` without an
  explicit `=onion` bind, forwarded peers can reach the ordinary P2P
  listener from the forwarder's loopback address. Eight unfinished
  handshakes there refused every later I2P or onion inbound, and one
  evicted overlay peer refused all of them for ten minutes.
  Loopback inbound on that listener now uses the shared
  `--max-inbound` limit and skips the netgroup wait, as the marked onion
  listener already did.
