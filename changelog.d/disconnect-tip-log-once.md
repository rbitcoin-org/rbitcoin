Fixed

- **One `DisconnectTip` line per disconnected block.** A disconnect logged
  the same warn line twice, before the scripthash unlink and after the tip
  shrink, so a one-block reorg read as two disconnects (#1432). The warn
  line now comes once, after the tip shrink commits; the earlier point logs
  `DisconnectTip start:` at debug.
