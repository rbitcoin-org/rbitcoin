Changed

- **The NixOS module eval checks testnet5 ports.** `network = "testnet5"`
  must default the P2P port to 18353 and the RPC port to 18352 and pass
  `--network testnet5`.
- **`p2p.openFirewall` no longer opens a `v1` `netPermissionBind` port.**
  That listener is plaintext P2P for a local wallet indexer. To reach it
  from another LAN host, open the port on that interface with
  `networking.firewall.interfaces.<name>.allowedTCPPorts`. Evaluation
  refuses a `v1` bind on the RPC, health, or SV2 port as well.
- **NixOS `p2p.onionListen` marks the Tor forwarding listener.**
  `p2p.onionListen = "127.0.0.1:8334"` passes `--listen 127.0.0.1:8334=onion`
  after the P2P listen flags. `listenOnion` publishes that listener, and
  source-IP grants skip it. Ordinary loopback grants apply unless
  `i2p.acceptIncoming` is enabled. Evaluation refuses a host that
  is not an IPv4 or bracketed IPv6 literal, an unspecified address in any
  spelling (including `::ffff:0:0`), a port outside 1–65535, a port shared
  with P2P, Electrum, Esplora, RPC, health, SV2, or a `v1` bind, `maxInbound = 0`, `trustPeer`, a missing `listenOnion` or onion
  `externalIp`, and I2P incoming without `p2p.listen`. The firewall never
  opens it, even when a `netPermissionBind` grant names its address or
  another address at that port. It
  replaces the `extraArgs` recipe in `docs/operator/operations.md`.
