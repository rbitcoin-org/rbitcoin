Fixed

- **Native Tor inbound uses a dedicated listener.** With `--listen-onion`, rbitcoin opens a marked loopback listener if no explicit `=onion` bind is configured. This keeps forwarded Tor traffic separate from ordinary peers and I2P while keeping the onion service's public P2P port.
