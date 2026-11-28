Fixed

- Inbound peers on an implicit native Tor or explicit `=onion` listener count
  as `onion` in `getpeerinfo` and `rbitcoin_peers{network}`, including before VERSION.
  `addr` and `addrbind` identify the TCP source and listening endpoint.
