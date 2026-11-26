Fixed

- Peer RPC and Prometheus classify ordinary private and loopback sockets and
  proxy-resolved names as `not_publicly_routable`. Routable IPv6 addresses with
  a linked IPv4 address count as `ipv4`, including NAT64 with a private
  embedded IPv4. CJDNS sockets count as `cjdns` when CJDNS is enabled and
  allowed by `--only-net`.
