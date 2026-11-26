Fixed

- Peer RPC and Prometheus classify ordinary private and loopback sockets and
  proxy-resolved names as `not_publicly_routable`. Routable linked IPv4 addresses
  count as `ipv4`, and CJDNS sockets count as `cjdns` when CJDNS is enabled.
