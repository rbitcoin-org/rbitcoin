Fixed

- **`--proxy` now resolves `--connect` and `addnode` names.** The node
  hands the name to the SOCKS proxy (address type 3). Before, the OS resolver
  looked it up first, so clear-text DNS queries for the peer left the host
  outside the proxy, again every two seconds while the dial failed (#1348).
- **`--only-net onion` no longer asks clearnet seeds.** With no IPv4 or
  IPv6 reachable, the node sends no DNS seed query, local or through
  `--proxy`, and adds only the fixed onion seeds. Before, it looked up the
  seed hostnames anyway and dropped the answers (#1348).
