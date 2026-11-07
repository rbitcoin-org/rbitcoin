Fixed

- **`--proxy` now resolves `--connect` and `addnode` names.** The node
  hands the name to the SOCKS proxy (address type 3). Before, the OS resolver
  looked it up first, so clear-text DNS queries for the peer left the host
  outside the proxy, again every two seconds while the dial failed (#1348).
