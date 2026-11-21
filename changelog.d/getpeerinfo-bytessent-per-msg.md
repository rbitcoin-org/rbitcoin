Fixed

- **`getpeerinfo.bytessent_per_msg` counts what was sent.** It was always
  `{}`: nothing wrote the per-message map. The session writer now counts
  each message it puts on the wire, as payload plus the 24-byte v1 header,
  the same rule `bytesrecv_per_msg` uses. That includes `sendheaders`,
  `sendcmpct`, the first `ping` and `feefilter` at session start. The
  version handshake (`version`, `verack`, `wtxidrelay`, `sendaddrv2`) is
  not counted.
