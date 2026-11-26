Fixed

- **`getcfilters` is answered in full past the 4 MiB send budget.** The
  node queued filters until a peer's send queue passed 4 MiB and dropped
  the rest of the range without a `notfound`, so a 1,000-block request for
  recent mainnet filters got a few hundred `cfilter` messages and then
  nothing, and Neutrino (LND) and Kyoto (BDK) clients waited for their
  timeout or dropped the peer. The rest of the range is now parked, as a
  `getdata` tail is: the session reads nothing more from that peer until
  the writer drains, then sends the remaining filters in order. As in
  Core, one request's replies are held at once (#2078).
