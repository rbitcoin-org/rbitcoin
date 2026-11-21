Fixed

- **Electrum `blockchain.silentpayments.unsubscribe` no longer waits on
  the scripthash index.** With `--sh-index` off it answered `scripthash
  index disabled`, and while the index rebuilt or froze it answered
  `scripthash index rebuilding` / `updating`, although the subscribe it
  ends was served: a silent-payment scan reads the tweak index, not the
  scripthash index.
