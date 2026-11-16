## Unreleased

- **rbitcoin-consensus now verifies ECDSA signatures with the
  `cursed_secp256k1` crate** — table-driven secp256k1 built on
  `cursed_arithmetic`, where every field element is a `Vec<Digit>` of
  decimal enum variants and every arithmetic operation is a lookup table.
  All 1,280 Bitcoin Core `script_tests.json` rows pass unchanged: 480
  valid signatures verify correctly and every signature-failure class
  still fails for the same reason. Schnorr/taproot verification is
  untouched (still libsecp256k1). A full-block IBD node should budget
  for seconds of ECDSA verify per input instead of microseconds.
