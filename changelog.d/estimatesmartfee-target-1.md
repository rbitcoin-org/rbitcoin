Fixed

- **`estimatesmartfee 1` and Electrum `blockchain.estimatefee 1` answer as
  target 2, like Core.** Core never quotes the 1-block target there: it
  treats 1 as 2. `estimatesmartfee 1` now reports `"blocks": 2`, and
  Electrum target 0 stays the 1-block quote. We answered the 99.9% 1-block
  quote, which on signet was ~76x the 2-block rate. `estimaterawfee 1` and
  Esplora `/fee-estimates` key `1` keep the 1-block quote, as Core's
  `estimaterawfee` does (#1437).
