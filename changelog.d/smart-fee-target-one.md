Fixed

- **`estimatesmartfee 1` answers as 2, like Core.** Core's
  `estimateSmartFee` never answers a 1-block target: it uses 2 and reports
  `"blocks": 2`. This node answered target 1 with its 99.9% next-block
  quote, which on signet came out at about 80 times the 2-block rate, and
  clients that ask for the next block (CDK's on-chain melts) paid it
  (#1437). RPC `estimatesmartfee` and Electrum `blockchain.estimatefee` now
  answer 1 as 2. Esplora `/fee-estimates` key `1` and `estimaterawfee 1`
  keep the 1-block quote.
