Fixed

- **Esplora `GET /tx/:txid/merkleblock-proof` builds its header and its
  txids from one block.** It read the txids at the transaction's height and
  then the header at that height. A reorg between the two reads answered
  `200` with the new block's header over the old block's txids, a proof
  that does not verify. The route now reads the block at that height once
  and takes both from it.
