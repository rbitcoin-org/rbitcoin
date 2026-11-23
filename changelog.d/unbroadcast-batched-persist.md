Fixed

- **Many unfetched local transactions no longer stall the node.** Every
  `sendrawtransaction`, served getdata, and confirmation of a local tx
  rewrote and fsynced the whole unbroadcast set, under its lock, and logged
  the confirmation at INFO. With thousands of local txs no peer fetched, a
  block confirming them took one fsync per tx, which also held up shutdown.
  The set is now written by the periodic mempool persist and the shutdown
  flush, and the confirmation line is a `p2p` debug line, as in Core.
- **Electrum, Esplora, and BlindBit broadcasts are rebroadcast until a peer
  fetches them.** Every local submit now joins the unbroadcast set when it
  enters the mempool, as `sendrawtransaction` and `submitpackage` already
  did, so `getmempoolinfo.unbroadcastcount` counts them too. A crash right
  after a local submit no longer reloads the tx without its rebroadcast.
