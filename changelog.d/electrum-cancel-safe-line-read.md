Fixed

- **Electrum keeps a request that arrives in pieces.** A request line
  split across TCP reads lost its first part when a push (a scripthash
  tick, a new tip, a mempool announce, a silent-payment scan step, or a
  tweaks wave) ran between the pieces, and the client got
  `-32700 parse error` instead of its reply. The bytes read so far now
  stay with the connection until the line ends. The request-line cap and
  its `-32600 request line too long` answer are unchanged (#1806).
