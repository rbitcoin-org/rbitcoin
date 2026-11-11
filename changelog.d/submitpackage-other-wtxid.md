Fixed

- **`submitpackage` reports `other-wtxid`.** A member whose txid is already
  in the mempool under another witness now returns Core's
  `{"txid", "other-wtxid"}` entry naming the live wtxid, instead of fee and
  size fields.
