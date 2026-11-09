Fixed

- **Open keeps the covered Class A prefix after power loss.** A body header
  shorter than the locator count used to refuse startup. Open now truncates
  to the last create those headers still name, clears `header_txs` ranges
  past that prefix, and shrinks the tip to match. A Class C array torn
  mid-record opens at the last whole row.
