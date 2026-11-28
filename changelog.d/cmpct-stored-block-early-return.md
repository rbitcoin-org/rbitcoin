Fixed

- **A compact block for a body we already have returns before the peer's
  parked headers are scored.** The header was admitted and every parked
  header walked before the node looked for the body, so a peer that repeated
  such a `cmpctblock` made the node pay that walk each time. The node now
  returns as soon as the early rejects pass, as Core does once it has the
  data, and the announced header no longer takes a parked slot.
