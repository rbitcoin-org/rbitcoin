Fixed

- **RPC auth schemes match in any case.** `Authorization: BEARER …` and
  `basic …` are accepted, as RFC 7235 and Core allow. Before, only
  `Bearer`/`bearer` and `Basic`/`basic` passed.
- **A crash while minting the RPC token no longer blocks the next start.**
  The token is synced in `rpc.token.tmp` and then linked into place, so
  `rpc.token` is never left empty. A zero-length `rpc.token` from an older
  crash is replaced with a new token instead of failing startup.
