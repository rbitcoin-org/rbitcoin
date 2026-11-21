Fixed

- **An IPv4 peer accepted on a `[::]` listener is an IPv4 peer.** Linux
  makes that listener dual-stack, and the peer was kept as
  `::ffff:a.b.c.d`. `getpeerinfo.addr` showed the mapped form, a local
  `127.0.0.1` client that misbehaved was discouraged (loopback is exempt)
  and refused on reconnect, and a discouraged remote IPv4 address did not
  match the same address seen elsewhere. The listener still accepts IPv4,
  as before.
