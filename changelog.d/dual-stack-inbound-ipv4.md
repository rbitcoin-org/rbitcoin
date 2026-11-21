Fixed

- **An IPv4 peer accepted on a `[::]` listener is an IPv4 peer.** Linux
  makes that listener dual-stack, and the peer was kept as
  `::ffff:a.b.c.d`. `getpeerinfo.addr` showed the mapped form, a local
  `127.0.0.1` client that misbehaved was discouraged (loopback is exempt)
  and refused on reconnect, and a discouraged remote IPv4 address did not
  match the same address seen elsewhere. The listener still accepts IPv4,
  as before.
- **`--net-permission` reads `::ffff:a.b.c.d` as IPv4 `a.b.c.d`, as Core
  does.** A grant written in the mapped form `getpeerinfo` used to show
  (`noban@::ffff:127.0.0.1`) still matches that peer, now that it is kept
  as IPv4. The prefix counts IPv4 bits, so `::ffff:10.0.0.0/8` is
  `10.0.0.0/8`, and a prefix over 32 such as `::ffff:0:0/96` is rejected
  at startup with "Invalid netmask".
