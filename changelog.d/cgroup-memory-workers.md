Fixed

- **Scripthash build and `tx.head` rebuild respect a cgroup memory limit.**
  On Linux both pools size their workers from the smaller of `MemAvailable`
  and the cgroup v2 headroom (`memory.max` / `memory.high` less the working
  set, at the node's cgroup and each parent). Before, a node under
  systemd `MemoryMax=` or a container limit read the whole host's free RAM
  and could start more workers than the limit holds (#1434).
