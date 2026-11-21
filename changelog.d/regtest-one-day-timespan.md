Fixed

- **Regtest's difficulty period is 144 blocks, as in Core.** Its target
  timespan was rust-bitcoin's two weeks, so the period was 2016 blocks.
  The minimum-difficulty walk now stops at a multiple of 144.
  `getnetworkhashps` with `nblocks` at or below 0 counts back to the last
  multiple of 144. `getblocktemplate` sets `mintime` from the new period:
  the timewarp floor applies at a multiple of 144, and the floor that keeps
  a period's last block from being earlier than its first applies one height
  before it. With `--regtest-pow-bits`, a block at a multiple of 144 now
  keeps its parent's bits. Two kinds of block mined there before this change
  no longer pass: one with the `--regtest-pow-bits` bits whose parent has
  the pow limit, and one with the pow limit, more than two spacings after a
  harder parent. A datadir holding such a block still opens, because open
  does not check `nBits` again, but a node syncing that chain rejects the
  block, so the chain needs to be mined again. A chain whose blocks all have
  the pow limit is unaffected (#1775).
