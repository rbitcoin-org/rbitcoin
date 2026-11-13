# 088 — Tip-follow chain selection diverged from Core

**Component:** `rbitcoin-net` (`ChainHub::accept_received_block`,
`accept_incoming`, `accept_branch`, `try_apply_held`)
**Severity:** high (the node stays on a lighter chain, or rewinds to one)
**Status:** partial. F1, F2, and F4 are fixed. F3 (reorg depth) is open.
**Found by:** chain-selection audit, 2026-10 (regtest scripts that call
`accept_received_block`)

Core follows the valid chain with the most total work. It ranks every
candidate tip by `nChainWork` (`CBlockIndexWorkComparator`), and equal
work goes to the first-seen tip. When a block fails connect, Core marks
it invalid (`InvalidChainFound`) and selects again from the remaining
candidates (`ActivateBestChain`). Core checks a header's `nBits` in
`AcceptBlockHeader`, before any tip change.

## F1: held branches ranked by local work

`try_apply_held` scored each held branch by the work summed from its own
fork point. Two branches that fork at different heights can have equal
local work while one has more total work. Example: the tip is `x3`, the
branch `y2, y3` forks at `x1`, and the branch `z3, z4` forks at `x2`.
Both scored two blocks. The first seen (`y3`) won the tie, then only
tied with the tip, and the apply stopped. `z4` was never tried. A
failed branch also returned its error at once, so a lighter valid
branch that still beat the tip was not tried.

**Fix:** rank by fork-point chain work plus branch work. When the best
branch fails, remember it as invalid and try the next best.

## F2: a mid-branch failure restored a lighter tip

When block `k` of a side branch failed connect, `accept_branch` always
restored the old tip, even when blocks `0..k` already had more work. The
error named the failing block, but it was returned for whichever block
triggered the apply. A `submitblock` of a valid parent was then rejected
and marked invalid. The restore also skipped any old height whose body
it could not rebuild, so it could reconnect blocks at the wrong heights.

**Fix:** keep the connected prefix when it has strictly more work than
the old branch, else restore the old branch. A held block's failure is
that block's verdict, not the offered block's. When the offered block is
the one that failed, its submit fails even though the kept prefix is the
new tip. Tip events of the kept prefix carry the connected branch
length, so peers get headers for a short reorg, not an inv. A missing
old body is a store invariant error. A restore that does not finish is a
store fault: no block is marked invalid and no other branch is tried on
the torn tip.

## F4: a same-height sibling disconnected the tip before validation

A sibling of the tip was compared on claimed header work only. If it
claimed more work, the tip was disconnected and the sibling connected.
If that connect failed, nothing was restored. Siblings with wrong
`nBits` (for example `0x1700ffff` on regtest) rewound the tip one block
per sibling. The P2P `block` handler stores the header first, but
`submitblock` and the compact-block paths did not.

**Fix:** check a side block's header in context (bits, median time,
version, proof of work) in `accept_incoming`, before any tip change, on
every entry path. The sibling goes through `accept_branch`, so F2's
restore applies.

## F3 (open): reorg depth

Tip-follow cannot adopt a heavier branch that forks more than 288 blocks
below the tip. `hold_body` does not keep a side body more than
`HeldBodies::STALE_BELOW` (288) below the tip, so the branch cannot be
built. Tip-follow never hands off to the IBD rewind. IBD's
`apply_header_rewind` refuses a rewind deeper than `REWIND_MAX_DEPTH`
(1024) and only logs a warning. Restart does not help: the resume seed
only looks 32 heights below the tip. Example: a 300-block chain, then a
302-block chain from genesis. Every side block is `IgnoredWeaker`, and
the tip stays at 300. With `--prune-seqsigwit`, a disconnect below the
pruned height fails with `Pruned`, so a deep rewind can stop partway
and leave the tip between the old tip and the LCA.

Raising the held window is not a fix. That would be a large
process-resident body cache ([`ibd-memory.md`](../ibd-memory.md)). Core
keeps the old chain active until the new bodies are on disk. A fix needs
one of two designs:

- Tip-follow hands a deep heavier header chain to the IBD rewind. IBD
  disconnects to the LCA only after peers served the fork blocks that
  out-work the old chain above it ([115](./115-withheld-heavier-fork.md)),
  so it no longer sits on a lighter chain while it downloads. Up to 64 MiB
  of those bodies are kept for the switch; the rest are fetched again
  after it.
- Unconnected side bodies are stored on disk. This is a store change.

Both are design decisions, so neither is in this change.

**Regression:** `rbitcoin-net`
`chain::tests::sibling_claiming_more_work_with_wrong_bits_keeps_the_tip`
(F4), `failed_branch_tip_keeps_the_heavier_valid_prefix`,
`failed_branch_tip_does_not_reject_the_offered_parent`,
`failed_offered_block_is_rejected_when_its_held_prefix_stays`,
`peer::tests::tip_announce_kept_prefix_of_failed_reorg_is_headers` (F2),
`held_branch_with_more_total_work_beats_an_earlier_local_tie`,
`failed_heavier_held_branch_does_not_hide_a_valid_one` (F1).
