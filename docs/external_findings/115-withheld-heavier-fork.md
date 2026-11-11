# 115 — IBD stayed below a heavier fork whose bodies were never served

**Severity:** high (IBD and restart catch-up stop below the honest tip)
**Status:** fixed
**Found by:** chain-selection audit against Core, 2026-11

During IBD or restart catch-up, a peer sent headers for a fork with more
work than the chain being downloaded, then never served the fork's blocks:
it stayed silent, answered `notfound`, or disconnected. IBD rewinds to the
fork point on header work ([architecture](../architecture.md), most-work
chain selection), so the confirmed tip went back to the fork point and
stayed there while an honest peer served every block of its own chain.
Only a strictly heavier honest chain got the node moving again. A restart
seeded the stored fork again. Once the attacker was gone, the honest peer
was asked for the fork's blocks, could not answer, and was disconnected as
quiet with growing cooldowns.

Core connects the most-work chain whose blocks it has. A header-only chain
stays in the block index and is never a candidate tip until its data is
complete (`FindMostWorkChain`, `BLOCK_HAVE_DATA`), and a peer is asked
only for blocks on its own best known chain.

**Fix:** IBD keeps rewinding on header work. When the confirmed tip has
needed the planted branch's next block for one stall window (30 s on the
node clock) and no live peer may serve it (no peer showed it, the one that
did answered `notfound`, or it was disconnected), while a live peer's
chain is another chain at that height, the branch is retired at that
block like a failed one, but it is not marked invalid. A `--connect` peer
paused for stalling still counts as serving a block it showed. The
download path is seeded again from stored headers without the branch for
ten minutes, the first stall-kick cooldown. The addresses that announced
it are not believed about it for that long. Another address that
announces it reopens it without clearing those marks, and a retire past
the cap drops only the oldest chain. A peer whose record shows another
chain at or below a block is never asked for it, and a request already
sent to it is released as if it had answered `notfound`. A peer that
refuses a requested block twice is not asked for it for one stall window,
even if it announces its chain again. The reserved header peer, or a lone
peer, is probed when a rewind left its record stale or no peer has shown
the next block, so its record can say which chain it is on.

Restart keeps no withheld mark. A restart that reseeds the stored fork
retires it again one window after a peer's record shows its own chain.

**Regression:** `rbitcoin-ibd` `withheld_fork::withheld_fork_rewind_notfound`,
`withheld_fork_rewind_notfound_reannounced`, `withheld_fork_rewind_disconnect`,
`withheld_fork_from_start_notfound`, `withheld_fork_restart_honest_only`,
`withheld_fork_restart_both_peers`, `withheld_fork_extends_honest_tip` (a
fork that only extends the honest tip is still harmless),
`heavier_fork_served_after_one_notfound_is_adopted`,
`ibd::header_walk::a_withheld_chain_is_retired_after_one_window`,
`a_withheld_chain_is_refused_only_from_its_announcer`,
`ibd::peer_chain::a_second_refusal_outlasts_announcements`. The silent
journeys `withheld_fork_rewind_silent` and `withheld_fork_from_start_silent`
are ignored: they wait out the real 30 s stall floor.
