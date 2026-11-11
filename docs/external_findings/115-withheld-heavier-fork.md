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

**Fix:** IBD proves a heavier fork is served before it switches to it.
When headers show a fork with more work than the download candidate, the
walk takes it only after peers have served the shortest prefix of it whose
work beats this node's chain with data above the fork point: its confirmed
blocks there, then the download path's bodies already queued. Each body is
checked against its header (block hash and merkle root) and held in RAM,
at most 64 MiB across two forks and 1,025 blocks per fork; under the work
floor the first 1,025 are enough. Then the walk takes the fork, the
confirmed tip rewinds to the fork point, and the served bodies go to the
body queue. Taking the fork never leaves the node with less work it can
connect than before, so a peer that serves part of that prefix and then
withholds, or leaves after serving it, cannot hold the tip down. A fork
where this node has no data above the fork point needs no proof. A fork
nobody serves never moves the walk, the path, or the tip, however much
later its headers come again.

The fork's blocks are asked only of the peer that sent it or a peer whose
headers announced it. A peer reader passes such a block on even when it was
not requested, still charged to its rate window, so a peer that connects
later and pushes the block proves the fork; no other unrequested block
reaches the coordinator. A peer whose record shows another chain at or below
a block is never asked for it, and a request already sent to it is released
as if it had answered `notfound`, so an honest peer is not dropped for a
block it never had. Catch-up does not finish while a proof request is in
flight or a served fork is being handed back to the walk; a withholder holds
that for at most one stall window.

The same holds after a restart: a stored fork beside the confirmed chain is
rewound onto only when that prefix is in Class A or served, and until then
the confirmed tip's own chain is seeded.

One case does not go through a fork offer: when the withholder is the first
header peer, its chain is the candidate from the start. When no live peer
has been able to serve the path's next block for one stall window (30 s on
the node clock) and a live peer's chain differs there, that candidate is
retired like a failed block, without an invalid mark. It comes back only
through the proof above. A second `notfound` for a requested block holds
across re-announcements for one stall window, so re-announcing does not keep
such a block looking served.

**Regression:** `rbitcoin-ibd` `withheld_fork::withheld_fork_rewind_silent`,
`withheld_fork_rewind_notfound`, `withheld_fork_rewind_notfound_reannounced`,
`withheld_fork_rewind_disconnect`, `withheld_fork_from_start_silent`,
`withheld_fork_from_start_notfound`, `withheld_fork_restart_honest_only`,
`withheld_fork_restart_both_peers`, `withheld_fork_extends_honest_tip` (a fork
that only extends the honest tip is still harmless),
`withheld_fork_reannounced_much_later_does_not_rewind`,
`unrequested_fork_blocks_prove_the_fork`,
`withheld_fork_after_its_first_block_does_not_rewind`,
`served_fork_is_taken_after_its_peer_leaves`,
`heavier_fork_served_after_one_notfound_is_adopted`,
`ibd::fork_proof::*`, `ibd::manual_stall::an_unrequested_block_a_fork_proof_wants_reaches_the_coordinator`,
`ibd::header_walk::a_withheld_chain_is_retired_after_one_window`,
`a_retired_chain_is_refused_until_peers_serve_it`,
`ibd::path::seed_rewinds_tip_to_lca_on_heavier_sibling`,
`ibd::peer_chain::a_second_refusal_outlasts_announcements`.
