#!/usr/bin/env bash
# bitcoin-consensus-spec conformance suites against this tree.
#
#   run.sh build              bcs-conformance (in $BCS_SPEC), rbitcoin-node, bcs-harness
#   run.sh vectors            script, tx, sighash, taproot and BIP340 suites, in process
#   run.sh corpus             the block corpus against rbitcoin-node over RPC
#   run.sh interop BITCOIND   rbitcoin-node syncing each corpus chain from bitcoind
#   run.sh peer-sync BITCOIND rbitcoin-node syncing each corpus chain from the runner,
#                             blocks Core rejects included (bitcoind classifies them)
#
# BCS_SPEC is a checkout of BCS_REPO at BCS_COMMIT (pin.env). A run fails on any
# failure known-failures.txt does not name, and on an entry there that no longer
# fails. The full log is $BCS_LOGS/<suite>.log (default target/consensus-spec).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
# shellcheck source=pin.env
source "$HERE/pin.env"
: "${BCS_SPEC:?set BCS_SPEC to a $BCS_REPO checkout at $BCS_COMMIT}"
BCS_SPEC="$(cd "$BCS_SPEC" && pwd)"
# cargo resolves a relative CARGO_TARGET_DIR against the directory build runs in.
target="${CARGO_TARGET_DIR:-target}"
[[ "$target" == /* ]] || target="$ROOT/$target"
BIN="$target/release"
LOGS="${BCS_LOGS:-$ROOT/target/consensus-spec}"
export BCS_SPEC
export RBTC_NODE="$BIN/rbitcoin-node"

at="$(git -C "$BCS_SPEC" rev-parse HEAD)"
if [[ "$at" != "$BCS_COMMIT" ]]; then
  echo "run.sh: $BCS_SPEC is at $at, pin.env pins $BCS_COMMIT" >&2
  exit 2
fi

# One sh -c word, as the runner's shell_quote makes them: bcs-conformance runs
# --impl and --node through sh -c.
shq() { printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"; }

# An absolute path to a bitcoind of the pinned Core release, or exit 2.
pinned_bitcoind() {
  local bitcoind="$1"
  # suite() runs from the spec checkout.
  [[ "$bitcoind" == /* ]] || bitcoind="$PWD/$bitcoind"
  # bitcoind writes settings.json into its datadir even for --version.
  local probe version
  probe="$(mktemp -d "${TMPDIR:-/tmp}/rbtc-bcs-probe.XXXXXX")"
  version="$("$bitcoind" -datadir="$probe" --version | head -n 1)"
  rm -rf "$probe"
  if [[ "$version" != *" $BCS_CORE_VERSION"* ]]; then
    echo "run.sh: $bitcoind is \"$version\", the spec is pinned to $BCS_CORE_VERSION" >&2
    exit 2
  fi
  printf '%s' "$bitcoind"
}

suite() {
  local name="$1"
  shift
  mkdir -p "$LOGS"
  local log="$LOGS/$name.log"
  set +e
  (cd "$BCS_SPEC" && target/release/bcs-conformance "$@" \
    --known-failures "$HERE/known-failures.txt" --verbose) >"$log" 2>&1
  local ec=$?
  set -e
  sed -n '/^suite /,$p' "$log"
  grep -E '^(FAIL|DIVERGE|STALE) ' "$log" | head -n 40 || true
  return "$ec"
}

case "${1:-}" in
  build)
    (cd "$BCS_SPEC" && CARGO_TARGET_DIR="$BCS_SPEC/target" cargo build --release --locked -p conformance-runner)
    (cd "$ROOT" && cargo build --release --locked -p rbitcoin-node -p rbitcoin-test \
      --bin rbitcoin-node --bin bcs-harness)
    ;;
  vectors)
    suite vectors --impl "$(shq "$BIN/bcs-harness")" --exclude corpus
    ;;
  corpus)
    suite corpus --suite corpus --timeout 900 \
      --impl "python3 -I $(shq "$HERE/chain_harness.py")"
    ;;
  interop)
    bitcoind="$(pinned_bitcoind "${2:?usage: run.sh interop BITCOIND}")"
    suite interop --suite interop --v2transport --bitcoind "$bitcoind" --node-timeout 900 \
      --node "python3 -I $(shq "$HERE/interop_node.py") --network {network} --datadir {datadir} --peer {peer} --stop-at {stop_at} --options {options}"
    ;;
  peer-sync)
    bitcoind="$(pinned_bitcoind "${2:?usage: run.sh peer-sync BITCOIND}")"
    suite peer-sync --suite peer-sync --bitcoind "$bitcoind" --node-timeout 120 \
      --sync-node "python3 -I $(shq "$HERE/sync_node.py") --network {network} --datadir {datadir} --peer {peer} --options {options}"
    ;;
  *)
    echo "usage: $0 build|vectors|corpus|interop BITCOIND|peer-sync BITCOIND" >&2
    exit 2
    ;;
esac
