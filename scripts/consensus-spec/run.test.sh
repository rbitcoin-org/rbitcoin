#!/usr/bin/env bash
# Contract: run.sh is the release gate's verdict. It refuses a spec checkout
# that is not at pin.env's BCS_COMMIT and a bitcoind that is not the pinned
# Core release, exits as the runner does, prints the runner's summary (or its
# last lines when it stopped before one), and hands the runner commands that
# survive sh -c from a path with a space or a quote in it.
# No network and no build: git, the runner, the harness and bitcoind are stubs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RUN="$ROOT/scripts/consensus-spec/run.sh"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"
# shellcheck source=pin.env
source "$ROOT/scripts/consensus-spec/pin.env"

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/rbitcoin-bcs-run.XXXXXX")"
# As the shell names it after cd (macOS TMPDIR ends in a slash).
WORKDIR="$(cd "$WORKDIR" && pwd)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# A spec checkout and a cargo target directory, each with a space and a quote.
SPEC="$WORKDIR/the spec's"
TARGET="$WORKDIR/tar get's"
mkdir -p "$WORKDIR/bin" "$SPEC/target/release" "$TARGET/release"

# run.sh asks git only for the checkout's HEAD.
cat >"$WORKDIR/bin/git" <<'EOF'
#!/bin/sh
echo "$STUB_HEAD"
EOF

# The runner: records its arguments, then acts out one run.
cat >"$SPEC/target/release/bcs-conformance" <<'EOF'
#!/bin/sh
: >"$STUB_ARGS"
for a in "$@"; do printf '%s\n' "$a" >>"$STUB_ARGS"; done
case "$STUB_MODE" in
  pass)
    echo "LEVEL2 a line before the summary"
    echo "suite   cases  passed"
    echo "RESULT: PASS"
    ;;
  fail)
    echo "FAIL    [corpus] feature_block.node0 check 1"
    echo "suite   cases  passed"
    echo "RESULT: FAIL"
    exit 1
    ;;
  dead)
    echo "bcs-conformance: info failed: harness died"
    exit 1
    ;;
  impl)
    # As the runner starts a harness: its --impl value through sh -c.
    echo "suite   cases  passed"
    while [ "$#" -gt 1 ]; do
      if [ "$1" = --impl ]; then sh -c "$2"; fi
      shift
    done
    ;;
esac
exit 0
EOF

printf '#!/bin/sh\necho "the harness ran"\n' >"$TARGET/release/bcs-harness"

bitcoind_stub() {
  printf '#!/bin/sh\necho "Bitcoin Core daemon version %s bitcoind"\n' "$2" >"$1"
  chmod +x "$1"
}
bitcoind_stub "$WORKDIR/bitcoind-pinned" "$BCS_CORE_VERSION"
bitcoind_stub "$WORKDIR/bitcoind-other" "v0.0.1"
chmod +x "$WORKDIR/bin/git" "$SPEC/target/release/bcs-conformance" "$TARGET/release/bcs-harness"

export PATH="$WORKDIR/bin:$PATH"
export BCS_SPEC="$SPEC" BCS_LOGS="$WORKDIR/logs" CARGO_TARGET_DIR="$TARGET"
export STUB_ARGS="$WORKDIR/args" STUB_HEAD="$BCS_COMMIT" STUB_MODE=pass

# Runs run.sh with stdout and stderr in $out and its exit status in $ec.
run() {
  ec=0
  out="$("$RUN" "$@" 2>&1)" || ec=$?
}
says() { grep -Fq -- "$1" <<<"$out"; }
arg_after() { grep -Fx -A 1 -- "$1" "$STUB_ARGS" | tail -n 1; }

run vectors
assert_ok "a passing run exits 0" test "$ec" -eq 0
assert_ok "a passing run prints the summary" says "RESULT: PASS"
assert_fail "lines before the summary stay in the log" says "LEVEL2"
assert_ok "the full log is kept" grep -q LEVEL2 "$WORKDIR/logs/vectors.log"
assert_ok "the runner gets known-failures.txt" test \
  "$(arg_after --known-failures)" = "$ROOT/scripts/consensus-spec/known-failures.txt"

STUB_MODE=fail run corpus
assert_ok "a failing run exits as the runner does" test "$ec" -eq 1
assert_ok "a failing run prints its FAIL lines" says "FAIL    [corpus] feature_block.node0 check 1"

STUB_MODE=dead run corpus
assert_ok "a runner that stops before its summary exits non-zero" test "$ec" -eq 1
assert_ok "and its last lines are printed" says "harness died"

STUB_MODE=impl run vectors
assert_ok "--impl survives sh -c from a path with a space and a quote" says "the harness ran"

STUB_HEAD=0000000000000000000000000000000000000000 run vectors
assert_ok "another spec revision exits 2" test "$ec" -eq 2
assert_ok "and names the pin" says "pin.env pins $BCS_COMMIT"

: >"$STUB_ARGS"
run interop "$WORKDIR/bitcoind-other"
assert_ok "a bitcoind of another release exits 2" test "$ec" -eq 2
assert_ok "and names the pinned release" says "the spec is pinned to $BCS_CORE_VERSION"
assert_ok "and the runner is not started" test ! -s "$STUB_ARGS"

rel=0
(cd "$WORKDIR" && run peer-sync bitcoind-pinned && exit "$ec") || rel=$?
assert_ok "a relative bitcoind of the pinned release is accepted" test "$rel" -eq 0
assert_ok "and reaches the runner as an absolute path" test \
  "$(arg_after --bitcoind)" = "$WORKDIR/bitcoind-pinned"

run
assert_ok "no suite exits 2" test "$ec" -eq 2

if [[ "$FAIL" -ne 0 ]]; then
  echo "run.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "run.test.sh: $PASS passed"
