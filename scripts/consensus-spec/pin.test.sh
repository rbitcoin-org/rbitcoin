#!/usr/bin/env bash
# Contract: the interop and peer-sync suites' bitcoind has its own pin. bitcoind.toml
# resolves through release_pin.py for both Linux arches to the Core release
# pin.env's BCS_CORE_VERSION names, and consensus-spec.yml fetches from it,
# not from the core-functional inventory. No network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HERE="$ROOT/scripts/consensus-spec"
PIN_PY="$ROOT/scripts/core-functional/release_pin.py"
WF="$ROOT/.github/workflows/consensus-spec.yml"
PASS=0
FAIL=0
source "$ROOT/scripts/contract-assert.sh"

# shellcheck source=pin.env
source "$HERE/pin.env"
# v32.1.0 is released as bitcoin-32.1.
release="${BCS_CORE_VERSION#v}"
release="${release%.0}"

has_line() { grep -Fqx -- "$2" <<<"$1"; }

for arch in x86_64-linux-gnu aarch64-linux-gnu; do
  if ! out="$(python3 "$PIN_PY" --inventory "$HERE/bitcoind.toml" --arch "$arch" 2>&1)"; then
    # The four checks below fail; say why (release_pin.py needs Python 3.11).
    echo "# $arch: release_pin.py failed: $out"
  fi
  assert_ok "$arch version is v$release" has_line "$out" "version=v$release"
  assert_ok "$arch tarball is bitcoin-$release" has_line "$out" "tarball=bitcoin-$release-$arch.tar.gz"
  assert_ok "$arch url is bitcoin-core-$release" has_line "$out" \
    "url=https://bitcoincore.org/bin/bitcoin-core-$release/bitcoin-$release-$arch.tar.gz"
  assert_ok "$arch has a sha256" grep -Eqx 'sha256=[0-9a-f]{64}' <<<"$out"
done

assert_ok "consensus-spec.yml fetches from bitcoind.toml" grep -Fq \
  'FETCH_BITCOIND_INVENTORY=scripts/consensus-spec/bitcoind.toml ./scripts/core-functional/fetch-bitcoind.sh' "$WF"

if [[ "$FAIL" -ne 0 ]]; then
  echo "pin.test.sh: $PASS passed, $FAIL failed"
  exit 1
fi
echo "pin.test.sh: $PASS passed"
