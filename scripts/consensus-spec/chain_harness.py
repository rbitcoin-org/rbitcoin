#!/usr/bin/env python3
"""Chain operations of bitcoin-consensus-spec conformance/PROTOCOL.md, answered
by rbitcoin-node.

Reuses the spec's Core chain harness (conformance/recorder/core_chain_harness.py)
and swaps only the node it drives: each chain_reset starts a fresh
`rbitcoin-node --network regtest` with an empty datadir, a loopback RPC port, no
P2P listener, no seeds and no peers. Blocks go through submitblock, headers
through submitheader, the clock through setmocktime. The Core P2P rules for a
`via: p2p` delivery (mutated-block drop, anti-DoS work, unrequested blocks,
headers messages) are applied by that harness on top of the RPCs, so the corpus
tests block validation, storage, chain selection, reorganization and
invalidateblock. rbitcoin's own P2P handling is the interop suite's.

Not listed: utxo_hash (rbitcoin keeps no UTXO set). Refused on chain_reset:
`test` (rbitcoin has no regtest -test=bip94) and `vbparams`.

Environment: BCS_SPEC (spec checkout), RBTC_NODE (rbitcoin-node), RBTC_WORK
(parent of the datadirs, default the system temp dir), BCS_HARNESS_KEEP=1 keeps
the datadirs.
"""

import os
import shutil
import subprocess
import sys
import tempfile
import time

SPEC = os.environ["BCS_SPEC"]
NODE = os.environ["RBTC_NODE"]
WORK = os.environ.get("RBTC_WORK") or tempfile.gettempdir()
sys.path.insert(0, os.path.join(SPEC, "conformance", "recorder"))

import core_chain_harness as core  # noqa: E402

core.OPS = [op for op in core.OPS if op != "utxo_hash"]


def node_version():
    out = subprocess.run([NODE, "--version"], capture_output=True, text=True, timeout=30)
    return (out.stdout or out.stderr).strip().splitlines()[0]


class RNode(core.Node):
    def __init__(self, options):
        options = options or {}
        unknown = set(options) - {"testactivationheight", "test", "vbparams"}
        if unknown:
            raise core.BadRequest("unsupported options: %s" % ", ".join(sorted(unknown)))
        if options.get("test"):
            raise core.BadRequest("rbitcoin-node has no regtest switch for %s (Core -test=)" % options["test"])
        if options.get("vbparams"):
            raise core.BadRequest("rbitcoin-node has no -vbparams")
        os.makedirs(WORK, exist_ok=True)
        self.dir = tempfile.mkdtemp(prefix="rbtc-bcs-", dir=WORK)
        self.port = core.free_port()
        self.id = 0
        self.conn = None
        self.auth = None
        self.mocktime = None
        self.segwit_height = int(options.get("testactivationheight", {}).get("segwit", 0))
        args = [NODE, "--network", "regtest", "--datadir", self.dir,
                "--rpc-listen", "127.0.0.1:%d" % self.port,
                "--no-listen", "--no-seeds", "--no-discover"]
        for name, h in sorted(options.get("testactivationheight", {}).items()):
            args += ["--test-activation-height", "%s@%d" % (name, h)]
        env = dict(os.environ)
        # As the Core functional shim does: tip reads wait for the tip-accept lane.
        env["RBITCOIN_RPC_WAIT_TIP_IDLE"] = "1"
        self.log = open(os.path.join(self.dir, "node.log"), "wb")
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT, env=env)
        deadline = time.time() + 120
        token_path = os.path.join(self.dir, "rpc.token")
        while True:
            if self.proc.poll() is not None:
                self.abandon("rbitcoin-node exited at start")
            try:
                self.auth = "Bearer " + open(token_path).read().strip()
                self.call("getblockcount")
                break
            except (OSError, core.RPCError, ValueError):
                if time.time() > deadline:
                    self.abandon("rbitcoin-node did not come up")
                self.conn = None
                time.sleep(0.05)

    def tail(self, n=2000):
        try:
            self.log.flush()
            with open(os.path.join(self.dir, "node.log"), "rb") as f:
                return f.read()[-n:].decode(errors="replace")
        except OSError:
            return ""

    def abandon(self, why):
        # The harness never holds a node that did not come up, so its stop() will
        # not run: end the process and remove the datadir here.
        tail = self.tail()
        self.reap(0)
        raise RuntimeError("%s: %s" % (why, tail))

    def stop(self):
        try:
            self.call("stop")
        except Exception:  # noqa: BLE001
            pass
        self.reap(120)

    def reap(self, grace):
        try:
            self.proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()
        if core.KEEP:
            core.log("kept datadir %s" % self.dir)
        else:
            shutil.rmtree(self.dir, ignore_errors=True)

    def tip(self):
        # getbestblockhash waits for the tip-accept lane; getblockchaininfo does not.
        self.call("getbestblockhash")
        return self.call("getblockchaininfo")

    def segwit_after(self, prev_hash):
        # getdeploymentinfo answers only for a block with data, so a header-only
        # parent falls back to the activation height.
        try:
            return bool(self.call("getdeploymentinfo", prev_hash)["deployments"]["segwit"]["active"])
        except (core.RPCError, KeyError, TypeError):
            hdr = self.header(prev_hash)
            return hdr is not None and hdr["height"] + 1 >= self.segwit_height


class RHarness(core.Harness):
    def handle(self, req):
        if req.get("op") == "info":
            return {"name": "rbitcoin-node (RPC; Core P2P rules applied by the harness)",
                    "version": node_version(), "spec_version": "v32.1", "ops": core.OPS}
        if req.get("op") == "utxo_hash":
            return None
        return super().handle(req)


core.Node = RNode
core.Harness = RHarness

if __name__ == "__main__":
    core.main()
