#!/usr/bin/env python3
"""rbitcoin-node as the live node of the peer-sync suite (bitcoin-consensus-spec
conformance/PROTOCOL.md section 5.1).

usage: sync_node.py --network N --datadir D --peer HOST:PORT --options JSON

Starts rbitcoin-node on an empty datadir, connected only to the peer (the
runner, which serves blocks Core rejects as well as the chain), with the
scenario's test activation heights. Answers each request on standard input:

  {"op":"tip","id":n}  ->  {"event":"tip","id":n,"tip":hash,"height":n}
  {"op":"stop"}        ->  {"event":"stopped","tip":hash,"height":n}

A tip request first waits until getblockchaininfo reports initialblockdownload
false: during catch-up the IBD confirm engine connects blocks behind RPC's
back. That flag also needs a tip younger than --max-tip-age, and corpus blocks
carry the time they were recorded, so the node runs with a maximum tip age
that never expires. RBITCOIN_RPC_WAIT_TIP_IDLE=1 then makes getbestblockhash
and getblockcount wait for the tip-accept lane, so the answer covers every
block the node has received. Standard input closing stops the node.

The runner starts this command in a process group of its own and signals the
whole group when it gives up on it, so rbitcoin-node needs no watchdog here.

Environment: RBTC_NODE (rbitcoin-node).
"""

import argparse
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import time

NODE = os.environ["RBTC_NODE"]
# Seconds; any tip is recent enough, so initialblockdownload ends with catch-up.
MAX_TIP_AGE = 2**62


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def fail(message):
    emit({"event": "error", "message": message})
    sys.exit(1)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Rpc:
    def __init__(self, port, token_path):
        self.port = port
        self.token_path = token_path
        self.auth = None
        self.id = 0

    def call(self, method, *params):
        if self.auth is None:
            self.auth = "Bearer " + open(self.token_path).read().strip()
        self.id += 1
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=300)
        try:
            body = json.dumps({"jsonrpc": "2.0", "id": self.id, "method": method, "params": list(params)})
            conn.request("POST", "/", body, {"Authorization": self.auth, "Content-Type": "application/json"})
            obj = json.loads(conn.getresponse().read())
        finally:
            conn.close()
        if obj.get("error"):
            raise RuntimeError("%s: %s" % (method, obj["error"]))
        return obj["result"]

    def tip(self):
        # Two calls; a block connected between them shows as a height change.
        while True:
            height = self.call("getblockcount")
            best = self.call("getbestblockhash")
            if self.call("getblockcount") == height:
                return best, height


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", required=True)
    ap.add_argument("--datadir", required=True)
    ap.add_argument("--peer", required=True)
    ap.add_argument("--options", default="{}")
    a = ap.parse_args()
    options = json.loads(a.options or "{}")
    if options.get("test"):
        fail("rbitcoin-node has no regtest switch for %s (Core -test=)" % options["test"])
    if options.get("vbparams"):
        fail("rbitcoin-node has no -vbparams")

    port = free_port()
    args = [NODE, "--network", a.network, "--datadir", a.datadir, "--connect", a.peer,
            "--no-listen", "--no-seeds", "--no-discover", "--rpc-listen", "127.0.0.1:%d" % port,
            "--max-tip-age", str(MAX_TIP_AGE)]
    for name, h in sorted(options.get("testactivationheight", {}).items()):
        args += ["--test-activation-height", "%s@%d" % (name, h)]
    env = dict(os.environ)
    env["RBITCOIN_RPC_WAIT_TIP_IDLE"] = "1"
    log = open(os.path.join(a.datadir, "node.log"), "wb")
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, env=env)
    rpc = Rpc(port, os.path.join(a.datadir, "rpc.token"))

    def stop(code):
        try:
            rpc.call("stop")
        except Exception:  # noqa: BLE001
            pass
        try:
            proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        return code

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(stop(1)))
    deadline = time.time() + 120
    while True:
        if proc.poll() is not None:
            fail("rbitcoin-node exited at start with %s (see %s/node.log)" % (proc.returncode, a.datadir))
        try:
            rpc.call("getblockcount")
            break
        except Exception:  # noqa: BLE001
            if time.time() > deadline:
                stop(1)
                fail("rbitcoin-node RPC did not come up")
            rpc.auth = None
            time.sleep(0.1)

    try:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            req = json.loads(line)
            if proc.poll() is not None:
                fail("rbitcoin-node exited with %s (see %s/node.log)" % (proc.returncode, a.datadir))
            if req.get("op") == "tip":
                while rpc.call("getblockchaininfo")["initialblockdownload"]:
                    time.sleep(0.05)
                best, height = rpc.tip()
                emit({"event": "tip", "id": req["id"], "tip": best, "height": height})
            elif req.get("op") == "stop":
                best, height = rpc.tip()
                emit({"event": "stopped", "tip": best, "height": height})
                sys.exit(stop(0))
    except Exception as e:  # noqa: BLE001
        stop(1)
        fail("RPC failed: %s" % e)
    sys.exit(stop(1))


if __name__ == "__main__":
    main()
