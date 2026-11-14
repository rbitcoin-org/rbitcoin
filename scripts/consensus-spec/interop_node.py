#!/usr/bin/env python3
"""rbitcoin-node as the live node of the interop suite (bitcoin-consensus-spec
conformance/PROTOCOL.md section 5).

usage: interop_node.py --network N --datadir D --peer HOST:PORT --stop-at HASH --options JSON

Starts rbitcoin-node on an empty datadir, connected only to the peer, with the
scenario's test activation heights. rbitcoin dials BIP324 v2 only, so the runner
needs --v2transport. When the active tip is the stop hash it prints the stopped
line and exits 0. The line has no hash_serialized_3: rbitcoin keeps no UTXO set.

Environment: RBTC_NODE (rbitcoin-node), RBTC_STALL_SECS (seconds without tip
progress before giving up, default 120).
"""

import argparse
import atexit
import http.client
import json
import os
import signal
import socket
import subprocess
import sys
import time

NODE = os.environ["RBTC_NODE"]
STALL = float(os.environ.get("RBTC_STALL_SECS", "120"))


def emit(obj):
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def fail(message, tip=None, height=None):
    ev = {"event": "error", "message": message}
    if tip is not None:
        ev["tip"] = tip
        ev["height"] = height
    emit(ev)
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
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        try:
            body = json.dumps({"jsonrpc": "2.0", "id": self.id, "method": method, "params": list(params)})
            conn.request("POST", "/", body, {"Authorization": self.auth, "Content-Type": "application/json"})
            obj = json.loads(conn.getresponse().read())
        finally:
            conn.close()
        if obj.get("error"):
            raise RuntimeError("%s: %s" % (method, obj["error"]))
        return obj["result"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", required=True)
    ap.add_argument("--datadir", required=True)
    ap.add_argument("--peer", required=True)
    ap.add_argument("--stop-at", required=True)
    ap.add_argument("--options", default="{}")
    a = ap.parse_args()
    options = json.loads(a.options or "{}")
    if options.get("test"):
        fail("rbitcoin-node has no regtest switch for %s (Core -test=)" % options["test"])
    if options.get("vbparams"):
        fail("rbitcoin-node has no -vbparams")

    port = free_port()
    args = [NODE, "--network", a.network, "--datadir", a.datadir, "--connect", a.peer,
            "--no-listen", "--no-seeds", "--no-discover", "--rpc-listen", "127.0.0.1:%d" % port]
    for name, h in sorted(options.get("testactivationheight", {}).items()):
        args += ["--test-activation-height", "%s@%d" % (name, h)]
    env = dict(os.environ)
    env["RBITCOIN_RPC_WAIT_TIP_IDLE"] = "1"
    log = open(os.path.join(a.datadir, "node.log"), "wb")
    proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, env=env)
    # The runner SIGKILLs this wrapper on --node-timeout, which no handler sees,
    # so a detached watchdog stops rbitcoin-node once this process is gone.
    watchdog = subprocess.Popen(
        ["/bin/sh", "-c",
         "while kill -0 %d 2>/dev/null; do sleep 1; done; kill %d 2>/dev/null; "
         "i=0; while [ $i -lt 15 ] && kill -0 %d 2>/dev/null; do sleep 1; i=$((i+1)); done; "
         "kill -0 %d 2>/dev/null && kill -9 %d" % (os.getpid(), proc.pid, proc.pid, proc.pid, proc.pid)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)

    def reap():
        # On every exit Python sees. The watchdog acts only once this process is
        # gone, so ending it here leaves it nothing to signal; it stays for a
        # SIGKILL alone. Then make sure the node is down.
        watchdog.kill()
        watchdog.wait()
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    atexit.register(reap)
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

    tip, height = None, -1
    last_change = time.time()
    while True:
        if proc.poll() is not None:
            fail("rbitcoin-node exited with %s (see %s/node.log)" % (proc.returncode, a.datadir), tip, height)
        try:
            best = rpc.call("getbestblockhash")
            h = rpc.call("getblockcount")
        except Exception as e:  # noqa: BLE001
            stop(1)
            fail("RPC failed: %s" % e, tip, height)
        if best != tip:
            tip, height = best, h
            last_change = time.time()
            emit({"event": "tip", "tip": tip, "height": height})
        if tip == a.stop_at:
            emit({"event": "stopped", "tip": tip, "height": height})
            sys.exit(stop(0))
        if time.time() - last_change > STALL:
            stop(1)
            fail("no tip progress for %d s" % STALL, tip, height)
        time.sleep(0.25)


if __name__ == "__main__":
    main()
