"""Live demo: two bridge processes talk over the mesh, driven exactly as
two Claude Code instances would drive them — real MCP JSON-RPC over stdio.

No Claude needed: this script plays the role of both Claude clients. It
spawns alice's and bob's bridges as subprocesses, does the MCP handshake
with each, then:

    alice's client  --send_message-->  alice bridge  ==mesh==>  bob bridge
    bob's client    --check_inbox-->   bob bridge  (reads the verified msg)

Run:  python demo_conversation.py
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import time

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
from gen_bridge_config import generate  # noqa: E402

_BRIDGE = _HERE / "mesh_mcp_bridge.py"


class Client:
    """Stands in for one Claude Code instance driving its bridge over stdio."""

    def __init__(self, name: str, peer: str, cfgdir: pathlib.Path):
        self.name = name
        self.proc = subprocess.Popen(
            [sys.executable, str(_BRIDGE), "--name", name, "--peer", peer,
             "--config", str(cfgdir)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True,
        )
        self._id = 0

    def _rpc(self, method, params=None, notify=False):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        if not notify:
            self._id += 1
            msg["id"] = self._id
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        if notify:
            return None
        return json.loads(self.proc.stdout.readline())

    def initialize(self):
        r = self._rpc("initialize", {"protocolVersion": "2025-06-18",
                                     "capabilities": {}, "clientInfo": {"name": self.name}})
        self._rpc("notifications/initialized", notify=True)
        return r["result"]["serverInfo"]["name"]

    def call(self, tool, args=None):
        r = self._rpc("tools/call", {"name": tool, "arguments": args or {}})
        return r["result"]["content"][0]["text"]

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:  # noqa: BLE001
            pass
        self.proc.terminate()
        self.proc.wait(timeout=5)


def line(c="-"):
    print(c * 66)


def main():
    with tempfile.TemporaryDirectory() as td:
        cfgdir = pathlib.Path(td) / "mesh-config"
        generate(cfgdir, ["alice", "bob"])

        print("\nTWO CLAUDE-SHAPED CLIENTS TALKING OVER THE MESH — LIVE")
        line("=")
        alice = Client("alice", "bob", cfgdir)
        bob = Client("bob", "alice", cfgdir)
        try:
            print(f"alice's bridge : {alice.initialize()}")
            print(f"bob's bridge   : {bob.initialize()}")
            time.sleep(0.3)  # let both mesh listeners bind + publish addr

            line()
            print("alice's Claude calls  send_message(to='bob', body='ping!')")
            line()
            print("  bridge says:", alice.call(
                "send_message", {"to": "bob", "body": "ping! are you there, bob?"}))

            time.sleep(0.4)  # mesh delivery + verify

            line()
            print("bob's Claude calls  check_inbox()")
            line()
            print("  bob sees:\n   ", bob.call("check_inbox"))

            line()
            print("bob replies:  send_message(to='alice', body='pong!')")
            line()
            print("  bridge says:", bob.call(
                "send_message", {"to": "alice", "body": "pong! loud and clear."}))
            time.sleep(0.4)

            line()
            print("alice's Claude calls  check_inbox()")
            line()
            print("  alice sees:\n   ", alice.call("check_inbox"))

            line("=")
            print("Two separate MCP servers exchanged signed, verified messages")
            print("over a real TCP mesh hop. Swap these clients for two real")
            print("Claude Code instances and it is the same path.\n")
        finally:
            alice.close()
            bob.close()


if __name__ == "__main__":
    main()
