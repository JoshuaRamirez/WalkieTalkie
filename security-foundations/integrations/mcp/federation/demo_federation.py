"""Live demo: one MCP client, one gateway, two federated tool servers.

Plays the role of a Claude Code client: spawns the gateway as a subprocess
and drives real MCP JSON-RPC over stdio, while two backend tool servers run
in-process on the mesh. Shows discovery (the gateway learns both backends),
aggregation (one tools/list, namespaced), and routing (each call reaches
the right backend).

Run:  python demo_federation.py
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))

from tool_server import DEPLOY_TOOLS, REPO_TOOLS, ToolServer  # noqa: E402

_GATEWAY = _HERE / "mcp_gateway.py"


class _Client:
    def __init__(self, registry):
        self.proc = subprocess.Popen(
            [sys.executable, str(_GATEWAY), "--registry", str(registry)],
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
        return None if notify else json.loads(self.proc.stdout.readline())

    def initialize(self):
        r = self._rpc("initialize", {"protocolVersion": "2025-06-18",
                                     "capabilities": {}, "clientInfo": {"name": "demo"}})
        self._rpc("notifications/initialized", notify=True)
        return r["result"]["serverInfo"]["name"]

    def list_tools(self):
        return self._rpc("tools/list")["result"]["tools"]

    def call(self, name, args=None):
        r = self._rpc("tools/call", {"name": name, "arguments": args or {}})
        return r["result"]["content"][0]["text"]

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.stdout.close()
        except Exception:  # noqa: BLE001
            pass
        self.proc.terminate()
        self.proc.wait(timeout=5)


def line(c="-"):
    print(c * 66)


def main():
    with tempfile.TemporaryDirectory() as td:
        reg = pathlib.Path(td)
        print("\nMCP FEDERATION — ONE GATEWAY, TWO TOOL SERVERS — LIVE")
        line("=")
        repo = ToolServer("repo", REPO_TOOLS, reg)
        deploy = ToolServer("deploy", DEPLOY_TOOLS, reg)
        print(f"backend 'repo'   on mesh at {repo.transport.address}")
        print(f"backend 'deploy' on mesh at {deploy.transport.address}")
        client = _Client(reg)
        try:
            print(f"\nclient connected to ONE endpoint: {client.initialize()}")

            line()
            print("client calls tools/list  (gateway aggregates both backends)")
            line()
            for t in client.list_tools():
                print(f"   {t['name']:24} {t['description']}")

            line()
            print("client calls  repo__read_file(path='src/app.py')")
            line()
            print("  ->", client.call("repo__read_file", {"path": "src/app.py"}).replace("\n", "\n     "))

            line()
            print("client calls  deploy__status()")
            line()
            print("  ->", client.call("deploy__status").replace("\n", "\n     "))

            line("=")
            print("One client, one connection — reached two independent tool")
            print("servers across the mesh. Add a third backend (drop its announce")
            print("file) and it shows up in tools/list with no client change.\n")
        finally:
            client.close()
            repo.close()
            deploy.close()


if __name__ == "__main__":
    main()
