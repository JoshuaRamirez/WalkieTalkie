"""End-to-end tests for MCP federation.

Two proofs:
1. **Federation logic** — a gateway discovers two backends, aggregates
   their tools, and routes calls to the right one (+ dynamic discovery).
2. **MCP protocol** — a client (spawned gateway subprocess) drives the
   JSON-RPC handshake and calls a federated tool that routes to a backend.
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))

from mcp_gateway import Gateway  # noqa: E402
from tool_server import DEPLOY_TOOLS, REPO_TOOLS, ToolServer  # noqa: E402

_GATEWAY = _HERE / "mcp_gateway.py"


class FederationLogicTests(unittest.TestCase):
    def test_gateway_federates_and_routes(self):
        with tempfile.TemporaryDirectory() as td:
            reg = pathlib.Path(td)
            repo = ToolServer("repo", REPO_TOOLS, reg)
            deploy = ToolServer("deploy", DEPLOY_TOOLS, reg)
            gw = Gateway(reg)
            try:
                names = {t["name"] for t in gw.list_tools()}
                # One entry point, both servers' tools, namespaced.
                self.assertIn("repo__read_file", names)
                self.assertIn("repo__list_files", names)
                self.assertIn("deploy__status", names)
                self.assertIn("deploy__history", names)

                # A call routes to the owning backend.
                r = gw.call("repo__read_file", {"path": "src/app.py"})
                self.assertEqual(r["server"], "repo")
                self.assertEqual(r["result"]["path"], "src/app.py")

                d = gw.call("deploy__status", {})
                self.assertEqual(d["server"], "deploy")
                self.assertEqual(d["result"]["staging"], "healthy")
            finally:
                gw.close()
                repo.close()
                deploy.close()

    def test_dynamic_discovery_of_new_backend(self):
        with tempfile.TemporaryDirectory() as td:
            reg = pathlib.Path(td)
            repo = ToolServer("repo", REPO_TOOLS, reg)
            gw = Gateway(reg)
            try:
                self.assertNotIn("deploy__status", {t["name"] for t in gw.list_tools()})
                # A new backend joins — no gateway restart, no config change.
                deploy = ToolServer("deploy", DEPLOY_TOOLS, reg)
                try:
                    self.assertIn("deploy__status", {t["name"] for t in gw.list_tools()})
                    self.assertEqual(gw.call("deploy__status", {})["server"], "deploy")
                finally:
                    deploy.close()
            finally:
                gw.close()
                repo.close()

    def test_unknown_backend_errors(self):
        with tempfile.TemporaryDirectory() as td:
            reg = pathlib.Path(td)
            gw = Gateway(reg)
            try:
                self.assertIn("error", gw.call("ghost__do", {}))
            finally:
                gw.close()


class McpProtocolTests(unittest.TestCase):
    def test_client_drives_gateway_over_stdio(self):
        with tempfile.TemporaryDirectory() as td:
            reg = pathlib.Path(td)
            # Backends run in-process; the gateway is a separate process that
            # reaches them over the mesh (real cross-process federation).
            repo = ToolServer("repo", REPO_TOOLS, reg)
            deploy = ToolServer("deploy", DEPLOY_TOOLS, reg)
            proc = subprocess.Popen(
                [sys.executable, str(_GATEWAY), "--registry", str(reg)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True,
            )
            try:
                def rpc(obj):
                    proc.stdin.write(json.dumps(obj) + "\n")
                    proc.stdin.flush()

                def read():
                    return json.loads(proc.stdout.readline())

                rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                     "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                "clientInfo": {"name": "t"}}})
                init = read()
                self.assertEqual(init["result"]["serverInfo"]["name"],
                                 "walkietalkie-mcp-gateway")

                rpc({"jsonrpc": "2.0", "method": "notifications/initialized"})

                rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
                names = {t["name"] for t in read()["result"]["tools"]}
                self.assertIn("repo__read_file", names)
                self.assertIn("deploy__status", names)

                # A federated tool call routes through the gateway to the
                # in-process backend and back.
                rpc({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                     "params": {"name": "deploy__status", "arguments": {}}})
                text = read()["result"]["content"][0]["text"]
                self.assertIn("healthy", text)

                rpc({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                     "params": {"name": "repo__read_file",
                                "arguments": {"path": "README.md"}}})
                text2 = read()["result"]["content"][0]["text"]
                self.assertIn("README.md", text2)
            finally:
                proc.stdin.close()
                proc.stdout.close()
                proc.terminate()
                proc.wait(timeout=5)
                repo.close()
                deploy.close()


if __name__ == "__main__":
    unittest.main()
