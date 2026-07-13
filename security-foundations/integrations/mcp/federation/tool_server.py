"""A mesh-connected backend tool server (MCP federation demo). [RUNNABLE]

Federation turns MCP from point-to-point into a *network*. Today a Claude
Code client talks to a handful of local stdio MCP servers it has hard-coded
in its config. This demo shows the alternative: many tool servers live on
the mesh, **announce themselves**, and a single gateway (`mcp_gateway.py`)
discovers them and routes calls — so a client configures ONE endpoint and
reaches all of them.

A `ToolServer` is one backend:
- runs a mesh transport (`LocalSocketTransport` — real loopback TCP),
- **announces** its name + address + tool manifest to a shared registry
  directory (drop a file, and the gateway picks it up — no gateway config
  change), and
- serves `call` requests: run the named tool, send the result back to the
  requester's ``reply_to`` address.

The tools here are stubs (they return canned data) — the point of the demo
is the *federation + discovery + routing*, not the tools. Swap the handlers
for real ones (a DB query, a deploy trigger, a docs search) and it's a real
team tool mesh.

This runs on the same mesh transports as the rest of the substrate, so the
identity/mTLS layer composes on top when you want it — but nothing here
depends on it; this is the coordination-fabric view.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import threading
import time

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))

from socket_transport import LocalSocketTransport  # noqa: E402


class ToolServer:
    def __init__(self, name: str, tools: dict, registry_dir: pathlib.Path) -> None:
        self.name = name
        self.tools = tools
        self.registry = pathlib.Path(registry_dir)
        self.registry.mkdir(parents=True, exist_ok=True)
        self.transport = LocalSocketTransport(source_address=name)
        self._stop = threading.Event()
        self._announce()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _manifest(self) -> dict:
        return {
            "name": self.name,
            "address": self.transport.address,
            "tools": [
                {"name": n, "description": t["description"], "inputSchema": t["inputSchema"]}
                for n, t in self.tools.items()
            ],
        }

    def _announce(self) -> None:
        (self.registry / f"backend-{self.name}.json").write_text(
            json.dumps(self._manifest(), indent=2)
        )

    def _serve(self) -> None:
        while not self._stop.is_set():
            frame = self.transport.receive()
            if frame is None:
                time.sleep(0.02)
                continue
            try:
                req = json.loads(frame.payload)
            except (ValueError, TypeError):
                continue
            if req.get("op") != "call":
                continue
            rid = req.get("id")
            reply_to = req.get("reply_to")
            tool = req.get("tool")
            args = req.get("args") or {}
            if tool in self.tools:
                try:
                    result = self.tools[tool]["handler"](args)
                    resp = {"id": rid, "server": self.name, "result": result}
                except Exception as exc:  # noqa: BLE001
                    resp = {"id": rid, "server": self.name, "error": str(exc)}
            else:
                resp = {"id": rid, "server": self.name, "error": f"unknown tool: {tool}"}
            if reply_to:
                try:
                    self.transport.send(reply_to, json.dumps(resp).encode())
                except Exception as exc:  # noqa: BLE001
                    print(f"[{self.name}] reply failed: {exc}", file=sys.stderr)

    def close(self) -> None:
        self._stop.set()
        self.transport.close()
        with __import__("contextlib").suppress(OSError):
            (self.registry / f"backend-{self.name}.json").unlink()


# --- preset toolsets (stubs; swap handlers for real integrations) ----------

REPO_TOOLS = {
    "list_files": {
        "description": "List the files in the repository.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: {"files": ["README.md", "src/app.py", "src/util.py"]},
    },
    "read_file": {
        "description": "Read a file from the repository.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        "handler": lambda a: {
            "path": a.get("path"),
            "contents": f"# stub contents of {a.get('path')}\nprint('hello')\n",
        },
    },
}

DEPLOY_TOOLS = {
    "status": {
        "description": "Current deployment status by environment.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: {"staging": "healthy", "prod": "healthy"},
    },
    "history": {
        "description": "Recent deployments.",
        "inputSchema": {"type": "object", "properties": {}},
        "handler": lambda a: {
            "recent": [
                {"env": "staging", "sha": "abc123", "when": "2h ago"},
                {"env": "prod", "sha": "def456", "when": "yesterday"},
            ]
        },
    },
}

_PRESETS = {"repo": REPO_TOOLS, "deploy": DEPLOY_TOOLS}


def main() -> None:
    ap = argparse.ArgumentParser(description="Mesh-connected backend tool server")
    ap.add_argument("--name", required=True)
    ap.add_argument("--preset", required=True, choices=sorted(_PRESETS))
    ap.add_argument("--registry", required=True, type=pathlib.Path)
    args = ap.parse_args()
    server = ToolServer(args.name, _PRESETS[args.preset], args.registry)
    print(
        f"[{args.name}] serving {args.preset} tools on {server.transport.address}; "
        f"announced to {args.registry}",
        file=sys.stderr,
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        server.close()


if __name__ == "__main__":
    main()
