"""MCP federation gateway (MCP federation demo). [RUNNABLE]

The single endpoint a Claude Code client connects to. It **discovers**
every backend tool server on the mesh (from the shared registry the
servers announce to), **aggregates** their tools into one namespaced
`tools/list`, and **routes** each `tools/call` to the backend that owns
the tool — over the mesh, awaiting the reply.

    Claude ──stdio/MCP──▶ gateway ──mesh──▶ repo   (list_files, read_file)
                                  └────────▶ deploy (status, history)

Claude sees `repo__read_file`, `deploy__status`, … as if they were one
server's tools. Add a backend (drop its announce file in the registry) and
it appears in the next `tools/list` — no gateway restart, no client config
change. That is the federation MCP itself doesn't provide: many networked
servers behind one entry point.

Tools are namespaced ``<server>__<tool>`` so two servers can offer a tool
of the same name without collision, and so a call routes unambiguously.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))

from socket_transport import LocalSocketTransport  # noqa: E402

_PROTOCOL_FALLBACK = "2025-06-18"
_CALL_TIMEOUT = 5.0
_NS = "__"  # namespace separator: <server>__<tool>


def _log(msg: str) -> None:
    print(f"[gateway] {msg}", file=sys.stderr, flush=True)


class Gateway:
    """Discovers backends and routes calls. Not MCP-aware itself — the stdio
    loop below adapts it to the MCP wire."""

    def __init__(self, registry_dir: pathlib.Path) -> None:
        self.registry = pathlib.Path(registry_dir)
        self.registry.mkdir(parents=True, exist_ok=True)
        self.transport = LocalSocketTransport(source_address="gateway")
        self._id = 0

    def discover(self) -> dict[str, dict]:
        """Read every backend's announce file. Called fresh each time so a
        backend that joins/leaves is reflected immediately."""
        backends: dict[str, dict] = {}
        for f in sorted(self.registry.glob("backend-*.json")):
            try:
                m = json.loads(f.read_text())
                backends[m["name"]] = m
            except (ValueError, KeyError, OSError):
                continue
        return backends

    def list_tools(self) -> list[dict]:
        tools = []
        for bname, m in self.discover().items():
            for t in m.get("tools", []):
                tools.append(
                    {
                        "name": f"{bname}{_NS}{t['name']}",
                        "description": f"[{bname}] {t.get('description', '')}",
                        "inputSchema": t.get("inputSchema", {"type": "object"}),
                    }
                )
        return tools

    def call(self, namespaced: str, args: dict) -> dict:
        bname, sep, tool = namespaced.partition(_NS)
        if not sep:
            return {"error": f"tool name must be <server>{_NS}<tool>: {namespaced!r}"}
        backends = self.discover()
        if bname not in backends:
            return {"error": f"no backend named {bname!r} (known: {sorted(backends)})"}
        addr = backends[bname]["address"]
        self._id += 1
        rid = str(self._id)
        req = {
            "op": "call", "tool": tool, "args": args, "id": rid,
            "reply_to": self.transport.address,
        }
        try:
            self.transport.send(addr, json.dumps(req).encode())
        except Exception as exc:  # noqa: BLE001
            return {"error": f"failed to reach {bname!r}: {exc}"}
        return self._await(rid)

    def _await(self, rid: str) -> dict:
        deadline = time.monotonic() + _CALL_TIMEOUT
        while time.monotonic() < deadline:
            frame = self.transport.receive()
            if frame is None:
                time.sleep(0.02)
                continue
            try:
                resp = json.loads(frame.payload)
            except (ValueError, TypeError):
                continue
            if resp.get("id") == rid:
                return resp
            # A response for a different (earlier/timed-out) call: ignore.
        return {"error": f"backend timed out after {_CALL_TIMEOUT}s"}

    def close(self) -> None:
        self.transport.close()


# --- MCP stdio adapter -----------------------------------------------------


def _result(id_, result):
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def _text(text: str, is_error: bool = False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _dispatch(gw: Gateway, params: dict) -> dict:
    name = params.get("name", "")
    args = params.get("arguments") or {}
    resp = gw.call(name, args)
    if "error" in resp:
        return _text(f"error: {resp['error']}", True)
    return _text(json.dumps(resp.get("result"), indent=2))


def serve_stdio(gw: Gateway) -> None:
    _log(f"federation gateway ready; registry={gw.registry}")
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue
        method = msg.get("method")
        mid = msg.get("id")
        is_notification = "id" not in msg
        try:
            if method == "initialize":
                params = msg.get("params") or {}
                reply = _result(mid, {
                    "protocolVersion": params.get("protocolVersion", _PROTOCOL_FALLBACK),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "walkietalkie-mcp-gateway", "version": "0.1.0"},
                })
            elif method == "tools/list":
                reply = _result(mid, {"tools": gw.list_tools()})
            elif method == "tools/call":
                reply = _result(mid, _dispatch(gw, msg.get("params") or {}))
            elif method == "ping":
                reply = _result(mid, {})
            elif is_notification:
                continue
            else:
                reply = _error(mid, -32601, f"method not found: {method}")
        except Exception as exc:  # noqa: BLE001
            if is_notification:
                continue
            reply = _error(mid, -32603, f"internal error: {exc}")
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


def main() -> None:
    ap = argparse.ArgumentParser(description="MCP federation gateway")
    ap.add_argument("--registry", required=True, type=pathlib.Path)
    args = ap.parse_args()
    gw = Gateway(args.registry)
    try:
        serve_stdio(gw)
    finally:
        gw.close()


if __name__ == "__main__":
    main()
