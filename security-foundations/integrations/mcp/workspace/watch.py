"""Workspace watcher — pull a teammate's feature status without interrupting
anyone.

The owner's `workspace_server` just answers read requests; the owner (the
human) is never in the loop, so watching them causes **zero context
switches** for them. On the watcher's side, this poller pulls the status on
an interval and only writes a digest **when something changed** — so the
watcher isn't spammed either, and a `UserPromptSubmit` hook can surface new
progress into their Claude session passively (same pattern as the mesh
bridge's `mail_hook.py`).

Nobody gets tapped on the shoulder: the owner isn't interrupted to answer,
and the watcher sees updates only when there's genuine news.
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

_TIMEOUT = 5.0
# Fields that constitute real "news" — updated_at changes every poll and is
# deliberately excluded so an idle workspace produces no digest churn.
_NEWS_FIELDS = ("branch", "note", "recent_commits", "changed_files")


class WorkspaceWatcher:
    def __init__(self, watcher_id: str, registry: pathlib.Path) -> None:
        self.watcher_id = watcher_id
        self.registry = pathlib.Path(registry)
        self.transport = LocalSocketTransport(source_address=f"watcher-{watcher_id}")
        self._id = 0
        self._last: dict[str, dict] = {}

    def _resolve(self, name: str) -> str | None:
        f = self.registry / f"workspace-{name}.json"
        if not f.exists():
            return None
        try:
            return json.loads(f.read_text())["address"]
        except (ValueError, KeyError, OSError):
            return None

    def poll(self, name: str) -> dict:
        """Pull the current status for workspace ``name`` (or an error dict)."""
        addr = self._resolve(name)
        if addr is None:
            return {"error": f"workspace {name!r} is not published (server down?)"}
        self._id += 1
        rid = str(self._id)
        req = {"op": "call", "tool": "get_status", "requester": self.watcher_id,
               "id": rid, "reply_to": self.transport.address}
        try:
            self.transport.send(addr, json.dumps(req).encode())
        except Exception as exc:  # noqa: BLE001
            return {"error": f"could not reach {name!r}: {exc}"}
        deadline = time.monotonic() + _TIMEOUT
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
        return {"error": "timed out"}

    def check(self, name: str) -> tuple[bool, dict]:
        """Poll; return (changed, response). 'changed' is True only when the
        news-bearing fields differ from the last successful pull."""
        resp = self.poll(name)
        if "result" not in resp:
            return False, resp
        status = resp["result"]
        news = {k: status.get(k) for k in _NEWS_FIELDS}
        changed = self._last.get(name) != news
        if changed:
            self._last[name] = news
        return changed, resp

    def close(self) -> None:
        self.transport.close()


def render_digest(status: dict) -> str:
    lines = [f"📋 {status.get('workspace')} — {status.get('branch')}"]
    if status.get("note"):
        lines.append(f"   note: {status['note']}")
    if status.get("recent_commits"):
        lines.append("   recent: " + "; ".join(status["recent_commits"][:3]))
    if status.get("changed_files"):
        lines.append(f"   changed: {len(status['changed_files'])} file(s)")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Watch a teammate's workspace status")
    ap.add_argument("--watcher", required=True, help="your id (must be on the allow list)")
    ap.add_argument("--workspace", required=True, help="the workspace/feature name")
    ap.add_argument("--registry", required=True, type=pathlib.Path)
    ap.add_argument("--interval", type=float, default=10.0)
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    w = WorkspaceWatcher(args.watcher, args.registry)
    try:
        while True:
            changed, resp = w.check(args.workspace)
            if resp.get("denied"):
                print(f"[watch] denied: not on {args.workspace!r}'s allow list", file=sys.stderr)
            elif "error" in resp:
                print(f"[watch] {resp['error']}", file=sys.stderr)
            elif changed:
                print(render_digest(resp["result"]))
            if args.once:
                return 0
            time.sleep(args.interval)
    finally:
        w.close()


if __name__ == "__main__":
    raise SystemExit(main())
