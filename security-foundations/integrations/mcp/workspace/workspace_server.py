"""Workspace status server — share feature progress without being spied on.

The use case: a developer working on an important feature stands up a
status server for that workspace. A teammate connects to get updates —
asynchronously, so the owner is never interrupted with a context switch.
The hard requirement is the **privacy model**: the owner must not feel
surveilled outside the workspace.

This module makes "don't feel spied on" **structural**, not a promise:

1. **Read-only, curated surface.** The only thing exposed is a
   `get_status` view the owner controls. There is *no* tool to read a
   file, run a command, or name an arbitrary path — a watcher cannot ask
   for more than the status object, by construction.
2. **Workspace-bounded.** Auto-derived facts come only from *git in the
   configured workspace directory*. The server never reads outside it,
   never sees other repos, never touches the rest of the machine.
3. **Visibility levels.** The owner picks how much even the status object
   reveals: SUMMARY (branch + a note), STANDARD (+ recent commit
   subjects), DETAILED (+ changed file *names* — never contents/diffs).
4. **Consent / deny-by-default.** Only allow-listed watchers get an
   answer; everyone else is denied. (Identity is the mesh-verified SVID
   in the full stack; a name here on loopback.)
5. **Reciprocal transparency.** Every access — granted *and* denied — is
   logged with the watcher's identity and time. The owner can see exactly
   who checked and when. Watching is not covert; it goes both ways.
6. **Off means invisible.** Nothing is ambient. When the server isn't
   running, there is nothing to see; standing it up is an explicit,
   revocable publish of *this workspace's* status only.

Runs on the mesh transports like the rest of the substrate, so the
mTLS/identity/admission layer composes on top — but the privacy model
here does not depend on it.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))

from socket_transport import LocalSocketTransport  # noqa: E402


class Visibility(StrEnum):
    SUMMARY = "summary"      # branch + note only
    STANDARD = "standard"    # + recent commit subjects
    DETAILED = "detailed"    # + changed file names (never contents)


@dataclass
class AccessEvent:
    watcher: str
    when: str
    granted: bool


@dataclass
class WorkspaceServer:
    """A read-only status surface for ONE workspace directory."""

    workspace: pathlib.Path
    name: str
    allow: set[str]
    visibility: Visibility = Visibility.STANDARD
    note: str = ""
    access_log: list[AccessEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.workspace = pathlib.Path(self.workspace).resolve()

    # ---- workspace-bounded git facts (read-only, this dir only) -------
    def _git(self, *args: str) -> str:
        try:
            out = subprocess.run(
                ["git", "-C", str(self.workspace), *args],
                capture_output=True, text=True, timeout=5,
            )
            return out.stdout.strip() if out.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            return ""

    def _now(self) -> str:
        return datetime.now(UTC).isoformat()

    def build_status(self) -> dict:
        """The curated status object, gated by the visibility level. Never
        includes file contents, diffs, arbitrary paths, or anything outside
        the workspace."""
        status = {
            "workspace": self.name,
            "visibility": self.visibility.value,
            "branch": self._git("rev-parse", "--abbrev-ref", "HEAD") or "(unknown)",
            "note": self.note,
            "updated_at": self._now(),
        }
        if self.visibility in (Visibility.STANDARD, Visibility.DETAILED):
            commits = self._git("log", "-n", "5", "--format=%s")
            status["recent_commits"] = commits.splitlines() if commits else []
        if self.visibility is Visibility.DETAILED:
            # Changed file NAMES only (porcelain gives "XY path"); never
            # contents. Split on the status token so spacing variants and
            # untracked ("??") lines all yield just the path.
            porcelain = self._git("status", "--porcelain")
            status["changed_files"] = [
                parts[1]
                for line in porcelain.splitlines()
                if len(parts := line.split(maxsplit=1)) > 1
            ]
        return status

    # ---- authorization + access logging -------------------------------
    def handle_request(
        self, requester: str, tool: str, *, verified_identity: str | None = None
    ) -> dict:
        """Authorize, log, and answer. Deny-by-default; every attempt is
        recorded so the owner sees who watched.

        ``verified_identity``, when supplied by a transport that
        cryptographically authenticates the peer (the mTLS `TlsSocketTransport`
        yields the peer SVID as ``Frame.source``), OVERRIDES the
        self-asserted ``requester`` — so a watcher cannot spoof another's id
        onto the allow list. On a plain loopback transport that does not
        verify the sender, ``requester`` is self-asserted (a known boundary;
        see README). Authorization and the audit log always key on the
        effective (verified-if-present) identity."""
        effective = verified_identity if verified_identity is not None else requester
        granted = effective in self.allow
        self.access_log.append(
            AccessEvent(watcher=effective, when=self._now(), granted=granted)
        )
        if not granted:
            return {"error": "not authorized for this workspace", "denied": True}
        if tool == "get_status":
            return {"result": self.build_status()}
        # No other tool exists — the surface is bounded by construction.
        return {"error": f"unknown tool: {tool!r} (only get_status is exposed)"}

    def who_is_watching(self) -> list[dict]:
        """Owner-facing: exactly who accessed (or tried), and when."""
        return [
            {"watcher": e.watcher, "when": e.when, "granted": e.granted}
            for e in self.access_log
        ]


class WorkspaceServerNode:
    """Wraps a WorkspaceServer with a mesh transport + serve loop.

    ``transport`` defaults to a plain loopback socket. Pass a
    `TlsSocketTransport` and ``trust_transport_identity=True`` and the
    server authorizes on the mTLS-verified peer SVID (``Frame.source``)
    instead of the self-asserted requester — spoof-resistant."""

    def __init__(
        self,
        server: WorkspaceServer,
        registry: pathlib.Path,
        *,
        transport=None,
        trust_transport_identity: bool = False,
    ) -> None:
        self.server = server
        self.registry = pathlib.Path(registry)
        self.registry.mkdir(parents=True, exist_ok=True)
        self.transport = transport or LocalSocketTransport(
            source_address=f"ws-{server.name}"
        )
        self.trust_transport_identity = trust_transport_identity
        self._stop = threading.Event()
        (self.registry / f"workspace-{server.name}.json").write_text(
            json.dumps({"name": server.name, "address": self.transport.address})
        )
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

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
            # When the transport verifies the peer (mTLS), frame.source IS the
            # authenticated SVID — use it, ignoring any self-asserted claim.
            verified = frame.source if self.trust_transport_identity else None
            resp = self.server.handle_request(
                requester=req.get("requester", "(anonymous)"),
                tool=req.get("tool", ""),
                verified_identity=verified,
            )
            resp["id"] = req.get("id")
            reply_to = req.get("reply_to")
            if reply_to:
                with __import__("contextlib").suppress(Exception):
                    self.transport.send(reply_to, json.dumps(resp).encode())

    def close(self) -> None:
        self._stop.set()
        self.transport.close()
        with __import__("contextlib").suppress(OSError):
            (self.registry / f"workspace-{self.server.name}.json").unlink()


def _load_note(note_path: pathlib.Path | None) -> str:
    if note_path and note_path.exists():
        return note_path.read_text().strip()
    return ""


def main() -> None:
    ap = argparse.ArgumentParser(description="Read-only workspace status server")
    ap.add_argument("--workspace", required=True, type=pathlib.Path)
    ap.add_argument("--name", required=True, help="workspace/feature name")
    ap.add_argument("--allow", nargs="*", default=[], help="watcher ids allowed to read")
    ap.add_argument("--visibility", default="standard",
                    choices=[v.value for v in Visibility])
    ap.add_argument("--note-file", type=pathlib.Path, default=None,
                    help="a file whose contents are the owner-curated status note")
    ap.add_argument("--registry", required=True, type=pathlib.Path)
    args = ap.parse_args()

    server = WorkspaceServer(
        workspace=args.workspace, name=args.name, allow=set(args.allow),
        visibility=Visibility(args.visibility), note=_load_note(args.note_file),
    )
    node = WorkspaceServerNode(server, args.registry)
    print(
        f"[workspace:{args.name}] serving {args.visibility} status on "
        f"{node.transport.address}; allow={sorted(server.allow) or '(none)'}",
        file=sys.stderr,
    )
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        node.close()


if __name__ == "__main__":
    main()
