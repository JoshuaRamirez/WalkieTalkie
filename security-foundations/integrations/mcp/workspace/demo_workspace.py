"""Live demo: a dev shares feature progress; a teammate follows it; nobody
gets spied on.

Owner stands up a status server for a workspace (allow-listed, read-only,
visibility-capped). An allowed teammate pulls updates asynchronously. An
un-listed peer is refused. The owner sees exactly who watched.

Run:  python demo_workspace.py
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import time

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))

from watch import WorkspaceWatcher, render_digest  # noqa: E402
from workspace_server import (  # noqa: E402
    Visibility,
    WorkspaceServer,
    WorkspaceServerNode,
)


def _git_repo(tmp):
    repo = tmp / "payments-feature"
    repo.mkdir()
    kw = dict(cwd=repo, capture_output=True, text=True)
    subprocess.run(["git", "init", "-q"], **kw)
    subprocess.run(["git", "config", "user.email", "owner@example.com"], **kw)
    subprocess.run(["git", "config", "user.name", "Owner"], **kw)
    (repo / "retry.py").write_text("# payment retry\n")
    subprocess.run(["git", "add", "."], **kw)
    subprocess.run(["git", "commit", "-q", "-m", "scaffold retry handler"], **kw)
    return repo


def line(c="-"):
    print(c * 66)


def main():
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        repo = _git_repo(tmp)
        reg = tmp / "registry"

        print("\nWORKSPACE STATUS — SHARE PROGRESS, DON'T GET SPIED ON — LIVE")
        line("=")
        server = WorkspaceServer(
            workspace=repo, name="payments-feature", allow={"alice"},
            visibility=Visibility.STANDARD,
            note="working on payment retry logic; blocked on webhook signature",
        )
        node = WorkspaceServerNode(server, reg)
        print("owner stood up a status server for 'payments-feature'")
        print(f"   visibility={server.visibility.value}  allow={sorted(server.allow)}")
        print("   (read-only: the ONLY thing exposed is get_status)")

        alice = WorkspaceWatcher("alice", reg)      # on the allow list
        mallory = WorkspaceWatcher("mallory", reg)  # not on the allow list
        try:
            line()
            print("alice (allowed) follows the feature — the owner is NOT interrupted")
            line()
            _, resp = alice.check("payments-feature")
            print(render_digest(resp["result"]))

            line()
            print("mallory (NOT on the allow list) tries to peek")
            line()
            _, mresp = mallory.check("payments-feature")
            print(f"   -> {'DENIED' if mresp.get('denied') else mresp}")

            line()
            print("owner makes progress and updates the note (no ceremony)")
            line()
            server.note = "retry logic landed; wiring the webhook verifier now"
            time.sleep(0.05)
            changed, resp2 = alice.check("payments-feature")
            print(f"   alice sees news? {changed}")
            print(render_digest(resp2["result"]))

            line()
            print("owner checks WHO has been watching (reciprocal transparency)")
            line()
            for e in server.who_is_watching():
                mark = "✓ granted" if e["granted"] else "✗ denied"
                print(f"   {e['watcher']:8} {mark}")

            line("=")
            print("What alice could NEVER see: file contents, diffs, other repos,")
            print("or anything outside this workspace. She saw only the curated,")
            print("visibility-capped status the owner published — and the owner")
            print("saw exactly who looked.\n")

            # Prove the surface is bounded: there is no file-read tool.
            probe = server.handle_request("alice", "read_file")
            assert "result" not in probe and "error" in probe
        finally:
            alice.close()
            mallory.close()
            node.close()


if __name__ == "__main__":
    main()
