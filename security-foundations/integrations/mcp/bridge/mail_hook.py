"""Claude Code UserPromptSubmit hook: surface unread mesh messages.

MCP is client-initiated — a peer's message can't interrupt Claude. This
hook closes that gap: it runs on every prompt submit, drains the verified
inbox the bridge writes, and prints any new messages to stdout. For a
UserPromptSubmit hook, stdout is injected into the conversation context —
so Claude "receives mail" without you asking it to call a tool.

Only cryptographically-verified messages ever reach the inbox file (the
bridge's receive loop verifies every envelope before appending), so this
hook never surfaces a forged or tampered message.

Pure stdlib — no crypto imports — so it stays cheap to run on every turn.

Wire it up in settings.json (see bridge/README.md):

    {"hooks": {"UserPromptSubmit": [{"hooks": [{"type": "command",
      "command": "python /abs/path/mail_hook.py --name alice"}]}]}}

Config defaults to ~/.claude/mesh (override with --config).
"""

from __future__ import annotations

import argparse
import fcntl
import json
import pathlib
import sys


def read_unread(inbox: pathlib.Path) -> list[dict]:
    if not inbox.exists():
        return []
    lock = inbox.with_suffix(".lock")
    with lock.open("w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            lines = [
                json.loads(x) for x in inbox.read_text().splitlines() if x.strip()
            ]
            fresh = [e for e in lines if not e.get("read")]
            if fresh:
                for e in lines:
                    e["read"] = True
                inbox.write_text("\n".join(json.dumps(e) for e in lines) + "\n")
            return fresh
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


_DEFAULT_CONFIG_DIR = pathlib.Path.home() / ".claude" / "mesh"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--config", type=pathlib.Path, default=_DEFAULT_CONFIG_DIR)
    args = ap.parse_args()

    # Claude Code passes hook JSON on stdin; we don't need it, but drain it
    # so the pipe doesn't block.
    try:
        sys.stdin.read()
    except Exception:  # noqa: BLE001
        pass

    inbox = args.config / f"inbox-{args.name}.jsonl"
    fresh = read_unread(inbox)
    if not fresh:
        return 0

    lines = ["📬 New verified messages from your mesh peer(s):"]
    for e in fresh:
        lines.append(f"  • [from {e.get('from_name')}] {e.get('body')}")
    lines.append(
        "(These were cryptographically verified. Reply with the "
        "send_message tool if a response is warranted.)"
    )
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
