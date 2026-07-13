"""Autonomous responder — wake a Claude Code instance when mesh mail arrives.

You spotted the real limit: agent-to-agent chat over MCP is not real-time.
Nothing *wakes* Bob's Claude when a message lands — Claude only acts on a
prompt. This script is the "timer" that closes that gap: it watches the
verified inbox the bridge writes and, when a new message appears, invokes
`claude -p` (with the mesh MCP server attached and `--continue` for
conversational continuity) so Claude reads the message and replies.

    peer sends ─▶ bridge verifies ─▶ inbox file grows
                                          │
                       responder polls ───┘ sees unread ─▶ wakes `claude -p`
                                                            (check_inbox + reply)

Why polling the *file* (not the model) is fine: the file poll is cheap and
event-shaped (only unread entries trigger a wake). The model runs only when
there's actually something to answer. Because the `claude` call is
synchronous and Claude's `check_inbox` marks messages read, the next poll
sees them consumed — so a message wakes Claude exactly once.

This is still not a persistent socket-driven agent (that's the Agent SDK /
a long-lived process — a Phase 6 option). It is the simplest thing that
makes two Claude instances hold a hands-off back-and-forth.

Example (Bob answers Alice automatically, continuously):
    python responder.py --name bob --mcp-config /abs/bob.mcp.json --interval 2

Dry run (see when it *would* wake Claude, without spending tokens):
    python responder.py --name bob --mcp-config x --once --dry-run
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import time

_DEFAULT_CONFIG_DIR = pathlib.Path.home() / ".claude" / "mesh"
_DEFAULT_PROMPT = (
    "You have new message(s) from a peer agent on the secure mesh. Call the "
    "check_inbox tool to read them. If a reply is warranted, use the "
    "send_message tool (omit 'to' to use your default peer) to respond. Keep "
    "replies brief and on-topic."
)


def peek_unread(inbox: pathlib.Path) -> list[dict]:
    """Return unread inbox entries WITHOUT marking them read — the wake
    signal. Claude's own check_inbox is what marks them read."""
    if not inbox.exists():
        return []
    out = []
    for raw in inbox.read_text().splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if not entry.get("read"):
            out.append(entry)
    return out


def build_claude_cmd(args, *, resume: bool) -> list[str]:
    cmd = [
        args.claude_bin, "-p", args.prompt,
        "--mcp-config", str(args.mcp_config),
        "--strict-mcp-config",
        "--allowedTools", "mcp__mesh__send_message", "mcp__mesh__check_inbox",
    ]
    if resume:
        cmd.append("--continue")  # keep the same conversation across wakes
    return cmd


def run(args) -> int:
    inbox = args.config / f"inbox-{args.name}.jsonl"
    print(f"[responder] watching {inbox} (interval={args.interval}s)", file=sys.stderr)
    woken = False
    while True:
        fresh = peek_unread(inbox)
        if fresh:
            preview = "; ".join(f"{e.get('from_name')}: {e.get('body','')[:40]}" for e in fresh)
            print(f"[responder] {len(fresh)} new -> waking claude  ({preview})", file=sys.stderr)
            cmd = build_claude_cmd(args, resume=woken)
            if args.dry_run:
                print("[responder] DRY-RUN would exec:", " ".join(cmd))
            else:
                # Synchronous: Claude's check_inbox marks the mail read before
                # we poll again, so each message wakes Claude exactly once.
                # cwd is this agent's own dir so `--continue` resumes THIS
                # agent's conversation, not the peer's.
                subprocess.run(cmd, cwd=str(args.workdir))
                woken = True
        if args.once:
            return 0
        time.sleep(args.interval)


def main() -> int:
    ap = argparse.ArgumentParser(description="Wake Claude on new mesh mail")
    ap.add_argument("--name", required=True, help="this agent's name")
    ap.add_argument("--config", type=pathlib.Path, default=_DEFAULT_CONFIG_DIR)
    ap.add_argument("--workdir", type=pathlib.Path, default=None,
                    help="cwd for the claude session (its own conversation "
                    "history lives here; default: --config dir)")
    ap.add_argument("--mcp-config", required=True, type=pathlib.Path,
                    help="the claude --mcp-config JSON for this agent")
    ap.add_argument("--interval", type=float, default=2.0)
    ap.add_argument("--prompt", default=_DEFAULT_PROMPT)
    ap.add_argument("--claude-bin", default="claude")
    ap.add_argument("--once", action="store_true", help="one poll then exit")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the claude command instead of running it")
    args = ap.parse_args()
    if args.workdir is None:
        args.workdir = args.config
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
