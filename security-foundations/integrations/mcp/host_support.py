"""Pure stateless helpers for the example MCP host (Phase 4).

Extracted from ``host.py`` to keep that module focused on the
substrate pipeline (and under its 500-line ceiling). Every function
here is pure: no I/O, no host state.
"""

from __future__ import annotations

import hashlib
from typing import Any

from verify_envelope import EnvelopeVerificationError


def request_id_from_envelope(envelope: dict[str, Any]) -> int | str | None:
    """Pull the JSON-RPC request id out of an envelope's payload, or None."""
    if not isinstance(envelope, dict):
        return None
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return None
    return payload.get("id")


def exc_reason_code(exc: EnvelopeVerificationError) -> str:
    """Return the machine-readable DenyReason value, or '' if absent."""
    return exc.reason.value if getattr(exc, "reason", None) is not None else ""


def derive_reply_id(envelope: dict[str, Any]) -> str:
    """Derive a UUIDv7-shaped reply id deterministically from the inbound
    envelope's message_id. Real operators pick this from a monotonic
    clock; the demo derives from input for reproducibility."""
    base = envelope.get("message_id", "00000000-0000-7000-8000-000000000000")
    if not isinstance(base, str) or len(base) != 36:
        base = "00000000-0000-7000-8000-000000000000"
    # Reverse the last hex group so the reply id is distinct but still
    # UUIDv7-shaped.
    head = base[:-12]
    return head + base[-12:][::-1]


def derive_reply_nonce(envelope: dict[str, Any]) -> str:
    msg = envelope.get("message_id", "") if isinstance(envelope, dict) else ""
    digest = hashlib.sha256(f"reply::{msg}".encode()).hexdigest()
    return f"replynonce-{digest[:20]}"


__all__ = [
    "derive_reply_id",
    "derive_reply_nonce",
    "exc_reason_code",
    "request_id_from_envelope",
]
