"""Audit event types and sinks for envelope verification.

Phase 0 plan E1 calls for hash-chained audit events for every privileged
action. Phase 1 D1.4 specifies "explicit checkpoints for discovery,
verification, policy, execution." This module provides the verification
checkpoint:

- :class:`AuditEvent` — a frozen record of one verifier outcome.
- :class:`AuditSink` — abstract interface for durable storage.
- :class:`InMemoryAuditSink` — list-backed; useful for tests and short-lived
  workloads.
- :class:`JsonlAuditSink` — append-only newline-delimited JSON file.
- :func:`verify_chain` — re-derives the hash chain from a sequence of events
  and raises if any link is broken.

Hash chain
----------
Each event carries ``prev_hash`` (the previous event's ``this_hash``, or 64
zeros for the genesis event) and ``this_hash`` (sha256 of ``prev_hash``
concatenated with the JCS-canonical serialization of every other field).
Re-running :func:`verify_chain` on the persisted events detects any insertion,
deletion, or in-place mutation of past records.

Out of scope for v0
-------------------
- Distributed audit (single-process / single-file).
- Checkpoint signing / external anchoring.
- Cross-event correlation IDs (trace IDs land with D1.4 trace work).
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import jcs

GENESIS_PREV_HASH = "0" * 64

# Stable order of fields fed into the hash. New fields MUST be appended to
# preserve hash compatibility for existing chains.
_HASHED_FIELDS = (
    "timestamp",
    "event_type",
    "outcome",
    "reason",
    "message_id",
    "sender",
    "recipient",
    "envelope_kid",
    "issuer_iss",
    "issuer_kid",
    "reason_code",
    "artifact_version",
)

ALLOWED_OUTCOMES = ("allow", "deny")


class AuditChainError(ValueError):
    """Raised when an audit chain fails integrity checks."""


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    event_type: str
    outcome: str
    reason: str
    message_id: str
    sender: str
    recipient: str
    envelope_kid: str
    issuer_iss: str
    issuer_kid: str
    prev_hash: str
    this_hash: str
    # ``reason_code`` is the machine-readable counterpart to ``reason``; it
    # carries a :class:`deny_reason.DenyReason` value (as a str) for events
    # produced by the deterministic-error-contract path, or ``""`` for legacy
    # events. Defaulted so existing callers keep working; appended last in
    # ``_HASHED_FIELDS`` so the hash chain extends cleanly.
    reason_code: str = ""
    # ``artifact_version`` records which contract/wire format produced the
    # decision. v0 emits ``"envelope/v0"`` for envelope.verify events and
    # ``"wt-cap+jwt"`` for capability.verify events. Phase 1 Track D D1.
    artifact_version: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _compute_this_hash(prev_hash: str, fields: dict[str, str]) -> str:
    body = {name: fields[name] for name in _HASHED_FIELDS}
    payload = prev_hash.encode("ascii") + jcs.canonicalize(body)
    return hashlib.sha256(payload).hexdigest()


def _build_event(prev_hash: str, **fields: str) -> AuditEvent:
    if fields["outcome"] not in ALLOWED_OUTCOMES:
        raise ValueError(f"outcome must be one of {ALLOWED_OUTCOMES!r}")
    this_hash = _compute_this_hash(prev_hash, fields)
    return AuditEvent(prev_hash=prev_hash, this_hash=this_hash, **fields)


class AuditSink(ABC):
    """Append-only sink for envelope verification audit events."""

    @abstractmethod
    def tail_hash(self) -> str:
        """Return the most recent event's ``this_hash``, or ``GENESIS_PREV_HASH``."""

    @abstractmethod
    def _append(self, event: AuditEvent) -> None:
        """Persist a fully-formed event."""

    def record(
        self,
        *,
        event_type: str,
        outcome: str,
        reason: str,
        message_id: str = "",
        sender: str = "",
        recipient: str = "",
        envelope_kid: str = "",
        issuer_iss: str = "",
        issuer_kid: str = "",
        reason_code: str = "",
        artifact_version: str = "",
        timestamp: datetime | None = None,
    ) -> AuditEvent:
        ts = (timestamp or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")
        event = _build_event(
            prev_hash=self.tail_hash(),
            timestamp=ts,
            event_type=event_type,
            outcome=outcome,
            reason=reason,
            message_id=message_id,
            sender=sender,
            recipient=recipient,
            envelope_kid=envelope_kid,
            issuer_iss=issuer_iss,
            issuer_kid=issuer_kid,
            reason_code=reason_code,
            artifact_version=artifact_version,
        )
        self._append(event)
        return event


class InMemoryAuditSink(AuditSink):
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def tail_hash(self) -> str:
        return self._events[-1].this_hash if self._events else GENESIS_PREV_HASH

    def _append(self, event: AuditEvent) -> None:
        self._events.append(event)

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)


class JsonlAuditSink(AuditSink):
    """Append-only newline-delimited JSON file.

    The file is opened, appended to, and closed on every record() call so the
    on-disk state is always durable. ``tail_hash()`` reads only the last line.
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.touch(exist_ok=True)

    def tail_hash(self) -> str:
        if self._path.stat().st_size == 0:
            return GENESIS_PREV_HASH
        # Read backwards to find the last non-empty line without loading the
        # whole file. The file is always small in v0 single-process use.
        with self._path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            block = 4096
            data = b""
            while size > 0:
                read = min(block, size)
                size -= read
                f.seek(size)
                data = f.read(read) + data
                if b"\n" in data.rstrip(b"\n"):
                    break
            last_line = data.rstrip(b"\n").rsplit(b"\n", 1)[-1]
        if not last_line:
            return GENESIS_PREV_HASH
        return json.loads(last_line)["this_hash"]

    def _append(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), separators=(",", ":")) + "\n"
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line)

    def read_all(self) -> tuple[AuditEvent, ...]:
        events: list[AuditEvent] = []
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                # Fields appended after initial ship default to "" so legacy
                # lines (without these keys) still load.
                record.setdefault("reason_code", "")
                record.setdefault("artifact_version", "")
                events.append(AuditEvent(**record))
        return tuple(events)


def verify_chain(events: Iterable[AuditEvent]) -> None:
    """Re-derive every event's hash. Raise AuditChainError on the first break."""
    expected_prev = GENESIS_PREV_HASH
    for index, event in enumerate(events):
        if event.prev_hash != expected_prev:
            raise AuditChainError(
                f"event {index}: prev_hash {event.prev_hash} != expected {expected_prev}"
            )
        recomputed = _compute_this_hash(
            event.prev_hash,
            {name: getattr(event, name) for name in _HASHED_FIELDS},
        )
        if event.this_hash != recomputed:
            raise AuditChainError(
                f"event {index}: this_hash mismatch (recorded {event.this_hash}, "
                f"recomputed {recomputed})"
            )
        expected_prev = event.this_hash
