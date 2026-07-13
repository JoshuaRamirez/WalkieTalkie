"""Canned search views over an audit event stream.

Closes Phase 1 Track D D2 ("Queryability and Incident Readiness: Search
views for break-glass, denies, replay attempts, and cross-tenant attempts").

Each function is a pure generator over an ``Iterable[AuditEvent]`` —
composable with the other filters in this module, with stdlib ``itertools``,
and with caller-supplied predicates. Backed by whatever sink the operator
chose: ``InMemoryAuditSink.events`` for in-process workloads,
``JsonlAuditSink.read_all()`` for persisted streams.

The plan's "search views" language implies an ad-hoc query surface for
incident response. v0 ships the canned filters that the plan names; downstream
tooling (a CLI, a dashboard, a notebook) composes them. Anything richer
(SQL, OpenSearch indices, materialized views) is a transport / storage
concern that v0 deliberately defers.

Out of scope for v0
-------------------
- Time-bounded queries beyond what callers can write with
  ``itertools.dropwhile`` / ``takewhile`` on the timestamp field.
- Multi-stream queries / joins.
- Full-text search over reason strings (use ``with_reason_code`` instead).
- Break-glass *mechanism*: the filter is defined here but until a
  break-glass capability or event_type ships, ``break_glass_attempts``
  returns nothing. Documented below.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from audit import AuditEvent

# Trust domain is the host component of a SPIFFE ID
# (``spiffe://<trust_domain>/<workload-path>``).
_SPIFFE_TRUST_DOMAIN_RE = re.compile(r"^spiffe://([^/]+)")


def trust_domain_of(spiffe_id: str) -> str | None:
    """Return the trust domain segment of a SPIFFE ID, or ``None``."""
    if not isinstance(spiffe_id, str):
        return None
    m = _SPIFFE_TRUST_DOMAIN_RE.match(spiffe_id)
    return m.group(1) if m else None


def allows(events: Iterable[AuditEvent]) -> Iterator[AuditEvent]:
    return (e for e in events if e.outcome == "allow")


def denies(events: Iterable[AuditEvent]) -> Iterator[AuditEvent]:
    return (e for e in events if e.outcome == "deny")


def with_event_type(events: Iterable[AuditEvent], event_type: str) -> Iterator[AuditEvent]:
    return (e for e in events if e.event_type == event_type)


def with_reason_code(events: Iterable[AuditEvent], reason_code: str) -> Iterator[AuditEvent]:
    return (e for e in events if e.reason_code == reason_code)


def with_sender(events: Iterable[AuditEvent], sender: str) -> Iterator[AuditEvent]:
    return (e for e in events if e.sender == sender)


def with_recipient(events: Iterable[AuditEvent], recipient: str) -> Iterator[AuditEvent]:
    return (e for e in events if e.recipient == recipient)


def with_message_id(events: Iterable[AuditEvent], message_id: str) -> Iterator[AuditEvent]:
    return (e for e in events if e.message_id == message_id)


def replays(events: Iterable[AuditEvent]) -> Iterator[AuditEvent]:
    """Events where the replay cache rejected a previously-seen nonce."""
    return with_reason_code(events, "replay_detected")


def cross_tenant_attempts(events: Iterable[AuditEvent]) -> Iterator[AuditEvent]:
    """Events whose sender and recipient live in different SPIFFE trust domains.

    "Tenant" maps to the SPIFFE trust domain (the segment between
    ``spiffe://`` and the first ``/``). Same-domain envelopes are not yielded.
    Events missing one or both fields are not yielded.
    """
    for e in events:
        sender_td = trust_domain_of(e.sender)
        recipient_td = trust_domain_of(e.recipient)
        if sender_td and recipient_td and sender_td != recipient_td:
            yield e


def break_glass_attempts(events: Iterable[AuditEvent]) -> Iterator[AuditEvent]:
    """Reserved hook for break-glass governance events.

    Until a break-glass mechanism ships (Phase 0 §3 mentions it; the
    capability/event surface is not yet built), this filter matches any
    event_type starting with ``"break_glass."`` and any reason_code starting
    with ``"break_glass_"``. Currently nothing in the verifier or issuer
    emits those, so this returns ``()`` in practice — the filter exists so
    incident tooling has a stable hook to call once the feature lands.
    """
    for e in events:
        if e.event_type.startswith("break_glass.") or e.reason_code.startswith("break_glass_"):
            yield e
