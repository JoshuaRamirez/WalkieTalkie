"""Tests for the canned audit search views (Phase 1 Track D D2)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from audit import InMemoryAuditSink, JsonlAuditSink
from audit_query import (
    allows,
    break_glass_attempts,
    cross_tenant_attempts,
    denies,
    replays,
    trust_domain_of,
    with_event_type,
    with_message_id,
    with_reason_code,
    with_recipient,
    with_sender,
)

_TD_A = "spiffe://mesh.example/ns-a/svc"
_TD_B = "spiffe://mesh.example/ns-b/svc"
_TD_OTHER = "spiffe://other-mesh.example/ns-z/svc"


def _record(sink, **overrides):
    defaults = dict(
        event_type="envelope.verify",
        outcome="allow",
        reason="ok",
        reason_code="ok",
        artifact_version="envelope/v0",
        sender=_TD_A,
        recipient=_TD_B,
        timestamp=datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC),
    )
    defaults.update(overrides)
    return sink.record(**defaults)


class TrustDomainOfTests(unittest.TestCase):
    def test_extracts_host(self):
        self.assertEqual(trust_domain_of(_TD_A), "mesh.example")
        self.assertEqual(trust_domain_of(_TD_OTHER), "other-mesh.example")

    def test_returns_none_for_non_spiffe(self):
        for bad in ("", "https://mesh.example/x", "not-a-uri", None):
            with self.subTest(value=bad):
                self.assertIsNone(trust_domain_of(bad))


class OutcomeFiltersTests(unittest.TestCase):
    def setUp(self):
        self.sink = InMemoryAuditSink()
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record(self.sink, outcome="allow", timestamp=ts)
        _record(self.sink, outcome="deny", reason_code="signature_invalid",
                timestamp=ts + timedelta(seconds=1))
        _record(self.sink, outcome="allow", timestamp=ts + timedelta(seconds=2))

    def test_allows(self):
        self.assertEqual(len(list(allows(self.sink.events))), 2)

    def test_denies(self):
        self.assertEqual(len(list(denies(self.sink.events))), 1)


class AttributeFiltersTests(unittest.TestCase):
    def setUp(self):
        self.sink = InMemoryAuditSink()
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record(self.sink, event_type="envelope.verify", timestamp=ts)
        _record(self.sink, event_type="capability.verify",
                timestamp=ts + timedelta(seconds=1))
        _record(self.sink, event_type="capability.issue",
                timestamp=ts + timedelta(seconds=2))
        _record(self.sink, sender="spiffe://mesh.example/ns-c/svc",
                timestamp=ts + timedelta(seconds=3))

    def test_with_event_type(self):
        envs = list(with_event_type(self.sink.events, "envelope.verify"))
        self.assertEqual(len(envs), 2)  # the initial one and the sender=ns-c one

    def test_with_sender(self):
        self.assertEqual(
            len(list(with_sender(self.sink.events, "spiffe://mesh.example/ns-c/svc"))),
            1,
        )

    def test_with_recipient(self):
        self.assertEqual(len(list(with_recipient(self.sink.events, _TD_B))), 4)

    def test_with_message_id(self):
        ts = datetime(2026, 4, 14, 13, 0, 0, tzinfo=UTC)
        _record(self.sink, message_id="abc-123", timestamp=ts)
        self.assertEqual(
            len(list(with_message_id(self.sink.events, "abc-123"))), 1
        )

    def test_with_reason_code(self):
        ts = datetime(2026, 4, 14, 13, 0, 0, tzinfo=UTC)
        _record(self.sink, outcome="deny", reason_code="replay_detected", timestamp=ts)
        self.assertEqual(
            len(list(with_reason_code(self.sink.events, "replay_detected"))), 1
        )


class ReplayQueryTests(unittest.TestCase):
    def test_replays_filters_by_reason_code(self):
        sink = InMemoryAuditSink()
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record(sink, outcome="deny", reason_code="signature_invalid", timestamp=ts)
        _record(sink, outcome="deny", reason_code="replay_detected",
                timestamp=ts + timedelta(seconds=1))
        _record(sink, outcome="deny", reason_code="payload_digest_mismatch",
                timestamp=ts + timedelta(seconds=2))
        self.assertEqual(
            [e.reason_code for e in replays(sink.events)], ["replay_detected"]
        )


class CrossTenantQueryTests(unittest.TestCase):
    def test_same_trust_domain_not_flagged(self):
        sink = InMemoryAuditSink()
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record(sink, sender=_TD_A, recipient=_TD_B, timestamp=ts)
        self.assertEqual(list(cross_tenant_attempts(sink.events)), [])

    def test_different_trust_domain_flagged(self):
        sink = InMemoryAuditSink()
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record(sink, sender=_TD_A, recipient=_TD_OTHER, timestamp=ts)
        self.assertEqual(len(list(cross_tenant_attempts(sink.events))), 1)

    def test_missing_sender_or_recipient_not_flagged(self):
        sink = InMemoryAuditSink()
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record(sink, sender="", recipient=_TD_OTHER, timestamp=ts)
        _record(sink, sender=_TD_A, recipient="",
                timestamp=ts + timedelta(seconds=1))
        self.assertEqual(list(cross_tenant_attempts(sink.events)), [])


class BreakGlassQueryTests(unittest.TestCase):
    def test_nothing_today(self):
        # No verifier or issuer code emits break_glass events yet; the filter
        # exists as a stable hook for when the mechanism ships.
        sink = InMemoryAuditSink()
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record(sink, timestamp=ts)
        _record(sink, outcome="deny", reason_code="signature_invalid",
                timestamp=ts + timedelta(seconds=1))
        self.assertEqual(list(break_glass_attempts(sink.events)), [])

    def test_matches_break_glass_event_type(self):
        sink = InMemoryAuditSink()
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        sink.record(
            event_type="break_glass.invoke",
            outcome="allow",
            reason="dual-approval emergency override",
            reason_code="ok",
            artifact_version="",
            sender=_TD_A,
            recipient=_TD_B,
            timestamp=ts,
        )
        self.assertEqual(len(list(break_glass_attempts(sink.events))), 1)

    def test_matches_break_glass_reason_code(self):
        sink = InMemoryAuditSink()
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        sink.record(
            event_type="envelope.verify",
            outcome="deny",
            reason="break-glass override required",
            reason_code="break_glass_required",
            artifact_version="envelope/v0",
            sender=_TD_A,
            recipient=_TD_B,
            timestamp=ts,
        )
        self.assertEqual(len(list(break_glass_attempts(sink.events))), 1)


class VectorIntegrationTests(unittest.TestCase):
    """Sanity-check against the checked-in test vector."""

    def test_canned_views_work_on_persisted_vector(self):
        vectors = pathlib.Path(__file__).resolve().parent / "test-vectors" / "audit-event.jsonl"
        events = JsonlAuditSink(vectors).read_all()

        # The fixture has three scenarios: success (cap+env allow),
        # pre-cap deny (env-only), cap-level deny (cap+env).
        self.assertEqual(len(list(allows(events))), 2)
        self.assertEqual(len(list(denies(events))), 3)
        self.assertEqual(
            len(list(with_event_type(events, "capability.verify"))), 2
        )
        self.assertEqual(
            len(list(with_reason_code(events, "capability_revoked"))), 2
        )
        # Same trust domain in the fixture, so no cross-tenant.
        self.assertEqual(list(cross_tenant_attempts(events)), [])
        self.assertEqual(list(replays(events)), [])
        self.assertEqual(list(break_glass_attempts(events)), [])


if __name__ == "__main__":
    unittest.main()
