"""Tests for the audit-stream alerting layer (Phase 1 Track D D3)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from alerting import (
    ABNORMAL_ISSUANCE_VOLUME,
    REPEATED_VALIDATION_FAILURE,
    Alert,
    AlertingAuditSink,
    ThresholdAlertingPolicy,
)
from audit import InMemoryAuditSink

_SENDER_A = "spiffe://mesh/ns-a/service-a"
_SENDER_B = "spiffe://mesh/ns-b/service-b"
_RECIPIENT = "spiffe://mesh/ns-x/service-x"


def _record_deny(sink, *, sender: str, when: datetime, reason_code: str = "signature_invalid") -> None:
    sink.record(
        event_type="envelope.verify",
        outcome="deny",
        reason="signature invalid",
        reason_code=reason_code,
        artifact_version="envelope/v0",
        sender=sender,
        recipient=_RECIPIENT,
        timestamp=when,
    )


def _record_issue_allow(sink, *, sender: str, when: datetime) -> None:
    sink.record(
        event_type="capability.issue",
        outcome="allow",
        reason="ok",
        reason_code="ok",
        artifact_version="wt-cap+jwt",
        sender=sender,
        recipient=_RECIPIENT,
        issuer_iss="spiffe://mesh/cap-issuer-1",
        issuer_kid="issuer-kid-1",
        timestamp=when,
    )


class ThresholdAlertingPolicyConstructionTests(unittest.TestCase):
    def test_zero_window_rejected(self):
        with self.assertRaisesRegex(ValueError, "window"):
            ThresholdAlertingPolicy(window=timedelta(0))

    def test_zero_thresholds_rejected(self):
        with self.assertRaisesRegex(ValueError, "repeated_deny_threshold"):
            ThresholdAlertingPolicy(repeated_deny_threshold=0)
        with self.assertRaisesRegex(ValueError, "issuance_volume_threshold"):
            ThresholdAlertingPolicy(issuance_volume_threshold=0)


class AlertingAuditSinkBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.inner = InMemoryAuditSink()
        self.alerts: list[Alert] = []
        self.policy = ThresholdAlertingPolicy(
            window=timedelta(minutes=5),
            repeated_deny_threshold=3,
            issuance_volume_threshold=3,
        )
        self.sink = AlertingAuditSink(
            self.inner, policy=self.policy, on_alert=self.alerts.append
        )

    def test_inner_sink_still_receives_events(self):
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record_deny(self.sink, sender=_SENDER_A, when=ts)
        self.assertEqual(len(self.inner.events), 1)

    def test_tail_hash_delegates_to_inner(self):
        self.assertEqual(self.sink.tail_hash(), self.inner.tail_hash())
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record_deny(self.sink, sender=_SENDER_A, when=ts)
        self.assertEqual(self.sink.tail_hash(), self.inner.tail_hash())

    def test_repeated_deny_alert_fires_at_threshold(self):
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        for i in range(3):
            _record_deny(self.sink, sender=_SENDER_A, when=ts + timedelta(seconds=i))
        self.assertEqual(len(self.alerts), 1)
        alert = self.alerts[0]
        self.assertEqual(alert.kind, REPEATED_VALIDATION_FAILURE)
        self.assertEqual(alert.identity, _SENDER_A)
        self.assertEqual(alert.count, 3)
        self.assertEqual(alert.window_seconds, 300)

    def test_alert_does_not_double_fire_immediately(self):
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        for i in range(3):
            _record_deny(self.sink, sender=_SENDER_A, when=ts + timedelta(seconds=i))
        # Threshold met; one more event after should NOT re-fire because the
        # bucket is cleared after the alert.
        _record_deny(self.sink, sender=_SENDER_A, when=ts + timedelta(seconds=3))
        self.assertEqual(len(self.alerts), 1)

    def test_alert_refires_once_bucket_refills(self):
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        for i in range(3):
            _record_deny(self.sink, sender=_SENDER_A, when=ts + timedelta(seconds=i))
        for i in range(3):
            _record_deny(self.sink, sender=_SENDER_A, when=ts + timedelta(seconds=10 + i))
        self.assertEqual(len(self.alerts), 2)

    def test_per_identity_buckets_independent(self):
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record_deny(self.sink, sender=_SENDER_A, when=ts)
        _record_deny(self.sink, sender=_SENDER_B, when=ts + timedelta(seconds=1))
        _record_deny(self.sink, sender=_SENDER_A, when=ts + timedelta(seconds=2))
        # Two for A, one for B — neither at threshold yet.
        self.assertEqual(self.alerts, [])

    def test_sliding_window_forgets_old_denies(self):
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        _record_deny(self.sink, sender=_SENDER_A, when=ts)
        _record_deny(self.sink, sender=_SENDER_A, when=ts + timedelta(seconds=1))
        # Third event arrives 10 minutes later — outside the 5-minute window,
        # so the bucket is purged and we only have 1 entry, no alert.
        _record_deny(self.sink, sender=_SENDER_A, when=ts + timedelta(minutes=10))
        self.assertEqual(self.alerts, [])

    def test_allow_events_do_not_count_toward_deny_threshold(self):
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        # Three allow events from the same sender — should not trigger any alert.
        for i in range(3):
            self.sink.record(
                event_type="envelope.verify",
                outcome="allow",
                reason="ok",
                reason_code="ok",
                artifact_version="envelope/v0",
                sender=_SENDER_A,
                recipient=_RECIPIENT,
                timestamp=ts + timedelta(seconds=i),
            )
        self.assertEqual(self.alerts, [])

    def test_capability_verify_denies_do_not_count_toward_envelope_threshold(self):
        # Only envelope.verify deny counts. capability.verify deny is the
        # cap-checkpoint counterpart; if both counted, every cap-level deny
        # would double-count toward the same threshold.
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        for i in range(3):
            self.sink.record(
                event_type="capability.verify",
                outcome="deny",
                reason="capability token: revoked",
                reason_code="capability_revoked",
                artifact_version="wt-cap+jwt",
                sender=_SENDER_A,
                recipient=_RECIPIENT,
                timestamp=ts + timedelta(seconds=i),
            )
        self.assertEqual(self.alerts, [])

    def test_issuance_volume_alert_fires_at_threshold(self):
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        for i in range(3):
            _record_issue_allow(self.sink, sender=_SENDER_A, when=ts + timedelta(seconds=i))
        self.assertEqual(len(self.alerts), 1)
        alert = self.alerts[0]
        self.assertEqual(alert.kind, ABNORMAL_ISSUANCE_VOLUME)
        self.assertEqual(alert.identity, _SENDER_A)

    def test_issuance_deny_events_do_not_count(self):
        ts = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        for i in range(3):
            self.sink.record(
                event_type="capability.issue",
                outcome="deny",
                reason="issuance policy: not in allowlist",
                reason_code="issuance_policy_denied",
                artifact_version="wt-cap+jwt",
                sender=_SENDER_A,
                recipient=_RECIPIENT,
                timestamp=ts + timedelta(seconds=i),
            )
        self.assertEqual(self.alerts, [])


if __name__ == "__main__":
    unittest.main()
