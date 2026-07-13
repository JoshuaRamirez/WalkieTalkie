"""Tests for admission coupling (Phase 1 Track A A3)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from admission_coupling import (
    AdmissionDecision,
    AdmissionError,
    AdmissionPolicy,
    admit,
    require_admission,
)
from discovery_record import DiscoveryRecord

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_WORKLOAD_A = "spiffe://mesh.example/ns-a/svc"
_WORKLOAD_B = "spiffe://mesh.example/ns-b/svc"
_WORKLOAD_UNAPPROVED = "spiffe://mesh.example/ns-z/intruder"
_ENDPOINTS = ("mesh://node.example.test:443",)


def _record(workload_iss: str = _WORKLOAD_A, version: str = "v0") -> DiscoveryRecord:
    return DiscoveryRecord(
        version=version,
        workload_iss=workload_iss,
        workload_kid="envelope-kid-a",
        endpoints=_ENDPOINTS,
        issuer_iss="spiffe://mesh.example/discovery",
        issuer_kid="discovery-kid-1",
        issued_at=_NOW.isoformat().replace("+00:00", "Z"),
        expires_at=(_NOW + timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
        signature="signature-placeholder",  # admit() does NOT verify; caller does
    )


class AdmissionPolicyConstructionTests(unittest.TestCase):
    def test_requires_frozenset_workloads(self):
        with self.assertRaisesRegex(TypeError, "allowed_workloads"):
            AdmissionPolicy(allowed_workloads={_WORKLOAD_A})  # set, not frozenset

    def test_requires_frozenset_versions(self):
        with self.assertRaisesRegex(TypeError, "accepted_discovery_versions"):
            AdmissionPolicy(
                allowed_workloads=frozenset({_WORKLOAD_A}),
                accepted_discovery_versions={"v0"},  # set, not frozenset
            )

    def test_empty_version_set_rejected(self):
        with self.assertRaisesRegex(ValueError, "accepted_discovery_versions"):
            AdmissionPolicy(
                allowed_workloads=frozenset({_WORKLOAD_A}),
                accepted_discovery_versions=frozenset(),
            )

    def test_default_compatibility_matrix(self):
        p = AdmissionPolicy(allowed_workloads=frozenset({_WORKLOAD_A}))
        self.assertIn("v0", p.accepted_discovery_versions)


class AdmitTests(unittest.TestCase):
    def setUp(self):
        self.policy = AdmissionPolicy(
            allowed_workloads=frozenset({_WORKLOAD_A, _WORKLOAD_B})
        )

    def test_allowlisted_workload_admitted(self):
        d = admit(_record(_WORKLOAD_A), self.policy)
        self.assertTrue(d.admitted)
        self.assertEqual(d.workload_iss, _WORKLOAD_A)
        self.assertEqual(d.endpoints, _ENDPOINTS)
        self.assertEqual(d.reason, "ok")

    def test_unapproved_workload_denied(self):
        d = admit(_record(_WORKLOAD_UNAPPROVED), self.policy)
        self.assertFalse(d.admitted)
        self.assertEqual(d.workload_iss, _WORKLOAD_UNAPPROVED)
        self.assertIn("not in admission allowlist", d.reason)
        # Endpoints field is empty on denials — the deny path MUST NOT
        # propagate transport hints for an unadmitted peer.
        self.assertEqual(d.endpoints, ())

    def test_unaccepted_discovery_version_denied(self):
        d = admit(_record(version="v999"), self.policy)
        self.assertFalse(d.admitted)
        self.assertIn("compatibility matrix", d.reason)

    def test_compatibility_matrix_is_evaluated_before_allowlist(self):
        # An unapproved workload with an unaccepted version is denied for the
        # version reason first — the matrix check is a precondition.
        d = admit(_record(_WORKLOAD_UNAPPROVED, version="v999"), self.policy)
        self.assertFalse(d.admitted)
        self.assertIn("compatibility matrix", d.reason)

    def test_empty_allowlist_denies_everything(self):
        empty = AdmissionPolicy(allowed_workloads=frozenset())
        d = admit(_record(_WORKLOAD_A), empty)
        self.assertFalse(d.admitted)
        self.assertIn("not in admission allowlist", d.reason)


class RequireAdmissionTests(unittest.TestCase):
    def test_allows_silently_on_admission(self):
        policy = AdmissionPolicy(allowed_workloads=frozenset({_WORKLOAD_A}))
        d = require_admission(_record(_WORKLOAD_A), policy)
        self.assertIsInstance(d, AdmissionDecision)
        self.assertTrue(d.admitted)

    def test_raises_on_denial_carrying_decision(self):
        policy = AdmissionPolicy(allowed_workloads=frozenset({_WORKLOAD_A}))
        with self.assertRaises(AdmissionError) as ctx:
            require_admission(_record(_WORKLOAD_UNAPPROVED), policy)
        self.assertFalse(ctx.exception.decision.admitted)
        self.assertIn("not in admission allowlist", str(ctx.exception))
        self.assertEqual(ctx.exception.decision.workload_iss, _WORKLOAD_UNAPPROVED)


class AuditEmissionTests(unittest.TestCase):
    """Admission decisions emit one ``admission.evaluate`` event per call."""

    def _new_sink(self):
        from audit import InMemoryAuditSink
        return InMemoryAuditSink()

    def test_allow_event_on_admission(self):
        sink = self._new_sink()
        policy = AdmissionPolicy(allowed_workloads=frozenset({_WORKLOAD_A}))
        admit(_record(_WORKLOAD_A), policy, audit_sink=sink)
        self.assertEqual(len(sink.events), 1)
        ev = sink.events[0]
        self.assertEqual(ev.event_type, "admission.evaluate")
        self.assertEqual(ev.outcome, "allow")
        self.assertEqual(ev.reason_code, "ok")
        self.assertEqual(ev.artifact_version, "wt-admission/v0")
        self.assertEqual(ev.sender, _WORKLOAD_A)

    def test_deny_event_workload_not_allowed(self):
        sink = self._new_sink()
        policy = AdmissionPolicy(allowed_workloads=frozenset({_WORKLOAD_A}))
        admit(_record(_WORKLOAD_UNAPPROVED), policy, audit_sink=sink)
        self.assertEqual(sink.events[0].reason_code, "admission_workload_not_allowed")
        self.assertEqual(sink.events[0].outcome, "deny")

    def test_deny_event_version_incompatible(self):
        sink = self._new_sink()
        policy = AdmissionPolicy(allowed_workloads=frozenset({_WORKLOAD_A}))
        admit(_record(_WORKLOAD_A, version="v999"), policy, audit_sink=sink)
        self.assertEqual(sink.events[0].reason_code, "admission_version_incompatible")

    def test_require_admission_emits_and_raises(self):
        sink = self._new_sink()
        policy = AdmissionPolicy(allowed_workloads=frozenset({_WORKLOAD_A}))
        with self.assertRaises(AdmissionError):
            require_admission(_record(_WORKLOAD_UNAPPROVED), policy, audit_sink=sink)
        # Deny event was still recorded.
        self.assertEqual(len(sink.events), 1)
        self.assertEqual(sink.events[0].outcome, "deny")


if __name__ == "__main__":
    unittest.main()
