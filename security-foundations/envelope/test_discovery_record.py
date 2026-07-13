"""Tests for discovery record integrity (Phase 1 Track A A2)."""

import json
import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from discovery_record import (
    DEFAULT_DISCOVERY_CONFIG,
    DiscoveryRecord,
    DiscoveryRecordError,
    DiscoveryVerificationConfig,
    from_json,
    sign_record,
    to_json,
    verify_record,
)

_WORKLOAD_ISS = "spiffe://mesh.example/ns-a/svc"
_WORKLOAD_KID = "envelope-kid-a"
_ISSUER_ISS = "spiffe://mesh.example/discovery-authority"
_ISSUER_KID = "discovery-kid-1"
_ENDPOINTS = ("mesh://node-a.example.test:443",)
_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def _record(
    *,
    issued_at: datetime = _NOW,
    expires_at: datetime | None = None,
    workload_iss: str = _WORKLOAD_ISS,
    workload_kid: str = _WORKLOAD_KID,
    issuer_iss: str = _ISSUER_ISS,
    issuer_kid: str = _ISSUER_KID,
    endpoints: tuple[str, ...] = _ENDPOINTS,
    version: str = "v0",
) -> DiscoveryRecord:
    if expires_at is None:
        expires_at = issued_at + timedelta(minutes=30)
    return DiscoveryRecord(
        version=version,
        workload_iss=workload_iss,
        workload_kid=workload_kid,
        endpoints=endpoints,
        issuer_iss=issuer_iss,
        issuer_kid=issuer_kid,
        issued_at=issued_at.isoformat().replace("+00:00", "Z"),
        expires_at=expires_at.isoformat().replace("+00:00", "Z"),
    )


class SignAndVerifyTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = lambda iss, kid: self.pem

    def test_round_trip(self):
        signed = sign_record(_record(), self.priv)
        encoded = to_json(signed)
        decoded = from_json(encoded)
        verified = verify_record(decoded, issuer_lookup=self.lookup, now=_NOW)
        self.assertEqual(verified.workload_iss, _WORKLOAD_ISS)
        self.assertEqual(verified.workload_kid, _WORKLOAD_KID)
        self.assertEqual(verified.endpoints, _ENDPOINTS)

    def test_unsigned_record_rejected(self):
        with self.assertRaisesRegex(DiscoveryRecordError, "unsigned"):
            verify_record(_record(), issuer_lookup=self.lookup, now=_NOW)

    def test_tampered_workload_iss_rejected(self):
        signed = sign_record(_record(), self.priv)
        tampered = DiscoveryRecord(
            version=signed.version,
            workload_iss="spiffe://mesh.example/ns-x/other",
            workload_kid=signed.workload_kid,
            endpoints=signed.endpoints,
            issuer_iss=signed.issuer_iss,
            issuer_kid=signed.issuer_kid,
            issued_at=signed.issued_at,
            expires_at=signed.expires_at,
            signature=signed.signature,
        )
        with self.assertRaisesRegex(DiscoveryRecordError, "signature invalid"):
            verify_record(tampered, issuer_lookup=self.lookup, now=_NOW)

    def test_signed_with_unrelated_key_rejected(self):
        signed = sign_record(_record(), self.priv)
        _, other_pem = _keypair()
        with self.assertRaisesRegex(DiscoveryRecordError, "signature invalid"):
            verify_record(signed, issuer_lookup=lambda iss, kid: other_pem, now=_NOW)

    def test_unknown_issuer_rejected(self):
        signed = sign_record(_record(), self.priv)

        def lookup(iss, kid):
            raise Exception(f"unknown ({iss}, {kid})")

        with self.assertRaisesRegex(DiscoveryRecordError, "unknown discovery issuer key"):
            verify_record(signed, issuer_lookup=lookup, now=_NOW)


class TimeWindowTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = lambda iss, kid: self.pem

    def test_expired_record_rejected(self):
        signed = sign_record(_record(), self.priv)
        # Pretend "now" is 2 hours later — well past expiry.
        with self.assertRaisesRegex(DiscoveryRecordError, "record expired"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW + timedelta(hours=2))

    def test_future_record_rejected(self):
        signed = sign_record(_record(issued_at=_NOW + timedelta(hours=2)), self.priv)
        with self.assertRaisesRegex(DiscoveryRecordError, "issued_at in future"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW)

    def test_ttl_above_max_rejected(self):
        signed = sign_record(
            _record(expires_at=_NOW + timedelta(hours=24)),
            self.priv,
        )
        with self.assertRaisesRegex(DiscoveryRecordError, "ttl exceeds maximum"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW)

    def test_invalid_validity_window_rejected(self):
        signed = sign_record(
            _record(expires_at=_NOW - timedelta(seconds=1)),
            self.priv,
        )
        with self.assertRaisesRegex(DiscoveryRecordError, "invalid validity window"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW)

    def test_clock_skew_tolerance(self):
        # Record issued 30 seconds in the future — should pass with default
        # 60-second skew.
        signed = sign_record(
            _record(issued_at=_NOW + timedelta(seconds=30)),
            self.priv,
        )
        verify_record(signed, issuer_lookup=self.lookup, now=_NOW)

    def test_custom_max_ttl(self):
        signed = sign_record(
            _record(expires_at=_NOW + timedelta(minutes=10)),
            self.priv,
        )
        tight = DiscoveryVerificationConfig(
            max_clock_skew=DEFAULT_DISCOVERY_CONFIG.max_clock_skew,
            max_record_ttl=timedelta(minutes=5),
        )
        with self.assertRaisesRegex(DiscoveryRecordError, "ttl exceeds maximum"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW, config=tight)


class ShapeValidationTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = lambda iss, kid: self.pem

    def test_unsupported_version_rejected(self):
        signed = sign_record(_record(version="v999"), self.priv)
        with self.assertRaisesRegex(DiscoveryRecordError, "unsupported version"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW)

    def test_invalid_workload_iss_rejected(self):
        signed = sign_record(_record(workload_iss="not-a-spiffe"), self.priv)
        with self.assertRaisesRegex(DiscoveryRecordError, "workload_iss"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW)

    def test_invalid_workload_kid_rejected(self):
        signed = sign_record(_record(workload_kid="kid with space"), self.priv)
        with self.assertRaisesRegex(DiscoveryRecordError, "workload_kid"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW)

    def test_empty_endpoints_rejected(self):
        signed = sign_record(_record(endpoints=()), self.priv)
        with self.assertRaisesRegex(DiscoveryRecordError, "endpoints must be non-empty"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW)

    def test_empty_endpoint_string_rejected(self):
        signed = sign_record(_record(endpoints=("mesh://a", "")), self.priv)
        with self.assertRaisesRegex(DiscoveryRecordError, r"endpoints\[1\]"):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW)


class JsonRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()

    def test_missing_required_field(self):
        signed = sign_record(_record(), self.priv)
        obj = json.loads(to_json(signed))
        del obj["expires_at"]
        with self.assertRaisesRegex(DiscoveryRecordError, "missing required fields: expires_at"):
            from_json(json.dumps(obj).encode())

    def test_non_json(self):
        with self.assertRaisesRegex(DiscoveryRecordError, "not valid JSON"):
            from_json(b"{not json")

    def test_endpoints_not_a_list(self):
        signed = sign_record(_record(), self.priv)
        obj = json.loads(to_json(signed))
        obj["endpoints"] = "mesh://single"
        with self.assertRaisesRegex(DiscoveryRecordError, "endpoints must be a list"):
            from_json(json.dumps(obj).encode())


class AuditEmissionTests(unittest.TestCase):
    """The discovery checkpoint is part of Phase 1 Track D D1."""

    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = lambda iss, kid: self.pem

    def _new_sink(self):
        from audit import InMemoryAuditSink
        return InMemoryAuditSink()

    def test_allow_event_on_success(self):
        sink = self._new_sink()
        signed = sign_record(_record(), self.priv)
        verify_record(signed, issuer_lookup=self.lookup, now=_NOW, audit_sink=sink)
        self.assertEqual(len(sink.events), 1)
        ev = sink.events[0]
        self.assertEqual(ev.event_type, "discovery.verify")
        self.assertEqual(ev.outcome, "allow")
        self.assertEqual(ev.reason_code, "ok")
        self.assertEqual(ev.artifact_version, "wt-discovery-record/v0")
        self.assertEqual(ev.sender, _WORKLOAD_ISS)
        self.assertEqual(ev.issuer_iss, _ISSUER_ISS)

    def test_deny_event_on_expired_record(self):
        sink = self._new_sink()
        signed = sign_record(_record(), self.priv)
        with self.assertRaises(DiscoveryRecordError):
            verify_record(
                signed,
                issuer_lookup=self.lookup,
                now=_NOW + timedelta(hours=2),
                audit_sink=sink,
            )
        self.assertEqual(len(sink.events), 1)
        ev = sink.events[0]
        self.assertEqual(ev.event_type, "discovery.verify")
        self.assertEqual(ev.outcome, "deny")
        self.assertEqual(ev.reason_code, "discovery_expired")

    def test_deny_event_on_bad_signature(self):
        sink = self._new_sink()
        signed = sign_record(_record(), self.priv)
        _, other_pem = _keypair()
        with self.assertRaises(DiscoveryRecordError):
            verify_record(
                signed,
                issuer_lookup=lambda iss, kid: other_pem,
                now=_NOW,
                audit_sink=sink,
            )
        self.assertEqual(sink.events[0].reason_code, "discovery_signature_invalid")

    def test_deny_event_on_unknown_issuer(self):
        sink = self._new_sink()
        signed = sign_record(_record(), self.priv)

        def lookup(iss, kid):
            raise Exception("nope")

        with self.assertRaises(DiscoveryRecordError):
            verify_record(signed, issuer_lookup=lookup, now=_NOW, audit_sink=sink)
        self.assertEqual(sink.events[0].reason_code, "discovery_unknown_issuer")

    def test_deny_event_on_malformed_record(self):
        sink = self._new_sink()
        signed = sign_record(_record(workload_iss="not-spiffe"), self.priv)
        with self.assertRaises(DiscoveryRecordError):
            verify_record(signed, issuer_lookup=self.lookup, now=_NOW, audit_sink=sink)
        self.assertEqual(sink.events[0].reason_code, "discovery_malformed")


if __name__ == "__main__":
    unittest.main()
