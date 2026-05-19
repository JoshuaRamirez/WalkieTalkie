"""Tests for reviewer workflow (Phase 2 Track C C3)."""

import hashlib
import pathlib
import sys
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from data_classification import DataClass
from output_scanning import RiskLevel
from reviewer_workflow import (
    QuarantineRecord,
    ReviewDecision,
    ReviewError,
    ReviewVerdict,
    from_json,
    sign_decision,
    to_json,
    verify_decision,
    verify_release_authorization,
)
from verify_envelope import EnvelopeVerificationError

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_TS = int(_NOW.timestamp())
_REVIEWER_ISS = "spiffe://mesh.example/ns-review/reviewer-1"
_REVIEWER_KID = "review-kid-1"
_REQUESTER_ISS = "spiffe://mesh.example/ns-a/workload-1"
_RECORD_UUID = "01900000-0000-7000-8000-000000000001"
_DECISION_UUID = "01900000-0000-7000-8000-000000000002"
_ARTIFACT_DIGEST = hashlib.sha256(b"artifact").hexdigest()


def _record(**overrides) -> QuarantineRecord:
    kwargs = dict(
        record_id=_RECORD_UUID,
        artifact_digest=_ARTIFACT_DIGEST,
        risk=RiskLevel.HIGH,
        data_class=DataClass.CONFIDENTIAL,
        requested_at="2026-04-14T12:00:00Z",
        requester_iss=_REQUESTER_ISS,
        purpose_of_use="invoke_tool",
    )
    kwargs.update(overrides)
    return QuarantineRecord(**kwargs)


def _unsigned_decision(record: QuarantineRecord, **overrides) -> ReviewDecision:
    kwargs = dict(
        record_digest=record.record_digest,
        verdict=ReviewVerdict.RELEASE,
        reason="reviewed and approved",
        reviewer_iss=_REVIEWER_ISS,
        reviewer_kid=_REVIEWER_KID,
        iat=_NOW_TS - 5,
        nbf=_NOW_TS,
        exp=_NOW_TS + 600,
        jti=_DECISION_UUID,
    )
    kwargs.update(overrides)
    return ReviewDecision(**kwargs)


def _make_keypair():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def _lookup(expected_iss: str, expected_kid: str, pem: bytes):
    def _f(iss: str, kid: str) -> bytes:
        if (iss, kid) != (expected_iss, expected_kid):
            raise EnvelopeVerificationError(
                f"unknown issuer: iss={iss!r}, kid={kid!r}"
            )
        return pem
    return _f


class QuarantineRecordTests(unittest.TestCase):
    def test_invalid_record_id_rejected(self):
        with self.assertRaisesRegex(ValueError, "record_id"):
            _record(record_id="not-uuidv7")

    def test_invalid_artifact_digest_rejected(self):
        with self.assertRaisesRegex(ValueError, "artifact_digest"):
            _record(artifact_digest="not-hex")

    def test_record_digest_is_stable_across_constructs(self):
        a = _record()
        b = _record()
        self.assertEqual(a.record_digest, b.record_digest)

    def test_record_digest_changes_with_artifact(self):
        a = _record()
        b = _record(artifact_digest=hashlib.sha256(b"other").hexdigest())
        self.assertNotEqual(a.record_digest, b.record_digest)


class HappyPathTests(unittest.TestCase):
    def test_release_decision_verifies(self):
        priv, pem = _make_keypair()
        record = _record()
        decision = sign_decision(_unsigned_decision(record), priv)
        result = verify_release_authorization(
            decision,
            record=record,
            issuer_lookup=_lookup(_REVIEWER_ISS, _REVIEWER_KID, pem),
            current=_NOW,
        )
        self.assertIs(result, decision)

    def test_verify_decision_passes_a_reject_too(self):
        # verify_decision is the audit/archive path: it should validate
        # well-formed REJECTs the same way it validates RELEASEs.
        priv, pem = _make_keypair()
        record = _record()
        decision = sign_decision(
            _unsigned_decision(record, verdict=ReviewVerdict.REJECT), priv
        )
        result = verify_decision(
            decision,
            record=record,
            issuer_lookup=_lookup(_REVIEWER_ISS, _REVIEWER_KID, pem),
            current=_NOW,
        )
        self.assertIs(result, decision)


class BindingTests(unittest.TestCase):
    def test_record_digest_mismatch_rejected(self):
        priv, pem = _make_keypair()
        record_a = _record()
        record_b = _record(record_id="01900000-0000-7000-8000-00000000000a")
        # Sign for record_a, verify against record_b → mismatch.
        decision = sign_decision(_unsigned_decision(record_a), priv)
        with self.assertRaises(ReviewError) as ctx:
            verify_release_authorization(
                decision,
                record=record_b,
                issuer_lookup=_lookup(_REVIEWER_ISS, _REVIEWER_KID, pem),
                current=_NOW,
            )
        self.assertEqual(ctx.exception.reason, "review_record_mismatch")


class TimeWindowTests(unittest.TestCase):
    def _verify(self, decision: ReviewDecision, record: QuarantineRecord, pem: bytes, **kw):
        return verify_release_authorization(
            decision,
            record=record,
            issuer_lookup=_lookup(_REVIEWER_ISS, _REVIEWER_KID, pem),
            current=_NOW,
            **kw,
        )

    def test_iat_after_nbf_rejected(self):
        priv, pem = _make_keypair()
        record = _record()
        decision = sign_decision(
            _unsigned_decision(record, iat=_NOW_TS + 5, nbf=_NOW_TS), priv
        )
        with self.assertRaises(ReviewError) as ctx:
            self._verify(decision, record, pem)
        self.assertEqual(ctx.exception.reason, "review_invalid_validity_window")

    def test_nbf_after_exp_rejected(self):
        priv, pem = _make_keypair()
        record = _record()
        decision = sign_decision(
            _unsigned_decision(record, nbf=_NOW_TS + 1000, exp=_NOW_TS + 10), priv
        )
        with self.assertRaises(ReviewError) as ctx:
            self._verify(decision, record, pem)
        self.assertEqual(ctx.exception.reason, "review_invalid_validity_window")

    def test_ttl_exceeds_max_rejected(self):
        priv, pem = _make_keypair()
        record = _record()
        # 48h TTL with the 24h default cap.
        decision = sign_decision(
            _unsigned_decision(
                record, nbf=_NOW_TS, exp=_NOW_TS + 48 * 3600
            ),
            priv,
        )
        with self.assertRaises(ReviewError) as ctx:
            self._verify(decision, record, pem)
        self.assertEqual(ctx.exception.reason, "review_ttl_exceeded")

    def test_not_yet_valid_rejected(self):
        priv, pem = _make_keypair()
        record = _record()
        decision = sign_decision(
            _unsigned_decision(
                record,
                iat=_NOW_TS + 600,
                nbf=_NOW_TS + 3600,
                exp=_NOW_TS + 7200,
            ),
            priv,
        )
        with self.assertRaises(ReviewError) as ctx:
            self._verify(decision, record, pem)
        self.assertEqual(ctx.exception.reason, "review_not_yet_valid")

    def test_expired_rejected(self):
        priv, pem = _make_keypair()
        record = _record()
        decision = sign_decision(
            _unsigned_decision(
                record,
                iat=_NOW_TS - 7200,
                nbf=_NOW_TS - 7200,
                exp=_NOW_TS - 3600,
            ),
            priv,
        )
        with self.assertRaises(ReviewError) as ctx:
            self._verify(decision, record, pem)
        self.assertEqual(ctx.exception.reason, "review_expired")


class SignatureTests(unittest.TestCase):
    def test_tampered_decision_fails_signature_check(self):
        priv, pem = _make_keypair()
        record = _record()
        signed = sign_decision(_unsigned_decision(record), priv)
        # Mutate `reason` post-sign so signature no longer covers it.
        import dataclasses
        tampered = dataclasses.replace(signed, reason="forged-reason")
        with self.assertRaises(ReviewError) as ctx:
            verify_release_authorization(
                tampered,
                record=record,
                issuer_lookup=_lookup(_REVIEWER_ISS, _REVIEWER_KID, pem),
                current=_NOW,
            )
        self.assertEqual(ctx.exception.reason, "review_signature_invalid")

    def test_unknown_issuer_rejected(self):
        priv, _ = _make_keypair()
        record = _record()
        decision = sign_decision(_unsigned_decision(record), priv)

        def _empty_lookup(iss: str, kid: str) -> bytes:
            raise EnvelopeVerificationError("not found")

        with self.assertRaises(ReviewError) as ctx:
            verify_release_authorization(
                decision,
                record=record,
                issuer_lookup=_empty_lookup,
                current=_NOW,
            )
        self.assertEqual(ctx.exception.reason, "review_unknown_issuer")

    def test_signed_with_unrelated_key_rejected(self):
        priv_a, _pem_a = _make_keypair()
        _priv_b, pem_b = _make_keypair()
        record = _record()
        # Reviewer signs with priv_a; trust store hands back pem_b.
        decision = sign_decision(_unsigned_decision(record), priv_a)
        with self.assertRaises(ReviewError) as ctx:
            verify_release_authorization(
                decision,
                record=record,
                issuer_lookup=_lookup(_REVIEWER_ISS, _REVIEWER_KID, pem_b),
                current=_NOW,
            )
        self.assertEqual(ctx.exception.reason, "review_signature_invalid")


class VerdictTests(unittest.TestCase):
    def test_reject_blocks_release_path(self):
        priv, pem = _make_keypair()
        record = _record()
        decision = sign_decision(
            _unsigned_decision(record, verdict=ReviewVerdict.REJECT), priv
        )
        with self.assertRaises(ReviewError) as ctx:
            verify_release_authorization(
                decision,
                record=record,
                issuer_lookup=_lookup(_REVIEWER_ISS, _REVIEWER_KID, pem),
                current=_NOW,
            )
        self.assertEqual(ctx.exception.reason, "review_rejected")


class JsonRoundTripTests(unittest.TestCase):
    def test_round_trip_preserves_fields(self):
        priv, _ = _make_keypair()
        record = _record()
        signed = sign_decision(_unsigned_decision(record), priv)
        blob = to_json(signed)
        restored = from_json(blob)
        self.assertEqual(restored, signed)

    def test_unknown_verdict_rejected(self):
        priv, _ = _make_keypair()
        record = _record()
        signed = sign_decision(_unsigned_decision(record), priv)
        blob = to_json(signed).replace(b'"release"', b'"shrug"')
        with self.assertRaises(ReviewError) as ctx:
            from_json(blob)
        self.assertEqual(ctx.exception.reason, "review_malformed")


if __name__ == "__main__":
    unittest.main()
