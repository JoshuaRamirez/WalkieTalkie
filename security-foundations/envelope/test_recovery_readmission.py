"""Tests for recovery and re-admission (Phase 3 Track D D3)."""

import dataclasses
import hashlib
import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from recovery_readmission import (
    CleanRoomAttestation,
    QuarantineEntry,
    ReAdmissionError,
    ReAdmissionGrant,
    from_json,
    sign_attestation,
    to_json,
    verify_readmission,
)
from verify_envelope import EnvelopeVerificationError

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_TS = int(_NOW.timestamp())
_WORKLOAD = "spiffe://mesh.example/ns-a/agent-1"
_ATTESTER = "spiffe://mesh.example/ns-ops/clean-room-1"
_ATTESTER_KID = "attester-kid-1"
_OLD_KID = "kid-pre-quarantine"
_NEW_KID = "kid-post-rebuild"
_QID = "01900000-0000-7000-8000-aaaaaaaaaaa1"
_JTI = "01900000-0000-7000-8000-aaaaaaaaaaa2"
_BASELINE = hashlib.sha256(b"clean-baseline-bytes").hexdigest()


def _make_keypair():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def _lookup(pem: bytes):
    def _f(iss: str, kid: str) -> bytes:
        if (iss, kid) != (_ATTESTER, _ATTESTER_KID):
            raise EnvelopeVerificationError(
                f"unknown: iss={iss!r}, kid={kid!r}"
            )
        return pem
    return _f


def _quarantine(**overrides) -> QuarantineEntry:
    kwargs = dict(
        quarantine_id=_QID,
        workload_iss=_WORKLOAD,
        last_kid=_OLD_KID,
        quarantined_at=_NOW - timedelta(hours=2),
        reason="key material suspected compromised",
    )
    kwargs.update(overrides)
    return QuarantineEntry(**kwargs)


def _attestation(**overrides) -> CleanRoomAttestation:
    kwargs = dict(
        quarantine_id=_QID,
        workload_iss=_WORKLOAD,
        new_kid=_NEW_KID,
        baseline_digest=_BASELINE,
        attester_iss=_ATTESTER,
        attester_kid=_ATTESTER_KID,
        iat=_NOW_TS - 60,
        nbf=_NOW_TS - 60,
        exp=_NOW_TS + 3600,
        monitoring_period_seconds=86400,
        jti=_JTI,
    )
    kwargs.update(overrides)
    return CleanRoomAttestation(**kwargs)


class QuarantineValidationTests(unittest.TestCase):
    def test_bad_quarantine_id_rejected(self):
        with self.assertRaises(ReAdmissionError) as ctx:
            _quarantine(quarantine_id="not-uuid")
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_malformed"
        )

    def test_naive_quarantined_at_rejected(self):
        with self.assertRaises(ReAdmissionError):
            _quarantine(quarantined_at=datetime(2026, 4, 14, 12))


class HappyPathTests(unittest.TestCase):
    def test_valid_attestation_grants_readmission(self):
        priv, pem = _make_keypair()
        q = _quarantine()
        signed = sign_attestation(_attestation(), priv)
        grant = verify_readmission(
            signed,
            quarantine=q,
            issuer_lookup=_lookup(pem),
            current=_NOW,
        )
        self.assertIsInstance(grant, ReAdmissionGrant)
        self.assertEqual(grant.workload_iss, _WORKLOAD)
        self.assertEqual(grant.new_kid, _NEW_KID)
        self.assertEqual(grant.monitoring_period, timedelta(days=1))


class BindingTests(unittest.TestCase):
    def test_quarantine_id_mismatch_rejected(self):
        priv, pem = _make_keypair()
        q = _quarantine()
        signed = sign_attestation(
            _attestation(
                quarantine_id="01900000-0000-7000-8000-bbbbbbbbbbbb"
            ),
            priv,
        )
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed, quarantine=q, issuer_lookup=_lookup(pem), current=_NOW
            )
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_mismatch"
        )

    def test_workload_mismatch_rejected(self):
        priv, pem = _make_keypair()
        q = _quarantine()
        signed = sign_attestation(
            _attestation(workload_iss="spiffe://mesh.example/ns-x/other"),
            priv,
        )
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed, quarantine=q, issuer_lookup=_lookup(pem), current=_NOW
            )
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_mismatch"
        )

    def test_kid_reuse_rejected(self):
        priv, pem = _make_keypair()
        q = _quarantine()
        # Attestation tries to reuse the quarantined kid.
        signed = sign_attestation(_attestation(new_kid=_OLD_KID), priv)
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed, quarantine=q, issuer_lookup=_lookup(pem), current=_NOW
            )
        self.assertEqual(ctx.exception.reason.value, "readmission_kid_reuse")


class WindowTests(unittest.TestCase):
    def test_expired_attestation_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_attestation(
            _attestation(
                iat=_NOW_TS - 7200,
                nbf=_NOW_TS - 7200,
                exp=_NOW_TS - 3600,
            ),
            priv,
        )
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed,
                quarantine=_quarantine(),
                issuer_lookup=_lookup(pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_expired"
        )

    def test_not_yet_valid_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_attestation(
            _attestation(
                iat=_NOW_TS + 3600,
                nbf=_NOW_TS + 3600,
                exp=_NOW_TS + 7200,
            ),
            priv,
        )
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed,
                quarantine=_quarantine(),
                issuer_lookup=_lookup(pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_expired"
        )

    def test_ttl_exceeds_max_rejected(self):
        priv, pem = _make_keypair()
        # 48h window with 24h max.
        signed = sign_attestation(
            _attestation(iat=_NOW_TS, nbf=_NOW_TS, exp=_NOW_TS + 48 * 3600),
            priv,
        )
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed,
                quarantine=_quarantine(),
                issuer_lookup=_lookup(pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_malformed"
        )


class SignatureTests(unittest.TestCase):
    def test_unknown_attester_rejected(self):
        priv, _ = _make_keypair()
        signed = sign_attestation(_attestation(), priv)

        def _empty(iss: str, kid: str) -> bytes:
            raise EnvelopeVerificationError("not found")

        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed,
                quarantine=_quarantine(),
                issuer_lookup=_empty,
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_unknown_issuer"
        )

    def test_tampered_attestation_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_attestation(_attestation(), priv)
        tampered = dataclasses.replace(
            signed, baseline_digest=hashlib.sha256(b"tampered").hexdigest()
        )
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                tampered,
                quarantine=_quarantine(),
                issuer_lookup=_lookup(pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value,
            "readmission_attestation_signature_invalid",
        )

    def test_signed_with_unrelated_key_rejected(self):
        priv_a, _pem_a = _make_keypair()
        _priv_b, pem_b = _make_keypair()
        signed = sign_attestation(_attestation(), priv_a)
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed,
                quarantine=_quarantine(),
                issuer_lookup=_lookup(pem_b),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value,
            "readmission_attestation_signature_invalid",
        )


class JsonRoundTripTests(unittest.TestCase):
    def test_round_trip(self):
        priv, _ = _make_keypair()
        signed = sign_attestation(_attestation(), priv)
        restored = from_json(to_json(signed))
        self.assertEqual(restored, signed)

    def test_missing_field_rejected(self):
        with self.assertRaises(ReAdmissionError) as ctx:
            from_json(b'{"quarantine_id": "x"}')
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_malformed"
        )


class CleanStateEvidenceTests(unittest.TestCase):
    """The Track D D3 acceptance criterion: 'Re-admitted nodes
    satisfy clean-state evidence requirements.' v0 pins three
    concrete requirements:
        1. Signed by an attester in a separate trust pool (so the
           rebuilt workload cannot sign its own re-admission).
        2. Carries baseline_digest committing to a specific clean
           image / state.
        3. Uses a new kid distinct from the quarantined material."""

    def test_attester_trust_pool_is_separate(self):
        # The lookup function fails for non-attester (iss, kid) pairs,
        # so a workload that tries to use ITS OWN key as the attester
        # key gets rejected at issuer_lookup time. (Validated more
        # explicitly by test_unknown_attester_rejected above.)
        priv, pem = _make_keypair()
        signed = sign_attestation(
            _attestation(
                attester_iss=_WORKLOAD,  # the workload signing its own re-admission
                attester_kid=_OLD_KID,
            ),
            priv,
        )
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed,
                quarantine=_quarantine(),
                issuer_lookup=_lookup(pem),  # lookup recognizes only _ATTESTER
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_unknown_issuer"
        )

    def test_baseline_digest_required(self):
        # Malformed digest fails shape validation.
        priv, pem = _make_keypair()
        signed = sign_attestation(
            _attestation(baseline_digest="not-hex-sha256"),
            priv,
        )
        with self.assertRaises(ReAdmissionError) as ctx:
            verify_readmission(
                signed,
                quarantine=_quarantine(),
                issuer_lookup=_lookup(pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "readmission_attestation_malformed"
        )

    def test_new_kid_required_and_recorded_in_grant(self):
        priv, pem = _make_keypair()
        signed = sign_attestation(_attestation(), priv)
        grant = verify_readmission(
            signed,
            quarantine=_quarantine(),
            issuer_lookup=_lookup(pem),
            current=_NOW,
        )
        # Grant explicitly mentions the post-rebuild kid AND the
        # baseline that proves clean state.
        self.assertEqual(grant.new_kid, _NEW_KID)
        self.assertEqual(grant.baseline_digest, _BASELINE)
        self.assertNotEqual(grant.new_kid, _OLD_KID)


if __name__ == "__main__":
    unittest.main()
