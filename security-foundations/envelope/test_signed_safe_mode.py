"""Tests for signed safe-mode artifacts (Phase 3 D3.3 circle-back)."""

import dataclasses
import pathlib
import sys
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from safe_mode_engine import (
    SafeModeEngine,
    SafeModeEngineError,
    SafeModeState,
    TriggerCategory,
    TriggerKind,
    trigger_for,
)
from signed_safe_mode import (
    SignedDowngradeApproval,
    SignedSafeModeError,
    approval_from_json,
    approval_to_json,
    from_transition,
    sign_downgrade_approval,
    sign_transition,
    transition_from_json,
    transition_to_json,
    verified_downgrade,
    verify_downgrade_approval,
    verify_transition,
)
from verify_envelope import EnvelopeVerificationError

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_TS = int(_NOW.timestamp())
_ATTESTER = "spiffe://mesh.example/ns-ops/attester-1"
_ATT_KID = "attester-kid-1"
_APPROVER = "spiffe://mesh.example/ns-ops/approver-1"
_APP_KID = "approver-kid-1"
_TRANS_JTI = "01900000-0000-7000-8000-aaaaaaaaaaa1"
_APP_JTI = "01900000-0000-7000-8000-aaaaaaaaaaa2"


def _make_keypair():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def _lookup_for(iss: str, kid: str, pem: bytes):
    def _f(want_iss: str, want_kid: str) -> bytes:
        if (want_iss, want_kid) != (iss, kid):
            raise EnvelopeVerificationError(
                f"unknown: iss={want_iss!r}, kid={want_kid!r}"
            )
        return pem
    return _f


def _engine_with_trigger() -> SafeModeEngine:
    engine = SafeModeEngine()
    engine.observe(
        trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
    )
    return engine


# ---------------------------------------------------------------------
# Signed transition tests
# ---------------------------------------------------------------------


class TransitionHappyPathTests(unittest.TestCase):
    def test_round_trip_and_verify(self):
        priv, pem = _make_keypair()
        engine = SafeModeEngine()
        transition = engine.observe(
            trigger_for(TriggerKind.LEDGER_DIVERGENCE, observed_at=_NOW)
        )
        signed = sign_transition(
            from_transition(
                transition,
                attester_iss=_ATTESTER,
                attester_kid=_ATT_KID,
                jti=_TRANS_JTI,
            ),
            priv,
        )
        result = verify_transition(
            signed, issuer_lookup=_lookup_for(_ATTESTER, _ATT_KID, pem)
        )
        self.assertIs(result, signed)
        self.assertEqual(signed.from_state, SafeModeState.S0_NORMAL)
        self.assertEqual(signed.to_state, SafeModeState.S4_LOCKDOWN)
        self.assertEqual(signed.cause, "trigger")
        self.assertIn("ledger_divergence", signed.active_kinds)

    def test_active_kinds_sorted_deterministically(self):
        priv, _pem = _make_keypair()
        engine = SafeModeEngine()
        engine.observe(trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW))
        transition = engine.observe(
            trigger_for(TriggerKind.ANOMALY_QUARANTINE, observed_at=_NOW)
        )
        signed = sign_transition(
            from_transition(
                transition,
                attester_iss=_ATTESTER,
                attester_kid=_ATT_KID,
                jti=_TRANS_JTI,
            ),
            priv,
        )
        # Sorted alphabetically for determinism across processes.
        self.assertEqual(
            list(signed.active_kinds), sorted(signed.active_kinds)
        )


class TransitionFailureTests(unittest.TestCase):
    def test_tampered_transition_rejected(self):
        priv, pem = _make_keypair()
        engine = SafeModeEngine()
        transition = engine.observe(
            trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
        )
        signed = sign_transition(
            from_transition(
                transition,
                attester_iss=_ATTESTER,
                attester_kid=_ATT_KID,
                jti=_TRANS_JTI,
            ),
            priv,
        )
        tampered = dataclasses.replace(signed, detail="forged-detail")
        with self.assertRaises(SignedSafeModeError) as ctx:
            verify_transition(
                tampered,
                issuer_lookup=_lookup_for(_ATTESTER, _ATT_KID, pem),
            )
        self.assertEqual(
            ctx.exception.reason.value, "safe_mode_artifact_signature_invalid"
        )

    def test_unknown_attester_rejected(self):
        priv, _ = _make_keypair()
        engine = SafeModeEngine()
        transition = engine.observe(
            trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
        )
        signed = sign_transition(
            from_transition(
                transition,
                attester_iss=_ATTESTER,
                attester_kid=_ATT_KID,
                jti=_TRANS_JTI,
            ),
            priv,
        )

        def _empty(iss, kid):
            raise EnvelopeVerificationError("nope")

        with self.assertRaises(SignedSafeModeError) as ctx:
            verify_transition(signed, issuer_lookup=_empty)
        self.assertEqual(
            ctx.exception.reason.value, "safe_mode_artifact_unknown_issuer"
        )

    def test_bad_jti_rejected_at_shape(self):
        priv, pem = _make_keypair()
        engine = SafeModeEngine()
        transition = engine.observe(
            trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
        )
        signed = sign_transition(
            dataclasses.replace(
                from_transition(
                    transition,
                    attester_iss=_ATTESTER,
                    attester_kid=_ATT_KID,
                    jti=_TRANS_JTI,
                ),
                jti="not-uuid",
            ),
            priv,
        )
        with self.assertRaises(SignedSafeModeError) as ctx:
            verify_transition(
                signed, issuer_lookup=_lookup_for(_ATTESTER, _ATT_KID, pem)
            )
        self.assertEqual(ctx.exception.reason.value, "safe_mode_artifact_malformed")


class TransitionJsonTests(unittest.TestCase):
    def test_round_trip(self):
        priv, _pem = _make_keypair()
        engine = SafeModeEngine()
        transition = engine.observe(
            trigger_for(TriggerKind.LEDGER_DIVERGENCE, observed_at=_NOW)
        )
        signed = sign_transition(
            from_transition(
                transition,
                attester_iss=_ATTESTER,
                attester_kid=_ATT_KID,
                jti=_TRANS_JTI,
            ),
            priv,
        )
        restored = transition_from_json(transition_to_json(signed))
        self.assertEqual(restored, signed)

    def test_missing_field_rejected(self):
        with self.assertRaises(SignedSafeModeError) as ctx:
            transition_from_json(b'{"from_state": "s0_normal"}')
        self.assertEqual(ctx.exception.reason.value, "safe_mode_artifact_malformed")

    def test_unknown_state_value_rejected(self):
        with self.assertRaises(SignedSafeModeError) as ctx:
            transition_from_json(
                b'{"from_state":"not-a-state","to_state":"s0_normal",'
                b'"transition_at":0,"cause":"trigger","active_kinds":[],'
                b'"detail":"","attester_iss":"spiffe://m/n/a",'
                b'"attester_kid":"k","jti":"01900000-0000-7000-8000-0",'
                b'"signature":"sig"}'
            )
        self.assertEqual(ctx.exception.reason.value, "safe_mode_artifact_malformed")


# ---------------------------------------------------------------------
# Signed downgrade approval tests
# ---------------------------------------------------------------------


def _unsigned_approval(**overrides) -> SignedDowngradeApproval:
    kwargs = dict(
        approver_iss=_APPROVER,
        approver_kid=_APP_KID,
        authority=TriggerCategory.CRYPTO_TRUST,
        issued_at=_NOW_TS - 5,
        nbf=_NOW_TS,
        exp=_NOW_TS + 600,
        detail="ops decision",
        jti=_APP_JTI,
    )
    kwargs.update(overrides)
    return SignedDowngradeApproval(**kwargs)


class ApprovalHappyPathTests(unittest.TestCase):
    def test_signed_approval_verifies(self):
        priv, pem = _make_keypair()
        signed = sign_downgrade_approval(_unsigned_approval(), priv)
        result = verify_downgrade_approval(
            signed,
            issuer_lookup=_lookup_for(_APPROVER, _APP_KID, pem),
            current=_NOW,
        )
        self.assertIs(result, signed)


class ApprovalFailureTests(unittest.TestCase):
    def test_tampered_approval_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_downgrade_approval(_unsigned_approval(), priv)
        tampered = dataclasses.replace(
            signed, authority=TriggerCategory.AVAILABILITY
        )
        with self.assertRaises(SignedSafeModeError) as ctx:
            verify_downgrade_approval(
                tampered,
                issuer_lookup=_lookup_for(_APPROVER, _APP_KID, pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "safe_mode_artifact_signature_invalid"
        )

    def test_expired_approval_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_downgrade_approval(
            _unsigned_approval(
                issued_at=_NOW_TS - 600,
                nbf=_NOW_TS - 600,
                exp=_NOW_TS - 300,
            ),
            priv,
        )
        with self.assertRaises(SignedSafeModeError) as ctx:
            verify_downgrade_approval(
                signed,
                issuer_lookup=_lookup_for(_APPROVER, _APP_KID, pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "safe_mode_artifact_expired"
        )

    def test_unknown_approver_rejected(self):
        priv, _pem = _make_keypair()
        signed = sign_downgrade_approval(_unsigned_approval(), priv)

        def _empty(iss, kid):
            raise EnvelopeVerificationError("nope")

        with self.assertRaises(SignedSafeModeError) as ctx:
            verify_downgrade_approval(
                signed, issuer_lookup=_empty, current=_NOW
            )
        self.assertEqual(
            ctx.exception.reason.value, "safe_mode_artifact_unknown_issuer"
        )

    def test_ttl_exceeds_max_rejected(self):
        priv, pem = _make_keypair()
        # 48h window vs. 1h default cap.
        signed = sign_downgrade_approval(
            _unsigned_approval(
                issued_at=_NOW_TS,
                nbf=_NOW_TS,
                exp=_NOW_TS + 48 * 3600,
            ),
            priv,
        )
        with self.assertRaises(SignedSafeModeError) as ctx:
            verify_downgrade_approval(
                signed,
                issuer_lookup=_lookup_for(_APPROVER, _APP_KID, pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "safe_mode_artifact_malformed"
        )


class VerifiedDowngradeTests(unittest.TestCase):
    def test_end_to_end_downgrade_succeeds(self):
        priv, pem = _make_keypair()
        engine = _engine_with_trigger()
        signed = sign_downgrade_approval(_unsigned_approval(), priv)
        transition = verified_downgrade(
            engine,
            to_state=SafeModeState.S2_RESTRICTED,
            signed_approval=signed,
            issuer_lookup=_lookup_for(_APPROVER, _APP_KID, pem),
            current=_NOW,
        )
        self.assertEqual(transition.cause, "downgrade")
        self.assertEqual(transition.to_state, SafeModeState.S2_RESTRICTED)

    def test_signature_failure_blocks_engine_call(self):
        priv, pem = _make_keypair()
        engine = _engine_with_trigger()
        signed = sign_downgrade_approval(_unsigned_approval(), priv)
        tampered = dataclasses.replace(
            signed, authority=TriggerCategory.AVAILABILITY
        )
        # If the signature check passed (it shouldn't), the engine
        # check would then refuse the AVAILABILITY-authority approval
        # against the AUTHORIZATION trigger. We want to confirm the
        # signature check runs FIRST.
        with self.assertRaises(SignedSafeModeError) as ctx:
            verified_downgrade(
                engine,
                to_state=SafeModeState.S0_NORMAL,
                signed_approval=tampered,
                issuer_lookup=_lookup_for(_APPROVER, _APP_KID, pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "safe_mode_artifact_signature_invalid"
        )
        # Engine state unchanged.
        self.assertEqual(engine.current, SafeModeState.S2_RESTRICTED)

    def test_engine_authority_check_still_fires_after_signature(self):
        # Even with a valid signature, the engine's authority
        # dominance rule must still apply. AVAILABILITY-authority
        # approval against AUTHORIZATION trigger fails inside the
        # engine, not at the signature check.
        priv, pem = _make_keypair()
        engine = _engine_with_trigger()
        signed = sign_downgrade_approval(
            _unsigned_approval(authority=TriggerCategory.AVAILABILITY),
            priv,
        )
        with self.assertRaises(SafeModeEngineError) as ctx:
            verified_downgrade(
                engine,
                to_state=SafeModeState.S0_NORMAL,
                signed_approval=signed,
                issuer_lookup=_lookup_for(_APPROVER, _APP_KID, pem),
                current=_NOW,
            )
        self.assertIn("unauthorized", str(ctx.exception))


class ApprovalJsonTests(unittest.TestCase):
    def test_round_trip(self):
        priv, _pem = _make_keypair()
        signed = sign_downgrade_approval(_unsigned_approval(), priv)
        restored = approval_from_json(approval_to_json(signed))
        self.assertEqual(restored, signed)

    def test_unknown_authority_rejected(self):
        with self.assertRaises(SignedSafeModeError) as ctx:
            approval_from_json(
                b'{"approver_iss":"spiffe://m/n/a","approver_kid":"k",'
                b'"authority":"shrug","issued_at":0,"nbf":0,"exp":1,'
                b'"detail":"","jti":"01900000-0000-7000-8000-0",'
                b'"signature":"sig"}'
            )
        self.assertEqual(ctx.exception.reason.value, "safe_mode_artifact_malformed")


if __name__ == "__main__":
    unittest.main()
