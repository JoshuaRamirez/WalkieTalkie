"""Tests for the tool policy gate (Phase 2 Track D D2)."""

import dataclasses
import hashlib
import pathlib
import sys
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tool_policy_gate import (
    RiskTier,
    StepUpAttestation,
    StepUpError,
    ToolCall,
    ToolPolicy,
    ToolPolicyDenied,
    ToolPolicyError,
    ToolRule,
    evaluate_tool_call,
    from_json,
    require_tool_call,
    sign_step_up,
    to_json,
)
from verify_envelope import EnvelopeVerificationError

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_TS = int(_NOW.timestamp())
_CALLER = "spiffe://mesh.example/ns-a/agent-1"
_OTHER_CALLER = "spiffe://mesh.example/ns-z/other"
_ISSUER = "spiffe://mesh.example/ns-stepup/issuer-1"
_KID = "stepup-kid-1"
_ARGS_DIGEST = hashlib.sha256(b"args").hexdigest()
_OTHER_DIGEST = hashlib.sha256(b"other-args").hexdigest()
_JTI = "01900000-0000-7000-8000-000000000001"


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
                f"unknown: iss={iss!r}, kid={kid!r}"
            )
        return pem
    return _f


def _empty_lookup(iss: str, kid: str) -> bytes:
    raise EnvelopeVerificationError("not found")


def _call(tool: str = "read_file", *, caller: str = _CALLER, digest: str = _ARGS_DIGEST) -> ToolCall:
    return ToolCall(tool_name=tool, caller_iss=caller, arguments_digest=digest)


def _unsigned_attestation(call: ToolCall, **overrides) -> StepUpAttestation:
    kwargs = dict(
        tool_name=call.tool_name,
        caller_iss=call.caller_iss,
        arguments_digest=call.arguments_digest,
        issuer_iss=_ISSUER,
        issuer_kid=_KID,
        iat=_NOW_TS - 5,
        nbf=_NOW_TS,
        exp=_NOW_TS + 300,
        jti=_JTI,
    )
    kwargs.update(overrides)
    return StepUpAttestation(**kwargs)


class ToolRuleTests(unittest.TestCase):
    def test_invalid_spiffe_in_allowlist_rejected(self):
        with self.assertRaisesRegex(ToolPolicyError, "SPIFFE"):
            ToolRule(
                tool_name="x",
                risk_tier=RiskTier.LOW,
                allowed_callers=frozenset({"not-spiffe"}),
            )

    def test_step_up_auto_for_high_risk(self):
        rule = ToolRule(tool_name="x", risk_tier=RiskTier.HIGH)
        self.assertTrue(rule.effective_step_up_required)

    def test_step_up_auto_for_critical(self):
        rule = ToolRule(tool_name="x", risk_tier=RiskTier.CRITICAL)
        self.assertTrue(rule.effective_step_up_required)

    def test_step_up_auto_off_for_low(self):
        rule = ToolRule(tool_name="x", risk_tier=RiskTier.LOW)
        self.assertFalse(rule.effective_step_up_required)

    def test_step_up_explicit_override_wins(self):
        rule = ToolRule(
            tool_name="x", risk_tier=RiskTier.LOW, step_up_required=True
        )
        self.assertTrue(rule.effective_step_up_required)
        rule2 = ToolRule(
            tool_name="x", risk_tier=RiskTier.CRITICAL, step_up_required=False
        )
        self.assertFalse(rule2.effective_step_up_required)


class ToolPolicyTests(unittest.TestCase):
    def test_duplicate_tool_name_rejected(self):
        a = ToolRule(tool_name="t", risk_tier=RiskTier.LOW)
        with self.assertRaisesRegex(ToolPolicyError, "duplicate"):
            ToolPolicy(rules=(a, a))


class UnknownToolTests(unittest.TestCase):
    def test_unknown_tool_denied(self):
        policy = ToolPolicy(rules=())
        decision = evaluate_tool_call(
            call=_call(), policy=policy, current=_NOW
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "tool_unknown")


class CallerAllowlistTests(unittest.TestCase):
    def test_empty_allowlist_means_any_caller(self):
        policy = ToolPolicy(
            rules=(ToolRule(tool_name="read_file", risk_tier=RiskTier.LOW),)
        )
        decision = evaluate_tool_call(
            call=_call(), policy=policy, current=_NOW
        )
        self.assertTrue(decision.allowed)

    def test_caller_not_in_allowlist_denied(self):
        policy = ToolPolicy(
            rules=(
                ToolRule(
                    tool_name="read_file",
                    risk_tier=RiskTier.LOW,
                    allowed_callers=frozenset({_CALLER}),
                ),
            )
        )
        decision = evaluate_tool_call(
            call=_call(caller=_OTHER_CALLER), policy=policy, current=_NOW
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "tool_caller_not_allowed")

    def test_caller_in_allowlist_allowed(self):
        policy = ToolPolicy(
            rules=(
                ToolRule(
                    tool_name="read_file",
                    risk_tier=RiskTier.LOW,
                    allowed_callers=frozenset({_CALLER}),
                ),
            )
        )
        decision = evaluate_tool_call(
            call=_call(), policy=policy, current=_NOW
        )
        self.assertTrue(decision.allowed)


class StepUpHappyPathTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _make_keypair()
        self.policy = ToolPolicy(
            rules=(ToolRule(tool_name="exec_sql", risk_tier=RiskTier.CRITICAL),)
        )

    def test_critical_tool_with_valid_step_up_allowed(self):
        call = _call(tool="exec_sql")
        attestation = sign_step_up(_unsigned_attestation(call), self.priv)
        decision = evaluate_tool_call(
            call=call,
            policy=self.policy,
            step_up=attestation,
            issuer_lookup=_lookup(_ISSUER, _KID, self.pem),
            current=_NOW,
        )
        self.assertTrue(decision.allowed)

    def test_critical_tool_without_step_up_denied(self):
        decision = evaluate_tool_call(
            call=_call(tool="exec_sql"),
            policy=self.policy,
            current=_NOW,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "tool_step_up_required")


class StepUpBindingTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _make_keypair()
        self.policy = ToolPolicy(
            rules=(ToolRule(tool_name="exec_sql", risk_tier=RiskTier.CRITICAL),)
        )

    def test_step_up_for_different_tool_rejected(self):
        call = _call(tool="exec_sql")
        # Sign an attestation for a *different* tool.
        attestation = sign_step_up(
            _unsigned_attestation(call, tool_name="read_file"),
            self.priv,
        )
        decision = evaluate_tool_call(
            call=call,
            policy=self.policy,
            step_up=attestation,
            issuer_lookup=_lookup(_ISSUER, _KID, self.pem),
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "tool_step_up_mismatch")

    def test_step_up_for_different_caller_rejected(self):
        call = _call(tool="exec_sql")
        attestation = sign_step_up(
            _unsigned_attestation(call, caller_iss=_OTHER_CALLER),
            self.priv,
        )
        decision = evaluate_tool_call(
            call=call,
            policy=self.policy,
            step_up=attestation,
            issuer_lookup=_lookup(_ISSUER, _KID, self.pem),
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "tool_step_up_mismatch")

    def test_step_up_for_different_arguments_rejected(self):
        call = _call(tool="exec_sql")
        attestation = sign_step_up(
            _unsigned_attestation(call, arguments_digest=_OTHER_DIGEST),
            self.priv,
        )
        decision = evaluate_tool_call(
            call=call,
            policy=self.policy,
            step_up=attestation,
            issuer_lookup=_lookup(_ISSUER, _KID, self.pem),
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "tool_step_up_mismatch")


class StepUpFreshnessTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _make_keypair()
        self.policy = ToolPolicy(
            rules=(ToolRule(tool_name="exec_sql", risk_tier=RiskTier.CRITICAL),)
        )
        self.call = _call(tool="exec_sql")

    def test_expired_step_up_rejected(self):
        # 4-minute window, sits entirely in the past — within the
        # 10-minute default TTL cap so the freshness check fires.
        attestation = sign_step_up(
            _unsigned_attestation(
                self.call,
                iat=_NOW_TS - 300,
                nbf=_NOW_TS - 300,
                exp=_NOW_TS - 120,
            ),
            self.priv,
        )
        decision = evaluate_tool_call(
            call=self.call,
            policy=self.policy,
            step_up=attestation,
            issuer_lookup=_lookup(_ISSUER, _KID, self.pem),
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "tool_step_up_expired")

    def test_not_yet_valid_step_up_rejected(self):
        attestation = sign_step_up(
            _unsigned_attestation(
                self.call,
                iat=_NOW_TS,
                nbf=_NOW_TS + 300,
                exp=_NOW_TS + 540,
            ),
            self.priv,
        )
        decision = evaluate_tool_call(
            call=self.call,
            policy=self.policy,
            step_up=attestation,
            issuer_lookup=_lookup(_ISSUER, _KID, self.pem),
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "tool_step_up_expired")


class StepUpSignatureTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _make_keypair()
        self.policy = ToolPolicy(
            rules=(ToolRule(tool_name="exec_sql", risk_tier=RiskTier.CRITICAL),)
        )
        self.call = _call(tool="exec_sql")

    def test_unknown_issuer_rejected(self):
        attestation = sign_step_up(_unsigned_attestation(self.call), self.priv)
        decision = evaluate_tool_call(
            call=self.call,
            policy=self.policy,
            step_up=attestation,
            issuer_lookup=_empty_lookup,
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "tool_step_up_unknown_issuer")

    def test_tampered_attestation_rejected(self):
        attestation = sign_step_up(_unsigned_attestation(self.call), self.priv)
        # Tamper iat post-sign so the sig no longer covers it.
        tampered = dataclasses.replace(attestation, iat=attestation.iat + 1)
        decision = evaluate_tool_call(
            call=self.call,
            policy=self.policy,
            step_up=tampered,
            issuer_lookup=_lookup(_ISSUER, _KID, self.pem),
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "tool_step_up_signature_invalid")

    def test_signed_with_unrelated_key_rejected(self):
        attestation = sign_step_up(_unsigned_attestation(self.call), self.priv)
        _other_priv, other_pem = _make_keypair()
        decision = evaluate_tool_call(
            call=self.call,
            policy=self.policy,
            step_up=attestation,
            issuer_lookup=_lookup(_ISSUER, _KID, other_pem),
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "tool_step_up_signature_invalid")


class StepUpExplicitOverrideTests(unittest.TestCase):
    def test_low_risk_tool_with_step_up_required_demands_step_up(self):
        policy = ToolPolicy(
            rules=(
                ToolRule(
                    tool_name="read_file",
                    risk_tier=RiskTier.LOW,
                    step_up_required=True,
                ),
            )
        )
        decision = evaluate_tool_call(
            call=_call(), policy=policy, current=_NOW
        )
        self.assertEqual(decision.reason_code, "tool_step_up_required")

    def test_critical_tool_with_step_up_disabled_passes_without(self):
        policy = ToolPolicy(
            rules=(
                ToolRule(
                    tool_name="exec_sql",
                    risk_tier=RiskTier.CRITICAL,
                    step_up_required=False,
                ),
            )
        )
        decision = evaluate_tool_call(
            call=_call(tool="exec_sql"), policy=policy, current=_NOW
        )
        self.assertTrue(decision.allowed)


class RequireToolCallTests(unittest.TestCase):
    def test_allow_returns_decision(self):
        policy = ToolPolicy(
            rules=(ToolRule(tool_name="read_file", risk_tier=RiskTier.LOW),)
        )
        d = require_tool_call(call=_call(), policy=policy, current=_NOW)
        self.assertTrue(d.allowed)

    def test_deny_raises_with_reason(self):
        policy = ToolPolicy(rules=())
        with self.assertRaises(ToolPolicyDenied) as ctx:
            require_tool_call(call=_call(), policy=policy, current=_NOW)
        self.assertEqual(ctx.exception.reason.value, "tool_unknown")


class JsonRoundTripTests(unittest.TestCase):
    def test_round_trip(self):
        priv, _ = _make_keypair()
        call = _call()
        signed = sign_step_up(_unsigned_attestation(call), priv)
        blob = to_json(signed)
        restored = from_json(blob)
        self.assertEqual(restored, signed)

    def test_missing_field_rejected(self):
        with self.assertRaises(StepUpError) as ctx:
            from_json(b'{"tool_name": "x"}')
        self.assertEqual(ctx.exception.reason.value, "tool_step_up_malformed")


if __name__ == "__main__":
    unittest.main()
