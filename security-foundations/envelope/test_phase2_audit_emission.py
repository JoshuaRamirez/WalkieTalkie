"""Audit-checkpoint emission for Phase 2 verifiers (leftover #100).

Pins the leftover: each named Phase 2 verifier emits one hash-chained
``XXX.verify`` / ``checkpoint.evaluate`` event on allow and on deny
when an ``audit_sink`` is attached. Existing callers that omit the
sink are unchanged. Sink failure fails closed.
"""

from __future__ import annotations

import hashlib
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from envelope.audit import AuditSink, InMemoryAuditSink, verify_chain
from envelope.capability_token import CapabilityClaims
from envelope.checkpointed_execution import (
    Checkpoint,
    CheckpointAction,
    CheckpointPolicy,
    InMemoryRevocationLedger,
    validate_checkpoint,
)
from envelope.data_classification import DataClass, classify
from envelope.delegation_receipt import (
    DelegationError,
    DelegationReceipt,
    sign_receipt,
    verify_receipt,
)
from envelope.deny_reason import DenyReason
from envelope.egress_policy import (
    EgressAction,
    EgressMatrixCell,
    MatrixEgressPolicy,
)
from envelope.output_scanning import RiskLevel
from envelope.retrieval_policy import AllowlistRetrievalPolicy, RetrievalRule
from envelope.reviewer_workflow import (
    QuarantineRecord,
    ReviewDecision,
    ReviewError,
    ReviewVerdict,
    sign_decision,
    verify_decision,
    verify_release_authorization,
)
from envelope.session_token import (
    SessionError,
    SessionToken,
    sign_session,
    verify_resume,
    verify_session_token,
)
from envelope.tool_policy_gate import (
    RiskTier,
    ToolCall,
    ToolPolicy,
    ToolRule,
    evaluate_tool_call,
    sign_step_up,
    StepUpAttestation,
)
from envelope.verify_envelope import EnvelopeVerificationError

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_TS = int(_NOW.timestamp())
_DIGEST = hashlib.sha256(b"x").hexdigest()
_A = "spiffe://mesh.example/ns-a/svc"
_B = "spiffe://mesh.example/ns-b/svc"
_AUD = "spiffe://mesh.example/ns-x/svc"
_ISS = "spiffe://mesh.example/ns-iss/issuer-1"
_KID = "issuer-kid-1"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def _lookup(pem: bytes, expected_iss: str | None = None, expected_kid: str | None = None):
    def _f(iss: str, kid: str) -> bytes:
        if expected_iss is not None and (iss, kid) != (expected_iss, expected_kid):
            raise EnvelopeVerificationError(f"unknown: iss={iss!r}, kid={kid!r}")
        return pem

    return _f


class BrokenSink(AuditSink):
    def tail_hash(self) -> str:
        return "0" * 64

    def _append(self, event) -> None:
        raise AssertionError("unreachable")

    def record(self, **fields):
        raise OSError("audit disk full")


class _AuditPin(unittest.TestCase):
    def _assert_event(
        self,
        sink: InMemoryAuditSink,
        *,
        event_type: str,
        outcome: str,
        reason_code: str,
        artifact_version: str,
    ):
        self.assertEqual(len(sink.events), 1)
        ev = sink.events[0]
        self.assertEqual(ev.event_type, event_type)
        self.assertEqual(ev.outcome, outcome)
        self.assertEqual(ev.reason_code, reason_code)
        self.assertEqual(ev.artifact_version, artifact_version)
        verify_chain(sink.events)
        return ev


class DelegationAuditTests(_AuditPin):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = _lookup(self.pem)

    def _root(self) -> DelegationReceipt:
        return DelegationReceipt(
            chain_id="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c0",
            hop_index=0,
            parent_jti="",
            delegator_iss=_ISS,
            delegator_kid=_KID,
            delegate_iss=_A,
            scope="invoke_tool",
            aud=_AUD,
            iat=_NOW_TS - 30,
            nbf=_NOW_TS - 30,
            exp=_NOW_TS + 240,
            jti="0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1",
        )

    def test_allow_emits_delegation_verify(self):
        sink = InMemoryAuditSink()
        signed = sign_receipt(self._root(), self.priv)
        verify_receipt(
            signed, parent=None, issuer_lookup=self.lookup, current=_NOW, audit_sink=sink
        )
        ev = self._assert_event(
            sink,
            event_type="delegation.verify",
            outcome="allow",
            reason_code="ok",
            artifact_version="wt-delegation/v0",
        )
        self.assertEqual(ev.sender, _ISS)
        self.assertEqual(ev.recipient, _A)

    def test_deny_emits_delegation_verify(self):
        sink = InMemoryAuditSink()
        signed = sign_receipt(self._root(), self.priv)
        with self.assertRaises(DelegationError):
            verify_receipt(
                signed,
                parent=None,
                issuer_lookup=self.lookup,
                current=_NOW + timedelta(hours=2),
                audit_sink=sink,
            )
        self._assert_event(
            sink,
            event_type="delegation.verify",
            outcome="deny",
            reason_code="delegation_expired",
            artifact_version="wt-delegation/v0",
        )

    def test_no_sink_is_silent(self):
        signed = sign_receipt(self._root(), self.priv)
        verify_receipt(signed, parent=None, issuer_lookup=self.lookup, current=_NOW)

    def test_sink_failure_on_allow_fails_closed(self):
        signed = sign_receipt(self._root(), self.priv)
        with self.assertRaises(DelegationError) as ctx:
            verify_receipt(
                signed,
                parent=None,
                issuer_lookup=self.lookup,
                current=_NOW,
                audit_sink=BrokenSink(),
            )
        self.assertEqual(ctx.exception.reason, DenyReason.AUDIT_SINK_FAILURE)


class RetrievalAuditTests(_AuditPin):
    def _policy(self) -> AllowlistRetrievalPolicy:
        return AllowlistRetrievalPolicy(
            rules=(RetrievalRule(_B, "invoke_tool", DataClass.CONFIDENTIAL),)
        )

    def _data(self, data_class: DataClass = DataClass.INTERNAL):
        return classify(
            data_digest=_DIGEST,
            data_class=data_class,
            actor_iss=_A,
            actor_kid=_KID,
            now=_NOW,
        )

    def test_allow_emits_retrieval_verify(self):
        sink = InMemoryAuditSink()
        decision = self._policy().evaluate(
            caller_iss=_B,
            purpose_of_use="invoke_tool",
            data=self._data(),
            audit_sink=sink,
        )
        self.assertTrue(decision.allowed)
        ev = self._assert_event(
            sink,
            event_type="retrieval.verify",
            outcome="allow",
            reason_code="ok",
            artifact_version="wt-retrieval/v0",
        )
        self.assertEqual(ev.sender, _B)

    def test_deny_emits_retrieval_verify(self):
        sink = InMemoryAuditSink()
        decision = self._policy().evaluate(
            caller_iss=_B,
            purpose_of_use="invoke_tool",
            data=self._data(DataClass.RESTRICTED),
            audit_sink=sink,
        )
        self.assertFalse(decision.allowed)
        self._assert_event(
            sink,
            event_type="retrieval.verify",
            outcome="deny",
            reason_code="retrieval_class_exceeds_rule",
            artifact_version="wt-retrieval/v0",
        )

    def test_sink_failure_on_allow_returns_deny(self):
        decision = self._policy().evaluate(
            caller_iss=_B,
            purpose_of_use="invoke_tool",
            data=self._data(),
            audit_sink=BrokenSink(),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, DenyReason.AUDIT_SINK_FAILURE.value)


class EgressAuditTests(_AuditPin):
    def _policy(self) -> MatrixEgressPolicy:
        return MatrixEgressPolicy(
            cells=(
                EgressMatrixCell(
                    risk=RiskLevel.NONE,
                    data_class=DataClass.PUBLIC,
                    action=EgressAction.ALLOW,
                ),
            )
        )

    def test_allow_emits_egress_verify(self):
        sink = InMemoryAuditSink()
        decision = self._policy().evaluate(
            risk=RiskLevel.NONE, data_class=DataClass.PUBLIC, audit_sink=sink
        )
        self.assertEqual(decision.action, EgressAction.ALLOW)
        self._assert_event(
            sink,
            event_type="egress.verify",
            outcome="allow",
            reason_code="ok",
            artifact_version="wt-egress/v0",
        )

    def test_deny_emits_egress_verify(self):
        sink = InMemoryAuditSink()
        decision = self._policy().evaluate(
            risk=RiskLevel.HIGH, data_class=DataClass.PUBLIC, audit_sink=sink
        )
        self.assertEqual(decision.action, EgressAction.DENY)
        self._assert_event(
            sink,
            event_type="egress.verify",
            outcome="deny",
            reason_code="egress_no_matrix_entry",
            artifact_version="wt-egress/v0",
        )


class ReviewAuditTests(_AuditPin):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.reviewer = "spiffe://mesh.example/ns-review/reviewer-1"
        self.lookup = _lookup(self.pem, self.reviewer, "review-kid-1")
        self.record = QuarantineRecord(
            record_id="01900000-0000-7000-8000-000000000001",
            artifact_digest=_DIGEST,
            risk=RiskLevel.HIGH,
            data_class=DataClass.CONFIDENTIAL,
            requested_at="2026-04-14T12:00:00Z",
            requester_iss=_A,
            purpose_of_use="invoke_tool",
        )

    def _decision(self, **overrides) -> ReviewDecision:
        kwargs = dict(
            record_digest=self.record.record_digest,
            verdict=ReviewVerdict.RELEASE,
            reason="reviewed and approved",
            reviewer_iss=self.reviewer,
            reviewer_kid="review-kid-1",
            iat=_NOW_TS - 5,
            nbf=_NOW_TS,
            exp=_NOW_TS + 600,
            jti="01900000-0000-7000-8000-000000000002",
        )
        kwargs.update(overrides)
        return ReviewDecision(**kwargs)

    def test_allow_emits_review_verify(self):
        sink = InMemoryAuditSink()
        signed = sign_decision(self._decision(), self.priv)
        verify_decision(
            signed,
            record=self.record,
            issuer_lookup=self.lookup,
            current=_NOW,
            audit_sink=sink,
        )
        ev = self._assert_event(
            sink,
            event_type="review.verify",
            outcome="allow",
            reason_code="ok",
            artifact_version="wt-review/v0",
        )
        self.assertEqual(ev.sender, self.reviewer)
        self.assertEqual(ev.recipient, _A)

    def test_deny_emits_review_verify(self):
        sink = InMemoryAuditSink()
        signed = sign_decision(self._decision(), self.priv)
        with self.assertRaises(ReviewError):
            verify_decision(
                signed,
                record=self.record,
                issuer_lookup=self.lookup,
                current=_NOW + timedelta(hours=2),
                audit_sink=sink,
            )
        self._assert_event(
            sink,
            event_type="review.verify",
            outcome="deny",
            reason_code="review_expired",
            artifact_version="wt-review/v0",
        )

    def test_release_path_reject_emits_one_deny(self):
        sink = InMemoryAuditSink()
        signed = sign_decision(
            self._decision(verdict=ReviewVerdict.REJECT), self.priv
        )
        with self.assertRaises(ReviewError):
            verify_release_authorization(
                signed,
                record=self.record,
                issuer_lookup=self.lookup,
                current=_NOW,
                audit_sink=sink,
            )
        self._assert_event(
            sink,
            event_type="review.verify",
            outcome="deny",
            reason_code="review_rejected",
            artifact_version="wt-review/v0",
        )


class ToolGateAuditTests(_AuditPin):
    def test_allow_emits_tool_verify(self):
        sink = InMemoryAuditSink()
        policy = ToolPolicy(
            rules=(ToolRule(tool_name="read_file", risk_tier=RiskTier.LOW),)
        )
        call = ToolCall(tool_name="read_file", caller_iss=_A, arguments_digest=_DIGEST)
        decision = evaluate_tool_call(call=call, policy=policy, current=_NOW, audit_sink=sink)
        self.assertTrue(decision.allowed)
        self._assert_event(
            sink,
            event_type="tool.verify",
            outcome="allow",
            reason_code="ok",
            artifact_version="wt-tool-gate/v0",
        )

    def test_deny_emits_tool_verify(self):
        sink = InMemoryAuditSink()
        policy = ToolPolicy(
            rules=(ToolRule(tool_name="read_file", risk_tier=RiskTier.LOW),)
        )
        call = ToolCall(tool_name="exec_sql", caller_iss=_A, arguments_digest=_DIGEST)
        decision = evaluate_tool_call(call=call, policy=policy, current=_NOW, audit_sink=sink)
        self.assertFalse(decision.allowed)
        self._assert_event(
            sink,
            event_type="tool.verify",
            outcome="deny",
            reason_code="tool_unknown",
            artifact_version="wt-tool-gate/v0",
        )

    def test_step_up_path_still_emits_one_event(self):
        priv, pem = _keypair()
        sink = InMemoryAuditSink()
        policy = ToolPolicy(
            rules=(ToolRule(tool_name="exec_sql", risk_tier=RiskTier.CRITICAL),)
        )
        call = ToolCall(tool_name="exec_sql", caller_iss=_A, arguments_digest=_DIGEST)
        att = sign_step_up(
            StepUpAttestation(
                tool_name=call.tool_name,
                caller_iss=call.caller_iss,
                arguments_digest=call.arguments_digest,
                issuer_iss=_ISS,
                issuer_kid=_KID,
                iat=_NOW_TS - 5,
                nbf=_NOW_TS,
                exp=_NOW_TS + 300,
                jti="01900000-0000-7000-8000-000000000099",
            ),
            priv,
        )
        decision = evaluate_tool_call(
            call=call,
            policy=policy,
            step_up=att,
            issuer_lookup=_lookup(pem, _ISS, _KID),
            current=_NOW,
            audit_sink=sink,
        )
        self.assertTrue(decision.allowed)
        self._assert_event(
            sink,
            event_type="tool.verify",
            outcome="allow",
            reason_code="ok",
            artifact_version="wt-tool-gate/v0",
        )


class CheckpointAuditTests(_AuditPin):
    def _checkpoint(self) -> Checkpoint:
        return Checkpoint(
            checkpoint_id="01900000-0000-7000-8000-000000000002",
            task_id="01900000-0000-7000-8000-000000000001",
            step=1,
            requested_at="2026-04-14T12:00:00Z",
            intended_action="db_write:users",
        )

    def _capability(self, **overrides) -> CapabilityClaims:
        kwargs = dict(
            iss=_ISS,
            sub=_A,
            aud=_B,
            scope="invoke_tool",
            iat=_NOW_TS - 60,
            nbf=_NOW_TS - 60,
            exp=_NOW_TS + 300,
            jti="01900000-0000-7000-8000-000000000003",
            envelope_digest=_DIGEST,
            issuer_kid=_KID,
        )
        kwargs.update(overrides)
        return CapabilityClaims(**kwargs)

    def test_allow_emits_checkpoint_evaluate(self):
        sink = InMemoryAuditSink()
        decision = validate_checkpoint(
            checkpoint=self._checkpoint(),
            capability=self._capability(),
            active_epoch="epoch-1",
            policy=CheckpointPolicy(expected_epoch="epoch-1"),
            ledger=InMemoryRevocationLedger(),
            current=_NOW,
            audit_sink=sink,
        )
        self.assertEqual(decision.action, CheckpointAction.COMMIT)
        ev = self._assert_event(
            sink,
            event_type="checkpoint.evaluate",
            outcome="allow",
            reason_code="ok",
            artifact_version="wt-checkpoint/v0",
        )
        self.assertEqual(ev.sender, _A)
        self.assertEqual(ev.recipient, _B)

    def test_deny_emits_checkpoint_evaluate(self):
        sink = InMemoryAuditSink()
        cap = self._capability()
        ledger = InMemoryRevocationLedger()
        ledger.revoke(cap.jti, at=_NOW, reason="operator-initiated")
        decision = validate_checkpoint(
            checkpoint=self._checkpoint(),
            capability=cap,
            active_epoch="epoch-1",
            policy=CheckpointPolicy(expected_epoch="epoch-1"),
            ledger=ledger,
            current=_NOW,
            audit_sink=sink,
        )
        self.assertEqual(decision.action, CheckpointAction.ABORT)
        self._assert_event(
            sink,
            event_type="checkpoint.evaluate",
            outcome="deny",
            reason_code="checkpoint_capability_revoked",
            artifact_version="wt-checkpoint/v0",
        )


class SessionAuditTests(_AuditPin):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = _lookup(self.pem, _ISS, _KID)

    def _open(self, **overrides) -> SessionToken:
        kwargs = dict(
            session_id="01900000-0000-7000-8000-aaaaaaaaaaa1",
            seq=0,
            parent_jti="",
            iss=_ISS,
            iss_kid=_KID,
            sub=_A,
            aud=_B,
            scope="stream_response",
            iat=_NOW_TS - 5,
            nbf=_NOW_TS,
            exp=_NOW_TS + 60,
            jti="01900000-0000-7000-8000-aaaaaaaaaaa2",
        )
        kwargs.update(overrides)
        return SessionToken(**kwargs)

    def test_allow_emits_session_verify(self):
        sink = InMemoryAuditSink()
        signed = sign_session(self._open(), self.priv)
        verify_session_token(
            signed, issuer_lookup=self.lookup, current=_NOW, audit_sink=sink
        )
        ev = self._assert_event(
            sink,
            event_type="session.verify",
            outcome="allow",
            reason_code="ok",
            artifact_version="wt-session/v0",
        )
        self.assertEqual(ev.sender, _A)
        self.assertEqual(ev.recipient, _B)

    def test_deny_emits_session_verify(self):
        sink = InMemoryAuditSink()
        signed = sign_session(
            self._open(iat=_NOW_TS - 240, nbf=_NOW_TS - 240, exp=_NOW_TS - 120),
            self.priv,
        )
        with self.assertRaises(SessionError):
            verify_session_token(
                signed, issuer_lookup=self.lookup, current=_NOW, audit_sink=sink
            )
        self._assert_event(
            sink,
            event_type="session.verify",
            outcome="deny",
            reason_code="session_expired",
            artifact_version="wt-session/v0",
        )

    def test_resume_emits_one_event(self):
        sink = InMemoryAuditSink()
        opened = sign_session(self._open(), self.priv)
        resumed = sign_session(
            SessionToken(
                session_id=opened.session_id,
                seq=1,
                parent_jti=opened.jti,
                iss=opened.iss,
                iss_kid=opened.iss_kid,
                sub=opened.sub,
                aud=opened.aud,
                scope=opened.scope,
                iat=_NOW_TS,
                nbf=_NOW_TS,
                exp=_NOW_TS + 60,
                jti="01900000-0000-7000-8000-aaaaaaaaaaa3",
            ),
            self.priv,
        )
        verify_resume(
            resumed,
            previous=opened,
            session_opened_at=opened.iat,
            issuer_lookup=self.lookup,
            current=_NOW,
            audit_sink=sink,
        )
        self._assert_event(
            sink,
            event_type="session.verify",
            outcome="allow",
            reason_code="ok",
            artifact_version="wt-session/v0",
        )


class CoverageTests(unittest.TestCase):
    """One method the proof-obligation registry can point at.

    Asserts every leftover-named Phase 2 verifier has an allow pin and
    a deny pin in this module. Renaming a test class without updating
    this list fails CI.
    """

    def test_every_named_phase2_verifier_has_allow_and_deny_pins(self):
        expected = {
            "DelegationAuditTests": ("delegation.verify",),
            "RetrievalAuditTests": ("retrieval.verify",),
            "EgressAuditTests": ("egress.verify",),
            "ReviewAuditTests": ("review.verify",),
            "ToolGateAuditTests": ("tool.verify",),
            "CheckpointAuditTests": ("checkpoint.evaluate",),
            "SessionAuditTests": ("session.verify",),
        }
        g = globals()
        for class_name, event_types in expected.items():
            cls = g[class_name]
            methods = {name for name in dir(cls) if name.startswith("test_")}
            self.assertTrue(
                any("allow" in name for name in methods),
                f"{class_name} is missing an allow pin",
            )
            self.assertTrue(
                any("deny" in name for name in methods),
                f"{class_name} is missing a deny pin",
            )
            self.assertTrue(event_types)


if __name__ == "__main__":
    unittest.main()
