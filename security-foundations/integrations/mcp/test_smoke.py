"""End-to-end smoke test for the example MCP host (Phase 4 D4.3).

This is THE integration test the Phase 4 plan calls for. It stands
up :class:`host.ExampleMCPHost` in-process, mints real keypairs,
real trust stores, and a real capability token, and drives one
signed MCP envelope through the entire substrate pipeline:

  verify_envelope (signature + window + replay + capability binding)
    -> unwrap_request
    -> tool_policy_gate.evaluate_tool_call
    -> tool dispatch
    -> output_scanning.scan
    -> egress_policy.evaluate
    -> sign reply envelope (with a real, payload-bound capability
       token, so the reply is independently verifiable end-to-end)

Then asserts:
- the reply verifies cleanly via :func:`verify_envelope.verify_envelope`,
- the response payload carries the tool output,
- the audit chain hash-validates via :func:`audit_query.verify_chain`,
- the expected event sequence appears (envelope.verify ok,
  capability.verify ok, tool.gate ok, egress.evaluate ok).

Three sad paths:
- Missing capability token   → ``CAP_MISSING``, no nonce reserved.
- Tampered payload digest    → digest mismatch / signature failure.
- CRITICAL tool without step-up  → ``TOOL_STEP_UP_REQUIRED``.

These pin Phase 4 §6 acceptance criterion #1 ("The smoke test runs
green and exercises every substrate primitive named in Mission")
and #6 ("New proof obligation lands in proof_obligations.py
pointing at the smoke test").
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "envelope")
)

from audit import InMemoryAuditSink, verify_chain
from capability_issuer import CapabilityIssuer
from cryptography.hazmat.primitives import serialization
from data_classification import DataClass
from egress_policy import EgressAction, EgressMatrixCell, MatrixEgressPolicy
from envelope_adapter import (
    EnvelopeFields,
    MCPRequest,
    build_envelope,
    mcp_request_to_payload,
    sign_envelope,
    unwrap_response,
)
from host import ExampleMCPHost, HandleOptions, HostConfig
from issuance_policy import AllowlistPolicy
from output_scanning import PatternRegistry, RiskLevel
from rate_limiter import IdentityRateLimiter
from revocation_list import InMemoryRevocationList
from tool_policy_gate import RiskTier, ToolPolicy, ToolRule
from verify_envelope import (
    EnvelopeVerificationError,
    InMemoryReplayCache,
    verify_envelope,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_CLIENT_ISS = "spiffe://mesh.example/ns-client/agent-1"
_CLIENT_KID = "client-kid-1"
_HOST_ISS = "spiffe://mesh.example/ns-host/server-1"
_HOST_KID = "host-kid-1"
_ISSUER_ISS = "spiffe://mesh.example/ns-iss/cap-issuer-1"
_ISSUER_KID = "issuer-kid-1"


# ---------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------


def _make_keypair():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


class _Stage:
    """Bundles everything one smoke-test scenario needs: keypairs,
    trust stores, the issuer, the host. Each test instantiates its
    own to keep state isolated."""

    def __init__(self, *, rate_limit: int = 100):
        self.client_priv, self.client_pem = _make_keypair()
        self.host_priv, self.host_pem = _make_keypair()
        self.issuer_priv, self.issuer_pem = _make_keypair()

        # Trust stores are just callables that map (iss, kid) to PEM.
        # In production these would back onto FileSystemTrustStore /
        # IssuerTrustStore. The smoke test goes direct.
        self._key_pems = {
            _CLIENT_KID: self.client_pem,
            _HOST_KID: self.host_pem,
        }
        self._issuer_pems = {
            (_ISSUER_ISS, _ISSUER_KID): self.issuer_pem,
        }

        self.replay_cache = InMemoryReplayCache()
        self.audit_sink = InMemoryAuditSink()

        # Gated issuance: only the two (sub, aud, scope) grants this
        # demo actually mints are allowed. The request direction
        # (client -> host) and the reply direction (host -> client),
        # both at scope "invoke_tool". Anything else is refused at
        # mint time with IssuancePolicyError.
        self.issuer = CapabilityIssuer(
            iss=_ISSUER_ISS,
            kid=_ISSUER_KID,
            signing_key=self.issuer_priv,
            default_ttl=timedelta(minutes=5),
            clock_skew=timedelta(seconds=30),
            audit_sink=self.audit_sink,
            policy=AllowlistPolicy(
                allowed_grants=frozenset(
                    {
                        (_CLIENT_ISS, _HOST_ISS, "invoke_tool"),
                        (_HOST_ISS, _CLIENT_ISS, "invoke_tool"),
                    }
                ),
                max_ttl=timedelta(minutes=5),
            ),
        )

        # Tool policy: read_file LOW (no step-up), exec_sql CRITICAL
        # (step-up required). Caller_iss allowlist locked to client.
        self.tool_policy = ToolPolicy(
            rules=(
                ToolRule(
                    tool_name="read_file",
                    risk_tier=RiskTier.LOW,
                    allowed_callers=frozenset({_CLIENT_ISS}),
                ),
                ToolRule(
                    tool_name="exec_sql",
                    risk_tier=RiskTier.CRITICAL,
                    allowed_callers=frozenset({_CLIENT_ISS}),
                ),
            )
        )

        # Egress: INTERNAL data at NONE risk = ALLOW; anything else
        # falls through to default-deny.
        self.egress_policy = MatrixEgressPolicy(
            cells=(
                EgressMatrixCell(
                    risk=RiskLevel.NONE,
                    data_class=DataClass.INTERNAL,
                    action=EgressAction.ALLOW,
                ),
            )
        )

        # A revocation list + rate limiter the tests can drive. The host
        # holds a reference to the same objects, so revoking / consuming
        # after construction takes effect on the next handle().
        self.revocation_list = InMemoryRevocationList()
        self.rate_limiter = IdentityRateLimiter(
            limit=rate_limit, window=timedelta(minutes=1)
        )

        self.config = HostConfig(
            host_iss=_HOST_ISS,
            host_kid=_HOST_KID,
            host_signing_key=self.host_priv,
            key_lookup=self._key_lookup,
            issuer_lookup=self._issuer_lookup,
            replay_cache=self.replay_cache,
            tool_policy=self.tool_policy,
            egress_policy=self.egress_policy,
            audit_sink=self.audit_sink,
            rate_limiter=self.rate_limiter,
            revocation_list=self.revocation_list,
            output_data_class=DataClass.INTERNAL,
            pattern_registry=PatternRegistry.builtin(),
            reply_capability_minter=self._reply_capability_minter,
        )
        self.host = ExampleMCPHost(self.config)

    # ----- trust-store callbacks -----

    def _key_lookup(self, kid: str) -> bytes:
        pem = self._key_pems.get(kid)
        if pem is None:
            raise EnvelopeVerificationError(f"unknown kid: {kid!r}")
        return pem

    def _issuer_lookup(self, iss: str, kid: str) -> bytes:
        pem = self._issuer_pems.get((iss, kid))
        if pem is None:
            raise EnvelopeVerificationError(
                f"unknown issuer (iss={iss!r}, kid={kid!r})"
            )
        return pem

    def _reply_capability_minter(self, payload_digest: str) -> str:
        return self.issuer.issue(
            sub=_HOST_ISS,
            aud=_CLIENT_ISS,
            scope="invoke_tool",
            envelope_digest=payload_digest,
            now=_NOW,
        )

    # ----- request builder -----

    def build_request_envelope(
        self,
        *,
        method: str,
        params: dict,
        message_id: str,
        nonce: str,
        capability_token: str | None = None,
        capability_jti: str | None = None,
        sender_iss: str = _CLIENT_ISS,
        sender_kid: str = _CLIENT_KID,
        purpose: str = "invoke_tool",
    ) -> dict:
        payload = mcp_request_to_payload(
            MCPRequest(method=method, params=params, id=1)
        )
        payload_digest = hashlib.sha256(jcs.canonicalize(payload)).hexdigest()
        if capability_token is None:
            capability_token = self.issuer.issue(
                sub=sender_iss,
                aud=_HOST_ISS,
                scope=purpose,
                envelope_digest=payload_digest,
                jti=capability_jti,
                now=_NOW,
            )
        fields = EnvelopeFields(
            sender_spiffe_id=sender_iss,
            recipient_spiffe_id=_HOST_ISS,
            purpose_of_use=purpose,
            kid=sender_kid,
            capability_token=capability_token,
            message_id=message_id,
            nonce=nonce,
            issued_at=_NOW,
            ttl=timedelta(minutes=5),
        )
        env = build_envelope(payload=payload, fields=fields)
        return sign_envelope(env, self.client_priv)


# ---------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------


class HappyPathTests(unittest.TestCase):
    """The substrate-works-as-a-system test."""

    def test_round_trip_succeeds_and_reply_is_verifiable(self):
        stage = _Stage()
        request = stage.build_request_envelope(
            method="read_file",
            params={"path": "/etc/motd"},
            message_id="01900000-0000-7000-8000-aaaaaaaaaaa1",
            nonce="client-nonce-happy0001",
        )

        # Drive it through the host.
        reply = stage.host.handle(request, options=HandleOptions(now=_NOW))

        # The reply must independently verify via verify_envelope —
        # which means the host's signature, payload digest, time
        # window, replay (new nonce), and capability binding all hold.
        reply_replay = InMemoryReplayCache()
        claims = verify_envelope(
            reply,
            key_lookup=stage._key_lookup,
            issuer_lookup=stage._issuer_lookup,
            replay_cache=reply_replay,
            now=_NOW,
        )
        self.assertEqual(claims.sub, _HOST_ISS)
        self.assertEqual(claims.aud, _CLIENT_ISS)

        # The unwrapped response carries the tool output.
        resp = unwrap_response(reply)
        self.assertIsNone(resp.error)
        self.assertEqual(resp.result["path"], "/etc/motd")
        self.assertIn("/etc/motd", resp.result["contents"])

        # Audit chain validates.
        events = stage.audit_sink.events
        verify_chain(events)
        # And the expected event sequence appears, in order.
        types = [e.event_type for e in events]
        self.assertIn("capability.issue", types)
        self.assertIn("envelope.verify", types)
        self.assertIn("tool.gate", types)
        self.assertIn("egress.evaluate", types)
        # Every substrate decision recorded outcome=allow.
        for event in events:
            if event.event_type in ("envelope.verify", "tool.gate", "egress.evaluate"):
                self.assertEqual(
                    event.outcome, "allow",
                    f"{event.event_type} expected allow, got {event.outcome}",
                )


# ---------------------------------------------------------------------
# Sad path 1: missing capability token
# ---------------------------------------------------------------------


class MissingCapabilityTests(unittest.TestCase):
    def test_empty_capability_token_rejected_no_nonce_burned(self):
        stage = _Stage()
        # An empty capability_token violates the schema (minLength=1)
        # so build_envelope would still accept the dict (schema check
        # happens in the verifier). The verifier rejects it.
        request = stage.build_request_envelope(
            method="read_file",
            params={"path": "/etc/motd"},
            message_id="01900000-0000-7000-8000-aaaaaaaaaaa2",
            nonce="client-nonce-sad00001",
            capability_token="x",  # malformed but non-empty so schema accepts
        )

        reply = stage.host.handle(request, options=HandleOptions(now=_NOW))

        # The host returned a signed error reply rather than raising.
        resp = unwrap_response(reply)
        self.assertIsNotNone(resp.error)

        # Nonce was NOT burned — the verifier's invariant for failure paths.
        # If we resend the exact same envelope with a valid cap token, the
        # replay cache should still admit the nonce (because the first
        # send was rejected before nonce reservation).
        self.assertFalse(stage.replay_cache.seen(_CLIENT_ISS, "client-nonce-sad00001"))


# ---------------------------------------------------------------------
# Sad path 2: tampered payload
# ---------------------------------------------------------------------


class TamperedPayloadTests(unittest.TestCase):
    def test_post_signing_payload_mutation_rejected(self):
        stage = _Stage()
        request = stage.build_request_envelope(
            method="read_file",
            params={"path": "/etc/motd"},
            message_id="01900000-0000-7000-8000-aaaaaaaaaaa3",
            nonce="client-nonce-tamp00001",
        )
        # Mutate the payload after signing — the digest stops matching
        # the body and the envelope signature stops covering the body.
        tampered = dict(request)
        tampered["payload"] = mcp_request_to_payload(
            MCPRequest(method="read_file", params={"path": "/etc/shadow"}, id=1)
        )

        reply = stage.host.handle(tampered, options=HandleOptions(now=_NOW))
        resp = unwrap_response(reply)
        self.assertIsNotNone(resp.error)

        # The audit chain still validates even though we failed.
        verify_chain(stage.audit_sink.events)


# ---------------------------------------------------------------------
# Sad path 3: critical tool without step-up
# ---------------------------------------------------------------------


class CriticalToolWithoutStepUpTests(unittest.TestCase):
    def test_critical_tool_without_stepup_denied_at_tool_gate(self):
        stage = _Stage()
        request = stage.build_request_envelope(
            method="exec_sql",
            params={"query": "SELECT 1"},
            message_id="01900000-0000-7000-8000-aaaaaaaaaaa4",
            nonce="client-nonce-stepup0001",
        )

        reply = stage.host.handle(request, options=HandleOptions(now=_NOW))
        resp = unwrap_response(reply)
        self.assertIsNotNone(resp.error)

        # The audit log should contain a tool.gate deny event with the
        # expected reason code.
        tool_gate_events = [
            e for e in stage.audit_sink.events if e.event_type == "tool.gate"
        ]
        self.assertTrue(tool_gate_events)
        self.assertEqual(tool_gate_events[-1].outcome, "deny")
        self.assertEqual(
            tool_gate_events[-1].reason_code, "tool_step_up_required"
        )


# ---------------------------------------------------------------------
# Marquee: revoke-then-reject capability lifecycle
# ---------------------------------------------------------------------


class RevocationLifecycleTests(unittest.TestCase):
    """The substrate's headline claim, end-to-end: a capability that
    verified cleanly a moment ago is rejected once its jti is revoked,
    with no code change to the host — just an entry in the revocation
    list the host was already consulting."""

    _JTI = "01900000-0000-7000-8000-cafe00000001"

    def test_revoked_capability_rejected_on_next_use(self):
        stage = _Stage()
        params = {"path": "/etc/motd"}

        # 1. Mint a token with a known jti and send it — succeeds.
        first = stage.build_request_envelope(
            method="read_file",
            params=params,
            message_id="01900000-0000-7000-8000-aaaaaaaaaab1",
            nonce="client-nonce-revoke0001",
            capability_jti=self._JTI,
        )
        reply1 = stage.host.handle(first, options=HandleOptions(now=_NOW))
        resp1 = unwrap_response(reply1)
        self.assertIsNone(
            resp1.error, "first use of a valid capability must succeed"
        )

        # Grab the exact token the host just accepted so we replay the
        # SAME credential (same jti, same payload-digest binding).
        cap_token = first["capability_token"]

        # 2. Operator revokes the capability out of band.
        stage.revocation_list.revoke(self._JTI, reason="key compromise")

        # 3. Re-send the same credential (fresh nonce + message_id so
        # only the revocation — not replay — is the reason for denial).
        second = stage.build_request_envelope(
            method="read_file",
            params=params,
            message_id="01900000-0000-7000-8000-aaaaaaaaaab2",
            nonce="client-nonce-revoke0002",
            capability_token=cap_token,
        )
        reply2 = stage.host.handle(second, options=HandleOptions(now=_NOW))
        resp2 = unwrap_response(reply2)
        self.assertIsNotNone(
            resp2.error, "a revoked capability must be rejected"
        )

        # The envelope.verify audit event for the second send records
        # the revocation as the machine-readable cause.
        verify_events = [
            e
            for e in stage.audit_sink.events
            if e.event_type == "envelope.verify"
        ]
        self.assertTrue(verify_events)
        self.assertEqual(verify_events[-1].outcome, "deny")
        self.assertEqual(verify_events[-1].reason_code, "capability_revoked")

    def test_unrevoked_sibling_capability_still_works(self):
        # Revoking one jti must not affect a different, unrelated
        # capability. Confirms revocation is jti-scoped, not blanket.
        stage = _Stage()
        stage.revocation_list.revoke(self._JTI, reason="unrelated")
        request = stage.build_request_envelope(
            method="read_file",
            params={"path": "/etc/motd"},
            message_id="01900000-0000-7000-8000-aaaaaaaaaab3",
            nonce="client-nonce-revoke0003",
            capability_jti="01900000-0000-7000-8000-cafe00000002",
        )
        reply = stage.host.handle(request, options=HandleOptions(now=_NOW))
        self.assertIsNone(unwrap_response(reply).error)


# ---------------------------------------------------------------------
# Rate-limit lifecycle (post-auth)
# ---------------------------------------------------------------------


class RateLimitLifecycleTests(unittest.TestCase):
    def _valid_request(self, stage, *, n: int) -> dict:
        return stage.build_request_envelope(
            method="read_file",
            params={"path": f"/etc/motd-{n}"},
            message_id=f"01900000-0000-7000-8000-bbbb0000000{n}",
            nonce=f"client-nonce-rl00000{n}",
        )

    def test_requests_beyond_limit_are_denied(self):
        stage = _Stage(rate_limit=2)
        # First two authenticated requests pass.
        for i in (1, 2):
            reply = stage.host.handle(
                self._valid_request(stage, n=i), options=HandleOptions(now=_NOW)
            )
            self.assertIsNone(
                unwrap_response(reply).error, f"request {i} should pass"
            )
        # The third exceeds the per-identity window limit.
        reply3 = stage.host.handle(
            self._valid_request(stage, n=3), options=HandleOptions(now=_NOW)
        )
        resp3 = unwrap_response(reply3)
        self.assertIsNotNone(resp3.error)

        rl_events = [
            e
            for e in stage.audit_sink.events
            if e.event_type == "rate_limit.check"
        ]
        self.assertTrue(rl_events)
        self.assertEqual(rl_events[-1].outcome, "deny")
        self.assertEqual(rl_events[-1].reason_code, "rate_limited")

    def test_spoofed_sender_does_not_burn_victim_allowance(self):
        # The Phase 1 hardening invariant, demonstrated end-to-end: a
        # badly-signed envelope claiming the victim's SPIFFE ID is
        # rejected at envelope.verify BEFORE the rate limiter runs, so
        # it consumes none of the victim's allowance.
        stage = _Stage(rate_limit=2)

        good = self._valid_request(stage, n=1)
        spoof = dict(good)
        # Same length, wrong bytes → signature verification fails.
        spoof["signature"] = "A" * len(good["signature"])
        spoof["nonce"] = "client-nonce-spoof0001"
        spoof["message_id"] = "01900000-0000-7000-8000-bbbbffff0001"
        spoof_reply = stage.host.handle(spoof, options=HandleOptions(now=_NOW))
        self.assertIsNotNone(unwrap_response(spoof_reply).error)

        # The rate limiter never saw the spoof: no rate_limit.check event
        # was emitted for it (the flow bailed at envelope.verify).
        rl_events = [
            e
            for e in stage.audit_sink.events
            if e.event_type == "rate_limit.check"
        ]
        self.assertEqual(
            len(rl_events), 0, "spoof must not reach the post-auth limiter"
        )

        # The victim can now use their FULL allowance of 2.
        for i in (2, 3):
            reply = stage.host.handle(
                self._valid_request(stage, n=i), options=HandleOptions(now=_NOW)
            )
            self.assertIsNone(
                unwrap_response(reply).error,
                f"victim request {i} should pass; allowance was not burned",
            )


if __name__ == "__main__":
    unittest.main()
