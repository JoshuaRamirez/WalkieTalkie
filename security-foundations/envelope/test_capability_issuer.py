import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from capability_issuer import CapabilityIssuer, generate_uuidv7
from capability_token import verify_capability_token
from verify_envelope import UUID_V7_RE, EnvelopeVerificationError

_ISS = "spiffe://mesh/cap-issuer-1"
_KID = "issuer-kid-1"
_SUB = "spiffe://mesh/ns-a/service-a"
_AUD = "spiffe://mesh/ns-b/service-b"
_PURPOSE = "invoke_tool"
_DIGEST = "94fabd33a2221b6d3986e8d5ba98d75a91dcdad9b978ac7ea70bbc996fb2bb45"


def _make_issuer(**overrides) -> tuple[CapabilityIssuer, bytes]:
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kwargs: dict = {"iss": _ISS, "kid": _KID, "signing_key": priv}
    kwargs.update(overrides)
    return CapabilityIssuer(**kwargs), pem


class GenerateUuidv7Tests(unittest.TestCase):
    def test_matches_uuidv7_regex(self):
        for _ in range(50):
            jti = generate_uuidv7()
            self.assertRegex(jti, UUID_V7_RE)

    def test_deterministic_with_explicit_inputs(self):
        when = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        rand = b"\x00" * 10
        jti = generate_uuidv7(now=when, rand_bytes=rand)
        self.assertRegex(jti, UUID_V7_RE)
        # Same inputs → same UUID.
        self.assertEqual(jti, generate_uuidv7(now=when, rand_bytes=rand))

    def test_rejects_wrong_rand_length(self):
        with self.assertRaisesRegex(ValueError, "10 bytes"):
            generate_uuidv7(rand_bytes=b"\x00" * 9)


class CapabilityIssuerConstructionTests(unittest.TestCase):
    def test_invalid_iss_rejected_at_construction(self):
        priv = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ValueError, "invalid iss"):
            CapabilityIssuer(iss="not-spiffe", kid=_KID, signing_key=priv)

    def test_invalid_kid_rejected_at_construction(self):
        priv = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ValueError, "invalid kid"):
            CapabilityIssuer(iss=_ISS, kid="kid with space", signing_key=priv)

    def test_zero_default_ttl_rejected(self):
        priv = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ValueError, "default_ttl"):
            CapabilityIssuer(
                iss=_ISS, kid=_KID, signing_key=priv, default_ttl=timedelta(0)
            )

    def test_negative_clock_skew_rejected(self):
        priv = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ValueError, "clock_skew"):
            CapabilityIssuer(
                iss=_ISS, kid=_KID, signing_key=priv, clock_skew=timedelta(seconds=-1)
            )


class CapabilityIssuerIssueTests(unittest.TestCase):
    def test_round_trip_through_validator(self):
        issuer, pem = _make_issuer()
        now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        token = issuer.issue(
            sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST, now=now
        )
        envelope = {
            "sender_spiffe_id": _SUB,
            "recipient_spiffe_id": _AUD,
            "purpose_of_use": _PURPOSE,
            "payload_digest": _DIGEST,
        }

        def _lookup(iss, kid):
            if (iss, kid) != (_ISS, _KID):
                raise EnvelopeVerificationError("unknown")
            return pem

        claims = verify_capability_token(
            token,
            envelope=envelope,
            issuer_lookup=_lookup,
            current=now,
            max_clock_skew=timedelta(seconds=60),
            max_capability_ttl=timedelta(minutes=5),
        )
        self.assertEqual(claims.iss, _ISS)
        self.assertEqual(claims.issuer_kid, _KID)
        self.assertEqual(claims.scope, _PURPOSE)

    def test_default_ttl_used_when_no_ttl_passed(self):
        issuer, _ = _make_issuer(default_ttl=timedelta(minutes=2))
        now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        token = issuer.issue(
            sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST, now=now
        )
        # Decode payload to check exp - nbf == 2 minutes.
        import base64
        import json
        _, p, _ = token.split(".")
        padded = p + ("=" * ((4 - len(p) % 4) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded))
        self.assertEqual(payload["exp"] - payload["nbf"], 120)

    def test_explicit_ttl_overrides_default(self):
        issuer, _ = _make_issuer(default_ttl=timedelta(minutes=2))
        now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        token = issuer.issue(
            sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST,
            ttl=timedelta(seconds=45), now=now,
        )
        import base64
        import json
        _, p, _ = token.split(".")
        padded = p + ("=" * ((4 - len(p) % 4) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded))
        self.assertEqual(payload["exp"] - payload["nbf"], 45)

    def test_clock_skew_backdates_iat(self):
        issuer, _ = _make_issuer(clock_skew=timedelta(seconds=30))
        now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        token = issuer.issue(
            sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST, now=now
        )
        import base64
        import json
        _, p, _ = token.split(".")
        padded = p + ("=" * ((4 - len(p) % 4) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded))
        self.assertEqual(int(now.timestamp()) - payload["iat"], 30)

    def test_explicit_jti_preserved(self):
        issuer, _ = _make_issuer()
        now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        explicit_jti = generate_uuidv7(now=now, rand_bytes=b"\x42" * 10)
        token = issuer.issue(
            sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST,
            jti=explicit_jti, now=now,
        )
        import base64
        import json
        _, p, _ = token.split(".")
        padded = p + ("=" * ((4 - len(p) % 4) % 4))
        payload = json.loads(base64.urlsafe_b64decode(padded))
        self.assertEqual(payload["jti"], explicit_jti)

    def test_invalid_jti_rejected(self):
        issuer, _ = _make_issuer()
        with self.assertRaisesRegex(ValueError, "invalid jti"):
            issuer.issue(
                sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST,
                jti="not-a-uuid",
            )

    def test_invalid_sub_rejected(self):
        issuer, _ = _make_issuer()
        with self.assertRaisesRegex(ValueError, "invalid sub"):
            issuer.issue(
                sub="not-spiffe", aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST
            )

    def test_invalid_envelope_digest_rejected(self):
        issuer, _ = _make_issuer()
        with self.assertRaisesRegex(ValueError, "invalid envelope_digest"):
            issuer.issue(sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest="not-hex")

    def test_zero_ttl_rejected(self):
        issuer, _ = _make_issuer()
        with self.assertRaisesRegex(ValueError, "ttl must be positive"):
            issuer.issue(
                sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST,
                ttl=timedelta(0),
            )


class CapabilityIssuerPolicyTests(unittest.TestCase):
    """Phase 1 Track C C1 acceptance — policy gates issuance, denials are
    fail-closed, and the issuance audit event reflects each decision.
    """

    def test_default_allow_all_policy_preserves_behavior(self):
        # No policy passed → AllowAllPolicy default → existing test path works.
        issuer, _ = _make_issuer()
        token = issuer.issue(
            sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST
        )
        self.assertEqual(len(token.split(".")), 3)

    def test_allowlist_policy_permits_listed_grant(self):
        from issuance_policy import AllowlistPolicy

        issuer, _ = _make_issuer(
            policy=AllowlistPolicy(
                allowed_grants=frozenset({(_SUB, _AUD, _PURPOSE)}),
            )
        )
        token = issuer.issue(
            sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST
        )
        self.assertEqual(len(token.split(".")), 3)

    def test_allowlist_policy_denies_unlisted_grant(self):
        from issuance_policy import AllowlistPolicy, IssuancePolicyError

        issuer, _ = _make_issuer(
            policy=AllowlistPolicy(
                allowed_grants=frozenset({(_SUB, _AUD, _PURPOSE)}),
            )
        )
        with self.assertRaises(IssuancePolicyError) as ctx:
            issuer.issue(
                sub=_SUB,
                aud=_AUD,
                scope="different_scope",
                envelope_digest=_DIGEST,
            )
        self.assertFalse(ctx.exception.decision.allowed)
        self.assertIn("not in allowlist", ctx.exception.decision.reason)

    def test_allowlist_policy_denies_ttl_above_cap(self):
        from datetime import timedelta as _td

        from issuance_policy import AllowlistPolicy, IssuancePolicyError

        issuer, _ = _make_issuer(
            policy=AllowlistPolicy(
                allowed_grants=frozenset({(_SUB, _AUD, _PURPOSE)}),
                max_ttl=_td(minutes=2),
            )
        )
        with self.assertRaisesRegex(IssuancePolicyError, "exceeds policy max"):
            issuer.issue(
                sub=_SUB,
                aud=_AUD,
                scope=_PURPOSE,
                envelope_digest=_DIGEST,
                ttl=_td(minutes=10),
            )

    def test_audit_sink_records_issue_allow_event(self):
        import sys as _sys
        from pathlib import Path as _P

        _sys.path.insert(0, str(_P(__file__).resolve().parent))
        from audit import InMemoryAuditSink

        sink = InMemoryAuditSink()
        issuer, _ = _make_issuer(audit_sink=sink)
        issuer.issue(
            sub=_SUB, aud=_AUD, scope=_PURPOSE, envelope_digest=_DIGEST
        )
        self.assertEqual(len(sink.events), 1)
        ev = sink.events[0]
        self.assertEqual(ev.event_type, "capability.issue")
        self.assertEqual(ev.outcome, "allow")
        self.assertEqual(ev.reason_code, "ok")
        self.assertEqual(ev.artifact_version, "wt-cap+jwt")
        self.assertEqual(ev.sender, _SUB)
        self.assertEqual(ev.recipient, _AUD)
        self.assertEqual(ev.issuer_iss, _ISS)
        self.assertEqual(ev.issuer_kid, _KID)

    def test_audit_sink_records_issue_deny_event_on_policy_failure(self):
        from audit import InMemoryAuditSink
        from issuance_policy import AllowlistPolicy, IssuancePolicyError

        sink = InMemoryAuditSink()
        issuer, _ = _make_issuer(
            policy=AllowlistPolicy(
                allowed_grants=frozenset({(_SUB, _AUD, _PURPOSE)}),
            ),
            audit_sink=sink,
        )
        with self.assertRaises(IssuancePolicyError):
            issuer.issue(
                sub=_SUB,
                aud=_AUD,
                scope="different_scope",
                envelope_digest=_DIGEST,
            )
        self.assertEqual(len(sink.events), 1)
        ev = sink.events[0]
        self.assertEqual(ev.event_type, "capability.issue")
        self.assertEqual(ev.outcome, "deny")
        self.assertEqual(ev.reason_code, "issuance_policy_denied")
        self.assertIn("not in allowlist", ev.reason)


if __name__ == "__main__":
    unittest.main()
