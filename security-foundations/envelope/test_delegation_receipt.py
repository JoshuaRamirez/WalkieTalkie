"""Tests for delegation receipts (Phase 2 Track A A1 + A2)."""

import pathlib
import sys
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from delegation_receipt import (
    DEFAULT_DELEGATION_CONFIG,
    DelegationError,
    DelegationReceipt,
    DelegationVerificationConfig,
    ParentClaims,
    from_json,
    parent_from_capability_claims,
    parent_from_receipt,
    sign_receipt,
    to_json,
    verify_receipt,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_EPOCH = int(_NOW.timestamp())

_ROOT_DELEGATOR = "spiffe://mesh.example/cap-issuer"
_A = "spiffe://mesh.example/ns-a/svc"
_B = "spiffe://mesh.example/ns-b/svc"
_C = "spiffe://mesh.example/ns-c/svc"
_AUD = "spiffe://mesh.example/ns-x/svc"
_SCOPE = "invoke_tool"

_CHAIN_ID = "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c0"
_ROOT_JTI = "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1"
_HOP1_JTI = "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2"
_HOP2_JTI = "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c3"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def _root_receipt(*, delegator_kid: str = "delegator-kid-a") -> DelegationReceipt:
    return DelegationReceipt(
        chain_id=_CHAIN_ID,
        hop_index=0,
        parent_jti="",
        delegator_iss=_ROOT_DELEGATOR,
        delegator_kid=delegator_kid,
        delegate_iss=_A,
        scope=_SCOPE,
        aud=_AUD,
        iat=_NOW_EPOCH - 30,
        nbf=_NOW_EPOCH - 30,
        exp=_NOW_EPOCH + 240,
        jti=_ROOT_JTI,
    )


def _hop1_receipt() -> DelegationReceipt:
    return DelegationReceipt(
        chain_id=_CHAIN_ID,
        hop_index=1,
        parent_jti=_ROOT_JTI,
        delegator_iss=_A,
        delegator_kid="delegator-kid-a",
        delegate_iss=_B,
        scope=_SCOPE,
        aud=_AUD,
        iat=_NOW_EPOCH - 20,
        nbf=_NOW_EPOCH - 20,
        exp=_NOW_EPOCH + 200,
        jti=_HOP1_JTI,
    )


class RoundTripTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = lambda iss, kid: self.pem

    def test_root_round_trip(self):
        signed = sign_receipt(_root_receipt(), self.priv)
        decoded = from_json(to_json(signed))
        verified = verify_receipt(
            decoded,
            parent=None,
            issuer_lookup=self.lookup,
            current=_NOW,
        )
        self.assertEqual(verified.chain_id, _CHAIN_ID)
        self.assertEqual(verified.hop_index, 0)
        self.assertEqual(verified.delegate_iss, _A)

    def test_two_hop_chain_round_trip(self):
        root = sign_receipt(_root_receipt(), self.priv)
        hop1 = sign_receipt(_hop1_receipt(), self.priv)

        v0 = verify_receipt(root, parent=None, issuer_lookup=self.lookup, current=_NOW)
        v1 = verify_receipt(
            hop1,
            parent=parent_from_receipt(v0),
            issuer_lookup=self.lookup,
            current=_NOW,
        )
        self.assertEqual(v1.hop_index, 1)
        self.assertEqual(v1.delegate_iss, _B)

    def test_missing_required_field_at_parse(self):
        signed = sign_receipt(_root_receipt(), self.priv)
        encoded = to_json(signed)
        import json as _json

        obj = _json.loads(encoded)
        del obj["exp"]
        with self.assertRaisesRegex(DelegationError, "missing required fields: exp"):
            from_json(_json.dumps(obj).encode())


class ShapeValidationTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = lambda iss, kid: self.pem

    def test_root_with_parent_jti_rejected(self):
        bad = sign_receipt(replace(_root_receipt(), parent_jti=_HOP1_JTI), self.priv)
        with self.assertRaisesRegex(DelegationError, "root hop .* empty parent_jti"):
            verify_receipt(bad, parent=None, issuer_lookup=self.lookup, current=_NOW)

    def test_non_root_with_empty_parent_jti_rejected(self):
        bad = sign_receipt(replace(_hop1_receipt(), parent_jti=""), self.priv)
        with self.assertRaisesRegex(DelegationError, "non-root hop"):
            verify_receipt(
                bad,
                parent=parent_from_receipt(sign_receipt(_root_receipt(), self.priv)),
                issuer_lookup=self.lookup,
                current=_NOW,
            )

    def test_invalid_chain_id_rejected(self):
        bad = sign_receipt(replace(_root_receipt(), chain_id="not-uuid"), self.priv)
        with self.assertRaisesRegex(DelegationError, "chain_id"):
            verify_receipt(bad, parent=None, issuer_lookup=self.lookup, current=_NOW)

    def test_negative_hop_index_rejected(self):
        bad = sign_receipt(replace(_root_receipt(), hop_index=-1), self.priv)
        with self.assertRaisesRegex(DelegationError, "hop_index"):
            verify_receipt(bad, parent=None, issuer_lookup=self.lookup, current=_NOW)


class NonEscalationTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = lambda iss, kid: self.pem
        root = sign_receipt(_root_receipt(), self.priv)
        self.root_parent = parent_from_receipt(
            verify_receipt(root, parent=None, issuer_lookup=self.lookup, current=_NOW)
        )

    def test_depth_limit_enforced(self):
        # hop_index=3 with max_chain_depth=3 → exceeds.
        deep = sign_receipt(
            replace(_hop1_receipt(), hop_index=3, parent_jti=_HOP2_JTI),
            self.priv,
        )
        deep_parent = ParentClaims(
            jti=_HOP2_JTI, sub=_A, aud=_AUD, scope=_SCOPE,
            iat=_NOW_EPOCH - 25, exp=_NOW_EPOCH + 220, hop_index=2,
        )
        with self.assertRaisesRegex(DelegationError, "max_chain_depth"):
            verify_receipt(
                deep,
                parent=deep_parent,
                issuer_lookup=self.lookup,
                current=_NOW,
            )

    def test_parent_jti_mismatch_rejected(self):
        bad = sign_receipt(
            replace(_hop1_receipt(), parent_jti=_HOP2_JTI),
            self.priv,
        )
        with self.assertRaisesRegex(DelegationError, "parent_jti"):
            verify_receipt(
                bad,
                parent=self.root_parent,
                issuer_lookup=self.lookup,
                current=_NOW,
            )

    def test_hop_index_not_parent_plus_one_rejected(self):
        bad = sign_receipt(
            replace(_hop1_receipt(), hop_index=2),
            self.priv,
        )
        with self.assertRaisesRegex(DelegationError, "hop_index"):
            verify_receipt(
                bad,
                parent=self.root_parent,
                issuer_lookup=self.lookup,
                current=_NOW,
            )

    def test_delegator_must_be_parent_subject(self):
        # parent.sub = _A, but the child claims to delegate from _C.
        bad = sign_receipt(
            replace(_hop1_receipt(), delegator_iss=_C),
            self.priv,
        )
        with self.assertRaisesRegex(DelegationError, "delegator_iss"):
            verify_receipt(
                bad,
                parent=self.root_parent,
                issuer_lookup=self.lookup,
                current=_NOW,
            )

    def test_scope_widening_rejected(self):
        # Different scope = "different action". v0 forbids any divergence.
        bad = sign_receipt(
            replace(_hop1_receipt(), scope="invoke_admin_tool"),
            self.priv,
        )
        with self.assertRaisesRegex(DelegationError, "scope"):
            verify_receipt(
                bad,
                parent=self.root_parent,
                issuer_lookup=self.lookup,
                current=_NOW,
            )

    def test_scope_narrowing_also_rejected_in_v0(self):
        # Strict v0: even narrowing is rejected. Documented out-of-scope.
        bad = sign_receipt(
            replace(_hop1_receipt(), scope="invoke_tool:read_only"),
            self.priv,
        )
        with self.assertRaisesRegex(DelegationError, "scope"):
            verify_receipt(
                bad,
                parent=self.root_parent,
                issuer_lookup=self.lookup,
                current=_NOW,
            )

    def test_audience_drift_rejected(self):
        bad = sign_receipt(
            replace(_hop1_receipt(), aud="spiffe://mesh.example/ns-z/other"),
            self.priv,
        )
        with self.assertRaisesRegex(DelegationError, "aud"):
            verify_receipt(
                bad,
                parent=self.root_parent,
                issuer_lookup=self.lookup,
                current=_NOW,
            )

    def test_ttl_extending_past_parent_rejected(self):
        # Child exp > parent.exp.
        bad = sign_receipt(
            replace(_hop1_receipt(), exp=_NOW_EPOCH + 9999),
            self.priv,
        )
        with self.assertRaisesRegex(DelegationError, "validity window"):
            verify_receipt(
                bad,
                parent=self.root_parent,
                issuer_lookup=self.lookup,
                current=_NOW,
            )

    def test_iat_before_parent_iat_rejected(self):
        bad = sign_receipt(
            replace(_hop1_receipt(), iat=_NOW_EPOCH - 9999, nbf=_NOW_EPOCH - 9999),
            self.priv,
        )
        with self.assertRaisesRegex(DelegationError, "validity window"):
            verify_receipt(
                bad,
                parent=self.root_parent,
                issuer_lookup=self.lookup,
                current=_NOW,
            )


class TimeWindowTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = lambda iss, kid: self.pem

    def test_expired_receipt_rejected(self):
        signed = sign_receipt(_root_receipt(), self.priv)
        with self.assertRaisesRegex(DelegationError, "expired"):
            verify_receipt(
                signed,
                parent=None,
                issuer_lookup=self.lookup,
                current=_NOW + timedelta(hours=1),
            )

    def test_not_yet_valid_rejected(self):
        signed = sign_receipt(
            replace(_root_receipt(), iat=_NOW_EPOCH + 9999, nbf=_NOW_EPOCH + 9999, exp=_NOW_EPOCH + 10000),
            self.priv,
        )
        with self.assertRaisesRegex(DelegationError, "future"):
            verify_receipt(signed, parent=None, issuer_lookup=self.lookup, current=_NOW)

    def test_ttl_above_max_rejected(self):
        # Default max_receipt_ttl is 5 minutes; this is 10.
        signed = sign_receipt(
            replace(_root_receipt(), exp=_NOW_EPOCH + 600 - 30),
            self.priv,
        )
        tight = DelegationVerificationConfig(
            max_clock_skew=DEFAULT_DELEGATION_CONFIG.max_clock_skew,
            max_receipt_ttl=timedelta(minutes=5),
        )
        with self.assertRaisesRegex(DelegationError, "ttl exceeds"):
            verify_receipt(
                signed, parent=None, issuer_lookup=self.lookup, current=_NOW, config=tight
            )


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()

    def test_unsigned_rejected(self):
        with self.assertRaisesRegex(DelegationError, "unsigned"):
            verify_receipt(
                _root_receipt(),
                parent=None,
                issuer_lookup=lambda iss, kid: self.pem,
                current=_NOW,
            )

    def test_unrelated_key_rejected(self):
        _, other_pem = _keypair()
        signed = sign_receipt(_root_receipt(), self.priv)
        with self.assertRaisesRegex(DelegationError, "signature invalid"):
            verify_receipt(
                signed,
                parent=None,
                issuer_lookup=lambda iss, kid: other_pem,
                current=_NOW,
            )

    def test_unknown_issuer_rejected(self):
        signed = sign_receipt(_root_receipt(), self.priv)

        def lookup(iss, kid):
            raise Exception("nope")

        with self.assertRaisesRegex(DelegationError, "unknown delegation issuer key"):
            verify_receipt(
                signed, parent=None, issuer_lookup=lookup, current=_NOW
            )

    def test_tampered_scope_rejected(self):
        signed = sign_receipt(_root_receipt(), self.priv)
        tampered = replace(signed, scope="invoke_admin_tool")
        with self.assertRaisesRegex(DelegationError, "signature invalid"):
            verify_receipt(
                tampered,
                parent=None,
                issuer_lookup=lambda iss, kid: self.pem,
                current=_NOW,
            )


class CapabilityClaimsBridgeTests(unittest.TestCase):
    def test_parent_from_capability_claims(self):
        # A delegation chain MAY originate from a cap token rather than
        # another receipt. parent_from_capability_claims projects the cap
        # claim set into the ParentClaims shape.
        priv, pem = _keypair()
        from capability_token import CapabilityClaims

        cap = CapabilityClaims(
            iss=_ROOT_DELEGATOR,
            sub=_A,
            aud=_AUD,
            scope=_SCOPE,
            iat=_NOW_EPOCH - 30,
            nbf=_NOW_EPOCH - 30,
            exp=_NOW_EPOCH + 240,
            jti=_ROOT_JTI,
            envelope_digest="0" * 64,
            issuer_kid="cap-issuer-kid-1",
        )
        parent = parent_from_capability_claims(cap)
        self.assertEqual(parent.sub, _A)
        self.assertEqual(parent.scope, _SCOPE)
        self.assertEqual(parent.jti, _ROOT_JTI)

        # Use it as the parent for hop_index=1, even though the cap claim
        # set didn't carry a hop_index (we treat -1 as "originating cap").
        signed = sign_receipt(_hop1_receipt(), priv)
        verify_receipt(
            signed,
            parent=parent,
            issuer_lookup=lambda iss, kid: pem,
            current=_NOW,
        )


if __name__ == "__main__":
    unittest.main()
