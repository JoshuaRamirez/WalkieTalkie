"""Tests for signed policy bundles + anti-rollback (Phase 1 Track C C3)."""

import json
import pathlib
import sys
import tempfile
import unittest
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from policy_bundle import (
    FileBackedRollbackGuard,
    InMemoryRollbackGuard,
    PolicyBundle,
    PolicyBundleError,
    from_json,
    sign_bundle,
    to_json,
    verify_bundle,
)

_POLICY_ISS = "spiffe://mesh.example/policy-authority"
_POLICY_KID = "policy-kid-1"
_SUB = "spiffe://mesh.example/ns-a/svc"
_AUD = "spiffe://mesh.example/ns-b/svc"
_SCOPE = "invoke_tool"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def _bundle(version: int = 1, grants=None, max_ttl_seconds: int = 300) -> PolicyBundle:
    if grants is None:
        grants = ((_SUB, _AUD, _SCOPE),)
    return PolicyBundle(
        version=version,
        issuer_iss=_POLICY_ISS,
        issuer_kid=_POLICY_KID,
        allowlist_grants=grants,
        max_ttl_seconds=max_ttl_seconds,
    )


class SignAndVerifyTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()
        self.lookup = lambda iss, kid: self.pem

    def test_round_trip(self):
        signed = sign_bundle(_bundle(), self.priv)
        self.assertNotEqual(signed.signature, "")

        encoded = to_json(signed)
        decoded = from_json(encoded)
        self.assertEqual(decoded.signature, signed.signature)

        policy = verify_bundle(decoded, issuer_lookup=self.lookup)
        decision = policy.evaluate(
            sub=_SUB, aud=_AUD, scope=_SCOPE, ttl=timedelta(seconds=60)
        )
        self.assertTrue(decision.allowed)

    def test_unsigned_bundle_rejected(self):
        bundle = _bundle()  # no signature
        with self.assertRaisesRegex(PolicyBundleError, "unsigned"):
            verify_bundle(bundle, issuer_lookup=self.lookup)

    def test_tampered_grants_rejected(self):
        signed = sign_bundle(_bundle(), self.priv)
        # Mutate after signing — signature now covers a different body.
        tampered = PolicyBundle(
            version=signed.version,
            issuer_iss=signed.issuer_iss,
            issuer_kid=signed.issuer_kid,
            allowlist_grants=(("spiffe://mesh.example/ns-z/svc", _AUD, _SCOPE),),
            max_ttl_seconds=signed.max_ttl_seconds,
            signature=signed.signature,
        )
        with self.assertRaisesRegex(PolicyBundleError, "signature invalid"):
            verify_bundle(tampered, issuer_lookup=self.lookup)

    def test_unknown_issuer_rejected(self):
        signed = sign_bundle(_bundle(), self.priv)

        def lookup(iss, kid):
            raise Exception(f"unknown ({iss}, {kid})")

        with self.assertRaisesRegex(PolicyBundleError, "unknown policy issuer key"):
            verify_bundle(signed, issuer_lookup=lookup)

    def test_invalid_pem_rejected(self):
        signed = sign_bundle(_bundle(), self.priv)
        with self.assertRaisesRegex(PolicyBundleError, "invalid policy issuer public key"):
            verify_bundle(signed, issuer_lookup=lambda iss, kid: b"not a pem")

    def test_signed_with_unrelated_key_rejected(self):
        signed = sign_bundle(_bundle(), self.priv)
        _, other_pem = _keypair()
        with self.assertRaisesRegex(PolicyBundleError, "signature invalid"):
            verify_bundle(signed, issuer_lookup=lambda iss, kid: other_pem)


class BundleShapeTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()

    def test_zero_version_rejected(self):
        signed = sign_bundle(_bundle(version=0), self.priv)
        with self.assertRaisesRegex(PolicyBundleError, "version must be a positive integer"):
            verify_bundle(signed, issuer_lookup=lambda iss, kid: self.pem)

    def test_zero_max_ttl_rejected(self):
        signed = sign_bundle(_bundle(max_ttl_seconds=0), self.priv)
        with self.assertRaisesRegex(PolicyBundleError, "max_ttl_seconds"):
            verify_bundle(signed, issuer_lookup=lambda iss, kid: self.pem)

    def test_invalid_iss_rejected(self):
        bad = PolicyBundle(
            version=1,
            issuer_iss="not-a-spiffe-id",
            issuer_kid=_POLICY_KID,
            allowlist_grants=((_SUB, _AUD, _SCOPE),),
            max_ttl_seconds=300,
        )
        signed = sign_bundle(bad, self.priv)
        with self.assertRaisesRegex(PolicyBundleError, "issuer_iss"):
            verify_bundle(signed, issuer_lookup=lambda iss, kid: self.pem)

    def test_invalid_grant_sub_rejected(self):
        bad = _bundle(grants=(("not-spiffe", _AUD, _SCOPE),))
        signed = sign_bundle(bad, self.priv)
        with self.assertRaisesRegex(PolicyBundleError, r"grants\[0\]\.sub invalid"):
            verify_bundle(signed, issuer_lookup=lambda iss, kid: self.pem)


class JsonRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()

    def test_missing_required_field_rejected(self):
        signed = sign_bundle(_bundle(), self.priv)
        obj = json.loads(to_json(signed))
        del obj["max_ttl_seconds"]
        with self.assertRaisesRegex(PolicyBundleError, "missing required fields: max_ttl_seconds"):
            from_json(json.dumps(obj).encode())

    def test_non_json_rejected(self):
        with self.assertRaisesRegex(PolicyBundleError, "not valid JSON"):
            from_json(b"{not json")

    def test_non_object_rejected(self):
        with self.assertRaisesRegex(PolicyBundleError, "must be an object"):
            from_json(b'"a string"')

    def test_malformed_grants_rejected(self):
        signed = sign_bundle(_bundle(), self.priv)
        obj = json.loads(to_json(signed))
        obj["allowlist_grants"] = [["only", "two"]]
        with self.assertRaisesRegex(PolicyBundleError, "3-tuple of strings"):
            from_json(json.dumps(obj).encode())


class RollbackGuardTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _keypair()

    def test_in_memory_accepts_increasing_versions(self):
        guard = InMemoryRollbackGuard()
        guard.accept(_bundle(version=1))
        guard.accept(_bundle(version=2))
        guard.accept(_bundle(version=10))

    def test_in_memory_rejects_equal_version(self):
        guard = InMemoryRollbackGuard()
        guard.accept(_bundle(version=5))
        with self.assertRaisesRegex(PolicyBundleError, "rollback"):
            guard.accept(_bundle(version=5))

    def test_in_memory_rejects_lower_version(self):
        guard = InMemoryRollbackGuard()
        guard.accept(_bundle(version=5))
        with self.assertRaisesRegex(PolicyBundleError, "rollback"):
            guard.accept(_bundle(version=3))

    def test_per_issuer_isolation(self):
        guard = InMemoryRollbackGuard()
        guard.accept(_bundle(version=10))
        # Different issuer — same version sequence is fine.
        other = PolicyBundle(
            version=1,
            issuer_iss="spiffe://other-mesh.example/policy",
            issuer_kid=_POLICY_KID,
            allowlist_grants=((_SUB, _AUD, _SCOPE),),
            max_ttl_seconds=300,
        )
        guard.accept(other)

    def test_file_backed_persists_across_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "rollback.json"
            g1 = FileBackedRollbackGuard(path)
            g1.accept(_bundle(version=7))

            g2 = FileBackedRollbackGuard(path)
            with self.assertRaisesRegex(PolicyBundleError, "rollback"):
                g2.accept(_bundle(version=6))
            g2.accept(_bundle(version=8))

    def test_file_backed_corrupt_file_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "rollback.json"
            path.write_text("not json")
            guard = FileBackedRollbackGuard(path)
            with self.assertRaisesRegex(PolicyBundleError, "corrupt"):
                guard.accept(_bundle(version=1))


if __name__ == "__main__":
    unittest.main()
