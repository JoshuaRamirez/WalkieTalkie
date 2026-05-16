"""Tests for bootstrap artifact validation (Phase 1 Track A A1)."""

import json
import pathlib
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from bootstrap_bundle import (
    BootstrapAnchor,
    BootstrapBundle,
    BootstrapBundleError,
    encode_anchor_pem,
    from_json,
    read_bundle,
    sign_bundle,
    to_json,
    verify_bundle,
    write_bundle,
)
from verify_envelope import EnvelopeVerificationError

_TRUST_DOMAIN = "mesh.example"
_ANCHOR_ISS = "spiffe://mesh.example/cap-issuer-1"
_ANCHOR_KID = "issuer-kid-1"


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def _bundle(*, anchors=None, version=1, epoch=1, trust_domain=_TRUST_DOMAIN) -> BootstrapBundle:
    if anchors is None:
        _, anchor_pem = _keypair()
        anchors = (
            BootstrapAnchor(
                iss=_ANCHOR_ISS, kid=_ANCHOR_KID, pem_b64=encode_anchor_pem(anchor_pem)
            ),
        )
    return BootstrapBundle(
        version=version,
        trust_domain=trust_domain,
        epoch=epoch,
        anchors=anchors,
    )


class SignAndVerifyTests(unittest.TestCase):
    def setUp(self):
        self.root_priv, self.root_pem = _keypair()

    def test_round_trip_returns_issuer_trust_store(self):
        anchor_priv, anchor_pem = _keypair()
        b = _bundle(
            anchors=(
                BootstrapAnchor(
                    iss=_ANCHOR_ISS, kid=_ANCHOR_KID, pem_b64=encode_anchor_pem(anchor_pem)
                ),
            )
        )
        signed = sign_bundle(b, self.root_priv)
        encoded = to_json(signed)
        decoded = from_json(encoded)

        store = verify_bundle(decoded, expected_root_pem=self.root_pem)
        self.assertEqual(store(_ANCHOR_ISS, _ANCHOR_KID), anchor_pem)

    def test_trust_domain_pin_matches(self):
        signed = sign_bundle(_bundle(), self.root_priv)
        verify_bundle(
            signed,
            expected_root_pem=self.root_pem,
            expected_trust_domain=_TRUST_DOMAIN,
        )

    def test_trust_domain_pin_mismatch_rejected(self):
        signed = sign_bundle(_bundle(), self.root_priv)
        with self.assertRaisesRegex(BootstrapBundleError, "trust_domain mismatch"):
            verify_bundle(
                signed,
                expected_root_pem=self.root_pem,
                expected_trust_domain="other-mesh.example",
            )

    def test_unsigned_bundle_rejected(self):
        with self.assertRaisesRegex(BootstrapBundleError, "unsigned"):
            verify_bundle(_bundle(), expected_root_pem=self.root_pem)

    def test_tampered_epoch_rejected(self):
        signed = sign_bundle(_bundle(epoch=5), self.root_priv)
        tampered = BootstrapBundle(
            version=signed.version,
            trust_domain=signed.trust_domain,
            epoch=4,  # rolled back
            anchors=signed.anchors,
            signature=signed.signature,
        )
        with self.assertRaisesRegex(BootstrapBundleError, "signature invalid"):
            verify_bundle(tampered, expected_root_pem=self.root_pem)

    def test_signed_with_unrelated_root_rejected(self):
        signed = sign_bundle(_bundle(), self.root_priv)
        _, other_pem = _keypair()
        with self.assertRaisesRegex(BootstrapBundleError, "signature invalid"):
            verify_bundle(signed, expected_root_pem=other_pem)

    def test_invalid_root_pem_rejected(self):
        signed = sign_bundle(_bundle(), self.root_priv)
        with self.assertRaisesRegex(BootstrapBundleError, "invalid root public key"):
            verify_bundle(signed, expected_root_pem=b"not a pem")


class ShapeValidationTests(unittest.TestCase):
    def setUp(self):
        self.root_priv, self.root_pem = _keypair()

    def test_zero_version_rejected(self):
        signed = sign_bundle(_bundle(version=0), self.root_priv)
        with self.assertRaisesRegex(BootstrapBundleError, "version"):
            verify_bundle(signed, expected_root_pem=self.root_pem)

    def test_zero_epoch_rejected(self):
        signed = sign_bundle(_bundle(epoch=0), self.root_priv)
        with self.assertRaisesRegex(BootstrapBundleError, "epoch"):
            verify_bundle(signed, expected_root_pem=self.root_pem)

    def test_invalid_trust_domain_rejected(self):
        signed = sign_bundle(_bundle(trust_domain="mesh with space"), self.root_priv)
        with self.assertRaisesRegex(BootstrapBundleError, "trust_domain"):
            verify_bundle(signed, expected_root_pem=self.root_pem)

    def test_empty_anchors_rejected(self):
        signed = sign_bundle(_bundle(anchors=()), self.root_priv)
        with self.assertRaisesRegex(BootstrapBundleError, "anchors must be non-empty"):
            verify_bundle(signed, expected_root_pem=self.root_pem)

    def test_duplicate_anchor_rejected(self):
        _, pem = _keypair()
        anchors = (
            BootstrapAnchor(iss=_ANCHOR_ISS, kid=_ANCHOR_KID, pem_b64=encode_anchor_pem(pem)),
            BootstrapAnchor(iss=_ANCHOR_ISS, kid=_ANCHOR_KID, pem_b64=encode_anchor_pem(pem)),
        )
        signed = sign_bundle(_bundle(anchors=anchors), self.root_priv)
        with self.assertRaisesRegex(BootstrapBundleError, "duplicate"):
            verify_bundle(signed, expected_root_pem=self.root_pem)

    def test_non_ed25519_anchor_rejected(self):
        signed = sign_bundle(
            _bundle(anchors=(
                BootstrapAnchor(
                    iss=_ANCHOR_ISS, kid=_ANCHOR_KID, pem_b64=encode_anchor_pem(b"not a pem"),
                ),
            )),
            self.root_priv,
        )
        with self.assertRaisesRegex(BootstrapBundleError, "valid Ed25519"):
            verify_bundle(signed, expected_root_pem=self.root_pem)


class JsonRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.root_priv, self.root_pem = _keypair()

    def test_missing_required_field(self):
        signed = sign_bundle(_bundle(), self.root_priv)
        obj = json.loads(to_json(signed))
        del obj["epoch"]
        with self.assertRaisesRegex(BootstrapBundleError, "missing required fields: epoch"):
            from_json(json.dumps(obj).encode())

    def test_non_json(self):
        with self.assertRaisesRegex(BootstrapBundleError, "not valid JSON"):
            from_json(b"{not json")

    def test_anchor_missing_field(self):
        signed = sign_bundle(_bundle(), self.root_priv)
        obj = json.loads(to_json(signed))
        del obj["anchors"][0]["pem_b64"]
        with self.assertRaisesRegex(BootstrapBundleError, "pem_b64"):
            from_json(json.dumps(obj).encode())


class FileIoTests(unittest.TestCase):
    def test_write_and_read_round_trip(self):
        priv, root_pem = _keypair()
        signed = sign_bundle(_bundle(), priv)
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "bundle.json"
            write_bundle(signed, path)
            reloaded = read_bundle(path)
            store = verify_bundle(reloaded, expected_root_pem=root_pem)
            # Lookup should succeed.
            store(_ANCHOR_ISS, _ANCHOR_KID)


class IssuerTrustStoreInteropTests(unittest.TestCase):
    """The materialized store SHOULD behave like a manifest-loaded one."""

    def test_unknown_kid_raises_envelope_verification_error(self):
        priv, root_pem = _keypair()
        signed = sign_bundle(_bundle(), priv)
        store = verify_bundle(signed, expected_root_pem=root_pem)
        with self.assertRaises(EnvelopeVerificationError):
            store("spiffe://mesh.example/unknown", "kid")


if __name__ == "__main__":
    unittest.main()
