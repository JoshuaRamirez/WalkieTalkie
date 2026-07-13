"""Tests for image signature attestation (Phase 5 Track D D5.6)."""

import hashlib
import pathlib
import sys
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from deny_reason import DenyReason
from image_attestation import (
    ImageSignature,
    ImageSignatureError,
    from_json,
    sign_image_signature,
    to_json,
    verify_image_signature,
)

_SIGNER = "spiffe://mesh.example/ci/release-signer"
_KID = "release-key-1"
_DIGEST = hashlib.sha256(b"reference-image-layer").hexdigest()
_OTHER_DIGEST = hashlib.sha256(b"a-different-image").hexdigest()


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pub_pem


def _lookup_for(pub_pem: bytes):
    def _lookup(signer_id: str, kid: str) -> bytes:
        if signer_id == _SIGNER and kid == _KID:
            return pub_pem
        raise KeyError(f"no key for {signer_id}/{kid}")

    return _lookup


def _signed(priv, *, digest: str = _DIGEST) -> ImageSignature:
    return sign_image_signature(
        ImageSignature(image_digest=digest, signer_id=_SIGNER, signer_kid=_KID),
        priv,
    )


class HappyPathTests(unittest.TestCase):
    def test_valid_signature_verifies(self):
        priv, pub = _keypair()
        sig = _signed(priv)
        got = verify_image_signature(
            sig, expected_digest=_DIGEST, issuer_lookup=_lookup_for(pub)
        )
        self.assertEqual(got, sig)

    def test_json_round_trip(self):
        priv, pub = _keypair()
        sig = _signed(priv)
        restored = from_json(to_json(sig))
        self.assertEqual(restored, sig)
        verify_image_signature(
            restored, expected_digest=_DIGEST, issuer_lookup=_lookup_for(pub)
        )


class DenialTests(unittest.TestCase):
    def test_wrong_key_rejected_as_invalid(self):
        priv, _ = _keypair()
        _, other_pub = _keypair()
        sig = _signed(priv)
        with self.assertRaises(ImageSignatureError) as ctx:
            verify_image_signature(
                sig, expected_digest=_DIGEST, issuer_lookup=_lookup_for(other_pub)
            )
        self.assertEqual(ctx.exception.reason, DenyReason.IMAGE_SIG_INVALID)

    def test_digest_mismatch_rejected(self):
        priv, pub = _keypair()
        sig = _signed(priv)
        with self.assertRaises(ImageSignatureError) as ctx:
            verify_image_signature(
                sig, expected_digest=_OTHER_DIGEST, issuer_lookup=_lookup_for(pub)
            )
        self.assertEqual(ctx.exception.reason, DenyReason.IMAGE_SIG_DIGEST_MISMATCH)

    def test_unknown_signer_rejected(self):
        priv, pub = _keypair()
        sig = replace(_signed(priv), signer_kid="not-a-known-kid")
        # Re-sign so the signature is internally valid; the trust store just
        # has no key for this kid.
        sig = sign_image_signature(
            ImageSignature(
                image_digest=_DIGEST, signer_id=_SIGNER, signer_kid="not-a-known-kid"
            ),
            priv,
        )
        with self.assertRaises(ImageSignatureError) as ctx:
            verify_image_signature(
                sig, expected_digest=_DIGEST, issuer_lookup=_lookup_for(pub)
            )
        self.assertEqual(ctx.exception.reason, DenyReason.IMAGE_SIG_UNKNOWN_SIGNER)

    def test_tampered_digest_breaks_signature(self):
        priv, pub = _keypair()
        sig = _signed(priv)
        # Swap the digest after signing; both the caller's expected_digest and
        # the record now say _OTHER_DIGEST, so it passes the match but the
        # signature (over _DIGEST) no longer validates.
        tampered = replace(sig, image_digest=_OTHER_DIGEST)
        with self.assertRaises(ImageSignatureError) as ctx:
            verify_image_signature(
                tampered, expected_digest=_OTHER_DIGEST, issuer_lookup=_lookup_for(pub)
            )
        self.assertEqual(ctx.exception.reason, DenyReason.IMAGE_SIG_INVALID)

    def test_malformed_digest_rejected(self):
        priv, pub = _keypair()
        sig = replace(_signed(priv), image_digest="not-hex")
        with self.assertRaises(ImageSignatureError) as ctx:
            verify_image_signature(
                sig, expected_digest=_DIGEST, issuer_lookup=_lookup_for(pub)
            )
        self.assertEqual(ctx.exception.reason, DenyReason.IMAGE_SIG_MALFORMED)

    def test_malformed_signer_id_rejected(self):
        priv, pub = _keypair()
        sig = replace(_signed(priv), signer_id="not-a-spiffe-id")
        with self.assertRaises(ImageSignatureError) as ctx:
            verify_image_signature(
                sig, expected_digest=_DIGEST, issuer_lookup=_lookup_for(pub)
            )
        self.assertEqual(ctx.exception.reason, DenyReason.IMAGE_SIG_MALFORMED)

    def test_unsigned_rejected(self):
        sig = ImageSignature(image_digest=_DIGEST, signer_id=_SIGNER, signer_kid=_KID)
        _, pub = _keypair()
        with self.assertRaises(ImageSignatureError) as ctx:
            verify_image_signature(
                sig, expected_digest=_DIGEST, issuer_lookup=_lookup_for(pub)
            )
        self.assertEqual(ctx.exception.reason, DenyReason.IMAGE_SIG_MALFORMED)

    def test_bad_expected_digest_rejected(self):
        priv, pub = _keypair()
        sig = _signed(priv)
        with self.assertRaises(ImageSignatureError) as ctx:
            verify_image_signature(
                sig, expected_digest="not-hex", issuer_lookup=_lookup_for(pub)
            )
        self.assertEqual(ctx.exception.reason, DenyReason.IMAGE_SIG_MALFORMED)

    def test_from_json_missing_field_rejected(self):
        with self.assertRaises(ImageSignatureError) as ctx:
            from_json(b'{"image_digest":"' + _DIGEST.encode() + b'"}')
        self.assertEqual(ctx.exception.reason, DenyReason.IMAGE_SIG_MALFORMED)


if __name__ == "__main__":
    unittest.main()
