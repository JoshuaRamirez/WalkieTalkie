import json
import pathlib
import sys
import tempfile
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_private_key

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from issuer_trust_store import IssuerTrustStore
from verify_envelope import EnvelopeVerificationError


def _ed25519_pem() -> bytes:
    key = Ed25519PrivateKey.generate()
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _rsa_pem() -> bytes:
    key = generate_rsa_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _write_manifest(tmp_path: pathlib.Path, entries: list[dict]) -> pathlib.Path:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"keys": entries}))
    return manifest


class IssuerTrustStoreTests(unittest.TestCase):
    def test_manifest_lookup_returns_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            pem = _ed25519_pem()
            (tmp_path / "k.pem").write_bytes(pem)
            manifest = _write_manifest(
                tmp_path,
                [{"iss": "spiffe://mesh/issuer-1", "kid": "kid-1", "pem_path": "k.pem"}],
            )
            store = IssuerTrustStore.from_manifest(manifest)
            self.assertEqual(store("spiffe://mesh/issuer-1", "kid-1"), pem)

    def test_unknown_iss_kid_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "k.pem").write_bytes(_ed25519_pem())
            manifest = _write_manifest(
                tmp_path,
                [{"iss": "spiffe://mesh/issuer-1", "kid": "kid-1", "pem_path": "k.pem"}],
            )
            store = IssuerTrustStore.from_manifest(manifest)
            with self.assertRaisesRegex(EnvelopeVerificationError, "unknown issuer key"):
                store("spiffe://mesh/issuer-2", "kid-1")
            with self.assertRaisesRegex(EnvelopeVerificationError, "unknown issuer key"):
                store("spiffe://mesh/issuer-1", "kid-2")

    def test_manifest_rejects_missing_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "k.pem").write_bytes(_ed25519_pem())
            for omit in ("iss", "kid", "pem_path"):
                base = {"iss": "spiffe://mesh/i", "kid": "k", "pem_path": "k.pem"}
                base.pop(omit)
                manifest = _write_manifest(tmp_path, [base])
                with self.subTest(omit=omit):
                    with self.assertRaisesRegex(ValueError, f"missing field: {omit}"):
                        IssuerTrustStore.from_manifest(manifest)

    def test_manifest_rejects_unparseable_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "k.pem").write_bytes(b"not a pem")
            manifest = _write_manifest(
                tmp_path,
                [{"iss": "spiffe://mesh/i", "kid": "k", "pem_path": "k.pem"}],
            )
            with self.assertRaisesRegex(ValueError, "unparseable PEM"):
                IssuerTrustStore.from_manifest(manifest)

    def test_manifest_rejects_non_ed25519_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "k.pem").write_bytes(_rsa_pem())
            manifest = _write_manifest(
                tmp_path,
                [{"iss": "spiffe://mesh/i", "kid": "k", "pem_path": "k.pem"}],
            )
            with self.assertRaisesRegex(ValueError, "non-Ed25519 PEM"):
                IssuerTrustStore.from_manifest(manifest)

    def test_manifest_rejects_pem_path_escape(self):
        with tempfile.TemporaryDirectory() as outer:
            outer_path = pathlib.Path(outer)
            (outer_path / "sibling.pem").write_bytes(_ed25519_pem())
            inner = outer_path / "manifest_dir"
            inner.mkdir()
            manifest = _write_manifest(
                inner,
                [{"iss": "spiffe://mesh/i", "kid": "k", "pem_path": "../sibling.pem"}],
            )
            with self.assertRaisesRegex(ValueError, "escapes manifest directory"):
                IssuerTrustStore.from_manifest(manifest)

    def test_manifest_rejects_duplicate_iss_kid(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "a.pem").write_bytes(_ed25519_pem())
            (tmp_path / "b.pem").write_bytes(_ed25519_pem())
            manifest = _write_manifest(
                tmp_path,
                [
                    {"iss": "spiffe://mesh/i", "kid": "k", "pem_path": "a.pem"},
                    {"iss": "spiffe://mesh/i", "kid": "k", "pem_path": "b.pem"},
                ],
            )
            with self.assertRaisesRegex(ValueError, r"duplicate \(iss, kid\)"):
                IssuerTrustStore.from_manifest(manifest)

    def test_manifest_allows_iss_with_multiple_kids(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            pem_a = _ed25519_pem()
            pem_b = _ed25519_pem()
            (tmp_path / "a.pem").write_bytes(pem_a)
            (tmp_path / "b.pem").write_bytes(pem_b)
            manifest = _write_manifest(
                tmp_path,
                [
                    {"iss": "spiffe://mesh/i", "kid": "k-1", "pem_path": "a.pem"},
                    {"iss": "spiffe://mesh/i", "kid": "k-2", "pem_path": "b.pem"},
                ],
            )
            store = IssuerTrustStore.from_manifest(manifest)
            self.assertEqual(store("spiffe://mesh/i", "k-1"), pem_a)
            self.assertEqual(store("spiffe://mesh/i", "k-2"), pem_b)

    def test_manifest_rejects_invalid_not_after(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "k.pem").write_bytes(_ed25519_pem())
            manifest = _write_manifest(
                tmp_path,
                [
                    {
                        "iss": "spiffe://mesh/i",
                        "kid": "k",
                        "pem_path": "k.pem",
                        "not_after": "not-a-date",
                    }
                ],
            )
            with self.assertRaisesRegex(ValueError, "invalid not_after"):
                IssuerTrustStore.from_manifest(manifest)

    def test_expired_issuer_key_raises_at_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "k.pem").write_bytes(_ed25519_pem())
            past = (datetime.now(UTC) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
            manifest = _write_manifest(
                tmp_path,
                [
                    {
                        "iss": "spiffe://mesh/i",
                        "kid": "k",
                        "pem_path": "k.pem",
                        "not_after": past,
                    }
                ],
            )
            store = IssuerTrustStore.from_manifest(manifest)
            with self.assertRaisesRegex(EnvelopeVerificationError, "issuer key expired"):
                store("spiffe://mesh/i", "k")

    def test_manifest_rejects_invalid_iss_or_kid(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "k.pem").write_bytes(_ed25519_pem())
            bad_iss_manifest = _write_manifest(
                tmp_path,
                [{"iss": "not-spiffe", "kid": "k", "pem_path": "k.pem"}],
            )
            with self.assertRaisesRegex(ValueError, "invalid iss"):
                IssuerTrustStore.from_manifest(bad_iss_manifest)

            bad_kid_manifest = _write_manifest(
                tmp_path,
                [{"iss": "spiffe://mesh/i", "kid": "kid with space", "pem_path": "k.pem"}],
            )
            with self.assertRaisesRegex(ValueError, "invalid kid"):
                IssuerTrustStore.from_manifest(bad_kid_manifest)


if __name__ == "__main__":
    unittest.main()
