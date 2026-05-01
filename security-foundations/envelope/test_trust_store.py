import json
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key as generate_rsa_private_key

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from trust_store import FileSystemTrustStore
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


class FileSystemTrustStoreTests(unittest.TestCase):
    def test_directory_lookup_returns_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            pem = _ed25519_pem()
            (tmp_path / "kid-1.pem").write_bytes(pem)
            store = FileSystemTrustStore.from_directory(tmp_path)
            self.assertEqual(store("kid-1"), pem)

    def test_missing_kid_raises(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "kid-1.pem").write_bytes(_ed25519_pem())
            store = FileSystemTrustStore.from_directory(tmp_path)
            with self.assertRaises(EnvelopeVerificationError):
                store("missing-kid")

    def test_directory_rejects_unparseable_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "kid-1.pem").write_bytes(b"not a pem")
            with self.assertRaises(ValueError):
                FileSystemTrustStore.from_directory(tmp_path)

    def test_manifest_load_rejects_missing_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "kid-1.pem").write_bytes(_ed25519_pem())
            manifest = tmp_path / "manifest.json"
            manifest.write_text(json.dumps({"keys": [{"pem_path": "kid-1.pem"}]}))
            with self.assertRaisesRegex(ValueError, "missing field: kid"):
                FileSystemTrustStore.from_manifest(manifest)

    def test_manifest_load_rejects_unparseable_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "kid-1.pem").write_bytes(b"not a pem")
            manifest = tmp_path / "manifest.json"
            manifest.write_text(json.dumps({"keys": [{"kid": "kid-1", "pem_path": "kid-1.pem"}]}))
            with self.assertRaisesRegex(ValueError, "unparseable PEM"):
                FileSystemTrustStore.from_manifest(manifest)

    def test_manifest_load_rejects_duplicate_kid(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "kid-1.pem").write_bytes(_ed25519_pem())
            (tmp_path / "kid-1-copy.pem").write_bytes(_ed25519_pem())
            manifest = tmp_path / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "keys": [
                            {"kid": "kid-1", "pem_path": "kid-1.pem"},
                            {"kid": "kid-1", "pem_path": "kid-1-copy.pem"},
                        ]
                    }
                )
            )
            with self.assertRaisesRegex(ValueError, "duplicate kid"):
                FileSystemTrustStore.from_manifest(manifest)

    def test_directory_rejects_non_ed25519_pem(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "kid-1.pem").write_bytes(_rsa_pem())
            with self.assertRaisesRegex(ValueError, "non-Ed25519 PEM"):
                FileSystemTrustStore.from_directory(tmp_path)

    def test_manifest_rejects_pem_path_escape(self):
        with tempfile.TemporaryDirectory() as outer:
            outer_path = pathlib.Path(outer)
            sibling = outer_path / "sibling.pem"
            sibling.write_bytes(_ed25519_pem())
            inner = outer_path / "manifest_dir"
            inner.mkdir()
            manifest = inner / "manifest.json"
            manifest.write_text(
                json.dumps({"keys": [{"kid": "kid-1", "pem_path": "../sibling.pem"}]})
            )
            with self.assertRaisesRegex(ValueError, "escapes manifest directory"):
                FileSystemTrustStore.from_manifest(manifest)

    def test_manifest_rejects_invalid_not_after(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "kid-1.pem").write_bytes(_ed25519_pem())
            manifest = tmp_path / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {"keys": [{"kid": "kid-1", "pem_path": "kid-1.pem", "not_after": "not-a-date"}]}
                )
            )
            with self.assertRaisesRegex(ValueError, "invalid not_after"):
                FileSystemTrustStore.from_manifest(manifest)

    def test_expired_key_raises_at_lookup(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "kid-1.pem").write_bytes(_ed25519_pem())
            past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
            manifest = tmp_path / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {"keys": [{"kid": "kid-1", "pem_path": "kid-1.pem", "not_after": past}]}
                )
            )
            store = FileSystemTrustStore.from_manifest(manifest)
            with self.assertRaisesRegex(EnvelopeVerificationError, "key expired"):
                store("kid-1")


if __name__ == "__main__":
    unittest.main()
