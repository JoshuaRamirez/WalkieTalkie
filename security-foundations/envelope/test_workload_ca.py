"""Tests for the workload CA (Phase 5 Track A A1)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from workload_ca import (
    WorkloadCA,
    WorkloadCAError,
    svid_spiffe_id,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_TRUST_DOMAIN = "mesh.example"
_SPIFFE = "spiffe://mesh.example/ns-a/agent-1"


def _ca() -> WorkloadCA:
    return WorkloadCA(trust_domain=_TRUST_DOMAIN, root_key=Ed25519PrivateKey.generate())


class CAConstructionTests(unittest.TestCase):
    def test_empty_trust_domain_rejected(self):
        with self.assertRaisesRegex(WorkloadCAError, "trust_domain"):
            WorkloadCA(trust_domain="", root_key=Ed25519PrivateKey.generate())

    def test_bad_trust_domain_rejected(self):
        with self.assertRaisesRegex(WorkloadCAError, "SPIFFE authority"):
            WorkloadCA(
                trust_domain="not a domain",
                root_key=Ed25519PrivateKey.generate(),
            )

    def test_non_ed25519_root_rejected(self):
        with self.assertRaisesRegex(WorkloadCAError, "root_key"):
            WorkloadCA(trust_domain=_TRUST_DOMAIN, root_key="not-a-key")  # type: ignore[arg-type]

    def test_root_cert_is_self_signed_ca(self):
        ca = _ca()
        root = ca.root_cert
        self.assertEqual(root.subject, root.issuer)
        bc = root.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(bc.value.ca)

    def test_root_cert_is_cached(self):
        ca = _ca()
        self.assertIs(ca.root_cert, ca.root_cert)


class IssuanceTests(unittest.TestCase):
    def test_issue_binds_spiffe_id_in_san(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        cert = ca.issue_svid(
            spiffe_id=_SPIFFE, public_key=leaf_key.public_key(), now=_NOW
        )
        self.assertEqual(svid_spiffe_id(cert), _SPIFFE)

    def test_issued_cert_carries_workload_public_key(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        cert = ca.issue_svid(
            spiffe_id=_SPIFFE, public_key=leaf_key.public_key(), now=_NOW
        )
        self.assertEqual(
            cert.public_key().public_bytes_raw(),
            leaf_key.public_key().public_bytes_raw(),
        )

    def test_issued_cert_signed_by_root(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        cert = ca.issue_svid(
            spiffe_id=_SPIFFE, public_key=leaf_key.public_key(), now=_NOW
        )
        # The root public key verifies the leaf signature — raises on
        # failure.
        ca.root_key.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes
        )

    def test_ttl_sets_validity_window(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        cert = ca.issue_svid(
            spiffe_id=_SPIFFE,
            public_key=leaf_key.public_key(),
            now=_NOW,
            ttl=timedelta(minutes=30),
        )
        self.assertEqual(cert.not_valid_before_utc, _NOW)
        self.assertEqual(cert.not_valid_after_utc, _NOW + timedelta(minutes=30))

    def test_default_ttl_is_short(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        cert = ca.issue_svid(
            spiffe_id=_SPIFFE, public_key=leaf_key.public_key(), now=_NOW
        )
        window = cert.not_valid_after_utc - cert.not_valid_before_utc
        self.assertLessEqual(window, timedelta(hours=1))

    def test_deterministic_serial(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        cert = ca.issue_svid(
            spiffe_id=_SPIFFE,
            public_key=leaf_key.public_key(),
            now=_NOW,
            serial_number=42,
        )
        self.assertEqual(cert.serial_number, 42)

    def test_cross_domain_issuance_rejected(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(WorkloadCAError, "outside CA trust domain"):
            ca.issue_svid(
                spiffe_id="spiffe://other-mesh.example/ns-x/svc",
                public_key=leaf_key.public_key(),
                now=_NOW,
            )

    def test_invalid_spiffe_id_rejected(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(WorkloadCAError, "invalid spiffe_id"):
            ca.issue_svid(
                spiffe_id="not-spiffe",
                public_key=leaf_key.public_key(),
                now=_NOW,
            )

    def test_naive_now_rejected(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(WorkloadCAError, "timezone-aware"):
            ca.issue_svid(
                spiffe_id=_SPIFFE,
                public_key=leaf_key.public_key(),
                now=datetime(2026, 4, 14, 12),
            )

    def test_zero_ttl_rejected(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(WorkloadCAError, "ttl"):
            ca.issue_svid(
                spiffe_id=_SPIFFE,
                public_key=leaf_key.public_key(),
                now=_NOW,
                ttl=timedelta(0),
            )


class SvidSpiffeIdTests(unittest.TestCase):
    def test_extracts_id(self):
        ca = _ca()
        leaf_key = Ed25519PrivateKey.generate()
        cert = ca.issue_svid(
            spiffe_id=_SPIFFE, public_key=leaf_key.public_key(), now=_NOW
        )
        self.assertEqual(svid_spiffe_id(cert), _SPIFFE)

    def test_no_san_rejected(self):
        # The self-signed root has no SAN.
        ca = _ca()
        with self.assertRaisesRegex(WorkloadCAError, "SubjectAlternativeName"):
            svid_spiffe_id(ca.root_cert)


if __name__ == "__main__":
    unittest.main()
