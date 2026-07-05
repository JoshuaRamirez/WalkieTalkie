"""Tests for SVID verification (Phase 5 Track A A2)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from workload_ca import (
    SvidVerificationError,
    WorkloadCA,
    verify_svid,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_TRUST_DOMAIN = "mesh.example"
_SPIFFE = "spiffe://mesh.example/ns-a/agent-1"


def _ca() -> WorkloadCA:
    return WorkloadCA(trust_domain=_TRUST_DOMAIN, root_key=Ed25519PrivateKey.generate())


def _issue(ca: WorkloadCA, *, spiffe=_SPIFFE, now=_NOW, ttl=timedelta(hours=1)):
    leaf = Ed25519PrivateKey.generate()
    return ca.issue_svid(
        spiffe_id=spiffe, public_key=leaf.public_key(), now=now, ttl=ttl
    )


class HappyPathTests(unittest.TestCase):
    def test_valid_svid_verifies_and_returns_id(self):
        ca = _ca()
        cert = _issue(ca)
        result = verify_svid(cert, root_cert=ca.root_cert, current=_NOW)
        self.assertEqual(result, _SPIFFE)

    def test_binding_check_passes_when_expected_matches(self):
        ca = _ca()
        cert = _issue(ca)
        result = verify_svid(
            cert,
            root_cert=ca.root_cert,
            current=_NOW,
            expected_spiffe_id=_SPIFFE,
        )
        self.assertEqual(result, _SPIFFE)

    def test_valid_mid_window(self):
        ca = _ca()
        cert = _issue(ca, ttl=timedelta(hours=2))
        # 30 min in — still valid.
        verify_svid(cert, root_cert=ca.root_cert, current=_NOW + timedelta(minutes=30))


class SignatureTests(unittest.TestCase):
    def test_wrong_root_distinct_name_rejected_as_untrusted(self):
        # A root with a DIFFERENT subject name than the SVID's issuer
        # is caught by the issuer/subject check before signature math.
        ca = _ca()
        cert = _issue(ca)
        other_ca = WorkloadCA(
            trust_domain=_TRUST_DOMAIN,
            root_key=Ed25519PrivateKey.generate(),
            common_name="a-different-ca",
        )
        with self.assertRaises(SvidVerificationError) as ctx:
            verify_svid(cert, root_cert=other_ca.root_cert, current=_NOW)
        self.assertEqual(ctx.exception.reason_code, "svid_untrusted_root")

    def test_tampered_cert_rejected(self):
        # Issue two certs from the same CA subject but graft one's
        # signature check to fail: re-issue with a different key and
        # verify the leaf signature is bound. Simulate tamper by
        # verifying a cert against a root whose key differs but whose
        # subject name matches.
        root_key_a = Ed25519PrivateKey.generate()
        ca_a = WorkloadCA(trust_domain=_TRUST_DOMAIN, root_key=root_key_a)
        cert = _issue(ca_a)
        # A second CA with the SAME common_name (thus same subject
        # name) but a DIFFERENT root key. Issuer==subject passes; the
        # signature check must then fail.
        ca_b = WorkloadCA(
            trust_domain=_TRUST_DOMAIN,
            root_key=Ed25519PrivateKey.generate(),
            common_name=ca_a.common_name,
        )
        with self.assertRaises(SvidVerificationError) as ctx:
            verify_svid(cert, root_cert=ca_b.root_cert, current=_NOW)
        self.assertEqual(ctx.exception.reason_code, "svid_signature_invalid")


class TimeWindowTests(unittest.TestCase):
    def test_expired_rejected(self):
        ca = _ca()
        cert = _issue(ca, ttl=timedelta(minutes=30))
        with self.assertRaises(SvidVerificationError) as ctx:
            verify_svid(
                cert, root_cert=ca.root_cert, current=_NOW + timedelta(hours=2)
            )
        self.assertEqual(ctx.exception.reason_code, "svid_expired")

    def test_not_yet_valid_rejected(self):
        ca = _ca()
        cert = _issue(ca, now=_NOW + timedelta(hours=1))
        with self.assertRaises(SvidVerificationError) as ctx:
            verify_svid(cert, root_cert=ca.root_cert, current=_NOW)
        self.assertEqual(ctx.exception.reason_code, "svid_not_yet_valid")


class BindingTests(unittest.TestCase):
    def test_expected_mismatch_rejected(self):
        ca = _ca()
        cert = _issue(ca)
        with self.assertRaises(SvidVerificationError) as ctx:
            verify_svid(
                cert,
                root_cert=ca.root_cert,
                current=_NOW,
                expected_spiffe_id="spiffe://mesh.example/ns-b/other",
            )
        self.assertEqual(ctx.exception.reason_code, "svid_spiffe_mismatch")


class KeyUsageTests(unittest.TestCase):
    def test_root_cert_as_leaf_rejected_on_key_usage(self):
        # The root has key_cert_sign set and no SAN — feeding it as a
        # "leaf" fails at the shape check (no SAN) first, which is the
        # right defense. Confirm it does not verify as an SVID.
        ca = _ca()
        with self.assertRaises(SvidVerificationError):
            verify_svid(ca.root_cert, root_cert=ca.root_cert, current=_NOW)


class InputValidationTests(unittest.TestCase):
    def test_naive_current_rejected(self):
        ca = _ca()
        cert = _issue(ca)
        with self.assertRaises(SvidVerificationError) as ctx:
            verify_svid(cert, root_cert=ca.root_cert, current=datetime(2026, 4, 14, 12))
        self.assertEqual(ctx.exception.reason_code, "svid_malformed")


if __name__ == "__main__":
    unittest.main()
