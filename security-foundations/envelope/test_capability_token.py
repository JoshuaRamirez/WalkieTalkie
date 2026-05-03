import base64
import json
import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from capability_token import (
    EXPECTED_ALG,
    EXPECTED_TYP,
    MAX_TOKEN_BYTES,
    CapabilityClaims,
    verify_capability_token,
)
from verify_envelope import EnvelopeVerificationError


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _ed25519_keypair():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def _make_token(
    *,
    private_key: Ed25519PrivateKey,
    header_overrides: dict | None = None,
    payload_overrides: dict | None = None,
    raw_header: dict | None = None,
    raw_payload: dict | None = None,
) -> str:
    header = raw_header if raw_header is not None else {
        "alg": EXPECTED_ALG,
        "typ": EXPECTED_TYP,
        "kid": "issuer-kid-1",
    }
    if header_overrides:
        header = {**header, **header_overrides}

    now = 1_776_168_000  # 2026-04-14T12:00:00Z
    payload = raw_payload if raw_payload is not None else {
        "iss": "spiffe://mesh/cap-issuer-1",
        "sub": "spiffe://mesh/ns-a/service-a",
        "aud": "spiffe://mesh/ns-b/service-b",
        "scope": "invoke_tool",
        "iat": now - 10,
        "nbf": now - 10,
        "exp": now + 60,
        "jti": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2",
        "cnf": {"envelope_digest": "94fabd33a2221b6d3986e8d5ba98d75a91dcdad9b978ac7ea70bbc996fb2bb45"},
    }
    if payload_overrides:
        payload = {**payload, **payload_overrides}

    h = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = (h + "." + p).encode("ascii")
    sig = _b64u(private_key.sign(signing_input))
    return f"{h}.{p}.{sig}"


class CapabilityTokenTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _ed25519_keypair()
        self.envelope = {
            "sender_spiffe_id": "spiffe://mesh/ns-a/service-a",
            "recipient_spiffe_id": "spiffe://mesh/ns-b/service-b",
            "purpose_of_use": "invoke_tool",
            "payload_digest": "94fabd33a2221b6d3986e8d5ba98d75a91dcdad9b978ac7ea70bbc996fb2bb45",
        }
        self.now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        self.skew = timedelta(seconds=60)
        self.max_ttl = timedelta(minutes=5)
        self.lookup = lambda iss, kid: self.pem

    def _verify(self, token: str) -> CapabilityClaims:
        return verify_capability_token(
            token,
            envelope=self.envelope,
            issuer_lookup=self.lookup,
            current=self.now,
            max_clock_skew=self.skew,
            max_capability_ttl=self.max_ttl,
        )

    def test_well_formed_token_passes(self):
        token = _make_token(private_key=self.priv)
        claims = self._verify(token)
        self.assertEqual(claims.iss, "spiffe://mesh/cap-issuer-1")
        self.assertEqual(claims.scope, "invoke_tool")

    def test_oversized_token_rejected(self):
        token = "a" * (MAX_TOKEN_BYTES + 1)
        with self.assertRaisesRegex(EnvelopeVerificationError, "exceeds max size"):
            self._verify(token)

    def test_two_segment_token_rejected(self):
        token = _make_token(private_key=self.priv)
        bad = ".".join(token.split(".")[:2])
        with self.assertRaisesRegex(EnvelopeVerificationError, "three base64url"):
            self._verify(bad)

    def test_non_base64url_segment_rejected(self):
        token = _make_token(private_key=self.priv)
        # Garbage that decodes to bytes that aren't valid JSON; either path
        # (base64url failure or JSON failure) must surface as a token error.
        bad = "@@@." + ".".join(token.split(".")[1:])
        with self.assertRaisesRegex(EnvelopeVerificationError, "capability token:"):
            self._verify(bad)

    def test_non_object_payload_rejected(self):
        h = _b64u(b'{"alg":"EdDSA","typ":"wt-cap+jwt","kid":"k"}')
        p = _b64u(b'"not an object"')
        sig = _b64u(self.priv.sign((h + "." + p).encode("ascii")))
        with self.assertRaisesRegex(EnvelopeVerificationError, "payload is not a JSON object"):
            self._verify(f"{h}.{p}.{sig}")

    def test_wrong_alg_rejected(self):
        for bad in ("none", "HS256", "RS256", ""):
            with self.subTest(alg=bad):
                token = _make_token(
                    private_key=self.priv, header_overrides={"alg": bad}
                )
                with self.assertRaisesRegex(EnvelopeVerificationError, "alg must be"):
                    self._verify(token)

    def test_wrong_typ_rejected(self):
        token = _make_token(private_key=self.priv, header_overrides={"typ": "JWT"})
        with self.assertRaisesRegex(EnvelopeVerificationError, "typ must be"):
            self._verify(token)

    def test_kid_format_rejected(self):
        for bad in ("", "kid with space", "a" * 200):
            with self.subTest(kid=bad):
                token = _make_token(
                    private_key=self.priv, header_overrides={"kid": bad}
                )
                with self.assertRaisesRegex(EnvelopeVerificationError, "kid format"):
                    self._verify(token)

    def test_missing_required_claim_rejected(self):
        for claim in ("iss", "sub", "aud", "scope", "iat", "nbf", "exp", "jti", "cnf"):
            with self.subTest(claim=claim):
                token = _make_token(private_key=self.priv)
                # Re-mint without that claim.
                payload = {
                    "iss": "spiffe://mesh/cap-issuer-1",
                    "sub": "spiffe://mesh/ns-a/service-a",
                    "aud": "spiffe://mesh/ns-b/service-b",
                    "scope": "invoke_tool",
                    "iat": 1_776_167_990,
                    "nbf": 1_776_167_990,
                    "exp": 1_776_168_060,
                    "jti": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2",
                    "cnf": {
                        "envelope_digest": "94fabd33a2221b6d3986e8d5ba98d75a91dcdad9b978ac7ea70bbc996fb2bb45"
                    },
                }
                payload.pop(claim)
                token = _make_token(private_key=self.priv, raw_payload=payload)
                with self.assertRaisesRegex(EnvelopeVerificationError, "missing required"):
                    self._verify(token)

    def test_iss_format_rejected(self):
        token = _make_token(
            private_key=self.priv, payload_overrides={"iss": "not-spiffe"}
        )
        with self.assertRaisesRegex(EnvelopeVerificationError, "invalid iss"):
            self._verify(token)

    def test_cnf_format_rejected(self):
        for bad in ("not-hex", "0" * 63, "g" * 64):
            with self.subTest(digest=bad):
                token = _make_token(
                    private_key=self.priv,
                    payload_overrides={"cnf": {"envelope_digest": bad}},
                )
                with self.assertRaisesRegex(EnvelopeVerificationError, "hex sha256"):
                    self._verify(token)

    def test_iat_after_nbf_rejected(self):
        token = _make_token(
            private_key=self.priv,
            payload_overrides={"iat": 1_776_168_100, "nbf": 1_776_168_000},
        )
        with self.assertRaisesRegex(EnvelopeVerificationError, "iat must be <= nbf"):
            self._verify(token)

    def test_ttl_exceeds_max_rejected(self):
        # 10 minutes > default 5
        token = _make_token(
            private_key=self.priv,
            payload_overrides={
                "iat": 1_776_167_990,
                "nbf": 1_776_167_990,
                "exp": 1_776_167_990 + 600,
            },
        )
        with self.assertRaisesRegex(EnvelopeVerificationError, "ttl exceeds"):
            self._verify(token)

    def test_expired_token_rejected(self):
        token = _make_token(
            private_key=self.priv,
            payload_overrides={
                "iat": 1_776_167_000,
                "nbf": 1_776_167_000,
                "exp": 1_776_167_100,
            },
        )
        with self.assertRaisesRegex(EnvelopeVerificationError, "expired"):
            self._verify(token)

    def test_not_yet_valid_rejected(self):
        token = _make_token(
            private_key=self.priv,
            payload_overrides={
                "iat": 1_776_171_000,
                "nbf": 1_776_171_000,
                "exp": 1_776_171_100,
            },
        )
        with self.assertRaisesRegex(EnvelopeVerificationError, "nbf in future"):
            self._verify(token)

    def test_signature_invalid_rejected(self):
        token = _make_token(private_key=self.priv)
        h, p, _ = token.split(".")
        bad_sig = _b64u(b"\x00" * 64)
        with self.assertRaisesRegex(EnvelopeVerificationError, "signature invalid"):
            self._verify(f"{h}.{p}.{bad_sig}")

    def test_signed_with_unrelated_key_rejected(self):
        other, _ = _ed25519_keypair()
        token = _make_token(private_key=other)
        with self.assertRaisesRegex(EnvelopeVerificationError, "signature invalid"):
            self._verify(token)

    def test_envelope_binding_fields(self):
        for field, claim_key, bad in [
            ("sender_spiffe_id", "sub", "spiffe://mesh/ns-x/service-x"),
            ("recipient_spiffe_id", "aud", "spiffe://mesh/ns-x/service-x"),
            ("purpose_of_use", "scope", "different_purpose"),
            (
                "payload_digest",
                "cnf",
                {"envelope_digest": "0" * 64},
            ),
        ]:
            with self.subTest(field=field):
                token = _make_token(
                    private_key=self.priv, payload_overrides={claim_key: bad}
                )
                with self.assertRaises(EnvelopeVerificationError):
                    self._verify(token)


if __name__ == "__main__":
    unittest.main()
