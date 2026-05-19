"""Tests for session tokens (Phase 2 Track E E2)."""

import dataclasses
import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from session_token import (
    SessionError,
    SessionToken,
    from_json,
    sign_session,
    to_json,
    verify_resume,
    verify_session_token,
)
from verify_envelope import EnvelopeVerificationError

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_TS = int(_NOW.timestamp())
_ISS = "spiffe://mesh.example/ns-iss/session-issuer-1"
_KID = "session-kid-1"
_SUB = "spiffe://mesh.example/ns-a/client-1"
_AUD = "spiffe://mesh.example/ns-b/streaming-server-1"
_SESSION_ID = "01900000-0000-7000-8000-aaaaaaaaaaa1"
_JTI_OPEN = "01900000-0000-7000-8000-aaaaaaaaaaa2"
_JTI_RESUME_1 = "01900000-0000-7000-8000-aaaaaaaaaaa3"
_JTI_RESUME_2 = "01900000-0000-7000-8000-aaaaaaaaaaa4"


def _make_keypair():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def _lookup(pem: bytes):
    def _f(iss: str, kid: str) -> bytes:
        if (iss, kid) != (_ISS, _KID):
            raise EnvelopeVerificationError(
                f"unknown: iss={iss!r}, kid={kid!r}"
            )
        return pem
    return _f


def _open_token(**overrides) -> SessionToken:
    kwargs = dict(
        session_id=_SESSION_ID,
        seq=0,
        parent_jti="",
        iss=_ISS,
        iss_kid=_KID,
        sub=_SUB,
        aud=_AUD,
        scope="stream_response",
        iat=_NOW_TS - 5,
        nbf=_NOW_TS,
        exp=_NOW_TS + 60,
        jti=_JTI_OPEN,
    )
    kwargs.update(overrides)
    return SessionToken(**kwargs)


def _resume_token(prev: SessionToken, **overrides) -> SessionToken:
    kwargs = dict(
        session_id=prev.session_id,
        seq=prev.seq + 1,
        parent_jti=prev.jti,
        iss=prev.iss,
        iss_kid=prev.iss_kid,
        sub=prev.sub,
        aud=prev.aud,
        scope=prev.scope,
        iat=_NOW_TS,
        nbf=_NOW_TS,
        exp=_NOW_TS + 60,
        jti=_JTI_RESUME_1,
    )
    kwargs.update(overrides)
    return SessionToken(**kwargs)


class OpenTokenTests(unittest.TestCase):
    def test_well_formed_open_token_verifies(self):
        priv, pem = _make_keypair()
        signed = sign_session(_open_token(), priv)
        result = verify_session_token(
            signed,
            issuer_lookup=_lookup(pem),
            current=_NOW,
        )
        self.assertIs(result, signed)

    def test_open_token_with_parent_jti_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_session(
            _open_token(parent_jti=_JTI_RESUME_1), priv
        )
        with self.assertRaises(SessionError) as ctx:
            verify_session_token(
                signed, issuer_lookup=_lookup(pem), current=_NOW
            )
        self.assertEqual(ctx.exception.reason.value, "session_malformed")

    def test_resume_token_without_parent_jti_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_session(_open_token(seq=1, parent_jti=""), priv)
        with self.assertRaises(SessionError) as ctx:
            verify_session_token(
                signed, issuer_lookup=_lookup(pem), current=_NOW
            )
        self.assertEqual(ctx.exception.reason.value, "session_malformed")


class WindowTests(unittest.TestCase):
    def test_expired_token_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_session(
            _open_token(
                iat=_NOW_TS - 240, nbf=_NOW_TS - 240, exp=_NOW_TS - 120
            ),
            priv,
        )
        with self.assertRaises(SessionError) as ctx:
            verify_session_token(
                signed, issuer_lookup=_lookup(pem), current=_NOW
            )
        self.assertEqual(ctx.exception.reason.value, "session_expired")

    def test_not_yet_valid_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_session(
            _open_token(
                iat=_NOW_TS + 60, nbf=_NOW_TS + 240, exp=_NOW_TS + 300
            ),
            priv,
        )
        with self.assertRaises(SessionError) as ctx:
            verify_session_token(
                signed, issuer_lookup=_lookup(pem), current=_NOW
            )
        self.assertEqual(ctx.exception.reason.value, "session_not_yet_valid")

    def test_ttl_exceeds_max_rejected(self):
        priv, pem = _make_keypair()
        # 10 minute window, default max is 5 minutes.
        signed = sign_session(
            _open_token(
                iat=_NOW_TS - 5, nbf=_NOW_TS, exp=_NOW_TS + 600
            ),
            priv,
        )
        with self.assertRaises(SessionError) as ctx:
            verify_session_token(
                signed, issuer_lookup=_lookup(pem), current=_NOW
            )
        self.assertEqual(ctx.exception.reason.value, "session_ttl_exceeded")


class SignatureTests(unittest.TestCase):
    def test_tampered_token_rejected(self):
        priv, pem = _make_keypair()
        signed = sign_session(_open_token(), priv)
        tampered = dataclasses.replace(signed, scope="exfiltrate")
        with self.assertRaises(SessionError) as ctx:
            verify_session_token(
                tampered, issuer_lookup=_lookup(pem), current=_NOW
            )
        self.assertEqual(ctx.exception.reason.value, "session_signature_invalid")

    def test_unknown_issuer_rejected(self):
        priv, _ = _make_keypair()
        signed = sign_session(_open_token(), priv)

        def _empty_lookup(iss: str, kid: str) -> bytes:
            raise EnvelopeVerificationError("not found")

        with self.assertRaises(SessionError) as ctx:
            verify_session_token(
                signed, issuer_lookup=_empty_lookup, current=_NOW
            )
        self.assertEqual(ctx.exception.reason.value, "session_unknown_issuer")


class ResumeHappyPathTests(unittest.TestCase):
    def test_first_resume_verifies(self):
        priv, pem = _make_keypair()
        opened = sign_session(_open_token(), priv)
        resumed = sign_session(_resume_token(opened), priv)
        result = verify_resume(
            resumed,
            previous=opened,
            session_opened_at=opened.iat,
            issuer_lookup=_lookup(pem),
            current=_NOW,
        )
        self.assertIs(result, resumed)


class ResumeChainTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _make_keypair()
        self.opened = sign_session(_open_token(), self.priv)

    def test_sequence_skip_rejected(self):
        bad = sign_session(
            _resume_token(self.opened, seq=2, jti=_JTI_RESUME_2),
            self.priv,
        )
        with self.assertRaises(SessionError) as ctx:
            verify_resume(
                bad,
                previous=self.opened,
                session_opened_at=self.opened.iat,
                issuer_lookup=_lookup(self.pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "session_resume_sequence_invalid"
        )

    def test_sequence_replay_rejected(self):
        # seq must be previous.seq + 1; reusing previous.seq is a
        # replay attempt and fails the same check.
        replay = sign_session(
            _resume_token(self.opened, seq=self.opened.seq),
            self.priv,
        )
        with self.assertRaises(SessionError) as ctx:
            verify_resume(
                replay,
                previous=self.opened,
                session_opened_at=self.opened.iat,
                issuer_lookup=_lookup(self.pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "session_resume_sequence_invalid"
        )

    def test_parent_jti_mismatch_rejected(self):
        forged = sign_session(
            _resume_token(self.opened, parent_jti=_JTI_RESUME_2),
            self.priv,
        )
        with self.assertRaises(SessionError) as ctx:
            verify_resume(
                forged,
                previous=self.opened,
                session_opened_at=self.opened.iat,
                issuer_lookup=_lookup(self.pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "session_resume_parent_mismatch"
        )

    def test_cross_session_id_rejected(self):
        # parent_jti matches but session_id changed → different session.
        cross = sign_session(
            _resume_token(
                self.opened, session_id="01900000-0000-7000-8000-bbbbbbbbbbbb"
            ),
            self.priv,
        )
        with self.assertRaises(SessionError) as ctx:
            verify_resume(
                cross,
                previous=self.opened,
                session_opened_at=self.opened.iat,
                issuer_lookup=_lookup(self.pem),
                current=_NOW,
            )
        self.assertEqual(
            ctx.exception.reason.value, "session_resume_session_mismatch"
        )


class ResumeDriftTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pem = _make_keypair()
        self.opened = sign_session(_open_token(), self.priv)

    def _verify(self, drift):
        token = sign_session(_resume_token(self.opened, **drift), self.priv)
        return verify_resume(
            token,
            previous=self.opened,
            session_opened_at=self.opened.iat,
            issuer_lookup=_lookup(self.pem),
            current=_NOW,
        )

    def test_scope_drift_rejected(self):
        with self.assertRaises(SessionError) as ctx:
            self._verify({"scope": "different_scope"})
        self.assertEqual(
            ctx.exception.reason.value, "session_resume_scope_drift"
        )

    def test_audience_drift_rejected(self):
        with self.assertRaises(SessionError) as ctx:
            self._verify({"aud": "spiffe://mesh.example/ns-x/somewhere-else"})
        self.assertEqual(
            ctx.exception.reason.value, "session_resume_audience_drift"
        )

    def test_subject_drift_rejected(self):
        with self.assertRaises(SessionError) as ctx:
            self._verify({"sub": "spiffe://mesh.example/ns-y/different-client"})
        self.assertEqual(
            ctx.exception.reason.value, "session_resume_subject_drift"
        )


class ResumeLifetimeTests(unittest.TestCase):
    def test_cumulative_lifetime_capped(self):
        priv, pem = _make_keypair()
        # Original opened at _NOW_TS - 3500 (~58 min ago). A resume
        # with exp=_NOW_TS+200 would push cumulative just under 1h.
        # A resume with exp=_NOW_TS+200 should pass; one with
        # exp=_NOW_TS+3700 (~62 min cumulative) should fail.
        opened_iat = _NOW_TS - 3500
        opened = sign_session(
            _open_token(
                iat=opened_iat, nbf=opened_iat, exp=opened_iat + 60
            ),
            priv,
        )
        too_long = sign_session(
            _resume_token(
                opened,
                iat=_NOW_TS,
                nbf=_NOW_TS,
                exp=_NOW_TS + 3700,
            ),
            priv,
        )
        with self.assertRaises(SessionError) as ctx:
            verify_resume(
                too_long,
                previous=opened,
                session_opened_at=opened_iat,
                issuer_lookup=_lookup(pem),
                current=_NOW,
                max_session_lifetime=timedelta(hours=1),
            )
        self.assertEqual(
            ctx.exception.reason.value, "session_resume_lifetime_exceeded"
        )


class JsonRoundTripTests(unittest.TestCase):
    def test_round_trip(self):
        priv, _ = _make_keypair()
        signed = sign_session(_open_token(), priv)
        blob = to_json(signed)
        restored = from_json(blob)
        self.assertEqual(restored, signed)

    def test_missing_field_rejected(self):
        with self.assertRaises(SessionError) as ctx:
            from_json(b'{"session_id": "x"}')
        self.assertEqual(ctx.exception.reason.value, "session_malformed")


if __name__ == "__main__":
    unittest.main()
