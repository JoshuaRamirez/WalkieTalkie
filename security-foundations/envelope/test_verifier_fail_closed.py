"""Structural fail-closed invariant for :func:`verify_envelope.verify_envelope`.

The envelope handed to the verifier is attacker-controlled: the MCP adapter's
``envelope_from_json`` parses arbitrary wire bytes and only checks that the
result is a JSON *object*, then the host and the mesh bridge pass that dict
straight to ``verify_envelope``. So every field can hold any JSON type, at any
nesting depth.

Before this suite the verifier assumed each field's Python type. Regex matches
(``UUID_V7_RE.match(envelope["message_id"])``), set membership
(``envelope["alg"] not in ALLOWED_ALGORITHMS``), and ``str.replace`` in
``parse_rfc3339`` all *raise* on the wrong type rather than returning False, so
``{"message_id": 123, ...}`` escaped as a bare ``TypeError``. Two consequences,
both security-relevant:

1. The exception escaped every caller's ``except EnvelopeVerificationError``
   handler as a foreign type.
2. It bypassed the verifier's own deny path, so **no ``envelope.verify`` deny
   event was written** — a malformed-envelope probe left no forensic trace.

Plus a remote DoS: a few kilobytes of ``[[[[...]]]]`` drove ``jcs.canonicalize``
into ``RecursionError``.

The invariant these tests pin: **for any input whatsoever, the verifier either
returns claims or raises ``EnvelopeVerificationError`` carrying a
``DenyReason`` — and every denial emits exactly one deny audit event on a
chain that still verifies.** Nothing else escapes.
"""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from audit import InMemoryAuditSink, verify_chain
from deny_reason import DenyReason
from test_verify_envelope import (
    _ISSUER_IDENTITY,
    _ISSUER_KID,
    _PURPOSE,
    _RECIPIENT,
    _SENDER,
    canonicalize_envelope_for_signing,
    generate_ed25519_keypair,
    mint_capability_token,
    sign,
)
from verify_envelope import (
    DEFAULT_CONFIG,
    EnvelopeVerificationError,
    InMemoryReplayCache,
    VerificationConfig,
    _digest_payload,
    check_json_depth,
    verify_envelope,
)


def nest(depth: int, *, kind: str = "list"):
    """Build a structure nested exactly ``depth`` containers deep."""
    value: object = "leaf"
    for _ in range(depth):
        value = [value] if kind == "list" else {"k": value}
    return value


class _VerifierFixture(unittest.TestCase):
    """A real signed envelope plus a verify-with-audit helper."""

    @classmethod
    def setUpClass(cls):
        cls.signer_priv_pem, cls.signer_pub_pem = generate_ed25519_keypair()
        cls.issuer_priv_pem, cls.issuer_pub_pem = generate_ed25519_keypair()

    def issuer_lookup(self, iss, kid):
        if (iss, kid) != (_ISSUER_IDENTITY, _ISSUER_KID):
            raise EnvelopeVerificationError(f"unknown issuer key: iss={iss}, kid={kid}")
        return self.issuer_pub_pem

    def valid_envelope(self):
        now = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
        envelope = {
            "version": "v0",
            "message_id": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1",
            "sender_spiffe_id": _SENDER,
            "recipient_spiffe_id": _RECIPIENT,
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "nonce": "nonce-000000000001",
            "purpose_of_use": _PURPOSE,
            "kid": "dev-kid-1",
            "alg": "Ed25519",
            "payload": {"tool": "ping", "args": {"target": "node-1"}},
        }
        envelope["payload_digest"] = _digest_payload(envelope["payload"])
        envelope["capability_token"] = mint_capability_token(
            issuer_priv_pem=self.issuer_priv_pem,
            issuer_kid=_ISSUER_KID,
            iss=_ISSUER_IDENTITY,
            sub=_SENDER,
            aud=_RECIPIENT,
            scope=_PURPOSE,
            payload_digest=envelope["payload_digest"],
            now=now,
        )
        envelope["signature"] = ""
        envelope["signature"] = sign(
            canonicalize_envelope_for_signing(envelope), self.signer_priv_pem
        )
        return envelope, now

    def verify(self, envelope, now, *, sink=None, key_lookup=None, config=DEFAULT_CONFIG):
        return verify_envelope(
            envelope,
            key_lookup=key_lookup or (lambda kid: self.signer_pub_pem),
            issuer_lookup=self.issuer_lookup,
            replay_cache=InMemoryReplayCache(),
            now=now,
            audit_sink=sink,
            config=config,
        )

    def assert_denies(self, envelope, now, expected: DenyReason, **kwargs):
        """The verifier denies cleanly *and* leaves a verifiable audit trace.

        ``assertRaises(EnvelopeVerificationError)`` is the load-bearing part:
        a ``TypeError`` or ``RecursionError`` fails the test rather than
        satisfying it.
        """
        sink = InMemoryAuditSink()
        with self.assertRaises(EnvelopeVerificationError) as ctx:
            self.verify(envelope, now, sink=sink, **kwargs)
        self.assertEqual(ctx.exception.reason, expected)

        denials = [
            e
            for e in sink.events
            if e.event_type == "envelope.verify" and e.outcome == "deny"
        ]
        self.assertEqual(len(denials), 1, "exactly one envelope.verify deny event")
        self.assertEqual(denials[0].reason_code, expected.value)
        verify_chain(sink.events)
        return ctx.exception


class MalformedFieldTypeTests(_VerifierFixture):
    """Every string-typed envelope field must reject non-strings, not crash.

    Each case swaps one field for a JSON type the verifier's own regex or
    membership test would raise on.
    """

    CASES = [
        ("message_id", 123, DenyReason.INVALID_MESSAGE_ID),
        ("message_id", None, DenyReason.INVALID_MESSAGE_ID),
        ("message_id", {"a": 1}, DenyReason.INVALID_MESSAGE_ID),
        ("sender_spiffe_id", 7, DenyReason.INVALID_SENDER_SPIFFE_ID),
        ("sender_spiffe_id", ["spiffe://mesh/x"], DenyReason.INVALID_SENDER_SPIFFE_ID),
        ("recipient_spiffe_id", [], DenyReason.INVALID_RECIPIENT_SPIFFE_ID),
        ("recipient_spiffe_id", True, DenyReason.INVALID_RECIPIENT_SPIFFE_ID),
        ("nonce", {}, DenyReason.INVALID_NONCE),
        ("nonce", 12345678901234567890, DenyReason.INVALID_NONCE),
        ("kid", 1.5, DenyReason.INVALID_KID),
        ("kid", None, DenyReason.INVALID_KID),
        ("payload_digest", 5, DenyReason.INVALID_PAYLOAD_DIGEST),
        ("payload_digest", ["0" * 64], DenyReason.INVALID_PAYLOAD_DIGEST),
        ("version", 0, DenyReason.UNSUPPORTED_VERSION),
        ("version", None, DenyReason.UNSUPPORTED_VERSION),
        ("issued_at", 1, DenyReason.INVALID_TIMESTAMP),
        ("issued_at", None, DenyReason.INVALID_TIMESTAMP),
        ("expires_at", ["2026-04-14T12:05:00Z"], DenyReason.INVALID_TIMESTAMP),
        ("expires_at", {}, DenyReason.INVALID_TIMESTAMP),
    ]

    def test_non_string_fields_deny_cleanly(self):
        for field, value, expected in self.CASES:
            with self.subTest(field=field, value=repr(value)):
                envelope, now = self.valid_envelope()
                envelope[field] = value
                self.assert_denies(envelope, now, expected)

    def test_unhashable_alg_denies_cleanly(self):
        """``x in <set>`` hashes x; a list ``alg`` used to raise TypeError."""
        for value in (["Ed25519"], {"alg": "Ed25519"}, 0, None):
            with self.subTest(alg=repr(value)):
                envelope, now = self.valid_envelope()
                envelope["alg"] = value
                self.assert_denies(envelope, now, DenyReason.DISALLOWED_ALGORITHM)

    def test_envelope_not_an_object_denies_cleanly(self):
        for value in ([], "not-an-envelope", 42, None):
            with self.subTest(envelope=repr(value)):
                self.assert_denies(value, datetime(2026, 4, 14, 12, tzinfo=UTC),
                                   DenyReason.ENVELOPE_NOT_OBJECT)


class NonCanonicalizableTests(_VerifierFixture):
    """Values outside the JSON data model deny instead of escaping as TypeError.

    Reachable whenever a caller builds the envelope dict in-process rather than
    decoding it from JSON — the host's own reply path, for instance.
    """

    def test_non_json_payload_denies_cleanly(self):
        for value in ({1, 2}, b"bytes", float("nan"), float("inf"), object()):
            with self.subTest(payload=repr(value)):
                envelope, now = self.valid_envelope()
                envelope["payload"] = value
                self.assert_denies(envelope, now, DenyReason.ENVELOPE_NOT_CANONICALIZABLE)


class NestingDepthTests(_VerifierFixture):
    """A few KB of ``[[[[...]]]]`` must not exhaust the interpreter stack."""

    def test_deeply_nested_payload_denies_cleanly(self):
        for kind in ("list", "dict"):
            with self.subTest(kind=kind):
                envelope, now = self.valid_envelope()
                envelope["payload"] = nest(20_000, kind=kind)
                self.assert_denies(envelope, now, DenyReason.ENVELOPE_TOO_DEEP)

    def test_depth_at_limit_is_accepted(self):
        """The bound rejects only what is *past* it — no off-by-one."""
        config = VerificationConfig(max_json_depth=12)
        envelope, now = self.valid_envelope()
        # The payload sits one level inside the envelope object, so a payload
        # nested (limit - 1) deep lands exactly on the limit.
        envelope["payload"] = nest(config.max_json_depth - 1)
        envelope["payload_digest"] = _digest_payload(envelope["payload"])
        envelope["capability_token"] = mint_capability_token(
            issuer_priv_pem=self.issuer_priv_pem,
            issuer_kid=_ISSUER_KID,
            iss=_ISSUER_IDENTITY,
            sub=_SENDER,
            aud=_RECIPIENT,
            scope=_PURPOSE,
            payload_digest=envelope["payload_digest"],
            now=now,
        )
        envelope["signature"] = ""
        envelope["signature"] = sign(
            canonicalize_envelope_for_signing(envelope), self.signer_priv_pem
        )
        self.verify(envelope, now, config=config)

        envelope["payload"] = nest(config.max_json_depth)
        self.assert_denies(envelope, now, DenyReason.ENVELOPE_TOO_DEEP, config=config)

    def test_depth_checker_is_iterative(self):
        """The checker must not recurse — it would die on its own input.

        Raising the bound above the input's depth forces a *full* walk of all
        200k levels; a recursive implementation dies with ``RecursionError``
        here. The bounded call below then confirms it still denies.
        """
        check_json_depth(nest(200_000), 999_999)  # RecursionError if recursive
        with self.assertRaises(EnvelopeVerificationError) as ctx:
            check_json_depth(nest(200_000), 64)
        self.assertEqual(ctx.exception.reason, DenyReason.ENVELOPE_TOO_DEEP)

    def test_wide_but_shallow_is_accepted(self):
        """The bound is on depth, not size — breadth must not trip it."""
        check_json_depth({"k": [{"a": i} for i in range(5_000)]}, 8)


class InternalErrorBackstopTests(_VerifierFixture):
    """Unanticipated failures deny with a trace rather than escaping raw.

    Callback failures (trust store unreachable, replay cache down) are the
    realistic trigger. Deny is the safe direction for a security kernel, and
    the deny event is what makes the failure visible.
    """

    def test_raising_key_lookup_denies_cleanly(self):
        envelope, now = self.valid_envelope()

        def exploding_lookup(kid):
            raise RuntimeError("trust store unreachable")

        exc = self.assert_denies(
            envelope, now, DenyReason.VERIFIER_INTERNAL_ERROR,
            key_lookup=exploding_lookup,
        )
        self.assertIn("RuntimeError", str(exc))
        # The original failure stays chained for debugging.
        self.assertIsInstance(exc.__cause__, RuntimeError)

    def test_backstop_does_not_swallow_keyboard_interrupt(self):
        """``BaseException`` must still propagate — shutdown is not a denial."""
        envelope, now = self.valid_envelope()

        def interrupting_lookup(kid):
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            self.verify(envelope, now, key_lookup=interrupting_lookup)


class ValidEnvelopeStillVerifiesTests(_VerifierFixture):
    """The hardening must not have narrowed the accept path."""

    def test_valid_envelope_passes_and_audits_allow(self):
        envelope, now = self.valid_envelope()
        sink = InMemoryAuditSink()
        claims = self.verify(envelope, now, sink=sink)
        self.assertEqual(claims.iss, _ISSUER_IDENTITY)
        allows = [
            e
            for e in sink.events
            if e.event_type == "envelope.verify" and e.outcome == "allow"
        ]
        self.assertEqual(len(allows), 1)
        verify_chain(sink.events)


if __name__ == "__main__":
    unittest.main()
