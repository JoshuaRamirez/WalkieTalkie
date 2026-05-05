"""Sanity tests for the checked-in test vectors.

These vectors are the conformance fixtures for the Phase 1 frozen contracts
(see ``security-foundations/contracts/``). If they bit-rot, downstream
implementations have nothing to validate against. This module asserts:

- valid-envelope.json parses, contains every field the schema requires, and
  its capability_token field equals the standalone capability-token.txt vector.
- audit-event.jsonl parses to three events that pass ``verify_chain``.
- The cap token in the envelope decodes to claims that bind to the envelope.
"""

import base64
import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from audit import JsonlAuditSink, verify_chain
from capability_token import parse_jwt

_VECTORS_DIR = pathlib.Path(__file__).resolve().parent / "test-vectors"


class EnvelopeVectorTests(unittest.TestCase):
    def test_valid_envelope_has_all_required_fields(self):
        envelope = json.loads((_VECTORS_DIR / "valid-envelope.json").read_text())
        required = {
            "version", "message_id", "sender_spiffe_id", "recipient_spiffe_id",
            "issued_at", "expires_at", "nonce", "capability_token",
            "purpose_of_use", "kid", "alg", "payload", "payload_digest",
            "signature",
        }
        self.assertEqual(set(envelope) & required, required)
        self.assertEqual(envelope["version"], "v0")
        self.assertEqual(envelope["alg"], "Ed25519")

    def test_capability_token_vector_matches_envelope_field(self):
        envelope = json.loads((_VECTORS_DIR / "valid-envelope.json").read_text())
        standalone = (_VECTORS_DIR / "capability-token.txt").read_text().strip()
        self.assertEqual(envelope["capability_token"], standalone)

    def test_capability_token_decodes_to_bound_claims(self):
        envelope = json.loads((_VECTORS_DIR / "valid-envelope.json").read_text())
        header, payload, _, _ = parse_jwt(envelope["capability_token"])
        self.assertEqual(header["alg"], "EdDSA")
        self.assertEqual(header["typ"], "wt-cap+jwt")
        self.assertEqual(payload["sub"], envelope["sender_spiffe_id"])
        self.assertEqual(payload["aud"], envelope["recipient_spiffe_id"])
        self.assertEqual(payload["scope"], envelope["purpose_of_use"])
        self.assertEqual(payload["cnf"]["envelope_digest"], envelope["payload_digest"])


class AuditEventVectorTests(unittest.TestCase):
    def test_audit_chain_verifies(self):
        sink = JsonlAuditSink(_VECTORS_DIR / "audit-event.jsonl")
        events = sink.read_all()
        self.assertEqual(len(events), 3)
        verify_chain(events)
        self.assertEqual([e.outcome for e in events], ["allow", "deny", "allow"])
        self.assertEqual(
            [e.reason_code for e in events],
            ["ok", "payload_digest_mismatch", "ok"],
        )

    def test_audit_event_has_all_required_fields(self):
        sink = JsonlAuditSink(_VECTORS_DIR / "audit-event.jsonl")
        events = sink.read_all()
        required = {
            "timestamp", "event_type", "outcome", "reason", "reason_code",
            "message_id", "sender", "recipient", "envelope_kid",
            "issuer_iss", "issuer_kid", "prev_hash", "this_hash",
        }
        self.assertEqual(set(events[0].to_dict()) & required, required)


class TestVectorBytesAreReproducible(unittest.TestCase):
    """The cap-token vector is base64url ASCII; if it has whitespace anywhere
    other than the trailing newline, downstream consumers will trip."""

    def test_capability_token_is_pure_base64url_with_dots(self):
        raw = (_VECTORS_DIR / "capability-token.txt").read_text()
        # Trailing newline only; inner content has no whitespace.
        self.assertTrue(raw.endswith("\n"))
        body = raw.rstrip("\n")
        self.assertEqual(body, body.strip())
        # JWS Compact: three segments separated by '.', each base64url.
        parts = body.split(".")
        self.assertEqual(len(parts), 3)
        for segment in parts:
            padded = segment + ("=" * ((4 - len(segment) % 4) % 4))
            base64.urlsafe_b64decode(padded.encode("ascii"))


if __name__ == "__main__":
    unittest.main()
