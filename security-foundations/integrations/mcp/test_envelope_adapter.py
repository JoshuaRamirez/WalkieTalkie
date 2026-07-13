"""Tests for the MCP envelope adapter (Phase 4 D4.1)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "envelope")
)

from envelope_adapter import (
    EnvelopeFields,
    MCPAdapterError,
    MCPRequest,
    MCPResponse,
    build_envelope,
    envelope_from_json,
    envelope_to_json,
    mcp_request_to_payload,
    mcp_response_to_payload,
    payload_to_mcp_request,
    payload_to_mcp_response,
    sign_envelope,
    unwrap_request,
    unwrap_response,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_SENDER = "spiffe://mesh.example/ns-a/agent-1"
_RECIPIENT = "spiffe://mesh.example/ns-b/server-1"
_MSG_ID = "01900000-0000-7000-8000-aaaaaaaaaaa1"
_NONCE = "nonce-abcdefghijklmnop"
_KID = "dev-kid-1"
_CAP_TOKEN = "eyJ.eyJ.AAA"  # opaque to the adapter; envelope verifier checks it


def _fields(**overrides) -> EnvelopeFields:
    kwargs = dict(
        sender_spiffe_id=_SENDER,
        recipient_spiffe_id=_RECIPIENT,
        purpose_of_use="invoke_tool",
        kid=_KID,
        capability_token=_CAP_TOKEN,
        message_id=_MSG_ID,
        nonce=_NONCE,
        issued_at=_NOW,
        ttl=timedelta(minutes=5),
    )
    kwargs.update(overrides)
    return EnvelopeFields(**kwargs)


class MCPRequestValidationTests(unittest.TestCase):
    def test_empty_method_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "method"):
            MCPRequest(method="")

    def test_bad_params_type_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "params"):
            MCPRequest(method="x", params="not-a-dict-or-list")  # type: ignore[arg-type]

    def test_bad_id_type_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "id"):
            MCPRequest(method="x", id=3.14)  # type: ignore[arg-type]


class MCPResponseValidationTests(unittest.TestCase):
    def test_must_carry_exactly_one_of_result_or_error(self):
        with self.assertRaisesRegex(MCPAdapterError, "result.*error"):
            MCPResponse(id=1)
        with self.assertRaisesRegex(MCPAdapterError, "result.*error"):
            MCPResponse(
                id=1,
                result={"ok": True},
                error={"code": -1, "message": "x"},
            )

    def test_error_must_have_code_and_message(self):
        with self.assertRaisesRegex(MCPAdapterError, "code.*message"):
            MCPResponse(id=1, error={"code": -32600})  # type: ignore[arg-type]


class PayloadRoundTripTests(unittest.TestCase):
    def test_request_round_trip(self):
        req = MCPRequest(method="tools/list", params={"cursor": None}, id=1)
        payload = mcp_request_to_payload(req)
        self.assertEqual(payload["jsonrpc"], "2.0")
        self.assertEqual(payload["method"], "tools/list")
        restored = payload_to_mcp_request(payload)
        self.assertEqual(restored, req)

    def test_notification_has_no_id(self):
        req = MCPRequest(method="notifications/cancelled", params={"id": 7})
        payload = mcp_request_to_payload(req)
        self.assertNotIn("id", payload)
        self.assertEqual(payload_to_mcp_request(payload).id, None)

    def test_response_result_round_trip(self):
        resp = MCPResponse(id="abc", result={"tools": []})
        payload = mcp_response_to_payload(resp)
        self.assertEqual(payload["result"], {"tools": []})
        self.assertEqual(payload_to_mcp_response(payload), resp)

    def test_response_error_round_trip(self):
        err = {"code": -32601, "message": "Method not found"}
        resp = MCPResponse(id=1, error=err)
        payload = mcp_response_to_payload(resp)
        self.assertEqual(payload["error"], err)
        self.assertEqual(payload_to_mcp_response(payload), resp)

    def test_bad_jsonrpc_version_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "jsonrpc"):
            payload_to_mcp_request(
                {"jsonrpc": "1.0", "method": "x"}
            )

    def test_missing_method_on_request_payload_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "method"):
            payload_to_mcp_request({"jsonrpc": "2.0", "id": 1})


class EnvelopeFieldsTests(unittest.TestCase):
    def test_naive_issued_at_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "issued_at"):
            _fields(issued_at=datetime(2026, 4, 14, 12))

    def test_zero_ttl_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "ttl"):
            _fields(ttl=timedelta(0))

    def test_empty_required_field_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "kid"):
            _fields(kid="")


class BuildEnvelopeTests(unittest.TestCase):
    def _payload(self):
        return mcp_request_to_payload(
            MCPRequest(method="tools/call", params={"name": "read_file"}, id=1)
        )

    def test_envelope_has_all_required_schema_fields(self):
        env = build_envelope(payload=self._payload(), fields=_fields())
        for required in (
            "version",
            "message_id",
            "sender_spiffe_id",
            "recipient_spiffe_id",
            "issued_at",
            "expires_at",
            "nonce",
            "capability_token",
            "purpose_of_use",
            "kid",
            "alg",
            "payload",
            "payload_digest",
        ):
            self.assertIn(required, env, f"missing required field: {required}")
        # signature is added by sign_envelope, not build_envelope.
        self.assertNotIn("signature", env)

    def test_payload_digest_is_sha256_jcs(self):
        import hashlib

        import jcs
        payload = self._payload()
        env = build_envelope(payload=payload, fields=_fields())
        expected = hashlib.sha256(jcs.canonicalize(payload)).hexdigest()
        self.assertEqual(env["payload_digest"], expected)

    def test_expires_at_equals_issued_at_plus_ttl(self):
        env = build_envelope(
            payload=self._payload(),
            fields=_fields(ttl=timedelta(minutes=3)),
        )
        self.assertEqual(env["issued_at"], "2026-04-14T12:00:00Z")
        self.assertEqual(env["expires_at"], "2026-04-14T12:03:00Z")

    def test_non_dict_payload_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "payload"):
            build_envelope(payload="not a dict", fields=_fields())  # type: ignore[arg-type]


class SignEnvelopeTests(unittest.TestCase):
    def test_signature_attaches_and_is_valid(self):
        priv = Ed25519PrivateKey.generate()
        env = build_envelope(
            payload=mcp_request_to_payload(
                MCPRequest(method="ping", id=1)
            ),
            fields=_fields(),
        )
        signed = sign_envelope(env, priv)
        self.assertIn("signature", signed)
        # Verify against the same canonicalization rule the substrate uses.
        import base64

        import jcs
        unsigned = {k: v for k, v in signed.items() if k != "signature"}
        signing_input = jcs.canonicalize(unsigned)
        sig_bytes = base64.urlsafe_b64decode(
            signed["signature"] + "=" * (-len(signed["signature"]) % 4)
        )
        # This call raises InvalidSignature on failure.
        priv.public_key().verify(sig_bytes, signing_input)

    def test_resigning_replaces_old_signature(self):
        priv = Ed25519PrivateKey.generate()
        env = build_envelope(
            payload=mcp_request_to_payload(MCPRequest(method="ping", id=1)),
            fields=_fields(),
        )
        once = sign_envelope(env, priv)
        twice = sign_envelope(once, priv)
        self.assertEqual(once, twice)  # deterministic over the same body

    def test_resigning_after_payload_mutation_invalidates_old_signature(self):
        priv = Ed25519PrivateKey.generate()
        env = build_envelope(
            payload=mcp_request_to_payload(MCPRequest(method="ping", id=1)),
            fields=_fields(),
        )
        signed = sign_envelope(env, priv)
        mutated = dict(signed)
        mutated["payload"] = mcp_request_to_payload(
            MCPRequest(method="malicious", id=1)
        )
        # If a downstream re-signs after tampering, the new signature
        # is over the new body — but the verifier (verify_envelope)
        # rejects this on payload_digest mismatch + nonce reuse.
        # The adapter's job here is only to NOT make signing easier
        # without breaking the digest: confirm sign_envelope produces
        # a different signature for a different body.
        resigned = sign_envelope(mutated, priv)
        self.assertNotEqual(signed["signature"], resigned["signature"])


class UnwrapTests(unittest.TestCase):
    def test_unwrap_request_round_trip(self):
        req = MCPRequest(method="tools/list", id=1)
        env = build_envelope(
            payload=mcp_request_to_payload(req), fields=_fields()
        )
        self.assertEqual(unwrap_request(env), req)

    def test_unwrap_response_round_trip(self):
        resp = MCPResponse(id=1, result={"tools": []})
        env = build_envelope(
            payload=mcp_response_to_payload(resp), fields=_fields()
        )
        self.assertEqual(unwrap_response(env), resp)


class JsonTransportTests(unittest.TestCase):
    def test_envelope_to_from_json(self):
        env = build_envelope(
            payload=mcp_request_to_payload(MCPRequest(method="ping", id=1)),
            fields=_fields(),
        )
        blob = envelope_to_json(env)
        restored = envelope_from_json(blob)
        self.assertEqual(restored, env)

    def test_invalid_json_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "valid JSON"):
            envelope_from_json(b"{not-json")

    def test_non_object_json_rejected(self):
        with self.assertRaisesRegex(MCPAdapterError, "object"):
            envelope_from_json(b"[1,2,3]")


class IntegrationWithVerifierTests(unittest.TestCase):
    """The adapter is only useful if its output is verifiable by the
    Phase 1 verifier. Pin that contract here so any drift between the
    schema and the adapter fails CI on this branch."""

    def test_adapter_output_passes_schema_required_fields(self):
        # The schema requires exactly the set of fields the adapter
        # emits (plus signature). Drift between the two is the
        # likeliest source of "works in unit test, fails in
        # verify_envelope" surprises, so pin it.
        import json

        schema_path = (
            pathlib.Path(__file__).resolve().parent.parent.parent
            / "envelope"
            / "schema-v0.json"
        )
        with open(schema_path) as f:
            schema = json.load(f)
        required = set(schema["required"])

        priv = Ed25519PrivateKey.generate()
        env = sign_envelope(
            build_envelope(
                payload=mcp_request_to_payload(
                    MCPRequest(method="ping", id=1)
                ),
                fields=_fields(),
            ),
            priv,
        )
        missing = required - set(env)
        extra = set(env) - required
        self.assertFalse(missing, f"adapter omitted required fields: {missing}")
        self.assertFalse(extra, f"adapter emitted unexpected fields: {extra}")


if __name__ == "__main__":
    unittest.main()
