"""MCP envelope adapter v0 (Phase 4 D4.1).

Closes Phase 4 D4.1 ("MCP Envelope Adapter") — the bidirectional
translation layer between MCP's JSON-RPC 2.0 wire format and the
substrate's signed envelope schema (``schema-v0.json``).

Scope is intentionally narrow per the Phase 4 plan:

- Translate an MCP request / response into the ``payload`` field of
  an envelope and back. No transport. No signing infrastructure
  beyond a thin helper that calls Ed25519 + JCS.
- The adapter does NOT decide who to talk to, what scope to claim,
  or which capability token to attach — the caller (the example
  host in D4.2) supplies all of that.

What the substrate already does, the adapter does NOT duplicate:

- :func:`verify_envelope.verify_envelope` validates inbound
  envelopes. The adapter just hands wire bytes to ``verify_envelope``
  and then exposes the embedded MCP payload after success.
- :class:`capability_issuer.CapabilityIssuer` mints capability
  tokens. The adapter receives a pre-minted token from the caller.

Out of scope for D4.1 (lands in D4.2 / D4.3 / D4.4)
---------------------------------------------------
- Live MCP server loop, tool dispatch, output scanning pipeline.
- Smoke test driving a real message round-trip end-to-end.
- The integration runbook.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import jcs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class MCPAdapterError(ValueError):
    """Raised when adapter inputs violate v0 invariants."""


# JSON-RPC 2.0 carries either {jsonrpc, method, params?, id?} for a
# request / notification, or {jsonrpc, id, result|error} for a
# response. The adapter normalizes both shapes into dataclasses.


@dataclass(frozen=True)
class MCPRequest:
    """A parsed JSON-RPC 2.0 request or notification."""

    method: str
    params: dict[str, Any] | list[Any] | None = None
    id: int | str | None = None  # None ⇒ notification

    def __post_init__(self) -> None:
        if not isinstance(self.method, str) or not self.method:
            raise MCPAdapterError("method must be a non-empty string")
        if self.params is not None and not isinstance(
            self.params, (dict, list)
        ):
            raise MCPAdapterError(
                f"params must be dict, list, or None: {self.params!r}"
            )
        if self.id is not None and not isinstance(self.id, (int, str)):
            raise MCPAdapterError(f"id must be int, str, or None: {self.id!r}")


@dataclass(frozen=True)
class MCPResponse:
    """A parsed JSON-RPC 2.0 response.

    Exactly one of ``result`` and ``error`` must be set.
    """

    id: int | str | None
    result: Any = None
    error: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        if self.id is not None and not isinstance(self.id, (int, str)):
            raise MCPAdapterError(f"id must be int, str, or None: {self.id!r}")
        has_result = self.result is not None
        has_error = self.error is not None
        if has_result == has_error:
            raise MCPAdapterError(
                "exactly one of result and error must be set"
            )
        if has_error:
            if not isinstance(self.error, dict):
                raise MCPAdapterError("error must be a dict")
            if "code" not in self.error or "message" not in self.error:
                raise MCPAdapterError(
                    "error object must include 'code' and 'message'"
                )


# ---------------------------------------------------------------------
# Payload <-> MCP message translation
# ---------------------------------------------------------------------


def mcp_request_to_payload(req: MCPRequest) -> dict[str, Any]:
    """Render a request into the dict that goes inside envelope.payload."""
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "method": req.method,
    }
    if req.params is not None:
        payload["params"] = req.params
    if req.id is not None:
        payload["id"] = req.id
    return payload


def payload_to_mcp_request(payload: dict[str, Any]) -> MCPRequest:
    """Parse an envelope.payload into an :class:`MCPRequest`.

    Raises :class:`MCPAdapterError` if the payload does not look like
    a JSON-RPC 2.0 request.
    """
    if not isinstance(payload, dict):
        raise MCPAdapterError("payload must be a dict")
    if payload.get("jsonrpc") != "2.0":
        raise MCPAdapterError(
            f"jsonrpc field must be \"2.0\": {payload.get('jsonrpc')!r}"
        )
    if "method" not in payload:
        raise MCPAdapterError("payload is not a JSON-RPC request (no method)")
    return MCPRequest(
        method=payload["method"],
        params=payload.get("params"),
        id=payload.get("id"),
    )


def mcp_response_to_payload(resp: MCPResponse) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": resp.id,
    }
    if resp.result is not None:
        payload["result"] = resp.result
    else:
        payload["error"] = resp.error
    return payload


def payload_to_mcp_response(payload: dict[str, Any]) -> MCPResponse:
    if not isinstance(payload, dict):
        raise MCPAdapterError("payload must be a dict")
    if payload.get("jsonrpc") != "2.0":
        raise MCPAdapterError(
            f"jsonrpc field must be \"2.0\": {payload.get('jsonrpc')!r}"
        )
    if "result" in payload == ("error" in payload):
        raise MCPAdapterError(
            "response must carry exactly one of 'result' or 'error'"
        )
    return MCPResponse(
        id=payload.get("id"),
        result=payload.get("result"),
        error=payload.get("error"),
    )


# ---------------------------------------------------------------------
# Envelope build / sign
# ---------------------------------------------------------------------


def _rfc3339(when: datetime) -> str:
    return when.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _sha256_jcs(obj: Any) -> str:
    return hashlib.sha256(jcs.canonicalize(obj)).hexdigest()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class EnvelopeFields:
    """Operator-supplied fields that don't come from the MCP payload."""

    sender_spiffe_id: str
    recipient_spiffe_id: str
    purpose_of_use: str
    kid: str
    capability_token: str
    message_id: str
    nonce: str
    issued_at: datetime
    ttl: timedelta = field(default_factory=lambda: timedelta(minutes=5))

    def __post_init__(self) -> None:
        for name, value in (
            ("sender_spiffe_id", self.sender_spiffe_id),
            ("recipient_spiffe_id", self.recipient_spiffe_id),
            ("purpose_of_use", self.purpose_of_use),
            ("kid", self.kid),
            ("capability_token", self.capability_token),
            ("message_id", self.message_id),
            ("nonce", self.nonce),
        ):
            if not isinstance(value, str) or not value:
                raise MCPAdapterError(f"{name} must be a non-empty string")
        if not isinstance(self.issued_at, datetime) or self.issued_at.tzinfo is None:
            raise MCPAdapterError(
                "issued_at must be a timezone-aware datetime"
            )
        if not isinstance(self.ttl, timedelta) or self.ttl <= timedelta(0):
            raise MCPAdapterError("ttl must be a positive timedelta")


def build_envelope(
    *,
    payload: dict[str, Any],
    fields: EnvelopeFields,
) -> dict[str, Any]:
    """Assemble an unsigned envelope dict around ``payload``.

    The returned dict is exactly the shape ``schema-v0.json`` expects
    minus the ``signature`` field; pass it to :func:`sign_envelope`
    to attach a real Ed25519 signature.
    """
    if not isinstance(payload, dict):
        raise MCPAdapterError("payload must be a dict")
    envelope: dict[str, Any] = {
        "version": "v0",
        "message_id": fields.message_id,
        "sender_spiffe_id": fields.sender_spiffe_id,
        "recipient_spiffe_id": fields.recipient_spiffe_id,
        "issued_at": _rfc3339(fields.issued_at),
        "expires_at": _rfc3339(fields.issued_at + fields.ttl),
        "nonce": fields.nonce,
        "capability_token": fields.capability_token,
        "purpose_of_use": fields.purpose_of_use,
        "kid": fields.kid,
        "alg": "Ed25519",
        "payload": payload,
        "payload_digest": _sha256_jcs(payload),
    }
    return envelope


def sign_envelope(
    envelope: dict[str, Any], signing_key: Ed25519PrivateKey
) -> dict[str, Any]:
    """Attach an Ed25519 signature to ``envelope``.

    Signs the JCS canonicalization of the envelope WITHOUT the
    ``signature`` field — same convention the existing
    ``_regen_vectors.py`` and the substrate verifier use.
    """
    if "signature" in envelope:
        # Replace cleanly; signing must always be over the unsigned form.
        envelope = {k: v for k, v in envelope.items() if k != "signature"}
    signing_input = jcs.canonicalize(envelope)
    sig = _b64u(signing_key.sign(signing_input))
    return {**envelope, "signature": sig}


# ---------------------------------------------------------------------
# Unwrap path (after verify_envelope.verify_envelope succeeds)
# ---------------------------------------------------------------------


def unwrap_request(envelope: dict[str, Any]) -> MCPRequest:
    """Pull an :class:`MCPRequest` out of a verified envelope."""
    return payload_to_mcp_request(envelope["payload"])


def unwrap_response(envelope: dict[str, Any]) -> MCPResponse:
    return payload_to_mcp_response(envelope["payload"])


# ---------------------------------------------------------------------
# JSON helpers (operators send/receive envelopes as bytes)
# ---------------------------------------------------------------------


def envelope_to_json(envelope: dict[str, Any]) -> bytes:
    return json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode(
        "utf-8"
    )


def envelope_from_json(data: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise MCPAdapterError(f"envelope is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise MCPAdapterError("envelope JSON must be an object")
    return obj


__all__ = [
    "EnvelopeFields",
    "MCPAdapterError",
    "MCPRequest",
    "MCPResponse",
    "build_envelope",
    "envelope_from_json",
    "envelope_to_json",
    "mcp_request_to_payload",
    "mcp_response_to_payload",
    "payload_to_mcp_request",
    "payload_to_mcp_response",
    "sign_envelope",
    "unwrap_request",
    "unwrap_response",
]
