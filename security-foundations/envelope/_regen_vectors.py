"""Dev-time helper that regenerates the envelope test vectors under JCS.

Usage::

    python -m envelope._regen_vectors            # from repo root, with -e install
    python security-foundations/envelope/_regen_vectors.py

Writes:
- ``test-vectors/valid-envelope.json`` — verifies cleanly under the
  embedded envelope-signing private key and the embedded issuer key.
- ``test-vectors/tampered-envelope.json`` — same envelope and capability
  signatures, but the payload is mutated so digest and envelope signature
  both fail.
- ``test-vectors/dev-kid-1.pub.pem`` — envelope-signing public key.
- ``test-vectors/dev-issuer-1.pub.pem`` — capability-issuing public key.

The vectors are illustrative; no test loads them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
from datetime import UTC, datetime

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Deterministic 32-byte seeds derived from tag strings so the tags can be
# edited without breaking Ed25519PrivateKey.from_private_bytes' length
# requirement.
_SIGNER_SEED = hashlib.sha256(b"walkietalkie-phase0-test-vectors").digest()
_ISSUER_SEED = hashlib.sha256(b"walkietalkie-phase0-cap-issuer-vectors").digest()

_ENVELOPE_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_ISSUER_IDENTITY = "spiffe://mesh/cap-issuer-1"
_ISSUER_KID = "dev-issuer-kid-1"
_SENDER = "spiffe://mesh/ns-a/service-a"
_RECIPIENT = "spiffe://mesh/ns-b/service-b"
_PURPOSE = "invoke_tool"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _mint_capability_token(issuer_priv: Ed25519PrivateKey, payload_digest: str) -> str:
    header = {"alg": "EdDSA", "typ": "wt-cap+jwt", "kid": _ISSUER_KID}
    now_epoch = int(_ENVELOPE_NOW.timestamp())
    payload = {
        "iss": _ISSUER_IDENTITY,
        "sub": _SENDER,
        "aud": _RECIPIENT,
        "scope": _PURPOSE,
        "iat": now_epoch - 30,
        "nbf": now_epoch - 30,
        "exp": now_epoch + 240,
        "jti": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2",
        "cnf": {"envelope_digest": payload_digest},
    }
    h = _b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p = _b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = _b64u(issuer_priv.sign((h + "." + p).encode("ascii")))
    return f"{h}.{p}.{sig}"


def _build_envelope(target: str, capability_token: str) -> dict:
    envelope = {
        "version": "v0",
        "message_id": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1",
        "sender_spiffe_id": _SENDER,
        "recipient_spiffe_id": _RECIPIENT,
        "issued_at": "2026-04-14T12:00:00Z",
        "expires_at": "2026-04-14T12:05:00Z",
        "nonce": "nonce-000000000001",
        "capability_token": capability_token,
        "purpose_of_use": _PURPOSE,
        "kid": "dev-kid-1",
        "alg": "Ed25519",
        "payload": {"tool": "ping", "args": {"target": target}},
    }
    envelope["payload_digest"] = hashlib.sha256(jcs.canonicalize(envelope["payload"])).hexdigest()
    return envelope


def main() -> None:
    signer_priv = Ed25519PrivateKey.from_private_bytes(_SIGNER_SEED)
    issuer_priv = Ed25519PrivateKey.from_private_bytes(_ISSUER_SEED)
    here = pathlib.Path(__file__).parent
    out = here / "test-vectors"

    # The valid vector binds a real cap token to its own payload_digest.
    digest_for_token = hashlib.sha256(
        jcs.canonicalize({"tool": "ping", "args": {"target": "node-1"}})
    ).hexdigest()
    capability_token = _mint_capability_token(issuer_priv, digest_for_token)

    valid = _build_envelope("node-1", capability_token)
    unsigned = {k: v for k, v in valid.items()}
    signing_input = jcs.canonicalize(unsigned)
    signature = _b64u(signer_priv.sign(signing_input))
    valid["signature"] = signature
    (out / "valid-envelope.json").write_text(json.dumps(valid, indent=2) + "\n")

    # Tampered vector reuses the valid signatures but mutates the payload, so
    # both the envelope digest check and the cnf.envelope_digest binding fail.
    tampered = _build_envelope("node-1", capability_token)
    tampered["signature"] = signature
    tampered["payload"] = {"tool": "ping", "args": {"target": "node-2"}}
    (out / "tampered-envelope.json").write_text(json.dumps(tampered, indent=2) + "\n")

    signer_pub_pem = signer_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    issuer_pub_pem = issuer_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (out / "dev-kid-1.pub.pem").write_bytes(signer_pub_pem)
    (out / "dev-issuer-1.pub.pem").write_bytes(issuer_pub_pem)


if __name__ == "__main__":
    main()
