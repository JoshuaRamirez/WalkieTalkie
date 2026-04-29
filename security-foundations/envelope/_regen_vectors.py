"""Dev-time helper that regenerates the envelope test vectors under JCS.

Usage::

    python -m envelope._regen_vectors            # from repo root, with -e install
    python security-foundations/envelope/_regen_vectors.py

The script writes ``test-vectors/valid-envelope.json`` (verifies cleanly
against the embedded private key) and ``test-vectors/tampered-envelope.json``
(same signature, payload mutated, so digest and signature both fail).
The vectors are illustrative; no test loads them.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# Deterministic seed so regeneration is reproducible.
_SEED = b"walkietalkie-phase0-test-vectors"


def _build_envelope(target: str) -> dict:
    envelope = {
        "version": "v0",
        "message_id": "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c1",
        "sender_spiffe_id": "spiffe://mesh/ns-a/service-a",
        "recipient_spiffe_id": "spiffe://mesh/ns-b/service-b",
        "issued_at": "2026-04-14T12:00:00Z",
        "expires_at": "2026-04-14T12:05:00Z",
        "nonce": "nonce-000000000001",
        "capability_token": "cap-token-1",
        "purpose_of_use": "invoke_tool",
        "kid": "dev-kid-1",
        "alg": "Ed25519",
        "payload": {"tool": "ping", "args": {"target": target}},
    }
    envelope["payload_digest"] = hashlib.sha256(jcs.canonicalize(envelope["payload"])).hexdigest()
    return envelope


def main() -> None:
    private_key = Ed25519PrivateKey.from_private_bytes(_SEED)
    here = pathlib.Path(__file__).parent
    out = here / "test-vectors"

    valid = _build_envelope("node-1")
    unsigned = {k: v for k, v in valid.items()}
    signing_input = jcs.canonicalize(unsigned)
    signature = base64.urlsafe_b64encode(private_key.sign(signing_input)).rstrip(b"=").decode("ascii")
    valid["signature"] = signature
    (out / "valid-envelope.json").write_text(json.dumps(valid, indent=2) + "\n")

    tampered = _build_envelope("node-1")
    tampered["signature"] = signature
    tampered["payload"] = {"tool": "ping", "args": {"target": "node-2"}}
    (out / "tampered-envelope.json").write_text(json.dumps(tampered, indent=2) + "\n")

    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (out / "dev-kid-1.pub.pem").write_bytes(pub_pem)


if __name__ == "__main__":
    main()
