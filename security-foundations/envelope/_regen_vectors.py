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
- ``test-vectors/valid-discovery-record.json`` — Phase 1 hangover
  vector that verifies cleanly under the embedded issuer key.
- ``test-vectors/tampered-discovery-record.json`` — same signature
  with mutated endpoints so signature verification fails.
- ``test-vectors/dev-kid-1.pub.pem`` — envelope-signing public key.
- ``test-vectors/dev-issuer-1.pub.pem`` — capability-issuing /
  discovery-signing public key.

The envelope vectors are illustrative; ``test_discovery_test_vectors``
loads the discovery vectors and asserts they stay coherent with the
verifier.
"""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib
from datetime import UTC, datetime, timedelta

import jcs
from capability_issuer import CapabilityIssuer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from discovery_record import DiscoveryRecord, sign_record
from discovery_record import to_json as discovery_to_json

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

# Deterministic jti so the regenerated vectors are reproducible.
_FIXED_JTI = "0195f66a-0e14-7f0f-a5aa-0d7f3b6f08c2"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


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
    issuer = CapabilityIssuer(
        iss=_ISSUER_IDENTITY,
        kid=_ISSUER_KID,
        signing_key=issuer_priv,
        default_ttl=timedelta(minutes=4, seconds=30),
        clock_skew=timedelta(seconds=30),
    )
    here = pathlib.Path(__file__).parent
    out = here / "test-vectors"

    # The valid vector binds a real cap token to its own payload_digest.
    digest_for_token = hashlib.sha256(
        jcs.canonicalize({"tool": "ping", "args": {"target": "node-1"}})
    ).hexdigest()
    capability_token = issuer.issue(
        sub=_SENDER,
        aud=_RECIPIENT,
        scope=_PURPOSE,
        envelope_digest=digest_for_token,
        jti=_FIXED_JTI,
        now=_ENVELOPE_NOW,
    )

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

    # ---- Discovery records ----
    # The discovery issuer reuses the cap-issuer's keypair — the trust
    # pool is the same one operators load via IssuerTrustStore.
    valid_disco = DiscoveryRecord(
        version="v0",
        workload_iss=_SENDER,
        workload_kid="dev-kid-1",
        endpoints=("tls://service-a.mesh.example:4443",),
        issuer_iss=_ISSUER_IDENTITY,
        issuer_kid=_ISSUER_KID,
        issued_at="2026-04-14T12:00:00Z",
        expires_at="2026-04-14T12:30:00Z",
    )
    signed_disco = sign_record(valid_disco, issuer_priv)
    (out / "valid-discovery-record.json").write_bytes(
        discovery_to_json(signed_disco)
    )

    # Tampered vector reuses the valid signature but mutates the
    # endpoints — the signature check fails because the canonical
    # body no longer matches what was signed.
    tampered_disco = DiscoveryRecord(
        version=valid_disco.version,
        workload_iss=valid_disco.workload_iss,
        workload_kid=valid_disco.workload_kid,
        endpoints=("tls://attacker.example:4443",),  # mutated
        issuer_iss=valid_disco.issuer_iss,
        issuer_kid=valid_disco.issuer_kid,
        issued_at=valid_disco.issued_at,
        expires_at=valid_disco.expires_at,
        signature=signed_disco.signature,
    )
    (out / "tampered-discovery-record.json").write_bytes(
        discovery_to_json(tampered_disco)
    )


if __name__ == "__main__":
    main()
