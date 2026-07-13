"""Generate the example MCP host's keypairs and trust-store manifests.

Phase 4 D4.4 helper. Mints three deterministic Ed25519 keypairs
(client, host, capability issuer), writes their public PEMs, writes
a ``FileSystemTrustStore`` manifest and an ``IssuerTrustStore``
manifest, and saves the client + host + issuer PRIVATE PEMs for the
sender side. Re-running this script regenerates everything
identically — re-runs leave the working tree clean.

Usage from the repo root::

    python security-foundations/integrations/mcp/example/gen_keys.py

Writes into the same directory as this script::

    client-priv.pem      client-pub.pem
    host-priv.pem        host-pub.pem
    issuer-priv.pem      issuer-pub.pem
    workload-manifest.json   (consumed by FileSystemTrustStore.from_manifest)
    issuer-manifest.json     (consumed by IssuerTrustStore.from_manifest)

These files are *demo material only*. Real deployments use HSM- or
KMS-backed key generation; the script is here so an operator can
reproduce the smoke test from a clean ``git clone`` in well under
the 15-minute Phase 4 §6 acceptance criterion.
"""

from __future__ import annotations

import hashlib
import json
import pathlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

CLIENT_ISS = "spiffe://mesh.example/ns-client/agent-1"
CLIENT_KID = "client-kid-1"
HOST_ISS = "spiffe://mesh.example/ns-host/server-1"
HOST_KID = "host-kid-1"
ISSUER_ISS = "spiffe://mesh.example/ns-iss/cap-issuer-1"
ISSUER_KID = "issuer-kid-1"


def _seed(label: str) -> bytes:
    return hashlib.sha256(f"walkietalkie-phase4-example::{label}".encode()).digest()


def _mint(out: pathlib.Path, label: str) -> Ed25519PrivateKey:
    priv = Ed25519PrivateKey.from_private_bytes(_seed(label))
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (out / f"{label}-priv.pem").write_bytes(priv_pem)
    (out / f"{label}-pub.pem").write_bytes(pub_pem)
    return priv


def main() -> None:
    out = pathlib.Path(__file__).resolve().parent
    out.mkdir(parents=True, exist_ok=True)

    _mint(out, "client")
    _mint(out, "host")
    _mint(out, "issuer")

    workload_manifest = {
        "keys": [
            {"kid": CLIENT_KID, "pem_path": "client-pub.pem"},
            {"kid": HOST_KID, "pem_path": "host-pub.pem"},
        ]
    }
    issuer_manifest = {
        "keys": [
            {
                "iss": ISSUER_ISS,
                "kid": ISSUER_KID,
                "pem_path": "issuer-pub.pem",
            }
        ]
    }
    (out / "workload-manifest.json").write_text(
        json.dumps(workload_manifest, indent=2) + "\n"
    )
    (out / "issuer-manifest.json").write_text(
        json.dumps(issuer_manifest, indent=2) + "\n"
    )

    print(f"wrote example trust material under {out}")


if __name__ == "__main__":
    main()
