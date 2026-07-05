"""Generate identities + a shared trust manifest for the mesh MCP bridge.

Each named agent gets two Ed25519 keypairs:

- an **envelope** key (signs the message envelope; identified by ``env_kid``),
- an **issuer** key (mints the per-message capability token; identified by
  ``issuer_iss`` / ``issuer_kid``).

A single shared ``trust.json`` holds every agent's *public* material so any
agent can verify any other (symmetric peer-to-peer — no shared secret). Each
agent's *private* material lands in ``<name>.private.json``, read only by that
agent's bridge process.

Usage:
    python gen_bridge_config.py --out ./mesh-config --agents alice bob

Re-running is idempotent per name only if you delete the dir first; by
default it refuses to clobber an existing config so you don't rotate keys
out from under a running pair.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_TRUST_DOMAIN = "mesh.local"


def _priv_pem(key: Ed25519PrivateKey) -> str:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def _pub_pem(key: Ed25519PrivateKey) -> str:
    return (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )


def generate(out_dir: pathlib.Path, names: list[str]) -> None:
    if out_dir.exists() and any(out_dir.iterdir()):
        raise SystemExit(
            f"refusing to clobber non-empty config dir {out_dir} — "
            f"delete it first to rotate keys"
        )
    out_dir.mkdir(parents=True, exist_ok=True)

    agents_public: dict[str, dict] = {}
    for name in names:
        if not name.isalnum():
            raise SystemExit(f"agent name must be alphanumeric: {name!r}")
        env_key = Ed25519PrivateKey.generate()
        iss_key = Ed25519PrivateKey.generate()

        spiffe_id = f"spiffe://{_TRUST_DOMAIN}/{name}"
        env_kid = f"{name}-env"
        issuer_iss = f"spiffe://{_TRUST_DOMAIN}/{name}/issuer"
        issuer_kid = f"{name}-iss"

        agents_public[name] = {
            "spiffe_id": spiffe_id,
            "env_kid": env_kid,
            "env_pub_pem": _pub_pem(env_key),
            "issuer_iss": issuer_iss,
            "issuer_kid": issuer_kid,
            "issuer_pub_pem": _pub_pem(iss_key),
        }

        private = {
            "name": name,
            "env_priv_pem": _priv_pem(env_key),
            "issuer_priv_pem": _priv_pem(iss_key),
        }
        priv_path = out_dir / f"{name}.private.json"
        priv_path.write_text(json.dumps(private, indent=2))
        priv_path.chmod(0o600)
        print(f"  wrote {priv_path}  (private — keep secret)", file=sys.stderr)

    trust = {"trust_domain": _TRUST_DOMAIN, "agents": agents_public}
    trust_path = out_dir / "trust.json"
    trust_path.write_text(json.dumps(trust, indent=2))
    print(f"  wrote {trust_path}  (shared public trust manifest)", file=sys.stderr)
    print(f"\nGenerated {len(names)} identities in {out_dir}", file=sys.stderr)


# Default home: user-scoped ~/.claude/mesh so two local Claude instances
# share one discovery/trust/mailbox location out of the box. It MUST be a
# shared, user-scoped dir (not a per-project .claude) because the two
# bridges rendezvous through it — and private keys must never live in a
# git-tracked project dir.
DEFAULT_CONFIG_DIR = pathlib.Path.home() / ".claude" / "mesh"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--out", type=pathlib.Path, default=DEFAULT_CONFIG_DIR,
        help=f"config dir (default: {DEFAULT_CONFIG_DIR})",
    )
    ap.add_argument(
        "--agents", nargs="+", default=["alice", "bob"], help="agent names"
    )
    args = ap.parse_args()
    generate(args.out, args.agents)


if __name__ == "__main__":
    main()
