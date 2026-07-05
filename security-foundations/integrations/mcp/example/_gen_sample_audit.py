"""Regenerate ``sample-audit.jsonl`` from the deterministic example keys.

A standalone dev helper, not a test. Loads the example trust stores
written by ``gen_keys.py``, drives one happy-path envelope round
trip through :class:`host.ExampleMCPHost`, and writes the resulting
audit chain to ``sample-audit.jsonl``. Operators following the
runbook can compare their local audit output against this file as a
"did the substrate accept my setup?" smoke check.

Usage::

    python security-foundations/integrations/mcp/example/gen_keys.py
    python security-foundations/integrations/mcp/example/_gen_sample_audit.py
"""

from __future__ import annotations

import hashlib
import pathlib
import sys
from datetime import UTC, datetime, timedelta

import jcs
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE.parent))
sys.path.insert(0, str(_HERE.parent.parent.parent / "envelope"))

from audit import AuditEvent, JsonlAuditSink  # noqa: E402
from capability_issuer import CapabilityIssuer  # noqa: E402
from data_classification import DataClass  # noqa: E402
from egress_policy import EgressAction, EgressMatrixCell, MatrixEgressPolicy  # noqa: E402
from envelope_adapter import (  # noqa: E402
    EnvelopeFields,
    MCPRequest,
    build_envelope,
    mcp_request_to_payload,
    sign_envelope,
)
from host import ExampleMCPHost, HandleOptions, HostConfig  # noqa: E402
from issuance_policy import AllowlistPolicy  # noqa: E402
from issuer_trust_store import IssuerTrustStore  # noqa: E402
from output_scanning import PatternRegistry, RiskLevel  # noqa: E402
from tool_policy_gate import RiskTier, ToolPolicy, ToolRule  # noqa: E402
from trust_store import FileSystemTrustStore  # noqa: E402
from verify_envelope import InMemoryReplayCache  # noqa: E402

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_CLIENT_ISS = "spiffe://mesh.example/ns-client/agent-1"
_CLIENT_KID = "client-kid-1"
_HOST_ISS = "spiffe://mesh.example/ns-host/server-1"
_HOST_KID = "host-kid-1"
_ISSUER_ISS = "spiffe://mesh.example/ns-iss/cap-issuer-1"
_ISSUER_KID = "issuer-kid-1"


def _load_priv(name: str) -> Ed25519PrivateKey:
    pem = (_HERE / f"{name}-priv.pem").read_bytes()
    key = serialization.load_pem_private_key(pem, password=None)
    assert isinstance(key, Ed25519PrivateKey)
    return key


def main() -> None:
    client_priv = _load_priv("client")
    host_priv = _load_priv("host")
    issuer_priv = _load_priv("issuer")

    workload_store = FileSystemTrustStore.from_manifest(
        _HERE / "workload-manifest.json"
    )
    issuer_store = IssuerTrustStore.from_manifest(_HERE / "issuer-manifest.json")

    audit_path = _HERE / "sample-audit.jsonl"
    if audit_path.exists():
        audit_path.unlink()

    class _DeterministicJsonlAuditSink(JsonlAuditSink):
        """Forces every event's timestamp to ``_NOW`` so re-running
        the generator leaves the working tree clean."""

        def record(self, **kwargs) -> AuditEvent:  # type: ignore[override]
            kwargs["timestamp"] = _NOW
            return super().record(**kwargs)

    audit_sink = _DeterministicJsonlAuditSink(audit_path)

    issuer = CapabilityIssuer(
        iss=_ISSUER_ISS,
        kid=_ISSUER_KID,
        signing_key=issuer_priv,
        default_ttl=timedelta(minutes=5),
        clock_skew=timedelta(seconds=30),
        audit_sink=audit_sink,
        policy=AllowlistPolicy(
            allowed_grants=frozenset(
                {
                    (_CLIENT_ISS, _HOST_ISS, "invoke_tool"),
                    (_HOST_ISS, _CLIENT_ISS, "invoke_tool"),
                }
            ),
            max_ttl=timedelta(minutes=5),
        ),
    )

    tool_policy = ToolPolicy(
        rules=(
            ToolRule(
                tool_name="read_file",
                risk_tier=RiskTier.LOW,
                allowed_callers=frozenset({_CLIENT_ISS}),
            ),
        )
    )
    egress_policy = MatrixEgressPolicy(
        cells=(
            EgressMatrixCell(
                risk=RiskLevel.NONE,
                data_class=DataClass.INTERNAL,
                action=EgressAction.ALLOW,
            ),
        )
    )

    host = ExampleMCPHost(
        HostConfig(
            host_iss=_HOST_ISS,
            host_kid=_HOST_KID,
            host_signing_key=host_priv,
            key_lookup=workload_store,
            issuer_lookup=issuer_store,
            replay_cache=InMemoryReplayCache(),
            tool_policy=tool_policy,
            egress_policy=egress_policy,
            audit_sink=audit_sink,
            output_data_class=DataClass.INTERNAL,
            pattern_registry=PatternRegistry.builtin(),
            reply_capability_minter=lambda digest: issuer.issue(
                sub=_HOST_ISS,
                aud=_CLIENT_ISS,
                scope="invoke_tool",
                envelope_digest=digest,
                now=_NOW,
            ),
        )
    )

    payload = mcp_request_to_payload(
        MCPRequest(method="read_file", params={"path": "/etc/motd"}, id=1)
    )
    payload_digest = hashlib.sha256(jcs.canonicalize(payload)).hexdigest()
    cap_token = issuer.issue(
        sub=_CLIENT_ISS,
        aud=_HOST_ISS,
        scope="invoke_tool",
        envelope_digest=payload_digest,
        now=_NOW,
    )
    envelope = sign_envelope(
        build_envelope(
            payload=payload,
            fields=EnvelopeFields(
                sender_spiffe_id=_CLIENT_ISS,
                recipient_spiffe_id=_HOST_ISS,
                purpose_of_use="invoke_tool",
                kid=_CLIENT_KID,
                capability_token=cap_token,
                message_id="01900000-0000-7000-8000-aaaaaaaaaaa1",
                nonce="client-nonce-sample0001",
                issued_at=_NOW,
                ttl=timedelta(minutes=5),
            ),
        ),
        client_priv,
    )
    host.handle(envelope, options=HandleOptions(now=_NOW))
    print(f"wrote {audit_path}")


if __name__ == "__main__":
    main()
