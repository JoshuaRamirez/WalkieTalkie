"""Example MCP host wired with the WalkieTalkie substrate (Phase 4 D4.2).

Closes Phase 4 D4.2 ("Example MCP Host") — the minimum runnable
demonstration that the substrate primitives compose into a working
MCP-shaped system inside one process. There is no networking; the
host accepts envelope dicts in memory and returns envelope dicts in
memory. Adding a transport (HTTP / WebSocket / stdio) is the
operator's job and is intentionally out of scope.

What this host wires:

1. Inbound envelope -> :func:`verify_envelope.verify_envelope`
   (signature, time window, replay, capability binding, audit emit).
2. Verified envelope -> :func:`envelope_adapter.unwrap_request`
   producing an :class:`envelope_adapter.MCPRequest`.
3. The request's ``method`` is looked up in :attr:`ExampleMCPHost.tools`
   and run through :func:`tool_policy_gate.evaluate_tool_call`.
4. The tool's result is rendered to text, scanned via
   :func:`output_scanning.scan`, and gated by
   :class:`egress_policy.MatrixEgressPolicy`.
5. The reply is wrapped in a signed envelope returned to the caller.
6. Every decision emits a hash-chained audit event.

Two demo tools:
- ``read_file`` — :class:`tool_policy_gate.RiskTier.LOW`. No step-up.
  Returns a stub file body so the egress scan has real text to look at.
- ``exec_sql`` — :class:`tool_policy_gate.RiskTier.CRITICAL`. Requires
  step-up. Returns a stub row payload for demo purposes.

Hard 500-line ceiling per Phase 4 §6 acceptance criterion #4. If you
catch yourself thinking "this needs an Observability layer / a
distributed cache / a retry policy" — that's Phase 5. Stop and
revisit DEFERRED.md.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import jcs
from audit import AuditSink, InMemoryAuditSink
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from data_classification import DataClass
from demo_tools import DEMO_TOOLS
from egress_policy import EgressAction, EgressPolicy
from envelope_adapter import (
    EnvelopeFields,
    MCPRequest,
    MCPResponse,
    build_envelope,
    mcp_response_to_payload,
    sign_envelope,
    unwrap_request,
)
from host_support import (
    derive_reply_id,
    derive_reply_nonce,
    exc_reason_code,
    request_id_from_envelope,
)
from output_scanning import PatternRegistry, scan
from rate_limiter import IdentityRateLimiter
from revocation_list import RevocationList
from tool_policy_gate import (
    StepUpAttestation,
    ToolCall,
    ToolPolicy,
    evaluate_tool_call,
)
from verify_envelope import (
    EnvelopeVerificationError,
    ReplayCache,
    VerificationConfig,
    verify_envelope,
)

# JSON-RPC 2.0 standard error codes used in our error replies.
_JSONRPC_INVALID_REQUEST = -32600
_JSONRPC_METHOD_NOT_FOUND = -32601
_JSONRPC_INTERNAL_ERROR = -32603

# Application-level error codes for substrate denials.
_APP_ENVELOPE_DENIED = -32001
_APP_TOOL_DENIED = -32002
_APP_EGRESS_DENIED = -32003
_APP_RATE_LIMITED = -32004


class ExampleMCPHostError(RuntimeError):
    """Raised when host configuration is invalid."""


@dataclass
class HostConfig:
    """Operator-supplied wiring for the example host.

    Trust stores / policies / sinks are objects the operator
    constructs from the substrate primitives. The host does not
    invent any of them; it just runs the verified flow.
    """

    host_iss: str
    host_kid: str
    host_signing_key: Ed25519PrivateKey
    key_lookup: Callable[[str], bytes]
    issuer_lookup: Callable[[str, str], bytes]
    replay_cache: ReplayCache
    tool_policy: ToolPolicy
    egress_policy: EgressPolicy
    audit_sink: AuditSink = field(default_factory=InMemoryAuditSink)
    verify_config: VerificationConfig = field(default_factory=VerificationConfig)
    # Optional per-identity rate limiter, checked POST-auth on the
    # authenticated sender (see the step-1b comment in handle()).
    rate_limiter: IdentityRateLimiter | None = None
    # Optional capability-revocation list threaded into verify_envelope;
    # a revoked jti is rejected with CAP_REVOKED.
    revocation_list: RevocationList | None = None
    output_data_class: DataClass = DataClass.INTERNAL
    pattern_registry: PatternRegistry = field(
        default_factory=PatternRegistry.builtin
    )
    reply_ttl: timedelta = field(default_factory=lambda: timedelta(minutes=5))
    capability_token_for_reply: str = "reply"
    # When set, replies carry a REAL capability token bound to the
    # reply's payload digest (input: hex digest, output: token). This
    # makes the reply verifiable end-to-end via verify_envelope.
    reply_capability_minter: Callable[[str], str] | None = None
    reply_purpose: str = "invoke_tool"

    def __post_init__(self) -> None:
        if not self.host_iss or not self.host_kid:
            raise ExampleMCPHostError(
                "host_iss and host_kid must be non-empty strings"
            )


@dataclass(frozen=True)
class HandleOptions:
    """Per-request overrides that the caller supplies alongside the envelope."""

    now: datetime | None = None
    step_up: StepUpAttestation | None = None
    reply_message_id: str = ""
    reply_nonce: str = ""


# ---------------------------------------------------------------------
# The host
# ---------------------------------------------------------------------


class ExampleMCPHost:
    """Single-process MCP host wired with the substrate."""

    def __init__(
        self,
        config: HostConfig,
        *,
        tools: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] | None = None,
    ) -> None:
        self.config = config
        self.tools = tools if tools is not None else dict(DEMO_TOOLS)

    # ----- API -----

    def handle(
        self,
        envelope: dict[str, Any],
        *,
        options: HandleOptions | None = None,
    ) -> dict[str, Any]:
        """Process one inbound envelope and return a signed reply envelope.

        Failures at any substrate gate (envelope verify, tool gate,
        egress) produce a *signed* JSON-RPC error reply rather than
        propagating an exception. This way a peer always gets a
        verifiable, well-formed response, and the host's invariants
        (sign every reply, audit every decision) hold without special
        cases for the sad path.

        The envelope-verification path itself emits its own audit
        event via the verifier; tool-gate and egress-gate decisions
        emit additional events here.
        """
        opts = options or HandleOptions()
        now = (opts.now or datetime.now(UTC)).astimezone(UTC)

        # Step 1: envelope verification (signature, time window, replay,
        # capability binding, and — with a revocation_list — the
        # revoked-jti check that raises CAP_REVOKED).
        try:
            verify_envelope(
                envelope,
                key_lookup=self.config.key_lookup,
                issuer_lookup=self.config.issuer_lookup,
                replay_cache=self.config.replay_cache,
                config=self.config.verify_config,
                now=now,
                audit_sink=self.config.audit_sink,
                revocation_list=self.config.revocation_list,
            )
        except EnvelopeVerificationError as exc:
            return self._error_reply(
                envelope=envelope,
                request_id=request_id_from_envelope(envelope),
                code=_APP_ENVELOPE_DENIED,
                message=f"envelope denied: {exc}",
                reason_code=exc_reason_code(exc),
                now=now,
                opts=opts,
            )

        # Step 1b: post-auth rate limit. Runs on the AUTHENTICATED sender
        # so a spoofed sender_spiffe_id (rejected above) never reaches
        # here and cannot burn a victim's allowance.
        if self.config.rate_limiter is not None:
            rl = self.config.rate_limiter.check(
                envelope["sender_spiffe_id"], now=now
            )
            self._emit(
                event_type="rate_limit.check",
                outcome="allow" if rl.allowed else "deny",
                reason=rl.reason,
                reason_code="rate_limited" if not rl.allowed else "ok",
                envelope=envelope,
            )
            if not rl.allowed:
                return self._error_reply(
                    envelope=envelope,
                    request_id=request_id_from_envelope(envelope),
                    code=_APP_RATE_LIMITED,
                    message=f"rate limited: {rl.reason}",
                    reason_code="rate_limited",
                    now=now,
                    opts=opts,
                )

        # Step 2: unwrap to MCP request.
        try:
            req = unwrap_request(envelope)
        except Exception as exc:  # noqa: BLE001 — translation failure
            return self._error_reply(
                envelope=envelope,
                request_id=request_id_from_envelope(envelope),
                code=_JSONRPC_INVALID_REQUEST,
                message=f"payload is not a JSON-RPC request: {exc}",
                reason_code="invalid_request",
                now=now,
                opts=opts,
            )

        # Step 3: tool gate.
        tool_decision = self._tool_gate(
            req=req,
            envelope=envelope,
            now=now,
            opts=opts,
        )
        if not tool_decision.allowed:
            return self._error_reply(
                envelope=envelope,
                request_id=req.id,
                code=_APP_TOOL_DENIED,
                message=f"tool gate: {tool_decision.reason}",
                reason_code=tool_decision.reason_code,
                now=now,
                opts=opts,
            )

        # Step 4: dispatch.
        tool = self.tools.get(req.method)
        if tool is None:
            # Defensive — should not happen because the tool gate
            # already validated the name against ToolPolicy. Belt-
            # and-braces.
            return self._error_reply(
                envelope=envelope,
                request_id=req.id,
                code=_JSONRPC_METHOD_NOT_FOUND,
                message=f"tool not registered: {req.method!r}",
                reason_code="tool_not_registered",
                now=now,
                opts=opts,
            )
        try:
            result = tool(req.params if isinstance(req.params, dict) else {})
        except Exception as exc:  # noqa: BLE001 — tool body is operator-supplied
            return self._error_reply(
                envelope=envelope,
                request_id=req.id,
                code=_JSONRPC_INTERNAL_ERROR,
                message=f"tool raised: {exc}",
                reason_code="tool_exception",
                now=now,
                opts=opts,
            )

        # Step 5: output scan + egress gate.
        rendered = json.dumps(result, sort_keys=True, separators=(",", ":"))
        scan_result = scan(rendered, registry=self.config.pattern_registry)
        egress_decision = self.config.egress_policy.evaluate(
            risk=scan_result.risk, data_class=self.config.output_data_class
        )
        self._emit(
            event_type="egress.evaluate",
            outcome="allow" if egress_decision.action is EgressAction.ALLOW else "deny",
            reason=egress_decision.reason,
            reason_code=egress_decision.reason_code,
            envelope=envelope,
        )
        if egress_decision.action is not EgressAction.ALLOW:
            return self._error_reply(
                envelope=envelope,
                request_id=req.id,
                code=_APP_EGRESS_DENIED,
                message=f"egress denied: {egress_decision.reason}",
                reason_code=egress_decision.reason_code,
                now=now,
                opts=opts,
            )

        # Step 6: success reply.
        resp = MCPResponse(id=req.id, result=result)
        return self._reply_envelope(
            envelope=envelope,
            response=resp,
            now=now,
            opts=opts,
        )

    # ----- internals -----

    def _tool_gate(
        self,
        *,
        req: MCPRequest,
        envelope: dict[str, Any],
        now: datetime,
        opts: HandleOptions,
    ):
        args_digest = hashlib.sha256(
            jcs.canonicalize(req.params if isinstance(req.params, dict) else {})
        ).hexdigest()
        call = ToolCall(
            tool_name=req.method,
            caller_iss=envelope["sender_spiffe_id"],
            arguments_digest=args_digest,
        )
        decision = evaluate_tool_call(
            call=call,
            policy=self.config.tool_policy,
            step_up=opts.step_up,
            issuer_lookup=self.config.issuer_lookup,
            current=now,
        )
        self._emit(
            event_type="tool.gate",
            outcome="allow" if decision.allowed else "deny",
            reason=decision.reason,
            reason_code=decision.reason_code,
            envelope=envelope,
        )
        return decision

    def _reply_envelope(
        self,
        *,
        envelope: dict[str, Any],
        response: MCPResponse,
        now: datetime,
        opts: HandleOptions,
    ) -> dict[str, Any]:
        payload = mcp_response_to_payload(response)
        # If the operator wired a minter, attach a real capability
        # token bound to the reply's payload digest so the reply is
        # verifiable end-to-end through verify_envelope. Otherwise
        # fall back to the placeholder string (the original peer
        # may then choose to skip cap-token validation on replies).
        if self.config.reply_capability_minter is not None:
            payload_digest = hashlib.sha256(jcs.canonicalize(payload)).hexdigest()
            cap_token = self.config.reply_capability_minter(payload_digest)
        else:
            cap_token = self.config.capability_token_for_reply
        fields = EnvelopeFields(
            sender_spiffe_id=self.config.host_iss,
            recipient_spiffe_id=envelope["sender_spiffe_id"],
            purpose_of_use=self.config.reply_purpose,
            kid=self.config.host_kid,
            capability_token=cap_token,
            message_id=opts.reply_message_id or derive_reply_id(envelope),
            nonce=opts.reply_nonce or derive_reply_nonce(envelope),
            issued_at=now,
            ttl=self.config.reply_ttl,
        )
        return sign_envelope(
            build_envelope(payload=payload, fields=fields),
            self.config.host_signing_key,
        )

    def _error_reply(
        self,
        *,
        envelope: dict[str, Any],
        request_id: int | str | None,
        code: int,
        message: str,
        reason_code: str,
        now: datetime,
        opts: HandleOptions,
    ) -> dict[str, Any]:
        # Audit the host's own decision (the verifier already emitted
        # its own envelope.verify event when applicable).
        self._emit(
            event_type="host.deny",
            outcome="deny",
            reason=message,
            reason_code=reason_code,
            envelope=envelope,
        )
        sender = envelope.get("sender_spiffe_id") if isinstance(envelope, dict) else None
        if not sender:
            # We have no recipient to address the reply to. Surface
            # the error to the operator via a raise — we cannot
            # construct a valid signed envelope without a recipient.
            raise ExampleMCPHostError(
                f"cannot build error reply: envelope missing sender ({message})"
            )
        resp = MCPResponse(
            id=request_id,
            error={"code": code, "message": message},
        )
        return self._reply_envelope(
            envelope=envelope, response=resp, now=now, opts=opts
        )

    def _emit(
        self,
        *,
        event_type: str,
        outcome: str,
        reason: str,
        reason_code: str,
        envelope: dict[str, Any],
    ) -> None:
        env = envelope if isinstance(envelope, dict) else {}
        self.config.audit_sink.record(
            event_type=event_type,
            outcome=outcome,
            reason=reason,
            reason_code=reason_code,
            message_id=str(env.get("message_id", "")),
            sender=str(env.get("sender_spiffe_id", "")),
            recipient=str(env.get("recipient_spiffe_id", "")),
            envelope_kid=str(env.get("kid", "")),
        )


__all__ = [
    "DEMO_TOOLS",
    "ExampleMCPHost",
    "ExampleMCPHostError",
    "HandleOptions",
    "HostConfig",
]
