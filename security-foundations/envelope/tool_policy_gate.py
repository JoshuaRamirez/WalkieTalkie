"""Tool policy gate v0 (Phase 2 Track D D2).

Closes D2 ("Tool Policy Gate"):

- "Runtime tool-call validation independent of model deliberation."
  The gate sits between the model's proposed tool call and the actual
  execution path. Its inputs are operator-configured (a
  :class:`ToolPolicy`) and out-of-band (a possibly-attached
  :class:`StepUpAttestation`); the model has no influence on the
  decision.
- "High-risk tools require step-up authorization path."
  :class:`ToolRule` carries a :class:`RiskTier` and a
  ``step_up_required`` flag (which defaults to ``True`` for the HIGH
  and CRITICAL tiers). When the flag is set, the gate refuses to
  release the call unless the caller supplies a valid, current, and
  call-bound :class:`StepUpAttestation` signed by an issuer in a
  separate :class:`IssuerTrustStore`-shaped trust pool.

A :class:`StepUpAttestation` is an EdDSA-signed, JCS-canonical record
with ``typ="wt-stepup/v0"`` cross-protocol binding. It carries:

- ``tool_name`` — the specific tool the attestation authorizes; the
  gate refuses anything else.
- ``caller_iss`` — the SPIFFE id the attestation authorizes; the gate
  refuses calls from any other workload even if their tool name matches.
- ``arguments_digest`` — hex sha256 of the call arguments the
  attestation was minted for. Binding the proof to the *exact*
  arguments prevents a stale attestation from being reused for a
  different, more dangerous, call.
- ``iat`` / ``nbf`` / ``exp`` — NumericDate window.
- ``jti`` — UUIDv7 (operators may use this for replay tracking outside
  the gate's scope).

Out of scope for v0
-------------------
- Step-up issuance flow / interactive prompts. The gate verifies a
  pre-existing attestation; how operators mint one (push-to-approve,
  hardware token, second-factor verifier) is a higher-level concern.
- Replay caching of attestation ``jti``. v0 enforces the time window
  and call binding; replay-within-window is the operator's concern
  (typically narrow ``[nbf, exp]`` windows + per-call ``jti``).
- Rate-limited step-up cool-downs (e.g. "you can only authorize 5
  CRITICAL calls per hour"). Compose with the existing
  :mod:`rate_limiter` if needed.
"""

from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum

import jcs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from deny_reason import DenyReason
from verify_envelope import (
    HEX_SHA256_RE,
    KID_RE,
    SPIFFE_ID_RE,
    UUID_V7_RE,
    EnvelopeVerificationError,
    decode_base64url,
    load_ed25519_public_key,
)

STEP_UP_TYP = "wt-stepup/v0"


class RiskTier(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_RISK_RANK = {
    RiskTier.LOW: 0,
    RiskTier.MEDIUM: 1,
    RiskTier.HIGH: 2,
    RiskTier.CRITICAL: 3,
}

# Risk tiers that imply step-up by default. Operators can override
# per rule.
_STEP_UP_BY_DEFAULT_AT = RiskTier.HIGH


class ToolPolicyError(ValueError):
    """Raised when tool policy inputs violate v0 invariants."""


class StepUpError(EnvelopeVerificationError):
    """Raised when a step-up attestation fails verification."""


@dataclass(frozen=True)
class ToolRule:
    tool_name: str
    risk_tier: RiskTier
    allowed_callers: frozenset[str] = field(default_factory=frozenset)
    step_up_required: bool | None = None  # None → auto from risk_tier

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str) or not self.tool_name:
            raise ToolPolicyError("tool_name must be a non-empty string")
        if not isinstance(self.risk_tier, RiskTier):
            raise ToolPolicyError(
                f"risk_tier must be a RiskTier: {self.risk_tier!r}"
            )
        if not isinstance(self.allowed_callers, frozenset):
            raise ToolPolicyError(
                "allowed_callers must be a frozenset of SPIFFE ids"
            )
        for caller in self.allowed_callers:
            if not isinstance(caller, str) or not SPIFFE_ID_RE.match(caller):
                raise ToolPolicyError(
                    f"invalid SPIFFE id in allowed_callers: {caller!r}"
                )
        if self.step_up_required is not None and not isinstance(
            self.step_up_required, bool
        ):
            raise ToolPolicyError(
                "step_up_required must be bool or None for auto"
            )

    @property
    def effective_step_up_required(self) -> bool:
        if self.step_up_required is not None:
            return self.step_up_required
        return _RISK_RANK[self.risk_tier] >= _RISK_RANK[_STEP_UP_BY_DEFAULT_AT]


@dataclass(frozen=True)
class ToolPolicy:
    """A closed allowlist of named tools.

    Tools not present in :attr:`rules` are denied at the gate; tools
    present must satisfy the rule (caller allowlist + step-up).
    """

    rules: tuple[ToolRule, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.rules, tuple):
            raise ToolPolicyError("rules must be a tuple")
        seen: set[str] = set()
        for index, rule in enumerate(self.rules):
            if not isinstance(rule, ToolRule):
                raise ToolPolicyError(f"rules[{index}] must be a ToolRule")
            if rule.tool_name in seen:
                raise ToolPolicyError(
                    f"duplicate tool_name: {rule.tool_name!r}"
                )
            seen.add(rule.tool_name)

    def rule_for(self, tool_name: str) -> ToolRule | None:
        for rule in self.rules:
            if rule.tool_name == tool_name:
                return rule
        return None


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    caller_iss: str
    arguments_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.tool_name, str) or not self.tool_name:
            raise ToolPolicyError("tool_name must be a non-empty string")
        if not isinstance(self.caller_iss, str) or not SPIFFE_ID_RE.match(
            self.caller_iss
        ):
            raise ToolPolicyError(f"invalid caller_iss: {self.caller_iss!r}")
        if not isinstance(self.arguments_digest, str) or not HEX_SHA256_RE.match(
            self.arguments_digest
        ):
            raise ToolPolicyError(
                f"arguments_digest must be hex sha256: {self.arguments_digest!r}"
            )


@dataclass(frozen=True)
class StepUpAttestation:
    """Out-of-band proof that step-up auth happened for a specific call."""

    tool_name: str
    caller_iss: str
    arguments_digest: str
    issuer_iss: str
    issuer_kid: str
    iat: int
    nbf: int
    exp: int
    jti: str
    signature: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


def _stepup_body(att: StepUpAttestation) -> bytes:
    body = {
        "typ": STEP_UP_TYP,
        "tool_name": att.tool_name,
        "caller_iss": att.caller_iss,
        "arguments_digest": att.arguments_digest,
        "issuer_iss": att.issuer_iss,
        "issuer_kid": att.issuer_kid,
        "iat": att.iat,
        "nbf": att.nbf,
        "exp": att.exp,
        "jti": att.jti,
    }
    return jcs.canonicalize(body)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_step_up(
    att: StepUpAttestation, signing_key: Ed25519PrivateKey
) -> StepUpAttestation:
    sig = _b64u(signing_key.sign(_stepup_body(att)))
    return dataclasses.replace(att, signature=sig)


def to_json(att: StepUpAttestation) -> bytes:
    return json.dumps(att.to_dict(), separators=(",", ":")).encode("utf-8")


def from_json(data: bytes) -> StepUpAttestation:
    try:
        obj = json.loads(data)
    except (ValueError, TypeError) as exc:
        raise StepUpError(
            "step-up attestation is not valid JSON",
            reason=DenyReason.TOOL_STEP_UP_MALFORMED,
        ) from exc
    if not isinstance(obj, dict):
        raise StepUpError(
            "step-up JSON must be an object",
            reason=DenyReason.TOOL_STEP_UP_MALFORMED,
        )
    required = {
        "tool_name", "caller_iss", "arguments_digest", "issuer_iss",
        "issuer_kid", "iat", "nbf", "exp", "jti", "signature",
    }
    missing = sorted(required - set(obj))
    if missing:
        raise StepUpError(
            f"missing required fields: {','.join(missing)}",
            reason=DenyReason.TOOL_STEP_UP_MALFORMED,
        )
    return StepUpAttestation(**{k: obj[k] for k in required})


def _malformed(msg: str) -> StepUpError:
    return StepUpError(msg, reason=DenyReason.TOOL_STEP_UP_MALFORMED)


def _validate_shape(att: StepUpAttestation) -> None:
    if not isinstance(att.tool_name, str) or not att.tool_name:
        raise _malformed("tool_name must be a non-empty string")
    if not isinstance(att.caller_iss, str) or not SPIFFE_ID_RE.match(att.caller_iss):
        raise _malformed(f"invalid caller_iss: {att.caller_iss!r}")
    if not isinstance(att.arguments_digest, str) or not HEX_SHA256_RE.match(
        att.arguments_digest
    ):
        raise _malformed(
            f"arguments_digest must be hex sha256: {att.arguments_digest!r}"
        )
    if not isinstance(att.issuer_iss, str) or not SPIFFE_ID_RE.match(att.issuer_iss):
        raise _malformed(f"invalid issuer_iss: {att.issuer_iss!r}")
    if not isinstance(att.issuer_kid, str) or not KID_RE.match(att.issuer_kid):
        raise _malformed(f"invalid issuer_kid: {att.issuer_kid!r}")
    if not isinstance(att.jti, str) or not UUID_V7_RE.match(att.jti):
        raise _malformed(f"jti must be UUIDv7: {att.jti!r}")
    for name, value in (("iat", att.iat), ("nbf", att.nbf), ("exp", att.exp)):
        if not isinstance(value, int) or isinstance(value, bool):
            raise _malformed(f"{name} must be a NumericDate (int)")
    if not isinstance(att.signature, str) or not att.signature:
        raise _malformed("signature must be a non-empty string")


def verify_step_up(
    att: StepUpAttestation,
    *,
    call: ToolCall,
    issuer_lookup: Callable[[str, str], bytes],
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_step_up_ttl: timedelta = timedelta(minutes=10),
) -> StepUpAttestation:
    """Validate shape, call-binding, time window, and signature.

    Returns the attestation on success. Raises :class:`StepUpError`
    with a distinct :class:`DenyReason` on every failure path.
    """
    _validate_shape(att)

    if att.tool_name != call.tool_name or att.caller_iss != call.caller_iss:
        raise StepUpError(
            (
                f"step-up does not bind to this call: "
                f"att=({att.tool_name!r}, {att.caller_iss!r}) "
                f"call=({call.tool_name!r}, {call.caller_iss!r})"
            ),
            reason=DenyReason.TOOL_STEP_UP_MISMATCH,
        )
    if att.arguments_digest != call.arguments_digest:
        raise StepUpError(
            "step-up arguments_digest does not match call",
            reason=DenyReason.TOOL_STEP_UP_MISMATCH,
        )

    if att.iat > att.nbf or att.nbf > att.exp:
        raise StepUpError(
            f"invalid validity window: iat={att.iat}, nbf={att.nbf}, exp={att.exp}",
            reason=DenyReason.TOOL_STEP_UP_MALFORMED,
        )
    ttl = timedelta(seconds=att.exp - att.nbf)
    if ttl > max_step_up_ttl:
        raise StepUpError(
            f"step-up TTL {ttl} exceeds maximum {max_step_up_ttl}",
            reason=DenyReason.TOOL_STEP_UP_MALFORMED,
        )

    nbf_dt = datetime.fromtimestamp(att.nbf, tz=UTC)
    exp_dt = datetime.fromtimestamp(att.exp, tz=UTC)
    current_utc = current.astimezone(UTC)
    if current_utc + max_clock_skew < nbf_dt:
        raise StepUpError(
            f"step-up not yet valid (nbf={nbf_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.TOOL_STEP_UP_EXPIRED,
        )
    if current_utc - max_clock_skew > exp_dt:
        raise StepUpError(
            f"step-up expired (exp={exp_dt.isoformat()}, "
            f"current={current_utc.isoformat()})",
            reason=DenyReason.TOOL_STEP_UP_EXPIRED,
        )

    try:
        pem = issuer_lookup(att.issuer_iss, att.issuer_kid)
    except EnvelopeVerificationError as exc:
        raise StepUpError(
            f"unknown step-up issuer: iss={att.issuer_iss!r}, "
            f"kid={att.issuer_kid!r}",
            reason=DenyReason.TOOL_STEP_UP_UNKNOWN_ISSUER,
        ) from exc

    public_key = load_ed25519_public_key(pem)
    try:
        sig_bytes = decode_base64url(att.signature)
    except EnvelopeVerificationError as exc:
        raise StepUpError(
            "step-up signature is not valid base64url",
            reason=DenyReason.TOOL_STEP_UP_SIGNATURE_INVALID,
        ) from exc
    try:
        public_key.verify(sig_bytes, _stepup_body(att))
    except InvalidSignature as exc:
        raise StepUpError(
            "step-up signature failed verification",
            reason=DenyReason.TOOL_STEP_UP_SIGNATURE_INVALID,
        ) from exc

    return att


@dataclass(frozen=True)
class ToolCallDecision:
    allowed: bool
    reason: str
    reason_code: str = ""


def evaluate_tool_call(
    *,
    call: ToolCall,
    policy: ToolPolicy,
    step_up: StepUpAttestation | None = None,
    issuer_lookup: Callable[[str, str], bytes] | None = None,
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_step_up_ttl: timedelta = timedelta(minutes=10),
) -> ToolCallDecision:
    """Decide whether a proposed :class:`ToolCall` may proceed.

    When the matched :class:`ToolRule` requires step-up, both
    ``step_up`` and ``issuer_lookup`` MUST be supplied. The function
    verifies the attestation in-line (call-bound, current, signed by a
    trusted issuer); on any failure the corresponding step-up
    :class:`DenyReason` is propagated.
    """
    rule = policy.rule_for(call.tool_name)
    if rule is None:
        return ToolCallDecision(
            allowed=False,
            reason=f"unknown tool: {call.tool_name!r}",
            reason_code=DenyReason.TOOL_UNKNOWN.value,
        )

    if rule.allowed_callers and call.caller_iss not in rule.allowed_callers:
        return ToolCallDecision(
            allowed=False,
            reason=(
                f"caller {call.caller_iss!r} not in allowlist for "
                f"tool {call.tool_name!r}"
            ),
            reason_code=DenyReason.TOOL_CALLER_NOT_ALLOWED.value,
        )

    if rule.effective_step_up_required:
        if step_up is None:
            return ToolCallDecision(
                allowed=False,
                reason=(
                    f"tool {call.tool_name!r} (risk={rule.risk_tier.value}) "
                    f"requires step-up authorization"
                ),
                reason_code=DenyReason.TOOL_STEP_UP_REQUIRED.value,
            )
        if issuer_lookup is None:
            raise ToolPolicyError(
                "issuer_lookup must be supplied when a rule requires step-up"
            )
        try:
            verify_step_up(
                step_up,
                call=call,
                issuer_lookup=issuer_lookup,
                current=current,
                max_clock_skew=max_clock_skew,
                max_step_up_ttl=max_step_up_ttl,
            )
        except StepUpError as exc:
            return ToolCallDecision(
                allowed=False,
                reason=str(exc),
                reason_code=(
                    exc.reason.value
                    if exc.reason is not None
                    else DenyReason.TOOL_STEP_UP_REQUIRED.value
                ),
            )

    return ToolCallDecision(allowed=True, reason="ok", reason_code="ok")


class ToolPolicyDenied(EnvelopeVerificationError):
    """Raised by :func:`require_tool_call` on denial."""


def require_tool_call(
    *,
    call: ToolCall,
    policy: ToolPolicy,
    step_up: StepUpAttestation | None = None,
    issuer_lookup: Callable[[str, str], bytes] | None = None,
    current: datetime,
    max_clock_skew: timedelta = timedelta(seconds=60),
    max_step_up_ttl: timedelta = timedelta(minutes=10),
) -> ToolCallDecision:
    """Evaluate the policy and raise :class:`ToolPolicyDenied` on denial."""
    decision = evaluate_tool_call(
        call=call,
        policy=policy,
        step_up=step_up,
        issuer_lookup=issuer_lookup,
        current=current,
        max_clock_skew=max_clock_skew,
        max_step_up_ttl=max_step_up_ttl,
    )
    if not decision.allowed:
        try:
            reason_enum = DenyReason(decision.reason_code)
        except ValueError:
            reason_enum = None
        raise ToolPolicyDenied(decision.reason, reason=reason_enum)
    return decision
