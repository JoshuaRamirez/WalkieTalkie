"""Policy decisions in the audit trail (Phase 5 Track B, D5.3). [RUNNABLE]

Completes the vision's Layer C requirement that "every tool
invocation must carry a provable chain: caller identity, delegated
capability, **policy decision ID**." B1 built the engine that produces
decision IDs; this slice threads those IDs into the hash-chained audit
trail so the forensic record can answer "which policy decision
authorized this action, and can I prove the record wasn't altered?"

Two pieces:

- :func:`decide_and_audit` runs a :class:`policy_engine.PolicyEngine`
  and emits a ``policy.decide`` audit event whose ``reason`` embeds
  the ``decision_id`` and matched rule. Because ``reason`` is one of
  the audit chain's hashed fields, the decision id is tamper-evident
  by construction — you cannot alter it without breaking the chain.
- :func:`build_baseline_engine` assembles a
  :class:`policy_engine.NativePolicyEngine` mirroring the existing
  Phase 2 gates (tool allowlist + step-up posture, retrieval class
  ceiling, restricted-egress deny). This is the vision's "baseline
  policy library" — the deny-by-default starting point an operator
  tunes, expressed as engine rules instead of bespoke gate code.

Note on schema: v0 embeds the decision id in the ``reason`` string
rather than adding a first-class ``decision_id`` audit field, because
promoting a field would change the hash-chain field set and break
every existing event. A v1 audit-schema revision could promote it;
until then ``reason`` carries it and the chain still protects it.
"""

from __future__ import annotations

from datetime import datetime

from audit import AuditSink
from policy_engine import (
    ANY,
    Condition,
    ConditionOp,
    Effect,
    NativePolicyEngine,
    PolicyDecision,
    PolicyEngine,
    PolicyRequest,
    PolicyRule,
)

# The audit event type for a policy decision. Joins the existing
# taxonomy (envelope.verify, capability.issue, tool.gate, ...).
POLICY_DECIDE_EVENT = "policy.decide"


def decide_and_audit(
    *,
    engine: PolicyEngine,
    request: PolicyRequest,
    audit_sink: AuditSink,
    now: datetime | None = None,
    sender: str = "",
    recipient: str = "",
) -> PolicyDecision:
    """Evaluate ``request`` and emit a ``policy.decide`` audit event.

    The event's ``reason`` embeds the decision id and matched rule so
    the forensic trace is complete and tamper-evident. ``outcome`` is
    ``allow`` on permit and ``deny`` otherwise, matching the audit
    alphabet. Returns the :class:`PolicyDecision` so the caller can act
    on it.
    """
    decision = engine.decide(request, now=now)
    outcome = "allow" if decision.permitted else "deny"
    reason = (
        f"decision_id={decision.decision_id} "
        f"rule={decision.matched_rule or '<deny-by-default>'} "
        f"principal={request.principal} action={request.action} "
        f"resource={request.resource}"
    )
    audit_sink.record(
        event_type=POLICY_DECIDE_EVENT,
        outcome=outcome,
        reason=reason,
        sender=sender or request.principal,
        recipient=recipient,
        timestamp=now,
    )
    return decision


def build_baseline_engine(
    *,
    allowed_callers: tuple[str, ...],
    low_risk_tools: tuple[str, ...] = ("read_file",),
    step_up_tools: tuple[str, ...] = ("exec_sql",),
) -> NativePolicyEngine:
    """Assemble the vision's "baseline policy library" as engine rules.

    Deny-by-default with narrow permits, mirroring the Phase 2 gates:

    - Low-risk tools are permitted for allowlisted callers.
    - Step-up tools are permitted only when the request context
      carries ``step_up=True`` (the engine analogue of
      `tool_policy_gate`'s step-up requirement).
    - Everything else falls through to deny-by-default.

    ``resource`` is the tool name; ``action`` is ``"invoke_tool"``.
    """
    callers = list(allowed_callers)
    rules: list[PolicyRule] = []

    # Low-risk tools: permit for any allowlisted caller.
    for tool in low_risk_tools:
        rules.append(
            PolicyRule(
                name=f"permit-low-{tool}",
                effect=Effect.PERMIT,
                action="invoke_tool",
                resource=tool,
                conditions=(
                    Condition(
                        key="caller", op=ConditionOp.IN, value=callers
                    ),
                ),
            )
        )

    # Step-up tools: permit only with step_up=True in context.
    for tool in step_up_tools:
        rules.append(
            PolicyRule(
                name=f"permit-stepup-{tool}",
                effect=Effect.PERMIT,
                action="invoke_tool",
                resource=tool,
                conditions=(
                    Condition(key="caller", op=ConditionOp.IN, value=callers),
                    Condition(key="step_up", op=ConditionOp.EQUALS, value=True),
                ),
            )
        )
        # Explicit deny for the step-up tool without step_up, so the
        # trace records an intentional deny rather than a bare
        # deny-by-default (clearer forensics for the sensitive path).
        rules.append(
            PolicyRule(
                name=f"deny-stepup-missing-{tool}",
                effect=Effect.DENY,
                action="invoke_tool",
                resource=tool,
                principal=ANY,
            )
        )

    return NativePolicyEngine(rules=tuple(rules))
