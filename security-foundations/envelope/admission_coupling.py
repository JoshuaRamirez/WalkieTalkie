"""Admission coupling for discovered workloads.

Closes Phase 1 Track A **A3** ("Admission Coupling"):

- "Discovery output only feeds admitted peers."
- "Discovery and admission policy versions must match compatibility matrix."

After :func:`discovery_record.verify_record` succeeds, the verified record
is fed through :func:`admit` (or :func:`require_admission`). The
:class:`AdmissionPolicy` decides whether the discovered workload is
allowed *as a peer* — separate from the cryptographic question of whether
the discovery record itself is trustworthy.

Closes the plan's Track A acceptance criteria:

- "Unauthorized peer join test always fails" — covered by the allowlist
  check (workload SPIFFE ID must be in ``allowed_workloads``).
- "Misconfigured permissive policy is rejected in CI semantic checks" — an
  empty allowlist is permitted (zero peers) but never silently accepts
  anything; callers MUST opt a workload in explicitly.

Out of scope for v0
-------------------
- Per-environment allowlists (today is one allowlist per :class:`AdmissionPolicy`
  instance; callers compose multiple instances themselves).
- Cert pinning for high-trust peers (Phase 0 A3 mentions it; needs a
  certificate substrate not in scope here).
- Real-time admission revocation (operators rebuild the policy and rotate).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from deny_reason import DenyReason
from discovery_record import DiscoveryRecord

if TYPE_CHECKING:
    from audit import AuditSink

ADMISSION_EVENT_TYPE = "admission.evaluate"
ADMISSION_ARTIFACT_VERSION = "wt-admission/v0"


class AdmissionError(ValueError):
    """Raised by :func:`require_admission` when the policy denies."""

    def __init__(self, decision: AdmissionDecision) -> None:
        super().__init__(decision.reason)
        self.decision = decision


@dataclass(frozen=True)
class AdmissionDecision:
    admitted: bool
    reason: str
    workload_iss: str
    endpoints: tuple[str, ...] = ()
    reason_code: str = ""


@dataclass(frozen=True)
class AdmissionPolicy:
    """Closed allowlist of admitted workloads + accepted discovery versions.

    ``accepted_discovery_versions`` is the "compatibility matrix" — the set
    of discovery-record versions this admission policy understands. A
    discovery record with a version outside this set is denied even if the
    workload is allowlisted; this prevents an old admission policy from
    accidentally accepting a record format it doesn't fully validate.
    """

    allowed_workloads: frozenset[str]
    accepted_discovery_versions: frozenset[str] = field(
        default_factory=lambda: frozenset({"v0"})
    )

    def __post_init__(self) -> None:
        if not isinstance(self.allowed_workloads, frozenset):
            raise TypeError("allowed_workloads must be a frozenset")
        if not isinstance(self.accepted_discovery_versions, frozenset):
            raise TypeError("accepted_discovery_versions must be a frozenset")
        if not self.accepted_discovery_versions:
            raise ValueError("accepted_discovery_versions must be non-empty")


def admit(
    record: DiscoveryRecord,
    policy: AdmissionPolicy,
    *,
    audit_sink: AuditSink | None = None,
) -> AdmissionDecision:
    """Evaluate ``record`` against ``policy``. Never raises.

    Caller MUST have already verified the record's signature and time
    window via :func:`discovery_record.verify_record`. This function
    answers only the *policy* question, not the *integrity* question.

    ``audit_sink``, if supplied, receives one ``admission.evaluate``
    event per call.
    """
    if record.version not in policy.accepted_discovery_versions:
        decision = AdmissionDecision(
            admitted=False,
            reason=(
                f"discovery version {record.version!r} not in admission "
                f"compatibility matrix {sorted(policy.accepted_discovery_versions)}"
            ),
            workload_iss=record.workload_iss,
            reason_code=DenyReason.ADMISSION_VERSION_INCOMPATIBLE.value,
        )
    elif record.workload_iss not in policy.allowed_workloads:
        decision = AdmissionDecision(
            admitted=False,
            reason=f"workload {record.workload_iss!r} not in admission allowlist",
            workload_iss=record.workload_iss,
            reason_code=DenyReason.ADMISSION_WORKLOAD_NOT_ALLOWED.value,
        )
    else:
        decision = AdmissionDecision(
            admitted=True,
            reason="ok",
            workload_iss=record.workload_iss,
            endpoints=record.endpoints,
            reason_code="ok",
        )
    _emit(decision, record, audit_sink)
    return decision


def _emit(decision: AdmissionDecision, record: DiscoveryRecord, sink: AuditSink | None) -> None:
    if sink is None:
        return
    sink.record(
        event_type=ADMISSION_EVENT_TYPE,
        outcome="allow" if decision.admitted else "deny",
        reason=decision.reason,
        reason_code=decision.reason_code,
        artifact_version=ADMISSION_ARTIFACT_VERSION,
        sender=record.workload_iss,
        envelope_kid=record.workload_kid,
        issuer_iss=record.issuer_iss,
        issuer_kid=record.issuer_kid,
    )


def require_admission(
    record: DiscoveryRecord,
    policy: AdmissionPolicy,
    *,
    audit_sink: AuditSink | None = None,
) -> AdmissionDecision:
    """:func:`admit` that raises :class:`AdmissionError` on denial."""
    decision = admit(record, policy, audit_sink=audit_sink)
    if not decision.admitted:
        raise AdmissionError(decision)
    return decision
