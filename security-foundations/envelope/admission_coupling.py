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

from discovery_record import DiscoveryRecord


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


def admit(record: DiscoveryRecord, policy: AdmissionPolicy) -> AdmissionDecision:
    """Evaluate ``record`` against ``policy``. Never raises.

    Caller MUST have already verified the record's signature and time
    window via :func:`discovery_record.verify_record`. This function
    answers only the *policy* question, not the *integrity* question.
    """
    if record.version not in policy.accepted_discovery_versions:
        return AdmissionDecision(
            admitted=False,
            reason=(
                f"discovery version {record.version!r} not in admission "
                f"compatibility matrix {sorted(policy.accepted_discovery_versions)}"
            ),
            workload_iss=record.workload_iss,
        )
    if record.workload_iss not in policy.allowed_workloads:
        return AdmissionDecision(
            admitted=False,
            reason=f"workload {record.workload_iss!r} not in admission allowlist",
            workload_iss=record.workload_iss,
        )
    return AdmissionDecision(
        admitted=True,
        reason="ok",
        workload_iss=record.workload_iss,
        endpoints=record.endpoints,
    )


def require_admission(record: DiscoveryRecord, policy: AdmissionPolicy) -> AdmissionDecision:
    """:func:`admit` that raises :class:`AdmissionError` on denial."""
    decision = admit(record, policy)
    if not decision.admitted:
        raise AdmissionError(decision)
    return decision
