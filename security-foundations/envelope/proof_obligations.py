"""Proof obligations registry v0 (Phase 3 Track E E1+E2+E3).

Closes Phase 3 Track E at the substrate level:

- E1 Protocol State-Machine Model
- E2 Proof Obligations
- E3 CI Blocking Integration

Genuine formal verification (TLA+, Coq, Lean) is out of scope for
the Python substrate. The v0 equivalent is this registry: a
**stable, machine-checked enumeration** of every safety invariant
the substrate claims to enforce. Each :class:`ProofObligation`
names the invariant, restates it in human-readable form, and points
at the canonical test that pins it. The :mod:`test_proof_obligations`
companion module asserts that every entry resolves to a real test
method — so renaming or deleting a backing test breaks CI loudly,
satisfying the E3 "block release on model/proof regression"
requirement.

Stability contract
------------------
Just like :class:`deny_reason.DenyReason`, obligation names are a
stable taxonomy. Once shipped, a name is never reused for a
different invariant; the canonical test it points at can be
renamed, but every rename must update this registry in the same
commit. Adding obligations is additive; retiring one requires a
documented justification.

The registry is **not** a substitute for actual model checking — it
catches regressions in the tests that pin invariants, not in the
invariants themselves. A future Phase 3+ slice can introduce TLA+
proofs and have them feed back into this registry as additional
``proof_artifact`` references.
"""

from __future__ import annotations

import importlib
import inspect
from dataclasses import dataclass
from enum import StrEnum


class ProofObligationError(ValueError):
    """Raised when an obligation cannot be resolved."""


class Phase(StrEnum):
    PHASE_0 = "phase-0"
    PHASE_1 = "phase-1"
    PHASE_2 = "phase-2"
    PHASE_3 = "phase-3"


@dataclass(frozen=True)
class ProofObligation:
    """One safety invariant + its canonical pinning test.

    ``canonical_test`` is ``"<module>.<TestClass>.<test_method>"`` —
    importable via :func:`resolve_test`.
    """

    name: str
    phase: Phase
    track: str
    statement: str
    canonical_test: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ProofObligationError("name must be a non-empty string")
        if not isinstance(self.phase, Phase):
            raise ProofObligationError(f"phase must be a Phase: {self.phase!r}")
        if not isinstance(self.track, str) or not self.track:
            raise ProofObligationError("track must be a non-empty string")
        if not isinstance(self.statement, str) or not self.statement:
            raise ProofObligationError("statement must be a non-empty string")
        if not isinstance(self.canonical_test, str) or "." not in self.canonical_test:
            raise ProofObligationError(
                f"canonical_test must be 'module.Class.method': "
                f"{self.canonical_test!r}"
            )


def resolve_test(canonical_test: str):
    """Import the test method named by ``canonical_test``.

    Returns the unbound function object. Raises
    :class:`ProofObligationError` if the dotted path doesn't resolve
    to a callable defined inside a ``unittest.TestCase`` subclass.
    """
    parts = canonical_test.rsplit(".", 2)
    if len(parts) != 3:
        raise ProofObligationError(
            f"canonical_test must be 'module.Class.method': {canonical_test!r}"
        )
    module_name, class_name, method_name = parts
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        raise ProofObligationError(
            f"cannot import {module_name!r} for obligation: {exc}"
        ) from exc
    cls = getattr(module, class_name, None)
    if cls is None or not inspect.isclass(cls):
        raise ProofObligationError(
            f"{module_name}.{class_name} is not a class"
        )
    method = getattr(cls, method_name, None)
    if method is None or not callable(method):
        raise ProofObligationError(
            f"{canonical_test} is not a callable test method"
        )
    return method


# ---------------------------------------------------------------------
# The registry. ADD new obligations only; NEVER reuse a name.
# ---------------------------------------------------------------------

OBLIGATIONS: tuple[ProofObligation, ...] = (
    # ----- Phase 1 envelope verifier -----
    ProofObligation(
        name="envelope_signature_required",
        phase=Phase.PHASE_1,
        track="A",
        statement=(
            "An envelope with a tampered or absent EdDSA signature is "
            "rejected; the replay nonce is NOT reserved on failure."
        ),
        canonical_test=(
            "test_verify_envelope.VerifyEnvelopeTests"
            ".test_invalid_signature_does_not_reserve_nonce"
        ),
    ),
    # ----- Phase 1 capability token -----
    ProofObligation(
        name="capability_cnf_binding_prevents_reuse",
        phase=Phase.PHASE_1,
        track="D",
        statement=(
            "A capability token whose cnf.envelope_digest does not match "
            "the envelope's payload digest is rejected — tokens cannot "
            "be replayed across distinct payloads."
        ),
        canonical_test=(
            "test_verify_envelope.VerifyEnvelopeTests"
            ".test_capability_wrong_envelope_digest_rejected"
        ),
    ),
    ProofObligation(
        name="capability_signer_pool_separation",
        phase=Phase.PHASE_1,
        track="D",
        statement=(
            "A workload's envelope-signing key cannot sign a capability "
            "token; IssuerTrustStore is type-distinct from FileSystemTrustStore "
            "and the (iss, kid) lookup rejects the cross-pool attempt."
        ),
        canonical_test=(
            "test_verify_envelope.VerifyEnvelopeTests"
            ".test_envelope_signing_key_cannot_sign_capability"
        ),
    ),
    # ----- Phase 2 Track A delegation -----
    ProofObligation(
        name="delegation_scope_monotonicity",
        phase=Phase.PHASE_2,
        track="A",
        statement=(
            "A delegation receipt cannot broaden the parent's scope; "
            "every hop must carry an identical scope string."
        ),
        canonical_test=(
            "test_delegation_receipt.NonEscalationTests"
            ".test_scope_widening_rejected"
        ),
    ),
    ProofObligation(
        name="delegation_audience_monotonicity",
        phase=Phase.PHASE_2,
        track="A",
        statement=(
            "A delegation receipt cannot drift the parent's audience; "
            "every hop must carry an identical aud."
        ),
        canonical_test=(
            "test_delegation_receipt.NonEscalationTests"
            ".test_audience_drift_rejected"
        ),
    ),
    ProofObligation(
        name="delegation_window_containment",
        phase=Phase.PHASE_2,
        track="A",
        statement=(
            "A delegation receipt's [iat, exp] is contained within the "
            "parent's window — the child cannot extend lifetime."
        ),
        canonical_test=(
            "test_delegation_receipt.NonEscalationTests"
            ".test_ttl_extending_past_parent_rejected"
        ),
    ),
    ProofObligation(
        name="delegation_depth_bounded",
        phase=Phase.PHASE_2,
        track="A",
        statement=(
            "Delegation chains cannot exceed max_chain_depth (default 3)."
        ),
        canonical_test=(
            "test_delegation_receipt.NonEscalationTests"
            ".test_depth_limit_enforced"
        ),
    ),
    # ----- Phase 2 Track B retrieval policy -----
    ProofObligation(
        name="retrieval_cross_tenant_default_deny",
        phase=Phase.PHASE_2,
        track="B",
        statement=(
            "Cross-tenant retrieval is denied by default — the tenant "
            "check runs before rule matching, so a matching rule cannot "
            "override the boundary unless cross_tenant=ALLOW is "
            "explicitly set."
        ),
        canonical_test=(
            "test_retrieval_policy.CrossTenantTests"
            ".test_cross_tenant_check_runs_before_rule_match"
        ),
    ),
    ProofObligation(
        name="data_classification_non_demotion",
        phase=Phase.PHASE_2,
        track="B",
        statement=(
            "A derived ClassifiedData cannot drop below its parent's "
            "data class; demotion raises DataClassificationError."
        ),
        canonical_test=(
            "test_data_classification.DeriveTests"
            ".test_derive_cannot_demote_class"
        ),
    ),
    # ----- Phase 2 Track C egress / reviewer -----
    ProofObligation(
        name="egress_restricted_no_export",
        phase=Phase.PHASE_2,
        track="C",
        statement=(
            "When restricted_no_export=True, every RESTRICTED-class "
            "artifact is denied egress regardless of matrix or risk."
        ),
        canonical_test=(
            "test_egress_policy.RestrictedNoExportTests"
            ".test_restricted_denied_even_with_allow_cell"
        ),
    ),
    ProofObligation(
        name="reviewer_record_binding",
        phase=Phase.PHASE_2,
        track="C",
        statement=(
            "A signed reviewer decision cannot be reused for a "
            "different quarantine record; record_digest is bound."
        ),
        canonical_test=(
            "test_reviewer_workflow.BindingTests"
            ".test_record_digest_mismatch_rejected"
        ),
    ),
    # ----- Phase 2 Track D instruction isolation / tool gate -----
    ProofObligation(
        name="tool_output_untrusted_unless_signed",
        phase=Phase.PHASE_2,
        track="D",
        statement=(
            "A TOOL ContentSegment may only be Trust.TRUSTED when "
            "accompanied by a non-empty signature_ref."
        ),
        canonical_test=(
            "test_instruction_isolation.ChannelTrustRulesTests"
            ".test_tool_trusted_requires_signature_ref"
        ),
    ),
    ProofObligation(
        name="tool_step_up_call_binding",
        phase=Phase.PHASE_2,
        track="D",
        statement=(
            "A step-up attestation is bound to (tool_name, caller_iss, "
            "arguments_digest); a stale attestation cannot be reused "
            "for a different, more dangerous call."
        ),
        canonical_test=(
            "test_tool_policy_gate.StepUpBindingTests"
            ".test_step_up_for_different_arguments_rejected"
        ),
    ),
    ProofObligation(
        name="adversarial_corpus_full_block_rate",
        phase=Phase.PHASE_2,
        track="D",
        statement=(
            "Every entry in adversarial-corpus-v0.json is intercepted "
            "by its declared gate. 100% block-rate is mandatory; any "
            "regression fails CI."
        ),
        canonical_test=(
            "test_adversarial_corpus.AdversarialCorpusTests"
            ".test_every_entry_is_blocked"
        ),
    ),
    # ----- Phase 2 Track E checkpointed + session -----
    ProofObligation(
        name="revoked_capability_blocked_at_checkpoint",
        phase=Phase.PHASE_2,
        track="E",
        statement=(
            "A capability whose jti is in the RevocationLedger cannot "
            "commit at the next checkpoint, regardless of how the task "
            "began. This is the Phase 2 Track E acceptance criterion."
        ),
        canonical_test=(
            "test_checkpointed_execution.RevocationTests"
            ".test_revoked_capability_blocked_at_next_checkpoint"
        ),
    ),
    ProofObligation(
        name="session_resume_sequence_strict",
        phase=Phase.PHASE_2,
        track="E",
        statement=(
            "A resume SessionToken must have seq == previous.seq + 1; "
            "skip and replay both fail with the same code."
        ),
        canonical_test=(
            "test_session_token.ResumeChainTests"
            ".test_sequence_replay_rejected"
        ),
    ),
    # ----- Phase 3 Track A topology -----
    ProofObligation(
        name="sybil_cluster_cannot_dominate_peer_view",
        phase=Phase.PHASE_3,
        track="A",
        statement=(
            "DiversityRule.max_per_trust_domain enforces an upper bound "
            "on how many neighbor slots one trust domain can occupy, "
            "regardless of how many candidates that domain submits."
        ),
        canonical_test=(
            "test_eclipse_resistance.DiversityCapTests"
            ".test_per_domain_cap_blocks_sybil_dominance"
        ),
    ),
    ProofObligation(
        name="discovery_freshness_monotonic",
        phase=Phase.PHASE_3,
        track="A",
        statement=(
            "DiscoveryFreshnessTracker refuses any record whose "
            "issued_at does not strictly increase past the highest "
            "pin for (workload_iss, workload_kid)."
        ),
        canonical_test=(
            "test_discovery_propagation.FreshnessTests"
            ".test_rewound_record_rejected"
        ),
    ),
    # ----- Phase 3 Track B capacity -----
    ProofObligation(
        name="non_preemptible_floor_invariant",
        phase=Phase.PHASE_3,
        track="B",
        statement=(
            "A BudgetController pool cannot burst into another pool's "
            "reserved capacity, even when the other pool is idle — the "
            "non-preemptible floor that ensures data-plane flood cannot "
            "starve security-critical services."
        ),
        canonical_test=(
            "test_capacity_budgets.FloorGuardTests"
            ".test_data_plane_cannot_consume_security_floor"
        ),
    ),
    # ----- Phase 3 Track C safe-mode -----
    ProofObligation(
        name="safe_mode_authority_hierarchy_dominance",
        phase=Phase.PHASE_3,
        track="C",
        statement=(
            "A DowngradeApproval cannot clear a trigger whose category "
            "outranks the approval's authority — CRYPTO_TRUST triggers "
            "require CRYPTO_TRUST-level approval."
        ),
        canonical_test=(
            "test_safe_mode_engine.DowngradeTests"
            ".test_downgrade_blocked_when_higher_category_trigger_active"
        ),
    ),
    ProofObligation(
        name="safe_mode_determinism",
        phase=Phase.PHASE_3,
        track="C",
        statement=(
            "Two SafeModeEngines processing the same trigger sequence "
            "land identical state histories. Compound failures always "
            "produce predictable state and logs."
        ),
        canonical_test=(
            "test_safe_mode_engine.DeterminismTests"
            ".test_two_engines_walk_identical_history"
        ),
    ),
    # ----- Phase 3 Track D rotation / readmission -----
    ProofObligation(
        name="rotation_phases_deterministic",
        phase=Phase.PHASE_3,
        track="D",
        statement=(
            "For any KeyRotationPlan and any 'now', current_phase() "
            "returns exactly one of PRE_OVERLAP / OVERLAP / "
            "POST_CUTOVER / COMPLETE."
        ),
        canonical_test=(
            "test_key_rotation.PhaseTests.test_overlap"
        ),
    ),
    ProofObligation(
        name="readmission_kid_must_be_fresh",
        phase=Phase.PHASE_3,
        track="D",
        statement=(
            "Clean-room re-admission must use a kid distinct from the "
            "one that was quarantined; reuse of the old kid is rejected."
        ),
        canonical_test=(
            "test_recovery_readmission.BindingTests"
            ".test_kid_reuse_rejected"
        ),
    ),
    ProofObligation(
        name="readmission_attester_pool_separation",
        phase=Phase.PHASE_3,
        track="D",
        statement=(
            "A re-admission attestation must be signed by an attester "
            "in a separate trust pool; the workload being readmitted "
            "physically cannot sign its own re-admission."
        ),
        canonical_test=(
            "test_recovery_readmission.CleanStateEvidenceTests"
            ".test_attester_trust_pool_is_separate"
        ),
    ),
    # ----- Phase 3 D3.3 circle-back: signed safe-mode artifacts -----
    ProofObligation(
        name="signed_safe_mode_transition_integrity",
        phase=Phase.PHASE_3,
        track="C",
        statement=(
            "A safe-mode state-transition record whose body has been "
            "tampered with post-signing fails signature verification."
        ),
        canonical_test=(
            "test_signed_safe_mode.TransitionFailureTests"
            ".test_tampered_transition_rejected"
        ),
    ),
    ProofObligation(
        name="signed_downgrade_signature_runs_before_engine",
        phase=Phase.PHASE_3,
        track="C",
        statement=(
            "verified_downgrade() refuses a tampered SignedDowngradeApproval "
            "BEFORE consulting the safe-mode engine; authority spoofing "
            "via constructed-in-memory approvals is prevented."
        ),
        canonical_test=(
            "test_signed_safe_mode.VerifiedDowngradeTests"
            ".test_signature_failure_blocks_engine_call"
        ),
    ),
)


def by_phase(phase: Phase) -> tuple[ProofObligation, ...]:
    return tuple(o for o in OBLIGATIONS if o.phase is phase)


def by_track(track: str) -> tuple[ProofObligation, ...]:
    return tuple(o for o in OBLIGATIONS if o.track == track)


def find(name: str) -> ProofObligation:
    for o in OBLIGATIONS:
        if o.name == name:
            return o
    raise ProofObligationError(f"unknown obligation: {name!r}")
