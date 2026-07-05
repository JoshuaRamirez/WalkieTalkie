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
    PHASE_4 = "phase-4"
    PHASE_5 = "phase-5"


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
    # ----- Phase 1 hangover circle-back: discovery test vectors -----
    ProofObligation(
        name="discovery_test_vectors_coherent",
        phase=Phase.PHASE_1,
        track="D",
        statement=(
            "The shipped valid-discovery-record.json vector verifies "
            "cleanly under the bundled issuer public key, and the "
            "tampered-discovery-record.json vector (same signature, "
            "mutated endpoints) fails signature verification — proving "
            "the vectors are interpreted identically by the verifier "
            "across regenerations."
        ),
        canonical_test=(
            "test_discovery_test_vectors.TamperedVectorTests"
            ".test_tampered_vector_fails_signature_check"
        ),
    ),
    # ----- Phase 4 D4.1: MCP envelope adapter -----
    ProofObligation(
        name="mcp_adapter_emits_schema_complete_envelope",
        phase=Phase.PHASE_3,  # nearest peer; Phase enum not yet extended for Phase 4
        track="D",
        statement=(
            "The MCP envelope adapter's build_envelope+sign_envelope output "
            "carries exactly the field set declared 'required' in "
            "schema-v0.json — no missing fields, no extras. The verifier "
            "and the adapter cannot drift apart without failing CI."
        ),
        canonical_test=(
            "test_envelope_adapter.IntegrationWithVerifierTests"
            ".test_adapter_output_passes_schema_required_fields"
        ),
    ),
    # ----- Phase 4 D4.2: example MCP host -----
    ProofObligation(
        name="example_host_under_500_lines",
        phase=Phase.PHASE_3,  # nearest peer; Phase enum not yet extended for Phase 4
        track="D",
        statement=(
            "The example MCP host stays within the Phase 4 §6 "
            "acceptance criterion #4 ceiling of 500 lines. Growing "
            "past it means we're solving Phase 5 problems early — "
            "the test fails CI and forces an explicit decision."
        ),
        canonical_test=(
            "test_host.HostLineCountTests.test_host_module_under_500_lines"
        ),
    ),
    # ----- Phase 4 D4.3: end-to-end smoke test -----
    ProofObligation(
        name="mcp_smoke_round_trip_verifies",
        phase=Phase.PHASE_3,  # nearest peer; Phase enum not yet extended for Phase 4
        track="D",
        statement=(
            "A signed MCP envelope round-trips through the example "
            "host end-to-end: verify_envelope accepts the inbound, "
            "the tool gate allows the call, output_scanning and "
            "egress_policy approve the response, and the signed reply "
            "envelope is independently verifiable via verify_envelope. "
            "The audit chain hash-validates and the expected event "
            "sequence appears. This is the substrate-works-as-a-system "
            "proof for Phase 4."
        ),
        canonical_test=(
            "test_smoke.HappyPathTests"
            ".test_round_trip_succeeds_and_reply_is_verifiable"
        ),
    ),
    # ----- Phase 4 host security features (rate limit + revocation) -----
    ProofObligation(
        name="host_revocation_lifecycle_enforced",
        phase=Phase.PHASE_3,  # nearest peer; Phase enum not yet extended for Phase 4
        track="D",
        statement=(
            "A capability that the example host accepted a moment ago is "
            "rejected on its next use once its jti is entered into the "
            "revocation list the host consults — no host code change, "
            "just an out-of-band revocation. The envelope.verify audit "
            "event records capability_revoked as the machine-readable "
            "cause. This is the substrate's revoke-then-reject lifecycle "
            "demonstrated end-to-end."
        ),
        canonical_test=(
            "test_smoke.RevocationLifecycleTests"
            ".test_revoked_capability_rejected_on_next_use"
        ),
    ),
    ProofObligation(
        name="host_rate_limit_enforced_post_auth",
        phase=Phase.PHASE_3,  # nearest peer; Phase enum not yet extended for Phase 4
        track="D",
        statement=(
            "The example host's per-identity rate limiter runs AFTER "
            "envelope authentication, so a badly-signed envelope claiming "
            "a victim's SPIFFE ID is rejected before the limiter runs and "
            "consumes none of the victim's allowance — the Phase 1 "
            "hardening invariant, demonstrated end-to-end through the "
            "running host."
        ),
        canonical_test=(
            "test_smoke.RateLimitLifecycleTests"
            ".test_spoofed_sender_does_not_burn_victim_allowance"
        ),
    ),
    # ----- Phase 3 B3 deferred-half circle-back: capacity rebalancer -----
    ProofObligation(
        name="rebalancer_preserves_non_preemptible_floor",
        phase=Phase.PHASE_3,
        track="B",
        statement=(
            "After CapacityRebalancer.apply, every pool's ceiling is "
            "still >= its own reserved — the Track B non-preemptible "
            "floor invariant survives every rebalance step."
        ),
        canonical_test=(
            "test_capacity_rebalancer.ApplyTests"
            ".test_apply_preserves_floor_invariant"
        ),
    ),
    ProofObligation(
        name="rebalancer_preserves_oversubscription_cap",
        phase=Phase.PHASE_3,
        track="B",
        statement=(
            "After CapacityRebalancer.apply, every pool satisfies "
            "ceiling + sum(other_pools.reserved) <= total_capacity — "
            "the cross-pool oversubscription cap holds end-to-end."
        ),
        canonical_test=(
            "test_capacity_rebalancer.ApplyTests"
            ".test_apply_preserves_oversubscription_cap"
        ),
    ),
    # ----- Phase 5 Track A: real X.509 identity -----
    ProofObligation(
        name="svid_binding_verified",
        phase=Phase.PHASE_5,
        track="A",
        statement=(
            "An X.509 SVID verifies only when its signature chains to "
            "the trusted root, its time window is current, its key "
            "usage forbids cert-signing, and (when supplied) its "
            "SPIFFE-SAN id matches the expected id. A cert signed by a "
            "different root key fails with svid_signature_invalid; a "
            "mismatched id fails with svid_spiffe_mismatch."
        ),
        canonical_test=(
            "test_verify_svid.HappyPathTests"
            ".test_binding_check_passes_when_expected_matches"
        ),
    ),
    ProofObligation(
        name="unadmitted_peer_denied",
        phase=Phase.PHASE_5,
        track="A",
        statement=(
            "Peer admission is deny-by-default: an identity not on the "
            "allowlist is denied (admission_peer_not_allowed), an "
            "allowlisted identity presenting on the wrong env tier is "
            "denied (admission_tier_mismatch), and a pinned peer "
            "presenting the wrong key is denied "
            "(admission_cert_pin_mismatch). This is vision §8.1 — an "
            "unauthorized peer cannot join the mesh."
        ),
        canonical_test=(
            "test_peer_admission.AdmissionTests.test_deny_by_default"
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
