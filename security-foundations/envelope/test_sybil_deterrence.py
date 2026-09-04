"""Tests for Sybil deterrence (Phase 3 Track A A1)."""

import hashlib
import unittest
from datetime import UTC, datetime, timedelta

import jcs

from envelope.sybil_deterrence import (
    BURDEN_TYP,
    AttestationBurden,
    AttestationBurdenProof,
    InMemorySybilLedger,
    IssuanceRecord,
    IssuerReputation,
    SybilDeterrence,
    SybilDeterrenceError,
    make_attestation_proof,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_ISSUER_A = "spiffe://mesh.example/ns-iss/issuer-a"
_ISSUER_B = "spiffe://mesh.example/ns-iss/issuer-b"
_FOREIGN_ISSUER = "spiffe://other-mesh.example/ns-iss/issuer-z"
_KID = "issuer-kid-1"

def _record(*, issuer: str = _ISSUER_A, minted: str | None = None, at: datetime = _NOW) -> IssuanceRecord:
    return IssuanceRecord(
        issuer_iss=issuer,
        issuer_kid=_KID,
        minted_iss=minted or f"spiffe://mesh.example/ns-a/svc-{int(at.timestamp())}",
        at=at,
    )

def _gate(**overrides) -> SybilDeterrence:
    kwargs = dict(
        ledger=InMemorySybilLedger(),
        reputation=IssuerReputation(),
        window=timedelta(hours=1),
        max_per_issuer=5,
        max_per_tenant=10,
        min_reputation=1,
    )
    kwargs.update(overrides)
    return SybilDeterrence(**kwargs)

class IssuanceRecordTests(unittest.TestCase):
    def test_invalid_issuer_rejected(self):
        with self.assertRaisesRegex(SybilDeterrenceError, "issuer_iss"):
            IssuanceRecord(
                issuer_iss="not-spiffe",
                issuer_kid=_KID,
                minted_iss="spiffe://mesh.example/ns-x/svc-1",
                at=_NOW,
            )

    def test_naive_datetime_rejected(self):
        with self.assertRaisesRegex(SybilDeterrenceError, "timezone-aware"):
            IssuanceRecord(
                issuer_iss=_ISSUER_A,
                issuer_kid=_KID,
                minted_iss="spiffe://mesh.example/ns-x/svc-1",
                at=datetime(2026, 4, 14, 12),  # naive
            )

class LedgerCountingTests(unittest.TestCase):
    def test_window_excludes_old_entries(self):
        ledger = InMemorySybilLedger(retention=timedelta(days=1))
        ledger.record(_record(at=_NOW - timedelta(hours=2)))
        ledger.record(_record(at=_NOW - timedelta(minutes=30)))
        ledger.record(_record(at=_NOW - timedelta(minutes=5)))
        in_last_hour = ledger.count_for_issuer(
            _ISSUER_A, _KID, since=_NOW - timedelta(hours=1)
        )
        self.assertEqual(in_last_hour, 2)

    def test_tenant_count_aggregates_issuers(self):
        ledger = InMemorySybilLedger(retention=timedelta(days=1))
        ledger.record(_record(issuer=_ISSUER_A, at=_NOW - timedelta(minutes=10)))
        ledger.record(_record(issuer=_ISSUER_B, at=_NOW - timedelta(minutes=5)))
        # Both in mesh.example tenant.
        count = ledger.count_for_tenant(
            "mesh.example", since=_NOW - timedelta(hours=1)
        )
        self.assertEqual(count, 2)

    def test_retention_drops_aged_entries(self):
        ledger = InMemorySybilLedger(retention=timedelta(minutes=10))
        # Older than retention — trimmed on the next record-driven trim.
        ledger.record(_record(at=_NOW - timedelta(minutes=20)))
        ledger.record(_record(at=_NOW))  # triggers trim against _NOW
        count = ledger.count_for_issuer(
            _ISSUER_A, _KID, since=_NOW - timedelta(hours=1)
        )
        self.assertEqual(count, 1)

class ReputationDecayTests(unittest.TestCase):
    def test_initial_score_seeded(self):
        rep = IssuerReputation(initial_score=50)
        self.assertEqual(
            rep.current_score(_ISSUER_A, _KID, now=_NOW), 50
        )

    def test_score_decays_over_intervals(self):
        rep = IssuerReputation(
            initial_score=10,
            decay_per_interval=1,
            decay_interval=timedelta(hours=1),
        )
        rep.current_score(_ISSUER_A, _KID, now=_NOW)  # seed
        # 3 hours later → score decays by 3.
        later = _NOW + timedelta(hours=3)
        self.assertEqual(
            rep.current_score(_ISSUER_A, _KID, now=later), 7
        )

    def test_decay_floors_at_zero(self):
        rep = IssuerReputation(
            initial_score=2,
            decay_per_interval=1,
            decay_interval=timedelta(hours=1),
        )
        rep.current_score(_ISSUER_A, _KID, now=_NOW)
        # 10h later: 2 - 10 = -8 → clamped to 0.
        self.assertEqual(
            rep.current_score(_ISSUER_A, _KID, now=_NOW + timedelta(hours=10)),
            0,
        )

    def test_reward_clamps_at_ceiling(self):
        rep = IssuerReputation(initial_score=95, ceiling=100)
        rep.current_score(_ISSUER_A, _KID, now=_NOW)
        rep.reward(_ISSUER_A, _KID, amount=20, now=_NOW)
        self.assertEqual(
            rep.current_score(_ISSUER_A, _KID, now=_NOW), 100
        )

    def test_penalize_floors_at_zero(self):
        rep = IssuerReputation(initial_score=10)
        rep.current_score(_ISSUER_A, _KID, now=_NOW)
        rep.penalize(_ISSUER_A, _KID, amount=100, now=_NOW)
        self.assertEqual(
            rep.current_score(_ISSUER_A, _KID, now=_NOW), 0
        )

    def test_zero_amount_rejected(self):
        rep = IssuerReputation()
        with self.assertRaisesRegex(SybilDeterrenceError, "positive"):
            rep.reward(_ISSUER_A, _KID, amount=0, now=_NOW)

class DeterrenceGateTests(unittest.TestCase):
    def test_allows_within_quota(self):
        gate = _gate()
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A, issuer_kid=_KID, now=_NOW
        )
        self.assertTrue(decision.allowed)

    def test_issuer_quota_saturation_denies(self):
        gate = _gate(max_per_issuer=3)
        for i in range(3):
            gate.record_admission(
                issuer_iss=_ISSUER_A,
                issuer_kid=_KID,
                minted_iss=f"spiffe://mesh.example/ns-a/svc-{i}",
                at=_NOW - timedelta(minutes=i),
            )
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A, issuer_kid=_KID, now=_NOW
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "sybil_issuer_quota_exceeded")

    def test_tenant_quota_saturation_denies(self):
        gate = _gate(max_per_issuer=100, max_per_tenant=4)
        # Two issuers, both in mesh.example, push the tenant over.
        for i in range(2):
            gate.record_admission(
                issuer_iss=_ISSUER_A,
                issuer_kid=_KID,
                minted_iss=f"spiffe://mesh.example/ns-a/svc-a{i}",
                at=_NOW - timedelta(minutes=10 + i),
            )
        for i in range(2):
            gate.record_admission(
                issuer_iss=_ISSUER_B,
                issuer_kid=_KID,
                minted_iss=f"spiffe://mesh.example/ns-b/svc-b{i}",
                at=_NOW - timedelta(minutes=20 + i),
            )
        # Third issuer in same tenant should now be tenant-blocked.
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A, issuer_kid=_KID, now=_NOW
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "sybil_tenant_quota_exceeded")

    def test_foreign_tenant_unaffected_by_local_saturation(self):
        gate = _gate(max_per_issuer=100, max_per_tenant=2)
        # Saturate mesh.example.
        for i in range(2):
            gate.record_admission(
                issuer_iss=_ISSUER_A,
                issuer_kid=_KID,
                minted_iss=f"spiffe://mesh.example/ns-a/svc-{i}",
                at=_NOW - timedelta(minutes=i),
            )
        # other-mesh.example issuer should still be allowed.
        decision = gate.evaluate(
            issuer_iss=_FOREIGN_ISSUER, issuer_kid=_KID, now=_NOW
        )
        self.assertTrue(decision.allowed)

    def test_reputation_floor_blocks(self):
        rep = IssuerReputation(initial_score=10)
        rep.current_score(_ISSUER_A, _KID, now=_NOW)
        rep.penalize(_ISSUER_A, _KID, amount=15, now=_NOW)
        gate = _gate(reputation=rep, min_reputation=5)
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A, issuer_kid=_KID, now=_NOW
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "sybil_reputation_insufficient")

    def test_reputation_check_runs_before_quota(self):
        # A penalized issuer below floor should be rejected on
        # reputation grounds even if their quota is fine.
        rep = IssuerReputation(initial_score=10)
        rep.current_score(_ISSUER_A, _KID, now=_NOW)
        rep.penalize(_ISSUER_A, _KID, amount=15, now=_NOW)
        gate = _gate(reputation=rep, min_reputation=5, max_per_issuer=100)
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A, issuer_kid=_KID, now=_NOW
        )
        self.assertEqual(decision.reason_code, "sybil_reputation_insufficient")

    def test_negative_quota_rejected_at_construction(self):
        with self.assertRaisesRegex(SybilDeterrenceError, "max_per_issuer"):
            _gate(max_per_issuer=-1)

    def test_zero_window_rejected(self):
        with self.assertRaisesRegex(SybilDeterrenceError, "window"):
            _gate(window=timedelta(0))

class WindowSlideTests(unittest.TestCase):
    def test_old_admissions_age_out_of_window(self):
        gate = _gate(max_per_issuer=2, window=timedelta(minutes=10))
        # Admissions outside the 10-minute window don't count.
        for i in range(5):
            gate.record_admission(
                issuer_iss=_ISSUER_A,
                issuer_kid=_KID,
                minted_iss=f"spiffe://mesh.example/ns-a/svc-{i}",
                at=_NOW - timedelta(minutes=30 + i),
            )
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A, issuer_kid=_KID, now=_NOW
        )
        self.assertTrue(decision.allowed)


def _proof(*, work_units: int = 8, issuer: str = _ISSUER_A, kid: str = _KID):
    return make_attestation_proof(
        work_units=work_units, issuer_iss=issuer, issuer_kid=kid
    )


class AttestationBurdenTests(unittest.TestCase):
    """Leftover #106: optional attestation-burden cost dial."""

    def test_omit_hook_unchanged_without_proof(self):
        gate = _gate()
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A, issuer_kid=_KID, now=_NOW
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason_code, "ok")

    def test_omit_hook_ignores_presented_proof(self):
        gate = _gate()
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A,
            issuer_kid=_KID,
            now=_NOW,
            attestation_proof=_proof(work_units=0),
        )
        self.assertTrue(decision.allowed)

    def test_below_min_work_units_denied(self):
        gate = _gate(burden=AttestationBurden(min_work_units=10))
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A,
            issuer_kid=_KID,
            now=_NOW,
            attestation_proof=_proof(work_units=9),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason_code, "sybil_attestation_burden_insufficient"
        )

    def test_exact_min_work_units_allowed(self):
        gate = _gate(burden=AttestationBurden(min_work_units=10))
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A,
            issuer_kid=_KID,
            now=_NOW,
            attestation_proof=_proof(work_units=10),
        )
        self.assertTrue(decision.allowed)

    def test_missing_proof_fails_closed_when_hook_attached(self):
        gate = _gate(burden=AttestationBurden(min_work_units=1))
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A, issuer_kid=_KID, now=_NOW
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason_code, "sybil_attestation_proof_malformed"
        )

    def test_wrong_type_fails_closed(self):
        gate = _gate(burden=AttestationBurden(min_work_units=1))
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A,
            issuer_kid=_KID,
            now=_NOW,
            attestation_proof={"work_units": 99},  # type: ignore[arg-type]
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason_code, "sybil_attestation_proof_malformed"
        )

    def test_integrity_mismatch_fails_closed(self):
        good = _proof(work_units=10)
        tampered = AttestationBurdenProof(
            work_units=99,
            issuer_iss=good.issuer_iss,
            issuer_kid=good.issuer_kid,
            integrity=good.integrity,
        )
        gate = _gate(burden=AttestationBurden(min_work_units=10))
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A,
            issuer_kid=_KID,
            now=_NOW,
            attestation_proof=tampered,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason_code, "sybil_attestation_proof_malformed"
        )

    def test_issuer_binding_mismatch_fails_closed(self):
        foreign = _proof(work_units=10, issuer=_FOREIGN_ISSUER)
        gate = _gate(burden=AttestationBurden(min_work_units=10))
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A,
            issuer_kid=_KID,
            now=_NOW,
            attestation_proof=foreign,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(
            decision.reason_code, "sybil_attestation_proof_malformed"
        )

    def test_integrity_digest_is_deterministic(self):
        proof = _proof(work_units=8)
        expected = hashlib.sha256(
            jcs.canonicalize(
                {
                    "typ": BURDEN_TYP,
                    "work_units": 8,
                    "issuer_iss": _ISSUER_A,
                    "issuer_kid": _KID,
                }
            )
        ).hexdigest()
        self.assertEqual(proof.integrity, expected)

    def test_sibling_verify_is_callable_from_pipeline(self):
        dial = AttestationBurden(min_work_units=5)
        ok = dial.verify(
            _proof(work_units=5), issuer_iss=_ISSUER_A, issuer_kid=_KID
        )
        self.assertTrue(ok.allowed)
        denied = dial.verify(
            _proof(work_units=4), issuer_iss=_ISSUER_A, issuer_kid=_KID
        )
        self.assertEqual(
            denied.reason_code, "sybil_attestation_burden_insufficient"
        )

    def test_burden_does_not_skip_reputation(self):
        rep = IssuerReputation(initial_score=10)
        rep.current_score(_ISSUER_A, _KID, now=_NOW)
        rep.penalize(_ISSUER_A, _KID, amount=15, now=_NOW)
        gate = _gate(
            reputation=rep,
            min_reputation=5,
            burden=AttestationBurden(min_work_units=1),
        )
        decision = gate.evaluate(
            issuer_iss=_ISSUER_A,
            issuer_kid=_KID,
            now=_NOW,
            attestation_proof=_proof(work_units=1),
        )
        self.assertEqual(decision.reason_code, "sybil_reputation_insufficient")

    def test_invalid_issuer_still_raises_when_hook_attached(self):
        gate = _gate(burden=AttestationBurden(min_work_units=1))
        with self.assertRaisesRegex(SybilDeterrenceError, "issuer_iss"):
            gate.evaluate(
                issuer_iss="not-spiffe",
                issuer_kid=_KID,
                now=_NOW,
            )
        with self.assertRaisesRegex(SybilDeterrenceError, "issuer_kid"):
            gate.evaluate(
                issuer_iss=_ISSUER_A,
                issuer_kid="bad kid",
                now=_NOW,
            )

    def test_negative_min_work_units_rejected(self):
        with self.assertRaisesRegex(SybilDeterrenceError, "min_work_units"):
            AttestationBurden(min_work_units=-1)

    def test_negative_work_units_rejected_at_construct(self):
        with self.assertRaisesRegex(SybilDeterrenceError, "work_units"):
            AttestationBurdenProof(
                work_units=-1,
                issuer_iss=_ISSUER_A,
                issuer_kid=_KID,
                integrity="0" * 64,
            )


if __name__ == "__main__":
    unittest.main()
