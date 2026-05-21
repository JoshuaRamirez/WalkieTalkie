"""Tests for the safe-mode engine (Phase 3 Track C C1+C2+C3)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from safe_mode_engine import (
    DowngradeApproval,
    SafeModeEngine,
    SafeModeEngineError,
    SafeModeState,
    Trigger,
    TriggerCategory,
    TriggerKind,
    is_higher_authority,
    is_more_severe_state,
    max_state,
    require_authorized_downgrade,
    trigger_for,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)


class StateOrderingTests(unittest.TestCase):
    def test_severity_chain(self):
        self.assertTrue(
            is_more_severe_state(SafeModeState.S4_LOCKDOWN, SafeModeState.S3_QUARANTINE)
        )
        self.assertTrue(
            is_more_severe_state(SafeModeState.S3_QUARANTINE, SafeModeState.S2_RESTRICTED)
        )
        self.assertFalse(
            is_more_severe_state(SafeModeState.S1_GUARDED, SafeModeState.S2_RESTRICTED)
        )

    def test_max_state(self):
        self.assertEqual(
            max_state(
                [SafeModeState.S0_NORMAL, SafeModeState.S2_RESTRICTED, SafeModeState.S4_LOCKDOWN]
            ),
            SafeModeState.S4_LOCKDOWN,
        )
        self.assertEqual(max_state([]), SafeModeState.S0_NORMAL)


class AuthorityHierarchyTests(unittest.TestCase):
    def test_crypto_trust_outranks_authorization(self):
        self.assertTrue(
            is_higher_authority(
                TriggerCategory.CRYPTO_TRUST, TriggerCategory.AUTHORIZATION
            )
        )

    def test_authorization_outranks_data_protection(self):
        self.assertTrue(
            is_higher_authority(
                TriggerCategory.AUTHORIZATION, TriggerCategory.DATA_PROTECTION
            )
        )

    def test_data_protection_outranks_availability(self):
        self.assertTrue(
            is_higher_authority(
                TriggerCategory.DATA_PROTECTION, TriggerCategory.AVAILABILITY
            )
        )


class TriggerValidationTests(unittest.TestCase):
    def test_normal_state_rejected(self):
        with self.assertRaisesRegex(SafeModeEngineError, "S0_NORMAL"):
            Trigger(
                kind=TriggerKind.POLICY_ROLLBACK,
                category=TriggerCategory.AUTHORIZATION,
                minimum_state=SafeModeState.S0_NORMAL,
                observed_at=_NOW,
                detail="x",
            )

    def test_naive_observed_at_rejected(self):
        with self.assertRaisesRegex(SafeModeEngineError, "timezone-aware"):
            Trigger(
                kind=TriggerKind.POLICY_ROLLBACK,
                category=TriggerCategory.AUTHORIZATION,
                minimum_state=SafeModeState.S2_RESTRICTED,
                observed_at=datetime(2026, 4, 14, 12),
                detail="x",
            )


class ObserveTests(unittest.TestCase):
    def test_starts_at_s0(self):
        engine = SafeModeEngine()
        self.assertEqual(engine.current, SafeModeState.S0_NORMAL)

    def test_first_trigger_elevates(self):
        engine = SafeModeEngine()
        transition = engine.observe(
            trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
        )
        self.assertEqual(engine.current, SafeModeState.S2_RESTRICTED)
        self.assertIsNotNone(transition)
        self.assertEqual(transition.from_state, SafeModeState.S0_NORMAL)
        self.assertEqual(transition.to_state, SafeModeState.S2_RESTRICTED)

    def test_compound_triggers_resolve_to_max(self):
        engine = SafeModeEngine()
        engine.observe(trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW))
        engine.observe(
            trigger_for(TriggerKind.LEDGER_DIVERGENCE, observed_at=_NOW)
        )
        # ledger_divergence default → S4_LOCKDOWN.
        self.assertEqual(engine.current, SafeModeState.S4_LOCKDOWN)

    def test_idempotent_re_observation(self):
        engine = SafeModeEngine()
        first = engine.observe(
            trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
        )
        second = engine.observe(
            trigger_for(
                TriggerKind.POLICY_ROLLBACK,
                observed_at=_NOW + timedelta(seconds=30),
            )
        )
        self.assertIsNotNone(first)
        self.assertIsNone(second)  # no new transition
        self.assertEqual(engine.current, SafeModeState.S2_RESTRICTED)

    def test_re_observation_with_higher_severity_elevates(self):
        engine = SafeModeEngine()
        engine.observe(
            Trigger(
                kind=TriggerKind.POLICY_ROLLBACK,
                category=TriggerCategory.AUTHORIZATION,
                minimum_state=SafeModeState.S1_GUARDED,
                observed_at=_NOW,
                detail="initial sighting",
            )
        )
        elevated = engine.observe(
            Trigger(
                kind=TriggerKind.POLICY_ROLLBACK,
                category=TriggerCategory.AUTHORIZATION,
                minimum_state=SafeModeState.S3_QUARANTINE,
                observed_at=_NOW + timedelta(seconds=10),
                detail="escalated",
            )
        )
        self.assertIsNotNone(elevated)
        self.assertEqual(engine.current, SafeModeState.S3_QUARANTINE)


class ClearTests(unittest.TestCase):
    def test_clearing_last_trigger_returns_to_s0(self):
        engine = SafeModeEngine()
        engine.observe(trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW))
        engine.clear(TriggerKind.POLICY_ROLLBACK, at=_NOW + timedelta(seconds=60))
        self.assertEqual(engine.current, SafeModeState.S0_NORMAL)

    def test_clearing_one_of_many_recomputes_to_max_remaining(self):
        engine = SafeModeEngine()
        engine.observe(trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW))
        engine.observe(
            trigger_for(TriggerKind.LEDGER_DIVERGENCE, observed_at=_NOW)
        )
        # Clear the more-severe one — state drops to S2 (the
        # remaining policy_rollback).
        engine.clear(
            TriggerKind.LEDGER_DIVERGENCE, at=_NOW + timedelta(seconds=60)
        )
        self.assertEqual(engine.current, SafeModeState.S2_RESTRICTED)

    def test_clearing_non_active_is_noop(self):
        engine = SafeModeEngine()
        result = engine.clear(TriggerKind.POLICY_ROLLBACK, at=_NOW)
        self.assertIsNone(result)
        self.assertEqual(engine.current, SafeModeState.S0_NORMAL)


class DowngradeTests(unittest.TestCase):
    def _approval(self, authority: TriggerCategory) -> DowngradeApproval:
        return DowngradeApproval(
            approver_iss="spiffe://mesh.example/ns-ops/approver-1",
            approver_kid="approver-kid-1",
            authority=authority,
            issued_at=_NOW,
            detail="ops decision",
        )

    def test_downgrade_blocked_when_higher_category_trigger_active(self):
        engine = SafeModeEngine()
        engine.observe(
            trigger_for(TriggerKind.LEDGER_DIVERGENCE, observed_at=_NOW)
        )
        # Approver authority is AUTHORIZATION; ledger_divergence is
        # CRYPTO_TRUST, so the approval cannot override it.
        with self.assertRaisesRegex(SafeModeEngineError, "unauthorized"):
            engine.downgrade(
                to_state=SafeModeState.S0_NORMAL,
                approval=self._approval(TriggerCategory.AUTHORIZATION),
            )

    def test_downgrade_allowed_when_authority_dominates(self):
        engine = SafeModeEngine()
        engine.observe(
            trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
        )
        # POLICY_ROLLBACK is AUTHORIZATION; approver is CRYPTO_TRUST.
        # Authority dominates so downgrade is permitted — but the
        # target must still be at least S2 because the trigger is
        # still active. Downgrade to S2 succeeds (no-op effectively),
        # but to S0 is blocked.
        engine.downgrade(
            to_state=SafeModeState.S2_RESTRICTED,
            approval=self._approval(TriggerCategory.CRYPTO_TRUST),
        )
        with self.assertRaisesRegex(SafeModeEngineError, "blocked"):
            engine.downgrade(
                to_state=SafeModeState.S0_NORMAL,
                approval=self._approval(TriggerCategory.CRYPTO_TRUST),
            )

    def test_downgrade_to_more_severe_rejected(self):
        engine = SafeModeEngine()
        engine.observe(
            trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
        )
        with self.assertRaisesRegex(SafeModeEngineError, "more severe"):
            engine.downgrade(
                to_state=SafeModeState.S4_LOCKDOWN,
                approval=self._approval(TriggerCategory.CRYPTO_TRUST),
            )

    def test_require_authorized_downgrade_tags_codes(self):
        engine = SafeModeEngine()
        engine.observe(
            trigger_for(TriggerKind.LEDGER_DIVERGENCE, observed_at=_NOW)
        )
        with self.assertRaisesRegex(
            SafeModeEngineError, "safe_mode_downgrade_unauthorized"
        ):
            require_authorized_downgrade(
                engine,
                to_state=SafeModeState.S0_NORMAL,
                approval=self._approval(TriggerCategory.AUTHORIZATION),
            )


class DeterminismTests(unittest.TestCase):
    """Track C acceptance: 'Compound failures always result in
    predictable state and logs.'"""

    def _scenario(self, engine: SafeModeEngine) -> list[SafeModeState]:
        history = [engine.current]
        engine.observe(
            trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
        )
        history.append(engine.current)
        engine.observe(
            trigger_for(TriggerKind.ANOMALY_QUARANTINE, observed_at=_NOW)
        )
        history.append(engine.current)
        engine.observe(
            trigger_for(TriggerKind.LEDGER_DIVERGENCE, observed_at=_NOW)
        )
        history.append(engine.current)
        engine.clear(
            TriggerKind.LEDGER_DIVERGENCE, at=_NOW + timedelta(seconds=60)
        )
        history.append(engine.current)
        engine.clear(
            TriggerKind.ANOMALY_QUARANTINE,
            at=_NOW + timedelta(seconds=120),
        )
        history.append(engine.current)
        engine.clear(
            TriggerKind.POLICY_ROLLBACK, at=_NOW + timedelta(seconds=180)
        )
        history.append(engine.current)
        return history

    def test_two_engines_walk_identical_history(self):
        a = SafeModeEngine()
        b = SafeModeEngine()
        self.assertEqual(self._scenario(a), self._scenario(b))

    def test_expected_history(self):
        engine = SafeModeEngine()
        history = self._scenario(engine)
        self.assertEqual(
            history,
            [
                SafeModeState.S0_NORMAL,
                SafeModeState.S2_RESTRICTED,    # policy_rollback
                SafeModeState.S3_QUARANTINE,    # +anomaly_quarantine
                SafeModeState.S4_LOCKDOWN,      # +ledger_divergence
                SafeModeState.S3_QUARANTINE,    # -ledger_divergence
                SafeModeState.S2_RESTRICTED,    # -anomaly_quarantine
                SafeModeState.S0_NORMAL,        # -policy_rollback
            ],
        )


class TransitionRecordTests(unittest.TestCase):
    def test_transition_captures_active_kinds_after_change(self):
        engine = SafeModeEngine()
        transition = engine.observe(
            trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW)
        )
        self.assertEqual(transition.cause, "trigger")
        self.assertIn(TriggerKind.POLICY_ROLLBACK, transition.active_kinds)

    def test_clear_transition_recorded_with_cause(self):
        engine = SafeModeEngine()
        engine.observe(trigger_for(TriggerKind.POLICY_ROLLBACK, observed_at=_NOW))
        transition = engine.clear(
            TriggerKind.POLICY_ROLLBACK,
            at=_NOW + timedelta(seconds=60),
        )
        self.assertEqual(transition.cause, "clear")
        self.assertEqual(transition.to_state, SafeModeState.S0_NORMAL)
        self.assertEqual(transition.active_kinds, ())


if __name__ == "__main__":
    unittest.main()
