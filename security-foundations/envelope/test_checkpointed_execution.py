"""Tests for checkpointed execution (Phase 2 Track E E1)."""

import hashlib
import pathlib
import sys
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from capability_token import CapabilityClaims
from checkpointed_execution import (
    Checkpoint,
    CheckpointAction,
    CheckpointDecision,
    CheckpointError,
    CheckpointPolicy,
    InMemoryRevocationLedger,
    validate_checkpoint,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_TS = int(_NOW.timestamp())
_TASK_ID = "01900000-0000-7000-8000-000000000001"
_CKPT_ID = "01900000-0000-7000-8000-000000000002"
_CAP_JTI = "01900000-0000-7000-8000-000000000003"
_ENV_DIGEST = hashlib.sha256(b"env").hexdigest()


def _checkpoint(**overrides) -> Checkpoint:
    kwargs = dict(
        checkpoint_id=_CKPT_ID,
        task_id=_TASK_ID,
        step=1,
        requested_at="2026-04-14T12:00:00Z",
        intended_action="db_write:users",
    )
    kwargs.update(overrides)
    return Checkpoint(**kwargs)


def _capability(**overrides) -> CapabilityClaims:
    kwargs = dict(
        iss="spiffe://mesh.example/ns-iss/issuer-1",
        sub="spiffe://mesh.example/ns-a/agent-1",
        aud="spiffe://mesh.example/ns-b/service-1",
        scope="invoke_tool",
        iat=_NOW_TS - 60,
        nbf=_NOW_TS - 60,
        exp=_NOW_TS + 300,
        jti=_CAP_JTI,
        envelope_digest=_ENV_DIGEST,
        issuer_kid="issuer-kid-1",
    )
    kwargs.update(overrides)
    return CapabilityClaims(**kwargs)


def _policy(**overrides) -> CheckpointPolicy:
    kwargs = dict(expected_epoch="epoch-2026-04-14-01")
    kwargs.update(overrides)
    return CheckpointPolicy(**kwargs)


class CheckpointShapeTests(unittest.TestCase):
    def test_invalid_task_id_rejected(self):
        with self.assertRaisesRegex(CheckpointError, "task_id"):
            _checkpoint(task_id="not-uuidv7")

    def test_negative_step_rejected(self):
        with self.assertRaisesRegex(CheckpointError, "step"):
            _checkpoint(step=-1)

    def test_empty_action_rejected(self):
        with self.assertRaisesRegex(CheckpointError, "intended_action"):
            _checkpoint(intended_action="")


class PolicyShapeTests(unittest.TestCase):
    def test_empty_epoch_rejected(self):
        with self.assertRaisesRegex(CheckpointError, "expected_epoch"):
            _policy(expected_epoch="")

    def test_commit_as_failure_action_rejected(self):
        with self.assertRaisesRegex(CheckpointError, "COMMIT"):
            _policy(on_capability_revoked=CheckpointAction.COMMIT)


class HappyPathTests(unittest.TestCase):
    def test_commit_when_all_checks_pass(self):
        decision = validate_checkpoint(
            checkpoint=_checkpoint(),
            capability=_capability(),
            active_epoch="epoch-2026-04-14-01",
            policy=_policy(),
            ledger=InMemoryRevocationLedger(),
            current=_NOW,
        )
        self.assertIsInstance(decision, CheckpointDecision)
        self.assertEqual(decision.action, CheckpointAction.COMMIT)
        self.assertEqual(decision.reason_code, "ok")


class ExpirationTests(unittest.TestCase):
    def test_expired_capability_aborted(self):
        cap = _capability(exp=_NOW_TS - 3600, nbf=_NOW_TS - 7200, iat=_NOW_TS - 7200)
        decision = validate_checkpoint(
            checkpoint=_checkpoint(),
            capability=cap,
            active_epoch="epoch-2026-04-14-01",
            policy=_policy(),
            ledger=InMemoryRevocationLedger(),
            current=_NOW,
        )
        self.assertEqual(decision.action, CheckpointAction.ABORT)
        self.assertEqual(decision.reason_code, "checkpoint_capability_expired")

    def test_expired_capability_can_downgrade_when_configured(self):
        cap = _capability(exp=_NOW_TS - 3600, nbf=_NOW_TS - 7200, iat=_NOW_TS - 7200)
        decision = validate_checkpoint(
            checkpoint=_checkpoint(),
            capability=cap,
            active_epoch="epoch-2026-04-14-01",
            policy=_policy(on_capability_expired=CheckpointAction.DOWNGRADE),
            ledger=InMemoryRevocationLedger(),
            current=_NOW,
        )
        self.assertEqual(decision.action, CheckpointAction.DOWNGRADE)
        self.assertEqual(decision.reason_code, "checkpoint_capability_expired")


class RevocationTests(unittest.TestCase):
    def test_revoked_capability_blocked_at_next_checkpoint(self):
        # The Phase 2 Track E acceptance criterion in writing:
        # "Revoked capability cannot commit writes post-revocation
        # checkpoint." We construct a still-current capability, revoke
        # its jti in the ledger, and assert the next checkpoint aborts.
        cap = _capability()
        ledger = InMemoryRevocationLedger()
        ledger.revoke(cap.jti, at=_NOW, reason="operator-initiated")
        decision = validate_checkpoint(
            checkpoint=_checkpoint(),
            capability=cap,
            active_epoch="epoch-2026-04-14-01",
            policy=_policy(),
            ledger=ledger,
            current=_NOW,
        )
        self.assertEqual(decision.action, CheckpointAction.ABORT)
        self.assertEqual(decision.reason_code, "checkpoint_capability_revoked")

    def test_revocation_downgrade_path(self):
        cap = _capability()
        ledger = InMemoryRevocationLedger()
        ledger.revoke(cap.jti, at=_NOW, reason="operator-initiated")
        decision = validate_checkpoint(
            checkpoint=_checkpoint(),
            capability=cap,
            active_epoch="epoch-2026-04-14-01",
            policy=_policy(on_capability_revoked=CheckpointAction.DOWNGRADE),
            ledger=ledger,
            current=_NOW,
        )
        self.assertEqual(decision.action, CheckpointAction.DOWNGRADE)

    def test_revoke_validates_inputs(self):
        ledger = InMemoryRevocationLedger()
        with self.assertRaisesRegex(CheckpointError, "jti"):
            ledger.revoke("not-uuid", at=_NOW, reason="x")
        with self.assertRaisesRegex(CheckpointError, "timezone-aware"):
            ledger.revoke(_CAP_JTI, at=datetime(2026, 4, 14, 12), reason="x")  # naive
        with self.assertRaisesRegex(CheckpointError, "reason"):
            ledger.revoke(_CAP_JTI, at=_NOW, reason="")


class EpochMismatchTests(unittest.TestCase):
    def test_epoch_mismatch_aborts_by_default(self):
        decision = validate_checkpoint(
            checkpoint=_checkpoint(),
            capability=_capability(),
            active_epoch="epoch-2026-04-15-01",  # newer than policy expects
            policy=_policy(),
            ledger=InMemoryRevocationLedger(),
            current=_NOW,
        )
        self.assertEqual(decision.action, CheckpointAction.ABORT)
        self.assertEqual(decision.reason_code, "checkpoint_policy_epoch_mismatch")

    def test_epoch_mismatch_can_downgrade(self):
        decision = validate_checkpoint(
            checkpoint=_checkpoint(),
            capability=_capability(),
            active_epoch="epoch-2026-04-15-01",
            policy=_policy(on_epoch_mismatch=CheckpointAction.DOWNGRADE),
            ledger=InMemoryRevocationLedger(),
            current=_NOW,
        )
        self.assertEqual(decision.action, CheckpointAction.DOWNGRADE)


class CheckOrderingTests(unittest.TestCase):
    def test_expiration_check_runs_before_revocation(self):
        # When both checks would fail, expiration wins because it's
        # the more fundamental invariant — an expired cap is invalid
        # to anyone, while a revoked-but-still-current cap is only
        # invalid to issuers that know about the revocation.
        cap = _capability(exp=_NOW_TS - 3600, nbf=_NOW_TS - 7200, iat=_NOW_TS - 7200)
        ledger = InMemoryRevocationLedger()
        ledger.revoke(cap.jti, at=_NOW, reason="x")
        decision = validate_checkpoint(
            checkpoint=_checkpoint(),
            capability=cap,
            active_epoch="epoch-2026-04-14-01",
            policy=_policy(),
            ledger=ledger,
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "checkpoint_capability_expired")

    def test_revocation_check_runs_before_epoch_mismatch(self):
        cap = _capability()
        ledger = InMemoryRevocationLedger()
        ledger.revoke(cap.jti, at=_NOW, reason="x")
        decision = validate_checkpoint(
            checkpoint=_checkpoint(),
            capability=cap,
            active_epoch="epoch-2026-04-15-01",  # also mismatched
            policy=_policy(),
            ledger=ledger,
            current=_NOW,
        )
        self.assertEqual(decision.reason_code, "checkpoint_capability_revoked")


class InputValidationTests(unittest.TestCase):
    def test_non_capability_rejected(self):
        with self.assertRaisesRegex(CheckpointError, "CapabilityClaims"):
            validate_checkpoint(
                checkpoint=_checkpoint(),
                capability="not-claims",  # type: ignore[arg-type]
                active_epoch="epoch-2026-04-14-01",
                policy=_policy(),
                ledger=InMemoryRevocationLedger(),
                current=_NOW,
            )

    def test_empty_active_epoch_rejected(self):
        with self.assertRaisesRegex(CheckpointError, "active_epoch"):
            validate_checkpoint(
                checkpoint=_checkpoint(),
                capability=_capability(),
                active_epoch="",
                policy=_policy(),
                ledger=InMemoryRevocationLedger(),
                current=_NOW,
            )


if __name__ == "__main__":
    unittest.main()
