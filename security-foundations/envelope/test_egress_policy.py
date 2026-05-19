"""Tests for policy-adaptive egress (Phase 2 Track C C2)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from data_classification import DataClass
from egress_policy import (
    EgressAction,
    EgressDecision,
    EgressError,
    EgressMatrixCell,
    MatrixEgressPolicy,
    require_egress,
)
from output_scanning import RiskLevel


def _cell(risk: RiskLevel, dc: DataClass, action: EgressAction) -> EgressMatrixCell:
    return EgressMatrixCell(risk=risk, data_class=dc, action=action)


class CellValidationTests(unittest.TestCase):
    def test_non_risklevel_rejected(self):
        with self.assertRaisesRegex(ValueError, "risk"):
            EgressMatrixCell(
                risk="critical",  # type: ignore[arg-type]
                data_class=DataClass.PUBLIC,
                action=EgressAction.ALLOW,
            )

    def test_non_dataclass_rejected(self):
        with self.assertRaisesRegex(ValueError, "data_class"):
            EgressMatrixCell(
                risk=RiskLevel.NONE,
                data_class="public",  # type: ignore[arg-type]
                action=EgressAction.ALLOW,
            )

    def test_non_action_rejected(self):
        with self.assertRaisesRegex(ValueError, "action"):
            EgressMatrixCell(
                risk=RiskLevel.NONE,
                data_class=DataClass.PUBLIC,
                action="allow",  # type: ignore[arg-type]
            )


class MatrixValidationTests(unittest.TestCase):
    def test_duplicate_cell_rejected(self):
        c = _cell(RiskLevel.NONE, DataClass.PUBLIC, EgressAction.ALLOW)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            MatrixEgressPolicy(cells=(c, c))

    def test_non_bool_no_export_rejected(self):
        with self.assertRaisesRegex(ValueError, "restricted_no_export"):
            MatrixEgressPolicy(
                cells=(_cell(RiskLevel.NONE, DataClass.PUBLIC, EgressAction.ALLOW),),
                restricted_no_export="yes",  # type: ignore[arg-type]
            )


class MatrixDispatchTests(unittest.TestCase):
    def _full_policy(self, **overrides):
        return MatrixEgressPolicy(
            cells=(
                _cell(RiskLevel.NONE, DataClass.PUBLIC, EgressAction.ALLOW),
                _cell(RiskLevel.NONE, DataClass.INTERNAL, EgressAction.ALLOW),
                _cell(RiskLevel.LOW, DataClass.PUBLIC, EgressAction.ALLOW),
                _cell(RiskLevel.MEDIUM, DataClass.INTERNAL, EgressAction.QUARANTINE),
                _cell(RiskLevel.HIGH, DataClass.INTERNAL, EgressAction.DENY),
                _cell(RiskLevel.CRITICAL, DataClass.PUBLIC, EgressAction.DENY),
            ),
            **overrides,
        )

    def test_allow_path(self):
        decision = self._full_policy().evaluate(
            risk=RiskLevel.NONE, data_class=DataClass.PUBLIC
        )
        self.assertEqual(decision.action, EgressAction.ALLOW)
        self.assertEqual(decision.reason_code, "ok")

    def test_quarantine_path(self):
        decision = self._full_policy().evaluate(
            risk=RiskLevel.MEDIUM, data_class=DataClass.INTERNAL
        )
        self.assertEqual(decision.action, EgressAction.QUARANTINE)
        self.assertEqual(decision.reason_code, "egress_quarantined")

    def test_matrix_deny_path(self):
        decision = self._full_policy().evaluate(
            risk=RiskLevel.HIGH, data_class=DataClass.INTERNAL
        )
        self.assertEqual(decision.action, EgressAction.DENY)
        self.assertEqual(decision.reason_code, "egress_denied_by_policy")

    def test_no_matrix_entry_defaults_to_deny(self):
        decision = self._full_policy().evaluate(
            # MEDIUM/PUBLIC is unspecified in the matrix.
            risk=RiskLevel.MEDIUM,
            data_class=DataClass.PUBLIC,
        )
        self.assertEqual(decision.action, EgressAction.DENY)
        self.assertEqual(decision.reason_code, "egress_no_matrix_entry")


class RestrictedNoExportTests(unittest.TestCase):
    def test_restricted_denied_even_with_allow_cell(self):
        policy = MatrixEgressPolicy(
            cells=(
                _cell(RiskLevel.NONE, DataClass.RESTRICTED, EgressAction.ALLOW),
            ),
        )
        decision = policy.evaluate(
            risk=RiskLevel.NONE, data_class=DataClass.RESTRICTED
        )
        self.assertEqual(decision.action, EgressAction.DENY)
        self.assertEqual(decision.reason_code, "egress_restricted_no_export")

    def test_restricted_denied_even_with_quarantine_cell(self):
        policy = MatrixEgressPolicy(
            cells=(
                _cell(
                    RiskLevel.NONE,
                    DataClass.RESTRICTED,
                    EgressAction.QUARANTINE,
                ),
            ),
        )
        decision = policy.evaluate(
            risk=RiskLevel.NONE, data_class=DataClass.RESTRICTED
        )
        self.assertEqual(decision.action, EgressAction.DENY)
        self.assertEqual(decision.reason_code, "egress_restricted_no_export")

    def test_no_export_opt_out_lets_matrix_decide(self):
        policy = MatrixEgressPolicy(
            cells=(
                _cell(RiskLevel.NONE, DataClass.RESTRICTED, EgressAction.ALLOW),
            ),
            restricted_no_export=False,
        )
        decision = policy.evaluate(
            risk=RiskLevel.NONE, data_class=DataClass.RESTRICTED
        )
        self.assertEqual(decision.action, EgressAction.ALLOW)

    def test_non_restricted_unaffected_by_no_export(self):
        policy = MatrixEgressPolicy(
            cells=(
                _cell(RiskLevel.NONE, DataClass.CONFIDENTIAL, EgressAction.ALLOW),
            ),
        )
        decision = policy.evaluate(
            risk=RiskLevel.NONE, data_class=DataClass.CONFIDENTIAL
        )
        self.assertEqual(decision.action, EgressAction.ALLOW)


class RequireEgressTests(unittest.TestCase):
    def test_allow_returns_decision(self):
        policy = MatrixEgressPolicy(
            cells=(_cell(RiskLevel.NONE, DataClass.PUBLIC, EgressAction.ALLOW),)
        )
        d = require_egress(
            risk=RiskLevel.NONE, data_class=DataClass.PUBLIC, policy=policy
        )
        self.assertIsInstance(d, EgressDecision)
        self.assertEqual(d.action, EgressAction.ALLOW)

    def test_deny_raises(self):
        policy = MatrixEgressPolicy(cells=())  # default-deny everything
        with self.assertRaises(EgressError) as ctx:
            require_egress(
                risk=RiskLevel.NONE, data_class=DataClass.PUBLIC, policy=policy
            )
        self.assertEqual(ctx.exception.decision.reason_code, "egress_no_matrix_entry")

    def test_quarantine_also_raises(self):
        policy = MatrixEgressPolicy(
            cells=(_cell(RiskLevel.LOW, DataClass.PUBLIC, EgressAction.QUARANTINE),)
        )
        with self.assertRaises(EgressError) as ctx:
            require_egress(
                risk=RiskLevel.LOW, data_class=DataClass.PUBLIC, policy=policy
            )
        self.assertEqual(ctx.exception.decision.action, EgressAction.QUARANTINE)


if __name__ == "__main__":
    unittest.main()
