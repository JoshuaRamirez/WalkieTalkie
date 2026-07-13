"""Tests for prompt assembly minimization (Phase 2 Track B B3)."""

import hashlib
import pathlib
import sys
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from data_classification import DataClass, classify
from prompt_assembly import (
    ActionBudget,
    PromptAssemblyError,
    PromptCandidate,
    PromptContext,
    compose,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_ACTOR_HOME = "spiffe://mesh.example/ns-a/svc"
_ACTOR_FOREIGN = "spiffe://other-mesh.example/ns-z/svc"
_KID = "kid-a"


def _data(*, data_class: DataClass, actor: str = _ACTOR_HOME, salt: str = "x"):
    return classify(
        data_digest=hashlib.sha256(salt.encode()).hexdigest(),
        data_class=data_class,
        actor_iss=actor,
        actor_kid=_KID,
        now=_NOW,
    )


def _candidate(label: str, data_class: DataClass, *, actor: str = _ACTOR_HOME):
    return PromptCandidate(
        source_label=label,
        data=_data(data_class=data_class, actor=actor, salt=label),
        text=f"[{label}]",
    )


class ActionBudgetValidationTests(unittest.TestCase):
    def test_empty_action_rejected(self):
        with self.assertRaisesRegex(PromptAssemblyError, "action"):
            ActionBudget(action="", max_class=DataClass.PUBLIC, max_items=1)

    def test_non_dataclass_rejected(self):
        with self.assertRaisesRegex(PromptAssemblyError, "max_class"):
            ActionBudget(
                action="summarize",
                max_class="public",  # type: ignore[arg-type]
                max_items=1,
            )

    def test_zero_max_items_rejected(self):
        with self.assertRaisesRegex(PromptAssemblyError, "max_items"):
            ActionBudget(
                action="summarize", max_class=DataClass.PUBLIC, max_items=0
            )


class PromptCandidateValidationTests(unittest.TestCase):
    def test_empty_source_label_rejected(self):
        with self.assertRaisesRegex(PromptAssemblyError, "source_label"):
            PromptCandidate(
                source_label="",
                data=_data(data_class=DataClass.PUBLIC),
                text="x",
            )

    def test_non_classified_data_rejected(self):
        with self.assertRaisesRegex(PromptAssemblyError, "ClassifiedData"):
            PromptCandidate(
                source_label="src",
                data="not-classified",  # type: ignore[arg-type]
                text="x",
            )


class ClassCeilingTests(unittest.TestCase):
    def test_drops_items_above_budget(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.INTERNAL,
            max_items=10,
        )
        ctx = compose(
            [
                _candidate("a", DataClass.PUBLIC),
                _candidate("b", DataClass.INTERNAL),
                _candidate("c", DataClass.CONFIDENTIAL),
                _candidate("d", DataClass.RESTRICTED),
            ],
            budget=budget,
        )
        labels = [i.source_label for i in ctx.items]
        self.assertEqual(labels, ["a", "b"])
        dropped = {(d.source_label, d.reason_code) for d in ctx.dropped}
        self.assertEqual(
            dropped,
            {
                ("c", "class_exceeds_budget"),
                ("d", "class_exceeds_budget"),
            },
        )

    def test_class_equal_to_budget_kept(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.CONFIDENTIAL,
            max_items=10,
        )
        ctx = compose(
            [_candidate("a", DataClass.CONFIDENTIAL)],
            budget=budget,
        )
        self.assertEqual(len(ctx.items), 1)
        self.assertEqual(ctx.dropped, ())


class LeastSensitiveFirstTests(unittest.TestCase):
    def test_orders_by_rank_then_label(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.RESTRICTED,
            max_items=10,
        )
        ctx = compose(
            [
                _candidate("z-conf", DataClass.CONFIDENTIAL),
                _candidate("b-pub", DataClass.PUBLIC),
                _candidate("a-pub", DataClass.PUBLIC),
                _candidate("m-int", DataClass.INTERNAL),
            ],
            budget=budget,
        )
        labels = [i.source_label for i in ctx.items]
        # PUBLIC (a, b) → INTERNAL → CONFIDENTIAL
        self.assertEqual(labels, ["a-pub", "b-pub", "m-int", "z-conf"])

    def test_ordering_is_deterministic_across_calls(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.RESTRICTED,
            max_items=10,
        )
        cands = [
            _candidate("aaa", DataClass.PUBLIC),
            _candidate("bbb", DataClass.PUBLIC),
        ]
        c1 = compose(cands, budget=budget)
        c2 = compose(list(reversed(cands)), budget=budget)
        self.assertEqual(
            [i.source_label for i in c1.items],
            [i.source_label for i in c2.items],
        )


class MaxItemsTests(unittest.TestCase):
    def test_overflow_dropped_with_distinct_reason(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.RESTRICTED,
            max_items=2,
        )
        ctx = compose(
            [
                _candidate("a", DataClass.PUBLIC),
                _candidate("b", DataClass.PUBLIC),
                _candidate("c", DataClass.PUBLIC),
            ],
            budget=budget,
        )
        self.assertEqual([i.source_label for i in ctx.items], ["a", "b"])
        self.assertEqual(
            [(d.source_label, d.reason_code) for d in ctx.dropped],
            [("c", "items_over_budget")],
        )

    def test_overflow_kept_after_class_filter(self):
        # Drops c (class) AND overflows e (items=2). Confirms both
        # reasons can coexist in the same drop log.
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.INTERNAL,
            max_items=2,
        )
        ctx = compose(
            [
                _candidate("a", DataClass.PUBLIC),
                _candidate("b", DataClass.PUBLIC),
                _candidate("c", DataClass.CONFIDENTIAL),
                _candidate("d", DataClass.PUBLIC),
            ],
            budget=budget,
        )
        self.assertEqual([i.source_label for i in ctx.items], ["a", "b"])
        reasons = {(d.source_label, d.reason_code) for d in ctx.dropped}
        self.assertIn(("c", "class_exceeds_budget"), reasons)
        self.assertIn(("d", "items_over_budget"), reasons)


class LoggingMetadataTests(unittest.TestCase):
    def test_items_carry_trust_label(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.RESTRICTED,
            max_items=10,
        )
        ctx = compose(
            [
                _candidate("home", DataClass.PUBLIC, actor=_ACTOR_HOME),
                _candidate("away", DataClass.PUBLIC, actor=_ACTOR_FOREIGN),
            ],
            budget=budget,
        )
        labels = {(i.source_label, i.trust_label) for i in ctx.items}
        self.assertEqual(
            labels,
            {
                ("home", "mesh.example"),
                ("away", "other-mesh.example"),
            },
        )

    def test_items_carry_class_for_audit(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.CONFIDENTIAL,
            max_items=10,
        )
        ctx = compose(
            [
                _candidate("a", DataClass.PUBLIC),
                _candidate("b", DataClass.CONFIDENTIAL),
            ],
            budget=budget,
        )
        by_label = {i.source_label: i.data_class for i in ctx.items}
        self.assertEqual(by_label["a"], DataClass.PUBLIC)
        self.assertEqual(by_label["b"], DataClass.CONFIDENTIAL)


class RealizedMaxClassTests(unittest.TestCase):
    def test_empty_returns_public(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.RESTRICTED,
            max_items=10,
        )
        ctx = compose([], budget=budget)
        self.assertEqual(ctx.items, ())
        self.assertEqual(ctx.realized_max_class, DataClass.PUBLIC)

    def test_reflects_actual_included_max(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.RESTRICTED,
            max_items=10,
        )
        ctx = compose(
            [
                _candidate("a", DataClass.PUBLIC),
                _candidate("b", DataClass.INTERNAL),
            ],
            budget=budget,
        )
        # Budget allows RESTRICTED, but realized max is INTERNAL.
        self.assertEqual(ctx.realized_max_class, DataClass.INTERNAL)


class ResultShapeTests(unittest.TestCase):
    def test_returns_prompt_context(self):
        budget = ActionBudget(
            action="summarize",
            max_class=DataClass.PUBLIC,
            max_items=1,
        )
        ctx = compose([_candidate("a", DataClass.PUBLIC)], budget=budget)
        self.assertIsInstance(ctx, PromptContext)
        self.assertEqual(ctx.action, "summarize")
        self.assertEqual(ctx.max_class, DataClass.PUBLIC)

    def test_non_candidate_input_rejected(self):
        budget = ActionBudget(
            action="summarize", max_class=DataClass.PUBLIC, max_items=1
        )
        with self.assertRaisesRegex(PromptAssemblyError, "PromptCandidate"):
            compose(["not-a-candidate"], budget=budget)  # type: ignore[list-item]


if __name__ == "__main__":
    unittest.main()
