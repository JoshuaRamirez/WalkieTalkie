"""Tests for the policy engine (Phase 5 Track B B1)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from policy_engine import (
    ANY,
    Condition,
    ConditionOp,
    Effect,
    NativePolicyEngine,
    PolicyEngineError,
    PolicyRequest,
    PolicyRule,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_CALLER = "spiffe://mesh.example/ns-a/agent-1"


class ConditionTests(unittest.TestCase):
    def test_equals(self):
        c = Condition(key="tier", op=ConditionOp.EQUALS, value="prod")
        self.assertTrue(c.matches({"tier": "prod"}))
        self.assertFalse(c.matches({"tier": "dev"}))
        self.assertFalse(c.matches({}))

    def test_in(self):
        c = Condition(key="tool", op=ConditionOp.IN, value=["read_file", "ping"])
        self.assertTrue(c.matches({"tool": "ping"}))
        self.assertFalse(c.matches({"tool": "exec_sql"}))

    def test_not_in(self):
        c = Condition(key="tool", op=ConditionOp.NOT_IN, value=["exec_sql"])
        self.assertTrue(c.matches({"tool": "ping"}))
        self.assertFalse(c.matches({"tool": "exec_sql"}))

    def test_in_requires_collection(self):
        with self.assertRaisesRegex(PolicyEngineError, "collection"):
            Condition(key="t", op=ConditionOp.IN, value="not-a-list")


class RuleValidationTests(unittest.TestCase):
    def test_empty_name_rejected(self):
        with self.assertRaisesRegex(PolicyEngineError, "name"):
            PolicyRule(name="", effect=Effect.PERMIT)

    def test_non_effect_rejected(self):
        with self.assertRaisesRegex(PolicyEngineError, "effect"):
            PolicyRule(name="r", effect="permit")  # type: ignore[arg-type]


class EngineValidationTests(unittest.TestCase):
    def test_duplicate_rule_name_rejected(self):
        r = PolicyRule(name="dup", effect=Effect.PERMIT)
        with self.assertRaisesRegex(PolicyEngineError, "duplicate"):
            NativePolicyEngine(rules=(r, r))


class DecisionTests(unittest.TestCase):
    def test_deny_by_default(self):
        engine = NativePolicyEngine(rules=())
        d = engine.decide(
            PolicyRequest(principal=_CALLER, action="invoke", resource="read_file"),
            now=_NOW,
        )
        self.assertEqual(d.effect, Effect.DENY)
        self.assertEqual(d.matched_rule, "")
        self.assertIn("deny-by-default", d.reason)

    def test_first_match_permit(self):
        engine = NativePolicyEngine(
            rules=(
                PolicyRule(
                    name="allow-read",
                    effect=Effect.PERMIT,
                    action="invoke",
                    resource="read_file",
                ),
            )
        )
        d = engine.decide(
            PolicyRequest(principal=_CALLER, action="invoke", resource="read_file"),
            now=_NOW,
        )
        self.assertTrue(d.permitted)
        self.assertEqual(d.matched_rule, "allow-read")

    def test_first_match_wins_over_later(self):
        engine = NativePolicyEngine(
            rules=(
                PolicyRule(
                    name="deny-exec",
                    effect=Effect.DENY,
                    action="invoke",
                    resource="exec_sql",
                ),
                PolicyRule(name="allow-all", effect=Effect.PERMIT),
            )
        )
        d = engine.decide(
            PolicyRequest(principal=_CALLER, action="invoke", resource="exec_sql"),
            now=_NOW,
        )
        self.assertEqual(d.effect, Effect.DENY)
        self.assertEqual(d.matched_rule, "deny-exec")

    def test_wildcards_match(self):
        engine = NativePolicyEngine(
            rules=(PolicyRule(name="allow-all", effect=Effect.PERMIT, principal=ANY),)
        )
        d = engine.decide(
            PolicyRequest(principal="spiffe://any.mesh/x/y", action="z", resource="w"),
            now=_NOW,
        )
        self.assertTrue(d.permitted)

    def test_condition_gates_match(self):
        engine = NativePolicyEngine(
            rules=(
                PolicyRule(
                    name="prod-only",
                    effect=Effect.PERMIT,
                    conditions=(
                        Condition(key="tier", op=ConditionOp.EQUALS, value="prod"),
                    ),
                ),
            )
        )
        permit = engine.decide(
            PolicyRequest(
                principal=_CALLER, action="a", resource="r", context={"tier": "prod"}
            ),
            now=_NOW,
        )
        self.assertTrue(permit.permitted)
        deny = engine.decide(
            PolicyRequest(
                principal=_CALLER, action="a", resource="r", context={"tier": "dev"}
            ),
            now=_NOW,
        )
        self.assertEqual(deny.effect, Effect.DENY)

    def test_decision_id_is_uuidv7_shaped(self):
        engine = NativePolicyEngine(rules=())
        d = engine.decide(
            PolicyRequest(principal=_CALLER, action="a", resource="r"), now=_NOW
        )
        # UUIDv7: 36 chars, version nibble '7'.
        self.assertEqual(len(d.decision_id), 36)
        self.assertEqual(d.decision_id[14], "7")

    def test_every_decision_carries_an_id(self):
        engine = NativePolicyEngine(
            rules=(PolicyRule(name="allow", effect=Effect.PERMIT),)
        )
        permit = engine.decide(
            PolicyRequest(principal=_CALLER, action="a", resource="r"), now=_NOW
        )
        deny = NativePolicyEngine(rules=()).decide(
            PolicyRequest(principal=_CALLER, action="a", resource="r"), now=_NOW
        )
        self.assertTrue(permit.decision_id)
        self.assertTrue(deny.decision_id)


class RequestValidationTests(unittest.TestCase):
    def test_empty_principal_rejected(self):
        with self.assertRaisesRegex(PolicyEngineError, "principal"):
            PolicyRequest(principal="", action="a", resource="r")


if __name__ == "__main__":
    unittest.main()
