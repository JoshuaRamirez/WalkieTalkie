"""Tests for retrieval policy (Phase 2 Track B B2)."""

import hashlib
import pathlib
import sys
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from data_classification import DataClass, classify
from retrieval_policy import (
    AllowlistRetrievalPolicy,
    CrossTenantRetrieval,
    RetrievalDecision,
    RetrievalError,
    RetrievalRule,
    require_retrieval,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_DIGEST = hashlib.sha256(b"x").hexdigest()

# Same trust domain (mesh.example): same-tenant cases.
_ACTOR_A = "spiffe://mesh.example/ns-a/svc"
_ACTOR_B = "spiffe://mesh.example/ns-b/svc"
_ACTOR_C = "spiffe://mesh.example/ns-c/svc"
_KID = "kid-a"

# Different trust domain.
_FOREIGN_ACTOR = "spiffe://other-mesh.example/ns-z/foreign"


def _data(*, data_class: DataClass = DataClass.INTERNAL, actor: str = _ACTOR_A):
    return classify(
        data_digest=_DIGEST,
        data_class=data_class,
        actor_iss=actor,
        actor_kid=_KID,
        now=_NOW,
    )


class RuleValidationTests(unittest.TestCase):
    def test_invalid_caller_iss_rejected(self):
        with self.assertRaisesRegex(ValueError, "caller_iss"):
            RetrievalRule(
                caller_iss="not-spiffe",
                purpose_of_use="invoke_tool",
                max_class=DataClass.INTERNAL,
            )

    def test_empty_purpose_rejected(self):
        with self.assertRaisesRegex(ValueError, "purpose_of_use"):
            RetrievalRule(
                caller_iss=_ACTOR_A,
                purpose_of_use="",
                max_class=DataClass.INTERNAL,
            )

    def test_non_dataclass_rejected(self):
        with self.assertRaisesRegex(ValueError, "max_class"):
            RetrievalRule(
                caller_iss=_ACTOR_A,
                purpose_of_use="invoke_tool",
                max_class="internal",  # type: ignore[arg-type]
            )


class AllowlistRetrievalPolicyTests(unittest.TestCase):
    def _policy(self, *rules, cross_tenant=CrossTenantRetrieval.DENY):
        return AllowlistRetrievalPolicy(rules=tuple(rules), cross_tenant=cross_tenant)

    def test_matching_rule_allows_at_or_below_max_class(self):
        policy = self._policy(
            RetrievalRule(_ACTOR_B, "invoke_tool", DataClass.CONFIDENTIAL),
        )
        decision = policy.evaluate(
            caller_iss=_ACTOR_B,
            purpose_of_use="invoke_tool",
            data=_data(data_class=DataClass.INTERNAL, actor=_ACTOR_A),
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason_code, "ok")

    def test_class_above_max_denied(self):
        policy = self._policy(
            RetrievalRule(_ACTOR_B, "invoke_tool", DataClass.INTERNAL),
        )
        decision = policy.evaluate(
            caller_iss=_ACTOR_B,
            purpose_of_use="invoke_tool",
            data=_data(data_class=DataClass.RESTRICTED, actor=_ACTOR_A),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "retrieval_class_exceeds_rule")

    def test_no_matching_rule_denied(self):
        policy = self._policy(
            RetrievalRule(_ACTOR_B, "invoke_tool", DataClass.RESTRICTED),
        )
        # Different purpose_of_use.
        decision = policy.evaluate(
            caller_iss=_ACTOR_B,
            purpose_of_use="other_purpose",
            data=_data(),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "retrieval_no_rule_match")

    def test_different_caller_denied(self):
        policy = self._policy(
            RetrievalRule(_ACTOR_B, "invoke_tool", DataClass.RESTRICTED),
        )
        decision = policy.evaluate(
            caller_iss=_ACTOR_C,
            purpose_of_use="invoke_tool",
            data=_data(),
        )
        self.assertEqual(decision.reason_code, "retrieval_no_rule_match")

    def test_first_match_wins(self):
        # The narrow rule (max=INTERNAL) appears before the broad one
        # (max=RESTRICTED). For caller=_ACTOR_B + purpose=invoke_tool the
        # narrow rule MUST win — that's the documented evaluation order.
        policy = self._policy(
            RetrievalRule(_ACTOR_B, "invoke_tool", DataClass.INTERNAL),
            RetrievalRule(_ACTOR_B, "invoke_tool", DataClass.RESTRICTED),
        )
        decision = policy.evaluate(
            caller_iss=_ACTOR_B,
            purpose_of_use="invoke_tool",
            data=_data(data_class=DataClass.CONFIDENTIAL),
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "retrieval_class_exceeds_rule")


class CrossTenantTests(unittest.TestCase):
    def test_cross_tenant_denied_by_default(self):
        policy = AllowlistRetrievalPolicy(
            rules=(
                RetrievalRule(_FOREIGN_ACTOR, "invoke_tool", DataClass.RESTRICTED),
            ),
        )
        decision = policy.evaluate(
            caller_iss=_FOREIGN_ACTOR,
            purpose_of_use="invoke_tool",
            data=_data(actor=_ACTOR_A),  # origin in mesh.example
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "retrieval_cross_tenant")

    def test_cross_tenant_check_runs_before_rule_match(self):
        # Even an exact-match rule cannot override the default-deny tenant
        # boundary — operators must explicitly set cross_tenant=ALLOW.
        policy = AllowlistRetrievalPolicy(
            rules=(
                RetrievalRule(_FOREIGN_ACTOR, "invoke_tool", DataClass.RESTRICTED),
            ),
            cross_tenant=CrossTenantRetrieval.DENY,
        )
        decision = policy.evaluate(
            caller_iss=_FOREIGN_ACTOR,
            purpose_of_use="invoke_tool",
            data=_data(actor=_ACTOR_A),
        )
        self.assertEqual(decision.reason_code, "retrieval_cross_tenant")

    def test_cross_tenant_allow_opt_in(self):
        policy = AllowlistRetrievalPolicy(
            rules=(
                RetrievalRule(_FOREIGN_ACTOR, "invoke_tool", DataClass.RESTRICTED),
            ),
            cross_tenant=CrossTenantRetrieval.ALLOW,
        )
        decision = policy.evaluate(
            caller_iss=_FOREIGN_ACTOR,
            purpose_of_use="invoke_tool",
            data=_data(actor=_ACTOR_A),
        )
        self.assertTrue(decision.allowed)

    def test_same_tenant_unaffected_by_cross_tenant_dial(self):
        policy = AllowlistRetrievalPolicy(
            rules=(
                RetrievalRule(_ACTOR_B, "invoke_tool", DataClass.RESTRICTED),
            ),
            cross_tenant=CrossTenantRetrieval.DENY,
        )
        decision = policy.evaluate(
            caller_iss=_ACTOR_B,
            purpose_of_use="invoke_tool",
            data=_data(actor=_ACTOR_A),  # same mesh.example tenant
        )
        self.assertTrue(decision.allowed)


class RequireRetrievalTests(unittest.TestCase):
    def test_allows_silently_on_success(self):
        policy = AllowlistRetrievalPolicy(
            rules=(
                RetrievalRule(_ACTOR_B, "invoke_tool", DataClass.INTERNAL),
            ),
        )
        d = require_retrieval(
            caller_iss=_ACTOR_B,
            purpose_of_use="invoke_tool",
            data=_data(data_class=DataClass.PUBLIC),
            policy=policy,
        )
        self.assertIsInstance(d, RetrievalDecision)
        self.assertTrue(d.allowed)

    def test_raises_on_denial_carrying_decision(self):
        policy = AllowlistRetrievalPolicy(
            rules=(
                RetrievalRule(_ACTOR_B, "invoke_tool", DataClass.INTERNAL),
            ),
        )
        with self.assertRaises(RetrievalError) as ctx:
            require_retrieval(
                caller_iss=_ACTOR_B,
                purpose_of_use="invoke_tool",
                data=_data(data_class=DataClass.RESTRICTED),
                policy=policy,
            )
        self.assertEqual(
            ctx.exception.decision.reason_code, "retrieval_class_exceeds_rule"
        )


if __name__ == "__main__":
    unittest.main()
