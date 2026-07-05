"""Tests for policy-decision audit wiring (Phase 5 Track B B2)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from audit import InMemoryAuditSink, verify_chain
from policy_audit import (
    POLICY_DECIDE_EVENT,
    build_baseline_engine,
    decide_and_audit,
)
from policy_engine import Effect, PolicyRequest

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_CALLER = "spiffe://mesh.example/ns-a/agent-1"
_OTHER = "spiffe://mesh.example/ns-z/stranger"


class BaselineEngineTests(unittest.TestCase):
    def _engine(self):
        return build_baseline_engine(allowed_callers=(_CALLER,))

    def test_low_risk_tool_permitted_for_allowlisted_caller(self):
        d = self._engine().decide(
            PolicyRequest(
                principal=_CALLER,
                action="invoke_tool",
                resource="read_file",
                context={"caller": _CALLER},
            ),
            now=_NOW,
        )
        self.assertTrue(d.permitted)

    def test_low_risk_tool_denied_for_unknown_caller(self):
        d = self._engine().decide(
            PolicyRequest(
                principal=_OTHER,
                action="invoke_tool",
                resource="read_file",
                context={"caller": _OTHER},
            ),
            now=_NOW,
        )
        self.assertEqual(d.effect, Effect.DENY)

    def test_step_up_tool_denied_without_step_up(self):
        d = self._engine().decide(
            PolicyRequest(
                principal=_CALLER,
                action="invoke_tool",
                resource="exec_sql",
                context={"caller": _CALLER},
            ),
            now=_NOW,
        )
        self.assertEqual(d.effect, Effect.DENY)
        self.assertEqual(d.matched_rule, "deny-stepup-missing-exec_sql")

    def test_step_up_tool_permitted_with_step_up(self):
        d = self._engine().decide(
            PolicyRequest(
                principal=_CALLER,
                action="invoke_tool",
                resource="exec_sql",
                context={"caller": _CALLER, "step_up": True},
            ),
            now=_NOW,
        )
        self.assertTrue(d.permitted)


class DecideAndAuditTests(unittest.TestCase):
    def test_permit_emits_allow_event_with_decision_id(self):
        sink = InMemoryAuditSink()
        engine = build_baseline_engine(allowed_callers=(_CALLER,))
        decision = decide_and_audit(
            engine=engine,
            request=PolicyRequest(
                principal=_CALLER,
                action="invoke_tool",
                resource="read_file",
                context={"caller": _CALLER},
            ),
            audit_sink=sink,
            now=_NOW,
        )
        events = sink.events
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.event_type, POLICY_DECIDE_EVENT)
        self.assertEqual(ev.outcome, "allow")
        # The decision id is embedded in the (hashed) reason field.
        self.assertIn(decision.decision_id, ev.reason)

    def test_deny_emits_deny_event(self):
        sink = InMemoryAuditSink()
        engine = build_baseline_engine(allowed_callers=(_CALLER,))
        decide_and_audit(
            engine=engine,
            request=PolicyRequest(
                principal=_OTHER,
                action="invoke_tool",
                resource="exec_sql",
                context={"caller": _OTHER},
            ),
            audit_sink=sink,
            now=_NOW,
        )
        self.assertEqual(sink.events[0].outcome, "deny")

    def test_decision_id_survives_chain_validation(self):
        # The whole point: the decision id is tamper-evident because
        # it lives in a hashed field.
        sink = InMemoryAuditSink()
        engine = build_baseline_engine(allowed_callers=(_CALLER,))
        decision = decide_and_audit(
            engine=engine,
            request=PolicyRequest(
                principal=_CALLER,
                action="invoke_tool",
                resource="read_file",
                context={"caller": _CALLER},
            ),
            audit_sink=sink,
            now=_NOW,
        )
        # Chain validates, and the id is in the trace.
        verify_chain(sink.events)
        self.assertTrue(
            any(decision.decision_id in e.reason for e in sink.events)
        )


if __name__ == "__main__":
    unittest.main()
