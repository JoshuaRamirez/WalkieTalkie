"""Adversarial corpus CI gate (Phase 2 Track D D3).

Closes D3 ("Adversarial Corpus CI Gate"):

- "Curated injection and smuggling corpus run per release."
- "Block release on regressions below safety threshold."

The corpus lives at ``test-vectors/adversarial-corpus-v0.json``. Each
entry pairs a malicious input with the v0 gate that MUST block it
plus an expectation shape (a reason_code, a risk level, or a
structural property of the assembled output). This harness loads
the corpus and asserts a **100 % block-rate** — any regression below
that threshold fails the unittest suite, which already gates CI.

Extending the corpus is an additive operation: add an entry under
``entries`` with a ``gate`` and an expectation, and the dispatch
table below picks the matching checker.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import unittest
from datetime import UTC, datetime
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from data_classification import DataClass, classify
from egress_policy import (
    EgressAction,
    EgressMatrixCell,
    MatrixEgressPolicy,
)
from instruction_isolation import (
    ContentChannel,
    ContentSegment,
    InstructionIsolationError,
    Trust,
    assemble_isolated_prompt,
)
from output_scanning import RiskLevel, scan
from retrieval_policy import (
    AllowlistRetrievalPolicy,
    CrossTenantRetrieval,
    RetrievalRule,
)
from tool_policy_gate import (
    RiskTier,
    ToolCall,
    ToolPolicy,
    ToolRule,
    evaluate_tool_call,
)

_CORPUS_PATH = (
    pathlib.Path(__file__).resolve().parent
    / "test-vectors"
    / "adversarial-corpus-v0.json"
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_NOW_TS = int(_NOW.timestamp())

_HOME_CALLER = "spiffe://mesh.example/ns-a/agent-1"
_FOREIGN_CALLER = "spiffe://other-mesh.example/ns-z/agent-x"
_KID = "kid-a"


# ----------------------------------------------------------------------
# Checkers per gate
# ----------------------------------------------------------------------


def _check_instruction_isolation(entry: dict[str, Any]) -> None:
    expected = entry["expected"]
    payload = _payload(entry)
    nonce = "fixednonce-abc"

    if expected == "wrapped_as_untrusted_user":
        seg = ContentSegment(
            channel=ContentChannel.USER,
            source_label="end-user",
            trust=Trust.UNTRUSTED,
            text=payload,
        )
        result = assemble_isolated_prompt([seg], nonce=nonce)
        assert (
            f'<<wt-iso:{nonce}:user source="end-user" trust="untrusted">>'
            in result.text
        ), "user payload must be wrapped in untrusted fence"
        return

    if expected == "no_unescaped_fence_in_wrapped_region":
        seg = ContentSegment(
            channel=ContentChannel.RETRIEVED
            if "retrieved" in entry["name"]
            else ContentChannel.USER,
            source_label="kb:doc-42" if "retrieved" in entry["name"] else "end-user",
            trust=Trust.UNTRUSTED,
            text=payload,
        )
        result = assemble_isolated_prompt([seg], nonce=nonce)
        open_marker_user = (
            f'<<wt-iso:{nonce}:user source="end-user" trust="untrusted">>'
        )
        open_marker_retr = (
            f'<<wt-iso:{nonce}:retrieved source="kb:doc-42" trust="untrusted">>'
        )
        close_marker = f"<<wt-iso:{nonce}:end>>"
        open_marker = (
            open_marker_retr if open_marker_retr in result.text else open_marker_user
        )
        body = result.text.split(open_marker, 1)[1].rsplit(close_marker, 1)[0]
        assert "<<" not in body, (
            f"corpus entry {entry['name']!r}: synthetic fence leaked "
            f"into wrapped region"
        )
        assert ">>" not in body, (
            f"corpus entry {entry['name']!r}: synthetic fence leaked "
            f"into wrapped region"
        )
        return

    if expected == "trusted_tool_requires_signature_ref":
        # Attempting to construct a TRUSTED tool segment without a
        # signature_ref must be rejected at __post_init__ time.
        try:
            ContentSegment(
                channel=ContentChannel.TOOL,
                source_label="tool:weather",
                trust=Trust.TRUSTED,
                text=payload,
                signature_ref="",
            )
        except InstructionIsolationError:
            return
        raise AssertionError(
            f"corpus entry {entry['name']!r}: TRUSTED tool without "
            f"signature_ref was admitted"
        )

    raise AssertionError(
        f"unknown instruction_isolation expectation: {expected!r}"
    )


def _payload(entry: dict[str, Any]) -> str:
    """Return the entry's payload, joining fragments if present.

    Some corpus payloads are stored as fragment arrays so the file on
    disk doesn't literally contain a secret-shaped string that
    GitHub's push-protection scanner would flag. The test joins them
    before exercising the gate.
    """
    if "payload_fragments" in entry:
        return "".join(entry["payload_fragments"])
    return entry["payload"]


def _check_output_scanning(entry: dict[str, Any]) -> None:
    expected_risk = RiskLevel(entry["expected_risk"])
    result = scan(_payload(entry))
    assert result.matches, (
        f"corpus entry {entry['name']!r}: scanner missed a secret"
    )
    assert result.risk is expected_risk, (
        f"corpus entry {entry['name']!r}: expected risk "
        f"{expected_risk.value}, got {result.risk.value}"
    )


def _make_issuer_keypair():
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv, pem


def _check_tool_policy_gate(entry: dict[str, Any]) -> None:
    expected_reason = entry["expected_reason"]
    args_digest = hashlib.sha256(entry["payload"].encode()).hexdigest()
    policy = ToolPolicy(
        rules=(
            ToolRule(
                tool_name="read_file",
                risk_tier=RiskTier.LOW,
                allowed_callers=frozenset({_HOME_CALLER}),
            ),
            ToolRule(
                tool_name="exec_sql", risk_tier=RiskTier.CRITICAL
            ),
        )
    )

    if expected_reason == "tool_unknown":
        call = ToolCall(
            tool_name=entry["payload"],
            caller_iss=_HOME_CALLER,
            arguments_digest=args_digest,
        )
        decision = evaluate_tool_call(call=call, policy=policy, current=_NOW)
        assert decision.reason_code == "tool_unknown", decision
        return

    if expected_reason == "tool_caller_not_allowed":
        call = ToolCall(
            tool_name=entry["payload"],
            caller_iss=_FOREIGN_CALLER,
            arguments_digest=args_digest,
        )
        decision = evaluate_tool_call(call=call, policy=policy, current=_NOW)
        assert decision.reason_code == "tool_caller_not_allowed", decision
        return

    if expected_reason == "tool_step_up_required":
        call = ToolCall(
            tool_name=entry["payload"],
            caller_iss=_HOME_CALLER,
            arguments_digest=args_digest,
        )
        decision = evaluate_tool_call(call=call, policy=policy, current=_NOW)
        assert decision.reason_code == "tool_step_up_required", decision
        return

    raise AssertionError(
        f"unknown tool_policy_gate expectation: {expected_reason!r}"
    )


def _make_classified(
    *,
    data_class: DataClass = DataClass.INTERNAL,
    actor: str = _HOME_CALLER,
):
    return classify(
        data_digest=hashlib.sha256(b"x").hexdigest(),
        data_class=data_class,
        actor_iss=actor,
        actor_kid=_KID,
        now=_NOW,
    )


def _check_retrieval_policy(entry: dict[str, Any]) -> None:
    expected = entry["expected_reason"]
    if expected == "retrieval_cross_tenant":
        policy = AllowlistRetrievalPolicy(
            rules=(
                RetrievalRule(_FOREIGN_CALLER, "invoke_tool", DataClass.RESTRICTED),
            ),
            cross_tenant=CrossTenantRetrieval.DENY,
        )
        decision = policy.evaluate(
            caller_iss=_FOREIGN_CALLER,
            purpose_of_use="invoke_tool",
            data=_make_classified(actor=_HOME_CALLER),
        )
        assert decision.reason_code == "retrieval_cross_tenant", decision
        return

    if expected == "retrieval_class_exceeds_rule":
        policy = AllowlistRetrievalPolicy(
            rules=(
                RetrievalRule(_HOME_CALLER, "invoke_tool", DataClass.INTERNAL),
            ),
        )
        decision = policy.evaluate(
            caller_iss=_HOME_CALLER,
            purpose_of_use="invoke_tool",
            data=_make_classified(data_class=DataClass.RESTRICTED),
        )
        assert decision.reason_code == "retrieval_class_exceeds_rule", decision
        return

    raise AssertionError(
        f"unknown retrieval_policy expectation: {expected!r}"
    )


def _check_egress_policy(entry: dict[str, Any]) -> None:
    expected = entry["expected_reason"]
    if expected == "egress_restricted_no_export":
        policy = MatrixEgressPolicy(
            cells=(
                EgressMatrixCell(
                    risk=RiskLevel.NONE,
                    data_class=DataClass.RESTRICTED,
                    action=EgressAction.ALLOW,
                ),
            ),
            restricted_no_export=True,
        )
        decision = policy.evaluate(
            risk=RiskLevel.NONE, data_class=DataClass.RESTRICTED
        )
        assert decision.reason_code == "egress_restricted_no_export", decision
        return

    raise AssertionError(
        f"unknown egress_policy expectation: {expected!r}"
    )


_CHECKERS = {
    "instruction_isolation": _check_instruction_isolation,
    "output_scanning": _check_output_scanning,
    "tool_policy_gate": _check_tool_policy_gate,
    "retrieval_policy": _check_retrieval_policy,
    "egress_policy": _check_egress_policy,
}


# ----------------------------------------------------------------------
# Harness
# ----------------------------------------------------------------------


def _load_corpus() -> dict[str, Any]:
    with _CORPUS_PATH.open("r", encoding="utf-8") as f:
        return json.load(f)


class AdversarialCorpusTests(unittest.TestCase):
    """100 % block-rate gate.

    Every entry must be intercepted by its declared gate. A regression
    here fails CI — the substance of D3.
    """

    @classmethod
    def setUpClass(cls):
        cls.corpus = _load_corpus()

    def test_corpus_is_non_empty(self):
        self.assertGreater(len(self.corpus["entries"]), 0)

    def test_every_entry_is_blocked(self):
        failures: list[str] = []
        for entry in self.corpus["entries"]:
            gate = entry.get("gate")
            checker = _CHECKERS.get(gate)
            if checker is None:
                failures.append(
                    f"{entry['name']}: unknown gate {gate!r}"
                )
                continue
            try:
                checker(entry)
            except AssertionError as exc:
                failures.append(f"{entry['name']}: {exc}")
            except Exception as exc:  # noqa: BLE001 — corpus-level catch-all
                failures.append(
                    f"{entry['name']}: unexpected {type(exc).__name__}: {exc}"
                )
        if failures:
            self.fail(
                "adversarial corpus regression — "
                f"{len(failures)}/{len(self.corpus['entries'])} entries "
                "leaked:\n  - " + "\n  - ".join(failures)
            )

    def test_corpus_covers_every_v0_gate(self):
        # Catch the inverse failure: a corpus that has shrunk so far
        # that some v0 gate is no longer exercised.
        gates_in_corpus = {e.get("gate") for e in self.corpus["entries"]}
        self.assertEqual(
            gates_in_corpus,
            set(_CHECKERS.keys()),
            "every v0 gate must have at least one adversarial corpus entry",
        )


if __name__ == "__main__":
    unittest.main()
