"""Shape tests for the example MCP host (Phase 4 D4.2).

The full end-to-end smoke test lives in D4.3; this slice ships
ONLY shape sanity tests: the host imports cleanly, HostConfig
validates its required fields, the demo tools return the expected
shapes, and the helper functions are pure.

Anything that would require building real Ed25519 keys, real
trust stores, and round-tripping a signed envelope through
verify_envelope belongs in D4.3 — keeping it out of D4.2 keeps
this slice tight.
"""

import pathlib
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "envelope")
)

from audit import InMemoryAuditSink
from egress_policy import EgressAction, EgressMatrixCell, MatrixEgressPolicy
from host import (
    DEMO_TOOLS,
    ExampleMCPHost,
    ExampleMCPHostError,
    HandleOptions,
    HostConfig,
    _derive_reply_id,
    _derive_reply_nonce,
    _exc_reason_code,
    _request_id_from_envelope,
    _tool_exec_sql,
    _tool_read_file,
)
from output_scanning import PatternRegistry, RiskLevel
from tool_policy_gate import RiskTier, ToolPolicy, ToolRule
from verify_envelope import EnvelopeVerificationError, InMemoryReplayCache


def _config():
    priv = Ed25519PrivateKey.generate()

    def _key_lookup(kid: str) -> bytes:
        raise RuntimeError("not exercised in shape tests")

    def _issuer_lookup(iss: str, kid: str) -> bytes:
        raise RuntimeError("not exercised in shape tests")

    return HostConfig(
        host_iss="spiffe://mesh.example/ns-host/server-1",
        host_kid="host-kid-1",
        host_signing_key=priv,
        key_lookup=_key_lookup,
        issuer_lookup=_issuer_lookup,
        replay_cache=InMemoryReplayCache(),
        tool_policy=ToolPolicy(
            rules=(
                ToolRule(tool_name="read_file", risk_tier=RiskTier.LOW),
                ToolRule(tool_name="exec_sql", risk_tier=RiskTier.CRITICAL),
            ),
        ),
        egress_policy=MatrixEgressPolicy(
            cells=(
                EgressMatrixCell(
                    risk=RiskLevel.NONE,
                    data_class=__import__(
                        "data_classification"
                    ).DataClass.INTERNAL,
                    action=EgressAction.ALLOW,
                ),
            )
        ),
        audit_sink=InMemoryAuditSink(),
    )


class ConfigValidationTests(unittest.TestCase):
    def test_empty_host_identity_rejected(self):
        priv = Ed25519PrivateKey.generate()
        with self.assertRaisesRegex(ExampleMCPHostError, "host_iss"):
            HostConfig(
                host_iss="",
                host_kid="kid",
                host_signing_key=priv,
                key_lookup=lambda kid: b"",
                issuer_lookup=lambda iss, kid: b"",
                replay_cache=InMemoryReplayCache(),
                tool_policy=ToolPolicy(rules=()),
                egress_policy=MatrixEgressPolicy(cells=()),
            )

    def test_default_audit_sink_is_in_memory(self):
        config = _config()
        self.assertIsInstance(config.audit_sink, InMemoryAuditSink)

    def test_default_pattern_registry_is_builtin(self):
        config = _config()
        self.assertIsInstance(config.pattern_registry, PatternRegistry)


class HostConstructionTests(unittest.TestCase):
    def test_default_tools_are_loaded(self):
        host = ExampleMCPHost(_config())
        self.assertEqual(set(host.tools.keys()), {"read_file", "exec_sql"})

    def test_custom_tools_replace_defaults(self):
        custom = {"only_this": lambda p: {"ok": True}}
        host = ExampleMCPHost(_config(), tools=custom)
        self.assertEqual(set(host.tools.keys()), {"only_this"})


class DemoToolShapeTests(unittest.TestCase):
    def test_read_file_returns_path_and_contents(self):
        out = _tool_read_file({"path": "/etc/hosts"})
        self.assertEqual(out["path"], "/etc/hosts")
        self.assertIn("contents", out)
        self.assertIn("/etc/hosts", out["contents"])

    def test_read_file_tolerates_missing_params(self):
        out = _tool_read_file({})
        self.assertEqual(out["path"], "")
        self.assertIn("no path", out["contents"])

    def test_exec_sql_returns_rows(self):
        out = _tool_exec_sql({"query": "SELECT 1"})
        self.assertEqual(out["query"], "SELECT 1")
        self.assertIsInstance(out["rows"], list)
        self.assertGreater(len(out["rows"]), 0)


class HelperFunctionTests(unittest.TestCase):
    def test_request_id_from_envelope_pulls_payload_id(self):
        env = {
            "payload": {"jsonrpc": "2.0", "method": "x", "id": 42},
        }
        self.assertEqual(_request_id_from_envelope(env), 42)

    def test_request_id_returns_none_for_non_dict_envelope(self):
        self.assertIsNone(_request_id_from_envelope(None))  # type: ignore[arg-type]
        self.assertIsNone(_request_id_from_envelope({"payload": "junk"}))

    def test_exc_reason_code_handles_missing_reason(self):
        exc = EnvelopeVerificationError("naked exception", reason=None)
        self.assertEqual(_exc_reason_code(exc), "")

    def test_derive_reply_id_is_deterministic(self):
        env = {"message_id": "01900000-0000-7000-8000-aaaaaaaaaaa1"}
        self.assertEqual(_derive_reply_id(env), _derive_reply_id(env))

    def test_derive_reply_id_differs_from_input(self):
        env = {"message_id": "01900000-0000-7000-8000-aaaaaaaaaaa1"}
        self.assertNotEqual(_derive_reply_id(env), env["message_id"])

    def test_derive_reply_id_falls_back_for_invalid_input(self):
        env = {"message_id": "not-a-uuid"}
        out = _derive_reply_id(env)
        self.assertEqual(len(out), 36)  # still UUIDv7-shaped

    def test_derive_reply_nonce_format(self):
        env = {"message_id": "01900000-0000-7000-8000-aaaaaaaaaaa1"}
        nonce = _derive_reply_nonce(env)
        self.assertTrue(nonce.startswith("replynonce-"))


class DemoToolsRegistryTests(unittest.TestCase):
    def test_demo_tools_carry_known_keys(self):
        self.assertEqual(set(DEMO_TOOLS.keys()), {"read_file", "exec_sql"})

    def test_demo_tools_are_callable(self):
        for name, tool in DEMO_TOOLS.items():
            self.assertTrue(callable(tool), f"{name} not callable")


class HandleOptionsTests(unittest.TestCase):
    def test_handle_options_default_construction(self):
        opts = HandleOptions()
        self.assertIsNone(opts.now)
        self.assertIsNone(opts.step_up)


class HostLineCountTests(unittest.TestCase):
    """Phase 4 §6 acceptance criterion #4: example host code under 500 lines."""

    def test_host_module_under_500_lines(self):
        host_path = pathlib.Path(__file__).resolve().parent / "host.py"
        line_count = len(host_path.read_text().splitlines())
        self.assertLessEqual(
            line_count,
            500,
            f"host.py is {line_count} lines; Phase 4 §6 ceiling is 500",
        )


if __name__ == "__main__":
    unittest.main()
