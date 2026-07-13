"""Tests for output scanning v0 (Phase 2 Track C C1)."""

import pathlib
import re
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from output_scanning import (
    BUILTIN_PATTERNS,
    OutputScanningError,
    PatternRegistry,
    RiskLevel,
    ScanMatch,
    ScanResult,
    SecretPattern,
    is_more_severe,
    scan,
)


class RiskLevelOrderingTests(unittest.TestCase):
    def test_severity_chain(self):
        self.assertTrue(is_more_severe(RiskLevel.CRITICAL, RiskLevel.HIGH))
        self.assertTrue(is_more_severe(RiskLevel.HIGH, RiskLevel.MEDIUM))
        self.assertTrue(is_more_severe(RiskLevel.MEDIUM, RiskLevel.LOW))
        self.assertTrue(is_more_severe(RiskLevel.LOW, RiskLevel.NONE))
        self.assertFalse(is_more_severe(RiskLevel.NONE, RiskLevel.NONE))
        self.assertFalse(is_more_severe(RiskLevel.MEDIUM, RiskLevel.HIGH))


class SecretPatternValidationTests(unittest.TestCase):
    def test_empty_name_rejected(self):
        with self.assertRaisesRegex(OutputScanningError, "name"):
            SecretPattern(
                name="", regex=re.compile("x"), severity=RiskLevel.HIGH
            )

    def test_uncompiled_regex_rejected(self):
        with self.assertRaisesRegex(OutputScanningError, "re.Pattern"):
            SecretPattern(
                name="x",
                regex="x",  # type: ignore[arg-type]
                severity=RiskLevel.HIGH,
            )

    def test_severity_none_rejected(self):
        with self.assertRaisesRegex(OutputScanningError, "NONE"):
            SecretPattern(
                name="x",
                regex=re.compile("x"),
                severity=RiskLevel.NONE,
            )


class PatternRegistryTests(unittest.TestCase):
    def test_builtin_registry_loads(self):
        reg = PatternRegistry.builtin()
        self.assertEqual(reg.patterns, BUILTIN_PATTERNS)

    def test_duplicate_pattern_name_rejected(self):
        p = SecretPattern(
            name="dupe", regex=re.compile("x"), severity=RiskLevel.HIGH
        )
        with self.assertRaisesRegex(OutputScanningError, "duplicate"):
            PatternRegistry(patterns=(p, p))

    def test_extend_returns_new_registry(self):
        base = PatternRegistry.from_patterns(
            [
                SecretPattern(
                    name="a", regex=re.compile("a"), severity=RiskLevel.LOW
                )
            ]
        )
        extra = SecretPattern(
            name="b", regex=re.compile("b"), severity=RiskLevel.LOW
        )
        bigger = base.extend([extra])
        self.assertEqual(len(base.patterns), 1)
        self.assertEqual(len(bigger.patterns), 2)


class BuiltinPatternDetectionTests(unittest.TestCase):
    def test_clean_text_returns_none(self):
        result = scan("hello world, no secrets here.")
        self.assertEqual(result.matches, ())
        self.assertEqual(result.risk, RiskLevel.NONE)
        self.assertTrue(result.is_clean)

    def test_aws_access_key_detected(self):
        result = scan("token: AKIAIOSFODNN7EXAMPLE done")
        self.assertEqual([m.pattern_name for m in result.matches], ["aws_access_key_id"])
        self.assertEqual(result.risk, RiskLevel.CRITICAL)

    def test_pem_private_key_detected(self):
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----"
        result = scan(body)
        self.assertIn("pem_private_key", {m.pattern_name for m in result.matches})
        self.assertEqual(result.risk, RiskLevel.CRITICAL)

    def test_anthropic_api_key_detected(self):
        key = "sk-ant-api03-" + "A" * 40
        result = scan(f"key={key}")
        self.assertIn("anthropic_api_key", {m.pattern_name for m in result.matches})
        # Severity HIGH; the OpenAI pattern is anchored with sk-(?!ant-)
        # so anthropic keys must not double-fire.
        self.assertEqual(
            [m.pattern_name for m in result.matches], ["anthropic_api_key"]
        )

    def test_openai_api_key_detected(self):
        key = "sk-proj-" + "A" * 48
        result = scan(f"OPENAI_API_KEY={key}")
        names = {m.pattern_name for m in result.matches}
        self.assertIn("openai_api_key", names)
        self.assertNotIn("anthropic_api_key", names)

    def test_github_personal_token_detected(self):
        token = "ghp_" + "a" * 36
        result = scan(f"X-GitHub-Token: {token}")
        self.assertIn("github_personal_token", {m.pattern_name for m in result.matches})

    def test_stripe_live_secret_key_detected(self):
        key = "sk_live_" + "A" * 32
        result = scan(f"stripe={key}")
        self.assertIn(
            "stripe_live_secret_key", {m.pattern_name for m in result.matches}
        )

    def test_jwt_detected(self):
        # eyJ-prefix marks a base64url-encoded JSON object — JWT header.
        jwt = "eyJhbGciOiJFZERTQSJ9." + "A" * 20 + "." + "B" * 20
        result = scan(f"authorization: Bearer {jwt}")
        self.assertIn("jwt_token", {m.pattern_name for m in result.matches})
        self.assertEqual(result.risk, RiskLevel.MEDIUM)

    def test_no_double_match_on_anthropic_keys(self):
        # Regression: an earlier draft's openai_api_key pattern was
        # greedy enough to swallow anthropic keys too. Pin that down.
        key = "sk-ant-api03-" + "X" * 60
        result = scan(key)
        names = [m.pattern_name for m in result.matches]
        self.assertEqual(names.count("openai_api_key"), 0)
        self.assertEqual(names.count("anthropic_api_key"), 1)


class AggregateRiskTests(unittest.TestCase):
    def test_aggregate_is_max_severity(self):
        text = (
            "ghp_" + "a" * 36 + " plus AKIAIOSFODNN7EXAMPLE in the same artifact"
        )
        result = scan(text)
        # github_personal_token = HIGH; aws_access_key_id = CRITICAL.
        # Aggregate must be CRITICAL.
        self.assertEqual(result.risk, RiskLevel.CRITICAL)


class RedactionTests(unittest.TestCase):
    def test_clean_text_passes_through(self):
        result = scan("nothing to see")
        self.assertEqual(result.redact(), "nothing to see")

    def test_single_match_redacted(self):
        token = "ghp_" + "a" * 36
        result = scan(f"key={token}!")
        self.assertEqual(result.redact(), "key=[REDACTED:github_personal_token]!")

    def test_multiple_disjoint_matches_redacted_in_order(self):
        a = "AKIAIOSFODNN7EXAMPLE"
        b = "ghp_" + "a" * 36
        result = scan(f"first={a} second={b}")
        redacted = result.redact()
        self.assertEqual(
            redacted,
            "first=[REDACTED:aws_access_key_id] second=[REDACTED:github_personal_token]",
        )

    def test_overlap_resolves_to_first_or_higher_severity(self):
        # Construct overlapping matches deliberately via a hand-rolled
        # registry, since the built-in set is designed not to overlap.
        text = "abcdef"
        reg = PatternRegistry.from_patterns(
            [
                SecretPattern(
                    name="low_short",
                    regex=re.compile(r"abc"),
                    severity=RiskLevel.LOW,
                ),
                SecretPattern(
                    name="high_wide",
                    regex=re.compile(r"abcdef"),
                    severity=RiskLevel.HIGH,
                ),
            ]
        )
        result = scan(text, registry=reg)
        # Tie on start (both at 0): higher severity (high_wide) wins.
        self.assertEqual(result.redact(), "[REDACTED:high_wide]")


class CustomRegistryTests(unittest.TestCase):
    def test_custom_pattern_detected(self):
        reg = PatternRegistry.from_patterns(
            [
                SecretPattern(
                    name="internal_token",
                    regex=re.compile(r"\bINT-[0-9A-F]{16}\b"),
                    severity=RiskLevel.MEDIUM,
                )
            ]
        )
        result = scan("ticket=INT-0123456789ABCDEF, ok?", registry=reg)
        self.assertEqual([m.pattern_name for m in result.matches], ["internal_token"])
        self.assertEqual(result.risk, RiskLevel.MEDIUM)

    def test_non_string_input_rejected(self):
        with self.assertRaisesRegex(OutputScanningError, "text"):
            scan(b"bytes-not-string")  # type: ignore[arg-type]


class ScanResultShapeTests(unittest.TestCase):
    def test_result_is_a_scan_result(self):
        result = scan("plain")
        self.assertIsInstance(result, ScanResult)

    def test_match_carries_span(self):
        result = scan("xx AKIAIOSFODNN7EXAMPLE yy")
        m = result.matches[0]
        self.assertIsInstance(m, ScanMatch)
        self.assertEqual(result.text[m.start : m.end], "AKIAIOSFODNN7EXAMPLE")


if __name__ == "__main__":
    unittest.main()
