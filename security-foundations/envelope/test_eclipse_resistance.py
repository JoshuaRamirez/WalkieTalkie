"""Tests for eclipse resistance (Phase 3 Track A A2)."""

import pathlib
import sys
import unittest
from datetime import UTC, datetime, timedelta

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from eclipse_resistance import (
    DiversityRule,
    EclipseResistanceError,
    NeighborCandidate,
    NeighborSelection,
    detect_trust_domain_surges,
    select_neighbors,
)

_NOW = datetime(2026, 4, 14, 12, 0, 0, tzinfo=UTC)
_KID = "peer-kid-1"


def _cand(spiffe: str, *, at_offset_min: int = 0) -> NeighborCandidate:
    return NeighborCandidate(
        peer_iss=spiffe,
        peer_kid=_KID,
        last_seen=_NOW - timedelta(minutes=at_offset_min),
    )


def _cluster(prefix: str, count: int, *, base_offset: int = 0) -> list[NeighborCandidate]:
    return [
        _cand(f"{prefix}/svc-{i}", at_offset_min=base_offset + i)
        for i in range(count)
    ]


class CandidateValidationTests(unittest.TestCase):
    def test_invalid_spiffe_rejected(self):
        with self.assertRaisesRegex(EclipseResistanceError, "peer_iss"):
            NeighborCandidate(peer_iss="not-spiffe", peer_kid=_KID, last_seen=_NOW)

    def test_naive_datetime_rejected(self):
        with self.assertRaisesRegex(EclipseResistanceError, "timezone-aware"):
            NeighborCandidate(
                peer_iss="spiffe://mesh.example/ns-a/x",
                peer_kid=_KID,
                last_seen=datetime(2026, 4, 14, 12),
            )


class RuleValidationTests(unittest.TestCase):
    def test_negative_target_rejected(self):
        with self.assertRaisesRegex(EclipseResistanceError, "target_count"):
            DiversityRule(
                target_count=0, max_per_trust_domain=1, min_distinct_trust_domains=1
            )

    def test_min_distinct_above_target_rejected(self):
        with self.assertRaisesRegex(
            EclipseResistanceError, "min_distinct_trust_domains"
        ):
            DiversityRule(
                target_count=3,
                max_per_trust_domain=1,
                min_distinct_trust_domains=5,
            )


class DiversityCapTests(unittest.TestCase):
    def test_per_domain_cap_blocks_sybil_dominance(self):
        # The acceptance criterion: a Sybil cluster cannot dominate.
        sybil = _cluster("spiffe://attacker.mesh/ns-x", count=50)
        honest = [
            _cand("spiffe://honest-a.mesh/ns-1/svc"),
            _cand("spiffe://honest-b.mesh/ns-2/svc"),
            _cand("spiffe://honest-c.mesh/ns-3/svc"),
        ]
        rule = DiversityRule(
            target_count=8,
            max_per_trust_domain=2,
            min_distinct_trust_domains=3,
        )
        result = select_neighbors([*sybil, *honest], rule=rule)
        # No matter how many Sybil candidates, attacker.mesh gets at
        # most 2 slots.
        per_td = result.per_trust_domain
        self.assertLessEqual(per_td.get("attacker.mesh", 0), 2)
        # And the honest peers get in.
        selected_iss = {c.peer_iss for c in result.selected}
        self.assertIn("spiffe://honest-a.mesh/ns-1/svc", selected_iss)

    def test_diversity_shortfall_flagged(self):
        # Only one trust domain present in the pool → shortfall.
        rule = DiversityRule(
            target_count=2,
            max_per_trust_domain=2,
            min_distinct_trust_domains=2,
        )
        result = select_neighbors(_cluster("spiffe://only.mesh/ns-a", 2), rule=rule)
        self.assertEqual(len(result.selected), 2)
        self.assertTrue(result.diversity_shortfall)

    def test_no_shortfall_when_diversity_met(self):
        rule = DiversityRule(
            target_count=2,
            max_per_trust_domain=1,
            min_distinct_trust_domains=2,
        )
        result = select_neighbors(
            [
                _cand("spiffe://a.mesh/x/y"),
                _cand("spiffe://b.mesh/x/y"),
            ],
            rule=rule,
        )
        self.assertFalse(result.diversity_shortfall)
        self.assertFalse(result.target_shortfall)

    def test_target_shortfall_when_too_few_candidates(self):
        rule = DiversityRule(
            target_count=5,
            max_per_trust_domain=3,
            min_distinct_trust_domains=1,
        )
        result = select_neighbors(
            [
                _cand("spiffe://a.mesh/x/y"),
                _cand("spiffe://b.mesh/x/y"),
            ],
            rule=rule,
        )
        self.assertTrue(result.target_shortfall)

    def test_freshness_ordering_drives_selection(self):
        # 3 candidates from the same domain (cap=1) — the freshest
        # wins.
        rule = DiversityRule(
            target_count=1,
            max_per_trust_domain=1,
            min_distinct_trust_domains=1,
        )
        result = select_neighbors(
            [
                _cand("spiffe://m.mesh/ns/old", at_offset_min=60),
                _cand("spiffe://m.mesh/ns/mid", at_offset_min=30),
                _cand("spiffe://m.mesh/ns/new", at_offset_min=0),
            ],
            rule=rule,
        )
        self.assertEqual(len(result.selected), 1)
        self.assertEqual(result.selected[0].peer_iss, "spiffe://m.mesh/ns/new")

    def test_rejection_reason_codes(self):
        # Target 2, cap=1: a (m.mesh) is admitted, b (m.mesh, same TD)
        # hits the cap, x (n.mesh) is admitted; the 4th c (m.mesh)
        # also hits the cap, and a 5th (any TD) hits target-reached.
        rule = DiversityRule(
            target_count=2, max_per_trust_domain=1, min_distinct_trust_domains=2
        )
        result = select_neighbors(
            [
                _cand("spiffe://m.mesh/ns/a"),
                _cand("spiffe://m.mesh/ns/b"),  # same TD, capped
                _cand("spiffe://n.mesh/ns/x"),  # different TD, fills target
                _cand("spiffe://p.mesh/ns/y"),  # target reached
            ],
            rule=rule,
        )
        reasons = {(r.candidate.peer_iss, r.reason_code) for r in result.rejected}
        self.assertIn(("spiffe://m.mesh/ns/b", "diversity_per_domain_cap"), reasons)
        self.assertIn(
            ("spiffe://p.mesh/ns/y", "diversity_target_reached"), reasons
        )


class SelectionShapeTests(unittest.TestCase):
    def test_returns_neighbor_selection(self):
        rule = DiversityRule(
            target_count=1, max_per_trust_domain=1, min_distinct_trust_domains=1
        )
        result = select_neighbors([_cand("spiffe://a.mesh/x/y")], rule=rule)
        self.assertIsInstance(result, NeighborSelection)

    def test_non_candidate_input_rejected(self):
        rule = DiversityRule(
            target_count=1, max_per_trust_domain=1, min_distinct_trust_domains=1
        )
        with self.assertRaisesRegex(EclipseResistanceError, "candidates\\[0\\]"):
            select_neighbors(["not-a-candidate"], rule=rule)  # type: ignore[list-item]


class SurgeDetectionTests(unittest.TestCase):
    def test_detects_surge_within_window(self):
        surges = detect_trust_domain_surges(
            _cluster("spiffe://attacker.mesh/ns-x", 15),
            window_start=_NOW - timedelta(hours=1),
            window_end=_NOW,
            surge_threshold=10,
        )
        self.assertEqual(len(surges), 1)
        self.assertEqual(surges[0].trust_domain, "attacker.mesh")
        self.assertGreaterEqual(surges[0].count, 10)

    def test_excludes_out_of_window_candidates(self):
        # Half inside, half outside the window.
        in_window = _cluster(
            "spiffe://attacker.mesh/ns-x", 6, base_offset=0
        )
        out_window = _cluster(
            "spiffe://attacker.mesh/ns-y", 6, base_offset=120
        )  # 2h ago
        surges = detect_trust_domain_surges(
            [*in_window, *out_window],
            window_start=_NOW - timedelta(hours=1),
            window_end=_NOW,
            surge_threshold=6,
        )
        # Only the in-window 6 count.
        self.assertEqual(len(surges), 1)
        self.assertEqual(surges[0].count, 6)

    def test_no_surge_below_threshold(self):
        surges = detect_trust_domain_surges(
            _cluster("spiffe://attacker.mesh/ns-x", 3),
            window_start=_NOW - timedelta(hours=1),
            window_end=_NOW,
            surge_threshold=10,
        )
        self.assertEqual(surges, ())

    def test_invalid_threshold_rejected(self):
        with self.assertRaisesRegex(EclipseResistanceError, "surge_threshold"):
            detect_trust_domain_surges(
                [],
                window_start=_NOW - timedelta(hours=1),
                window_end=_NOW,
                surge_threshold=0,
            )


if __name__ == "__main__":
    unittest.main()
