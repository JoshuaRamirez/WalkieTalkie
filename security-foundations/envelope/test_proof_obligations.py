"""Tests for the proof obligations registry (Phase 3 Track E E1+E2+E3).

This is the **CI release gate** for the substrate's safety claims. If
an obligation's canonical test goes away (rename, deletion), this
suite fails — operators must either restore the test or deliberately
retire the obligation. That's the "block release on model/proof
regression" requirement from E3.
"""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
# Also expose Phase 4+ integration and Phase 5 mesh test modules so
# canonical_test strings can point at them.
sys.path.insert(
    0,
    str(
        pathlib.Path(__file__).resolve().parent.parent
        / "integrations"
        / "mcp"
    ),
)
sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent.parent / "mesh")
)

from proof_obligations import (
    OBLIGATIONS,
    Phase,
    ProofObligation,
    ProofObligationError,
    by_phase,
    by_track,
    find,
    resolve_test,
)


class RegistryShapeTests(unittest.TestCase):
    def test_obligations_non_empty(self):
        self.assertGreater(len(OBLIGATIONS), 0)

    def test_obligation_names_unique(self):
        names = [o.name for o in OBLIGATIONS]
        self.assertEqual(len(names), len(set(names)), "duplicate obligation name")

    def test_every_phase_has_at_least_one_obligation(self):
        # Phase 0 is foundational + already covered by Phase 1's
        # envelope verifier coverage; Phases 1/2/3 must each have
        # representation.
        phases = {o.phase for o in OBLIGATIONS}
        self.assertIn(Phase.PHASE_1, phases)
        self.assertIn(Phase.PHASE_2, phases)
        self.assertIn(Phase.PHASE_3, phases)

    def test_each_obligation_has_canonical_test_format(self):
        for o in OBLIGATIONS:
            self.assertEqual(
                o.canonical_test.count("."),
                2,
                f"{o.name}: canonical_test must be 'module.Class.method': "
                f"{o.canonical_test!r}",
            )


class ResolutionTests(unittest.TestCase):
    """The hard CI guarantee: every obligation must resolve to a real
    test method that exists at the named location."""

    def test_every_obligation_resolves(self):
        failures: list[str] = []
        for o in OBLIGATIONS:
            try:
                resolve_test(o.canonical_test)
            except ProofObligationError as exc:
                failures.append(f"{o.name}: {exc}")
        if failures:
            self.fail(
                "Proof-obligations registry has unresolved entries — "
                "either the backing test was renamed/deleted (regression) "
                "or the obligation should be retired:\n  - "
                + "\n  - ".join(failures)
            )


class QueryHelperTests(unittest.TestCase):
    def test_by_phase_returns_only_that_phase(self):
        phase_2 = by_phase(Phase.PHASE_2)
        self.assertGreater(len(phase_2), 0)
        for o in phase_2:
            self.assertEqual(o.phase, Phase.PHASE_2)

    def test_by_track_filters(self):
        track_d = by_track("D")
        self.assertGreater(len(track_d), 0)
        for o in track_d:
            self.assertEqual(o.track, "D")

    def test_find_returns_known_obligation(self):
        o = find("safe_mode_determinism")
        self.assertIsInstance(o, ProofObligation)

    def test_find_raises_on_unknown(self):
        with self.assertRaisesRegex(ProofObligationError, "unknown"):
            find("not-a-thing")


class ObligationValidationTests(unittest.TestCase):
    def test_bad_canonical_test_format_rejected(self):
        with self.assertRaisesRegex(ProofObligationError, "canonical_test"):
            ProofObligation(
                name="x",
                phase=Phase.PHASE_1,
                track="A",
                statement="x",
                canonical_test="bad",  # missing class/method
            )

    def test_empty_statement_rejected(self):
        with self.assertRaisesRegex(ProofObligationError, "statement"):
            ProofObligation(
                name="x",
                phase=Phase.PHASE_1,
                track="A",
                statement="",
                canonical_test="m.C.test_x",
            )


class CoverageBreadthTests(unittest.TestCase):
    """The registry should keep covering every Phase 2/3 track we ship.
    If a future change removes ALL obligations for a track, that's a
    regression we want CI to surface."""

    def test_phase_2_covers_all_tracks(self):
        phase_2 = by_phase(Phase.PHASE_2)
        tracks = {o.track for o in phase_2}
        for required in ("A", "B", "C", "D", "E"):
            self.assertIn(required, tracks, f"Phase 2 Track {required} unrepresented")

    def test_phase_3_covers_core_tracks(self):
        phase_3 = by_phase(Phase.PHASE_3)
        tracks = {o.track for o in phase_3}
        for required in ("A", "B", "C", "D"):
            self.assertIn(required, tracks, f"Phase 3 Track {required} unrepresented")


if __name__ == "__main__":
    unittest.main()
