"""Replay rejection must be atomic, and the interface must force it.

Replay rejection is the one substrate invariant that *requires* atomicity:
"has this nonce been used?" and "reserve it" have to be a single operation,
or two concurrent callers both observe "not seen", both reserve, and both
are told they were first — the replay is accepted.

:class:`ReplayCache` used to ship a default ``mark_if_new`` built from
``seen`` + ``mark``, which is exactly that race. The two bundled caches
override it correctly, so the substrate itself was never vulnerable. The
hole was in the **extension point**: ``ReplayCache``'s documented interface
is ``seen``/``mark``, and `integrations/mcp/example/README.md` tells
operators to plug in "any ``ReplayCache`` subclass" for persistence. A
subclass supplying only those two methods inherited a racy replay guard.

That inheritance was worst exactly where it mattered most. Against a local
dict the window is a few bytecodes and the GIL usually hides it; but the
reason to write a custom cache is a *shared* backend for cross-process
deployment, where ``seen`` is a network round trip. Measured against a
2 ms-RTT backend: 32 of 32 concurrent callers accepted the same nonce.

These tests pin both halves of the fix: the bundled caches really are
atomic under contention, and the interface no longer lets a partial
implementation exist to be raced in the first place.
"""

import pathlib
import tempfile
import threading
import unittest
from datetime import timedelta
from typing import NamedTuple

from envelope.verify_envelope import InMemoryReplayCache, ReplayCache, SQLiteReplayCache

_SENDER = "spiffe://mesh/ns-a/service-a"
_TTL = timedelta(minutes=5)

class RaceResult(NamedTuple):
    winners: int
    losers: int
    errors: tuple[BaseException, ...]

def race_one_nonce(cache, nonce: str, *, threads: int = 32) -> RaceResult:
    """Race ``threads`` callers on one nonce; return every outcome.

    A barrier releases every thread at once so they contend on the same
    check-and-reserve rather than running in sequence. A correct cache
    returns True to exactly one.

    Every outcome is recorded, including exceptions. Counting only the
    winners would let a false green through: if one caller returned True
    and the rest *crashed* (a backend raising ``OperationalError`` under
    lock contention, say), ``Thread.join()` swallows those exceptions and
    the winner count is still 1 — but the contract says the losers must
    return False, not die. The caller asserts on all three counts.
    """
    outcomes: list[bool] = []
    errors: list[BaseException] = []
    lock = threading.Lock()
    barrier = threading.Barrier(threads)

    def worker() -> None:
        barrier.wait()
        try:
            reserved = cache.mark_if_new(_SENDER, nonce, _TTL)
        except BaseException as exc:  # noqa: BLE001 - recorded, then asserted on
            with lock:
                errors.append(exc)
            return
        with lock:
            outcomes.append(reserved)

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for t in workers:
        t.start()
    for t in workers:
        t.join()
    return RaceResult(
        winners=outcomes.count(True),
        losers=outcomes.count(False),
        errors=tuple(errors),
    )

class InterfaceForcesAtomicityTests(unittest.TestCase):
    """A cache cannot exist without deciding how it reserves atomically.

    This is the load-bearing test. The previous default made omitting
    ``mark_if_new`` silently mean "race me"; now it is a construction-time
    error, so the failure arrives at startup instead of as accepted replays
    under load.
    """

    def test_partial_implementation_cannot_be_instantiated(self):
        class SeenMarkOnlyCache(ReplayCache):
            """What a third-party cache looks like if it follows seen/mark."""

            def __init__(self):
                self._d = {}

            def seen(self, sender, nonce):
                return (sender, nonce) in self._d

            def mark(self, sender, nonce, ttl):
                self._d[(sender, nonce)] = 1

        with self.assertRaises(TypeError) as ctx:
            SeenMarkOnlyCache()
        self.assertIn("mark_if_new", str(ctx.exception))

    def test_mark_if_new_is_abstract(self):
        self.assertIn("mark_if_new", ReplayCache.__abstractmethods__)
        self.assertIn("seen", ReplayCache.__abstractmethods__)
        self.assertIn("mark", ReplayCache.__abstractmethods__)

    def test_base_class_cannot_be_instantiated(self):
        with self.assertRaises(TypeError):
            ReplayCache()

    def test_complete_implementation_is_accepted(self):
        """The interface constrains; it must not obstruct."""

        class CompleteCache(ReplayCache):
            def __init__(self):
                self._d = {}
                self._lock = threading.Lock()

            def seen(self, sender, nonce):
                with self._lock:
                    return (sender, nonce) in self._d

            def mark(self, sender, nonce, ttl):
                with self._lock:
                    self._d[(sender, nonce)] = 1

            def mark_if_new(self, sender, nonce, ttl):
                with self._lock:
                    if (sender, nonce) in self._d:
                        return False
                    self._d[(sender, nonce)] = 1
                    return True

        cache = CompleteCache()
        self.assertTrue(cache.mark_if_new(_SENDER, "n1", _TTL))
        self.assertFalse(cache.mark_if_new(_SENDER, "n1", _TTL))
        raced = race_one_nonce(cache, "raced", threads=32)
        self.assertEqual(raced.errors, ())
        self.assertEqual(raced.winners, 1)
        self.assertEqual(raced.losers, 31)

class BundledCacheAtomicityTests(unittest.TestCase):
    """The shipped caches reserve atomically under real contention."""

    def assert_exactly_one_winner(self, result: RaceResult, threads: int) -> None:
        self.assertEqual(result.errors, (), "no caller may raise")
        self.assertEqual(result.winners, 1, "exactly one caller reserves")
        self.assertEqual(result.losers, threads - 1, "every other caller is told replay")

    def test_in_memory_cache_admits_exactly_one_winner(self):
        cache = InMemoryReplayCache()
        for round_no in range(25):
            with self.subTest(round=round_no):
                self.assert_exactly_one_winner(
                    race_one_nonce(cache, f"nonce-{round_no}", threads=32), 32
                )

    def test_sqlite_cache_admits_exactly_one_winner(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = SQLiteReplayCache(pathlib.Path(tmp) / "replay.db")
            for round_no in range(10):
                with self.subTest(round=round_no):
                    self.assert_exactly_one_winner(
                        race_one_nonce(cache, f"nonce-{round_no}", threads=8), 8
                    )

    def test_concurrent_distinct_nonces_all_reserve(self):
        """Distinct keys must each reserve — contention on one must not
        spill over into rejecting unrelated nonces.

        This is a *correctness* claim, not a throughput one: it says nothing
        about whether the calls overlap. ``InMemoryReplayCache`` holds a
        single lock, so in fact they do not — and that is a fine design.
        Serialized reservation costs throughput, not safety, and per this
        repo's honesty rule a performance property earns no safety claim.
        """
        cache = InMemoryReplayCache()
        outcomes: list[bool] = []
        errors: list[BaseException] = []
        lock = threading.Lock()
        barrier = threading.Barrier(32)

        def worker(i: int) -> None:
            barrier.wait()
            try:
                ok = cache.mark_if_new(_SENDER, f"distinct-{i}", _TTL)
            except BaseException as exc:  # noqa: BLE001 - recorded, then asserted on
                with lock:
                    errors.append(exc)
                return
            with lock:
                outcomes.append(ok)

        workers = [threading.Thread(target=worker, args=(i,)) for i in range(32)]
        for t in workers:
            t.start()
        for t in workers:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(outcomes.count(True), 32)
        self.assertEqual(outcomes.count(False), 0)

    def test_same_nonce_from_different_senders_is_not_a_replay(self):
        """The reservation key is (sender, nonce), not nonce alone."""
        cache = InMemoryReplayCache()
        self.assertTrue(cache.mark_if_new("spiffe://mesh/a", "shared", _TTL))
        self.assertTrue(cache.mark_if_new("spiffe://mesh/b", "shared", _TTL))
        self.assertFalse(cache.mark_if_new("spiffe://mesh/a", "shared", _TTL))

if __name__ == "__main__":
    unittest.main()
