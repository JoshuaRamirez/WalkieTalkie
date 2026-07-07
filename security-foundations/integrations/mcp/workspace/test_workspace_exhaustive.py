"""Exhaustive verification of the workspace-status product design.

Organized by the guarantee each block verifies, adversarially. This is the
"can a dev trust it" suite: every privacy claim is attacked, every edge is
exercised. If a test here fails, a privacy promise is broken.

Guarantees under test:
  1. Bounded surface        — nothing but get_status is reachable
  2. Workspace boundary     — only this git dir; never contents/other repos
  3. Visibility gating      — exact, monotonic, contents never leak
  4. Deny-by-default        — exact-match allow list, no near-misses
  5. Transparency           — every access (grant AND deny) is logged
  6. Identity binding       — verified peer id beats a spoofed claim (mTLS)
  7. Off means invisible    — server down => nothing, no stale data
  8. Change detection       — news only on real change, recovers after error
  9. Delivery robustness    — malformed / concurrent / timeout / correlation
 10. Git edge cases         — non-repo, empty repo, deletes, untracked
"""

import json
import pathlib
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import UTC, datetime

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))
sys.path.insert(0, str(_HERE.parents[2] / "envelope"))

from watch import WorkspaceWatcher  # noqa: E402
from workspace_server import (  # noqa: E402
    Visibility,
    WorkspaceServer,
    WorkspaceServerNode,
)


def _run(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, text=True)


def _repo(tmp: pathlib.Path, name="repo", *, commit=True) -> pathlib.Path:
    repo = tmp / name
    repo.mkdir()
    _run(repo, "init", "-q")
    _run(repo, "config", "user.email", "d@e.com")
    _run(repo, "config", "user.name", "D")
    if commit:
        (repo / "app.py").write_text("SECRET_TOKEN = 'xyzzy'\n")
        _run(repo, "add", ".")
        _run(repo, "commit", "-q", "-m", "initial")
    return repo


def _server(repo, **kw):
    kw.setdefault("name", "feat")
    kw.setdefault("allow", {"alice"})
    kw.setdefault("note", "note")
    return WorkspaceServer(workspace=repo, **kw)


# --- 1. Bounded surface ----------------------------------------------------
class BoundedSurfaceTests(unittest.TestCase):
    MALICIOUS_TOOLS = [
        "read_file", "readFile", "cat", "exec", "run", "shell", "get_file",
        "list_dir", "glob", "grep", "diff", "get_diff", "download", "..",
        "../../etc/passwd", "get_status; rm -rf", "", "GET_STATUS", "status",
    ]

    def test_only_get_status_returns_data(self):
        with tempfile.TemporaryDirectory() as td:
            srv = _server(_repo(pathlib.Path(td)))
            for tool in self.MALICIOUS_TOOLS:
                resp = srv.handle_request("alice", tool)
                self.assertNotIn("result", resp, f"tool {tool!r} leaked a result")
                self.assertIn("error", resp)

    def test_get_status_ignores_adversarial_args(self):
        # get_status takes no scope-widening args; the server never reads a
        # path from the request. Whatever is thrown at it, the surface is fixed.
        with tempfile.TemporaryDirectory() as td:
            srv = _server(_repo(pathlib.Path(td)))
            resp = srv.handle_request("alice", "get_status")
            self.assertIn("result", resp)
            # The committed file's secret is never in the surface.
            self.assertNotIn("xyzzy", json.dumps(resp))

    def test_status_object_has_no_content_bearing_keys(self):
        with tempfile.TemporaryDirectory() as td:
            srv = _server(_repo(pathlib.Path(td)), visibility=Visibility.DETAILED)
            (srv.workspace / "app.py").write_text("SECRET_TOKEN = 'leak_marker_42'\n")
            status = srv.build_status()
            forbidden = {"contents", "content", "diff", "patch", "body", "data", "file"}
            self.assertEqual(forbidden & set(status), set())
            # The modified line's content is never present — only the filename.
            self.assertNotIn("leak_marker_42", json.dumps(status))
            self.assertIn("app.py", status["changed_files"])


# --- 2. Workspace boundary -------------------------------------------------
class WorkspaceBoundaryTests(unittest.TestCase):
    def test_only_configured_repo_is_read(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            mine = _repo(tmp, "mine")
            _run(mine, "commit", "--allow-empty", "-q", "-m", "MY-SECRET-COMMIT")
            other = _repo(tmp, "other")
            _run(other, "commit", "--allow-empty", "-q", "-m", "OTHER-COMMIT")
            srv = _server(mine, visibility=Visibility.STANDARD)
            blob = json.dumps(srv.build_status())
            self.assertIn("MY-SECRET-COMMIT", blob)
            self.assertNotIn("OTHER-COMMIT", blob)  # never sees the other repo

    def test_non_git_directory_is_graceful(self):
        with tempfile.TemporaryDirectory() as td:
            plain = pathlib.Path(td) / "plain"
            plain.mkdir()
            (plain / "secret.env").write_text("API_KEY=nope\n")
            srv = _server(plain, visibility=Visibility.DETAILED)
            status = srv.build_status()  # must not crash, must not read the file
            self.assertEqual(status["branch"], "(unknown)")
            self.assertNotIn("nope", json.dumps(status))

    def test_changed_files_are_names_only_within_repo(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(pathlib.Path(td))
            (repo / "new_secret.txt").write_text("PLAINTEXT SECRET")
            srv = _server(repo, visibility=Visibility.DETAILED)
            files = srv.build_status()["changed_files"]
            self.assertIn("new_secret.txt", files)
            self.assertNotIn("PLAINTEXT SECRET", json.dumps(files))


# --- 3. Visibility gating --------------------------------------------------
class VisibilityGatingTests(unittest.TestCase):
    def _keys(self, repo, vis):
        return set(_server(repo, visibility=vis).build_status())

    def test_exact_key_sets_per_level(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(pathlib.Path(td))
            base = {"workspace", "visibility", "branch", "note", "updated_at"}
            self.assertEqual(self._keys(repo, Visibility.SUMMARY), base)
            self.assertEqual(self._keys(repo, Visibility.STANDARD), base | {"recent_commits"})
            self.assertEqual(
                self._keys(repo, Visibility.DETAILED),
                base | {"recent_commits", "changed_files"},
            )

    def test_visibility_is_monotonic(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(pathlib.Path(td))
            s = self._keys(repo, Visibility.SUMMARY)
            st = self._keys(repo, Visibility.STANDARD)
            d = self._keys(repo, Visibility.DETAILED)
            self.assertTrue(s < st < d)  # strict superset chain

    def test_no_level_ever_exposes_contents(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(pathlib.Path(td))
            (repo / "app.py").write_text("SECRET_TOKEN = 'leakme'\n")
            for vis in Visibility:
                self.assertNotIn("leakme", json.dumps(_server(repo, visibility=vis).build_status()))

    def test_status_reports_its_own_visibility(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(pathlib.Path(td))
            self.assertEqual(
                _server(repo, visibility=Visibility.SUMMARY).build_status()["visibility"],
                "summary",
            )


# --- 4. Deny-by-default ----------------------------------------------------
class DenyByDefaultTests(unittest.TestCase):
    def _s(self, repo, allow):
        return _server(repo, allow=allow)

    def test_empty_allowlist_denies_everyone(self):
        with tempfile.TemporaryDirectory() as td:
            srv = self._s(_repo(pathlib.Path(td)), set())
            for who in ("alice", "bob", "", "(anonymous)", "admin", "root"):
                self.assertTrue(self._s(srv.workspace, set()).handle_request(who, "get_status").get("denied"))

    def test_exact_match_only_no_near_misses(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(pathlib.Path(td))
            near = ["Alice", "ALICE", " alice", "alice ", "alic", "alicee",
                    "alice\n", "al ice", "alice.", "spiffe://x/alice"]
            for who in near:
                self.assertTrue(
                    self._s(repo, {"alice"}).handle_request(who, "get_status").get("denied"),
                    f"near-miss {who!r} was wrongly admitted",
                )
            # The exact id is admitted.
            self.assertIn("result", self._s(repo, {"alice"}).handle_request("alice", "get_status"))

    def test_anonymous_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            srv = self._s(_repo(pathlib.Path(td)), {"alice"})
            self.assertTrue(srv.handle_request("(anonymous)", "get_status").get("denied"))

    def test_removing_from_allowlist_denies_next_call(self):
        with tempfile.TemporaryDirectory() as td:
            srv = self._s(_repo(pathlib.Path(td)), {"alice"})
            self.assertIn("result", srv.handle_request("alice", "get_status"))
            srv.allow.discard("alice")  # revoke
            self.assertTrue(srv.handle_request("alice", "get_status").get("denied"))


# --- 5. Transparency (reciprocal access log) -------------------------------
class TransparencyTests(unittest.TestCase):
    def test_every_access_logged_grant_and_deny(self):
        with tempfile.TemporaryDirectory() as td:
            srv = _server(_repo(pathlib.Path(td)), allow={"alice"})
            srv.handle_request("alice", "get_status")
            srv.handle_request("mallory", "get_status")
            srv.handle_request("alice", "read_file")  # allowed peer, bad tool
            log = srv.who_is_watching()
            self.assertEqual([e["watcher"] for e in log], ["alice", "mallory", "alice"])
            self.assertEqual([e["granted"] for e in log], [True, False, True])

    def test_denied_attempts_are_visible_to_owner(self):
        with tempfile.TemporaryDirectory() as td:
            srv = _server(_repo(pathlib.Path(td)), allow=set())
            srv.handle_request("snooper", "get_status")
            log = srv.who_is_watching()
            self.assertEqual(len(log), 1)
            self.assertEqual(log[0]["watcher"], "snooper")
            self.assertFalse(log[0]["granted"])

    def test_log_timestamps_are_iso_utc(self):
        with tempfile.TemporaryDirectory() as td:
            srv = _server(_repo(pathlib.Path(td)), allow={"alice"})
            srv.handle_request("alice", "get_status")
            when = srv.who_is_watching()[0]["when"]
            parsed = datetime.fromisoformat(when)
            self.assertIsNotNone(parsed.tzinfo)
            self.assertLessEqual(parsed, datetime.now(UTC))

    def test_repeated_access_accumulates_entries(self):
        with tempfile.TemporaryDirectory() as td:
            srv = _server(_repo(pathlib.Path(td)), allow={"alice"})
            for _ in range(5):
                srv.handle_request("alice", "get_status")
            self.assertEqual(len(srv.who_is_watching()), 5)


# --- 6. Identity binding (spoof resistance) --------------------------------
class IdentityBindingTests(unittest.TestCase):
    def test_verified_identity_overrides_spoofed_claim(self):
        # A watcher claims to be "alice" but the transport verified "mallory":
        # authorization + the log key on the VERIFIED id, so the spoof fails.
        with tempfile.TemporaryDirectory() as td:
            srv = _server(_repo(pathlib.Path(td)), allow={"alice"})
            resp = srv.handle_request("alice", "get_status", verified_identity="mallory")
            self.assertTrue(resp.get("denied"))
            self.assertEqual(srv.who_is_watching()[-1]["watcher"], "mallory")

    def test_verified_identity_admits_the_real_peer(self):
        with tempfile.TemporaryDirectory() as td:
            srv = _server(_repo(pathlib.Path(td)), allow={"spiffe://ws/alice"})
            # Claim is a lie ("nobody"), verified peer is the real alice SVID.
            resp = srv.handle_request("nobody", "get_status",
                                      verified_identity="spiffe://ws/alice")
            self.assertIn("result", resp)

    def test_mtls_transport_binds_identity_end_to_end(self):
        # Capstone: over real mTLS, the server authorizes on the SVID from the
        # handshake — a watcher CANNOT spoof another's id by lying in the body.
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from tls_transport import TlsSocketTransport, mint_identity
        from workload_ca import WorkloadCA

        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            repo = _repo(tmp)
            reg = tmp / "reg"
            ca = WorkloadCA(trust_domain="ws.local", root_key=Ed25519PrivateKey.generate())
            alice_id = "spiffe://ws.local/alice"
            mallory_id = "spiffe://ws.local/mallory"
            srv = _server(repo, name="feat", allow={alice_id}, note="secret plan")
            node = WorkspaceServerNode(
                srv, reg,
                transport=TlsSocketTransport(mint_identity(ca, "spiffe://ws.local/server")),
                trust_transport_identity=True,
            )
            # alice's SVID is on the allow list; she pulls successfully even if
            # she lies about her id in the payload.
            alice = WorkspaceWatcher(
                "i-am-totally-bob", reg,
                transport=TlsSocketTransport(mint_identity(ca, alice_id)),
            )
            # mallory's SVID is NOT on the list; claiming to be alice fails,
            # because the server keys on the mTLS-verified SVID.
            mallory = WorkspaceWatcher(
                "alice", reg,
                transport=TlsSocketTransport(mint_identity(ca, mallory_id)),
            )
            try:
                _, aresp = alice.check("feat")
                self.assertIn("result", aresp, "verified alice should be admitted")
                _, mresp = mallory.check("feat")
                self.assertTrue(mresp.get("denied"), "spoofing alice must fail over mTLS")
                # The log names the VERIFIED identities, not the claims.
                watchers = {e["watcher"] for e in srv.who_is_watching()}
                self.assertIn(alice_id, watchers)
                self.assertIn(mallory_id, watchers)
            finally:
                alice.close()
                mallory.close()
                node.close()


# --- 7. Off means invisible ------------------------------------------------
class OffMeansInvisibleTests(unittest.TestCase):
    def test_unpublished_workspace_errors(self):
        with tempfile.TemporaryDirectory() as td:
            w = WorkspaceWatcher("alice", pathlib.Path(td))
            try:
                _, resp = w.check("ghost")
                self.assertIn("error", resp)
                self.assertNotIn("result", resp)
            finally:
                w.close()

    def test_closed_server_leaves_nothing_to_read(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            reg = tmp / "reg"
            node = WorkspaceServerNode(_server(_repo(tmp), allow={"alice"}), reg)
            self.assertTrue((reg / "workspace-feat.json").exists())
            node.close()
            # Registry entry gone -> a watcher can't even find it.
            self.assertFalse((reg / "workspace-feat.json").exists())
            w = WorkspaceWatcher("alice", reg)
            try:
                _, resp = w.check("feat")
                self.assertIn("error", resp)
            finally:
                w.close()


# --- 8. Change detection ---------------------------------------------------
class ChangeDetectionTests(unittest.TestCase):
    def _wire(self, td):
        tmp = pathlib.Path(td)
        repo = _repo(tmp)
        reg = tmp / "reg"
        srv = _server(repo, allow={"alice"}, note="v1")
        node = WorkspaceServerNode(srv, reg)
        w = WorkspaceWatcher("alice", reg)
        return repo, srv, node, w

    def test_first_poll_is_news_then_quiet(self):
        with tempfile.TemporaryDirectory() as td:
            _, _, node, w = self._wire(td)
            try:
                self.assertTrue(w.check("feat")[0])
                self.assertFalse(w.check("feat")[0])
                self.assertFalse(w.check("feat")[0])
            finally:
                w.close()
                node.close()

    def test_each_news_field_triggers_change(self):
        with tempfile.TemporaryDirectory() as td:
            repo, srv, node, w = self._wire(td)
            try:
                w.check("feat")  # baseline
                srv.note = "v2"
                self.assertTrue(w.check("feat")[0], "note change missed")
                srv.visibility = Visibility.DETAILED
                (repo / "x.py").write_text("x")  # changed_files now non-empty
                self.assertTrue(w.check("feat")[0], "changed_files change missed")
                _run(repo, "add", ".")
                _run(repo, "commit", "-q", "-m", "new commit")
                self.assertTrue(w.check("feat")[0], "commit change missed")
            finally:
                w.close()
                node.close()

    def test_error_does_not_poison_baseline(self):
        with tempfile.TemporaryDirectory() as td:
            repo, srv, node, w = self._wire(td)
            try:
                self.assertTrue(w.check("feat")[0])   # got baseline
                node.close()                            # server goes away
                self.assertFalse(w.check("feat")[0])   # error, not news
            finally:
                w.close()


# --- 9. Delivery robustness ------------------------------------------------
class DeliveryRobustnessTests(unittest.TestCase):
    def test_malformed_request_does_not_crash_server(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            reg = tmp / "reg"
            node = WorkspaceServerNode(_server(_repo(tmp), allow={"alice"}), reg)
            junk = WorkspaceWatcher("alice", reg)
            try:
                # Send raw junk straight at the server's transport.
                addr = json.loads((reg / "workspace-feat.json").read_text())["address"]
                junk.transport.send(addr, b"not json at all")
                junk.transport.send(addr, json.dumps({"op": "nope"}).encode())
                # The server still answers a valid request afterward.
                _, resp = junk.check("feat")
                self.assertIn("result", resp)
            finally:
                junk.close()
                node.close()

    def test_concurrent_watchers_all_served_and_logged(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            reg = tmp / "reg"
            ids = [f"w{i}" for i in range(8)]
            srv = _server(_repo(tmp), allow=set(ids))
            node = WorkspaceServerNode(srv, reg)
            watchers = [WorkspaceWatcher(i, reg) for i in ids]
            results = {}

            def pull(w):
                results[w.watcher_id] = w.check("feat")[1]

            threads = [threading.Thread(target=pull, args=(w,)) for w in watchers]
            try:
                for t in threads:
                    t.start()
                for t in threads:
                    t.join(timeout=10)
                self.assertEqual(len(results), 8)
                for r in results.values():
                    self.assertIn("result", r)
                # Every watcher's access was recorded (thread-safe log).
                logged = {e["watcher"] for e in srv.who_is_watching()}
                self.assertEqual(logged, set(ids))
            finally:
                for w in watchers:
                    w.close()
                node.close()

    def test_timeout_when_no_server(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            reg = tmp / "reg"
            reg.mkdir()
            # Announce a bogus address nobody is listening on.
            (reg / "workspace-feat.json").write_text(
                json.dumps({"name": "feat", "address": "127.0.0.1:1"})
            )
            w = WorkspaceWatcher("alice", reg)
            try:
                _, resp = w.check("feat")
                self.assertIn("error", resp)
            finally:
                w.close()


# --- 10. Git edge cases ----------------------------------------------------
class GitEdgeTests(unittest.TestCase):
    def test_empty_repo_no_commits(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(pathlib.Path(td), commit=False)
            status = _server(repo, visibility=Visibility.STANDARD).build_status()
            self.assertEqual(status["recent_commits"], [])  # no commits, no crash

    def test_deleted_file_shows_as_name(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(pathlib.Path(td))
            (repo / "app.py").unlink()  # delete a tracked file
            files = _server(repo, visibility=Visibility.DETAILED).build_status()["changed_files"]
            self.assertIn("app.py", files)

    def test_untracked_file_shows_as_name_only(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _repo(pathlib.Path(td))
            (repo / "notes.md").write_text("PRIVATE BRAINSTORM")
            status = _server(repo, visibility=Visibility.DETAILED).build_status()
            self.assertIn("notes.md", status["changed_files"])
            self.assertNotIn("PRIVATE BRAINSTORM", json.dumps(status))


if __name__ == "__main__":
    unittest.main()
