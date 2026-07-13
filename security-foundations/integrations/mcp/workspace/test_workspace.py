"""Tests for the workspace status server (privacy model + delivery)."""

import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
sys.path.insert(0, str(_HERE.parents[2] / "mesh"))

from watch import WorkspaceWatcher  # noqa: E402
from workspace_server import (  # noqa: E402
    Visibility,
    WorkspaceServer,
    WorkspaceServerNode,
)


def _git_repo(tmp: pathlib.Path) -> pathlib.Path:
    repo = tmp / "repo"
    repo.mkdir()
    env_args = dict(cwd=repo, capture_output=True, text=True)
    subprocess.run(["git", "init", "-q"], **env_args)
    subprocess.run(["git", "config", "user.email", "dev@example.com"], **env_args)
    subprocess.run(["git", "config", "user.name", "Dev"], **env_args)
    (repo / "app.py").write_text("print('v1')\n")
    subprocess.run(["git", "add", "."], **env_args)
    subprocess.run(["git", "commit", "-q", "-m", "add app"], **env_args)
    return repo


class VisibilityTests(unittest.TestCase):
    def _server(self, repo, vis):
        return WorkspaceServer(
            workspace=repo, name="feat-x", allow={"alice"}, visibility=vis,
            note="working on the payment retry logic",
        )

    def test_summary_hides_commits_and_files(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _git_repo(pathlib.Path(td))
            s = self._server(repo, Visibility.SUMMARY).build_status()
            self.assertEqual(s["note"], "working on the payment retry logic")
            self.assertNotIn("recent_commits", s)
            self.assertNotIn("changed_files", s)
            # No file contents, ever.
            self.assertNotIn("contents", s)

    def test_standard_shows_commits_not_files(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _git_repo(pathlib.Path(td))
            s = self._server(repo, Visibility.STANDARD).build_status()
            self.assertIn("add app", s["recent_commits"])
            self.assertNotIn("changed_files", s)

    def test_detailed_shows_changed_file_names_only(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _git_repo(pathlib.Path(td))
            (repo / "app.py").write_text("print('v2')\n")  # uncommitted change
            s = self._server(repo, Visibility.DETAILED).build_status()
            self.assertIn("app.py", s["changed_files"])
            # Names only — the actual change ('v2') is never exposed.
            self.assertNotIn("v2", str(s))


class PermissionTests(unittest.TestCase):
    def _server(self, repo):
        return WorkspaceServer(workspace=repo, name="feat-x", allow={"alice"}, note="x")

    def test_allowed_watcher_gets_status(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _git_repo(pathlib.Path(td))
            resp = self._server(repo).handle_request("alice", "get_status")
            self.assertIn("result", resp)

    def test_unlisted_watcher_denied(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _git_repo(pathlib.Path(td))
            resp = self._server(repo).handle_request("mallory", "get_status")
            self.assertTrue(resp.get("denied"))
            self.assertNotIn("result", resp)

    def test_no_tool_can_read_files(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _git_repo(pathlib.Path(td))
            # Even an allowed watcher can only get_status — there is no tool
            # to read a file or name an arbitrary path.
            resp = self._server(repo).handle_request("alice", "read_file")
            self.assertNotIn("result", resp)
            self.assertIn("error", resp)

    def test_access_is_logged_both_ways(self):
        with tempfile.TemporaryDirectory() as td:
            repo = _git_repo(pathlib.Path(td))
            srv = self._server(repo)
            srv.handle_request("alice", "get_status")     # granted
            srv.handle_request("mallory", "get_status")   # denied
            log = srv.who_is_watching()
            self.assertEqual(len(log), 2)
            watchers = {e["watcher"]: e["granted"] for e in log}
            self.assertTrue(watchers["alice"])
            self.assertFalse(watchers["mallory"])


class DeliveryTests(unittest.TestCase):
    def test_watcher_pulls_over_the_mesh_and_denied_is_denied(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            repo = _git_repo(tmp)
            reg = tmp / "registry"
            server = WorkspaceServer(
                workspace=repo, name="feat-x", allow={"alice"},
                note="blocked on webhook signature",
            )
            node = WorkspaceServerNode(server, reg)
            alice = WorkspaceWatcher("alice", reg)
            mallory = WorkspaceWatcher("mallory", reg)
            try:
                changed, resp = alice.check("feat-x")
                self.assertTrue(changed)
                self.assertEqual(resp["result"]["note"], "blocked on webhook signature")
                # A second poll with no change → no new "news".
                changed2, _ = alice.check("feat-x")
                self.assertFalse(changed2)

                # Mallory is not on the allow list.
                _, mresp = mallory.check("feat-x")
                self.assertTrue(mresp.get("denied"))
            finally:
                alice.close()
                mallory.close()
                node.close()

    def test_change_produces_new_digest(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = pathlib.Path(td)
            repo = _git_repo(tmp)
            reg = tmp / "registry"
            server = WorkspaceServer(workspace=repo, name="feat-x", allow={"alice"}, note="v1")
            node = WorkspaceServerNode(server, reg)
            alice = WorkspaceWatcher("alice", reg)
            try:
                self.assertTrue(alice.check("feat-x")[0])       # first sight
                self.assertFalse(alice.check("feat-x")[0])      # unchanged
                server.note = "v2 — retry logic landed"          # owner updates
                time.sleep(0.05)
                self.assertTrue(alice.check("feat-x")[0])       # news again
            finally:
                alice.close()
                node.close()

    def test_unpublished_workspace_reports_down(self):
        with tempfile.TemporaryDirectory() as td:
            reg = pathlib.Path(td)
            reg.mkdir(exist_ok=True)
            alice = WorkspaceWatcher("alice", reg)
            try:
                _, resp = alice.check("ghost")
                self.assertIn("error", resp)
            finally:
                alice.close()


if __name__ == "__main__":
    unittest.main()
