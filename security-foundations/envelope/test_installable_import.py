"""Consumer-style import proof for the installable-package restructure.

The substrate used to resolve siblings by bare name (``from audit import …``)
only when each package directory was itself on ``sys.path``. After this
slice, ``pip install`` / ``pip install -e .`` produces a real library:
``import envelope.verify_envelope`` works, and bare sibling imports do not.

These tests drive a *separate process* that does not have the source
package directories on ``sys.path`` — the way a consumer of the installed
wheel would import the substrate.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_FLAT_ROOTS = (
    _REPO / "security-foundations" / "envelope",
    _REPO / "security-foundations" / "mesh",
    _REPO / "security-foundations" / "integrations",
    _REPO / "security-foundations" / "integrations" / "mcp",
)


def _drop_editable_finders_src() -> str:
    return (
        "sys.meta_path[:] = [\n"
        "    f for f in sys.meta_path\n"
        "    if 'hatchling' not in type(f).__module__\n"
        "    and 'editable' not in type(f).__module__.lower()\n"
        "]\n"
    )


class InstallableImportTests(unittest.TestCase):
    def test_public_imports_without_flat_source_dirs_on_path(self):
        """Import the public modules with the old flat roots stripped."""
        banned = [str(p.resolve()) for p in _FLAT_ROOTS]
        code = (
            "import sys\n"
            "from pathlib import Path\n"
            f"banned = {{Path(p).resolve() for p in {banned!r}}}\n"
            "sys.path[:] = [\n"
            "    p for p in sys.path\n"
            "    if p and Path(p).resolve() not in banned\n"
            "]\n"
            "import envelope.verify_envelope\n"
            "import envelope.audit\n"
            "import envelope.workload_ca\n"
            "import mesh.transport\n"
            "import mesh.tls_transport\n"
            "import mesh.node\n"
            "import integrations.mcp.envelope_adapter\n"
            "import integrations.mcp.host\n"
            "try:\n"
            "    import audit  # noqa: F401\n"
            "except ImportError:\n"
            "    pass\n"
            "else:\n"
            "    raise SystemExit(\"bare sibling import 'audit' unexpectedly succeeded\")\n"
            "print('ok')\n"
        )
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=tempfile.gettempdir(),
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            f"consumer import failed:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
        )
        self.assertIn("ok", proc.stdout)

    def test_wheel_install_imports_as_a_library(self):
        """Install a non-editable wheel into a temp dir and import from it."""
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "site"
            install = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "pip",
                    "install",
                    "--target",
                    str(target),
                    "--no-deps",
                    str(_REPO),
                ],
                cwd=td,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                install.returncode,
                0,
                f"pip install --target failed:\n{install.stdout}\n{install.stderr}",
            )
            self.assertTrue(
                (target / "envelope" / "verify_envelope.py").is_file(),
                "wheel did not install envelope.verify_envelope",
            )
            self.assertFalse(
                (target / "envelope" / "test_verify_envelope.py").exists(),
                "wheel must not ship test modules",
            )
            self.assertTrue(
                (target / "integrations" / "mcp" / "host.py").is_file(),
                "wheel did not install integrations.mcp.host",
            )
            self.assertTrue(
                (target / "integrations" / "mcp" / "default_tools.py").is_file(),
                "wheel must ship the host's default tool handlers",
            )
            self.assertFalse(
                (target / "integrations" / "mcp" / "demo_tools.py").exists(),
                "demo_*.py must stay excluded from the wheel",
            )
            code = (
                "import sys\n"
                "from pathlib import Path\n"
                + _drop_editable_finders_src()
                + f"repo = Path({str(_REPO)!r}).resolve()\n"
                "def _keep(p):\n"
                "    if not p:\n"
                "        return False\n"
                "    resolved = Path(p).resolve()\n"
                "    if resolved == repo or repo in resolved.parents:\n"
                "        # Keep the active venv (deps) but drop the source tree.\n"
                "        if '.venv' in resolved.parts or 'site-packages' in resolved.parts:\n"
                "            return True\n"
                "        return False\n"
                "    return True\n"
                "sys.path[:] = [p for p in sys.path if _keep(p)]\n"
                f"sys.path.insert(0, {str(target)!r})\n"
                "import envelope.verify_envelope as ev\n"
                "import mesh.tls_transport as tt\n"
                "import integrations.mcp.envelope_adapter as ea\n"
                "import integrations.mcp.host as host\n"
                f"installed = Path({str(target)!r}).resolve()\n"
                "assert Path(ev.__file__).resolve().is_relative_to(installed), ev.__file__\n"
                "assert Path(tt.__file__).resolve().is_relative_to(installed), tt.__file__\n"
                "assert Path(ea.__file__).resolve().is_relative_to(installed), ea.__file__\n"
                "assert Path(host.__file__).resolve().is_relative_to(installed), host.__file__\n"
                "try:\n"
                "    import audit  # noqa: F401\n"
                "except ImportError:\n"
                "    pass\n"
                "else:\n"
                "    raise SystemExit(\"bare sibling import 'audit' succeeded from wheel\")\n"
                "print('ok')\n"
            )
            env = os.environ.copy()
            env.pop("PYTHONPATH", None)
            proc = subprocess.run(
                [sys.executable, "-c", code],
                cwd=td,
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                proc.returncode,
                0,
                f"wheel consumer import failed:\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}",
            )
            self.assertIn("ok", proc.stdout)


if __name__ == "__main__":
    unittest.main()
