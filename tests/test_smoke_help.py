"""Smoke test: every standalone script's --help must exit 0.

Run from the repo root: python3 -m unittest

The per-script test suites exercise the underlying functions
thoroughly, but mostly call into the module directly rather than
through its actual argparse wiring. A typo'd flag definition (a
duplicate dest, a bad `type=`, a malformed default) can still slip
through that and only break at the command line -- this runs each
script as a real subprocess, the way a user actually invokes it, to
catch exactly that class of mistake.
"""
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = sorted(REPO_ROOT.glob("*.py"))


class TestHelpExitsZero(unittest.TestCase):
    pass


def _make_test(script: Path):
    def test(self):
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(
            result.returncode, 0,
            f"{script.name} --help exited {result.returncode}\nstderr:\n{result.stderr}",
        )
        self.assertIn("usage:", result.stdout.lower())

    return test


for _script in SCRIPTS:
    setattr(TestHelpExitsZero, f"test_{_script.stem}_help_exits_zero", _make_test(_script))


class TestAllEightScriptsAreCovered(unittest.TestCase):
    """A safety net for the safety net: if someone adds a 9th script
    without a corresponding entry here ever being noticed missing, at
    least confirm the discovery glob found *something* plausible."""

    def test_at_least_the_known_scripts_were_discovered(self):
        names = {s.name for s in SCRIPTS}
        expected = {
            "arp_spoof_detector.py", "bandwidth_dashboard.py", "cert_expiry_checker.py",
            "duplicate_finder.py", "lan_file_server.py", "log_watcher.py",
            "network_scanner.py", "port_scanner.py",
        }
        self.assertTrue(expected.issubset(names), f"missing: {expected - names}")


if __name__ == "__main__":
    unittest.main()
