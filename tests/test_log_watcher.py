"""Unit tests for log_watcher.py.

Run from the repo root: python3 -m unittest

Operates on real temporary files -- append, truncate, and rename/rotate
are exactly the filesystem edge cases that are easy to get subtly wrong
and cheap to test for real rather than with mocks.
"""
import os
import re
import tempfile
import unittest
from pathlib import Path

import log_watcher as m


class TestMatchesAny(unittest.TestCase):
    def test_matching_line(self):
        patterns = m.compile_patterns(["ERROR", "WARN"])
        self.assertIsNotNone(m.matches_any("an ERROR occurred", patterns))

    def test_non_matching_line(self):
        patterns = m.compile_patterns(["ERROR"])
        self.assertIsNone(m.matches_any("all good here", patterns))

    def test_invalid_regex_raises(self):
        with self.assertRaises(re.error):
            m.compile_patterns(["("])  # unbalanced paren


class LogWatcherTestCase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)
        self.log_path = self.tmp / "app.log"
        self.addCleanup(self._tmpdir.cleanup)
        self._watchers = []

    def tearDown(self):
        for w in self._watchers:
            w.close()

    def make_watcher(self, from_start=False):
        w = m.LogWatcher(str(self.log_path), from_start=from_start)
        self._watchers.append(w)
        return w


class TestTailSemantics(LogWatcherTestCase):
    def test_starts_at_end_sees_only_new_lines(self):
        self.log_path.write_text("old line 1\nold line 2\n")
        w = self.make_watcher(from_start=False)
        self.assertEqual(w.poll_new_lines(), [])

        with self.log_path.open("a") as f:
            f.write("new line 1\nnew line 2\n")
        self.assertEqual(w.poll_new_lines(), ["new line 1", "new line 2"])

    def test_from_start_reads_existing_content(self):
        self.log_path.write_text("old line 1\nold line 2\n")
        w = self.make_watcher(from_start=True)
        self.assertEqual(w.poll_new_lines(), ["old line 1", "old line 2"])

    def test_partial_line_not_yet_terminated_is_not_returned_until_newline(self):
        self.log_path.write_text("")
        w = self.make_watcher(from_start=True)
        with self.log_path.open("a") as f:
            f.write("no newline yet")
        self.assertEqual(w.poll_new_lines(), [])  # readlines() won't split an unterminated tail
        with self.log_path.open("a") as f:
            f.write(" -- now complete\n")
        self.assertEqual(w.poll_new_lines(), ["no newline yet -- now complete"])


class TestRotationHandling(LogWatcherTestCase):
    def test_truncation_same_inode_is_detected(self):
        self.log_path.write_text("line 1\nline 2\n")  # 14 bytes
        w = self.make_watcher(from_start=False)
        # Realistic truncation: logrotate's copytruncate zeroes the file,
        # and new content accumulates gradually -- so the new size starts
        # out smaller than our old read offset. (A polling watcher can't
        # detect truncation if the file is truncated AND refilled past the
        # old offset entirely between two polls; that's a known limitation
        # shared by any size-based heuristic, not exercised here.)
        with self.log_path.open("w") as f:  # truncate in place, same inode
            f.write("x\n")  # shorter than the 14 bytes already read
        self.assertEqual(w.poll_new_lines(), ["x"])

    def test_rename_rotation_new_inode_is_detected(self):
        self.log_path.write_text("line 1\n")
        w = self.make_watcher(from_start=False)

        rotated = self.tmp / "app.log.1"
        os.rename(self.log_path, rotated)
        self.log_path.write_text("brand new file\n")

        self.assertEqual(w.poll_new_lines(), ["brand new file"])

    def test_no_false_rotation_on_normal_append(self):
        self.log_path.write_text("line 1\n")
        w = self.make_watcher(from_start=False)
        original_inode = w._inode
        with self.log_path.open("a") as f:
            f.write("line 2\n")
        w.poll_new_lines()
        self.assertEqual(w._inode, original_inode)  # should not have reopened


if __name__ == "__main__":
    unittest.main()
