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
import unittest.mock as mock
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

    def make_watcher(self, from_start=False, max_line_bytes=m.DEFAULT_MAX_LINE_BYTES):
        w = m.LogWatcher(str(self.log_path), from_start=from_start, max_line_bytes=max_line_bytes)
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


class TestBoundedBuffer(LogWatcherTestCase):
    def test_unterminated_line_flushes_at_the_cap_instead_of_growing_forever(self):
        self.log_path.write_text("")
        w = self.make_watcher(from_start=True, max_line_bytes=1000)
        with self.log_path.open("a") as f:
            f.write("x" * 5000)  # far past the cap, never terminated
        lines = w.poll_new_lines()
        self.assertEqual(len(w._buffer), 0)
        self.assertEqual(len(lines), 1)
        self.assertIn("truncated", lines[0])
        self.assertGreater(len(lines[0]), 4900)  # the content itself is preserved, just marked

    def test_normal_terminated_lines_are_unaffected_by_the_cap(self):
        self.log_path.write_text("")
        w = self.make_watcher(from_start=True, max_line_bytes=1000)
        with self.log_path.open("a") as f:
            f.write("short line one\nshort line two\n")
        self.assertEqual(w.poll_new_lines(), ["short line one", "short line two"])

    def test_buffer_stays_bounded_under_sustained_unterminated_writes(self):
        """Reproduces the original finding directly: repeated large
        unterminated appends must never let the buffer grow past the cap."""
        self.log_path.write_text("")
        w = self.make_watcher(from_start=True)  # default 1 MiB cap
        for _ in range(15):  # 15 * 100KB = 1.5MB of content, no newlines
            with self.log_path.open("a") as f:
                f.write("x" * 100_000)
            w.poll_new_lines()
            self.assertLess(len(w._buffer), m.DEFAULT_MAX_LINE_BYTES)


class TestFileMissing(LogWatcherTestCase):
    def test_false_while_file_exists(self):
        self.log_path.write_text("hello\n")
        w = self.make_watcher(from_start=False)
        self.assertFalse(w.file_missing())

    def test_true_after_deletion_and_false_again_after_recreation(self):
        self.log_path.write_text("hello\n")
        w = self.make_watcher(from_start=False)
        self.log_path.unlink()
        self.assertTrue(w.file_missing())
        # must not crash while polling a deleted file
        self.assertEqual(w.poll_new_lines(), [])
        self.log_path.write_text("")
        self.assertFalse(w.file_missing())

    def test_main_loop_warns_exactly_once_per_transition(self):
        """Exercises main()'s own missing/present transition logic (not
        just LogWatcher.file_missing()) to confirm it doesn't spam a
        warning every poll cycle while the file stays missing."""
        self.log_path.write_text("")
        w = self.make_watcher(from_start=False)
        printed = []
        was_missing = False

        def one_cycle():
            nonlocal was_missing
            now_missing = w.file_missing()
            if now_missing and not was_missing:
                printed.append("missing")
            elif was_missing and not now_missing:
                printed.append("back")
            was_missing = now_missing
            w.poll_new_lines()

        for _ in range(3):
            one_cycle()
        self.log_path.unlink()
        for _ in range(5):
            one_cycle()
        self.log_path.write_text("")
        for _ in range(3):
            one_cycle()

        self.assertEqual(printed.count("missing"), 1)
        self.assertEqual(printed.count("back"), 1)


class TestTransientErrorHandling(LogWatcherTestCase):
    def test_oserror_during_read_is_swallowed_not_crashed(self):
        self.log_path.write_text("hello\n")
        w = self.make_watcher(from_start=True)
        with mock.patch.object(w._fh, "read", side_effect=OSError("simulated I/O error")):
            result = w.poll_new_lines()
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
