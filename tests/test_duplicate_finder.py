"""Unit tests for duplicate_finder.py.

Run from the repo root: python3 -m unittest

These operate on a real temporary directory (via tempfile), not mocks --
hashing and directory-walking are exactly the kind of logic that's easy
to get subtly wrong with mocks and cheap to test for real.
"""
import sys
import tempfile
import unittest
import unittest.mock as mock
from pathlib import Path

import duplicate_finder as m


class DuplicateFinderTestCase(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.root = Path(self._tmpdir.name)
        self.addCleanup(self._tmpdir.cleanup)

    def write(self, relative_path: str, content: str):
        path = self.root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return path


class TestHashFile(DuplicateFinderTestCase):
    def test_identical_content_same_hash(self):
        a = self.write("a.txt", "hello world")
        b = self.write("b.txt", "hello world")
        self.assertEqual(m.hash_file(a), m.hash_file(b))

    def test_different_content_different_hash(self):
        a = self.write("a.txt", "hello world")
        b = self.write("b.txt", "goodbye world")
        self.assertNotEqual(m.hash_file(a), m.hash_file(b))

    def test_large_file_chunked_correctly(self):
        # force multiple chunk_size reads to exercise the loop, not just a single read
        a = self.write("big_a.bin", "x" * 5000)
        b = self.write("big_b.bin", "x" * 5000)
        self.assertEqual(m.hash_file(a, chunk_size=1024), m.hash_file(b, chunk_size=1024))


class TestFindDuplicates(DuplicateFinderTestCase):
    def test_finds_duplicates_across_subdirectories(self):
        self.write("a.txt", "hello world")
        self.write("b.txt", "hello world")
        self.write("sub/c.txt", "hello world")
        self.write("unique.txt", "something else")

        duplicates = m.find_duplicates(self.root)
        self.assertEqual(len(duplicates), 1)
        group = list(duplicates.values())[0]
        self.assertEqual(sorted(p.name for p in group), ["a.txt", "b.txt", "c.txt"])

    def test_same_size_different_content_not_flagged(self):
        self.write("a.txt", "AAAAA")
        self.write("b.txt", "BBBBB")  # identical length, different bytes
        self.assertEqual(m.find_duplicates(self.root), {})

    def test_unique_sizes_never_hashed_together(self):
        self.write("a.txt", "short")
        self.write("b.txt", "a much longer string entirely")
        self.assertEqual(m.find_duplicates(self.root), {})

    def test_min_size_excludes_small_files(self):
        self.write("empty1.txt", "")
        self.write("empty2.txt", "")
        self.assertEqual(m.find_duplicates(self.root, min_size=1), {})
        # but they ARE duplicates of each other if min_size allows zero-byte files
        duplicates = m.find_duplicates(self.root, min_size=0)
        self.assertEqual(len(duplicates), 1)

    def test_singleton_sizes_are_not_duplicates(self):
        self.write("only_one.txt", "nothing else has this content or length")
        self.assertEqual(m.find_duplicates(self.root), {})

    def test_symlinks_are_not_followed_as_files(self):
        target = self.write("real.txt", "content")
        link = self.root / "link.txt"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlinks not supported in this environment")
        duplicates = m.find_duplicates(self.root)
        # the symlink must not be treated as a second independent duplicate file
        all_names = {p.name for group in duplicates.values() for p in group}
        self.assertNotIn("link.txt", all_names)


class TestDeleteBehavior(DuplicateFinderTestCase):
    def test_delete_keeps_first_sorted_copy_and_removes_rest(self):
        self.write("a.txt", "hello world")
        self.write("b.txt", "hello world")
        self.write("sub/c.txt", "hello world")
        self.write("unique.txt", "something else")

        with mock.patch.object(sys, "argv", ["duplicate_finder.py", str(self.root), "--delete"]):
            m.main()

        remaining = sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*.txt"))
        self.assertIn("a.txt", remaining)
        self.assertNotIn("b.txt", remaining)
        self.assertNotIn("sub/c.txt", remaining)
        self.assertIn("unique.txt", remaining)

    def test_dry_run_deletes_nothing(self):
        self.write("a.txt", "hello world")
        self.write("b.txt", "hello world")

        with mock.patch.object(sys, "argv", ["duplicate_finder.py", str(self.root)]):
            m.main()

        remaining = sorted(p.name for p in self.root.glob("*.txt"))
        self.assertEqual(remaining, ["a.txt", "b.txt"])  # nothing removed


class TestMainValidation(DuplicateFinderTestCase):
    def test_nonexistent_directory_gives_friendly_error(self):
        missing = self.root / "does-not-exist"
        with mock.patch.object(sys, "argv", ["duplicate_finder.py", str(missing)]):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertIn("not a directory", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
