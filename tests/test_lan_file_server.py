"""Unit tests for lan_file_server.py.

Run from the repo root: python3 -m unittest

Runs a real HTTP server on loopback with an ephemeral port and makes
real HTTP requests against it (download, directory listing, upload,
and -- importantly -- a path-traversal attempt in an upload filename),
rather than mocking the network layer. Nothing here binds to a
non-loopback address or touches the real network.
"""
import tempfile
import threading
import time
import unittest
import unittest.mock as mock
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import lan_file_server as m


class TestSafeUploadName(unittest.TestCase):
    def test_plain_filename_unchanged(self):
        self.assertEqual(m.safe_upload_name("report.txt"), "report.txt")

    def test_path_traversal_reduced_to_basename(self):
        self.assertEqual(m.safe_upload_name("../../../etc/passwd"), "passwd")

    def test_absolute_path_reduced_to_basename(self):
        self.assertEqual(m.safe_upload_name("/etc/passwd"), "passwd")

    def test_bare_dotdot_rejected(self):
        with self.assertRaises(ValueError):
            m.safe_upload_name("..")

    def test_empty_after_stripping_rejected(self):
        with self.assertRaises(ValueError):
            m.safe_upload_name("../")


class LiveServerTestCase(unittest.TestCase):
    """Starts a real ShareServer on 127.0.0.1:<ephemeral port> for the
    duration of each test."""

    allow_upload = False
    max_upload_size = 1 << 20

    def setUp(self):
        self._tmpdir = tempfile.TemporaryDirectory()
        self.served_dir = Path(self._tmpdir.name)
        self.addCleanup(self._tmpdir.cleanup)

        self.server = m.make_server(
            str(self.served_dir), "127.0.0.1", 0,
            allow_upload=self.allow_upload, max_upload_size=self.max_upload_size,
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.05)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"


class TestReadOnlyServing(LiveServerTestCase):
    def test_downloads_file_content_exactly(self):
        (self.served_dir / "hello.txt").write_text("hello from the LAN")
        resp = urllib.request.urlopen(self.url("/hello.txt"), timeout=2)
        self.assertEqual(resp.read(), b"hello from the LAN")

    def test_downloads_nested_file(self):
        (self.served_dir / "sub").mkdir()
        (self.served_dir / "sub" / "nested.txt").write_text("nested content")
        resp = urllib.request.urlopen(self.url("/sub/nested.txt"), timeout=2)
        self.assertEqual(resp.read(), b"nested content")

    def test_directory_listing_shows_files(self):
        (self.served_dir / "visible.txt").write_text("x")
        resp = urllib.request.urlopen(self.url("/"), timeout=2)
        self.assertIn("visible.txt", resp.read().decode())

    def test_missing_file_is_404(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.url("/does-not-exist.txt"), timeout=2)
        self.assertEqual(ctx.exception.code, 404)


class TestUploadDisabledByDefault(LiveServerTestCase):
    allow_upload = False

    def test_upload_is_rejected_with_403(self):
        req = urllib.request.Request(self.url("/upload?name=evil.txt"), data=b"x", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=2)
        self.assertEqual(ctx.exception.code, 403)
        self.assertFalse((self.served_dir / "evil.txt").exists())

    def test_upload_form_not_served(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(self.url("/upload-form"), timeout=2)
        self.assertEqual(ctx.exception.code, 404)


class TestUploadEnabled(LiveServerTestCase):
    allow_upload = True

    def test_upload_lands_on_disk_with_correct_content(self):
        req = urllib.request.Request(
            self.url("/upload?name=uploaded.txt"), data=b"content from a client", method="POST",
        )
        resp = urllib.request.urlopen(req, timeout=2)
        self.assertEqual(resp.status, 200)
        uploaded = self.served_dir / "uploaded.txt"
        self.assertTrue(uploaded.exists())
        self.assertEqual(uploaded.read_bytes(), b"content from a client")

    def test_path_traversal_in_upload_name_is_neutralized(self):
        """The whole point of safe_upload_name(): confirm it actually
        prevents escaping the served directory over real HTTP, not just
        in isolation."""
        traversal = urllib.parse.quote("../../../../etc/pwned.txt")
        req = urllib.request.Request(self.url(f"/upload?name={traversal}"), data=b"malicious", method="POST")
        resp = urllib.request.urlopen(req, timeout=2)
        self.assertEqual(resp.status, 200)
        # must land INSIDE served_dir as a bare filename, never outside it
        self.assertTrue((self.served_dir / "pwned.txt").exists())
        import os
        self.assertFalse(os.path.exists("/etc/pwned.txt"))

    def test_missing_name_param_is_400(self):
        req = urllib.request.Request(self.url("/upload"), data=b"x", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=2)
        self.assertEqual(ctx.exception.code, 400)

    def test_empty_body_is_400(self):
        req = urllib.request.Request(self.url("/upload?name=empty.txt"), data=b"", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=2)
        self.assertEqual(ctx.exception.code, 400)

    def test_oversized_upload_rejected_and_not_written(self):
        self.server.max_upload_size = 5
        req = urllib.request.Request(self.url("/upload?name=toobig.txt"), data=b"this is too big", method="POST")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=2)
        self.assertEqual(ctx.exception.code, 413)
        self.assertFalse((self.served_dir / "toobig.txt").exists())

    def test_upload_form_is_served(self):
        resp = urllib.request.urlopen(self.url("/upload-form"), timeout=2)
        self.assertIn(b"Upload a file", resp.read())

    def test_malformed_content_length_is_400_not_a_crash(self):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.putrequest("POST", "/upload?name=bad.txt")
            conn.putheader("Content-Length", "notanumber")
            conn.endheaders()
            resp = conn.getresponse()
            self.assertEqual(resp.status, 400)
        finally:
            conn.close()
        self.assertFalse((self.served_dir / "bad.txt").exists())

    def test_disconnect_mid_upload_leaves_no_file_under_real_name(self):
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest("POST", "/upload?name=partial.txt")
        conn.putheader("Content-Length", "1000")
        conn.endheaders()
        conn.send(b"only 10 b")
        conn.close()
        time.sleep(0.3)
        self.assertFalse((self.served_dir / "partial.txt").exists())
        # the private temp file must be cleaned up too, not left as debris
        self.assertEqual(list(self.served_dir.glob(".upload-*")), [])

    def test_concurrent_uploads_of_same_filename_never_corrupt(self):
        """The core fix: two simultaneous uploads to the same filename must
        never interleave/corrupt, and the file on disk must always be
        wholly one payload or the other -- never a partial mix, and never
        silently missing data while both requests report success."""
        import threading as _threading
        payload_a, payload_b = b"A" * 50000, b"B" * 50000

        def upload(payload, results, idx):
            req = urllib.request.Request(
                self.url("/upload?name=same.txt"), data=payload, method="POST",
            )
            resp = urllib.request.urlopen(req, timeout=5)
            results[idx] = resp.status

        for _ in range(5):
            results = [None, None]
            t1 = _threading.Thread(target=upload, args=(payload_a, results, 0))
            t2 = _threading.Thread(target=upload, args=(payload_b, results, 1))
            t1.start(); t2.start()
            t1.join(); t2.join()
            self.assertEqual(results, [200, 200])

            final = (self.served_dir / "same.txt").read_bytes()
            self.assertEqual(len(final), 50000)
            is_pure_a = final.count(b"A") == 50000 and final.count(b"B") == 0
            is_pure_b = final.count(b"B") == 50000 and final.count(b"A") == 0
            self.assertTrue(is_pure_a or is_pure_b, f"corrupted/interleaved file: {final.count(b'A')} A, {final.count(b'B')} B")


class TestMainValidation(unittest.TestCase):
    def test_nonexistent_directory_gives_friendly_error(self):
        import sys
        with mock.patch.object(sys, "argv", ["lan_file_server.py", "/does/not/exist", "--port", "0"]):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertIn("not a directory", str(ctx.exception))

    def test_permission_error_at_bind_gives_friendly_error(self):
        import sys
        with mock.patch.object(sys, "argv", ["lan_file_server.py", "--port", "80"]), \
             mock.patch.object(m, "make_server", side_effect=PermissionError("Permission denied")):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertIn("Permission denied", str(ctx.exception))
        self.assertIn("root", str(ctx.exception))

    def test_address_in_use_gives_friendly_error(self):
        import sys
        with mock.patch.object(sys, "argv", ["lan_file_server.py"]), \
             mock.patch.object(m, "make_server", side_effect=OSError("Address already in use")):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertIn("Address already in use", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
