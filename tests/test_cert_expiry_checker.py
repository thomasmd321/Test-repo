"""Unit tests for cert_expiry_checker.py.

Run from the repo root: python3 -m unittest

Includes one real TLS handshake integration test against a loopback
server using a throwaway self-signed certificate generated with the
system `openssl` CLI, in addition to pure-logic tests for date parsing
and status classification. Skipped automatically if `openssl` isn't
available in the environment running the tests.
"""
import datetime
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import unittest.mock as mock
from pathlib import Path

import cert_expiry_checker as m


class TestParseHostPort(unittest.TestCase):
    def test_host_only_uses_default_port(self):
        self.assertEqual(m.parse_host_port("example.com"), ("example.com", 443))

    def test_host_with_explicit_port(self):
        self.assertEqual(m.parse_host_port("example.com:8443"), ("example.com", 8443))


class TestParseNotAfter(unittest.TestCase):
    def test_parses_openssl_format_as_utc(self):
        dt = m.parse_not_after("Jun  1 12:00:00 2025 GMT")
        self.assertEqual(dt, datetime.datetime(2025, 6, 1, 12, 0, 0, tzinfo=datetime.timezone.utc))


class TestDaysRemaining(unittest.TestCase):
    def test_computes_whole_days_between(self):
        now = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        expiry = datetime.datetime(2025, 1, 11, tzinfo=datetime.timezone.utc)
        self.assertEqual(m.days_remaining(expiry, now), 10)

    def test_past_expiry_is_negative(self):
        now = datetime.datetime(2025, 1, 11, tzinfo=datetime.timezone.utc)
        expiry = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        self.assertLess(m.days_remaining(expiry, now), 0)


class TestClassify(unittest.TestCase):
    def test_healthy_cert(self):
        status, code = m.classify(100, None, warn_days=30)
        self.assertEqual((status, code), ("ok", 0))

    def test_expiring_soon(self):
        status, code = m.classify(10, None, warn_days=30)
        self.assertEqual(status, "EXPIRING SOON")
        self.assertEqual(code, 1)

    def test_boundary_exactly_at_warn_days_counts_as_expiring(self):
        status, _ = m.classify(30, None, warn_days=30)
        self.assertEqual(status, "EXPIRING SOON")

    def test_expired(self):
        status, code = m.classify(-5, None, warn_days=30)
        self.assertEqual(status, "EXPIRED")
        self.assertEqual(code, 2)

    def test_connection_error(self):
        status, code = m.classify(None, "connection refused", warn_days=30)
        self.assertIn("ERROR", status)
        self.assertEqual(code, 2)


class TestCheckHost(unittest.TestCase):
    def test_success_path(self):
        fixed_expiry = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
        with mock.patch.object(m, "get_certificate_expiry", return_value=fixed_expiry):
            days_left, error = m.check_host("example.com", 443, timeout=1.0)
        self.assertIsNone(error)
        self.assertGreater(days_left, 0)

    def test_failure_path_captures_exception_text(self):
        with mock.patch.object(m, "get_certificate_expiry", side_effect=socket.timeout("timed out")):
            days_left, error = m.check_host("example.com", 443, timeout=1.0)
        self.assertIsNone(days_left)
        self.assertIn("timed out", error)


@unittest.skipUnless(shutil.which("openssl"), "openssl CLI not available")
class TestRealTlsHandshake(unittest.TestCase):
    """Spins up a real TLS server on loopback with a throwaway self-signed
    cert and performs an actual handshake through get_certificate_expiry,
    rather than mocking the network layer."""

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.cert_path = str(Path(cls.tmpdir) / "cert.pem")
        cls.key_path = str(Path(cls.tmpdir) / "key.pem")
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", cls.key_path, "-out", cls.cert_path,
                "-days", "365", "-nodes", "-subj", "/CN=localhost",
            ],
            check=True, capture_output=True,
        )
        result = subprocess.run(
            ["openssl", "x509", "-in", cls.cert_path, "-noout", "-enddate"],
            check=True, capture_output=True, text=True,
        )
        # "notAfter=Jun  1 12:00:00 2025 GMT\n" -> the datetime part
        cls.expected_expiry = m.parse_not_after(result.stdout.strip().split("=", 1)[1])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_handshake_returns_the_certs_actual_expiry(self):
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        raw_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_server.bind(("127.0.0.1", 0))
        raw_server.listen(1)
        port = raw_server.getsockname()[1]
        self.addCleanup(raw_server.close)

        def serve_once():
            try:
                conn, _ = raw_server.accept()
            except OSError:
                return
            tls_conn = None
            try:
                tls_conn = server_ctx.wrap_socket(conn, server_side=True)
                tls_conn.recv(1)
            except (ssl.SSLError, OSError):
                pass
            finally:
                # Close the TLS wrapper, not the raw socket it wraps --
                # closing only `conn` left the SSLSocket object itself
                # unclosed, which fires a ResourceWarning at GC time.
                (tls_conn or conn).close()

        thread = threading.Thread(target=serve_once, daemon=True)
        thread.start()
        time.sleep(0.1)

        client_ctx = ssl.create_default_context(cafile=self.cert_path)
        expiry = m.get_certificate_expiry("localhost", port=port, timeout=5.0, context=client_ctx)

        self.assertEqual(expiry, self.expected_expiry)


if __name__ == "__main__":
    unittest.main()
