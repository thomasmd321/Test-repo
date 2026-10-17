"""Unit tests for cert_expiry_checker.py.

Run from the repo root: python3 -m unittest

Includes one real TLS handshake integration test against a loopback
server using a throwaway self-signed certificate generated with the
system `openssl` CLI, in addition to pure-logic tests for date parsing
and status classification. Skipped automatically if `openssl` isn't
available in the environment running the tests.
"""
import datetime
import json
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

    def test_bare_ipv6_literal_not_misparsed_as_host_plus_port(self):
        """The original finding: naive rpartition(":") turned
        "2001:db8::1" into host "2001:db8:" port 1."""
        self.assertEqual(m.parse_host_port("2001:db8::1"), ("2001:db8::1", 443))

    def test_bare_ipv6_loopback(self):
        self.assertEqual(m.parse_host_port("::1"), ("::1", 443))

    def test_bracketed_ipv6_no_port(self):
        self.assertEqual(m.parse_host_port("[2001:db8::1]"), ("2001:db8::1", 443))

    def test_bracketed_ipv6_with_port(self):
        self.assertEqual(m.parse_host_port("[2001:db8::1]:8443"), ("2001:db8::1", 8443))

    def test_non_numeric_port_still_raises(self):
        with self.assertRaises(ValueError):
            m.parse_host_port("example.com:notaport")


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


class TestMainBatchHandling(unittest.TestCase):
    """main()'s per-host loop, exercised through its real argv/stdout
    surface rather than by calling check_host()/classify() directly."""

    def _run_main_with_mocked_expiry(self, argv, fixed_expiry):
        import contextlib
        import io

        with mock.patch.object(sys, "argv", ["cert_expiry_checker.py"] + argv), \
             mock.patch.object(m, "get_certificate_expiry", return_value=fixed_expiry):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    m.main()
                except SystemExit as exc:
                    return buf.getvalue(), exc.code
        raise AssertionError("main() should always call sys.exit()")

    def test_one_malformed_spec_does_not_abort_checking_the_rest(self):
        fixed_expiry = datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc)
        output, exit_code = self._run_main_with_mocked_expiry(
            ["good1.example", "bad:", "good2.example"], fixed_expiry,
        )
        self.assertIn("good1.example", output)
        self.assertIn("good2.example", output)
        self.assertIn("ERROR", output)
        self.assertEqual(exit_code, 2)

    def test_keyboard_interrupt_mid_batch_stops_cleanly_with_partial_results(self):
        import contextlib
        import io

        def raise_on_second_host(host, port, timeout):
            if host == "host2":
                raise KeyboardInterrupt
            return 100, None

        with mock.patch.object(sys, "argv", ["cert_expiry_checker.py", "host1", "host2", "host3"]), \
             mock.patch.object(m, "check_host", side_effect=raise_on_second_host):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                try:
                    m.main()
                except SystemExit as exc:
                    exit_code = exc.code

        output = buf.getvalue()
        self.assertIn("Stopped.", output)
        self.assertIn("host1", output)
        self.assertNotIn("host3", output)  # never reached
        self.assertEqual(exit_code, 0)


class TestJsonOutputMode(unittest.TestCase):
    def _run_main_json(self, argv, expiry_days_left=100, check_host_side_effect=None):
        import contextlib
        import io

        fixed_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=expiry_days_left)
        patches = [mock.patch.object(sys, "argv", ["cert_expiry_checker.py"] + argv)]
        if check_host_side_effect is not None:
            patches.append(mock.patch.object(m, "check_host", side_effect=check_host_side_effect))
        else:
            patches.append(mock.patch.object(m, "get_certificate_expiry", return_value=fixed_expiry))

        with patches[0], patches[1]:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                try:
                    m.main()
                except SystemExit as exc:
                    return out.getvalue(), err.getvalue(), exc.code
        raise AssertionError("main() should always call sys.exit()")

    def test_json_mode_prints_a_valid_json_array_with_expected_fields(self):
        out, _err, exit_code = self._run_main_json(["--json", "healthy.example"], expiry_days_left=100)
        results = json.loads(out)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["host"], "healthy.example")
        self.assertEqual(results[0]["port"], 443)
        self.assertGreaterEqual(results[0]["days_left"], 99)  # .days truncates; allow for clock drift
        self.assertEqual(results[0]["status"], "ok")
        self.assertEqual(exit_code, 0)

    def test_json_mode_represents_a_malformed_spec_as_a_null_port_entry(self):
        out, _err, exit_code = self._run_main_json(["--json", "bad:"], expiry_days_left=100)
        results = json.loads(out)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["host"], "bad:")
        self.assertIsNone(results[0]["port"])
        self.assertIsNone(results[0]["days_left"])
        self.assertIn("ERROR", results[0]["status"])
        self.assertEqual(exit_code, 2)

    def test_json_mode_table_header_is_not_printed(self):
        out, _err, _code = self._run_main_json(["--json", "healthy.example"], expiry_days_left=100)
        self.assertNotIn("Days Left", out)

    def test_json_mode_keyboard_interrupt_mid_batch_gives_partial_json_not_corrupted_output(self):
        def raise_on_second_host(host, port, timeout):
            if host == "host2":
                raise KeyboardInterrupt
            return 100, None

        out, err, exit_code = self._run_main_json(
            ["--json", "host1", "host2", "host3"], check_host_side_effect=raise_on_second_host,
        )
        results = json.loads(out)  # must still be valid, parseable JSON
        self.assertEqual([r["host"] for r in results], ["host1"])
        self.assertIn("Stopped", err)  # the stop notice must not land in stdout
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
