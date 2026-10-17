"""Unit tests for port_scanner.py.

Run from the repo root: python3 -m unittest

Includes one real (loopback-only) integration test against an actual
listening socket, in addition to pure-logic tests for port-spec parsing.
"""
import socket
import threading
import unittest
import unittest.mock as mock

import port_scanner as m


class TestParsePorts(unittest.TestCase):
    def test_comma_list(self):
        self.assertEqual(m.parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(m.parse_ports("1-5"), [1, 2, 3, 4, 5])

    def test_mixed_list_and_range_deduplicated_and_sorted(self):
        self.assertEqual(m.parse_ports("443,22,80-82,22"), [22, 80, 81, 82, 443])

    def test_out_of_range_port_rejected(self):
        with self.assertRaises(ValueError):
            m.parse_ports("70000")
        with self.assertRaises(ValueError):
            m.parse_ports("0")

    def test_inverted_range_rejected(self):
        with self.assertRaises(ValueError):
            m.parse_ports("100-50")

    def test_whitespace_and_empty_segments_tolerated(self):
        self.assertEqual(m.parse_ports(" 22 , 80 ,"), [22, 80])


class TestServiceName(unittest.TestCase):
    def test_known_port(self):
        self.assertEqual(m.service_name(80), "http")

    def test_unknown_port_returns_empty_string(self):
        with mock.patch.object(m.socket, "getservbyport", side_effect=OSError):
            self.assertEqual(m.service_name(59999), "")


class TestScanHostAgainstRealSocket(unittest.TestCase):
    """Integration test: binds a real loopback listener and confirms
    scan_host actually distinguishes it from a closed port -- not just
    mocked socket behavior."""

    def test_distinguishes_open_from_closed_port(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        listening_port = server.getsockname()[1]

        def accept_loop():
            while True:
                try:
                    conn, _ = server.accept()
                    conn.close()
                except OSError:
                    break

        thread = threading.Thread(target=accept_loop, daemon=True)
        thread.start()
        self.addCleanup(server.close)

        closed_port = listening_port - 1 if listening_port > 1 else listening_port + 1
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        really_closed = probe.connect_ex(("127.0.0.1", closed_port)) != 0
        probe.close()
        if not really_closed:
            self.skipTest(f"port {closed_port} unexpectedly open in this environment")

        result = m.scan_host("127.0.0.1", [listening_port, closed_port], timeout=0.5)
        self.assertEqual(result, [listening_port])


class TestMainHostResolution(unittest.TestCase):
    def test_unresolvable_host_gives_friendly_error(self):
        import sys
        with mock.patch.object(sys, "argv", ["port_scanner.py", "this-does-not-resolve.invalid"]), \
             mock.patch.object(m.socket, "gethostbyname", side_effect=socket.gaierror("not found")):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertIn("Could not resolve", str(ctx.exception))

    def test_invalid_ports_flag_gives_friendly_error(self):
        import sys
        with mock.patch.object(sys, "argv", ["port_scanner.py", "127.0.0.1", "--ports", "99999"]):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertIn("Invalid --ports", str(ctx.exception))

    def test_zero_workers_gives_friendly_error_not_a_raw_valueerror(self):
        """ThreadPoolExecutor(max_workers=0) raises a bare ValueError;
        main() must catch this itself before it ever reaches there."""
        import sys
        with mock.patch.object(sys, "argv", ["port_scanner.py", "127.0.0.1", "--workers", "0"]):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertIn("--workers", str(ctx.exception))

    def test_negative_workers_gives_friendly_error(self):
        import sys
        with mock.patch.object(sys, "argv", ["port_scanner.py", "127.0.0.1", "--workers", "-5"]):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertIn("--workers", str(ctx.exception))


class TestMainKeyboardInterrupt(unittest.TestCase):
    def test_keyboard_interrupt_mid_scan_stops_cleanly_not_a_traceback(self):
        import contextlib
        import io
        import sys

        with mock.patch.object(sys, "argv", ["port_scanner.py", "127.0.0.1"]), \
             mock.patch.object(m, "scan_host", side_effect=KeyboardInterrupt):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                m.main()  # must not raise/traceback

        self.assertIn("Stopped", buf.getvalue())


class TestExitCodes(unittest.TestCase):
    def test_exits_nonzero_when_no_open_ports_found(self):
        import sys
        with mock.patch.object(sys, "argv", ["port_scanner.py", "127.0.0.1"]), \
             mock.patch.object(m, "scan_host", return_value=[]):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertNotEqual(ctx.exception.code, 0)

    def test_does_not_exit_nonzero_when_open_ports_found(self):
        import sys
        with mock.patch.object(sys, "argv", ["port_scanner.py", "127.0.0.1"]), \
             mock.patch.object(m, "scan_host", return_value=[80]):
            m.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
