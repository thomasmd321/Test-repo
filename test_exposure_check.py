import csv
import json
import socket
import threading
import urllib.error
from unittest.mock import MagicMock, patch

import exposure_check as ec


class TestGetPublicIp:
    def test_returns_stripped_body_when_it_is_a_valid_ip(self):
        fake_response = MagicMock()
        fake_response.read.return_value = b"203.0.113.5\n"
        fake_response.__enter__.return_value = fake_response

        with patch("exposure_check.urllib.request.urlopen", return_value=fake_response):
            assert ec.get_public_ip(timeout=1.0) == "203.0.113.5"

    def test_raises_when_the_request_fails(self):
        with patch("exposure_check.urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
            try:
                ec.get_public_ip(timeout=1.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "api.ipify.org" in str(exc)

    def test_raises_when_the_response_is_not_a_valid_ip(self):
        fake_response = MagicMock()
        fake_response.read.return_value = b"<html>not an ip</html>"
        fake_response.__enter__.return_value = fake_response

        with patch("exposure_check.urllib.request.urlopen", return_value=fake_response):
            try:
                ec.get_public_ip(timeout=1.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "isn't an IPv4 address" in str(exc)


class TestCheckPort:
    def test_returns_true_for_a_real_open_port(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def accept_once():
            conn, _ = server.accept()
            conn.close()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        try:
            assert ec.check_port("127.0.0.1", port, timeout=1.0) is True
        finally:
            server.close()
            thread.join(timeout=1)

    def test_returns_false_for_a_closed_port(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.close()  # Bound, then immediately closed - almost certainly refused.

        assert ec.check_port("127.0.0.1", port, timeout=1.0) is False


class TestCheckExposure:
    def test_probes_every_port_and_preserves_order(self):
        def fake_check(ip, port, timeout):
            return port == 80

        with patch("exposure_check.check_port", side_effect=fake_check):
            results = ec.check_exposure("203.0.113.5", [23, 80, 445], timeout=1.0)

        assert [r["port"] for r in results] == [23, 80, 445]
        assert [r["reachable"] for r in results] == [False, True, False]

    def test_attaches_the_risky_ports_reason_when_applicable(self):
        with patch("exposure_check.check_port", return_value=False):
            results = ec.check_exposure("203.0.113.5", [23], timeout=1.0)

        assert results[0]["reason"] == ec.RISKY_PORTS[23]

    def test_reason_is_empty_for_a_non_risky_port(self):
        with patch("exposure_check.check_port", return_value=False):
            results = ec.check_exposure("203.0.113.5", [8080], timeout=1.0)

        assert results[0]["reason"] == ""


class TestExportResults:
    def test_writes_json_by_default(self, tmp_path):
        path = tmp_path / "exposure.json"
        results = [{"port": 23, "reachable": True, "reason": "Telnet transmits everything, including credentials, in plaintext"}]

        ec.export_results("203.0.113.5", results, path)

        data = json.loads(path.read_text(encoding="utf-8"))
        assert data == {"ip": "203.0.113.5", "results": results}

    def test_writes_csv_when_extension_is_csv(self, tmp_path):
        path = tmp_path / "exposure.csv"
        results = [{"port": 23, "reachable": True, "reason": "risky"}]

        ec.export_results("203.0.113.5", results, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows == [{"ip": "203.0.113.5", "port": "23", "reachable": "True", "reason": "risky"}]


class TestUseColor:
    def test_disabled_by_flag(self):
        assert ec._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert ec._use_color(no_color_flag=False) is False

    def test_disabled_when_not_a_tty(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        with patch("exposure_check.sys.stdout.isatty", return_value=False):
            assert ec._use_color(no_color_flag=False) is False


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        assert ec._colorize("hello", "red", True) == f"{ec._ANSI_CODES['red']}hello{ec._ANSI_CODES['reset']}"

    def test_returns_text_unchanged_when_disabled(self):
        assert ec._colorize("hello", "red", False) == "hello"
