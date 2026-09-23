import csv
import json
import subprocess
from unittest.mock import MagicMock, patch

import traceroute_mapper as tm


class TestParseUnixTraceroute:
    def test_parses_a_normal_hop_with_three_rtts(self):
        output = "traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets\n 1  192.168.1.1  0.489 ms  0.410 ms  0.375 ms\n"
        hops = tm._parse_unix_traceroute(output)

        assert hops == [{"hop": 1, "ip": "192.168.1.1", "hostname": "", "rtts_ms": [0.489, 0.410, 0.375]}]

    def test_parses_multiple_hops_in_order(self):
        output = (
            " 1  192.168.1.1  0.489 ms  0.410 ms  0.375 ms\n"
            " 2  10.0.0.1  5.123 ms  4.998 ms  5.045 ms\n"
            " 3  8.8.8.8  14.234 ms  14.111 ms  14.098 ms\n"
        )
        hops = tm._parse_unix_traceroute(output)

        assert [h["hop"] for h in hops] == [1, 2, 3]
        assert [h["ip"] for h in hops] == ["192.168.1.1", "10.0.0.1", "8.8.8.8"]

    def test_fully_timed_out_hop_has_no_ip_and_three_nones(self):
        hops = tm._parse_unix_traceroute(" 4  * * *\n")

        assert hops == [{"hop": 4, "ip": None, "hostname": "", "rtts_ms": [None, None, None]}]

    def test_partially_timed_out_hop_mixes_values_and_none(self):
        hops = tm._parse_unix_traceroute(" 3  10.0.0.1  5.123 ms  * 5.045 ms\n")

        assert hops[0]["ip"] == "10.0.0.1"
        assert hops[0]["rtts_ms"] == [5.123, None, 5.045]

    def test_ignores_the_header_line(self):
        output = "traceroute to 8.8.8.8 (8.8.8.8), 30 hops max, 60 byte packets\n"
        assert tm._parse_unix_traceroute(output) == []

    def test_ignores_blank_lines(self):
        output = "\n 1  192.168.1.1  1.0 ms  1.0 ms  1.0 ms\n\n"
        assert len(tm._parse_unix_traceroute(output)) == 1


class TestRunUnixTraceroute:
    def test_raises_clear_error_when_traceroute_missing(self):
        with patch("traceroute_mapper.subprocess.run", side_effect=FileNotFoundError()):
            try:
                tm._run_unix_traceroute("8.8.8.8", max_hops=30, timeout=2.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "traceroute" in str(exc)

    def test_raises_clear_error_on_timeout(self):
        with patch("traceroute_mapper.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="traceroute", timeout=70)):
            try:
                tm._run_unix_traceroute("8.8.8.8", max_hops=30, timeout=2.0)
                assert False, "expected RuntimeError"
            except RuntimeError:
                pass

    def test_passes_max_hops_and_timeout_to_the_command(self):
        with patch("traceroute_mapper.subprocess.run", return_value=MagicMock(stdout="")) as mock_run:
            tm._run_unix_traceroute("8.8.8.8", max_hops=15, timeout=3.0)

        args = mock_run.call_args.args[0]
        assert "8.8.8.8" in args
        assert "15" in args
        assert "3.0" in args


class TestParseWindowsTracert:
    def test_parses_a_normal_hop(self):
        line = "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
        hops = tm._parse_windows_tracert(line)

        assert hops == [{"hop": 1, "ip": "192.168.1.1", "hostname": "", "rtts_ms": [1.0, 1.0, 1.0]}]

    def test_timed_out_hop_has_no_ip(self):
        line = "  2     *        *        *     Request timed out.\n"
        hops = tm._parse_windows_tracert(line)

        assert hops == [{"hop": 2, "ip": None, "hostname": "", "rtts_ms": [None, None, None]}]

    def test_ignores_non_hop_lines(self):
        output = "Tracing route to 8.8.8.8 over a maximum of 30 hops\n\nTrace complete.\n"
        assert tm._parse_windows_tracert(output) == []

    def test_parses_a_full_sample_trace(self):
        output = (
            "Tracing route to 8.8.8.8 over a maximum of 30 hops\n\n"
            "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
            "  2     *        *        *     Request timed out.\n"
            "  3    15 ms    14 ms    14 ms  8.8.8.8\n\n"
            "Trace complete.\n"
        )
        hops = tm._parse_windows_tracert(output)

        assert [h["hop"] for h in hops] == [1, 2, 3]
        assert hops[1]["ip"] is None
        assert hops[2]["ip"] == "8.8.8.8"


class TestRunWindowsTracert:
    def test_raises_clear_error_when_tracert_missing(self):
        with patch("traceroute_mapper.subprocess.run", side_effect=FileNotFoundError()):
            try:
                tm._run_windows_tracert("8.8.8.8", max_hops=30, timeout=2.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "tracert" in str(exc)


class TestTraceroute:
    def test_dispatches_to_unix_on_linux(self):
        with patch("traceroute_mapper.platform.system", return_value="Linux"), \
                patch("traceroute_mapper._run_unix_traceroute", return_value=[]) as mock_run:
            tm.traceroute("8.8.8.8")
        mock_run.assert_called_once()

    def test_dispatches_to_unix_on_macos(self):
        with patch("traceroute_mapper.platform.system", return_value="Darwin"), \
                patch("traceroute_mapper._run_unix_traceroute", return_value=[]) as mock_run:
            tm.traceroute("8.8.8.8")
        mock_run.assert_called_once()

    def test_dispatches_to_windows(self):
        with patch("traceroute_mapper.platform.system", return_value="Windows"), \
                patch("traceroute_mapper._run_windows_tracert", return_value=[]) as mock_run:
            tm.traceroute("8.8.8.8")
        mock_run.assert_called_once()

    def test_raises_on_unsupported_platform(self):
        with patch("traceroute_mapper.platform.system", return_value="Plan9"):
            try:
                tm.traceroute("8.8.8.8")
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "Plan9" in str(exc)

    def test_resolves_hostnames_by_default(self):
        hop = {"hop": 1, "ip": "192.168.1.1", "hostname": "", "rtts_ms": [1.0, 1.0, 1.0]}
        with patch("traceroute_mapper.platform.system", return_value="Linux"), \
                patch("traceroute_mapper._run_unix_traceroute", return_value=[hop]), \
                patch("traceroute_mapper._resolve_hop_hostname", return_value="router.local") as mock_resolve:
            hops = tm.traceroute("8.8.8.8")

        assert hops[0]["hostname"] == "router.local"
        mock_resolve.assert_called_once_with("192.168.1.1", timeout=1.0)

    def test_skips_hostname_resolution_when_disabled(self):
        hop = {"hop": 1, "ip": "192.168.1.1", "hostname": "", "rtts_ms": [1.0, 1.0, 1.0]}
        with patch("traceroute_mapper.platform.system", return_value="Linux"), \
                patch("traceroute_mapper._run_unix_traceroute", return_value=[hop]), \
                patch("traceroute_mapper._resolve_hop_hostname") as mock_resolve:
            tm.traceroute("8.8.8.8", resolve_hostnames=False)

        mock_resolve.assert_not_called()

    def test_does_not_try_to_resolve_a_timed_out_hop(self):
        hop = {"hop": 2, "ip": None, "hostname": "", "rtts_ms": [None, None, None]}
        with patch("traceroute_mapper.platform.system", return_value="Linux"), \
                patch("traceroute_mapper._run_unix_traceroute", return_value=[hop]), \
                patch("traceroute_mapper._resolve_hop_hostname") as mock_resolve:
            tm.traceroute("8.8.8.8")

        mock_resolve.assert_not_called()


class TestResolveHopHostname:
    def test_returns_hostname_on_success(self):
        with patch("traceroute_mapper.socket.gethostbyaddr", return_value=("router.local", [], ["192.168.1.1"])):
            assert tm._resolve_hop_hostname("192.168.1.1", timeout=1.0) == "router.local"

    def test_returns_empty_string_on_failure(self):
        import socket
        with patch("traceroute_mapper.socket.gethostbyaddr", side_effect=socket.herror):
            assert tm._resolve_hop_hostname("192.168.1.1", timeout=1.0) == ""

    def test_restores_the_previous_default_timeout(self):
        import socket
        socket.setdefaulttimeout(42.0)
        try:
            with patch("traceroute_mapper.socket.gethostbyaddr", return_value=("x", [], [])):
                tm._resolve_hop_hostname("192.168.1.1", timeout=1.0)
            assert socket.getdefaulttimeout() == 42.0
        finally:
            socket.setdefaulttimeout(None)


class TestExportResults:
    def test_writes_json_by_default(self, tmp_path):
        path = tmp_path / "path.json"
        hops = [{"hop": 1, "ip": "192.168.1.1", "hostname": "router.local", "rtts_ms": [1.0, 1.1, 1.2]}]

        tm.export_results(hops, path)

        assert json.loads(path.read_text(encoding="utf-8")) == hops

    def test_writes_csv_when_extension_is_csv(self, tmp_path):
        path = tmp_path / "path.csv"
        hops = [{"hop": 1, "ip": "192.168.1.1", "hostname": "router.local", "rtts_ms": [1.0, 1.1, 1.2]}]

        tm.export_results(hops, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["ip"] == "192.168.1.1"
        assert rows[0]["rtt1_ms"] == "1.0"

    def test_csv_handles_a_timed_out_hop_gracefully(self, tmp_path):
        path = tmp_path / "path.csv"
        hops = [{"hop": 2, "ip": None, "hostname": "", "rtts_ms": [None, None, None]}]

        tm.export_results(hops, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows[0]["ip"] == ""


class TestUseColor:
    def test_disabled_by_flag(self):
        assert tm._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert tm._use_color(no_color_flag=False) is False


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        assert tm._colorize("hello", "yellow", True) == f"{tm._ANSI_CODES['yellow']}hello{tm._ANSI_CODES['reset']}"

    def test_returns_text_unchanged_when_disabled(self):
        assert tm._colorize("hello", "yellow", False) == "hello"
