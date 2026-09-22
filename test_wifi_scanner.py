import csv
import json
import subprocess
from unittest.mock import MagicMock, patch

import wifi_scanner as ws


class TestParseNmcliLine:
    def test_splits_plain_fields_on_colon(self):
        assert ws._parse_nmcli_line("MyWiFi:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:78:WPA2") == [
            "MyWiFi", "AA:BB:CC:DD:EE:FF", "6", "78", "WPA2",
        ]

    def test_unescapes_backslash_itself(self):
        assert ws._parse_nmcli_line("Weird\\\\Name:aa\\:bb\\:cc\\:dd\\:ee\\:ff:1:50:") == [
            "Weird\\Name", "aa:bb:cc:dd:ee:ff", "1", "50", "",
        ]

    def test_handles_empty_ssid_field(self):
        assert ws._parse_nmcli_line(":aa\\:bb\\:cc\\:dd\\:ee\\:ff:1:50:Open") == [
            "", "aa:bb:cc:dd:ee:ff", "1", "50", "Open",
        ]


class TestScanLinux:
    def _fake_run(self, stdout="", returncode=0):
        return MagicMock(stdout=stdout, stderr="", returncode=returncode)

    def test_parses_nmcli_output_into_networks(self):
        stdout = (
            "MyWiFi:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:78:WPA2\n"
            "Neighbor:11\\:22\\:33\\:44\\:55\\:66:11:40:WPA1 WPA2\n"
        )
        with patch("wifi_scanner.subprocess.run", return_value=self._fake_run(stdout)):
            networks = ws._scan_linux(timeout=5.0)

        assert networks == [
            {"ssid": "MyWiFi", "bssid": "AA:BB:CC:DD:EE:FF", "channel": 6, "signal": "78%", "security": "WPA2"},
            {"ssid": "Neighbor", "bssid": "11:22:33:44:55:66", "channel": 11, "signal": "40%", "security": "WPA1 WPA2"},
        ]

    def test_hidden_ssid_gets_a_placeholder(self):
        stdout = ":aa\\:bb\\:cc\\:dd\\:ee\\:ff:6:50:WPA2\n"
        with patch("wifi_scanner.subprocess.run", return_value=self._fake_run(stdout)):
            networks = ws._scan_linux(timeout=5.0)

        assert networks[0]["ssid"] == "(hidden)"

    def test_open_network_gets_labeled_open(self):
        stdout = "FreeWifi:aa\\:bb\\:cc\\:dd\\:ee\\:ff:6:50:\n"
        with patch("wifi_scanner.subprocess.run", return_value=self._fake_run(stdout)):
            networks = ws._scan_linux(timeout=5.0)

        assert networks[0]["security"] == "Open"

    def test_skips_blank_lines(self):
        stdout = "\nMyWiFi:aa\\:bb\\:cc\\:dd\\:ee\\:ff:6:50:WPA2\n\n"
        with patch("wifi_scanner.subprocess.run", return_value=self._fake_run(stdout)):
            networks = ws._scan_linux(timeout=5.0)

        assert len(networks) == 1

    def test_raises_clear_error_when_nmcli_missing(self):
        with patch("wifi_scanner.subprocess.run", side_effect=FileNotFoundError()):
            try:
                ws._scan_linux(timeout=5.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "nmcli" in str(exc)

    def test_raises_clear_error_on_timeout(self):
        with patch("wifi_scanner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="nmcli", timeout=5.0)):
            try:
                ws._scan_linux(timeout=5.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "5" in str(exc)

    def test_raises_clear_error_on_nonzero_exit(self):
        with patch("wifi_scanner.subprocess.run", return_value=self._fake_run("", returncode=1)):
            try:
                ws._scan_linux(timeout=5.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "nmcli failed" in str(exc)


class TestParseAirportLine:
    def test_parses_a_data_row_anchored_on_the_mac_address(self):
        line = "                    Office WiFi aa:bb:cc:dd:ee:ff -55  6       Y  US WPA2(PSK/AES/AES)"
        network = ws._parse_airport_line(line)

        assert network == {
            "ssid": "Office WiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6,
            "signal": "-55 dBm", "security": "WPA2(PSK/AES/AES)",
        }

    def test_ssid_with_spaces_is_reassembled_correctly(self):
        line = "My Home Network 5G aa:bb:cc:dd:ee:ff -60  36      Y  US WPA2(PSK/AES/AES)"
        network = ws._parse_airport_line(line)

        assert network["ssid"] == "My Home Network 5G"

    def test_open_network_has_no_security_tokens(self):
        line = "FreeWifi aa:bb:cc:dd:ee:ff -70  1       N  US"
        network = ws._parse_airport_line(line)

        assert network["security"] == "Open"

    def test_returns_none_for_header_row(self):
        line = "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY"
        assert ws._parse_airport_line(line) is None

    def test_returns_none_when_no_mac_shaped_token_present(self):
        assert ws._parse_airport_line("garbage line with no mac") is None


class TestScanMacos:
    def test_parses_airport_output_skipping_header(self):
        stdout = (
            "                            SSID BSSID             RSSI CHANNEL HT CC SECURITY\n"
            "                          MyWiFi aa:bb:cc:dd:ee:ff  -55  6       Y  US WPA2(PSK/AES/AES)\n"
        )
        with patch("wifi_scanner.subprocess.run", return_value=MagicMock(stdout=stdout, stderr="")):
            networks = ws._scan_macos(timeout=5.0)

        assert len(networks) == 1
        assert networks[0]["ssid"] == "MyWiFi"

    def test_raises_clear_error_when_airport_missing(self):
        with patch("wifi_scanner.subprocess.run", side_effect=FileNotFoundError()):
            try:
                ws._scan_macos(timeout=5.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "airport" in str(exc)

    def test_raises_clear_error_on_timeout(self):
        with patch("wifi_scanner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="airport", timeout=5.0)):
            try:
                ws._scan_macos(timeout=5.0)
                assert False, "expected RuntimeError"
            except RuntimeError:
                pass


class TestScanWindows:
    _SAMPLE_OUTPUT = """Interface name : Wi-Fi
There are 2 networks currently visible.

SSID 1 : MyWiFi
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 80%
         Radio type         : 802.11ac
         Channel            : 6
         Basic rates (Mbps) : 1 2 5.5 11
         Other rates (Mbps) : 6 9 12 18 24 36 48 54

SSID 2 : FreeWifi
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 45%
         Radio type         : 802.11n
         Channel            : 11
"""

    def test_parses_networks_and_their_bssid_details(self):
        with patch("wifi_scanner.subprocess.run", return_value=MagicMock(stdout=self._SAMPLE_OUTPUT, stderr="")):
            networks = ws._scan_windows(timeout=5.0)

        assert networks == [
            {"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "80%", "security": "WPA2-Personal"},
            {"ssid": "FreeWifi", "bssid": "11:22:33:44:55:66", "channel": 11, "signal": "45%", "security": "Open"},
        ]

    def test_multiple_bssids_under_one_ssid_each_become_their_own_network(self):
        stdout = """SSID 1 : MyWiFi
    Authentication          : WPA2-Personal
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 80%
         Channel            : 6
    BSSID 2                 : aa:bb:cc:dd:ee:ff
         Signal             : 30%
         Channel            : 6
"""
        with patch("wifi_scanner.subprocess.run", return_value=MagicMock(stdout=stdout, stderr="")):
            networks = ws._scan_windows(timeout=5.0)

        assert len(networks) == 2
        assert all(n["ssid"] == "MyWiFi" for n in networks)
        assert {n["signal"] for n in networks} == {"80%", "30%"}

    def test_raises_clear_error_when_netsh_missing(self):
        with patch("wifi_scanner.subprocess.run", side_effect=FileNotFoundError()):
            try:
                ws._scan_windows(timeout=5.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "netsh" in str(exc)


class TestScanWifiNetworksDispatch:
    def test_dispatches_to_linux_scanner(self):
        with patch("wifi_scanner.platform.system", return_value="Linux"), \
                patch("wifi_scanner._scan_linux", return_value=[]) as mock_scan:
            ws.scan_wifi_networks(timeout=3.0)
        mock_scan.assert_called_once_with(3.0)

    def test_dispatches_to_macos_scanner(self):
        with patch("wifi_scanner.platform.system", return_value="Darwin"), \
                patch("wifi_scanner._scan_macos", return_value=[]) as mock_scan:
            ws.scan_wifi_networks(timeout=3.0)
        mock_scan.assert_called_once_with(3.0)

    def test_dispatches_to_windows_scanner(self):
        with patch("wifi_scanner.platform.system", return_value="Windows"), \
                patch("wifi_scanner._scan_windows", return_value=[]) as mock_scan:
            ws.scan_wifi_networks(timeout=3.0)
        mock_scan.assert_called_once_with(3.0)

    def test_raises_on_unsupported_platform(self):
        with patch("wifi_scanner.platform.system", return_value="Plan9"):
            try:
                ws.scan_wifi_networks(timeout=3.0)
                assert False, "expected RuntimeError"
            except RuntimeError as exc:
                assert "Plan9" in str(exc)


class TestExportResults:
    def test_writes_json_by_default(self, tmp_path):
        path = tmp_path / "networks.json"
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "WPA2"}]

        ws.export_results(networks, path)

        assert json.loads(path.read_text(encoding="utf-8")) == networks

    def test_writes_csv_when_extension_is_csv(self, tmp_path):
        path = tmp_path / "networks.csv"
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "WPA2"}]

        ws.export_results(networks, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows == [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": "6", "signal": "78%", "security": "WPA2"}]


class TestUseColor:
    def test_disabled_by_flag(self):
        assert ws._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert ws._use_color(no_color_flag=False) is False

    def test_disabled_when_not_a_tty(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        with patch("wifi_scanner.sys.stdout.isatty", return_value=False):
            assert ws._use_color(no_color_flag=False) is False


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        assert ws._colorize("hello", "yellow", True) == f"{ws._ANSI_CODES['yellow']}hello{ws._ANSI_CODES['reset']}"

    def test_returns_text_unchanged_when_disabled(self):
        assert ws._colorize("hello", "yellow", False) == "hello"
