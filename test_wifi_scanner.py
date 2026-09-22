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


class TestSecurityRank:
    def test_ranks_wpa3_highest(self):
        assert ws._security_rank("WPA3-Personal") == 4

    def test_ranks_wpa2_below_wpa3(self):
        assert ws._security_rank("WPA2(PSK/AES/AES)") < ws._security_rank("WPA3")

    def test_ranks_plain_wpa_below_wpa2(self):
        assert ws._security_rank("WPA1 WPA2") == ws._security_rank("WPA2")  # substring match picks the strongest present
        assert ws._security_rank("WPA-Personal") < ws._security_rank("WPA2-Personal")

    def test_ranks_wep_above_open_but_below_wpa(self):
        assert ws._security_rank("WEP") == 1
        assert 0 < ws._security_rank("WEP") < ws._security_rank("WPA")

    def test_ranks_open_and_unrecognized_as_zero(self):
        assert ws._security_rank("Open") == 0
        assert ws._security_rank("") == 0
        assert ws._security_rank("--") == 0


class TestLoadSaveKnownNetworks:
    def test_returns_empty_dict_when_file_does_not_exist(self, tmp_path):
        assert ws._load_known_networks(tmp_path / "missing.json") == {}

    def test_returns_empty_dict_on_corrupt_json(self, tmp_path):
        path = tmp_path / "known.json"
        path.write_text("not json", encoding="utf-8")

        assert ws._load_known_networks(path) == {}

    def test_round_trips_through_save_and_load(self, tmp_path):
        path = tmp_path / "known.json"
        known = {"MyWiFi": {"bssids": ["aa:bb:cc:dd:ee:ff"], "best_security": "WPA2", "best_security_rank": 3}}

        ws._save_known_networks(known, path)

        assert ws._load_known_networks(path) == known

    def test_save_does_not_raise_when_write_fails(self, tmp_path, monkeypatch):
        path = tmp_path / "known.json"
        monkeypatch.setattr(ws.Path, "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("Permission denied")))

        ws._save_known_networks({"x": {}}, path)  # Should not raise.


class TestFindEvilTwinCandidates:
    def test_first_time_seeing_an_ssid_is_not_flagged(self):
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "WPA2"}]

        assert ws._find_evil_twin_candidates(networks, known={}) == []

    def test_a_known_ssid_from_a_known_bssid_with_the_same_security_is_not_flagged(self):
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "WPA2"}]
        known = {"MyWiFi": {"bssids": ["aa:bb:cc:dd:ee:ff"], "best_security": "WPA2", "best_security_rank": 3}}

        assert ws._find_evil_twin_candidates(networks, known) == []

    def test_flags_a_security_downgrade(self):
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "Open"}]
        known = {"MyWiFi": {"bssids": ["aa:bb:cc:dd:ee:ff"], "best_security": "WPA2", "best_security_rank": 3}}

        candidates = ws._find_evil_twin_candidates(networks, known)

        assert len(candidates) == 1
        assert candidates[0]["kind"] == "security_downgrade"
        assert candidates[0]["ssid"] == "MyWiFi"

    def test_flags_a_new_bssid_for_a_known_ssid_with_unchanged_security(self):
        networks = [{"ssid": "MyWiFi", "bssid": "11:22:33:44:55:66", "channel": 6, "signal": "78%", "security": "WPA2"}]
        known = {"MyWiFi": {"bssids": ["aa:bb:cc:dd:ee:ff"], "best_security": "WPA2", "best_security_rank": 3}}

        candidates = ws._find_evil_twin_candidates(networks, known)

        assert len(candidates) == 1
        assert candidates[0]["kind"] == "new_bssid"

    def test_a_new_bssid_with_stronger_security_is_reported_as_new_bssid_not_downgrade(self):
        networks = [{"ssid": "MyWiFi", "bssid": "11:22:33:44:55:66", "channel": 6, "signal": "78%", "security": "WPA3"}]
        known = {"MyWiFi": {"bssids": ["aa:bb:cc:dd:ee:ff"], "best_security": "WPA2", "best_security_rank": 3}}

        candidates = ws._find_evil_twin_candidates(networks, known)

        assert len(candidates) == 1
        assert candidates[0]["kind"] == "new_bssid"

    def test_an_unrelated_ssid_in_the_registry_is_untouched(self):
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "WPA2"}]
        known = {"OtherNetwork": {"bssids": ["11:22:33:44:55:66"], "best_security": "WPA2", "best_security_rank": 3}}

        assert ws._find_evil_twin_candidates(networks, known) == []


class TestUpdateKnownNetworks:
    def test_creates_an_entry_for_a_new_ssid(self):
        known = {}
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "WPA2"}]

        ws._update_known_networks(networks, known)

        assert known["MyWiFi"]["bssids"] == ["aa:bb:cc:dd:ee:ff"]
        assert known["MyWiFi"]["best_security"] == "WPA2"
        assert known["MyWiFi"]["best_security_rank"] == 3

    def test_appends_a_new_bssid_without_dropping_the_old_one(self):
        known = {"MyWiFi": {"bssids": ["aa:bb:cc:dd:ee:ff"], "best_security": "WPA2", "best_security_rank": 3}}
        networks = [{"ssid": "MyWiFi", "bssid": "11:22:33:44:55:66", "channel": 6, "signal": "78%", "security": "WPA2"}]

        ws._update_known_networks(networks, known)

        assert sorted(known["MyWiFi"]["bssids"]) == ["11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff"]

    def test_does_not_re_add_an_already_known_bssid(self):
        known = {"MyWiFi": {"bssids": ["aa:bb:cc:dd:ee:ff"], "best_security": "WPA2", "best_security_rank": 3}}
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "WPA2"}]

        ws._update_known_networks(networks, known)

        assert known["MyWiFi"]["bssids"] == ["aa:bb:cc:dd:ee:ff"]

    def test_raises_the_high_water_mark_on_stronger_security(self):
        known = {"MyWiFi": {"bssids": ["aa:bb:cc:dd:ee:ff"], "best_security": "WPA2", "best_security_rank": 3}}
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "WPA3"}]

        ws._update_known_networks(networks, known)

        assert known["MyWiFi"]["best_security_rank"] == 4
        assert known["MyWiFi"]["best_security"] == "WPA3"

    def test_never_lowers_the_high_water_mark_on_a_weaker_scan(self):
        known = {"MyWiFi": {"bssids": ["aa:bb:cc:dd:ee:ff"], "best_security": "WPA2", "best_security_rank": 3}}
        networks = [{"ssid": "MyWiFi", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 6, "signal": "78%", "security": "Open"}]

        ws._update_known_networks(networks, known)

        assert known["MyWiFi"]["best_security_rank"] == 3
        assert known["MyWiFi"]["best_security"] == "WPA2"
