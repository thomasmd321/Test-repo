import csv
import json
from unittest.mock import patch

import pytest

import scan_diff as sd


class TestLoadDevices:
    def test_loads_json_by_default(self, tmp_path):
        path = tmp_path / "scan.json"
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local"}]
        path.write_text(json.dumps(devices), encoding="utf-8")

        assert sd.load_devices(path) == devices

    def test_loads_json_for_an_unrecognized_extension(self, tmp_path):
        path = tmp_path / "scan.txt"
        devices = [{"ip": "192.168.1.1"}]
        path.write_text(json.dumps(devices), encoding="utf-8")

        assert sd.load_devices(path) == devices

    def test_loads_csv_when_path_ends_in_dot_csv(self, tmp_path):
        path = tmp_path / "scan.csv"
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "port"])
            writer.writeheader()
            writer.writerow({"ip": "192.168.1.1", "port": "80"})

        devices = sd.load_devices(path)

        assert devices == [{"ip": "192.168.1.1", "port": "80"}]


class TestNormalizeDevice:
    def test_leaves_a_json_style_device_unchanged_in_shape(self):
        device = {"ip": "192.168.1.1", "port": 80, "risky_ports": [23, 445]}
        assert sd._normalize_device(device) == device

    def test_coerces_csv_style_string_port_to_int(self):
        assert sd._normalize_device({"ip": "192.168.1.1", "port": "80"})["port"] == 80

    def test_coerces_blank_csv_port_to_none(self):
        assert sd._normalize_device({"ip": "192.168.1.1", "port": ""})["port"] is None

    def test_coerces_csv_style_risky_ports_string_to_sorted_list(self):
        result = sd._normalize_device({"ip": "192.168.1.1", "risky_ports": "445;23"})
        assert result["risky_ports"] == [23, 445]

    def test_treats_blank_risky_ports_string_as_empty_list(self):
        assert sd._normalize_device({"ip": "192.168.1.1", "risky_ports": ""})["risky_ports"] == []

    def test_missing_risky_ports_defaults_to_empty_list(self):
        assert sd._normalize_device({"ip": "192.168.1.1"})["risky_ports"] == []


class TestDeviceIdentity:
    def test_uses_mac_when_present(self):
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"}
        assert sd._device_identity(device) == "aa:bb:cc:dd:ee:ff"

    def test_falls_back_to_ip_when_no_mac(self):
        assert sd._device_identity({"ip": "192.168.1.1"}) == "192.168.1.1"

    def test_falls_back_to_ip_when_mac_is_empty_string(self):
        assert sd._device_identity({"ip": "192.168.1.1", "mac": ""}) == "192.168.1.1"


class TestDiffDevices:
    def test_reports_a_device_present_only_in_new(self):
        old = []
        new = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "port": 80}]

        result = sd.diff_devices(old, new)

        assert result["added"] == [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "port": 80, "risky_ports": []}]
        assert result["removed"] == []
        assert result["changed"] == []

    def test_reports_a_device_present_only_in_old(self):
        old = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "port": 80}]
        new = []

        result = sd.diff_devices(old, new)

        assert result["removed"] == [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "port": 80, "risky_ports": []}]
        assert result["added"] == []
        assert result["changed"] == []

    def test_identical_devices_produce_no_diff(self):
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local", "port": 80}

        result = sd.diff_devices([device], [device])

        assert result == {"added": [], "removed": [], "changed": []}

    def test_reports_a_changed_port(self):
        old = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "port": 80}]
        new = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "port": 23}]

        result = sd.diff_devices(old, new)

        assert result["changed"] == [
            {"key": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.1", "changes": {"port": (80, 23)}}
        ]

    def test_reports_multiple_changed_fields_on_one_device(self):
        old = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "old.local", "port": 80}]
        new = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "new.local", "port": 23}]

        result = sd.diff_devices(old, new)

        assert result["changed"][0]["changes"] == {
            "hostname": ("old.local", "new.local"),
            "port": (80, 23),
        }

    def test_ignores_ip_itself_as_a_changed_field(self):
        # A device matched by MAC could have a different IP (DHCP lease
        # change) without that counting as a "field change" - it's shown
        # as this row's own label instead.
        old = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "port": 80}]
        new = [{"ip": "192.168.1.2", "mac": "aa:bb:cc:dd:ee:ff", "port": 80}]

        result = sd.diff_devices(old, new)

        assert result["changed"] == []

    def test_a_device_matched_by_ip_with_no_changes_is_not_reported(self):
        device = {"ip": "192.168.1.1", "hostname": "phone.local", "port": 80}
        result = sd.diff_devices([device], [device])
        assert result["changed"] == []

    def test_treats_csv_and_json_shaped_equivalents_as_unchanged(self):
        old = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "port": "80", "risky_ports": "23;445"}]
        new = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "port": 80, "risky_ports": [445, 23]}]

        result = sd.diff_devices(old, new)

        assert result["changed"] == []

    def test_results_are_sorted_by_ip(self):
        old = []
        new = [
            {"ip": "192.168.1.9", "mac": "cc:cc:cc:cc:cc:cc"},
            {"ip": "192.168.1.2", "mac": "aa:aa:aa:aa:aa:aa"},
        ]

        result = sd.diff_devices(old, new)

        assert [d["ip"] for d in result["added"]] == ["192.168.1.2", "192.168.1.9"]


class TestFormatValue:
    def test_formats_a_nonempty_list(self):
        assert sd._format_value([23, 445]) == "23,445"

    def test_formats_an_empty_list_as_none_placeholder(self):
        assert sd._format_value([]) == "(none)"

    def test_formats_none_as_placeholder(self):
        assert sd._format_value(None) == "(none)"

    def test_formats_empty_string_as_placeholder(self):
        assert sd._format_value("") == "(none)"

    def test_formats_a_plain_value_as_its_string_form(self):
        assert sd._format_value(80) == "80"


class TestDeviceLabel:
    def test_prefers_label_over_hostname(self):
        assert sd._device_label({"label": "Kitchen Echo", "hostname": "192-168-1-1.local"}) == "Kitchen Echo"

    def test_falls_back_to_hostname(self):
        assert sd._device_label({"hostname": "router.local"}) == "router.local"

    def test_returns_empty_string_when_neither_is_set(self):
        assert sd._device_label({}) == ""


class TestUseColor:
    def test_disabled_by_no_color_flag(self):
        with patch("scan_diff.sys.stdout.isatty", return_value=True), \
                patch.dict("scan_diff.os.environ", {}, clear=True):
            assert sd._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self):
        with patch("scan_diff.sys.stdout.isatty", return_value=True), \
                patch.dict("scan_diff.os.environ", {"NO_COLOR": "1"}):
            assert sd._use_color(no_color_flag=False) is False

    def test_disabled_when_stdout_is_not_a_tty(self):
        with patch("scan_diff.sys.stdout.isatty", return_value=False), \
                patch.dict("scan_diff.os.environ", {}, clear=True):
            assert sd._use_color(no_color_flag=False) is False

    def test_enabled_when_none_of_the_above_apply(self):
        with patch("scan_diff.sys.stdout.isatty", return_value=True), \
                patch.dict("scan_diff.os.environ", {}, clear=True):
            assert sd._use_color(no_color_flag=False) is True


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        result = sd._colorize("added", "green", enabled=True)
        assert result == f"{sd._ANSI_CODES['green']}added{sd._ANSI_CODES['reset']}"

    def test_returns_plain_text_when_disabled(self):
        assert sd._colorize("added", "green", enabled=False) == "added"


class TestPrintDiffReport:
    def test_prints_no_differences_message_when_nothing_changed(self, capsys):
        sd.print_diff_report({"added": [], "removed": [], "changed": []}, "old.json", "new.json", color=False)
        assert "No differences between old.json and new.json." in capsys.readouterr().out

    def test_prints_added_devices(self, capsys):
        result = {"added": [{"ip": "192.168.1.1", "hostname": "phone.local"}], "removed": [], "changed": []}
        sd.print_diff_report(result, "old.json", "new.json", color=False)

        out = capsys.readouterr().out
        assert "1 device(s) added:" in out
        assert "192.168.1.1" in out
        assert "phone.local" in out

    def test_prints_removed_devices(self, capsys):
        result = {"added": [], "removed": [{"ip": "192.168.1.1", "hostname": ""}], "changed": []}
        sd.print_diff_report(result, "old.json", "new.json", color=False)

        assert "1 device(s) removed:" in capsys.readouterr().out

    def test_prints_changed_fields(self, capsys):
        result = {
            "added": [], "removed": [],
            "changed": [{"key": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.1", "changes": {"port": (80, 23)}}],
        }
        sd.print_diff_report(result, "old.json", "new.json", color=False)

        out = capsys.readouterr().out
        assert "1 device(s) changed:" in out
        assert "port: 80 -> 23" in out
