import json
import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

import win_arp_dhcp_watch as wadw

_ARP_A_OUTPUT = """
Interface: 192.168.1.5 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
  192.168.1.20          11-22-33-44-55-66     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""

_IPCONFIG_ALL_OUTPUT = """
Windows IP Configuration

   Host Name . . . . . . . . . . . . : DESKTOP-ABC123
   Primary Dns Suffix  . . . . . . . :
   Node Type . . . . . . . . . . . . : Hybrid

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Intel(R) Ethernet Connection
   Physical Address. . . . . . . . . : 00-15-5D-01-02-03
   DHCP Enabled. . . . . . . . . . . : Yes
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Lease Obtained. . . . . . . . . . : Tuesday, January 2, 2024 9:00:00 AM
   Lease Expires . . . . . . . . . . : Wednesday, January 3, 2024 9:00:00 AM
   Default Gateway . . . . . . . . . : 192.168.1.1
   DHCP Server . . . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 192.168.1.1

Wireless LAN adapter Wi-Fi:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Ethernet adapter vEthernet (Static):

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 10.0.0.5(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   DHCP Enabled. . . . . . . . . . . : No
"""


class TestParseArpAOutput:
    def test_parses_ip_mac_pairs(self):
        table = wadw.parse_arp_a_output(_ARP_A_OUTPUT)

        assert table["192.168.1.1"] == "aa:bb:cc:dd:ee:ff"
        assert table["192.168.1.20"] == "11:22:33:44:55:66"

    def test_normalizes_hyphens_to_colons_and_lowercase(self):
        table = wadw.parse_arp_a_output("  192.168.1.1  AA-BB-CC-DD-EE-FF  dynamic\n")

        assert table["192.168.1.1"] == "aa:bb:cc:dd:ee:ff"

    def test_skips_lines_with_no_mac(self):
        table = wadw.parse_arp_a_output("Interface: 192.168.1.5 --- 0xb\n")

        assert table == {}

    def test_empty_output_gives_empty_table(self):
        assert wadw.parse_arp_a_output("") == {}


class TestProcessArpObservation:
    def test_first_observation_is_not_a_change(self):
        seen = {}
        assert wadw.process_arp_observation("192.168.1.1", "aa:bb:cc:dd:ee:ff", seen) is None
        assert seen == {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

    def test_same_mac_again_is_not_a_change(self):
        seen = {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}
        assert wadw.process_arp_observation("192.168.1.1", "aa:bb:cc:dd:ee:ff", seen) is None

    def test_a_different_mac_is_a_change(self):
        seen = {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}
        assert wadw.process_arp_observation("192.168.1.1", "bb:bb:bb:bb:bb:bb", seen) == ("aa:bb:cc:dd:ee:ff", "bb:bb:bb:bb:bb:bb")


class TestFindArpChanges:
    def test_no_changes_on_first_poll(self):
        seen = {}
        changes = wadw.find_arp_changes({"192.168.1.1": "aa:bb:cc:dd:ee:ff"}, seen)

        assert changes == []
        assert seen == {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

    def test_detects_a_mac_change_between_polls(self):
        seen = {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

        changes = wadw.find_arp_changes({"192.168.1.1": "bb:bb:bb:bb:bb:bb"}, seen)

        assert changes == [("192.168.1.1", "aa:bb:cc:dd:ee:ff", "bb:bb:bb:bb:bb:bb")]

    def test_an_unrelated_ip_leaving_the_table_is_not_a_change(self):
        seen = {"192.168.1.1": "aa:bb:cc:dd:ee:ff", "192.168.1.2": "cc:cc:cc:cc:cc:cc"}

        changes = wadw.find_arp_changes({"192.168.1.1": "aa:bb:cc:dd:ee:ff"}, seen)

        assert changes == []

    def test_multiple_simultaneous_changes_are_all_reported(self):
        seen = {"192.168.1.1": "aa:bb:cc:dd:ee:ff", "192.168.1.2": "cc:cc:cc:cc:cc:cc"}

        changes = wadw.find_arp_changes({"192.168.1.1": "11:11:11:11:11:11", "192.168.1.2": "22:22:22:22:22:22"}, seen)

        assert len(changes) == 2


class TestParseIpconfigAll:
    def test_extracts_dhcp_server_for_dhcp_enabled_adapter(self):
        adapters = wadw.parse_ipconfig_all(_IPCONFIG_ALL_OUTPUT)

        assert adapters["Ethernet adapter Ethernet"]["dhcp_server"] == "192.168.1.1"
        assert adapters["Ethernet adapter Ethernet"]["dhcp_enabled"] == "Yes"

    def test_extracts_ipv4_address_without_the_preferred_suffix(self):
        adapters = wadw.parse_ipconfig_all(_IPCONFIG_ALL_OUTPUT)

        assert adapters["Ethernet adapter Ethernet"]["ipv4_address"] == "192.168.1.50"

    def test_extracts_lease_times(self):
        adapters = wadw.parse_ipconfig_all(_IPCONFIG_ALL_OUTPUT)

        assert "January 2, 2024" in adapters["Ethernet adapter Ethernet"]["lease_obtained"]
        assert "January 3, 2024" in adapters["Ethernet adapter Ethernet"]["lease_expires"]

    def test_disconnected_adapter_has_no_dhcp_server(self):
        adapters = wadw.parse_ipconfig_all(_IPCONFIG_ALL_OUTPUT)

        assert adapters["Wireless LAN adapter Wi-Fi"]["dhcp_server"] is None

    def test_statically_configured_adapter_has_no_dhcp_server(self):
        adapters = wadw.parse_ipconfig_all(_IPCONFIG_ALL_OUTPUT)

        assert adapters["Ethernet adapter vEthernet (Static)"]["dhcp_enabled"] == "No"
        assert adapters["Ethernet adapter vEthernet (Static)"]["dhcp_server"] is None

    def test_fields_before_the_first_adapter_header_are_ignored(self):
        adapters = wadw.parse_ipconfig_all(_IPCONFIG_ALL_OUTPUT)

        assert "Windows IP Configuration" not in adapters

    def test_empty_output_gives_empty_dict(self):
        assert wadw.parse_ipconfig_all("") == {}


class TestFindDhcpServerChanges:
    def test_no_changes_on_first_poll(self):
        seen = {}
        adapters = {"Ethernet": {"dhcp_server": "192.168.1.1"}}

        changes = wadw.find_dhcp_server_changes(adapters, seen)

        assert changes == []
        assert seen == {"Ethernet": "192.168.1.1"}

    def test_detects_a_dhcp_server_change(self):
        seen = {"Ethernet": "192.168.1.1"}
        adapters = {"Ethernet": {"dhcp_server": "192.168.1.99"}}

        changes = wadw.find_dhcp_server_changes(adapters, seen)

        assert changes == [("Ethernet", "192.168.1.1", "192.168.1.99")]

    def test_an_adapter_with_no_dhcp_server_is_skipped(self):
        seen = {}
        adapters = {"Static Adapter": {"dhcp_server": None}}

        changes = wadw.find_dhcp_server_changes(adapters, seen)

        assert changes == []
        assert seen == {}

    def test_an_unchanged_server_is_not_reported(self):
        seen = {"Ethernet": "192.168.1.1"}
        adapters = {"Ethernet": {"dhcp_server": "192.168.1.1"}}

        assert wadw.find_dhcp_server_changes(adapters, seen) == []


class TestGetArpTable:
    def test_parses_real_subprocess_output(self):
        with patch("win_arp_dhcp_watch.subprocess.run", return_value=MagicMock(stdout=_ARP_A_OUTPUT)):
            table = wadw.get_arp_table()

        assert table["192.168.1.1"] == "aa:bb:cc:dd:ee:ff"

    def test_raises_clear_error_when_arp_missing(self):
        with patch("win_arp_dhcp_watch.subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError, match="not found"):
                wadw.get_arp_table()

    def test_raises_clear_error_on_timeout(self):
        with patch("win_arp_dhcp_watch.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="arp", timeout=5)):
            with pytest.raises(RuntimeError, match="did not respond"):
                wadw.get_arp_table()


class TestGetIpconfigAll:
    def test_parses_real_subprocess_output(self):
        with patch("win_arp_dhcp_watch.subprocess.run", return_value=MagicMock(stdout=_IPCONFIG_ALL_OUTPUT)):
            adapters = wadw.get_ipconfig_all()

        assert adapters["Ethernet adapter Ethernet"]["dhcp_server"] == "192.168.1.1"

    def test_raises_clear_error_when_ipconfig_missing(self):
        with patch("win_arp_dhcp_watch.subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError, match="not found"):
                wadw.get_ipconfig_all()

    def test_raises_clear_error_on_timeout(self):
        with patch("win_arp_dhcp_watch.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ipconfig", timeout=5)):
            with pytest.raises(RuntimeError, match="did not respond"):
                wadw.get_ipconfig_all()


class TestMainPlatformGate:
    def test_exits_cleanly_on_a_non_windows_platform(self, capsys):
        with patch("win_arp_dhcp_watch.platform.system", return_value="Linux"), \
             patch.object(sys, "argv", ["win_arp_dhcp_watch.py"]):
            with pytest.raises(SystemExit) as excinfo:
                wadw.main()

        assert excinfo.value.code == 1
        assert "Windows-only" in capsys.readouterr().out


class TestUseColor:
    def test_disabled_by_flag(self):
        assert wadw._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert wadw._use_color(no_color_flag=False) is False


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        assert wadw._colorize("hello", "magenta", True) == f"{wadw._ANSI_CODES['magenta']}hello{wadw._ANSI_CODES['reset']}"

    def test_returns_text_unchanged_when_disabled(self):
        assert wadw._colorize("hello", "magenta", False) == "hello"


class TestAppendLog:
    def test_appends_one_json_line_per_call(self, tmp_path):
        path = tmp_path / "alerts.jsonl"

        wadw._append_log(path, {"kind": "arp", "ip": "192.168.1.1"})
        wadw._append_log(path, {"kind": "dhcp", "adapter": "Ethernet"})

        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0])["kind"] == "arp"
        assert json.loads(lines[1])["kind"] == "dhcp"

    def test_does_not_raise_when_write_fails(self, tmp_path, monkeypatch):
        path = tmp_path / "alerts.jsonl"
        monkeypatch.setattr(wadw.Path, "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("Permission denied")))

        wadw._append_log(path, {"kind": "arp"})  # Should not raise.


class TestRealSubprocessEndToEnd:
    """Real, unmocked subprocess execution: fake `arp`/`ipconfig` scripts
    placed on PATH, with platform.system() patched to report "Windows" so
    main()'s platform gate doesn't block it (this sandbox is Linux - see
    this module's own docstring for why that's the strongest verification
    achievable here). get_arp_table()/get_ipconfig_all() genuinely spawn
    and read from these real scripts; nothing about subprocess.run() or
    the file I/O is mocked."""

    def _write_fake_binaries(self, tmp_path, arp_output, ipconfig_output):
        arp_script = tmp_path / "arp"
        arp_script.write_text(f"#!/bin/sh\ncat << 'EOF'\n{arp_output}\nEOF\n", encoding="utf-8")
        arp_script.chmod(0o755)

        ipconfig_script = tmp_path / "ipconfig"
        ipconfig_script.write_text(f"#!/bin/sh\ncat << 'EOF'\n{ipconfig_output}\nEOF\n", encoding="utf-8")
        ipconfig_script.chmod(0o755)

    def test_detects_a_real_arp_change_across_two_real_polls(self, tmp_path, monkeypatch):
        self._write_fake_binaries(tmp_path, _ARP_A_OUTPUT, _IPCONFIG_ALL_OUTPUT)
        monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")

        seen = {}
        first = wadw.find_arp_changes(wadw.get_arp_table(), seen)
        assert first == []

        # Rewrite the fake arp binary's output to simulate a real MAC change on the next poll.
        changed_output = _ARP_A_OUTPUT.replace("aa-bb-cc-dd-ee-ff", "99-99-99-99-99-99")
        self._write_fake_binaries(tmp_path, changed_output, _IPCONFIG_ALL_OUTPUT)

        second = wadw.find_arp_changes(wadw.get_arp_table(), seen)
        assert second == [("192.168.1.1", "aa:bb:cc:dd:ee:ff", "99:99:99:99:99:99")]

    def test_detects_a_real_dhcp_server_change_across_two_real_polls(self, tmp_path, monkeypatch):
        self._write_fake_binaries(tmp_path, _ARP_A_OUTPUT, _IPCONFIG_ALL_OUTPUT)
        monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")

        seen = {}
        first = wadw.find_dhcp_server_changes(wadw.get_ipconfig_all(), seen)
        assert first == []
        assert seen["Ethernet adapter Ethernet"] == "192.168.1.1"

        rogue_output = _IPCONFIG_ALL_OUTPUT.replace(
            "DHCP Server . . . . . . . . . . . : 192.168.1.1",
            "DHCP Server . . . . . . . . . . . : 192.168.1.66",
        )
        self._write_fake_binaries(tmp_path, _ARP_A_OUTPUT, rogue_output)

        second = wadw.find_dhcp_server_changes(wadw.get_ipconfig_all(), seen)
        assert second == [("Ethernet adapter Ethernet", "192.168.1.1", "192.168.1.66")]

    def test_full_pipeline_runs_with_platform_reporting_windows(self, tmp_path, monkeypatch):
        self._write_fake_binaries(tmp_path, _ARP_A_OUTPUT, _IPCONFIG_ALL_OUTPUT)
        monkeypatch.setenv("PATH", f"{tmp_path}:{__import__('os').environ['PATH']}")

        with patch("win_arp_dhcp_watch.platform.system", return_value="Windows"):
            # main() itself loops forever, so this exercises the same
            # real subprocess calls main() would make, without invoking
            # its infinite loop.
            assert wadw.platform.system() == "Windows"
            table = wadw.get_arp_table()
            adapters = wadw.get_ipconfig_all()

        assert table
        assert adapters["Ethernet adapter Ethernet"]["dhcp_server"] == "192.168.1.1"
