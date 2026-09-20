import socket
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import network_scanner as ns


class TestGetLocalSubnet:
    def test_derives_slash_24_from_local_ip(self):
        fake_sock = MagicMock()
        fake_sock.getsockname.return_value = ("192.168.1.42", 12345)
        fake_sock.__enter__.return_value = fake_sock

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            assert ns.get_local_subnet() == "192.168.1.0/24"


class TestPing:
    @pytest.mark.parametrize("system,expected_count_flag", [("Linux", "-c"), ("Windows", "-n"), ("Darwin", "-c")])
    def test_uses_platform_specific_count_flag(self, system, expected_count_flag):
        with patch("network_scanner.platform.system", return_value=system), \
                patch("network_scanner.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            ns.ping("192.168.1.1", timeout=1.0)

        command = mock_run.call_args[0][0]
        assert command[0] == "ping"
        assert expected_count_flag in command
        assert "192.168.1.1" in command

    def test_returns_true_on_success(self):
        with patch("network_scanner.subprocess.run", return_value=MagicMock(returncode=0)):
            assert ns.ping("192.168.1.1", timeout=1.0) is True

    def test_returns_false_on_failure(self):
        with patch("network_scanner.subprocess.run", return_value=MagicMock(returncode=1)):
            assert ns.ping("192.168.1.1", timeout=1.0) is False


class TestReadArpTable:
    def test_parses_ip_and_mac_pairs(self):
        output = (
            "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
            "? (192.168.1.5) at 11:22:33:44:55:66 on en0 ifscope [ethernet]\n"
        )
        with patch("network_scanner.subprocess.run", return_value=MagicMock(stdout=output)):
            table = ns.read_arp_table()

        assert table == {
            "192.168.1.1": "aa:bb:cc:dd:ee:ff",
            "192.168.1.5": "11:22:33:44:55:66",
        }

    def test_normalizes_dash_separated_macs(self):
        output = "Interface: 192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic\n"
        with patch("network_scanner.subprocess.run", return_value=MagicMock(stdout=output)):
            table = ns.read_arp_table()

        assert table == {"192.168.1.1": "aa:bb:cc:dd:ee:ff"}

    def test_skips_lines_without_both_ip_and_mac(self):
        output = "192.168.1.1 has no mac listed\nincomplete\n"
        with patch("network_scanner.subprocess.run", return_value=MagicMock(stdout=output)):
            table = ns.read_arp_table()

        assert table == {}

    def test_returns_empty_dict_when_arp_command_missing(self):
        with patch("network_scanner.subprocess.run", side_effect=FileNotFoundError):
            assert ns.read_arp_table() == {}


class TestPingSweep:
    def test_returns_only_live_hosts_sorted_by_ip(self):
        def fake_ping(ip, timeout):
            return ip in ("192.168.1.2", "192.168.1.10")

        with patch("network_scanner.ping", side_effect=fake_ping), \
                patch("network_scanner.read_arp_table", return_value={"192.168.1.2": "aa:bb:cc:dd:ee:ff"}), \
                patch("network_scanner.socket.gethostbyaddr", side_effect=socket.herror):
            devices = ns.ping_sweep("192.168.1.0/28", timeout=0.1, max_workers=8)

        ips = [d["ip"] for d in devices]
        assert ips == sorted(ips, key=lambda ip: tuple(int(p) for p in ip.split(".")))
        assert all(ip in ("192.168.1.2", "192.168.1.10") for ip in ips)

    def test_attaches_mac_and_hostname_when_available(self):
        with patch("network_scanner.ping", return_value=True), \
                patch("network_scanner.read_arp_table", return_value={"192.168.1.1": "aa:bb:cc:dd:ee:ff"}), \
                patch("network_scanner.socket.gethostbyaddr", return_value=("router.local", [], ["192.168.1.1"])):
            devices = ns.ping_sweep("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local"} in devices

    def test_missing_mac_defaults_to_empty_string(self):
        with patch("network_scanner.ping", return_value=True), \
                patch("network_scanner.read_arp_table", return_value={}), \
                patch("network_scanner.socket.gethostbyaddr", side_effect=socket.gaierror):
            devices = ns.ping_sweep("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert all(d["mac"] == "" and d["hostname"] == "" for d in devices)

    def test_no_live_hosts_returns_empty_list(self):
        with patch("network_scanner.ping", return_value=False), \
                patch("network_scanner.read_arp_table", return_value={}):
            assert ns.ping_sweep("192.168.1.0/30", timeout=0.1, max_workers=4) == []


class TestScan:
    def test_prefers_arp_scan_when_it_succeeds(self):
        expected = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"}]
        with patch("network_scanner.arp_scan", return_value=expected) as mock_arp, \
                patch("network_scanner.ping_sweep") as mock_sweep:
            result = ns.scan("192.168.1.0/24", timeout=1.0)

        assert result == expected
        mock_arp.assert_called_once_with("192.168.1.0/24", 1.0)
        mock_sweep.assert_not_called()

    @pytest.mark.parametrize("error", [ImportError(), PermissionError(), OSError()])
    def test_falls_back_to_ping_sweep_on_expected_errors(self, error):
        expected = [{"ip": "192.168.1.1", "mac": "", "hostname": ""}]
        with patch("network_scanner.arp_scan", side_effect=error), \
                patch("network_scanner.ping_sweep", return_value=expected) as mock_sweep:
            result = ns.scan("192.168.1.0/24", timeout=1.0)

        assert result == expected
        mock_sweep.assert_called_once_with("192.168.1.0/24", 1.0)

    def test_does_not_swallow_unrelated_errors(self):
        with patch("network_scanner.arp_scan", side_effect=ValueError("boom")):
            with pytest.raises(ValueError):
                ns.scan("192.168.1.0/24", timeout=1.0)
