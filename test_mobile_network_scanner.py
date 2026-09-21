import socket
from unittest.mock import MagicMock, patch

import pytest

import mobile_network_scanner as ms


class TestGetLocalSubnet:
    def test_derives_slash_24_from_local_ip(self):
        fake_sock = MagicMock()
        fake_sock.getsockname.return_value = ("10.0.0.7", 12345)
        fake_sock.__enter__.return_value = fake_sock

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.get_local_subnet() == "10.0.0.0/24"


class TestProbeHost:
    def test_returns_matched_port_when_one_accepts_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.side_effect = [1, 0]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.probe_host("192.168.1.1", [80, 443], timeout=0.1) == 443

    def test_returns_none_when_no_ports_accept_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 1

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.probe_host("192.168.1.1", [80, 443], timeout=0.1) is None

    def test_stops_probing_after_first_success(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 0

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ms.probe_host("192.168.1.1", [80, 443, 8080], timeout=0.1)

        assert fake_sock.connect_ex.call_count == 1


class TestTcpScan:
    def test_returns_only_live_hosts_sorted_by_ip(self):
        def fake_probe(ip, ports, timeout):
            return 80 if ip in ("192.168.1.2", "192.168.1.10") else None

        with patch("mobile_network_scanner.probe_host", side_effect=fake_probe), \
                patch("mobile_network_scanner.socket.gethostbyaddr", side_effect=socket.herror):
            devices = ms.tcp_scan("192.168.1.0/28", timeout=0.1, max_workers=8)

        ips = [d["ip"] for d in devices]
        assert ips == sorted(ips, key=lambda ip: tuple(int(p) for p in ip.split(".")))
        assert set(ips) == {"192.168.1.2", "192.168.1.10"}

    def test_attaches_hostname_and_matched_port_when_available(self):
        with patch("mobile_network_scanner.probe_host", return_value=8009), \
                patch("mobile_network_scanner.socket.gethostbyaddr", return_value=("phone.local", [], ["192.168.1.1"])):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert {"ip": "192.168.1.1", "hostname": "phone.local", "port": 8009} in devices

    def test_missing_hostname_defaults_to_empty_string(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.socket.gethostbyaddr", side_effect=socket.gaierror):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert all(d["hostname"] == "" for d in devices)

    def test_no_live_hosts_returns_empty_list(self):
        with patch("mobile_network_scanner.probe_host", return_value=None):
            assert ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4) == []

    def test_uses_default_ports_when_none_specified(self):
        captured_ports = []

        def fake_probe(ip, ports, timeout):
            captured_ports.append(ports)
            return None

        with patch("mobile_network_scanner.probe_host", side_effect=fake_probe):
            ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert all(ports == ms.DEFAULT_PORTS for ports in captured_ports)


class TestScanAllSubnets:
    def test_merges_devices_from_every_subnet(self):
        def fake_tcp_scan(subnet, timeout, ports, max_workers):
            return {
                "192.168.1.0/24": [{"ip": "192.168.1.5", "hostname": ""}],
                "10.0.0.0/24": [{"ip": "10.0.0.9", "hostname": "nas.local"}],
            }[subnet]

        with patch("mobile_network_scanner.tcp_scan", side_effect=fake_tcp_scan):
            devices = ms.scan_all_subnets(["192.168.1.0/24", "10.0.0.0/24"], timeout=0.1)

        assert [d["ip"] for d in devices] == ["10.0.0.9", "192.168.1.5"]

    def test_deduplicates_by_ip_across_overlapping_subnets(self):
        with patch("mobile_network_scanner.tcp_scan", return_value=[{"ip": "192.168.1.5", "hostname": ""}]):
            devices = ms.scan_all_subnets(["192.168.1.0/24", "192.168.1.0/24"], timeout=0.1)

        assert len(devices) == 1

    def test_empty_subnet_list_returns_empty(self):
        with patch("mobile_network_scanner.tcp_scan") as mock_tcp_scan:
            assert ms.scan_all_subnets([], timeout=0.1) == []
        mock_tcp_scan.assert_not_called()
