import csv
import json
import socket
import struct
import subprocess
import sys
import types
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

import network_scanner as ns


def _fake_addr(family, address, netmask):
    """Build a stand-in for the namedtuple psutil.net_if_addrs() entries."""
    return types.SimpleNamespace(family=family, address=address, netmask=netmask)


class TestGetLocalSubnet:
    def test_derives_slash_24_from_local_ip(self):
        fake_sock = MagicMock()
        fake_sock.getsockname.return_value = ("192.168.1.42", 12345)
        fake_sock.__enter__.return_value = fake_sock

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            assert ns.get_local_subnet() == "192.168.1.0/24"


class TestGetLocalSubnets:
    def test_falls_back_to_get_local_subnet_when_psutil_missing(self):
        with patch.dict(sys.modules, {"psutil": None}), \
                patch("network_scanner.get_local_subnet", return_value="192.168.1.0/24"):
            assert ns.get_local_subnets() == ["192.168.1.0/24"]

    def test_collects_subnets_from_every_interface(self):
        fake_psutil = MagicMock()
        fake_psutil.net_if_addrs.return_value = {
            "en0": [_fake_addr(socket.AF_INET, "192.168.1.42", "255.255.255.0")],
            "utun0": [_fake_addr(socket.AF_INET, "10.8.0.5", "255.255.255.0")],
        }

        with patch.dict(sys.modules, {"psutil": fake_psutil}):
            assert ns.get_local_subnets() == ["10.8.0.0/24", "192.168.1.0/24"]

    def test_excludes_loopback_and_link_local(self):
        fake_psutil = MagicMock()
        fake_psutil.net_if_addrs.return_value = {
            "lo0": [_fake_addr(socket.AF_INET, "127.0.0.1", "255.0.0.0")],
            "en0": [
                _fake_addr(socket.AF_INET, "169.254.1.2", "255.255.0.0"),
                _fake_addr(socket.AF_INET, "192.168.1.42", "255.255.255.0"),
            ],
        }

        with patch.dict(sys.modules, {"psutil": fake_psutil}):
            assert ns.get_local_subnets() == ["192.168.1.0/24"]

    def test_ignores_non_ipv4_and_missing_netmask_entries(self):
        fake_psutil = MagicMock()
        fake_psutil.net_if_addrs.return_value = {
            "en0": [
                _fake_addr(socket.AF_INET6, "fe80::1", "ffff:ffff:ffff:ffff::"),
                _fake_addr(socket.AF_INET, "192.168.1.42", None),
                _fake_addr(socket.AF_INET, "10.0.0.5", "255.255.255.0"),
            ],
        }

        with patch.dict(sys.modules, {"psutil": fake_psutil}):
            assert ns.get_local_subnets() == ["10.0.0.0/24"]

    def test_deduplicates_shared_subnets(self):
        fake_psutil = MagicMock()
        fake_psutil.net_if_addrs.return_value = {
            "en0": [_fake_addr(socket.AF_INET, "192.168.1.42", "255.255.255.0")],
            "en1": [_fake_addr(socket.AF_INET, "192.168.1.99", "255.255.255.0")],
        }

        with patch.dict(sys.modules, {"psutil": fake_psutil}):
            assert ns.get_local_subnets() == ["192.168.1.0/24"]


class TestScanAllSubnets:
    """_resolve_missing_hostnames/_attach_vendor_names are mocked as identity
    pass-throughs in most of these tests so they exercise only the merge/
    dedup logic; see the dedicated tests below for the enrichment wiring
    itself."""

    def _patch_enrichment(self):
        return (
            patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices),
            patch("network_scanner._attach_vendor_names", side_effect=lambda devices, force_refresh=False: devices),
        )

    def test_merges_devices_from_every_subnet(self):
        def fake_scan(subnet, timeout):
            return {
                "192.168.1.0/24": [{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": ""}],
                "10.0.0.0/24": [{"ip": "10.0.0.9", "mac": "", "hostname": "nas.local"}],
            }[subnet]

        patch_hostnames, patch_vendors = self._patch_enrichment()
        with patch("network_scanner.scan", side_effect=fake_scan), patch_hostnames, patch_vendors:
            devices = ns.scan_all_subnets(["192.168.1.0/24", "10.0.0.0/24"], timeout=1.0, scan_ports=False)

        assert [d["ip"] for d in devices] == ["10.0.0.9", "192.168.1.5"]

    def test_deduplicates_by_ip_across_overlapping_subnets(self):
        patch_hostnames, patch_vendors = self._patch_enrichment()
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "", "hostname": ""}]), \
                patch_hostnames, patch_vendors:
            devices = ns.scan_all_subnets(["192.168.1.0/24", "192.168.1.0/24"], timeout=1.0, scan_ports=False)

        assert len(devices) == 1

    def test_empty_subnet_list_returns_empty(self):
        with patch("network_scanner.scan") as mock_scan:
            assert ns.scan_all_subnets([], timeout=1.0) == []
        mock_scan.assert_not_called()

    def test_resolves_hostnames_once_per_subnet_before_merging(self):
        devices_by_subnet = {
            "192.168.1.0/24": [{"ip": "192.168.1.5", "mac": "", "hostname": ""}],
            "10.0.0.0/24": [{"ip": "10.0.0.9", "mac": "", "hostname": ""}],
        }

        def fake_scan(subnet, timeout):
            return devices_by_subnet[subnet]

        def fake_resolve(devices, mdns_timeout):
            for device in devices:
                device["hostname"] = f"resolved-{device['ip']}"
            return devices

        with patch("network_scanner.scan", side_effect=fake_scan), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=fake_resolve) as mock_resolve, \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices, force_refresh=False: devices):
            devices = ns.scan_all_subnets(["192.168.1.0/24", "10.0.0.0/24"], timeout=1.0, mdns_timeout=0.4, scan_ports=False)

        assert mock_resolve.call_count == 2
        assert all(call.args[1] == 0.4 for call in mock_resolve.call_args_list)
        assert {d["hostname"] for d in devices} == {"resolved-192.168.1.5", "resolved-10.0.0.9"}

    def test_attaches_vendors_once_over_final_merged_list(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "x"}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices, force_refresh=False: devices) as mock_vendor:
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0, scan_ports=False)

        mock_vendor.assert_called_once()

    def test_passes_refresh_vendor_db_through_to_attach_vendor_names(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "x"}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices, force_refresh=False: devices) as mock_vendor:
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0, refresh_vendor_db=True, scan_ports=False)

        assert mock_vendor.call_args.kwargs.get("force_refresh") is True

    def test_skips_vendor_lookup_when_disabled(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "x"}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names") as mock_vendor:
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0, vendor_lookup=False, scan_ports=False)

        mock_vendor.assert_not_called()

    def test_attaches_open_ports_and_risky_ports_over_final_list_by_default(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "", "hostname": "x", "vendor": ""}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices, force_refresh=False: devices), \
                patch("network_scanner._attach_open_ports", side_effect=lambda devices, ports, timeout: devices) as mock_ports, \
                patch("network_scanner._attach_risky_ports", side_effect=lambda devices, timeout: devices) as mock_risky:
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0)

        mock_ports.assert_called_once()
        mock_risky.assert_called_once()

    def test_uses_default_ports_when_none_specified(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "", "hostname": "x", "vendor": ""}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices, force_refresh=False: devices), \
                patch("network_scanner._attach_open_ports", side_effect=lambda devices, ports, timeout: devices) as mock_ports, \
                patch("network_scanner._attach_risky_ports", side_effect=lambda devices, timeout: devices):
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0)

        assert mock_ports.call_args.args[1] == ns.DEFAULT_PORTS

    def test_passes_custom_ports_through(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "", "hostname": "x", "vendor": ""}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices, force_refresh=False: devices), \
                patch("network_scanner._attach_open_ports", side_effect=lambda devices, ports, timeout: devices) as mock_ports, \
                patch("network_scanner._attach_risky_ports", side_effect=lambda devices, timeout: devices):
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0, ports=[22, 80])

        assert mock_ports.call_args.args[1] == [22, 80]

    def test_skips_port_scanning_when_disabled(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "", "hostname": "x", "vendor": ""}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices, force_refresh=False: devices), \
                patch("network_scanner._attach_open_ports") as mock_ports, \
                patch("network_scanner._attach_risky_ports") as mock_risky:
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0, scan_ports=False)

        mock_ports.assert_not_called()
        mock_risky.assert_not_called()

    def test_skips_risky_port_check_when_disabled_but_keeps_open_port_probe(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "", "hostname": "x", "vendor": ""}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices, force_refresh=False: devices), \
                patch("network_scanner._attach_open_ports", side_effect=lambda devices, ports, timeout: devices) as mock_ports, \
                patch("network_scanner._attach_risky_ports") as mock_risky:
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0, check_risky_ports=False)

        mock_ports.assert_called_once()
        mock_risky.assert_not_called()

    def test_skips_port_scanning_when_no_devices_found(self):
        with patch("network_scanner.scan", return_value=[]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_open_ports") as mock_ports, \
                patch("network_scanner._attach_risky_ports") as mock_risky:
            assert ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0) == []

        mock_ports.assert_not_called()
        mock_risky.assert_not_called()


class TestProbeOpenPort:
    def test_returns_first_open_port(self):
        def fake_probe(ip, port, timeout):
            return port == 443

        with patch("network_scanner._probe_tcp_port", side_effect=fake_probe):
            assert ns.probe_open_port("192.168.1.1", [80, 443, 22], timeout=0.1) == 443

    def test_returns_none_when_nothing_open(self):
        with patch("network_scanner._probe_tcp_port", return_value=False):
            assert ns.probe_open_port("192.168.1.1", [80, 443], timeout=0.1) is None

    def test_stops_at_first_success(self):
        with patch("network_scanner._probe_tcp_port", return_value=True) as mock_probe:
            ns.probe_open_port("192.168.1.1", [80, 443, 22], timeout=0.1)

        mock_probe.assert_called_once()


class TestAttachOpenPorts:
    def test_fills_in_port_for_each_device(self):
        devices = [
            {"ip": "192.168.1.1", "mac": "", "hostname": "", "vendor": ""},
            {"ip": "192.168.1.2", "mac": "", "hostname": "", "vendor": ""},
        ]

        def fake_probe(ip, ports, timeout):
            return {"192.168.1.1": 80, "192.168.1.2": None}[ip]

        with patch("network_scanner.probe_open_port", side_effect=fake_probe):
            result = ns._attach_open_ports(devices, ns.DEFAULT_PORTS, timeout=0.1)

        by_ip = {d["ip"]: d["port"] for d in result}
        assert by_ip == {"192.168.1.1": 80, "192.168.1.2": None}


class TestFindRiskyPorts:
    def test_reports_all_open_risky_ports_not_just_the_first(self):
        def fake_probe(ip, port, timeout):
            return port in (23, 3389)

        with patch("network_scanner._probe_tcp_port", side_effect=fake_probe):
            assert ns._find_risky_ports("192.168.1.1", timeout=0.1) == [23, 3389]

    def test_returns_empty_list_when_none_open(self):
        with patch("network_scanner._probe_tcp_port", return_value=False):
            assert ns._find_risky_ports("192.168.1.1", timeout=0.1) == []


class TestAttachRiskyPorts:
    def test_fills_in_risky_ports_for_each_device(self):
        devices = [{"ip": "192.168.1.1", "mac": "", "hostname": "", "vendor": ""}]

        with patch("network_scanner._find_risky_ports", return_value=[23]):
            result = ns._attach_risky_ports(devices, timeout=0.1)

        assert result[0]["risky_ports"] == [23]


class TestUseColor:
    def test_disabled_by_no_color_flag(self):
        with patch("network_scanner.sys.stdout.isatty", return_value=True), \
                patch.dict("network_scanner.os.environ", {}, clear=True):
            assert ns._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self):
        with patch("network_scanner.sys.stdout.isatty", return_value=True), \
                patch.dict("network_scanner.os.environ", {"NO_COLOR": "1"}):
            assert ns._use_color(no_color_flag=False) is False

    def test_disabled_when_stdout_is_not_a_tty(self):
        with patch("network_scanner.sys.stdout.isatty", return_value=False), \
                patch.dict("network_scanner.os.environ", {}, clear=True):
            assert ns._use_color(no_color_flag=False) is False

    def test_enabled_when_none_of_the_above_apply(self):
        with patch("network_scanner.sys.stdout.isatty", return_value=True), \
                patch.dict("network_scanner.os.environ", {}, clear=True):
            assert ns._use_color(no_color_flag=False) is True


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        result = ns._colorize("NEW", "green", enabled=True)
        assert result == f"{ns._ANSI_CODES['green']}NEW{ns._ANSI_CODES['reset']}"

    def test_returns_plain_text_when_disabled(self):
        assert ns._colorize("NEW", "green", enabled=False) == "NEW"


class TestExportResults:
    def test_writes_json_by_default(self, tmp_path):
        path = tmp_path / "scan.json"
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local", "vendor": "Netgear"}]

        ns.export_results(devices, path)

        assert json.loads(path.read_text(encoding="utf-8")) == devices

    def test_writes_json_for_an_unrecognized_extension(self, tmp_path):
        path = tmp_path / "scan.txt"
        devices = [{"ip": "192.168.1.1"}]

        ns.export_results(devices, path)

        assert json.loads(path.read_text(encoding="utf-8")) == devices

    def test_writes_csv_when_path_ends_in_dot_csv(self, tmp_path):
        path = tmp_path / "scan.csv"
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local",
             "vendor": "Netgear", "port": 80, "risky_ports": [23, 445]},
        ]

        ns.export_results(devices, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert rows == [{
            "ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local",
            "vendor": "Netgear", "port": "80", "risky_ports": "23;445",
        }]

    def test_csv_uses_empty_string_for_missing_fields(self, tmp_path):
        # Device is total=False - "port"/"risky_ports" may be entirely
        # absent (port scanning skipped or not yet run), not just None.
        path = tmp_path / "scan.csv"
        devices = [{"ip": "192.168.1.1", "mac": "", "hostname": "", "vendor": ""}]

        ns.export_results(devices, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert rows[0]["port"] == ""
        assert rows[0]["risky_ports"] == ""

    def test_csv_column_order_matches_fieldnames(self, tmp_path):
        path = tmp_path / "scan.csv"
        devices = [{"ip": "192.168.1.1", "mac": "", "hostname": "", "vendor": "", "port": None, "risky_ports": []}]

        ns.export_results(devices, path)

        header = path.read_text(encoding="utf-8").splitlines()[0]
        assert header == "ip,mac,hostname,vendor,port,risky_ports"


class TestBuildNotificationMessage:
    def test_returns_empty_string_when_nothing_to_report(self):
        message = ns._build_notification_message([], {}, {}, [], [])
        assert message == ""

    def test_includes_new_devices(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "phone.local"}]
        is_new = {"aa:bb:cc:dd:ee:ff": True}

        message = ns._build_notification_message(devices, is_new, {}, [], [])

        assert "1 new device(s):" in message
        assert "192.168.1.1  phone.local" in message

    def test_new_device_with_no_hostname_shows_placeholder(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": ""}]
        is_new = {"aa:bb:cc:dd:ee:ff": True}

        message = ns._build_notification_message(devices, is_new, {}, [], [])

        assert "(no hostname)" in message

    def test_includes_port_changes(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": ""}]
        port_changes = {"aa:bb:cc:dd:ee:ff": (80, 23)}

        message = ns._build_notification_message(devices, {}, port_changes, [], [])

        assert "1 device(s) with a changed port:" in message
        assert "http (80) -> telnet (23)" in message

    def test_includes_missing_devices(self):
        missing = [{"key": "aa:bb:cc:dd:ee:ff", "hostname": "router.local"}]

        message = ns._build_notification_message([], {}, {}, missing, [])

        assert "1 previously-seen device(s) missing:" in message
        assert "aa:bb:cc:dd:ee:ff (router.local)" in message

    def test_missing_device_label_takes_priority_over_hostname(self):
        missing = [{"key": "aa:bb:cc:dd:ee:ff", "hostname": "router.local", "label": "Kitchen Echo"}]

        message = ns._build_notification_message([], {}, {}, missing, [])

        assert "(Kitchen Echo)" in message
        assert "router.local" not in message

    def test_includes_risky_devices(self):
        risky = [{"ip": "192.168.1.1", "risky_ports": [23, 445]}]

        message = ns._build_notification_message([], {}, {}, [], risky)

        assert "1 device(s) exposing a risky port:" in message
        assert "telnet (23), smb (445)" in message

    def test_combines_multiple_categories_with_blank_line_between(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "phone.local"}]
        is_new = {"aa:bb:cc:dd:ee:ff": True}
        risky = [{"ip": "192.168.1.2", "risky_ports": [23]}]

        message = ns._build_notification_message(devices, is_new, {}, [], risky)

        assert "1 new device(s):" in message
        assert "1 device(s) exposing a risky port:" in message
        assert "\n\n" in message


class TestSendWebhookNotification:
    def test_returns_true_on_a_2xx_response(self):
        fake_response = MagicMock()
        fake_response.status = 200
        fake_response.__enter__.return_value = fake_response

        with patch("network_scanner.urllib.request.urlopen", return_value=fake_response) as mock_urlopen:
            result = ns.send_webhook_notification("https://example.com/hook", "hello")

        assert result is True
        request = mock_urlopen.call_args[0][0]
        assert request.full_url == "https://example.com/hook"
        assert json.loads(request.data) == {"text": "hello"}
        assert request.get_header("Content-type") == "application/json"

    def test_returns_false_on_a_non_2xx_response(self):
        fake_response = MagicMock()
        fake_response.status = 500
        fake_response.__enter__.return_value = fake_response

        with patch("network_scanner.urllib.request.urlopen", return_value=fake_response):
            assert ns.send_webhook_notification("https://example.com/hook", "hello") is False

    def test_returns_false_and_does_not_raise_on_network_error(self):
        with patch("network_scanner.urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
            assert ns.send_webhook_notification("https://example.com/hook", "hello") is False


def _block_import(monkeypatch, blocked_name, exc):
    """Make `import <blocked_name>` raise exc, passing every other import through."""
    import builtins
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == blocked_name:
            raise exc
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


class TestCheckScapy:
    def test_reports_ok_when_importable(self, monkeypatch):
        # Mocks the import succeeding rather than relying on scapy
        # actually being importable in whatever environment runs this
        # test - it may not be (this sandbox's own scapy install is
        # broken, which is exactly the case the next test covers).
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "scapy.all":
                return MagicMock()
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        ok, detail = ns._check_scapy()
        assert ok is True
        assert "available" in detail

    def test_reports_not_installed_on_import_error(self, monkeypatch):
        _block_import(monkeypatch, "scapy.all", ImportError("no module named scapy"))
        ok, detail = ns._check_scapy()
        assert ok is False
        assert "Not installed" in detail

    def test_reports_broken_install_on_a_baseexception_not_just_exception(self, monkeypatch):
        # Regression test: a broken scapy/cryptography install can raise
        # pyo3_runtime.PanicException from its Rust extension on import,
        # which subclasses BaseException directly, not Exception -
        # confirmed for real during testing, where `except Exception`
        # here let it crash straight through --doctor instead of being
        # reported as a diagnostic finding.
        class FakePanic(BaseException):
            pass

        _block_import(monkeypatch, "scapy.all", FakePanic("Python API call failed"))
        ok, detail = ns._check_scapy()
        assert ok is False
        assert "failed to import" in detail


class TestCheckPsutil:
    def test_reports_not_installed_on_import_error(self, monkeypatch):
        _block_import(monkeypatch, "psutil", ImportError("no module named psutil"))
        ok, detail = ns._check_psutil()
        assert ok is False
        assert "Not installed" in detail


class TestCheckPingBinary:
    def test_reports_found_path(self):
        with patch("network_scanner.shutil.which", return_value="/sbin/ping"):
            ok, detail = ns._check_ping_binary()
        assert ok is True
        assert "/sbin/ping" in detail

    def test_reports_not_found(self):
        with patch("network_scanner.shutil.which", return_value=None):
            ok, detail = ns._check_ping_binary()
        assert ok is False
        assert "Not found" in detail


class TestCheckArpBinary:
    def test_reports_found_path(self):
        with patch("network_scanner.shutil.which", return_value="/usr/sbin/arp"):
            ok, detail = ns._check_arp_binary()
        assert ok is True

    def test_reports_not_found(self):
        with patch("network_scanner.shutil.which", return_value=None):
            ok, detail = ns._check_arp_binary()
        assert ok is False


class TestCheckCacheWritable:
    def test_reports_writable_directory(self, tmp_path):
        with patch("network_scanner.Path.home", return_value=tmp_path):
            ok, detail = ns._check_cache_writable()
        assert ok is True
        assert str(tmp_path / ".cache") in detail

    def test_reports_unwritable_directory(self, tmp_path):
        with patch("network_scanner.Path.home", return_value=tmp_path), \
                patch("network_scanner.Path.write_text", side_effect=OSError("Permission denied")):
            ok, detail = ns._check_cache_writable()
        assert ok is False
        assert "not writable" in detail


class TestCheckOuiCache:
    def test_reports_cached_when_file_exists(self, tmp_path):
        cache_path = tmp_path / "network_scanner_oui.txt"
        cache_path.write_text("data", encoding="utf-8")
        with patch("network_scanner._OUI_CACHE_PATH", cache_path):
            ok, detail = ns._check_oui_cache()
        assert ok is True
        assert "Cached" in detail

    def test_reports_not_downloaded_yet_when_missing(self, tmp_path):
        cache_path = tmp_path / "network_scanner_oui.txt"
        with patch("network_scanner._OUI_CACHE_PATH", cache_path):
            ok, detail = ns._check_oui_cache()
        assert ok is True
        assert "Not downloaded yet" in detail


class TestHasRawSocketPrivileges:
    def test_true_when_root_on_unix(self):
        with patch("network_scanner.platform.system", return_value="Linux"), \
                patch("network_scanner.os.geteuid", return_value=0, create=True):
            assert ns._has_raw_socket_privileges() is True

    def test_false_when_not_root_on_unix(self):
        with patch("network_scanner.platform.system", return_value="Linux"), \
                patch("network_scanner.os.geteuid", return_value=1000, create=True):
            assert ns._has_raw_socket_privileges() is False

    def test_false_when_geteuid_unavailable(self):
        with patch("network_scanner.platform.system", return_value="Linux"), \
                patch("network_scanner.os.geteuid", side_effect=AttributeError, create=True):
            assert ns._has_raw_socket_privileges() is False


class TestCheckMdnsMulticast:
    def test_reports_ok_when_bind_and_join_succeed(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        with patch("network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ns._check_mdns_multicast()
        assert ok is True

    def test_reports_failure_when_bind_is_denied(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.bind.side_effect = OSError("Address already in use")
        with patch("network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ns._check_mdns_multicast()
        assert ok is False
        assert "Can't bind" in detail


class TestRunDoctor:
    def test_returns_true_when_every_check_passes(self, capsys):
        checks = (("Check A", lambda: (True, "fine")), ("Check B", lambda: (True, "also fine")))
        with patch("network_scanner._DOCTOR_CHECKS", checks):
            assert ns.run_doctor(color=False) is True
        assert "Everything checks out." in capsys.readouterr().out

    def test_returns_false_when_any_check_fails(self, capsys):
        checks = (("Check A", lambda: (True, "fine")), ("Check B", lambda: (False, "not fine")))
        with patch("network_scanner._DOCTOR_CHECKS", checks):
            assert ns.run_doctor(color=False) is False
        out = capsys.readouterr().out
        assert "not fine" in out
        assert "Some checks reported a limitation" in out


class TestDnsNameEncoding:
    def test_round_trips_a_simple_name(self):
        encoded = ns._encode_dns_name("72.1.168.192.in-addr.arpa")
        name, offset = ns._decode_dns_name(encoded, 0)

        assert name == "72.1.168.192.in-addr.arpa"
        assert offset == len(encoded)

    def test_decodes_a_compression_pointer(self):
        suffix = ns._encode_dns_name("local")
        pointer = bytes([0xC0, 0x00])  # Pointer to offset 0.
        message = suffix + pointer

        name, offset = ns._decode_dns_name(message, len(suffix))

        assert name == "local"
        assert offset == len(suffix) + 2


class TestBuildMdnsPtrQuery:
    def test_builds_a_well_formed_single_question_query(self):
        query = ns._build_mdns_ptr_query("72.1.168.192.in-addr.arpa")

        header = struct.unpack(">HHHHHH", query[:12])
        assert header == (0, 0, 1, 0, 0, 0)

        qname, offset = ns._decode_dns_name(query, 12)
        assert qname == "72.1.168.192.in-addr.arpa"

        qtype, qclass = struct.unpack(">HH", query[offset:offset + 4])
        assert qtype == ns._DNS_TYPE_PTR
        assert qclass == ns._DNS_CLASS_IN | ns._MDNS_QU_BIT


def _build_fake_ptr_response(qname: str, answer_name: str, target: str) -> bytes:
    """Build a minimal, valid mDNS response with one PTR answer, for tests."""
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    rdata = ns._encode_dns_name(target)
    answer = (
        ns._encode_dns_name(answer_name)
        + struct.pack(">HH", ns._DNS_TYPE_PTR, ns._DNS_CLASS_IN)
        + struct.pack(">I", 120)
        + struct.pack(">H", len(rdata))
        + rdata
    )
    return header + answer


class TestExtractPtrHostname:
    def test_extracts_hostname_from_matching_answer(self):
        qname = "72.1.168.192.in-addr.arpa"
        message = _build_fake_ptr_response(qname, qname, "printer.local.")

        assert ns._extract_ptr_hostname(message, qname) == "printer.local"

    def test_ignores_answer_for_a_different_name(self):
        message = _build_fake_ptr_response("9.1.168.192.in-addr.arpa", "9.1.168.192.in-addr.arpa", "other.local.")

        assert ns._extract_ptr_hostname(message, "72.1.168.192.in-addr.arpa") == ""

    def test_returns_empty_string_for_garbage_input(self):
        assert ns._extract_ptr_hostname(b"\x00\x01", "72.1.168.192.in-addr.arpa") == ""


def _build_a_record(name: str, ip: str) -> bytes:
    return (
        ns._encode_dns_name(name)
        + struct.pack(">HH", ns._DNS_TYPE_A, ns._DNS_CLASS_IN)
        + struct.pack(">I", 120)
        + struct.pack(">H", 4)
        + socket.inet_aton(ip)
    )


def _build_srv_record(instance_name: str, target: str, port: int = 8009) -> bytes:
    rdata = struct.pack(">HHH", 0, 0, port) + ns._encode_dns_name(target)
    return (
        ns._encode_dns_name(instance_name)
        + struct.pack(">HH", ns._DNS_TYPE_SRV, ns._DNS_CLASS_IN)
        + struct.pack(">I", 120)
        + struct.pack(">H", len(rdata))
        + rdata
    )


def _build_fake_service_response(*records: bytes, answer_count: int = 0, additional_count: int = 0) -> bytes:
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, answer_count, 0, additional_count)
    return header + b"".join(records)


class TestCollectServiceRecords:
    def test_collects_a_and_srv_records_regardless_of_section(self):
        a_record = _build_a_record("Chromecast-abc123.local", "192.168.1.72")
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        message = _build_fake_service_response(srv_record, a_record, answer_count=1, additional_count=1)

        host_to_ip: dict = {}
        instance_to_host: dict = {}
        ns._collect_service_records(message, host_to_ip, instance_to_host)

        assert host_to_ip == {"chromecast-abc123.local": "192.168.1.72"}
        assert instance_to_host == {"Living Room TV._googlecast._tcp.local": "chromecast-abc123.local"}


class TestMdnsReverseLookup:
    def test_returns_hostname_from_first_matching_response(self):
        qname = "72.1.168.192.in-addr.arpa"
        response = _build_fake_ptr_response(qname, qname, "printer.local.")

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.return_value = (response, ("192.168.1.72", 5353))

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            hostname = ns.mdns_reverse_lookup("192.168.1.72", timeout=0.5)

        assert hostname == "printer.local"
        fake_sock.sendto.assert_called_once()
        assert fake_sock.sendto.call_args[0][1] == ns._MDNS_GROUP

    def test_returns_empty_string_on_timeout(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            assert ns.mdns_reverse_lookup("192.168.1.72", timeout=0.01) == ""

    def test_returns_empty_string_when_send_fails(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError("Local network access denied")

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            assert ns.mdns_reverse_lookup("192.168.1.72", timeout=0.5) == ""


class TestMdnsServiceLookup:
    def test_joins_srv_and_a_records_into_ip_to_name_map(self):
        a_record = _build_a_record("Chromecast-abc123.local", "192.168.1.72")
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        response = _build_fake_service_response(srv_record, a_record, answer_count=2)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("192.168.1.72", 5353)), socket.timeout]

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            result = ns.mdns_service_lookup("_googlecast._tcp.local", timeout=0.2)

        assert result == {"192.168.1.72": "Living Room TV"}

    def test_returns_empty_dict_when_nothing_answers(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            assert ns.mdns_service_lookup("_googlecast._tcp.local", timeout=0.01) == {}

    def test_still_queries_when_bind_or_group_join_fails(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.bind.side_effect = OSError("Address already in use")
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            result = ns.mdns_service_lookup("_googlecast._tcp.local", timeout=0.01)

        assert result == {}
        fake_sock.sendto.assert_called_once()


class TestLoadOuiRegistry:
    """lookup_mac_vendor()'s underlying loader, tested directly so each
    scenario can control the cache-read outcome explicitly rather than
    relying on whatever happens to be (or not be) on the test machine's
    real filesystem at ~/.cache/network_scanner_oui.txt."""

    def _fake_response(self, text: str) -> MagicMock:
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = text.encode("utf-8")
        return response

    def test_uses_cached_copy_without_downloading_when_not_forcing_refresh(self):
        cached_text = "AA-BB-CC   (hex)\t\tCached Vendor\n"

        with patch("network_scanner.Path.read_text", return_value=cached_text), \
                patch("network_scanner.urllib.request.urlopen") as mock_urlopen:
            result = ns._load_oui_registry()

        assert result == cached_text
        mock_urlopen.assert_not_called()

    def test_downloads_when_no_cache_exists(self):
        registry_text = "AA-BB-CC   (hex)\t\tExample Vendor\n"

        with patch("network_scanner.Path.read_text", side_effect=OSError), \
                patch("network_scanner.urllib.request.urlopen", return_value=self._fake_response(registry_text)), \
                patch("network_scanner.Path.mkdir"), patch("network_scanner.Path.write_text") as mock_write:
            result = ns._load_oui_registry()

        assert result == registry_text
        mock_write.assert_called_once_with(registry_text, encoding="utf-8")

    def test_returns_none_when_no_cache_and_download_fails(self):
        with patch("network_scanner.Path.read_text", side_effect=OSError), \
                patch("network_scanner.urllib.request.urlopen", side_effect=urllib.error.URLError("offline")):
            assert ns._load_oui_registry() is None

    def test_force_refresh_downloads_even_when_cache_exists(self):
        cached_text = "AA-BB-CC   (hex)\t\tStale Vendor\n"
        fresh_text = "AA-BB-CC   (hex)\t\tFresh Vendor\n"

        with patch("network_scanner.Path.read_text", return_value=cached_text) as mock_read, \
                patch("network_scanner.urllib.request.urlopen", return_value=self._fake_response(fresh_text)), \
                patch("network_scanner.Path.mkdir"), patch("network_scanner.Path.write_text") as mock_write:
            result = ns._load_oui_registry(force_refresh=True)

        assert result == fresh_text
        mock_write.assert_called_once_with(fresh_text, encoding="utf-8")
        # The cache is never even consulted up front when refreshing -
        # only as a fallback if the download itself fails (see below).
        mock_read.assert_not_called()

    def test_force_refresh_falls_back_to_cache_when_download_fails(self):
        cached_text = "AA-BB-CC   (hex)\t\tCached Vendor\n"

        with patch("network_scanner.Path.read_text", return_value=cached_text), \
                patch("network_scanner.urllib.request.urlopen", side_effect=urllib.error.URLError("offline")) as mock_urlopen:
            result = ns._load_oui_registry(force_refresh=True)

        assert result == cached_text
        mock_urlopen.assert_called_once()


class TestLookupMacVendor:
    def setup_method(self):
        # _oui_vendor_table is a module-level cache shared across calls -
        # reset it before each test so one test's fake data can't leak
        # into another's.
        ns._oui_vendor_table = None

    def teardown_method(self):
        ns._oui_vendor_table = None

    def test_parses_and_looks_up_a_known_prefix(self):
        registry_text = (
            "00-1A-11   (hex)\t\tGoogle, Inc.\n"
            "000000     (base 16)\t\tGoogle, Inc.\n"
            "\n"
            "AA-BB-CC   (hex)\t\tExample Vendor\n"
        )

        with patch("network_scanner._load_oui_registry", return_value=registry_text):
            assert ns.lookup_mac_vendor("00:1a:11:22:33:44") == "Google, Inc."
            assert ns.lookup_mac_vendor("aa:bb:cc:dd:ee:ff") == "Example Vendor"

    def test_unknown_prefix_returns_empty_string(self):
        with patch("network_scanner._load_oui_registry", return_value="AA-BB-CC   (hex)\t\tExample Vendor\n"):
            assert ns.lookup_mac_vendor("ff:ff:ff:ff:ff:ff") == ""

    def test_registry_unavailable_returns_empty_string(self):
        with patch("network_scanner._load_oui_registry", return_value=None):
            assert ns.lookup_mac_vendor("aa:bb:cc:11:22:33") == ""

    def test_malformed_mac_returns_empty_string(self):
        with patch("network_scanner._load_oui_registry", return_value="AA-BB-CC   (hex)\t\tExample Vendor\n"):
            assert ns.lookup_mac_vendor("not-a-mac") == ""

    def test_only_loads_registry_once_across_multiple_lookups(self):
        with patch(
            "network_scanner._load_oui_registry", return_value="AA-BB-CC   (hex)\t\tExample Vendor\n"
        ) as mock_load:
            ns.lookup_mac_vendor("aa:bb:cc:11:22:33")
            ns.lookup_mac_vendor("aa:bb:cc:44:55:66")

        mock_load.assert_called_once()

    def test_passes_force_refresh_through_on_the_first_call_only(self):
        with patch(
            "network_scanner._load_oui_registry", return_value="AA-BB-CC   (hex)\t\tExample Vendor\n"
        ) as mock_load:
            ns.lookup_mac_vendor("aa:bb:cc:11:22:33", force_refresh=True)
            ns.lookup_mac_vendor("aa:bb:cc:44:55:66", force_refresh=False)

        mock_load.assert_called_once_with(force_refresh=True)


class TestResolveMissingHostnames:
    def test_leaves_already_named_devices_untouched(self):
        devices = [{"ip": "192.168.1.1", "mac": "", "hostname": "router.local", "vendor": ""}]

        with patch("network_scanner.mdns_reverse_lookup") as mock_mdns:
            result = ns._resolve_missing_hostnames(devices, mdns_timeout=0.3)

        mock_mdns.assert_not_called()
        assert result[0]["hostname"] == "router.local"

    def test_fills_in_hostname_via_mdns_reverse_lookup(self):
        devices = [{"ip": "192.168.1.72", "mac": "", "hostname": "", "vendor": ""}]

        with patch("network_scanner.mdns_reverse_lookup", return_value="printer.local"), \
                patch("network_scanner.mdns_service_lookup") as mock_cast:
            result = ns._resolve_missing_hostnames(devices, mdns_timeout=0.3)

        assert result[0]["hostname"] == "printer.local"
        mock_cast.assert_not_called()

    def test_falls_back_to_cast_service_lookup(self):
        devices = [{"ip": "192.168.1.72", "mac": "", "hostname": "", "vendor": ""}]

        with patch("network_scanner.mdns_reverse_lookup", return_value=""), \
                patch("network_scanner.mdns_service_lookup", return_value={"192.168.1.72": "Living Room TV"}):
            result = ns._resolve_missing_hostnames(devices, mdns_timeout=0.3)

        assert result[0]["hostname"] == "Living Room TV"

    def test_leaves_hostname_empty_when_nothing_resolves(self):
        devices = [{"ip": "192.168.1.72", "mac": "", "hostname": "", "vendor": ""}]

        with patch("network_scanner.mdns_reverse_lookup", return_value=""), \
                patch("network_scanner.mdns_service_lookup", return_value={}):
            result = ns._resolve_missing_hostnames(devices, mdns_timeout=0.3)

        assert result[0]["hostname"] == ""


class TestAttachVendorNames:
    def test_fills_in_vendor_for_devices_with_a_mac(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}]

        with patch("network_scanner.lookup_mac_vendor", return_value="Example Vendor"):
            result = ns._attach_vendor_names(devices)

        assert result[0]["vendor"] == "Example Vendor"

    def test_skips_devices_without_a_mac(self):
        devices = [{"ip": "192.168.1.1", "mac": "", "hostname": "", "vendor": ""}]

        with patch("network_scanner.lookup_mac_vendor") as mock_lookup:
            ns._attach_vendor_names(devices)

        mock_lookup.assert_not_called()

    def test_does_not_overwrite_an_existing_vendor(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": "Already Known"}]

        with patch("network_scanner.lookup_mac_vendor") as mock_lookup:
            result = ns._attach_vendor_names(devices)

        mock_lookup.assert_not_called()
        assert result[0]["vendor"] == "Already Known"

    def test_passes_force_refresh_through_to_lookup_mac_vendor(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}]

        with patch("network_scanner.lookup_mac_vendor", return_value="Example Vendor") as mock_lookup:
            ns._attach_vendor_names(devices, force_refresh=True)

        mock_lookup.assert_called_once_with("aa:bb:cc:dd:ee:ff", force_refresh=True)


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

    def test_raises_clear_error_when_ping_binary_missing(self):
        with patch("network_scanner.subprocess.run", side_effect=FileNotFoundError):
            with pytest.raises(RuntimeError, match="ping"):
                ns.ping("192.168.1.1", timeout=1.0)


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

        assert {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local", "vendor": ""} in devices

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

    def test_propagates_missing_ping_binary_error(self):
        with patch("network_scanner.ping", side_effect=RuntimeError("`ping` command not found.")):
            with pytest.raises(RuntimeError, match="ping"):
                ns.ping_sweep("192.168.1.0/30", timeout=0.1, max_workers=4)


class TestListScanInterfaces:
    def test_excludes_loopback(self):
        with patch("network_scanner.socket.if_nameindex", return_value=[(1, "lo"), (2, "eth0"), (3, "wlan0")]):
            assert ns._list_scan_interfaces() == ["eth0", "wlan0"]

    def test_returns_empty_list_when_unsupported(self):
        with patch("network_scanner.socket.if_nameindex", side_effect=AttributeError):
            assert ns._list_scan_interfaces() == []

    def test_returns_empty_list_on_os_error(self):
        with patch("network_scanner.socket.if_nameindex", side_effect=OSError):
            assert ns._list_scan_interfaces() == []


class TestPingIpv6Multicast:
    def test_uses_ping6_when_available_on_unix(self):
        with patch("network_scanner.platform.system", return_value="Linux"), \
                patch("network_scanner.shutil.which", return_value="/sbin/ping6"), \
                patch("network_scanner.subprocess.run") as mock_run:
            ns._ping_ipv6_multicast("eth0", timeout=1.0)

        command = mock_run.call_args[0][0]
        assert command[0] == "ping6"
        assert "-I" in command and "eth0" in command
        assert "ff02::1" in command

    def test_falls_back_to_plain_ping_when_ping6_missing(self):
        with patch("network_scanner.platform.system", return_value="Linux"), \
                patch("network_scanner.shutil.which", return_value=None), \
                patch("network_scanner.subprocess.run") as mock_run:
            ns._ping_ipv6_multicast("eth0", timeout=1.0)

        assert mock_run.call_args[0][0][0] == "ping"

    def test_uses_windows_syntax_on_windows(self):
        with patch("network_scanner.platform.system", return_value="Windows"), \
                patch("network_scanner.subprocess.run") as mock_run:
            ns._ping_ipv6_multicast("eth0", timeout=1.0)

        command = mock_run.call_args[0][0]
        assert command[:2] == ["ping", "-6"]
        assert "-I" not in command  # No interface scoping attempted on Windows.

    def test_swallows_missing_binary_without_raising(self):
        with patch("network_scanner.subprocess.run", side_effect=FileNotFoundError):
            ns._ping_ipv6_multicast("eth0", timeout=1.0)  # Should not raise.

    def test_swallows_timeout_without_raising(self):
        with patch("network_scanner.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="ping", timeout=1)):
            ns._ping_ipv6_multicast("eth0", timeout=1.0)  # Should not raise.


class TestReadIpv6NeighborTable:
    def test_parses_linux_ip_neigh_output(self):
        output = (
            "fe80::1234:5678:9abc:def0 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"
            "2001:db8::1 dev eth0 lladdr 11:22:33:44:55:66 STALE\n"
            "fe80::dead:beef dev eth0 FAILED\n"  # No lladdr - incomplete entry.
        )
        with patch("network_scanner.platform.system", return_value="Linux"), \
                patch("network_scanner.subprocess.run", return_value=MagicMock(stdout=output)):
            table = ns.read_ipv6_neighbor_table()

        assert table == {
            "fe80::1234:5678:9abc:def0": "aa:bb:cc:dd:ee:ff",
            "2001:db8::1": "11:22:33:44:55:66",
        }

    def test_parses_macos_ndp_output_and_strips_zone_id(self):
        output = (
            "Neighbor                             Linklayer Address  Netif Expire    S Flags\n"
            "fe80::1234:5678:9abc:def0%en0        aa:bb:cc:dd:ee:ff   en0   23h59m48s R\n"
        )
        with patch("network_scanner.platform.system", return_value="Darwin"), \
                patch("network_scanner.subprocess.run", return_value=MagicMock(stdout=output)):
            table = ns.read_ipv6_neighbor_table()

        assert table == {"fe80::1234:5678:9abc:def0": "aa:bb:cc:dd:ee:ff"}

    def test_returns_empty_dict_when_command_missing(self):
        with patch("network_scanner.subprocess.run", side_effect=FileNotFoundError):
            assert ns.read_ipv6_neighbor_table() == {}


class TestIpv6NeighborScan:
    def test_discovers_and_filters_multicast_and_loopback_entries(self):
        neighbors = {
            "fe80::1234:5678:9abc:def0": "aa:bb:cc:dd:ee:ff",
            "2001:db8::1": "11:22:33:44:55:66",
            "ff02::1": "33:33:00:00:00:01",  # Multicast - should be filtered.
            "::1": "00:00:00:00:00:00",  # Loopback - should be filtered.
        }
        with patch("network_scanner._list_scan_interfaces", return_value=["eth0"]), \
                patch("network_scanner._ping_ipv6_multicast"), \
                patch("network_scanner.read_ipv6_neighbor_table", return_value=neighbors):
            devices = ns.ipv6_neighbor_scan(timeout=1.0)

        ips = {d["ip"] for d in devices}
        assert ips == {"fe80::1234:5678:9abc:def0", "2001:db8::1"}
        assert all(d["hostname"] == "" and d["vendor"] == "" for d in devices)

    def test_pings_every_non_loopback_interface(self):
        with patch("network_scanner._list_scan_interfaces", return_value=["eth0", "wlan0"]), \
                patch("network_scanner._ping_ipv6_multicast") as mock_ping, \
                patch("network_scanner.read_ipv6_neighbor_table", return_value={}):
            ns.ipv6_neighbor_scan(timeout=1.0)

        assert mock_ping.call_count == 2
        pinged_interfaces = {call.args[0] for call in mock_ping.call_args_list}
        assert pinged_interfaces == {"eth0", "wlan0"}

    def test_returns_empty_list_when_nothing_found(self):
        with patch("network_scanner._list_scan_interfaces", return_value=[]), \
                patch("network_scanner.read_ipv6_neighbor_table", return_value={}):
            assert ns.ipv6_neighbor_scan(timeout=1.0) == []


class TestProbeTcpPort:
    def test_returns_true_when_port_accepts_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 0

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            assert ns._probe_tcp_port("192.168.1.1", 80, timeout=0.1) is True

    def test_returns_false_when_port_refuses_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 1

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            assert ns._probe_tcp_port("192.168.1.1", 80, timeout=0.1) is False


class TestSummarizeBanner:
    def test_prefers_server_header_over_status_line(self):
        data = b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.55\r\nContent-Length: 0\r\n\r\n"
        assert ns._summarize_banner(data) == "HTTP/1.1 200 OK  |  Server: lighttpd/1.4.55"

    def test_returns_first_line_when_no_server_header(self):
        data = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
        assert ns._summarize_banner(data) == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"

    def test_returns_empty_string_for_blank_data(self):
        assert ns._summarize_banner(b"\r\n\r\n   \r\n") == ""

    def test_truncates_long_lines(self):
        data = ("x" * 300).encode("ascii") + b"\r\n"
        assert len(ns._summarize_banner(data)) == 120


class TestGrabBanner:
    def test_sends_head_request_on_http_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            result = ns.grab_banner("192.168.1.1", 80, timeout=0.5)

        assert "nginx" in result
        sent = fake_sock.sendall.call_args[0][0]
        assert sent.startswith(b"HEAD / HTTP/1.0")

    def test_reads_unprompted_banner_on_non_http_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1\r\n"

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            result = ns.grab_banner("192.168.1.1", 22, timeout=0.5)

        assert result == "SSH-2.0-OpenSSH_8.9p1"
        fake_sock.sendall.assert_not_called()

    def test_wraps_https_port_in_tls(self):
        fake_raw_sock = MagicMock()
        fake_raw_sock.__enter__.return_value = fake_raw_sock
        fake_wrapped_sock = MagicMock()
        fake_wrapped_sock.recv.return_value = b"HTTP/1.1 401 Unauthorized\r\nServer: lighttpd\r\n\r\n"

        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_wrapped_sock

        with patch("network_scanner.socket.socket", return_value=fake_raw_sock), \
                patch("network_scanner.ssl.create_default_context", return_value=fake_context):
            result = ns.grab_banner("192.168.1.1", 8443, timeout=0.5)

        assert "lighttpd" in result
        assert fake_context.check_hostname is False
        fake_wrapped_sock.sendall.assert_called_once()

    def test_returns_empty_string_on_connection_failure(self):
        with patch("network_scanner.socket.socket", side_effect=OSError("Connection refused")):
            assert ns.grab_banner("192.168.1.1", 80, timeout=0.5) == ""

    def test_falls_back_to_http_probe_on_unrecognized_silent_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        # First recv() (passive listen) times out; second recv() (after
        # the HTTP fallback probe) returns a real response.
        fake_sock.recv.side_effect = [socket.timeout, b"HTTP/1.1 200 OK\r\nServer: mystery-iot\r\n\r\n"]

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            result = ns.grab_banner("192.168.1.1", 9999, timeout=0.5)

        assert "mystery-iot" in result
        fake_sock.sendall.assert_called_once()

    def test_does_not_send_http_probe_when_unrecognized_port_already_answered(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recv.return_value = b"220 example-ftp ready\r\n"

        with patch("network_scanner.socket.socket", return_value=fake_sock):
            result = ns.grab_banner("192.168.1.1", 9999, timeout=0.5)

        assert result == "220 example-ftp ready"
        fake_sock.sendall.assert_not_called()


class TestGetDeviceMac:
    def test_prefers_direct_arp_request(self):
        with patch("network_scanner.arp_scan", return_value=[{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}]), \
                patch("network_scanner.ping") as mock_ping:
            assert ns._get_device_mac("192.168.1.1", timeout=1.0) == "aa:bb:cc:dd:ee:ff"

        mock_ping.assert_not_called()

    def test_falls_back_to_ping_and_arp_cache_when_arp_scan_unavailable(self):
        with patch("network_scanner.arp_scan", side_effect=ImportError), \
                patch("network_scanner.ping", return_value=True) as mock_ping, \
                patch("network_scanner.read_arp_table", return_value={"192.168.1.1": "aa:bb:cc:dd:ee:ff"}):
            assert ns._get_device_mac("192.168.1.1", timeout=1.0) == "aa:bb:cc:dd:ee:ff"

        mock_ping.assert_called_once()

    def test_returns_empty_string_when_nothing_found(self):
        with patch("network_scanner.arp_scan", side_effect=ImportError), \
                patch("network_scanner.ping", return_value=False), \
                patch("network_scanner.read_arp_table", return_value={}):
            assert ns._get_device_mac("192.168.1.1", timeout=1.0) == ""

    def test_survives_missing_ping_binary(self):
        with patch("network_scanner.arp_scan", side_effect=ImportError), \
                patch("network_scanner.ping", side_effect=RuntimeError("no ping")), \
                patch("network_scanner.read_arp_table", return_value={}):
            assert ns._get_device_mac("192.168.1.1", timeout=1.0) == ""


class TestIdentifyDevice:
    def test_reports_open_ports_with_service_and_banner(self):
        def fake_probe(ip, port, timeout):
            return port in (22, 80)

        with patch("network_scanner._get_device_mac", return_value="aa:bb:cc:dd:ee:ff"), \
                patch("network_scanner._probe_tcp_port", side_effect=fake_probe), \
                patch("network_scanner.grab_banner", return_value="SSH-2.0-OpenSSH"), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices: devices):
            device = ns.identify_device("192.168.1.1", ports=[22, 23, 80], timeout=0.1)

        assert device["mac"] == "aa:bb:cc:dd:ee:ff"
        ports_found = {entry["port"] for entry in device["open_ports"]}
        assert ports_found == {22, 80}
        assert all(entry["banner"] == "SSH-2.0-OpenSSH" for entry in device["open_ports"])
        assert device["open_ports"][0]["service"] == "ssh"

    def test_no_open_ports_returns_empty_list(self):
        with patch("network_scanner._get_device_mac", return_value=""), \
                patch("network_scanner._probe_tcp_port", return_value=False), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices):
            device = ns.identify_device("192.168.1.1", ports=[22, 80], timeout=0.1)

        assert device["open_ports"] == []

    def test_skips_vendor_lookup_when_no_mac_found(self):
        with patch("network_scanner._get_device_mac", return_value=""), \
                patch("network_scanner._probe_tcp_port", return_value=False), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names") as mock_vendor:
            ns.identify_device("192.168.1.1", ports=[22], timeout=0.1)

        mock_vendor.assert_not_called()

    def test_skips_vendor_lookup_when_disabled(self):
        with patch("network_scanner._get_device_mac", return_value="aa:bb:cc:dd:ee:ff"), \
                patch("network_scanner._probe_tcp_port", return_value=False), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names") as mock_vendor:
            ns.identify_device("192.168.1.1", ports=[22], timeout=0.1, vendor_lookup=False)

        mock_vendor.assert_not_called()


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


class TestDeviceIdentity:
    def test_prefers_mac_over_ip(self):
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}
        assert ns._device_identity(device) == "aa:bb:cc:dd:ee:ff"

    def test_falls_back_to_ip_when_no_mac(self):
        device = {"ip": "192.168.1.1", "mac": "", "hostname": "", "vendor": ""}
        assert ns._device_identity(device) == "192.168.1.1"


class TestKnownDevicesPersistence:
    def test_load_returns_empty_dict_when_file_does_not_exist(self, tmp_path):
        assert ns._load_known_devices(tmp_path / "missing.json") == {}

    def test_load_returns_empty_dict_for_corrupt_json(self, tmp_path):
        path = tmp_path / "known.json"
        path.write_text("not valid json {{{", encoding="utf-8")
        assert ns._load_known_devices(path) == {}

    def test_save_then_load_round_trips(self, tmp_path):
        path = tmp_path / "nested" / "known.json"
        data = {"aa:bb:cc:dd:ee:ff": {"ip": "192.168.1.1", "first_seen": "2026-01-01T00:00:00"}}

        ns._save_known_devices(data, path)

        assert ns._load_known_devices(path) == data

    def test_save_does_not_raise_on_unwritable_path(self, tmp_path):
        # A path whose parent can't be created (e.g. permission denied,
        # read-only filesystem) shouldn't crash the caller.
        with patch("network_scanner.Path.mkdir", side_effect=OSError("Permission denied")):
            ns._save_known_devices({}, tmp_path / "known.json")  # Should not raise.


class TestMarkNewDevices:
    def test_first_time_seen_devices_are_all_new(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local", "vendor": ""},
            {"ip": "192.168.1.2", "mac": "", "hostname": "", "vendor": ""},
        ]

        is_new = ns._mark_new_devices(devices, known_devices_path=path)

        assert is_new == {"aa:bb:cc:dd:ee:ff": True, "192.168.1.2": True}

    def test_previously_seen_devices_are_not_new_on_a_later_scan(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}]

        ns._mark_new_devices(devices, known_devices_path=path)  # First scan.
        is_new = ns._mark_new_devices(devices, known_devices_path=path)  # Second scan.

        assert is_new == {"aa:bb:cc:dd:ee:ff": False}

    def test_only_the_genuinely_new_device_is_flagged(self, tmp_path):
        path = tmp_path / "known.json"
        known_device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}
        new_device = {"ip": "192.168.1.99", "mac": "11:22:33:44:55:66", "hostname": "", "vendor": ""}

        ns._mark_new_devices([known_device], known_devices_path=path)
        is_new = ns._mark_new_devices([known_device, new_device], known_devices_path=path)

        assert is_new == {"aa:bb:cc:dd:ee:ff": False, "11:22:33:44:55:66": True}

    def test_persists_device_details_and_timestamps(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local", "vendor": "Acme", "port": 80}
        ]

        ns._mark_new_devices(devices, known_devices_path=path)

        stored = ns._load_known_devices(path)["aa:bb:cc:dd:ee:ff"]
        assert stored["ip"] == "192.168.1.1"
        assert stored["hostname"] == "router.local"
        assert stored["vendor"] == "Acme"
        assert stored["port"] == 80
        assert "first_seen" in stored
        assert "last_seen" in stored

    def test_a_device_identified_by_ip_becomes_new_again_if_its_ip_changes(self, tmp_path):
        # Documents a known limitation: a MAC-less device (no ARP entry)
        # is identified by IP alone, so a DHCP lease change makes it
        # look like a different, "new" device.
        path = tmp_path / "known.json"
        ns._mark_new_devices([{"ip": "192.168.1.50", "mac": "", "hostname": "", "vendor": ""}], known_devices_path=path)

        is_new = ns._mark_new_devices(
            [{"ip": "192.168.1.51", "mac": "", "hostname": "", "vendor": ""}], known_devices_path=path
        )

        assert is_new == {"192.168.1.51": True}


class TestFindPortChanges:
    def test_reports_devices_whose_port_differs_from_the_registry(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": "", "port": 80}
        ns._mark_new_devices([device], known_devices_path=path)

        changed_device = dict(device, port=23)
        changes = ns._find_port_changes([changed_device], known_devices_path=path)

        assert changes == {"aa:bb:cc:dd:ee:ff": (80, 23)}

    def test_ignores_devices_with_an_unchanged_port(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": "", "port": 80}
        ns._mark_new_devices([device], known_devices_path=path)

        assert ns._find_port_changes([device], known_devices_path=path) == {}

    def test_a_brand_new_device_is_not_reported_as_a_port_change(self, tmp_path):
        path = tmp_path / "known.json"
        new_device = {"ip": "192.168.1.99", "mac": "11:22:33:44:55:66", "hostname": "", "vendor": "", "port": 80}

        assert ns._find_port_changes([new_device], known_devices_path=path) == {}

    def test_reports_a_device_that_lost_its_matched_port_entirely(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": "", "port": 80}
        ns._mark_new_devices([device], known_devices_path=path)

        no_port_device = dict(device, port=None)
        changes = ns._find_port_changes([no_port_device], known_devices_path=path)

        assert changes == {"aa:bb:cc:dd:ee:ff": (80, None)}

    def test_reports_a_device_that_gained_a_matched_port(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": "", "port": None}
        ns._mark_new_devices([device], known_devices_path=path)

        now_open_device = dict(device, port=80)
        changes = ns._find_port_changes([now_open_device], known_devices_path=path)

        assert changes == {"aa:bb:cc:dd:ee:ff": (None, 80)}


class TestFindMissingDevices:
    def test_empty_registry_reports_nothing_missing(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}]

        assert ns._find_missing_devices(devices, known_devices_path=path) == []

    def test_device_absent_from_this_scan_is_reported_missing(self, tmp_path):
        path = tmp_path / "known.json"
        router = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local", "vendor": "Acme"}
        laptop = {"ip": "192.168.1.50", "mac": "11:22:33:44:55:66", "hostname": "", "vendor": ""}

        ns._mark_new_devices([router, laptop], known_devices_path=path)

        missing = ns._find_missing_devices([router], known_devices_path=path)  # Laptop asleep this time.

        assert len(missing) == 1
        assert missing[0]["key"] == "11:22:33:44:55:66"
        assert "last_seen" in missing[0]

    def test_device_present_in_this_scan_is_not_reported_missing(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}

        ns._mark_new_devices([device], known_devices_path=path)

        assert ns._find_missing_devices([device], known_devices_path=path) == []

    def test_device_missing_again_still_stays_in_the_registry(self, tmp_path):
        # The registry itself is never pruned - a device just keeps
        # showing up in the missing list across scans until it's seen
        # again, rather than being forgotten after one absence.
        path = tmp_path / "known.json"
        router = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}
        laptop = {"ip": "192.168.1.50", "mac": "11:22:33:44:55:66", "hostname": "", "vendor": ""}

        ns._mark_new_devices([router, laptop], known_devices_path=path)
        ns._mark_new_devices([router], known_devices_path=path)  # Scan 2: laptop missing.
        missing = ns._find_missing_devices([router], known_devices_path=path)  # Scan 3: still missing.

        assert [entry["key"] for entry in missing] == ["11:22:33:44:55:66"]

    def test_results_are_sorted_by_identity_key(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [
            {"ip": "192.168.1.1", "mac": "cc:cc:cc:cc:cc:cc", "hostname": "", "vendor": ""},
            {"ip": "192.168.1.2", "mac": "aa:aa:aa:aa:aa:aa", "hostname": "", "vendor": ""},
        ]

        ns._mark_new_devices(devices, known_devices_path=path)

        missing = ns._find_missing_devices([], known_devices_path=path)

        assert [entry["key"] for entry in missing] == ["aa:aa:aa:aa:aa:aa", "cc:cc:cc:cc:cc:cc"]


class TestSetLabel:
    def test_sets_label_on_an_existing_device(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}
        ns._mark_new_devices([device], known_devices_path=path)

        ns._set_label("aa:bb:cc:dd:ee:ff", "Kitchen Echo", known_devices_path=path)

        stored = ns._load_known_devices(path)["aa:bb:cc:dd:ee:ff"]
        assert stored["label"] == "Kitchen Echo"

    def test_creates_a_minimal_entry_for_an_unseen_device(self, tmp_path):
        path = tmp_path / "known.json"

        ns._set_label("192.168.1.99", "Guest Phone", known_devices_path=path)

        stored = ns._load_known_devices(path)["192.168.1.99"]
        assert stored["label"] == "Guest Phone"

    def test_does_not_disturb_other_registry_fields(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local", "vendor": "Acme"}
        ns._mark_new_devices([device], known_devices_path=path)

        ns._set_label("aa:bb:cc:dd:ee:ff", "Router", known_devices_path=path)

        stored = ns._load_known_devices(path)["aa:bb:cc:dd:ee:ff"]
        assert stored["hostname"] == "router.local"
        assert stored["vendor"] == "Acme"
        assert "first_seen" in stored


class TestRemoveLabel:
    def test_removes_an_existing_label(self, tmp_path):
        path = tmp_path / "known.json"
        ns._set_label("aa:bb:cc:dd:ee:ff", "Kitchen Echo", known_devices_path=path)

        ns._remove_label("aa:bb:cc:dd:ee:ff", known_devices_path=path)

        assert "label" not in ns._load_known_devices(path)["aa:bb:cc:dd:ee:ff"]

    def test_does_not_raise_for_an_unknown_device(self, tmp_path):
        path = tmp_path / "known.json"
        ns._remove_label("192.168.1.99", known_devices_path=path)  # Should not raise.

    def test_does_not_raise_for_a_device_with_no_label(self, tmp_path):
        path = tmp_path / "known.json"
        ns._mark_new_devices(
            [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}], known_devices_path=path
        )
        ns._remove_label("aa:bb:cc:dd:ee:ff", known_devices_path=path)  # Should not raise.


class TestLoadLabels:
    def test_returns_only_devices_with_a_label_set(self, tmp_path):
        path = tmp_path / "known.json"
        ns._mark_new_devices(
            [
                {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""},
                {"ip": "192.168.1.2", "mac": "11:22:33:44:55:66", "hostname": "", "vendor": ""},
            ],
            known_devices_path=path,
        )
        ns._set_label("aa:bb:cc:dd:ee:ff", "Kitchen Echo", known_devices_path=path)

        assert ns._load_labels(known_devices_path=path) == {"aa:bb:cc:dd:ee:ff": "Kitchen Echo"}

    def test_returns_empty_dict_when_no_labels_are_set(self, tmp_path):
        path = tmp_path / "known.json"
        ns._mark_new_devices(
            [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "", "vendor": ""}], known_devices_path=path
        )

        assert ns._load_labels(known_devices_path=path) == {}


class TestDisplayHostname:
    def test_returns_bare_hostname_when_no_label_is_set(self):
        assert ns._display_hostname("router.local", "") == "router.local"

    def test_returns_label_when_no_hostname_is_set(self):
        assert ns._display_hostname("", "Kitchen Echo") == "Kitchen Echo"

    def test_combines_both_when_they_differ(self):
        assert ns._display_hostname("Chromecast-abc123.local", "Living Room TV") == \
            "Living Room TV (Chromecast-abc123.local)"

    def test_returns_just_the_label_when_they_are_identical(self):
        assert ns._display_hostname("router.local", "router.local") == "router.local"

    def test_returns_empty_string_when_neither_is_set(self):
        assert ns._display_hostname("", "") == ""
