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
            patch("network_scanner._attach_vendor_names", side_effect=lambda devices: devices),
        )

    def test_merges_devices_from_every_subnet(self):
        def fake_scan(subnet, timeout):
            return {
                "192.168.1.0/24": [{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": ""}],
                "10.0.0.0/24": [{"ip": "10.0.0.9", "mac": "", "hostname": "nas.local"}],
            }[subnet]

        patch_hostnames, patch_vendors = self._patch_enrichment()
        with patch("network_scanner.scan", side_effect=fake_scan), patch_hostnames, patch_vendors:
            devices = ns.scan_all_subnets(["192.168.1.0/24", "10.0.0.0/24"], timeout=1.0)

        assert [d["ip"] for d in devices] == ["10.0.0.9", "192.168.1.5"]

    def test_deduplicates_by_ip_across_overlapping_subnets(self):
        patch_hostnames, patch_vendors = self._patch_enrichment()
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "", "hostname": ""}]), \
                patch_hostnames, patch_vendors:
            devices = ns.scan_all_subnets(["192.168.1.0/24", "192.168.1.0/24"], timeout=1.0)

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
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices: devices):
            devices = ns.scan_all_subnets(["192.168.1.0/24", "10.0.0.0/24"], timeout=1.0, mdns_timeout=0.4)

        assert mock_resolve.call_count == 2
        assert all(call.args[1] == 0.4 for call in mock_resolve.call_args_list)
        assert {d["hostname"] for d in devices} == {"resolved-192.168.1.5", "resolved-10.0.0.9"}

    def test_attaches_vendors_once_over_final_merged_list(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "x"}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names", side_effect=lambda devices: devices) as mock_vendor:
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0)

        mock_vendor.assert_called_once()

    def test_skips_vendor_lookup_when_disabled(self):
        with patch("network_scanner.scan", return_value=[{"ip": "192.168.1.5", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "x"}]), \
                patch("network_scanner._resolve_missing_hostnames", side_effect=lambda devices, timeout: devices), \
                patch("network_scanner._attach_vendor_names") as mock_vendor:
            ns.scan_all_subnets(["192.168.1.0/24"], timeout=1.0, vendor_lookup=False)

        mock_vendor.assert_not_called()


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


class TestLookupMacVendor:
    def setup_method(self):
        # _oui_vendor_table is a module-level cache shared across calls -
        # reset it before each test so one test's fake data can't leak
        # into another's.
        ns._oui_vendor_table = None

    def teardown_method(self):
        ns._oui_vendor_table = None

    def test_downloads_and_parses_registry_on_first_use(self):
        registry_text = (
            "00-1A-11   (hex)\t\tGoogle, Inc.\n"
            "000000     (base 16)\t\tGoogle, Inc.\n"
            "\n"
            "AA-BB-CC   (hex)\t\tExample Vendor\n"
        )
        fake_response = MagicMock()
        fake_response.__enter__.return_value = fake_response
        fake_response.read.return_value = registry_text.encode("utf-8")

        with patch("network_scanner.urllib.request.urlopen", return_value=fake_response), \
                patch("network_scanner.Path.mkdir"), patch("network_scanner.Path.write_text"):
            assert ns.lookup_mac_vendor("00:1a:11:22:33:44") == "Google, Inc."
            assert ns.lookup_mac_vendor("aa:bb:cc:dd:ee:ff") == "Example Vendor"

    def test_unknown_prefix_returns_empty_string(self):
        with patch("network_scanner.urllib.request.urlopen", side_effect=urllib.error.URLError("offline")), \
                patch("network_scanner.Path.read_text", side_effect=OSError):
            assert ns.lookup_mac_vendor("ff:ff:ff:ff:ff:ff") == ""

    def test_falls_back_to_cache_when_download_fails(self):
        cached_text = "AA-BB-CC   (hex)\t\tCached Vendor\n"

        with patch("network_scanner.urllib.request.urlopen", side_effect=urllib.error.URLError("offline")), \
                patch("network_scanner.Path.read_text", return_value=cached_text):
            assert ns.lookup_mac_vendor("aa:bb:cc:11:22:33") == "Cached Vendor"

    def test_malformed_mac_returns_empty_string(self):
        with patch("network_scanner.urllib.request.urlopen", side_effect=urllib.error.URLError("offline")), \
                patch("network_scanner.Path.read_text", side_effect=OSError):
            assert ns.lookup_mac_vendor("not-a-mac") == ""

    def test_only_fetches_registry_once_across_multiple_lookups(self):
        registry_text = "AA-BB-CC   (hex)\t\tExample Vendor\n"
        fake_response = MagicMock()
        fake_response.__enter__.return_value = fake_response
        fake_response.read.return_value = registry_text.encode("utf-8")

        with patch("network_scanner.urllib.request.urlopen", return_value=fake_response) as mock_urlopen, \
                patch("network_scanner.Path.mkdir"), patch("network_scanner.Path.write_text"):
            ns.lookup_mac_vendor("aa:bb:cc:11:22:33")
            ns.lookup_mac_vendor("aa:bb:cc:44:55:66")

        mock_urlopen.assert_called_once()


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
