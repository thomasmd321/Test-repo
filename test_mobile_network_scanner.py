import csv
import json
import socket
import struct
import urllib.error
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


class TestSummarizeBanner:
    def test_prefers_server_header_over_status_line(self):
        data = b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.55\r\nContent-Length: 0\r\n\r\n"
        assert ms._summarize_banner(data) == "HTTP/1.1 200 OK  |  Server: lighttpd/1.4.55"

    def test_returns_first_line_when_no_server_header(self):
        data = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n"
        assert ms._summarize_banner(data) == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"

    def test_returns_empty_string_for_blank_data(self):
        assert ms._summarize_banner(b"\r\n\r\n   \r\n") == ""

    def test_truncates_long_lines(self):
        data = ("x" * 300).encode("ascii") + b"\r\n"
        assert len(ms._summarize_banner(data)) == 120


class TestGrabBanner:
    def test_sends_head_request_on_http_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.grab_banner("192.168.1.1", 80, timeout=0.5)

        assert "nginx" in result
        sent = fake_sock.sendall.call_args[0][0]
        assert sent.startswith(b"HEAD / HTTP/1.0")

    def test_reads_unprompted_banner_on_non_http_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9p1\r\n"

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.grab_banner("192.168.1.1", 22, timeout=0.5)

        assert result == "SSH-2.0-OpenSSH_8.9p1"
        fake_sock.sendall.assert_not_called()

    def test_wraps_https_port_in_tls(self):
        fake_raw_sock = MagicMock()
        fake_raw_sock.__enter__.return_value = fake_raw_sock
        fake_wrapped_sock = MagicMock()
        fake_wrapped_sock.recv.return_value = b"HTTP/1.1 401 Unauthorized\r\nServer: lighttpd\r\n\r\n"

        fake_context = MagicMock()
        fake_context.wrap_socket.return_value = fake_wrapped_sock

        with patch("mobile_network_scanner.socket.socket", return_value=fake_raw_sock), \
                patch("mobile_network_scanner.ssl.create_default_context", return_value=fake_context):
            result = ms.grab_banner("192.168.1.1", 8443, timeout=0.5)

        assert "lighttpd" in result
        assert fake_context.check_hostname is False
        fake_wrapped_sock.sendall.assert_called_once()

    def test_returns_empty_string_on_connection_failure(self):
        with patch("mobile_network_scanner.socket.socket", side_effect=OSError("Connection refused")):
            assert ms.grab_banner("192.168.1.1", 80, timeout=0.5) == ""

    def test_falls_back_to_http_probe_on_unrecognized_silent_port(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        # First recv() (passive listen) times out; second recv() (after
        # the HTTP fallback probe) returns a real response.
        fake_sock.recv.side_effect = [socket.timeout, b"HTTP/1.1 200 OK\r\nServer: mystery-iot\r\n\r\n"]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.grab_banner("192.168.1.1", 9999, timeout=0.5)

        assert "mystery-iot" in result
        fake_sock.sendall.assert_called_once()

    def test_does_not_send_http_probe_when_unrecognized_port_already_answered(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recv.return_value = b"220 example-ftp ready\r\n"

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.grab_banner("192.168.1.1", 9999, timeout=0.5)

        assert result == "220 example-ftp ready"
        fake_sock.sendall.assert_not_called()


class TestProbeTcpPort:
    def test_returns_true_when_port_accepts_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 0

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms._probe_tcp_port("192.168.1.1", 80, timeout=0.1) is True

    def test_returns_false_when_port_refuses_connection(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect_ex.return_value = 1

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms._probe_tcp_port("192.168.1.1", 80, timeout=0.1) is False


class TestFindRiskyPorts:
    def test_reports_all_open_risky_ports_not_just_the_first(self):
        def fake_probe(ip, port, timeout):
            return port in (23, 3389)

        with patch("mobile_network_scanner._probe_tcp_port", side_effect=fake_probe):
            assert ms._find_risky_ports("192.168.1.1", timeout=0.1) == [23, 3389]

    def test_returns_empty_list_when_none_open(self):
        with patch("mobile_network_scanner._probe_tcp_port", return_value=False):
            assert ms._find_risky_ports("192.168.1.1", timeout=0.1) == []


class TestAttachRiskyPorts:
    def test_fills_in_risky_ports_for_each_device(self):
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        with patch("mobile_network_scanner._find_risky_ports", return_value=[23]):
            result = ms._attach_risky_ports(devices, timeout=0.1)

        assert result[0]["risky_ports"] == [23]


class TestUseColor:
    def test_disabled_by_no_color_flag(self):
        with patch("mobile_network_scanner.sys.stdout.isatty", return_value=True), \
                patch.dict("mobile_network_scanner.os.environ", {}, clear=True):
            assert ms._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self):
        with patch("mobile_network_scanner.sys.stdout.isatty", return_value=True), \
                patch.dict("mobile_network_scanner.os.environ", {"NO_COLOR": "1"}):
            assert ms._use_color(no_color_flag=False) is False

    def test_disabled_when_stdout_is_not_a_tty(self):
        with patch("mobile_network_scanner.sys.stdout.isatty", return_value=False), \
                patch.dict("mobile_network_scanner.os.environ", {}, clear=True):
            assert ms._use_color(no_color_flag=False) is False

    def test_enabled_when_none_of_the_above_apply(self):
        with patch("mobile_network_scanner.sys.stdout.isatty", return_value=True), \
                patch.dict("mobile_network_scanner.os.environ", {}, clear=True):
            assert ms._use_color(no_color_flag=False) is True


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        result = ms._colorize("NEW", "green", enabled=True)
        assert result == f"{ms._ANSI_CODES['green']}NEW{ms._ANSI_CODES['reset']}"

    def test_returns_plain_text_when_disabled(self):
        assert ms._colorize("NEW", "green", enabled=False) == "NEW"


class TestExportResults:
    def test_writes_json_by_default(self, tmp_path):
        path = tmp_path / "scan.json"
        devices = [{"ip": "192.168.1.1", "hostname": "router.local", "port": 80, "banner": "", "risky_ports": []}]

        ms.export_results(devices, path)

        assert json.loads(path.read_text(encoding="utf-8")) == devices

    def test_writes_json_for_an_unrecognized_extension(self, tmp_path):
        path = tmp_path / "scan.txt"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        ms.export_results(devices, path)

        assert json.loads(path.read_text(encoding="utf-8")) == devices

    def test_writes_csv_when_path_ends_in_dot_csv(self, tmp_path):
        path = tmp_path / "scan.csv"
        devices = [{
            "ip": "192.168.1.1", "hostname": "router.local", "port": 80,
            "banner": "Server: nginx", "risky_ports": [23, 445],
        }]

        ms.export_results(devices, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert rows == [{
            "ip": "192.168.1.1", "hostname": "router.local", "port": "80",
            "banner": "Server: nginx", "risky_ports": "23;445",
        }]

    def test_csv_uses_empty_string_for_empty_risky_ports(self, tmp_path):
        path = tmp_path / "scan.csv"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        ms.export_results(devices, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert rows[0]["risky_ports"] == ""

    def test_csv_column_order_matches_fieldnames(self, tmp_path):
        path = tmp_path / "scan.csv"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}]

        ms.export_results(devices, path)

        header = path.read_text(encoding="utf-8").splitlines()[0]
        assert header == "ip,hostname,port,banner,risky_ports"


class TestBuildNotificationMessage:
    def test_returns_empty_string_when_nothing_to_report(self):
        message = ms._build_notification_message([], {}, {}, [], [])
        assert message == ""

    def test_includes_new_devices(self):
        devices = [{"ip": "192.168.1.1", "hostname": "phone.local"}]
        is_new = {"192.168.1.1": True}

        message = ms._build_notification_message(devices, is_new, {}, [], [])

        assert "1 new device(s):" in message
        assert "192.168.1.1  phone.local" in message

    def test_new_device_with_no_hostname_shows_placeholder(self):
        devices = [{"ip": "192.168.1.1", "hostname": ""}]
        is_new = {"192.168.1.1": True}

        message = ms._build_notification_message(devices, is_new, {}, [], [])

        assert "(no hostname)" in message

    def test_includes_port_changes(self):
        devices = [{"ip": "192.168.1.1", "hostname": ""}]
        port_changes = {"192.168.1.1": (80, 22)}

        message = ms._build_notification_message(devices, {}, port_changes, [], [])

        assert "1 device(s) with a changed port:" in message
        assert "http (80) -> ssh (22)" in message

    def test_includes_missing_devices(self):
        missing = [{"key": "192.168.1.1", "hostname": "router.local"}]

        message = ms._build_notification_message([], {}, {}, missing, [])

        assert "1 previously-seen device(s) missing:" in message
        assert "192.168.1.1 (router.local)" in message

    def test_missing_device_label_takes_priority_over_hostname(self):
        missing = [{"key": "192.168.1.1", "hostname": "router.local", "label": "Kitchen Echo"}]

        message = ms._build_notification_message([], {}, {}, missing, [])

        assert "(Kitchen Echo)" in message
        assert "router.local" not in message

    def test_includes_risky_devices(self):
        risky = [{"ip": "192.168.1.1", "risky_ports": [445, 3389]}]

        message = ms._build_notification_message([], {}, {}, [], risky)

        assert "1 device(s) exposing a risky port:" in message
        assert "smb (445), rdp (3389)" in message

    def test_combines_multiple_categories_with_blank_line_between(self):
        devices = [{"ip": "192.168.1.1", "hostname": "phone.local"}]
        is_new = {"192.168.1.1": True}
        risky = [{"ip": "192.168.1.2", "risky_ports": [23]}]

        message = ms._build_notification_message(devices, is_new, {}, [], risky)

        assert "1 new device(s):" in message
        assert "1 device(s) exposing a risky port:" in message
        assert "\n\n" in message


class TestSendWebhookNotification:
    def test_returns_true_on_a_2xx_response(self):
        fake_response = MagicMock()
        fake_response.status = 200
        fake_response.__enter__.return_value = fake_response

        with patch("mobile_network_scanner.urllib.request.urlopen", return_value=fake_response) as mock_urlopen:
            result = ms.send_webhook_notification("https://example.com/hook", "hello")

        assert result is True
        request = mock_urlopen.call_args[0][0]
        assert request.full_url == "https://example.com/hook"
        assert json.loads(request.data) == {"text": "hello"}
        assert request.get_header("Content-type") == "application/json"

    def test_returns_false_on_a_non_2xx_response(self):
        fake_response = MagicMock()
        fake_response.status = 500
        fake_response.__enter__.return_value = fake_response

        with patch("mobile_network_scanner.urllib.request.urlopen", return_value=fake_response):
            assert ms.send_webhook_notification("https://example.com/hook", "hello") is False

    def test_returns_false_and_does_not_raise_on_network_error(self):
        with patch("mobile_network_scanner.urllib.request.urlopen", side_effect=urllib.error.URLError("no route")):
            assert ms.send_webhook_notification("https://example.com/hook", "hello") is False


class TestCheckLocalSubnet:
    def test_reports_the_detected_subnet(self):
        with patch("mobile_network_scanner.get_local_subnet", return_value="192.168.1.0/24"):
            ok, detail = ms._check_local_subnet()
        assert ok is True
        assert "192.168.1.0/24" in detail

    def test_reports_failure_when_detection_raises(self):
        with patch("mobile_network_scanner.get_local_subnet", side_effect=OSError("no route")):
            ok, detail = ms._check_local_subnet()
        assert ok is False
        assert "Couldn't detect" in detail


class TestCheckTcpConnectivity:
    def test_reports_ok_when_connect_succeeds(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_tcp_connectivity()
        assert ok is True

    def test_reports_failure_when_connect_raises(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.connect.side_effect = OSError("timed out")
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_tcp_connectivity()
        assert ok is False
        assert "Couldn't open" in detail


class TestCheckCacheWritable:
    def test_reports_writable_directory(self, tmp_path):
        with patch("mobile_network_scanner.Path.home", return_value=tmp_path):
            ok, detail = ms._check_cache_writable()
        assert ok is True
        assert str(tmp_path / ".cache") in detail

    def test_reports_unwritable_directory(self, tmp_path):
        with patch("mobile_network_scanner.Path.home", return_value=tmp_path), \
                patch("mobile_network_scanner.Path.write_text", side_effect=OSError("Permission denied")):
            ok, detail = ms._check_cache_writable()
        assert ok is False
        assert "not writable" in detail


class TestCheckMdnsMulticast:
    def test_reports_ok_when_send_succeeds(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_mdns_multicast()
        assert ok is True

    def test_tolerates_bind_or_join_failure_and_still_tries_to_send(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.bind.side_effect = OSError("Address already in use")
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_mdns_multicast()
        assert ok is True
        fake_sock.sendto.assert_called_once()

    def test_reports_failure_when_send_is_denied(self):
        # The real iOS failure mode: bind/join succeed, the send itself
        # fails with OSError(65, 'No route to host').
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError(65, "No route to host")
        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ok, detail = ms._check_mdns_multicast()
        assert ok is False
        assert "Local Network Privacy" in detail


class TestRunDoctor:
    def test_returns_true_when_every_check_passes(self, capsys):
        checks = (("Check A", lambda: (True, "fine")), ("Check B", lambda: (True, "also fine")))
        with patch("mobile_network_scanner._DOCTOR_CHECKS", checks):
            assert ms.run_doctor(color=False) is True
        assert "Everything checks out." in capsys.readouterr().out

    def test_returns_false_when_any_check_fails(self, capsys):
        checks = (("Check A", lambda: (True, "fine")), ("Check B", lambda: (False, "not fine")))
        with patch("mobile_network_scanner._DOCTOR_CHECKS", checks):
            assert ms.run_doctor(color=False) is False
        out = capsys.readouterr().out
        assert "not fine" in out
        assert "Some checks reported a limitation" in out


class TestDnsNameEncoding:
    def test_round_trips_a_simple_name(self):
        encoded = ms._encode_dns_name("72.1.168.192.in-addr.arpa")
        # Decoding needs a full "message" buffer to index into, even
        # though this name has no compression pointers to jump through.
        name, offset = ms._decode_dns_name(encoded, 0)

        assert name == "72.1.168.192.in-addr.arpa"
        assert offset == len(encoded)

    def test_decodes_a_compression_pointer(self):
        # Simulates two records sharing a ".local" suffix: the first
        # spells it out at offset 0, the second just points back to it.
        suffix = ms._encode_dns_name("local")
        pointer = bytes([0xC0, 0x00])  # Pointer to offset 0.
        message = suffix + pointer

        name, offset = ms._decode_dns_name(message, len(suffix))

        assert name == "local"
        # The returned offset should be right after the 2-byte pointer,
        # not wherever the pointer jumped to.
        assert offset == len(suffix) + 2


class TestBuildMdnsPtrQuery:
    def test_builds_a_well_formed_single_question_query(self):
        query = ms._build_mdns_ptr_query("72.1.168.192.in-addr.arpa")

        header = struct.unpack(">HHHHHH", query[:12])
        assert header == (0, 0, 1, 0, 0, 0)  # ID, flags, QD/AN/NS/ARcount

        qname, offset = ms._decode_dns_name(query, 12)
        assert qname == "72.1.168.192.in-addr.arpa"

        qtype, qclass = struct.unpack(">HH", query[offset:offset + 4])
        assert qtype == ms._DNS_TYPE_PTR
        # The QU bit must be set - see _MDNS_QU_BIT's comment for why
        # this implementation depends on getting a unicast reply.
        assert qclass == ms._DNS_CLASS_IN | ms._MDNS_QU_BIT


def _build_fake_ptr_response(qname: str, answer_name: str, target: str) -> bytes:
    """Build a minimal, valid mDNS response with one PTR answer, for tests."""
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0)  # 0 questions, 1 answer
    rdata = ms._encode_dns_name(target)
    answer = (
        ms._encode_dns_name(answer_name)
        + struct.pack(">HH", ms._DNS_TYPE_PTR, ms._DNS_CLASS_IN)
        + struct.pack(">I", 120)  # TTL
        + struct.pack(">H", len(rdata))
        + rdata
    )
    return header + answer


class TestExtractPtrHostname:
    def test_extracts_hostname_from_matching_answer(self):
        qname = "72.1.168.192.in-addr.arpa"
        message = _build_fake_ptr_response(qname, qname, "Chromecast-abc123.local.")

        assert ms._extract_ptr_hostname(message, qname) == "Chromecast-abc123.local"

    def test_ignores_answer_for_a_different_name(self):
        message = _build_fake_ptr_response(
            "9.1.168.192.in-addr.arpa", "9.1.168.192.in-addr.arpa", "other-device.local."
        )

        assert ms._extract_ptr_hostname(message, "72.1.168.192.in-addr.arpa") == ""

    def test_returns_empty_string_for_garbage_input(self):
        assert ms._extract_ptr_hostname(b"\x00\x01", "72.1.168.192.in-addr.arpa") == ""


def _build_a_record(name: str, ip: str) -> bytes:
    """Build a single raw DNS A record, for tests."""
    return (
        ms._encode_dns_name(name)
        + struct.pack(">HH", ms._DNS_TYPE_A, ms._DNS_CLASS_IN)
        + struct.pack(">I", 120)  # TTL
        + struct.pack(">H", 4)  # RDLENGTH: an IPv4 address is 4 bytes
        + socket.inet_aton(ip)
    )


def _build_srv_record(instance_name: str, target: str, port: int = 8009) -> bytes:
    """Build a single raw DNS SRV record, for tests."""
    rdata = struct.pack(">HHH", 0, 0, port) + ms._encode_dns_name(target)  # priority, weight, port, target
    return (
        ms._encode_dns_name(instance_name)
        + struct.pack(">HH", ms._DNS_TYPE_SRV, ms._DNS_CLASS_IN)
        + struct.pack(">I", 120)  # TTL
        + struct.pack(">H", len(rdata))
        + rdata
    )


def _build_fake_service_response(*records: bytes, answer_count: int = 0, additional_count: int = 0) -> bytes:
    """Wrap prebuilt records in a minimal mDNS response header, for tests."""
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, answer_count, 0, additional_count)
    return header + b"".join(records)


class TestCollectServiceRecords:
    def test_collects_a_and_srv_records_regardless_of_section(self):
        a_record = _build_a_record("Chromecast-abc123.local", "192.168.1.72")
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        # A real response often splits these: SRV as an answer, its
        # supporting A record as "additional" - exercise that split.
        message = _build_fake_service_response(srv_record, a_record, answer_count=1, additional_count=1)

        host_to_ip: dict = {}
        instance_to_host: dict = {}
        ms._collect_service_records(message, host_to_ip, instance_to_host)

        assert host_to_ip == {"chromecast-abc123.local": "192.168.1.72"}
        assert instance_to_host == {"Living Room TV._googlecast._tcp.local": "chromecast-abc123.local"}

    def test_ignores_unrelated_record_types(self):
        ptr_record = _build_fake_ptr_response("x", "x", "y")  # Includes its own header - just reuse the answer bytes.
        # Strip the fake header this helper adds, since we only want the
        # record bytes to feed into _collect_service_records directly.
        message = _build_fake_service_response(ptr_record[12:], answer_count=1)

        host_to_ip: dict = {}
        instance_to_host: dict = {}
        ms._collect_service_records(message, host_to_ip, instance_to_host)

        assert host_to_ip == {}
        assert instance_to_host == {}


class TestMdnsServiceLookup:
    def test_joins_srv_and_a_records_into_ip_to_name_map(self):
        a_record = _build_a_record("Chromecast-abc123.local", "192.168.1.72")
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        response = _build_fake_service_response(srv_record, a_record, answer_count=2)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("192.168.1.72", 5353)), socket.timeout]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.2)

        assert result == {"192.168.1.72": "Living Room TV"}

    def test_combines_records_split_across_multiple_packets(self):
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        a_record = _build_a_record("Chromecast-abc123.local", "192.168.1.72")
        srv_packet = _build_fake_service_response(srv_record, answer_count=1)
        a_packet = _build_fake_service_response(a_record, answer_count=1)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(srv_packet, ("x", 5353)), (a_packet, ("x", 5353)), socket.timeout]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.2)

        assert result == {"192.168.1.72": "Living Room TV"}

    def test_omits_instance_with_no_matching_a_record(self):
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "Chromecast-abc123.local")
        response = _build_fake_service_response(srv_record, answer_count=1)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("x", 5353)), socket.timeout]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.2)

        assert result == {}

    def test_returns_empty_dict_when_nothing_answers(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.01) == {}

    def test_returns_empty_dict_when_multicast_send_is_denied(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError("Local network access denied")

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.5) == {}

    def test_binds_to_mdns_port_and_joins_the_multicast_group(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.01)

        fake_sock.bind.assert_called_once_with(("", 5353))
        join_call = next(
            call for call in fake_sock.setsockopt.call_args_list if call.args[0:2] == (socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP)
        )
        assert join_call.args[2] == struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)

    def test_still_queries_when_bind_or_group_join_fails(self):
        # A sandboxed environment (iOS) may refuse the bind/join - the
        # lookup should still send its query and listen on whatever
        # ordinary ephemeral-port socket resulted, rather than giving up.
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.bind.side_effect = OSError("Address already in use")
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            result = ms.mdns_service_lookup("_googlecast._tcp.local", timeout=0.01)

        assert result == {}
        fake_sock.sendto.assert_called_once()


class TestMdnsReverseLookup:
    def test_returns_hostname_from_first_matching_response(self):
        qname = "72.1.168.192.in-addr.arpa"
        response = _build_fake_ptr_response(qname, qname, "Chromecast-abc123.local.")

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.return_value = (response, ("192.168.1.72", 5353))

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            hostname = ms.mdns_reverse_lookup("192.168.1.72", timeout=0.5)

        assert hostname == "Chromecast-abc123.local"
        fake_sock.sendto.assert_called_once()
        assert fake_sock.sendto.call_args[0][1] == ms._MDNS_GROUP

    def test_skips_irrelevant_packets_before_the_matching_one(self):
        qname = "72.1.168.192.in-addr.arpa"
        unrelated = _build_fake_ptr_response("9.1.168.192.in-addr.arpa", "9.1.168.192.in-addr.arpa", "other.local.")
        matching = _build_fake_ptr_response(qname, qname, "Chromecast-abc123.local.")

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(unrelated, ("x", 5353)), (matching, ("x", 5353))]

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_reverse_lookup("192.168.1.72", timeout=0.5) == "Chromecast-abc123.local"

    def test_returns_empty_string_on_timeout(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_reverse_lookup("192.168.1.72", timeout=0.01) == ""

    def test_returns_empty_string_when_multicast_send_is_denied(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError("Local network access denied")

        with patch("mobile_network_scanner.socket.socket", return_value=fake_sock):
            assert ms.mdns_reverse_lookup("192.168.1.72", timeout=0.5) == ""


class TestResolveHostname:
    def test_prefers_reverse_dns_when_available(self):
        with patch("mobile_network_scanner.socket.gethostbyaddr", return_value=("nas.local", [], [])), \
                patch("mobile_network_scanner.mdns_reverse_lookup") as mock_mdns:
            assert ms._resolve_hostname("192.168.1.157", mdns_timeout=0.3) == "nas.local"

        mock_mdns.assert_not_called()

    def test_falls_back_to_mdns_when_reverse_dns_fails(self):
        with patch("mobile_network_scanner.socket.gethostbyaddr", side_effect=socket.herror), \
                patch("mobile_network_scanner.mdns_reverse_lookup", return_value="Chromecast-abc123.local") as mock_mdns:
            assert ms._resolve_hostname("192.168.1.72", mdns_timeout=0.3) == "Chromecast-abc123.local"

        mock_mdns.assert_called_once_with("192.168.1.72", timeout=0.3)


class TestTcpScan:
    def test_returns_only_live_hosts_sorted_by_ip(self):
        def fake_probe(ip, ports, timeout):
            return 80 if ip in ("192.168.1.2", "192.168.1.10") else None

        with patch("mobile_network_scanner.probe_host", side_effect=fake_probe), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/28", timeout=0.1, max_workers=8)

        ips = [d["ip"] for d in devices]
        assert ips == sorted(ips, key=lambda ip: tuple(int(p) for p in ip.split(".")))
        assert set(ips) == {"192.168.1.2", "192.168.1.10"}

    def test_attaches_hostname_and_matched_port_when_available(self):
        # Port 80, not 8009 (the Chromecast port), so this doesn't also
        # trigger the Cast-service-discovery path - see TestTcpScan's
        # cast-specific tests below for that.
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value="phone.local"):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert {
            "ip": "192.168.1.1", "hostname": "phone.local", "port": 80, "banner": "", "risky_ports": [],
        } in devices

    def test_falls_back_to_mdns_when_reverse_dns_has_no_hostname(self):
        # Exercises the real _resolve_hostname (not mocked out), so this
        # confirms tcp_scan actually wires the mDNS fallback in, not just
        # that _resolve_hostname works in isolation. Port 80 avoids also
        # triggering Cast service discovery (tested separately below).
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner.socket.gethostbyaddr", side_effect=socket.gaierror), \
                patch("mobile_network_scanner.mdns_reverse_lookup", return_value="some-device.local"):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, mdns_timeout=0.2)

        assert all(d["hostname"] == "some-device.local" for d in devices)

    def test_uses_cast_service_name_when_chromecast_port_matches(self):
        with patch("mobile_network_scanner.probe_host", return_value=8009), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner.mdns_service_lookup", return_value={"192.168.1.1": "Living Room TV"}), \
                patch("mobile_network_scanner._resolve_hostname", return_value="should-not-be-used"):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, mdns_timeout=0.2)

        assert {
            "ip": "192.168.1.1", "hostname": "Living Room TV", "port": 8009, "banner": "", "risky_ports": [],
        } in devices

    def test_falls_back_to_resolve_hostname_when_cast_lookup_has_no_name_for_ip(self):
        # mdns_service_lookup() might name some Cast devices on the
        # subnet but not this particular one (e.g. its A record arrived
        # too late) - it should still get a chance via the normal path.
        with patch("mobile_network_scanner.probe_host", return_value=8009), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner.mdns_service_lookup", return_value={}), \
                patch("mobile_network_scanner._resolve_hostname", return_value="fallback.local"):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, mdns_timeout=0.2)

        assert all(d["hostname"] == "fallback.local" for d in devices)

    def test_skips_cast_lookup_when_no_chromecast_port_present(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner.mdns_service_lookup") as mock_cast_lookup, \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        mock_cast_lookup.assert_not_called()

    def test_missing_hostname_defaults_to_empty_string(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
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

    def test_attaches_banner_from_grab_banner_for_each_matched_port(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value="Server: lighttpd"), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert all(d["banner"] == "Server: lighttpd" for d in devices)

    def test_grab_banner_called_with_each_device_matched_port(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value="") as mock_grab_banner, \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        mock_grab_banner.assert_any_call("192.168.1.1", 80, 0.1)
        mock_grab_banner.assert_any_call("192.168.1.2", 80, 0.1)
        assert mock_grab_banner.call_count == 2

    def test_skips_banner_grabbing_when_disabled(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner") as mock_grab_banner, \
                patch("mobile_network_scanner._find_risky_ports", return_value=[]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, grab_banners=False)

        mock_grab_banner.assert_not_called()
        assert all(d["banner"] == "" for d in devices)

    def test_attaches_risky_ports_from_find_risky_ports(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports", return_value=[23, 445]), \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4)

        assert all(d["risky_ports"] == [23, 445] for d in devices)

    def test_skips_risky_port_check_when_disabled(self):
        with patch("mobile_network_scanner.probe_host", return_value=80), \
                patch("mobile_network_scanner.grab_banner", return_value=""), \
                patch("mobile_network_scanner._find_risky_ports") as mock_find_risky_ports, \
                patch("mobile_network_scanner._resolve_hostname", return_value=""):
            devices = ms.tcp_scan("192.168.1.0/30", timeout=0.1, max_workers=4, check_risky_ports=False)

        mock_find_risky_ports.assert_not_called()
        assert all(d["risky_ports"] == [] for d in devices)


class TestScanAllSubnets:
    def test_merges_devices_from_every_subnet(self):
        def fake_tcp_scan(subnet, timeout, ports, max_workers, mdns_timeout, grab_banners, check_risky_ports):
            return {
                "192.168.1.0/24": [
                    {"ip": "192.168.1.5", "hostname": "", "port": 80, "banner": "", "risky_ports": []}
                ],
                "10.0.0.0/24": [
                    {"ip": "10.0.0.9", "hostname": "nas.local", "port": 445, "banner": "", "risky_ports": []}
                ],
            }[subnet]

        with patch("mobile_network_scanner.tcp_scan", side_effect=fake_tcp_scan):
            devices = ms.scan_all_subnets(["192.168.1.0/24", "10.0.0.0/24"], timeout=0.1)

        assert [d["ip"] for d in devices] == ["10.0.0.9", "192.168.1.5"]

    def test_deduplicates_by_ip_across_overlapping_subnets(self):
        with patch("mobile_network_scanner.tcp_scan", return_value=[{"ip": "192.168.1.5", "hostname": "", "port": 80}]):
            devices = ms.scan_all_subnets(["192.168.1.0/24", "192.168.1.0/24"], timeout=0.1)

        assert len(devices) == 1

    def test_empty_subnet_list_returns_empty(self):
        with patch("mobile_network_scanner.tcp_scan") as mock_tcp_scan:
            assert ms.scan_all_subnets([], timeout=0.1) == []
        mock_tcp_scan.assert_not_called()


class TestDeviceIdentity:
    def test_uses_ip_as_the_identity(self):
        device = {"ip": "192.168.1.72", "hostname": "", "port": 8009}
        assert ms._device_identity(device) == "192.168.1.72"


class TestKnownDevicesPersistence:
    def test_load_returns_empty_dict_when_file_does_not_exist(self, tmp_path):
        assert ms._load_known_devices(tmp_path / "missing.json") == {}

    def test_load_returns_empty_dict_for_corrupt_json(self, tmp_path):
        path = tmp_path / "known.json"
        path.write_text("not valid json {{{", encoding="utf-8")
        assert ms._load_known_devices(path) == {}

    def test_save_then_load_round_trips(self, tmp_path):
        path = tmp_path / "nested" / "known.json"
        data = {"192.168.1.1": {"port": 80, "first_seen": "2026-01-01T00:00:00"}}

        ms._save_known_devices(data, path)

        assert ms._load_known_devices(path) == data

    def test_save_does_not_raise_on_unwritable_path(self, tmp_path):
        with patch("mobile_network_scanner.Path.mkdir", side_effect=OSError("Permission denied")):
            ms._save_known_devices({}, tmp_path / "known.json")  # Should not raise.


class TestMarkNewDevices:
    def test_first_time_seen_devices_are_all_new(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [
            {"ip": "192.168.1.1", "hostname": "router.local", "port": 80},
            {"ip": "192.168.1.72", "hostname": "", "port": 8009},
        ]

        is_new = ms._mark_new_devices(devices, known_devices_path=path)

        assert is_new == {"192.168.1.1": True, "192.168.1.72": True}

    def test_previously_seen_devices_are_not_new_on_a_later_scan(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.1", "hostname": "router.local", "port": 80}]

        ms._mark_new_devices(devices, known_devices_path=path)
        is_new = ms._mark_new_devices(devices, known_devices_path=path)

        assert is_new == {"192.168.1.1": False}

    def test_only_the_genuinely_new_device_is_flagged(self, tmp_path):
        path = tmp_path / "known.json"
        known_device = {"ip": "192.168.1.1", "hostname": "router.local", "port": 80}
        new_device = {"ip": "192.168.1.99", "hostname": "", "port": 8009}

        ms._mark_new_devices([known_device], known_devices_path=path)
        is_new = ms._mark_new_devices([known_device, new_device], known_devices_path=path)

        assert is_new == {"192.168.1.1": False, "192.168.1.99": True}

    def test_persists_device_details_and_timestamps(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.72", "hostname": "Living Room TV", "port": 8009}]

        ms._mark_new_devices(devices, known_devices_path=path)

        stored = ms._load_known_devices(path)["192.168.1.72"]
        assert stored["port"] == 8009
        assert stored["hostname"] == "Living Room TV"
        assert "first_seen" in stored
        assert "last_seen" in stored


class TestFindPortChanges:
    def test_reports_devices_whose_port_differs_from_the_registry(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}
        ms._mark_new_devices([device], known_devices_path=path)

        changed_device = dict(device, port=23)
        changes = ms._find_port_changes([changed_device], known_devices_path=path)

        assert changes == {"192.168.1.1": (80, 23)}

    def test_ignores_devices_with_an_unchanged_port(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "", "port": 80, "banner": "", "risky_ports": []}
        ms._mark_new_devices([device], known_devices_path=path)

        assert ms._find_port_changes([device], known_devices_path=path) == {}

    def test_a_brand_new_device_is_not_reported_as_a_port_change(self, tmp_path):
        path = tmp_path / "known.json"
        new_device = {"ip": "192.168.1.99", "hostname": "", "port": 80, "banner": "", "risky_ports": []}

        assert ms._find_port_changes([new_device], known_devices_path=path) == {}


class TestFindMissingDevices:
    def test_empty_registry_reports_nothing_missing(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [{"ip": "192.168.1.1", "hostname": "", "port": 80}]

        assert ms._find_missing_devices(devices, known_devices_path=path) == []

    def test_device_absent_from_this_scan_is_reported_missing(self, tmp_path):
        path = tmp_path / "known.json"
        router = {"ip": "192.168.1.1", "hostname": "router.local", "port": 80}
        chromecast = {"ip": "192.168.1.72", "hostname": "Living Room TV", "port": 8009}

        ms._mark_new_devices([router, chromecast], known_devices_path=path)

        missing = ms._find_missing_devices([router], known_devices_path=path)  # Chromecast unplugged.

        assert len(missing) == 1
        assert missing[0]["key"] == "192.168.1.72"
        assert missing[0]["hostname"] == "Living Room TV"

    def test_device_present_in_this_scan_is_not_reported_missing(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "", "port": 80}

        ms._mark_new_devices([device], known_devices_path=path)

        assert ms._find_missing_devices([device], known_devices_path=path) == []

    def test_results_are_sorted_by_identity_key(self, tmp_path):
        path = tmp_path / "known.json"
        devices = [
            {"ip": "192.168.1.9", "hostname": "", "port": 80},
            {"ip": "192.168.1.2", "hostname": "", "port": 80},
        ]

        ms._mark_new_devices(devices, known_devices_path=path)

        missing = ms._find_missing_devices([], known_devices_path=path)

        assert [entry["key"] for entry in missing] == ["192.168.1.2", "192.168.1.9"]


class TestSetLabel:
    def test_sets_label_on_an_existing_device(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "", "port": 80}
        ms._mark_new_devices([device], known_devices_path=path)

        ms._set_label("192.168.1.1", "Kitchen Echo", known_devices_path=path)

        stored = ms._load_known_devices(path)["192.168.1.1"]
        assert stored["label"] == "Kitchen Echo"

    def test_creates_a_minimal_entry_for_an_unseen_device(self, tmp_path):
        path = tmp_path / "known.json"

        ms._set_label("192.168.1.99", "Guest Phone", known_devices_path=path)

        stored = ms._load_known_devices(path)["192.168.1.99"]
        assert stored["label"] == "Guest Phone"

    def test_does_not_disturb_other_registry_fields(self, tmp_path):
        path = tmp_path / "known.json"
        device = {"ip": "192.168.1.1", "hostname": "router.local", "port": 80}
        ms._mark_new_devices([device], known_devices_path=path)

        ms._set_label("192.168.1.1", "Router", known_devices_path=path)

        stored = ms._load_known_devices(path)["192.168.1.1"]
        assert stored["hostname"] == "router.local"
        assert "first_seen" in stored


class TestRemoveLabel:
    def test_removes_an_existing_label(self, tmp_path):
        path = tmp_path / "known.json"
        ms._set_label("192.168.1.1", "Kitchen Echo", known_devices_path=path)

        ms._remove_label("192.168.1.1", known_devices_path=path)

        assert "label" not in ms._load_known_devices(path)["192.168.1.1"]

    def test_does_not_raise_for_an_unknown_device(self, tmp_path):
        path = tmp_path / "known.json"
        ms._remove_label("192.168.1.99", known_devices_path=path)  # Should not raise.

    def test_does_not_raise_for_a_device_with_no_label(self, tmp_path):
        path = tmp_path / "known.json"
        ms._mark_new_devices([{"ip": "192.168.1.1", "hostname": "", "port": 80}], known_devices_path=path)
        ms._remove_label("192.168.1.1", known_devices_path=path)  # Should not raise.


class TestLoadLabels:
    def test_returns_only_devices_with_a_label_set(self, tmp_path):
        path = tmp_path / "known.json"
        ms._mark_new_devices(
            [
                {"ip": "192.168.1.1", "hostname": "", "port": 80},
                {"ip": "192.168.1.2", "hostname": "", "port": 80},
            ],
            known_devices_path=path,
        )
        ms._set_label("192.168.1.1", "Kitchen Echo", known_devices_path=path)

        assert ms._load_labels(known_devices_path=path) == {"192.168.1.1": "Kitchen Echo"}

    def test_returns_empty_dict_when_no_labels_are_set(self, tmp_path):
        path = tmp_path / "known.json"
        ms._mark_new_devices([{"ip": "192.168.1.1", "hostname": "", "port": 80}], known_devices_path=path)

        assert ms._load_labels(known_devices_path=path) == {}


class TestDisplayHostname:
    def test_returns_bare_hostname_when_no_label_is_set(self):
        assert ms._display_hostname("router.local", "") == "router.local"

    def test_returns_label_when_no_hostname_is_set(self):
        assert ms._display_hostname("", "Kitchen Echo") == "Kitchen Echo"

    def test_combines_both_when_they_differ(self):
        assert ms._display_hostname("Chromecast-abc123.local", "Living Room TV") == \
            "Living Room TV (Chromecast-abc123.local)"

    def test_returns_just_the_label_when_they_are_identical(self):
        assert ms._display_hostname("router.local", "router.local") == "router.local"

    def test_returns_empty_string_when_neither_is_set(self):
        assert ms._display_hostname("", "") == ""
