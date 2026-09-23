import csv
import json
import socket
import struct
from unittest.mock import MagicMock, patch

import mdns_browser as mb


class TestBuildMdnsPtrQuery:
    def test_builds_a_well_formed_single_question_query(self):
        query = mb._build_mdns_ptr_query("_googlecast._tcp.local")

        header = struct.unpack(">HHHHHH", query[:12])
        assert header == (0, 0, 1, 0, 0, 0)

        qname, offset = mb._decode_dns_name(query, 12)
        assert qname == "_googlecast._tcp.local"

        qtype, qclass = struct.unpack(">HH", query[offset:offset + 4])
        assert qtype == mb._DNS_TYPE_PTR
        assert qclass == mb._DNS_CLASS_IN | mb._MDNS_QU_BIT


def _build_ptr_record(qname: str, target: str) -> bytes:
    rdata = mb._encode_dns_name(target)
    return (
        mb._encode_dns_name(qname)
        + struct.pack(">HH", mb._DNS_TYPE_PTR, mb._DNS_CLASS_IN)
        + struct.pack(">I", 120)
        + struct.pack(">H", len(rdata))
        + rdata
    )


def _build_a_record(name: str, ip: str) -> bytes:
    return (
        mb._encode_dns_name(name)
        + struct.pack(">HH", mb._DNS_TYPE_A, mb._DNS_CLASS_IN)
        + struct.pack(">I", 120)
        + struct.pack(">H", 4)
        + socket.inet_aton(ip)
    )


def _build_srv_record(instance_name: str, target: str, port: int = 1234) -> bytes:
    rdata = struct.pack(">HHH", 0, 0, port) + mb._encode_dns_name(target)
    return (
        mb._encode_dns_name(instance_name)
        + struct.pack(">HH", mb._DNS_TYPE_SRV, mb._DNS_CLASS_IN)
        + struct.pack(">I", 120)
        + struct.pack(">H", len(rdata))
        + rdata
    )


def _build_fake_response(*records: bytes, answer_count: int = 0) -> bytes:
    header = struct.pack(">HHHHHH", 0, 0x8400, 0, answer_count, 0, 0)
    return header + b"".join(records)


class TestDiscoverServiceTypes:
    def test_collects_distinct_service_types_from_ptr_answers(self):
        response = _build_fake_response(
            _build_ptr_record(mb._DNS_SD_META_QUERY, "_googlecast._tcp.local"),
            _build_ptr_record(mb._DNS_SD_META_QUERY, "_ipp._tcp.local"),
            answer_count=2,
        )
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("x", 5353)), socket.timeout]

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            result = mb.discover_service_types(timeout=0.2)

        assert result == ["_googlecast._tcp.local", "_ipp._tcp.local"]

    def test_deduplicates_repeated_service_types(self):
        response = _build_fake_response(
            _build_ptr_record(mb._DNS_SD_META_QUERY, "_ipp._tcp.local"),
            _build_ptr_record(mb._DNS_SD_META_QUERY, "_ipp._tcp.local"),
            answer_count=2,
        )
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("x", 5353)), socket.timeout]

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            result = mb.discover_service_types(timeout=0.2)

        assert result == ["_ipp._tcp.local"]

    def test_ignores_ptr_answers_for_unrelated_names(self):
        response = _build_fake_response(
            _build_ptr_record("_googlecast._tcp.local", "Living Room TV._googlecast._tcp.local"),
            answer_count=1,
        )
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("x", 5353)), socket.timeout]

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            result = mb.discover_service_types(timeout=0.2)

        assert result == []

    def test_returns_empty_list_when_nothing_answers(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            assert mb.discover_service_types(timeout=0.01) == []

    def test_returns_empty_list_when_multicast_send_is_denied(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError("Local network access denied")

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            assert mb.discover_service_types(timeout=0.5) == []


class TestBrowseServices:
    def test_joins_srv_and_a_records_into_ip_to_name_map(self):
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "chromecast.local")
        a_record = _build_a_record("chromecast.local", "192.168.1.72")
        response = _build_fake_response(srv_record, a_record, answer_count=2)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("192.168.1.72", 5353)), socket.timeout]

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            result = mb.browse_services(["_googlecast._tcp.local"], timeout=0.2)

        assert result == {"_googlecast._tcp.local": {"192.168.1.72": "Living Room TV"}}

    def test_sends_one_query_per_service_type(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            mb.browse_services(["_googlecast._tcp.local", "_ipp._tcp.local"], timeout=0.01)

        assert fake_sock.sendto.call_count == 2

    def test_attributes_each_instance_to_the_correct_service_type(self):
        cast_srv = _build_srv_record("Living Room TV._googlecast._tcp.local", "chromecast.local")
        cast_a = _build_a_record("chromecast.local", "192.168.1.72")
        printer_srv = _build_srv_record("Office Printer._ipp._tcp.local", "printer.local")
        printer_a = _build_a_record("printer.local", "192.168.1.80")
        response = _build_fake_response(cast_srv, cast_a, printer_srv, printer_a, answer_count=4)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("x", 5353)), socket.timeout]

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            result = mb.browse_services(["_googlecast._tcp.local", "_ipp._tcp.local"], timeout=0.2)

        assert result == {
            "_googlecast._tcp.local": {"192.168.1.72": "Living Room TV"},
            "_ipp._tcp.local": {"192.168.1.80": "Office Printer"},
        }

    def test_missing_service_type_has_an_empty_dict_not_a_missing_key(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            result = mb.browse_services(["_googlecast._tcp.local"], timeout=0.01)

        assert result == {"_googlecast._tcp.local": {}}

    def test_omits_instance_with_no_matching_a_record(self):
        srv_record = _build_srv_record("Living Room TV._googlecast._tcp.local", "chromecast.local")
        response = _build_fake_response(srv_record, answer_count=1)

        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = [(response, ("x", 5353)), socket.timeout]

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            result = mb.browse_services(["_googlecast._tcp.local"], timeout=0.2)

        assert result == {"_googlecast._tcp.local": {}}

    def test_returns_empty_dicts_when_multicast_send_is_denied(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.sendto.side_effect = OSError("Local network access denied")

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            result = mb.browse_services(["_googlecast._tcp.local", "_ipp._tcp.local"], timeout=0.5)

        assert result == {"_googlecast._tcp.local": {}, "_ipp._tcp.local": {}}

    def test_binds_to_mdns_port_and_joins_the_multicast_group(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            mb.browse_services(["_googlecast._tcp.local"], timeout=0.01)

        fake_sock.bind.assert_called_once_with(("", 5353))
        join_call = next(
            call for call in fake_sock.setsockopt.call_args_list if call.args[0:2] == (socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP)
        )
        assert join_call.args[2] == struct.pack("4sl", socket.inet_aton("224.0.0.251"), socket.INADDR_ANY)

    def test_still_queries_when_bind_or_group_join_fails(self):
        fake_sock = MagicMock()
        fake_sock.__enter__.return_value = fake_sock
        fake_sock.bind.side_effect = OSError("Address already in use")
        fake_sock.recvfrom.side_effect = socket.timeout

        with patch("mdns_browser.socket.socket", return_value=fake_sock):
            result = mb.browse_services(["_googlecast._tcp.local"], timeout=0.01)

        assert result == {"_googlecast._tcp.local": {}}
        fake_sock.sendto.assert_called_once()


class TestExportResults:
    def test_writes_json_by_default(self, tmp_path):
        path = tmp_path / "services.json"
        results = {"_googlecast._tcp.local": {"192.168.1.72": "Living Room TV"}}

        mb.export_results(results, path)

        data = json.loads(path.read_text(encoding="utf-8"))
        assert data == [{"service_type": "_googlecast._tcp.local", "ip": "192.168.1.72", "name": "Living Room TV"}]

    def test_writes_csv_when_extension_is_csv(self, tmp_path):
        path = tmp_path / "services.csv"
        results = {"_ipp._tcp.local": {"192.168.1.80": "Office Printer"}}

        mb.export_results(results, path)

        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert rows == [{"service_type": "_ipp._tcp.local", "ip": "192.168.1.80", "name": "Office Printer"}]

    def test_empty_results_writes_an_empty_list(self, tmp_path):
        path = tmp_path / "services.json"

        mb.export_results({"_googlecast._tcp.local": {}}, path)

        assert json.loads(path.read_text(encoding="utf-8")) == []


class TestUseColor:
    def test_disabled_by_flag(self):
        assert mb._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert mb._use_color(no_color_flag=False) is False

    def test_disabled_when_not_a_tty(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        with patch("mdns_browser.sys.stdout.isatty", return_value=False):
            assert mb._use_color(no_color_flag=False) is False

    def test_enabled_when_a_tty_and_nothing_disables_it(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        with patch("mdns_browser.sys.stdout.isatty", return_value=True):
            assert mb._use_color(no_color_flag=False) is True


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        result = mb._colorize("hello", "cyan", True)
        assert result == f"{mb._ANSI_CODES['cyan']}hello{mb._ANSI_CODES['reset']}"

    def test_returns_text_unchanged_when_disabled(self):
        assert mb._colorize("hello", "cyan", False) == "hello"
