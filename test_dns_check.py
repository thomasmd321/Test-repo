import socket
import struct
import threading
from unittest.mock import patch

import pytest

import dns_check as dc


# --- Wire-format helpers ---

class TestEncodeDecodeDnsName:
    def test_round_trips_a_simple_name(self):
        encoded = dc._encode_dns_name("example.com")
        message = b"\x00" * 12 + encoded  # pad so offset 12 lines up like a real message

        name, offset = dc._decode_dns_name(message, 12)

        assert name == "example.com"
        assert offset == 12 + len(encoded)

    def test_decodes_a_compression_pointer(self):
        # Name at offset 12 is "example.com"; a second name at a later
        # offset is just a pointer back to it.
        first = dc._encode_dns_name("example.com")
        pointer = struct.pack(">H", 0xC000 | 12)
        message = b"\x00" * 12 + first + pointer

        name, offset = dc._decode_dns_name(message, 12 + len(first))

        assert name == "example.com"
        assert offset == 12 + len(first) + 2  # resumes right after the 2-byte pointer


class TestBuildDnsQuery:
    def test_sets_recursion_desired_and_one_question(self):
        query = dc._build_dns_query("example.com", txid=0x1234, qtype=dc._DNS_TYPE_A)

        txid, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", query[:12])
        assert txid == 0x1234
        assert flags & 0x0100  # RD bit
        assert qdcount == 1
        assert ancount == nscount == arcount == 0

        name, offset = dc._decode_dns_name(query, 12)
        assert name == "example.com"
        qtype, qclass = struct.unpack(">HH", query[offset:offset + 4])
        assert qtype == dc._DNS_TYPE_A
        assert qclass == dc._DNS_CLASS_IN


def _build_response(txid, rcode, qname="example.com", answers=()):
    flags = 0x8000 | rcode  # QR=1 (response)
    header = struct.pack(">HHHHHH", txid, flags, 1, len(answers), 0, 0)
    question = dc._encode_dns_name(qname) + struct.pack(">HH", dc._DNS_TYPE_A, dc._DNS_CLASS_IN)
    records = b""
    for ip in answers:
        rdata = bytes(int(p) for p in ip.split("."))
        records += dc._encode_dns_name(qname) + struct.pack(">HHIH", dc._DNS_TYPE_A, dc._DNS_CLASS_IN, 60, 4) + rdata
    return header + question + records


class TestParseDnsResponse:
    def test_parses_a_noerror_reply_with_one_answer(self):
        response = _build_response(0x1234, rcode=0, answers=["93.184.216.34"])

        result = dc._parse_dns_response(response, expected_txid=0x1234)

        assert result == {"rcode": 0, "answers": ["93.184.216.34"]}

    def test_parses_an_nxdomain_reply_with_no_answers(self):
        response = _build_response(0x1234, rcode=dc._RCODE_NXDOMAIN, answers=[])

        result = dc._parse_dns_response(response, expected_txid=0x1234)

        assert result == {"rcode": dc._RCODE_NXDOMAIN, "answers": []}

    def test_rejects_a_mismatched_transaction_id(self):
        response = _build_response(0x1234, rcode=0, answers=["1.2.3.4"])

        assert dc._parse_dns_response(response, expected_txid=0x9999) is None

    def test_rejects_a_message_with_the_query_bit_set_not_response(self):
        header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)  # QR bit unset - this is a query, not a reply
        question = dc._encode_dns_name("example.com") + struct.pack(">HH", dc._DNS_TYPE_A, dc._DNS_CLASS_IN)

        assert dc._parse_dns_response(header + question, expected_txid=0x1234) is None

    def test_rejects_too_short_data(self):
        assert dc._parse_dns_response(b"\x01\x02", expected_txid=0x1234) is None

    def test_handles_a_compressed_name_in_the_answer_record(self):
        txid = 0x1234
        flags = 0x8000
        header = struct.pack(">HHHHHH", txid, flags, 1, 1, 0, 0)
        question = dc._encode_dns_name("example.com") + struct.pack(">HH", dc._DNS_TYPE_A, dc._DNS_CLASS_IN)
        pointer = struct.pack(">H", 0xC000 | 12)  # answer's NAME is a pointer back to the question name
        answer = pointer + struct.pack(">HHIH", dc._DNS_TYPE_A, dc._DNS_CLASS_IN, 60, 4) + bytes([93, 184, 216, 34])

        result = dc._parse_dns_response(header + question + answer, expected_txid=txid)

        assert result == {"rcode": 0, "answers": ["93.184.216.34"]}

    def test_keeps_answers_parsed_before_a_truncated_record(self):
        txid = 0x1234
        header = struct.pack(">HHHHHH", txid, 0x8000, 1, 2, 0, 0)
        question = dc._encode_dns_name("example.com") + struct.pack(">HH", dc._DNS_TYPE_A, dc._DNS_CLASS_IN)
        good_answer = dc._encode_dns_name("example.com") + struct.pack(">HHIH", dc._DNS_TYPE_A, dc._DNS_CLASS_IN, 60, 4) + bytes([1, 2, 3, 4])
        truncated = dc._encode_dns_name("example.com") + struct.pack(">HHIH", dc._DNS_TYPE_A, dc._DNS_CLASS_IN, 60, 4)  # missing the actual 4 rdata bytes

        result = dc._parse_dns_response(header + question + good_answer + truncated, expected_txid=txid)

        assert result == {"rcode": 0, "answers": ["1.2.3.4"]}


# --- Real, unmocked UDP DNS server for query_resolver() end-to-end tests ---

def _run_fake_dns_server(respond, num_requests=1, timeout=2.0):
    """Bind a real UDP socket on an OS-assigned loopback port and answer up to num_requests queries with respond(qname) -> (rcode, [ip, ...]).

    Returns the port to send queries to; the server thread stops itself
    once num_requests have been handled (or timeout elapses without one).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(timeout)
    port = sock.getsockname()[1]

    def serve():
        try:
            for _ in range(num_requests):
                try:
                    data, addr = sock.recvfrom(4096)
                except socket.timeout:
                    return
                txid = struct.unpack(">H", data[:2])[0]
                qname, _offset = dc._decode_dns_name(data, 12)
                rcode, answers = respond(qname)
                sock.sendto(_build_response(txid, rcode, qname, answers), addr)
        finally:
            sock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return port, thread


class TestQueryResolver:
    def test_parses_a_real_noerror_reply_over_a_real_socket(self):
        port, thread = _run_fake_dns_server(lambda qname: (0, ["93.184.216.34"]))

        result = dc.query_resolver("127.0.0.1", "example.com", timeout=1.0, port=port)

        thread.join(timeout=2)
        assert result == {"rcode": 0, "answers": ["93.184.216.34"]}

    def test_parses_a_real_nxdomain_reply_over_a_real_socket(self):
        canary = "dns-check-abc123.invalid"
        port, thread = _run_fake_dns_server(lambda qname: (dc._RCODE_NXDOMAIN, []))

        result = dc.query_resolver("127.0.0.1", canary, timeout=1.0, port=port)

        thread.join(timeout=2)
        assert result == {"rcode": dc._RCODE_NXDOMAIN, "answers": []}

    def test_raises_on_timeout_when_nothing_answers(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        # Bound but never reads/replies - the query should just time out.

        with pytest.raises(RuntimeError, match="did not respond"):
            dc.query_resolver("127.0.0.1", "example.com", timeout=0.2, port=port)

        sock.close()


# --- Orchestration logic (mocked query_resolver/resolve_locally - the wire format itself is covered above) ---

class TestCheckNxdomainHijack:
    def test_reports_no_hijack_when_everything_returns_nxdomain(self):
        with patch.object(dc, "resolve_locally", return_value=None), \
             patch.object(dc, "query_resolver", return_value={"rcode": dc._RCODE_NXDOMAIN, "answers": []}):
            result = dc.check_nxdomain_hijack({"Cloudflare": "1.1.1.1"})

        assert result["local"]["hijacked"] is False
        assert result["resolvers"]["Cloudflare"]["hijacked"] is False

    def test_flags_the_local_resolver_when_it_answers_the_canary(self):
        with patch.object(dc, "resolve_locally", return_value=["10.0.0.1"]), \
             patch.object(dc, "query_resolver", return_value={"rcode": dc._RCODE_NXDOMAIN, "answers": []}):
            result = dc.check_nxdomain_hijack({"Cloudflare": "1.1.1.1"})

        assert result["local"]["hijacked"] is True
        assert "10.0.0.1" in result["local"]["detail"]

    def test_flags_a_public_resolver_that_answers_the_canary(self):
        with patch.object(dc, "resolve_locally", return_value=None), \
             patch.object(dc, "query_resolver", return_value={"rcode": 0, "answers": ["203.0.113.5"]}):
            result = dc.check_nxdomain_hijack({"Cloudflare": "1.1.1.1"})

        assert result["resolvers"]["Cloudflare"]["hijacked"] is True

    def test_an_unreachable_public_resolver_is_not_treated_as_hijacked(self):
        with patch.object(dc, "resolve_locally", return_value=None), \
             patch.object(dc, "query_resolver", side_effect=RuntimeError("boom")):
            result = dc.check_nxdomain_hijack({"Cloudflare": "1.1.1.1"})

        assert result["resolvers"]["Cloudflare"]["hijacked"] is False
        assert result["resolvers"]["Cloudflare"]["error"] == "boom"

    def test_canary_hostname_is_under_the_invalid_tld(self):
        with patch.object(dc, "resolve_locally", return_value=None), \
             patch.object(dc, "query_resolver", return_value={"rcode": dc._RCODE_NXDOMAIN, "answers": []}):
            result = dc.check_nxdomain_hijack({})

        assert result["canary"].endswith(".invalid")


class TestCheckResolverAgreement:
    def test_reports_no_mismatch_when_everyone_agrees(self):
        with patch.object(dc, "resolve_locally", return_value=["93.184.216.34"]), \
             patch.object(dc, "query_resolver", return_value={"rcode": 0, "answers": ["93.184.216.34"]}):
            result = dc.check_resolver_agreement({"Cloudflare": "1.1.1.1"})

        assert result["local"] == ["93.184.216.34"]
        assert result["resolvers"]["Cloudflare"]["answers"] == ["93.184.216.34"]

    def test_a_different_answer_is_still_reported_not_hidden(self):
        with patch.object(dc, "resolve_locally", return_value=["10.0.0.1"]), \
             patch.object(dc, "query_resolver", return_value={"rcode": 0, "answers": ["93.184.216.34"]}):
            result = dc.check_resolver_agreement({"Cloudflare": "1.1.1.1"})

        assert result["local"] == ["10.0.0.1"]
        assert result["resolvers"]["Cloudflare"]["answers"] == ["93.184.216.34"]

    def test_records_an_error_for_an_unreachable_resolver(self):
        with patch.object(dc, "resolve_locally", return_value=[]), \
             patch.object(dc, "query_resolver", side_effect=RuntimeError("unreachable")):
            result = dc.check_resolver_agreement({"Cloudflare": "1.1.1.1"})

        assert result["resolvers"]["Cloudflare"]["answers"] == []
        assert result["resolvers"]["Cloudflare"]["error"] == "unreachable"


class TestResolveLocally:
    def test_returns_sorted_unique_addresses(self):
        infos = [
            (socket.AF_INET, None, None, "", ("1.2.3.4", 0)),
            (socket.AF_INET, None, None, "", ("1.2.3.4", 0)),
            (socket.AF_INET, None, None, "", ("5.6.7.8", 0)),
        ]
        with patch.object(socket, "getaddrinfo", return_value=infos):
            result = dc.resolve_locally("example.com")

        assert result == ["1.2.3.4", "5.6.7.8"]

    def test_returns_none_on_gaierror(self):
        with patch.object(socket, "getaddrinfo", side_effect=socket.gaierror("nope")):
            assert dc.resolve_locally("nonexistent.invalid") is None

    def test_restores_the_previous_default_timeout(self):
        socket.setdefaulttimeout(None)
        with patch.object(socket, "getaddrinfo", return_value=[]):
            dc.resolve_locally("example.com", timeout=1.5)

        assert socket.getdefaulttimeout() is None


class TestMakeCanaryHostname:
    def test_ends_with_the_invalid_tld(self):
        assert dc.make_canary_hostname().endswith(".invalid")

    def test_two_calls_produce_different_hostnames(self):
        assert dc.make_canary_hostname() != dc.make_canary_hostname()


class TestUseColor:
    def test_disabled_by_flag(self):
        assert dc._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert dc._use_color(no_color_flag=False) is False


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        assert dc._colorize("hello", "red", True) == f"{dc._ANSI_CODES['red']}hello{dc._ANSI_CODES['reset']}"

    def test_returns_text_unchanged_when_disabled(self):
        assert dc._colorize("hello", "red", False) == "hello"
