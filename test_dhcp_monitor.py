import json
import socket
import threading
import time

import dhcp_monitor as dm


def _ipv4_bytes(ip: str) -> bytes:
    return bytes(int(part) for part in ip.split("."))


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(part, 16) for part in mac.split(":"))


def _build_dhcp_packet(
    message_type: int,
    server_id: str = None,
    yiaddr: str = "192.168.1.100",
    chaddr: str = "aa:bb:cc:dd:ee:ff",
    hlen: int = 6,
    magic_cookie: bytes = dm._DHCP_MAGIC_COOKIE,
) -> bytes:
    """Build a minimal, realistic DHCP OFFER/ACK-shaped packet for tests."""
    op = 2  # BOOTREPLY
    htype = 1  # Ethernet
    hops = 0
    xid = b"\x01\x02\x03\x04"
    secs_flags = b"\x00\x00\x00\x00"
    ciaddr = b"\x00\x00\x00\x00"
    yiaddr_bytes = _ipv4_bytes(yiaddr)
    siaddr = b"\x00\x00\x00\x00"
    giaddr = b"\x00\x00\x00\x00"
    chaddr_bytes = (_mac_bytes(chaddr) if chaddr else b"").ljust(16, b"\x00")
    sname = b"\x00" * 64
    file_field = b"\x00" * 128

    header = (
        bytes([op, htype, hlen, hops]) + xid + secs_flags + ciaddr + yiaddr_bytes
        + siaddr + giaddr + chaddr_bytes + sname + file_field
    )
    assert len(header) == dm._DHCP_HEADER_LENGTH

    options = bytes([53, 1, message_type])  # DHCP message type option
    if server_id:
        options += bytes([54, 4]) + _ipv4_bytes(server_id)
    options += bytes([255])  # End option

    return header + magic_cookie + options


class TestParseDhcpPacket:
    def test_parses_an_offer_with_server_id(self):
        packet = _build_dhcp_packet(dm._DHCP_OFFER, server_id="192.168.1.1", yiaddr="192.168.1.50")

        result = dm.parse_dhcp_packet(packet)

        assert result["message_type"] == dm._DHCP_OFFER
        assert result["server_id"] == "192.168.1.1"
        assert result["yiaddr"] == "192.168.1.50"
        assert result["chaddr"] == "aa:bb:cc:dd:ee:ff"

    def test_parses_an_ack(self):
        packet = _build_dhcp_packet(dm._DHCP_ACK, server_id="192.168.1.1")

        result = dm.parse_dhcp_packet(packet)

        assert result["message_type"] == dm._DHCP_ACK

    def test_returns_none_for_too_short_data(self):
        assert dm.parse_dhcp_packet(b"\x01\x02\x03") is None

    def test_returns_none_for_wrong_magic_cookie(self):
        packet = _build_dhcp_packet(dm._DHCP_OFFER, magic_cookie=b"\x00\x00\x00\x00")

        assert dm.parse_dhcp_packet(packet) is None

    def test_server_id_is_none_when_option_absent(self):
        packet = _build_dhcp_packet(dm._DHCP_OFFER, server_id=None)

        result = dm.parse_dhcp_packet(packet)

        assert result["server_id"] is None

    def test_chaddr_is_none_when_hlen_is_not_six(self):
        packet = _build_dhcp_packet(dm._DHCP_OFFER, server_id="192.168.1.1", hlen=0, chaddr=None)

        result = dm.parse_dhcp_packet(packet)

        assert result["chaddr"] is None

    def test_ignores_options_after_the_end_marker(self):
        packet = _build_dhcp_packet(dm._DHCP_OFFER, server_id="192.168.1.1")
        # Append garbage after the real End option - must not be misread as more options.
        packet_with_trailer = packet + b"\xff\xff\xff"

        result = dm.parse_dhcp_packet(packet_with_trailer)

        assert result["message_type"] == dm._DHCP_OFFER
        assert result["server_id"] == "192.168.1.1"


class TestProcessDhcpObservation:
    def test_first_server_observed_is_the_baseline_not_rogue(self):
        seen = set()

        is_rogue = dm.process_dhcp_observation("192.168.1.1", seen)

        assert is_rogue is False
        assert seen == {"192.168.1.1"}

    def test_repeated_observation_of_the_same_server_is_not_rogue(self):
        seen = {"192.168.1.1"}

        assert dm.process_dhcp_observation("192.168.1.1", seen) is False

    def test_a_second_distinct_server_is_flagged_as_rogue(self):
        seen = {"192.168.1.1"}

        is_rogue = dm.process_dhcp_observation("192.168.1.99", seen)

        assert is_rogue is True
        assert seen == {"192.168.1.1", "192.168.1.99"}

    def test_a_pre_seeded_trusted_server_is_not_flagged_when_it_is_the_first_packet(self):
        seen = {"192.168.1.1"}  # pre-seeded via --trusted-server, no packet observed yet

        assert dm.process_dhcp_observation("192.168.1.1", seen) is False

    def test_a_third_distinct_server_is_also_flagged(self):
        seen = {"192.168.1.1"}
        dm.process_dhcp_observation("192.168.1.99", seen)

        is_rogue = dm.process_dhcp_observation("192.168.1.200", seen)

        assert is_rogue is True


class TestMonitor:
    """Real, unmocked UDP socket tests - bound to an OS-assigned loopback
    port rather than the real (privileged) DHCP client port 68, so these
    run without root. This is genuine end-to-end verification of monitor()'s
    actual receive loop, something arp_monitor.py's equivalent test could
    never get (scapy's sniff() has no privilege-free substitute)."""

    def _start_monitor(self, on_rogue, trusted_servers=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.settimeout(0.05)
        port = sock.getsockname()[1]

        thread = threading.Thread(
            target=dm.monitor,
            kwargs={"on_rogue": on_rogue, "trusted_servers": trusted_servers, "sock": sock},
            daemon=True,
        )
        thread.start()
        self._threads.append(thread)
        return port, sock

    def setup_method(self):
        self._threads = []

    def teardown_method(self):
        for thread in self._threads:
            thread.join(timeout=2)

    def test_flags_a_second_distinct_server_over_a_real_socket(self):
        events = []
        port, sock = self._start_monitor(lambda ip, mt: events.append((ip, mt)))

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(_build_dhcp_packet(dm._DHCP_OFFER, server_id="10.0.0.1"), ("127.0.0.1", port))
            time.sleep(0.2)
            sender.sendto(_build_dhcp_packet(dm._DHCP_OFFER, server_id="10.0.0.99"), ("127.0.0.1", port))
            time.sleep(0.2)
        finally:
            sender.close()
            sock.close()

        assert events == [("10.0.0.99", dm._DHCP_OFFER)]

    def test_does_not_flag_a_single_repeated_server(self):
        events = []
        port, sock = self._start_monitor(lambda ip, mt: events.append((ip, mt)))

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(_build_dhcp_packet(dm._DHCP_OFFER, server_id="10.0.0.1"), ("127.0.0.1", port))
            time.sleep(0.1)
            sender.sendto(_build_dhcp_packet(dm._DHCP_ACK, server_id="10.0.0.1"), ("127.0.0.1", port))
            time.sleep(0.2)
        finally:
            sender.close()
            sock.close()

        assert events == []

    def test_pre_seeded_trusted_server_is_not_flagged_but_a_different_one_is(self):
        events = []
        port, sock = self._start_monitor(lambda ip, mt: events.append((ip, mt)), trusted_servers={"10.0.0.1"})

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(_build_dhcp_packet(dm._DHCP_ACK, server_id="10.0.0.1"), ("127.0.0.1", port))
            time.sleep(0.1)
            sender.sendto(_build_dhcp_packet(dm._DHCP_OFFER, server_id="10.0.0.66"), ("127.0.0.1", port))
            time.sleep(0.2)
        finally:
            sender.close()
            sock.close()

        assert events == [("10.0.0.66", dm._DHCP_OFFER)]

    def test_ignores_non_dhcp_udp_traffic_on_the_port(self):
        events = []
        port, sock = self._start_monitor(lambda ip, mt: events.append((ip, mt)))

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.sendto(b"not a dhcp packet at all", ("127.0.0.1", port))
            time.sleep(0.2)
        finally:
            sender.close()
            sock.close()

        assert events == []

    def test_falls_back_to_source_address_when_server_id_option_is_absent(self):
        events = []
        port, sock = self._start_monitor(lambda ip, mt: events.append((ip, mt)))

        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sender.bind(("127.0.0.1", 0))
            sender.sendto(_build_dhcp_packet(dm._DHCP_OFFER, server_id=None), ("127.0.0.1", port))
            time.sleep(0.1)
            sender.sendto(_build_dhcp_packet(dm._DHCP_OFFER, server_id=None), ("127.0.0.1", port))
            time.sleep(0.2)
            # A second packet from the *same* source address, still with no
            # server_id option, must not be treated as a second server.
        finally:
            sender.close()
            sock.close()

        assert events == []


class TestAppendLog:
    def test_appends_one_json_line_per_call(self, tmp_path):
        path = tmp_path / "rogue.jsonl"

        dm._append_log(path, "10.0.0.99", dm._DHCP_OFFER)
        dm._append_log(path, "10.0.0.100", dm._DHCP_ACK)

        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["server_ip"] == "10.0.0.99"
        assert first["message_type"] == "OFFER"
        assert "timestamp" in first
        second = json.loads(lines[1])
        assert second["message_type"] == "ACK"

    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "nested" / "rogue.jsonl"

        dm._append_log(path, "10.0.0.99", dm._DHCP_OFFER)

        assert path.exists()

    def test_does_not_raise_when_write_fails(self, tmp_path, monkeypatch):
        path = tmp_path / "rogue.jsonl"
        monkeypatch.setattr(dm.Path, "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError("Permission denied")))

        dm._append_log(path, "10.0.0.99", dm._DHCP_OFFER)  # Should not raise.


class TestUseColor:
    def test_disabled_by_flag(self):
        assert dm._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert dm._use_color(no_color_flag=False) is False


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        assert dm._colorize("hello", "magenta", True) == f"{dm._ANSI_CODES['magenta']}hello{dm._ANSI_CODES['reset']}"

    def test_returns_text_unchanged_when_disabled(self):
        assert dm._colorize("hello", "magenta", False) == "hello"
