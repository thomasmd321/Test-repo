import json
import sys
from unittest.mock import MagicMock, patch

import arp_monitor as am


class TestProcessArpObservation:
    def test_first_observation_of_an_ip_is_not_a_conflict(self):
        seen = {}
        result = am.process_arp_observation("192.168.1.1", "aa:aa:aa:aa:aa:aa", seen)

        assert result is None
        assert seen == {"192.168.1.1": "aa:aa:aa:aa:aa:aa"}

    def test_repeated_observation_with_the_same_mac_is_not_a_conflict(self):
        seen = {"192.168.1.1": "aa:aa:aa:aa:aa:aa"}
        result = am.process_arp_observation("192.168.1.1", "aa:aa:aa:aa:aa:aa", seen)

        assert result is None

    def test_a_different_mac_for_a_known_ip_is_a_conflict(self):
        seen = {"192.168.1.1": "aa:aa:aa:aa:aa:aa"}
        result = am.process_arp_observation("192.168.1.1", "bb:bb:bb:bb:bb:bb", seen)

        assert result == ("aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb")

    def test_updates_seen_to_the_new_mac_after_a_conflict(self):
        seen = {"192.168.1.1": "aa:aa:aa:aa:aa:aa"}
        am.process_arp_observation("192.168.1.1", "bb:bb:bb:bb:bb:bb", seen)

        assert seen["192.168.1.1"] == "bb:bb:bb:bb:bb:bb"

    def test_a_third_change_is_reported_against_the_second_mac_not_the_first(self):
        seen = {"192.168.1.1": "aa:aa:aa:aa:aa:aa"}
        am.process_arp_observation("192.168.1.1", "bb:bb:bb:bb:bb:bb", seen)
        result = am.process_arp_observation("192.168.1.1", "cc:cc:cc:cc:cc:cc", seen)

        assert result == ("bb:bb:bb:bb:bb:bb", "cc:cc:cc:cc:cc:cc")

    def test_different_ips_are_tracked_independently(self):
        seen = {}
        am.process_arp_observation("192.168.1.1", "aa:aa:aa:aa:aa:aa", seen)
        am.process_arp_observation("192.168.1.2", "bb:bb:bb:bb:bb:bb", seen)

        assert seen == {"192.168.1.1": "aa:aa:aa:aa:aa:aa", "192.168.1.2": "bb:bb:bb:bb:bb:bb"}


def _fake_arp_packet(op: int, psrc: str, hwsrc: str):
    """Build a minimal stand-in for a scapy packet with an ARP layer, for tests."""
    arp_layer = MagicMock()
    arp_layer.op = op
    arp_layer.psrc = psrc
    arp_layer.hwsrc = hwsrc

    packet = MagicMock()
    packet.haslayer.return_value = True
    packet.__getitem__.return_value = arp_layer
    return packet


class TestMonitor:
    def test_calls_on_conflict_when_sniff_reports_a_mac_change(self):
        first = _fake_arp_packet(op=2, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa")
        second = _fake_arp_packet(op=2, psrc="192.168.1.1", hwsrc="bb:bb:bb:bb:bb:bb")

        fake_scapy = MagicMock()
        fake_scapy.ARP = object

        def fake_sniff(filter, prn, store, iface):
            prn(first)
            prn(second)

        fake_scapy.sniff = fake_sniff

        on_conflict = MagicMock()
        with patch.dict(sys.modules, {"scapy": fake_scapy, "scapy.all": fake_scapy}):
            am.monitor(on_conflict)

        on_conflict.assert_called_once_with("192.168.1.1", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb")

    def test_ignores_non_arp_packets(self):
        packet = MagicMock()
        packet.haslayer.return_value = False

        fake_scapy = MagicMock()
        fake_scapy.ARP = object

        def fake_sniff(filter, prn, store, iface):
            prn(packet)

        fake_scapy.sniff = fake_sniff

        on_conflict = MagicMock()
        with patch.dict(sys.modules, {"scapy": fake_scapy, "scapy.all": fake_scapy}):
            am.monitor(on_conflict)

        on_conflict.assert_not_called()

    def test_ignores_arp_requests_op_1_not_just_replies(self):
        request_packet = _fake_arp_packet(op=1, psrc="192.168.1.1", hwsrc="aa:aa:aa:aa:aa:aa")

        fake_scapy = MagicMock()
        fake_scapy.ARP = object

        def fake_sniff(filter, prn, store, iface):
            prn(request_packet)

        fake_scapy.sniff = fake_sniff

        on_conflict = MagicMock()
        with patch.dict(sys.modules, {"scapy": fake_scapy, "scapy.all": fake_scapy}):
            am.monitor(on_conflict)

        on_conflict.assert_not_called()

    def test_passes_interface_through_to_sniff(self):
        fake_scapy = MagicMock()
        fake_scapy.ARP = object
        fake_scapy.sniff = MagicMock()

        with patch.dict(sys.modules, {"scapy": fake_scapy, "scapy.all": fake_scapy}):
            am.monitor(lambda *a: None, interface="eth0")

        fake_scapy.sniff.assert_called_once_with(filter="arp", prn=fake_scapy.sniff.call_args.kwargs["prn"], store=False, iface="eth0")

    def test_uses_and_mutates_a_provided_seen_dict(self):
        packet = _fake_arp_packet(op=2, psrc="192.168.1.1", hwsrc="bb:bb:bb:bb:bb:bb")

        fake_scapy = MagicMock()
        fake_scapy.ARP = object

        def fake_sniff(filter, prn, store, iface):
            prn(packet)

        fake_scapy.sniff = fake_sniff

        seen = {"192.168.1.1": "aa:aa:aa:aa:aa:aa"}
        on_conflict = MagicMock()
        with patch.dict(sys.modules, {"scapy": fake_scapy, "scapy.all": fake_scapy}):
            am.monitor(on_conflict, seen=seen)

        on_conflict.assert_called_once_with("192.168.1.1", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb")
        assert seen["192.168.1.1"] == "bb:bb:bb:bb:bb:bb"


class TestAppendLog:
    def test_appends_one_json_line_per_call(self, tmp_path):
        path = tmp_path / "conflicts.jsonl"

        am._append_log(path, "192.168.1.1", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb")
        am._append_log(path, "192.168.1.2", "cc:cc:cc:cc:cc:cc", "dd:dd:dd:dd:dd:dd")

        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["ip"] == "192.168.1.1"
        assert first["previous_mac"] == "aa:aa:aa:aa:aa:aa"
        assert first["new_mac"] == "bb:bb:bb:bb:bb:bb"
        assert "timestamp" in first

    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "nested" / "conflicts.jsonl"

        am._append_log(path, "192.168.1.1", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb")

        assert path.exists()

    def test_does_not_raise_when_write_fails(self, tmp_path):
        path = tmp_path / "conflicts.jsonl"
        with patch("arp_monitor.Path.mkdir", side_effect=OSError("Permission denied")):
            am._append_log(path, "192.168.1.1", "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb")  # Should not raise.


class TestUseColor:
    def test_disabled_by_flag(self):
        assert am._use_color(no_color_flag=True) is False

    def test_disabled_by_no_color_env_var(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "1")
        assert am._use_color(no_color_flag=False) is False


class TestColorize:
    def test_wraps_text_in_ansi_codes_when_enabled(self):
        assert am._colorize("hello", "magenta", True) == f"{am._ANSI_CODES['magenta']}hello{am._ANSI_CODES['reset']}"

    def test_returns_text_unchanged_when_disabled(self):
        assert am._colorize("hello", "magenta", False) == "hello"
