"""Unit tests for arp_spoof_detector.py.

Run from the repo root: python3 -m unittest
(or: python3 -m unittest discover -s tests -t .)

Covers FlapDetector's alerting and pruning logic, the packet->alert
wiring, pin_arp_entry's per-OS command construction, and the hardening
fixes (bounded memory, friendly error on missing root). Nothing here
sends real ARP traffic or needs root.
"""
import sys
import unittest
import unittest.mock as mock

import arp_spoof_detector as m


class TestFlapDetector(unittest.TestCase):
    def test_first_sighting_is_silent(self):
        d = m.FlapDetector(flap_window=10.0)
        self.assertIsNone(d.observe("192.168.1.1", "aa:bb:cc:11:22:33", 0.0))

    def test_same_mac_again_is_silent(self):
        d = m.FlapDetector(flap_window=10.0)
        d.observe("192.168.1.1", "aa:bb:cc:11:22:33", 0.0)
        self.assertIsNone(d.observe("192.168.1.1", "aa:bb:cc:11:22:33", 5.0))

    def test_rapid_mac_change_flags_as_flap(self):
        d = m.FlapDetector(flap_window=10.0)
        d.observe("192.168.1.1", "aa:bb:cc:11:22:33", 0.0)
        alert = d.observe("192.168.1.1", "ff:ff:00:ba:d0:01", 1.0)
        self.assertIsNotNone(alert)
        self.assertIn("FLAP", alert)
        self.assertIn("192.168.1.1", alert)

    def test_slow_mac_change_outside_window_is_not_a_flap(self):
        d = m.FlapDetector(flap_window=10.0)
        d.observe("192.168.1.1", "aa:bb:cc:11:22:33", 0.0)
        self.assertIsNone(d.observe("192.168.1.1", "11:22:33:44:55:66", 60.0))

    def test_pinned_mismatch_alerts_immediately(self):
        d = m.FlapDetector(pinned={"192.168.1.1": "AA:BB:CC:11:22:33"})
        alert = d.observe("192.168.1.1", "ff:ff:00:ba:d0:01", 0.0)
        self.assertIsNotNone(alert)
        self.assertIn("PINNED MISMATCH", alert)

    def test_pinned_match_is_case_insensitive(self):
        d = m.FlapDetector(pinned={"192.168.1.1": "AA:BB:CC:11:22:33"})
        self.assertIsNone(d.observe("192.168.1.1", "aa:bb:cc:11:22:33", 0.0))

    def test_pinned_check_takes_priority_over_flap_window(self):
        """A pinned ip is caught on the very first forged packet, without
        waiting for a second sighting inside the flap window."""
        d = m.FlapDetector(flap_window=10.0, pinned={"192.168.1.1": "aa:bb:cc:11:22:33"})
        alert = d.observe("192.168.1.1", "ff:ff:00:ba:d0:01", 0.0)
        self.assertIn("PINNED MISMATCH", alert)

    def test_last_seen_is_pruned_under_simulated_spoofing_attack(self):
        """The realistic adversary for this tool is one who spoofs many
        distinct forged source IPs -- exactly the traffic it watches for.
        last_seen must not grow without bound under that load."""
        d = m.FlapDetector(flap_window=10.0, stale_after=5.0)
        t = 0.0
        for i in range(2000):
            ip = f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}"
            d.observe(ip, "aa:bb:cc:00:00:01", t)
            t += 0.01
        self.assertLess(len(d.last_seen), 2000)

    def test_pruning_does_not_evict_fresh_entries(self):
        d = m.FlapDetector(flap_window=10.0, stale_after=1000.0)
        d.observe("1.1.1.1", "aa:aa:aa:aa:aa:aa", 0.0)
        for i in range(999):  # trip the 1000-call prune checkpoint
            d.observe(f"2.2.2.{i % 250}", "bb:bb:bb:bb:bb:bb", 0.5)
        self.assertIn("1.1.1.1", d.last_seen)


class FakeARP:
    def __init__(self, op, psrc, hwsrc):
        self.op, self.psrc, self.hwsrc = op, psrc, hwsrc


class FakePacket:
    def __init__(self, arp_layer, has_arp=True):
        self._arp = arp_layer
        self._has_arp = has_arp

    def haslayer(self, layer):
        return self._has_arp

    def __getitem__(self, layer):
        return self._arp


class TestMakeCallback(unittest.TestCase):
    def test_alert_is_printed(self):
        detector = m.FlapDetector(pinned={"192.168.1.1": "aa:bb:cc:11:22:33"})
        on_packet = m.make_callback(detector)
        pkt = FakePacket(FakeARP(op=2, psrc="192.168.1.1", hwsrc="ff:ff:00:ba:d0:01"))
        with mock.patch("builtins.print") as fake_print:
            on_packet(pkt)
        fake_print.assert_called_once()
        self.assertIn("PINNED MISMATCH", fake_print.call_args[0][0])

    def test_non_alert_prints_nothing(self):
        detector = m.FlapDetector()
        on_packet = m.make_callback(detector)
        pkt = FakePacket(FakeARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:11:22:33"))
        with mock.patch("builtins.print") as fake_print:
            on_packet(pkt)
        fake_print.assert_not_called()

    def test_arp_request_op_1_is_ignored(self):
        detector = m.FlapDetector()
        on_packet = m.make_callback(detector)
        pkt = FakePacket(FakeARP(op=1, psrc="192.168.1.1", hwsrc="aa:bb:cc:11:22:33"))
        with mock.patch("builtins.print") as fake_print:
            on_packet(pkt)
        fake_print.assert_not_called()
        self.assertEqual(detector.last_seen, {})  # request never reaches observe()

    def test_non_arp_packet_is_ignored(self):
        detector = m.FlapDetector()
        on_packet = m.make_callback(detector)
        pkt = FakePacket(None, has_arp=False)
        with mock.patch("builtins.print") as fake_print:
            on_packet(pkt)  # must not raise despite no ARP layer
        fake_print.assert_not_called()


class TestPinArpEntry(unittest.TestCase):
    def test_linux_command(self):
        with mock.patch.object(m.platform, "system", return_value="Linux"), \
             mock.patch.object(m.subprocess, "run") as run:
            m.pin_arp_entry("192.168.1.1", "aa:bb:cc:11:22:33")
        run.assert_called_once_with(
            ["sudo", "arp", "-s", "192.168.1.1", "aa:bb:cc:11:22:33"],
            capture_output=True, text=True, check=False,
        )

    def test_windows_command_swaps_colons_for_hyphens(self):
        with mock.patch.object(m.platform, "system", return_value="Windows"), \
             mock.patch.object(m.subprocess, "run") as run:
            m.pin_arp_entry("192.168.1.1", "aa:bb:cc:11:22:33", interface="Ethernet")
        run.assert_called_once_with(
            ["netsh", "interface", "ipv4", "add", "neighbors", "Ethernet",
             "192.168.1.1", "aa-bb-cc-11-22-33"],
            capture_output=True, text=True, check=False,
        )


class TestParseIpMac(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(m.parse_ip_mac("192.168.1.1=aa:bb:cc:11:22:33"), ("192.168.1.1", "aa:bb:cc:11:22:33"))

    def test_missing_equals_raises(self):
        with self.assertRaises(Exception):
            m.parse_ip_mac("not-valid")


class TestMainRepairPath(unittest.TestCase):
    def test_repair_dispatches_and_exits_with_subprocess_returncode(self):
        with mock.patch.object(sys, "argv", ["arp_spoof_detector.py", "--repair", "192.168.1.1=aa:bb:cc:11:22:33"]), \
             mock.patch.object(m.subprocess, "run") as run:
            run.return_value = mock.Mock(stdout="ok\n", stderr="", returncode=0)
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(run.call_args[0][0], ["sudo", "arp", "-s", "192.168.1.1", "aa:bb:cc:11:22:33"])

    def test_repair_propagates_nonzero_exit_code(self):
        with mock.patch.object(sys, "argv", ["arp_spoof_detector.py", "--repair", "192.168.1.1=aa:bb:cc:11:22:33"]), \
             mock.patch.object(m.subprocess, "run") as run:
            run.return_value = mock.Mock(stdout="", stderr="permission denied\n", returncode=1)
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertEqual(ctx.exception.code, 1)


class TestMainNoRootHandling(unittest.TestCase):
    def test_permission_error_gives_friendly_message(self):
        def raising_sniff(*a, **kw):
            raise PermissionError("Operation not permitted")

        with mock.patch.object(sys, "argv", ["arp_spoof_detector.py", "--interface", "eth0"]), \
             mock.patch.object(m, "sniff", raising_sniff):
            with self.assertRaises(SystemExit) as ctx:
                m.main()
        self.assertIn("sudo", str(ctx.exception))
        self.assertIn("Permission denied", str(ctx.exception))

    def test_keyboard_interrupt_exits_quietly(self):
        def interrupting_sniff(*a, **kw):
            raise KeyboardInterrupt

        with mock.patch.object(sys, "argv", ["arp_spoof_detector.py"]), \
             mock.patch.object(m, "sniff", interrupting_sniff):
            m.main()  # should not raise -- caught and handled


if __name__ == "__main__":
    unittest.main()
