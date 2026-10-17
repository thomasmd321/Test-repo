"""Unit tests for network_scanner.py.

Run from the repo root: python3 -m unittest
(or: python3 -m unittest discover -s tests -t .)

Covers pure logic and anything mockable without a real network, a real
privileged socket, or scapy actually being installed. Nothing here sends
real ping/ARP traffic.
"""
import ipaddress
import sys
import unittest
import unittest.mock as mock

import network_scanner as m


class TestReadArpTable(unittest.TestCase):
    def test_parses_linux_style_output(self):
        output = (
            "? (192.168.1.1) at aa:bb:cc:11:22:33 [ether] on eth0\n"
            "? (192.168.1.50) at 11:22:33:AA:BB-CC [ether] on eth0\n"
            "? (192.168.1.99) at <incomplete> on eth0\n"
        )
        with mock.patch.object(m.subprocess, "run", return_value=mock.Mock(stdout=output)):
            table = m.read_arp_table()
        self.assertEqual(table["192.168.1.1"], "aa:bb:cc:11:22:33")
        self.assertEqual(table["192.168.1.50"], "11:22:33:aa:bb:cc")  # hyphen normalized to colon
        self.assertNotIn("192.168.1.99", table)  # no MAC on that line

    def test_missing_arp_binary_returns_empty_dict(self):
        with mock.patch.object(m.subprocess, "run", side_effect=FileNotFoundError):
            self.assertEqual(m.read_arp_table(), {})


class TestPingSweep(unittest.TestCase):
    def test_only_live_hosts_are_returned_and_sorted(self):
        def fake_ping(ip, timeout):
            return ip.endswith(".2") or ip.endswith(".4")

        with mock.patch.object(m, "ping", side_effect=fake_ping), \
             mock.patch.object(m, "read_arp_table", return_value={}):
            devices = m.ping_sweep("192.168.1.0/29", timeout=0.01)

        ips = [d["ip"] for d in devices]
        self.assertEqual(ips, sorted(ips, key=ipaddress.ip_address))
        self.assertTrue(all(ip.endswith(".2") or ip.endswith(".4") for ip in ips))

    def test_arp_table_and_hostname_are_attached(self):
        with mock.patch.object(m, "ping", return_value=True), \
             mock.patch.object(m, "read_arp_table", return_value={"192.168.1.1": "aa:bb:cc:11:22:33"}), \
             mock.patch.object(m.socket, "gethostbyaddr", side_effect=m.socket.herror):
            devices = m.ping_sweep("192.168.1.0/30", timeout=0.01)
        by_ip = {d["ip"]: d for d in devices}
        self.assertEqual(by_ip["192.168.1.1"]["mac"], "aa:bb:cc:11:22:33")
        self.assertEqual(by_ip["192.168.1.1"]["hostname"], "")  # herror -> ""


class TestScanFallback(unittest.TestCase):
    def test_falls_back_to_ping_sweep_on_any_arp_failure(self):
        """scan() must fall back on ANY arp_scan failure, not just a narrow
        exception tuple -- a scapy-specific error (e.g. a bad interface)
        should trigger the fallback too."""
        with mock.patch.object(m, "arp_scan", side_effect=RuntimeError("scapy-specific failure")), \
             mock.patch.object(m, "ping_sweep", return_value=["fallback"]) as ping_sweep:
            result = m.scan("192.168.1.0/30", 0.1)
        self.assertEqual(result, ["fallback"])
        ping_sweep.assert_called_once()

    def test_uses_arp_scan_result_when_it_succeeds(self):
        with mock.patch.object(m, "arp_scan", return_value=["arp-result"]), \
             mock.patch.object(m, "ping_sweep") as ping_sweep:
            result = m.scan("192.168.1.0/30", 0.1)
        self.assertEqual(result, ["arp-result"])
        ping_sweep.assert_not_called()


class TestMainSubnetGuard(unittest.TestCase):
    def _run_main(self, argv):
        with mock.patch.object(sys, "argv", ["network_scanner.py"] + argv), \
             mock.patch.object(m, "scan", return_value=[]):
            m.main()

    def test_oversized_subnet_rejected(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run_main(["10.0.0.0/8"])
        self.assertIn("max-hosts", str(ctx.exception))

    def test_max_hosts_override_allows_larger_scan(self):
        # Should not raise -- scan() is mocked, so this only exercises the guard.
        self._run_main(["10.0.0.0/20", "--max-hosts", "5000"])

    def test_invalid_subnet_gives_friendly_error_not_traceback(self):
        with self.assertRaises(SystemExit) as ctx:
            self._run_main(["not-a-subnet"])
        self.assertIn("Invalid subnet", str(ctx.exception))

    def test_default_sized_subnet_is_not_rejected(self):
        self._run_main(["192.168.1.0/24"])  # should not raise


if __name__ == "__main__":
    unittest.main()
