"""Unit tests for bandwidth_dashboard.py.

Run from the repo root: python3 -m unittest
(or: python3 -m unittest discover -s tests -t .)

Covers pure logic plus the error-handling fixes from the hardening pass
(silent sniffer-thread death, conntrack RuntimeError surfacing, SSH
command construction). Nothing here touches a real interface, router,
or network.
"""
import subprocess
import sys
import time
import unittest
import unittest.mock as mock
from collections import namedtuple

import bandwidth_dashboard as m


class TestFormatRate(unittest.TestCase):
    def test_units_scale_up(self):
        self.assertEqual(m.format_rate(500, 2), "250.0 B/s")
        self.assertEqual(m.format_rate(2_000_000, 2), "976.6 KB/s")
        self.assertEqual(m.format_rate(0, 2), "0.0 B/s")

    def test_zero_seconds_does_not_divide_by_zero(self):
        self.assertEqual(m.format_rate(100, 0), "0.0 B/s")


class TestIsPrivate(unittest.TestCase):
    def test_private_and_public_and_garbage(self):
        self.assertTrue(m.is_private("192.168.1.5"))
        self.assertTrue(m.is_private("10.0.0.1"))
        self.assertFalse(m.is_private("8.8.8.8"))
        self.assertFalse(m.is_private("not-an-ip"))


class TestConntrackParsing(unittest.TestCase):
    SAMPLE = (
        'ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.1.50 dst=93.184.216.34 '
        'sport=51000 dport=443 packets=10 bytes=1500 src=93.184.216.34 dst=192.168.1.50 '
        'sport=443 dport=51000 packets=8 bytes=9000 [ASSURED] mark=0 use=2\n'
        'ipv4     2 udp      17 29 src=192.168.1.60 dst=8.8.8.8 sport=5000 dport=53 '
        'packets=1 bytes=60 src=8.8.8.8 dst=192.168.1.60 sport=53 dport=5000 '
        'packets=1 bytes=120 mark=0 use=1\n'
        'ipv4     2 icmp     1 29 src=192.168.1.50 dst=192.168.1.1 type=8 code=0 id=1 '
        'packets=1 bytes=84 src=192.168.1.1 dst=192.168.1.50 type=0 code=0 id=1 '
        'packets=1 bytes=84 mark=0 use=1\n'
    )

    def test_parse_conntrack_line_splits_orig_and_reply_blocks(self):
        blocks = m.parse_conntrack_line(self.SAMPLE.splitlines()[0])
        self.assertEqual(len(blocks), 2)
        self.assertEqual(blocks[0]["src"], "192.168.1.50")
        self.assertEqual(blocks[0]["bytes"], "1500")
        self.assertEqual(blocks[1]["src"], "93.184.216.34")
        self.assertEqual(blocks[1]["bytes"], "9000")

    def test_conntrack_totals_aggregates_across_protocols(self):
        sent, received = m.conntrack_totals(self.SAMPLE)
        self.assertEqual(sent["192.168.1.50"], 1500 + 84)  # tcp + icmp
        self.assertEqual(received["192.168.1.50"], 9000 + 84)
        self.assertEqual(sent["192.168.1.60"], 60)
        self.assertEqual(received["192.168.1.60"], 120)

    def test_public_source_ip_is_excluded(self):
        sent, _ = m.conntrack_totals(self.SAMPLE)
        self.assertNotIn("93.184.216.34", sent)
        self.assertNotIn("8.8.8.8", sent)


class TestDiffAndRanking(unittest.TestCase):
    def test_diff_totals_clamps_at_zero(self):
        diff = m.diff_totals({"1.1.1.1": 1000}, {"1.1.1.1": 500})  # counter reset
        self.assertEqual(diff["1.1.1.1"], 0)

    def test_diff_totals_normal_increase(self):
        diff = m.diff_totals({"1.1.1.1": 100}, {"1.1.1.1": 150})
        self.assertEqual(diff["1.1.1.1"], 50)

    def test_ranked_ips_sorts_by_total_descending_and_filters_public(self):
        sent = {"192.168.1.5": 100, "8.8.8.8": 99999}
        received = {"192.168.1.10": 500}
        ranked = m.ranked_ips(sent, received)
        self.assertEqual(ranked, ["192.168.1.10", "192.168.1.5"])


class FakePacket:
    """Mimics just enough of a scapy packet for Stats.record()."""

    def __init__(self, length, src, dst):
        self._length = length
        self._ip = mock.Mock(src=src, dst=dst)

    def __contains__(self, layer):
        return layer == "IP"

    def __getitem__(self, layer):
        return self._ip

    def __len__(self):
        return self._length


class TestStats(unittest.TestCase):
    def test_record_and_snapshot_reset(self):
        stats = m.Stats()
        stats.record(FakePacket(100, "192.168.1.5", "192.168.1.1"))
        sent, received = stats.snapshot_and_reset()
        self.assertEqual(sent["192.168.1.5"], 100)
        self.assertEqual(received["192.168.1.1"], 100)
        # a second snapshot after reset should be empty
        sent2, received2 = stats.snapshot_and_reset()
        self.assertEqual(sent2, {})
        self.assertEqual(received2, {})

    def test_record_ignores_non_ip_packets(self):
        stats = m.Stats()
        stats.record({})  # no "IP" key
        sent, received = stats.snapshot_and_reset()
        self.assertEqual(sent, {})
        self.assertEqual(received, {})

    def test_hostname_for_is_lock_protected(self):
        import inspect
        src = inspect.getsource(m.Stats.hostname_for)
        self.assertIn("with self.lock:", src)

    def test_hostname_for_caches_and_handles_lookup_failure(self):
        stats = m.Stats()
        with mock.patch.object(m.socket, "gethostbyaddr", side_effect=m.socket.herror):
            self.assertEqual(stats.hostname_for("192.168.1.1"), "")
        self.assertIn("192.168.1.1", stats.hostnames)  # cached


class TestReadConntrack(unittest.TestCase):
    def test_local_command(self):
        with mock.patch.object(m.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="data", stderr="")
            m.read_conntrack()
        self.assertEqual(run.call_args[0][0], ["cat", "/proc/net/nf_conntrack"])

    def test_ssh_command_has_batchmode_and_timeout(self):
        with mock.patch.object(m.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=0, stdout="data", stderr="")
            m.read_conntrack(host="root@192.168.1.1", ssh_port=2222)
        cmd = run.call_args[0][0]
        self.assertEqual(cmd[0], "ssh")
        self.assertIn("BatchMode=yes", cmd)
        self.assertIn("ConnectTimeout=5", cmd)
        self.assertIn("2222", cmd)
        self.assertIn("timeout", run.call_args[1])

    def test_timeout_expired_becomes_runtime_error(self):
        with mock.patch.object(m.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="ssh", timeout=10)):
            with self.assertRaises(RuntimeError) as ctx:
                m.read_conntrack(host="root@192.168.1.1")
        self.assertIn("Timed out", str(ctx.exception))

    def test_nonzero_exit_becomes_runtime_error(self):
        with mock.patch.object(m.subprocess, "run") as run:
            run.return_value = mock.Mock(returncode=1, stdout="", stderr="permission denied")
            with self.assertRaises(RuntimeError) as ctx:
                m.read_conntrack()
        self.assertIn("permission denied", str(ctx.exception))


class TestRunSniffSource(unittest.TestCase):
    class FakeArgs:
        interface = "eth0"
        interval = 0.01

    def test_exception_in_sniffer_thread_surfaces_as_system_exit(self):
        def raising_sniff(iface, prn, store):
            raise PermissionError("Operation not permitted")

        with mock.patch.object(m, "sniff", raising_sniff):
            stats = m.Stats()
            poll = m.run_sniff_source(self.FakeArgs(), stats)
            time.sleep(0.05)
            with self.assertRaises(SystemExit) as ctx:
                poll()
        self.assertIn("Sniffing failed", str(ctx.exception))
        self.assertIn("sudo", str(ctx.exception))

    def test_dead_thread_without_exception_also_surfaces(self):
        def quiet_sniff(iface, prn, store):
            return  # thread exits immediately, no exception

        with mock.patch.object(m, "sniff", quiet_sniff):
            stats = m.Stats()
            poll = m.run_sniff_source(self.FakeArgs(), stats)
            time.sleep(0.05)
            with self.assertRaises(SystemExit) as ctx:
                poll()
        self.assertIn("unexpectedly", str(ctx.exception))


class TestRunConntrackSource(unittest.TestCase):
    class FakeArgs:
        host = None
        ssh_port = 22
        interval = 0.01

    def test_runtime_error_surfaces_as_friendly_system_exit(self):
        with mock.patch.object(m, "read_conntrack", side_effect=RuntimeError("Permission denied")):
            poll = m.run_conntrack_source(self.FakeArgs(), None)
            with self.assertRaises(SystemExit) as ctx:
                poll()
        self.assertIn("Permission denied", str(ctx.exception))
        self.assertIn("nf_conntrack_acct", str(ctx.exception))


class TestNetgearTable(unittest.TestCase):
    Device = namedtuple(
        "Device",
        ["name", "ip", "mac", "type", "signal", "link_rate", "allow_or_block",
         "device_type", "device_model", "ssid", "conn_ap_mac"],
    )

    def _device(self, **overrides):
        base = dict(
            name="laptop", ip="192.168.1.20", mac="AA:BB:CC:DD:EE:01", type="5GHz",
            signal=90, link_rate="866", allow_or_block="Allow", device_type=0,
            device_model="", ssid="Home-5G", conn_ap_mac=None,
        )
        base.update(overrides)
        return self.Device(**base)

    @staticmethod
    def _as_text(table):
        """build_netgear_table()'s first return value is a rich.table.Table
        when rich is installed (it's fed straight into Live.update() in
        main()) and a plain string otherwise. Render the Table case to
        plain text so assertions can treat both the same way -- without
        this, these tests only ever exercised the no-rich fallback branch
        and silently never covered the rich.Table path at all."""
        if not m.HAVE_RICH:
            return table
        from rich.console import Console
        console = Console(record=True, width=200)
        console.print(table)
        return console.export_text()

    def test_ssid_and_link_type_both_shown_no_mismatch(self):
        table, meter_line = m.build_netgear_table([self._device()], {})
        table_text = self._as_text(table)
        self.assertIn("Home-5G", table_text)
        self.assertIn("5GHz", table_text)

    def test_sorted_by_link_rate_descending(self):
        slow = self._device(name="iot", link_rate="300")
        fast = self._device(name="phone", link_rate="866")
        table, _ = m.build_netgear_table([slow, fast], {})
        table_text = self._as_text(table)
        self.assertLess(table_text.index("phone"), table_text.index("iot"))

    def test_missing_link_rate_sorts_last_not_crashes(self):
        no_rate = self._device(name="unknown", link_rate=None)
        fast = self._device(name="phone", link_rate="866")
        table, _ = m.build_netgear_table([no_rate, fast], {})
        table_text = self._as_text(table)
        self.assertLess(table_text.index("phone"), table_text.index("unknown"))

    def test_empty_traffic_meter_shows_unavailable_message(self):
        _, meter_line = m.build_netgear_table([], {})
        self.assertIn("unavailable", meter_line)

    def test_populated_traffic_meter(self):
        _, meter_line = m.build_netgear_table([], {"NewTodayUpload": 1.5, "NewTodayDownload": 2.5})
        self.assertIn("1.5", meter_line)
        self.assertIn("2.5", meter_line)


if __name__ == "__main__":
    unittest.main()
