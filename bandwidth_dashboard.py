#!/usr/bin/env python3
"""Live per-device bandwidth dashboard for your local network.

Three data sources, picked with --source:

  sniff (default) -- passively sniffs traffic on a local network
    interface with scapy. On a typical switched network an ordinary
    host only sees its own unicast traffic plus broadcast/multicast,
    not other devices' unicast traffic, so this mostly shows your own
    device unless run on the gateway or a mirror/SPAN port.

  conntrack -- polls /proc/net/nf_conntrack, which every Linux-based
    router/gateway (OpenWrt, DD-WRT, a Raspberry Pi or other Linux box
    acting as your router, etc.) already maintains for NAT, and which
    lists every active connection with per-connection byte counters
    tagged by source/destination IP. This gives real whole-LAN,
    per-device totals without needing a vendor-specific router API,
    but it requires the router to run Linux and either running this
    script on the router itself or over SSH (--host user@router).
    Byte accounting must be enabled once on the router:
        sysctl -w net.netfilter.nf_conntrack_acct=1
    Because it reflects only currently-tracked connections, a
    connection's final bytes can be missed if it closes between polls
    -- fine for a live "who's using bandwidth right now" view, not for
    exact totals.

  netgear -- for stock Netgear firmware (e.g. Nighthawk/Orbi), which
    doesn't run Linux userspace tools and has no documented per-device
    bandwidth API. Uses pynetgear to poll the router's local SOAP API
    (the same one the Nighthawk app uses) for the attached-devices
    list and the router-WIDE traffic meter. Important: this does NOT
    give true per-device live throughput -- "Link Rate" is each
    device's negotiated WiFi PHY speed (a ceiling, not actual usage),
    and the traffic meter is a whole-router today/month total, not
    broken out per device. Treat this as "who's connected and how
    fast is their link" rather than "who's using bandwidth right now".
    Requires the Traffic Meter to be enabled in the router's web UI
    (Advanced > Setup > Traffic Meter) for the totals to populate.

Neither sniff nor conntrack alters, redirects, or throttles anyone's
connection -- both only observe. netgear only reads router status.

Requires scapy for --source sniff, pynetgear for --source netgear,
and (for any source) the optional `rich` package for the live table;
without `rich` it falls back to a plain periodic text summary.
Sniffing raw packets typically requires root/administrator privileges.

Usage:
    sudo python bandwidth_dashboard.py                          # sniff, auto-pick interface
    sudo python bandwidth_dashboard.py --interface eth0
    python bandwidth_dashboard.py --source conntrack             # running on the router itself
    python bandwidth_dashboard.py --source conntrack --host root@192.168.1.1
    NETGEAR_PASSWORD=... python bandwidth_dashboard.py --source netgear --netgear-host routerlogin.net
"""

import argparse
import ipaddress
import os
import socket
import subprocess
import threading
import time
from collections import defaultdict

try:
    from scapy.all import conf, sniff
except ImportError:
    conf = None

try:
    from pynetgear import Netgear
except ImportError:
    Netgear = None

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table

    HAVE_RICH = True
except ImportError:
    HAVE_RICH = False


class Stats:
    """Thread-safe accumulator of bytes sent/received per IP address."""

    def __init__(self):
        self.lock = threading.Lock()
        self.sent = defaultdict(int)
        self.received = defaultdict(int)
        self.hostnames = {}

    def record(self, packet):
        if "IP" not in packet:
            return
        size = len(packet)
        src, dst = packet["IP"].src, packet["IP"].dst
        with self.lock:
            self.sent[src] += size
            self.received[dst] += size

    def hostname_for(self, ip: str) -> str:
        if ip not in self.hostnames:
            try:
                self.hostnames[ip] = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                self.hostnames[ip] = ""
        return self.hostnames[ip]

    def snapshot_and_reset(self):
        with self.lock:
            sent, received = dict(self.sent), dict(self.received)
            self.sent.clear()
            self.received.clear()
        return sent, received


def format_rate(byte_count: int, seconds: float) -> str:
    bytes_per_sec = byte_count / seconds if seconds else 0
    for unit in ("B/s", "KB/s", "MB/s", "GB/s"):
        if bytes_per_sec < 1024:
            return f"{bytes_per_sec:.1f} {unit}"
        bytes_per_sec /= 1024
    return f"{bytes_per_sec:.1f} TB/s"


def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def parse_conntrack_line(line: str) -> list:
    """Split one /proc/net/nf_conntrack line into its key=value blocks.

    Each connection has an "original" direction block (client -> server)
    followed by a "reply" direction block (server -> client), each
    starting at its own src= token. Works across tcp/udp/icmp since it
    doesn't assume which keys are present.
    """
    blocks = []
    current = {}
    for token in line.split():
        if "=" not in token:
            continue
        key, _, value = token.partition("=")
        if key == "src" and "src" in current:
            blocks.append(current)
            current = {}
        current[key] = value
    if current:
        blocks.append(current)
    return blocks


def conntrack_totals(text: str):
    """Cumulative upload/download byte totals per private client IP."""
    sent = defaultdict(int)
    received = defaultdict(int)
    for line in text.splitlines():
        blocks = parse_conntrack_line(line)
        if not blocks:
            continue
        client_ip = blocks[0].get("src")
        if not client_ip or not is_private(client_ip):
            continue
        sent[client_ip] += int(blocks[0].get("bytes", 0))
        if len(blocks) > 1:
            received[client_ip] += int(blocks[1].get("bytes", 0))
    return dict(sent), dict(received)


def read_conntrack(host: str = None, ssh_port: int = 22) -> str:
    if host:
        command = ["ssh", "-p", str(ssh_port), host, "cat /proc/net/nf_conntrack"]
    else:
        command = ["cat", "/proc/net/nf_conntrack"]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Failed to read conntrack table: {result.stderr.strip()}")
    return result.stdout


def diff_totals(previous: dict, current: dict) -> dict:
    """Per-IP increase since the last poll, clamped at 0 (e.g. counter reset)."""
    return {ip: max(0, total - previous.get(ip, 0)) for ip, total in current.items()}


def ranked_ips(sent: dict, received: dict) -> list:
    ips = set(sent) | set(received)
    ips = [ip for ip in ips if is_private(ip)]
    return sorted(ips, key=lambda ip: sent.get(ip, 0) + received.get(ip, 0), reverse=True)


def build_table(sent: dict, received: dict, stats: Stats, seconds: float):
    ips = ranked_ips(sent, received)[:20]

    if HAVE_RICH:
        table = Table(title=f"Bandwidth by device (last {seconds:.0f}s)")
        table.add_column("IP")
        table.add_column("Hostname")
        table.add_column("Upload", justify="right")
        table.add_column("Download", justify="right")
        for ip in ips:
            table.add_row(
                ip,
                stats.hostname_for(ip) or "-",
                format_rate(sent.get(ip, 0), seconds),
                format_rate(received.get(ip, 0), seconds),
            )
        return table

    lines = [f"\nBandwidth by device (last {seconds:.0f}s)", "-" * 64]
    lines.append(f"{'IP':<16}{'Upload':<12}{'Download':<12}Hostname")
    for ip in ips:
        lines.append(
            f"{ip:<16}{format_rate(sent.get(ip, 0), seconds):<12}"
            f"{format_rate(received.get(ip, 0), seconds):<12}{stats.hostname_for(ip)}"
        )
    if not ips:
        lines.append("(no traffic observed yet)")
    return "\n".join(lines)


def run_sniff_source(args, stats: Stats):
    if conf is None:
        raise SystemExit("--source sniff requires scapy: pip install scapy")

    def sniffer():
        sniff(iface=args.interface, prn=stats.record, store=False)

    thread = threading.Thread(target=sniffer, daemon=True)
    thread.start()

    print(f"Sniffing on {args.interface or conf.iface} ... Ctrl+C to stop.")
    print(
        "Note: on a switched network you'll mainly see your own device's traffic\n"
        "plus broadcast/multicast, unless this runs on the gateway or a mirror port.\n"
    )

    def poll():
        time.sleep(args.interval)
        return stats.snapshot_and_reset()

    return poll


def run_conntrack_source(args, stats: Stats):
    previous_sent, previous_received = {}, {}

    where = args.host or "this machine (must be the router/gateway)"
    print(f"Polling conntrack on {where} every {args.interval}s ... Ctrl+C to stop.")
    print(
        "Note: requires net.netfilter.nf_conntrack_acct=1 on the router, and shows\n"
        "only currently-tracked connections, so short-lived flows can be missed.\n"
    )

    def poll():
        nonlocal previous_sent, previous_received
        time.sleep(args.interval)
        text = read_conntrack(args.host, args.ssh_port)
        total_sent, total_received = conntrack_totals(text)
        sent = diff_totals(previous_sent, total_sent)
        received = diff_totals(previous_received, total_received)
        previous_sent, previous_received = total_sent, total_received
        return sent, received

    return poll


def _link_rate_mbps(device) -> float:
    try:
        return float(device.link_rate)
    except (TypeError, ValueError):
        return 0.0


def build_netgear_table(devices: list, traffic_meter: dict):
    """Render an attached-devices snapshot (link rate, not live throughput)."""
    devices = sorted(devices, key=_link_rate_mbps, reverse=True)
    meter_line = (
        f"Router traffic meter -- today: {traffic_meter.get('NewTodayUpload', '?')} MB up / "
        f"{traffic_meter.get('NewTodayDownload', '?')} MB down, "
        f"this month: {traffic_meter.get('NewMonthUpload', '?')} MB up / "
        f"{traffic_meter.get('NewMonthDownload', '?')} MB down"
        if traffic_meter
        else "Router traffic meter: unavailable (enable it under Advanced > Setup > Traffic Meter)"
    )

    if HAVE_RICH:
        table = Table(title="Attached devices (link rate is a ceiling, not live usage)")
        table.add_column("IP")
        table.add_column("Name")
        table.add_column("MAC")
        table.add_column("Band")
        table.add_column("Link Rate", justify="right")
        for d in devices:
            table.add_row(d.ip or "-", d.name or "-", d.mac or "-", d.ssid or "-", f"{d.link_rate} Mbps" if d.link_rate else "-")
        return table, meter_line

    lines = ["\nAttached devices (link rate is a ceiling, not live usage)", "-" * 72]
    lines.append(f"{'IP':<16}{'Name':<20}{'MAC':<20}{'Band':<10}Link Rate")
    for d in devices:
        rate = f"{d.link_rate} Mbps" if d.link_rate else "-"
        lines.append(f"{(d.ip or '-'):<16}{(d.name or '-'):<20}{(d.mac or '-'):<20}{(d.ssid or '-'):<10}{rate}")
    if not devices:
        lines.append("(no devices reported)")
    return "\n".join(lines), meter_line


def run_netgear_source(args):
    if Netgear is None:
        raise SystemExit("--source netgear requires pynetgear: pip install pynetgear")

    password = os.environ.get("NETGEAR_PASSWORD")
    if not password:
        raise SystemExit("Set the NETGEAR_PASSWORD environment variable to your router admin password.")

    router = Netgear(password=password, user=args.netgear_user, host=args.netgear_host)
    if not router.login():
        raise SystemExit(f"Failed to log in to {args.netgear_host} as {args.netgear_user}. Check host/credentials.")

    print(f"Polling {args.netgear_host} every {args.interval}s ... Ctrl+C to stop.")
    print(
        "Note: stock Netgear firmware exposes attached-device link rate and a\n"
        "whole-router traffic meter, not true per-device live bandwidth.\n"
    )

    def poll():
        time.sleep(args.interval)
        devices = router.get_attached_devices_2() or []
        traffic_meter = router.get_traffic_meter() or {}
        return devices, traffic_meter

    return poll


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=("sniff", "conntrack", "netgear"), default="sniff", help="Data source (default: sniff)")
    parser.add_argument("--interface", help="[sniff] Network interface to sniff on (default: scapy's default)")
    parser.add_argument("--host", help="[conntrack] SSH target for the router, e.g. root@192.168.1.1 (default: read locally)")
    parser.add_argument("--ssh-port", type=int, default=22, help="[conntrack] SSH port (default: 22)")
    parser.add_argument("--netgear-host", default="routerlogin.net", help="[netgear] Router hostname/IP (default: routerlogin.net)")
    parser.add_argument("--netgear-user", default="admin", help="[netgear] Router admin username (default: admin)")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between dashboard refreshes (default: 2)")
    args = parser.parse_args()

    console = Console() if HAVE_RICH else None

    if args.source == "netgear":
        poll = run_netgear_source(args)
        try:
            if HAVE_RICH:
                with Live(console=console, refresh_per_second=1) as live:
                    while True:
                        devices, traffic_meter = poll()
                        table, meter_line = build_netgear_table(devices, traffic_meter)
                        live.update(table)
                        console.print(meter_line)
            else:
                while True:
                    devices, traffic_meter = poll()
                    table, meter_line = build_netgear_table(devices, traffic_meter)
                    print(table)
                    print(meter_line)
        except KeyboardInterrupt:
            print("\nStopped.")
        return

    stats = Stats()
    poll = run_sniff_source(args, stats) if args.source == "sniff" else run_conntrack_source(args, stats)

    try:
        if HAVE_RICH:
            with Live(console=console, refresh_per_second=1) as live:
                while True:
                    sent, received = poll()
                    live.update(build_table(sent, received, stats, args.interval))
        else:
            while True:
                sent, received = poll()
                print(build_table(sent, received, stats, args.interval))
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
