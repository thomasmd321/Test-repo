#!/usr/bin/env python3
"""Live per-device bandwidth dashboard for your local network.

Passively sniffs traffic on a network interface and aggregates bytes
seen per IP address, showing which devices on the LAN are using the
most bandwidth right now. This only observes traffic -- it never
alters, redirects, or throttles anyone's connection.

Caveat: on a typical switched network, an ordinary host only sees its
own unicast traffic plus broadcast/multicast traffic, not other
devices' unicast traffic. For visibility across the whole LAN, run
this on the router/gateway itself, or on a machine connected to a
mirror/SPAN port. Otherwise this will mostly show your own device.

Requires scapy (sniffing) and, for the live table, the optional
`rich` package; without `rich` it falls back to a plain periodic text
summary. Sniffing raw packets typically requires root/administrator
privileges.

Usage:
    sudo python bandwidth_dashboard.py                  # auto-pick interface
    sudo python bandwidth_dashboard.py --interface eth0
    sudo python bandwidth_dashboard.py --interval 5
"""

import argparse
import ipaddress
import socket
import threading
import time
from collections import defaultdict

try:
    from scapy.all import conf, sniff
except ImportError:
    conf = None

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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--interface", help="Network interface to sniff on (default: scapy's default)")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between dashboard refreshes (default: 2)")
    args = parser.parse_args()

    if conf is None:
        raise SystemExit("This tool requires scapy: pip install scapy")

    stats = Stats()

    def sniffer():
        sniff(iface=args.interface, prn=stats.record, store=False)

    thread = threading.Thread(target=sniffer, daemon=True)
    thread.start()

    console = Console() if HAVE_RICH else None
    print(f"Sniffing on {args.interface or conf.iface} ... Ctrl+C to stop.")
    print(
        "Note: on a switched network you'll mainly see your own device's traffic\n"
        "plus broadcast/multicast, unless this runs on the gateway or a mirror port.\n"
    )

    try:
        if HAVE_RICH:
            with Live(console=console, refresh_per_second=1) as live:
                while True:
                    time.sleep(args.interval)
                    sent, received = stats.snapshot_and_reset()
                    live.update(build_table(sent, received, stats, args.interval))
        else:
            while True:
                time.sleep(args.interval)
                sent, received = stats.snapshot_and_reset()
                print(build_table(sent, received, stats, args.interval))
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
