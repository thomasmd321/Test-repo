#!/usr/bin/env python3
"""Live per-device bandwidth dashboard for your local network.

Two data sources, picked with --source:

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

Neither mode alters, redirects, or throttles anyone's connection --
both only observe.

Requires scapy for --source sniff, and (for either source) the
optional `rich` package for the live table; without `rich` it falls
back to a plain periodic text summary. Sniffing raw packets typically
requires root/administrator privileges.

Usage:
    sudo python bandwidth_dashboard.py                          # sniff, auto-pick interface
    sudo python bandwidth_dashboard.py --interface eth0
    python bandwidth_dashboard.py --source conntrack             # running on the router itself
    python bandwidth_dashboard.py --source conntrack --host root@192.168.1.1
"""

import argparse
import ipaddress
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", choices=("sniff", "conntrack"), default="sniff", help="Data source (default: sniff)")
    parser.add_argument("--interface", help="[sniff] Network interface to sniff on (default: scapy's default)")
    parser.add_argument("--host", help="[conntrack] SSH target for the router, e.g. root@192.168.1.1 (default: read locally)")
    parser.add_argument("--ssh-port", type=int, default=22, help="[conntrack] SSH port (default: 22)")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between dashboard refreshes (default: 2)")
    args = parser.parse_args()

    stats = Stats()
    poll = run_sniff_source(args, stats) if args.source == "sniff" else run_conntrack_source(args, stats)
    console = Console() if HAVE_RICH else None

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
