#!/usr/bin/env python3
"""Discover devices on the local network.

Uses an ARP scan via scapy when available (fast, returns MAC addresses
directly). Falls back to a multithreaded ping sweep plus the system ARP
table when scapy isn't installed or the process lacks the privileges
ARP scanning requires.

Usage:
    python network_scanner.py                 # auto-detect local subnet
    python network_scanner.py 192.168.1.0/24   # scan a specific subnet
    python network_scanner.py --timeout 2
    python network_scanner.py --ips-only           # one bare IP per line
    python network_scanner.py --ips-only | xargs -n1 port_scanner.py
    python network_scanner.py --json

Exit code is 0 if at least one device was found, 1 if none were.
"""

import argparse
import ipaddress
import json
import platform
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# Sane upper bound for a single sequential scan (~a /20). Without this, a
# typo'd subnet like /8 would silently try to sweep millions of hosts --
# allocating a Future per address up front -- and hang or exhaust memory
# before producing any output.
DEFAULT_MAX_HOSTS = 4096


def get_local_subnet():
    """Guess the local /24 subnet from the host's primary network
    interface. Returns None (rather than letting OSError propagate) if
    no network route is available -- e.g. no interface is up -- the
    same way lan_file_server.get_lan_ip() handles the identical
    "guess my LAN-facing address" trick."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
    except OSError:
        return None
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def arp_scan(subnet: str, timeout: float):
    """Discover devices with an ARP request broadcast (requires scapy + privileges)."""
    from scapy.all import ARP, Ether, srp

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(request, timeout=timeout, verbose=False)

    devices = []
    for _, received in answered:
        # "hostname" is always "" here (ARP doesn't resolve names), but the
        # key is still present so callers -- --json in particular -- see
        # the same device schema regardless of which scan method ran.
        devices.append({"ip": received.psrc, "mac": received.hwsrc, "hostname": ""})
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def ping(ip: str, timeout: float) -> bool:
    """Return True if the host responds to a single ping."""
    count_flag = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_ms = str(int(timeout * 1000))
    timeout_flag = ["-w", timeout_ms] if platform.system().lower() == "windows" else ["-W", str(max(1, int(timeout)))]

    command = ["ping", count_flag, "1", *timeout_flag, ip]
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def read_arp_table() -> dict:
    """Parse the OS ARP cache into a map of IP -> MAC address."""
    command = ["arp", "-a"]
    try:
        output = subprocess.run(command, capture_output=True, text=True, check=False).stdout
    except FileNotFoundError:
        return {}

    mac_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
    ip_pattern = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

    table = {}
    for line in output.splitlines():
        ip_match = ip_pattern.search(line)
        mac_match = mac_pattern.search(line)
        if ip_match and mac_match:
            table[ip_match.group()] = mac_match.group().replace("-", ":").lower()
    return table


def ping_sweep(subnet: str, timeout: float, max_workers: int = 100):
    """Discover devices by pinging every host in the subnet, then reading the ARP cache."""
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())

    live_ips = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(ping, str(ip), timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                live_ips.append(ip)

    arp_table = read_arp_table()

    devices = []
    for ip in live_ips:
        ip_str = str(ip)
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except (socket.herror, socket.gaierror):
            hostname = ""
        devices.append({"ip": ip_str, "mac": arp_table.get(ip_str, ""), "hostname": hostname})

    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def scan(subnet: str, timeout: float, log=print):
    """Scan the subnet, preferring an ARP scan and falling back to a ping
    sweep. Status messages go through log() rather than a bare print()
    so machine-readable output modes can redirect them off stdout."""
    try:
        return arp_scan(subnet, timeout)
    except Exception as exc:
        log(f"ARP scan unavailable ({exc}); falling back to ping sweep.")
        return ping_sweep(subnet, timeout)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("subnet", nargs="?", help="Subnet to scan in CIDR notation, e.g. 192.168.1.0/24")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds per host (default: 1.0)")
    parser.add_argument(
        "--max-hosts", type=int, default=DEFAULT_MAX_HOSTS,
        help=f"Refuse to scan a subnet larger than this many addresses, as a safety net "
             f"against typos like /8 (default: {DEFAULT_MAX_HOSTS})",
    )
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument("--ips-only", action="store_true", help="Print one bare IP per line instead of a table, for piping into another tool (e.g. port_scanner.py)")
    output_group.add_argument("--json", action="store_true", help="Print the device list as a JSON array instead of a table")
    args = parser.parse_args()

    machine_readable = args.ips_only or args.json

    def status(msg):
        print(msg, file=sys.stderr if machine_readable else sys.stdout)

    subnet = args.subnet or get_local_subnet()
    if subnet is None:
        raise SystemExit(
            "Could not auto-detect the local subnet (no network route available). "
            "Pass one explicitly, e.g. network_scanner.py 192.168.1.0/24."
        )

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise SystemExit(f"Invalid subnet {subnet!r}: {exc}")

    if network.num_addresses > args.max_hosts:
        raise SystemExit(
            f"{subnet} has {network.num_addresses} addresses, more than --max-hosts "
            f"({args.max_hosts}). This is almost always a typo (e.g. /8 instead of /24).\n"
            "Scan a smaller subnet, or pass --max-hosts to override."
        )

    status(f"Scanning {subnet} ...")

    try:
        devices = scan(subnet, args.timeout, log=status)
    except KeyboardInterrupt:
        status("\nStopped.")
        return

    if not devices:
        status("No devices found.")
        sys.exit(1)

    if args.ips_only:
        for device in devices:
            print(device["ip"])
    elif args.json:
        print(json.dumps(devices))
    else:
        print(f"\n{'IP Address':<18}{'MAC Address':<20}Hostname")
        print("-" * 60)
        for device in devices:
            print(f"{device['ip']:<18}{device.get('mac') or '-':<20}{device.get('hostname', '')}")
        print(f"\n{len(devices)} device(s) found.")


if __name__ == "__main__":
    main()
