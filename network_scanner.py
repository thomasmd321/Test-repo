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
"""

import argparse
import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_local_subnet() -> str:
    """Guess the local /24 subnet from the host's primary network interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def arp_scan(subnet: str, timeout: float):
    """Discover devices with an ARP request broadcast (requires scapy + privileges)."""
    from scapy.all import ARP, Ether, srp

    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _ = srp(request, timeout=timeout, verbose=False)

    devices = []
    for _, received in answered:
        devices.append({"ip": received.psrc, "mac": received.hwsrc})
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


def scan(subnet: str, timeout: float):
    """Scan the subnet, preferring an ARP scan and falling back to a ping sweep."""
    try:
        return arp_scan(subnet, timeout)
    except (ImportError, PermissionError, OSError):
        return ping_sweep(subnet, timeout)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("subnet", nargs="?", help="Subnet to scan in CIDR notation, e.g. 192.168.1.0/24")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds per host (default: 1.0)")
    args = parser.parse_args()

    subnet = args.subnet or get_local_subnet()
    print(f"Scanning {subnet} ...")

    devices = scan(subnet, args.timeout)

    if not devices:
        print("No devices found.")
        return

    print(f"\n{'IP Address':<18}{'MAC Address':<20}Hostname")
    print("-" * 60)
    for device in devices:
        print(f"{device['ip']:<18}{device.get('mac') or '-':<20}{device.get('hostname', '')}")
    print(f"\n{len(devices)} device(s) found.")


if __name__ == "__main__":
    main()
