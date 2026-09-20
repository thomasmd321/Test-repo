#!/usr/bin/env python3
"""Discover devices on the local network from a sandboxed environment (e.g. iOS).

network_scanner.py relies on `subprocess` (to shell out to `ping`/`arp`) and
optionally raw sockets (scapy's ARP scan). Sandboxed Python runtimes such as
iOS apps (Pythonista, a-Shell, Pyto) allow neither: no spawning external
processes, no raw sockets. This script instead discovers hosts by attempting
plain TCP connections to a handful of commonly-open ports, which only needs
an ordinary client socket and works anywhere Python's `socket` module does.

It will not find hosts with none of the probed ports open or reachable
(e.g. a phone with all inbound connections blocked), so it's a best-effort
discovery method, not a guarantee of completeness the way an ARP scan is.

Usage:
    python mobile_network_scanner.py                 # auto-detect local subnet
    python mobile_network_scanner.py 192.168.1.0/24   # scan a specific subnet
    python mobile_network_scanner.py --timeout 0.5 --ports 22,80,443
"""

import argparse
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

DEFAULT_PORTS = (80, 443, 22, 445, 139, 8080, 8443, 62078)


def get_local_subnet() -> str:
    """Guess the local /24 subnet from the device's primary network interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def probe_host(ip: str, ports, timeout: float) -> bool:
    """Return True if any of the given TCP ports accept a connection on ip."""
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((ip, port)) == 0:
                return True
    return False


def tcp_scan(subnet: str, timeout: float = 0.5, ports=DEFAULT_PORTS, max_workers: int = 100):
    """Discover devices by probing common TCP ports across every host in subnet."""
    network = ipaddress.ip_network(subnet, strict=False)
    hosts = list(network.hosts())

    live_ips = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(probe_host, str(ip), ports, timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                live_ips.append(ip)

    devices = []
    for ip in live_ips:
        ip_str = str(ip)
        try:
            hostname = socket.gethostbyaddr(ip_str)[0]
        except (socket.herror, socket.gaierror):
            hostname = ""
        devices.append({"ip": ip_str, "hostname": hostname})

    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("subnet", nargs="?", help="Subnet to scan in CIDR notation, e.g. 192.168.1.0/24")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout in seconds per port probe (default: 0.5)")
    parser.add_argument("--ports", type=str, default=None, help="Comma-separated TCP ports to probe (default: common ports)")
    args = parser.parse_args()

    subnet = args.subnet or get_local_subnet()
    ports = tuple(int(p) for p in args.ports.split(",")) if args.ports else DEFAULT_PORTS

    print(f"Scanning {subnet} on ports {ports} ...")

    devices = tcp_scan(subnet, timeout=args.timeout, ports=ports)

    if not devices:
        print("No devices found.")
        return

    print(f"\n{'IP Address':<18}Hostname")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']:<18}{device.get('hostname', '')}")
    print(f"\n{len(devices)} device(s) found.")


if __name__ == "__main__":
    main()
