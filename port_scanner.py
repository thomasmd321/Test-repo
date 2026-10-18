#!/usr/bin/env python3
"""TCP port scanner for a single host on your own network.

Connects to each candidate port with a short timeout -- a standard TCP
connect scan, no raw packets and no stealth/SYN tricks -- and reports
which ones accept connections. Pairs naturally with network_scanner.py:
scan the LAN for devices, then scan a specific device's ports. Only
scan hosts you own or have explicit permission to test.

Usage:
    python port_scanner.py 192.168.1.50                  # ~25 common ports
    python port_scanner.py 192.168.1.50 --ports 1-1024
    python port_scanner.py 192.168.1.50 --ports 22,80,443
    python port_scanner.py 192.168.1.50 --ports 1-65535 --timeout 0.3

Exit code is 0 if at least one open port was found, 1 if none were.
"""

import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

# A short, well-known list covering the services most likely to be
# running on a home-network device, so a plain `port_scanner.py <host>`
# finishes in well under a second without needing --ports.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587,
    993, 995, 1723, 3000, 3306, 3389, 5000, 5900, 6379, 8000, 8080, 8443,
]


def parse_ports(spec: str) -> list:
    """Parse "22,80,443" / "1-1024" / a mix of both into sorted unique ports."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_str, _, end_str = part.partition("-")
            start, end = int(start_str), int(end_str)
            if start > end:
                raise ValueError(f"invalid range {part!r}: start > end")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} is out of the valid range 1-65535")
    return sorted(ports)


def scan_port(host: str, port: int, timeout: float) -> bool:
    """Return True if a TCP connection to host:port is accepted."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def scan_host(host: str, ports: list, timeout: float, max_workers: int = 200) -> list:
    """Return the sorted list of ports on host that accepted a connection."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except OSError:
                continue  # e.g. transient "too many open files" -- skip this port
    return sorted(open_ports)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", help="Target IP or hostname on your own network")
    parser.add_argument("--ports", help="Ports to scan, e.g. '22,80,443' or '1-1024' (default: ~25 common ports)")
    parser.add_argument("--timeout", type=float, default=0.5, help="Seconds to wait per port (default: 0.5)")
    parser.add_argument("--workers", type=int, default=200, help="Concurrent connection attempts (default: 200)")
    args = parser.parse_args()

    if args.workers < 1:
        raise SystemExit(f"--workers must be at least 1 (got {args.workers})")

    if args.timeout < 0:
        raise SystemExit(f"--timeout must not be negative (got {args.timeout})")

    try:
        ports = parse_ports(args.ports) if args.ports else list(COMMON_PORTS)
    except ValueError as exc:
        raise SystemExit(f"Invalid --ports {args.ports!r}: {exc}")

    try:
        resolved = socket.gethostbyname(args.host)
    except socket.gaierror as exc:
        raise SystemExit(f"Could not resolve {args.host}: {exc}")

    print(f"Scanning {args.host} ({len(ports)} ports) ...")
    try:
        open_ports = scan_host(resolved, ports, args.timeout, args.workers)
    except KeyboardInterrupt:
        print("\nStopped.")
        return

    if not open_ports:
        print("No open ports found.")
        sys.exit(1)

    print(f"\n{'Port':<8}Service")
    print("-" * 30)
    for port in open_ports:
        print(f"{port:<8}{service_name(port)}")
    print(f"\n{len(open_ports)} open port(s) found.")


if __name__ == "__main__":
    main()
