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
from typing import Iterable, List, Sequence, TypedDict


class Device(TypedDict):
    """A single discovered device, as returned by tcp_scan()."""

    ip: str
    hostname: str


# Ports likely to be open on common home/office devices, so a scan finds
# something useful without the caller having to know what to look for:
#   80, 443, 8080, 8443 - web UIs (routers, printers, smart-home hubs, IoT)
#   22                  - SSH (computers, NAS boxes, routers)
#   445, 139            - Windows/SMB file sharing
#   3389                - RDP (Windows remote desktop)
#   5000, 7000          - common dev-server / media-app ports (e.g. AirPlay)
#   62078               - Apple's "lockdownd" service (iPhones/iPads)
# This is a heuristic, not an exhaustive list - use --ports to override it
# if the devices you're looking for listen on something else.
DEFAULT_PORTS: Sequence[int] = (80, 443, 22, 445, 139, 8080, 8443, 62078, 3389, 5000, 7000)


def get_local_subnet() -> str:
    """Guess the local /24 subnet from the device's primary network interface.

    Returns:
        A CIDR string, e.g. "192.168.1.0/24".
    """
    # Connecting a UDP socket doesn't actually send any packets - it just
    # asks the OS to pick a local address/route for that destination, which
    # is a reliable way to find "my" IP without needing raw-socket or
    # interface-enumeration privileges the sandbox wouldn't grant anyway.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]

    # strict=False lets ipaddress build the containing network even though
    # local_ip is a host address, not the network address itself.
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def probe_host(ip: str, ports: Iterable[int], timeout: float) -> bool:
    """Return True if any of the given TCP ports accept a connection on ip.

    Uses an ordinary client TCP socket - the only kind of socket a
    sandboxed app is allowed to open - so this works without root,
    subprocess access, or raw sockets.

    Args:
        ip: The target host's IPv4 address.
        ports: TCP ports to try, in order. Stops at the first success.
        timeout: Per-port connection timeout, in seconds.

    Returns:
        True if at least one port accepted a connection (host is up),
        False if every port timed out or was refused.
    """
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            # connect_ex returns the connection's errno instead of raising
            # an exception, so a refused/timed-out port is just a nonzero
            # return value rather than something we need to catch.
            # 0 means the TCP handshake completed, i.e. something is
            # listening on that port and the host is reachable.
            if sock.connect_ex((ip, port)) == 0:
                return True
    return False


def tcp_scan(
    subnet: str,
    timeout: float = 0.5,
    ports: Sequence[int] = DEFAULT_PORTS,
    max_workers: int = 100,
) -> List[Device]:
    """Discover devices by probing common TCP ports across every host in subnet.

    Args:
        subnet: CIDR range to scan, e.g. "192.168.1.0/24".
        timeout: Per-port connection timeout, in seconds. Lower values
            scan faster but may miss slow-to-respond devices.
        ports: TCP ports to probe on each host (see DEFAULT_PORTS).
        max_workers: How many hosts to probe concurrently. A /24 subnet
            has 254 usable addresses, so probing them one at a time would
            take 254x as long as the timeout; a thread pool lets us probe
            them all in parallel instead.

    Returns:
        Discovered devices sorted by IP address, each with "hostname"
        populated if reverse DNS resolved it, or "" if not.
    """
    # strict=False: subnet may be given as a host address (e.g. from
    # get_local_subnet()) rather than a "clean" network address.
    network = ipaddress.ip_network(subnet, strict=False)
    # .hosts() excludes the network and broadcast addresses, since those
    # aren't assignable to real devices.
    hosts = list(network.hosts())

    live_ips = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit every probe up front; futures maps each pending result
        # back to the IP it's checking, since as_completed() only hands
        # back the future itself, not its arguments.
        futures = {executor.submit(probe_host, str(ip), ports, timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                live_ips.append(ip)

    devices: List[Device] = []
    for ip in live_ips:
        ip_str = str(ip)
        try:
            # gethostbyaddr does a reverse-DNS (PTR) lookup; on a home
            # network this usually only resolves for the router itself,
            # since consumer devices rarely register PTR records.
            hostname = socket.gethostbyaddr(ip_str)[0]
        except (socket.herror, socket.gaierror):
            # No PTR record, or the lookup timed out/failed outright -
            # either way, we just don't have a hostname for this device.
            hostname = ""
        devices.append({"ip": ip_str, "hostname": hostname})

    # Sort numerically by IP (not lexicographically as strings, which would
    # put "10.0.0.2" after "10.0.0.10").
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def main() -> None:
    """CLI entry point: parse arguments, run the scan, and print a results table."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("subnet", nargs="?", help="Subnet to scan in CIDR notation, e.g. 192.168.1.0/24")
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout in seconds per port probe (default: 0.5)")
    parser.add_argument("--ports", type=str, default=None, help="Comma-separated TCP ports to probe (default: common ports)")
    args = parser.parse_args()

    # If the user didn't pass a subnet, auto-detect it from the device's
    # own network configuration instead of forcing them to look it up.
    subnet: str = args.subnet or get_local_subnet()

    # --ports takes a comma-separated string on the command line (e.g.
    # "22,80,443"); convert it to a tuple of ints, or fall back to the
    # built-in defaults if the flag wasn't given at all.
    ports: Sequence[int] = tuple(int(p) for p in args.ports.split(",")) if args.ports else DEFAULT_PORTS

    print(f"Scanning {subnet} on ports {ports} ...")

    devices: List[Device] = tcp_scan(subnet, timeout=args.timeout, ports=ports)

    if not devices:
        print("No devices found.")
        return

    # Fixed-width columns keep the table aligned regardless of how long
    # each IP/hostname value happens to be.
    print(f"\n{'IP Address':<18}Hostname")
    print("-" * 40)
    for device in devices:
        print(f"{device['ip']:<18}{device.get('hostname', '')}")
    print(f"\n{len(devices)} device(s) found.")


if __name__ == "__main__":
    main()
