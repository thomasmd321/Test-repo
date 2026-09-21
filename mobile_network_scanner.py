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

Note on scanning multiple subnets: unlike network_scanner.py, this script
can't auto-detect every subnet a device is attached to - listing network
interfaces requires OS APIs (or the `psutil` package, which needs a C
compiler to build and generally isn't available in these sandboxes) that
iOS's sandbox doesn't expose. It also matters less here: a phone typically
has just one active local network (Wi-Fi) at a time. If you do know of more
than one subnet to check (e.g. your Wi-Fi range and a VPN range), pass them
as a comma-separated list and this script will scan each of them.

Usage:
    python mobile_network_scanner.py                    # auto-detect local subnet
    python mobile_network_scanner.py 192.168.1.0/24      # scan a specific subnet
    python mobile_network_scanner.py 192.168.1.0/24,10.0.0.0/24  # scan several
    python mobile_network_scanner.py --timeout 0.5 --ports 22,80,443
"""

import argparse
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Sequence, TypedDict


class Device(TypedDict):
    """A single discovered device, as returned by tcp_scan()."""

    ip: str
    hostname: str
    # The first port from the probe list that accepted a connection. This
    # is often a useful fingerprint on its own for a device with no
    # hostname - see PORT_SERVICES below - though it's only ever *one*
    # open port, not a full list of everything the device is listening on.
    port: int


# Ports likely to be open on common home/office devices, so a scan finds
# something useful without the caller having to know what to look for:
#   80, 443, 8080, 8443 - web UIs (routers, printers, smart-home hubs, IoT)
#   22                  - SSH (computers, NAS boxes, routers)
#   445, 139            - Windows/SMB file sharing
#   3389                - RDP (Windows remote desktop)
#   5000, 7000          - common dev-server / media-app ports (e.g. AirPlay)
#   62078               - Apple's "lockdownd" service (iPhones/iPads)
# This is a heuristic, not an exhaustive list - use --ports to override it
# if the devices you're looking for listen on something else. A few more
# worth trying for devices that don't show up above (pass them via
# --ports, comma-separated alongside these): 53 (DNS), 554 (RTSP/cameras),
# 1900 (SSDP/UPnP), 5353 (mDNS/Bonjour), 8009 (Chromecast).
DEFAULT_PORTS: Sequence[int] = (80, 443, 22, 445, 139, 8080, 8443, 62078, 3389, 5000, 7000)

# Short, human-readable labels for well-known ports, used only to annotate
# the results table - a hint at what a device might be, not a certainty
# (lots of devices repurpose these ports, or run several services on
# different ones and only happen to answer on the one we probed first).
# Covers DEFAULT_PORTS plus the extra ports suggested above, so the label
# still shows up if you pass those in via --ports.
PORT_SERVICES: Dict[int, str] = {
    80: "http",
    443: "https",
    22: "ssh",
    445: "smb",
    139: "netbios",
    8080: "http-alt",
    8443: "https-alt",
    62078: "lockdownd (iOS)",
    3389: "rdp",
    5000: "upnp/airplay",
    7000: "airplay",
    53: "dns",
    554: "rtsp (camera/streaming)",
    1900: "ssdp/upnp",
    5353: "mdns/bonjour",
    8009: "chromecast",
}


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


def probe_host(ip: str, ports: Iterable[int], timeout: float) -> Optional[int]:
    """Try connecting to each of the given TCP ports on ip, in order.

    Uses an ordinary client TCP socket - the only kind of socket a
    sandboxed app is allowed to open - so this works without root,
    subprocess access, or raw sockets.

    Args:
        ip: The target host's IPv4 address.
        ports: TCP ports to try, in order. Stops at the first success.
        timeout: Per-port connection timeout, in seconds.

    Returns:
        The first port that accepted a connection (host is up, and this
        is a hint at what service/device it might be - see
        PORT_SERVICES), or None if every port timed out or was refused.
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
                return port
    return None


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
        populated if reverse DNS resolved it (or "" if not) and "port"
        set to whichever probed port answered first.
    """
    # strict=False: subnet may be given as a host address (e.g. from
    # get_local_subnet()) rather than a "clean" network address.
    network = ipaddress.ip_network(subnet, strict=False)
    # .hosts() excludes the network and broadcast addresses, since those
    # aren't assignable to real devices.
    hosts = list(network.hosts())

    # Maps each live host to the port that answered, so tcp_scan() can
    # report it alongside the hostname - a useful fingerprint for devices
    # with no reverse-DNS name (see PORT_SERVICES).
    matched_ports: Dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit every probe up front; futures maps each pending result
        # back to the IP it's checking, since as_completed() only hands
        # back the future itself, not its arguments.
        futures = {executor.submit(probe_host, str(ip), ports, timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            port = future.result()
            if port is not None:
                matched_ports[str(ip)] = port

    devices: List[Device] = []
    for ip_str, port in matched_ports.items():
        try:
            # gethostbyaddr does a reverse-DNS (PTR) lookup; on a home
            # network this usually only resolves for the router itself,
            # since consumer devices rarely register PTR records.
            hostname = socket.gethostbyaddr(ip_str)[0]
        except (socket.herror, socket.gaierror):
            # No PTR record, or the lookup timed out/failed outright -
            # either way, we just don't have a hostname for this device.
            hostname = ""
        devices.append({"ip": ip_str, "hostname": hostname, "port": port})

    # Sort numerically by IP (not lexicographically as strings, which would
    # put "10.0.0.2" after "10.0.0.10").
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def scan_all_subnets(
    subnets: Iterable[str],
    timeout: float = 0.5,
    ports: Sequence[int] = DEFAULT_PORTS,
    max_workers: int = 100,
) -> List[Device]:
    """Run tcp_scan() over multiple subnets and merge the results into one list.

    Args:
        subnets: CIDR ranges to scan, e.g. ["192.168.1.0/24", "10.0.0.0/24"].
        timeout: Passed through to tcp_scan() for each subnet.
        ports: Passed through to tcp_scan() for each subnet.
        max_workers: Passed through to tcp_scan() for each subnet.

    Returns:
        Every discovered device across all subnets, sorted by IP and
        de-duplicated by IP address (the same device could otherwise be
        listed twice if two of the given subnets overlap).
    """
    # Keyed by IP so a later subnet's result for the same address simply
    # overwrites the earlier one rather than producing a duplicate row.
    devices_by_ip: Dict[str, Device] = {}
    for subnet in subnets:
        for device in tcp_scan(subnet, timeout=timeout, ports=ports, max_workers=max_workers):
            devices_by_ip[device["ip"]] = device

    return sorted(devices_by_ip.values(), key=lambda d: ipaddress.ip_address(d["ip"]))


def main() -> None:
    """CLI entry point: parse arguments, run the scan, and print a results table."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "subnet",
        nargs="?",
        help="Subnet(s) to scan in CIDR notation, comma-separated for more than one, e.g. 192.168.1.0/24,10.0.0.0/24",
    )
    parser.add_argument("--timeout", type=float, default=0.5, help="Timeout in seconds per port probe (default: 0.5)")
    parser.add_argument("--ports", type=str, default=None, help="Comma-separated TCP ports to probe (default: common ports)")
    args = parser.parse_args()

    # If the user didn't pass a subnet, auto-detect it from the device's
    # own network configuration instead of forcing them to look it up.
    # Multiple comma-separated subnets are supported since this sandbox
    # can't auto-detect more than one for us (see the module docstring).
    subnets: List[str] = [s.strip() for s in args.subnet.split(",")] if args.subnet else [get_local_subnet()]

    # --ports takes a comma-separated string on the command line (e.g.
    # "22,80,443"); convert it to a tuple of ints, or fall back to the
    # built-in defaults if the flag wasn't given at all.
    ports: Sequence[int] = tuple(int(p) for p in args.ports.split(",")) if args.ports else DEFAULT_PORTS

    print(f"Scanning {', '.join(subnets)} on ports {ports} ...")

    devices: List[Device] = scan_all_subnets(subnets, timeout=args.timeout, ports=ports)

    if not devices:
        print("No devices found.")
        return

    # Fixed-width columns keep the table aligned regardless of how long
    # each IP/hostname value happens to be.
    print(f"\n{'IP Address':<18}{'Port':<8}{'Service':<24}Hostname")
    print("-" * 70)
    for device in devices:
        port = device["port"]
        # Fall back to just the bare port number for anything not in
        # PORT_SERVICES (e.g. a custom --ports value we don't recognize).
        service = PORT_SERVICES.get(port, "?")
        print(f"{device['ip']:<18}{port:<8}{service:<24}{device.get('hostname', '')}")
    print(f"\n{len(devices)} device(s) found.")


if __name__ == "__main__":
    main()
