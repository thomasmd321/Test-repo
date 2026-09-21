#!/usr/bin/env python3
"""Discover devices on the local network.

Uses an ARP scan via scapy when available (fast, returns MAC addresses
directly). Falls back to a multithreaded ping sweep plus the system ARP
table when scapy isn't installed or the process lacks the privileges
ARP scanning requires.

Usage:
    python network_scanner.py                     # auto-detect local subnet
    python network_scanner.py 192.168.1.0/24       # scan a specific subnet
    python network_scanner.py 192.168.1.0/24,10.0.0.0/24  # scan several subnets
    python network_scanner.py --all-subnets        # scan every subnet this
                                                    # machine has an interface
                                                    # on (needs `pip install
                                                    # psutil`)
    python network_scanner.py --timeout 2
"""

import argparse
import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, TypedDict


class Device(TypedDict):
    """A single discovered device, as returned by arp_scan() and ping_sweep()."""

    ip: str
    mac: str
    # ping_sweep() also sets this key; arp_scan() does not (it has no way to
    # resolve hostnames), so callers should use device.get("hostname", "").
    hostname: str


def get_local_subnet() -> str:
    """Guess the local /24 subnet from the host's primary network interface.

    Returns:
        A CIDR string, e.g. "192.168.1.0/24".
    """
    # Connecting a UDP socket doesn't actually send any packets - it just
    # asks the OS to pick a local address/route for that destination, which
    # is a reliable, cross-platform way to find "my" outward-facing IP
    # without depending on a specific network interface name.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        local_ip = sock.getsockname()[0]

    # strict=False lets ipaddress build the containing network even though
    # local_ip is a host address, not the network address itself.
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    return str(network)


def get_local_subnets() -> List[str]:
    """Detect every local IPv4 subnet this machine has a network interface on.

    get_local_subnet() only finds the one subnet reachable via the OS's
    default route, so a machine with more than one active network (e.g.
    Wi-Fi *and* Ethernet, or a VPN) would have every other subnet go
    unscanned. This enumerates all interfaces instead, via the optional
    `psutil` dependency (not in the standard library, since there's no
    portable, dependency-free way to list interfaces/netmasks across
    Linux/macOS/Windows).

    Returns:
        A de-duplicated, sorted list of CIDR strings, e.g.
        ["10.8.0.0/24", "192.168.1.0/24"]. Loopback (127.0.0.0/8) and
        link-local (169.254.0.0/16) ranges are excluded, since those
        aren't networks other real devices live on. Falls back to a
        single-element list from get_local_subnet() if psutil isn't
        installed.
    """
    try:
        # Imported lazily so machines without psutil installed can still
        # use every other feature of this script - only --all-subnets
        # needs it.
        import psutil
    except ImportError:
        return [get_local_subnet()]

    subnets = set()
    # net_if_addrs() maps interface name -> list of its addresses (IPv4,
    # IPv6, and MAC, all mixed together), so we look at every interface's
    # every address rather than assuming one address per interface.
    for addresses in psutil.net_if_addrs().values():
        for addr in addresses:
            if addr.family != socket.AF_INET or not addr.netmask:
                # Skip IPv6/MAC entries, and any IPv4 entry missing a
                # netmask (some virtual interfaces report one without
                # the other).
                continue
            network = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
            if network.is_loopback or network.is_link_local:
                continue
            subnets.add(network)

    return [str(network) for network in sorted(subnets)]


def scan_all_subnets(subnets: Iterable[str], timeout: float) -> List[Device]:
    """Run scan() over multiple subnets and merge the results into one list.

    Args:
        subnets: CIDR ranges to scan, e.g. from get_local_subnets().
        timeout: Passed through to scan() for each subnet.

    Returns:
        Every discovered device across all subnets, sorted by IP and
        de-duplicated by IP address (the same device could otherwise be
        listed twice if, say, two scanned subnets overlap via a bridged
        or VPN interface).
    """
    # Keyed by IP so a later subnet's result for the same address simply
    # overwrites the earlier one rather than producing a duplicate row.
    devices_by_ip: Dict[str, Device] = {}
    for subnet in subnets:
        for device in scan(subnet, timeout):
            devices_by_ip[device["ip"]] = device

    return sorted(devices_by_ip.values(), key=lambda d: ipaddress.ip_address(d["ip"]))


def arp_scan(subnet: str, timeout: float) -> List[Device]:
    """Discover devices with an ARP request broadcast.

    This is the fast, reliable path: an ARP reply cannot be spoofed by
    firewall rules the way an ICMP ping reply can, and it hands back the
    MAC address directly. It requires the `scapy` package to be installed
    and, on most OSes, the process to be running as root/administrator
    (raw Ethernet frames need elevated privileges).

    Args:
        subnet: CIDR range to scan, e.g. "192.168.1.0/24".
        timeout: How long to wait (in seconds) for ARP replies to arrive.

    Returns:
        Discovered devices sorted by IP address. "hostname" is always an
        empty string, since ARP alone carries no reverse-DNS or name
        information - it's included only so callers can treat the
        return value of arp_scan() and ping_sweep() identically.

    Raises:
        ImportError: scapy is not installed.
        PermissionError / OSError: the process lacks permission to open
            raw sockets (e.g. not running as root).
    """
    # Imported lazily, not at module load time, so that machines without
    # scapy installed can still import and use this module (they'll just
    # fail here and fall back to ping_sweep() via scan()).
    from scapy.all import ARP, Ether, srp

    # Ether(dst="ff:ff:ff:ff:ff:ff") broadcasts the frame to every device
    # on the local link; ARP(pdst=subnet) asks "who has this IP?" for every
    # address in the subnet in one request.
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

    # srp() sends the layer-2 frame and collects replies until timeout.
    # answered pairs each reply with the request that triggered it;
    # unanswered (the second, unused return value) lists timed-out hosts.
    answered, _unanswered = srp(request, timeout=timeout, verbose=False)

    devices: List[Device] = []
    for _sent, received in answered:
        # psrc/hwsrc are the sender's (i.e. the *replying* device's) IP and
        # MAC address fields inside the ARP reply packet.
        devices.append({"ip": received.psrc, "mac": received.hwsrc, "hostname": ""})

    # Sort numerically by IP (not lexicographically as strings, which would
    # put "10.0.0.2" after "10.0.0.10").
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def ping(ip: str, timeout: float) -> bool:
    """Return True if the host responds to a single ICMP ping.

    Shells out to the OS's `ping` binary rather than opening a raw ICMP
    socket, since raw sockets need root/administrator privileges on most
    platforms and the `ping` binary is typically already
    privilege-escalated (e.g. via a setuid bit) to do this for us.

    Args:
        ip: The target host's IPv4 address.
        timeout: How long to wait for a reply, in seconds.

    Returns:
        True if the ping succeeded (host is reachable), False otherwise
        (host is down, unreachable, or blocking ICMP).
    """
    is_windows = platform.system().lower() == "windows"

    # Windows' ping uses "-n" for packet count and "-w" (milliseconds) for
    # timeout; Linux/macOS use "-c" and "-W" (whole seconds) respectively.
    count_flag = "-n" if is_windows else "-c"
    if is_windows:
        timeout_flag = ["-w", str(int(timeout * 1000))]
    else:
        # max(1, ...) guards against a 0-second timeout, which some ping
        # implementations treat as "wait forever" instead of "don't wait".
        timeout_flag = ["-W", str(max(1, int(timeout)))]

    command = ["ping", count_flag, "1", *timeout_flag, ip]

    # Discard ping's stdout/stderr - we only care about its exit code
    # (0 = got a reply, non-zero = timed out or errored).
    result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def read_arp_table() -> Dict[str, str]:
    """Parse the OS's ARP cache into a map of IP address -> MAC address.

    The ARP cache only contains entries for hosts the OS has already
    exchanged packets with (e.g. via the ping_sweep() above), so this
    should be called *after* pinging hosts, not before.

    Returns:
        A dict mapping IP address strings to lowercase, colon-separated
        MAC address strings. Empty if the `arp` command isn't available
        on this system.
    """
    command = ["arp", "-a"]
    try:
        output = subprocess.run(command, capture_output=True, text=True, check=False).stdout
    except FileNotFoundError:
        # Some minimal/sandboxed environments don't ship an `arp` binary;
        # treat that as "no MAC info available" rather than crashing.
        return {}

    # Matches MAC addresses in either aa:bb:cc:dd:ee:ff or aa-bb-cc-dd-ee-ff
    # form, since different OSes format `arp -a` output differently.
    mac_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")
    ip_pattern = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

    table: Dict[str, str] = {}
    for line in output.splitlines():
        ip_match = ip_pattern.search(line)
        mac_match = mac_pattern.search(line)
        # A line only tells us something useful if it has both an IP and a
        # MAC on it (header lines, blank lines, etc. have neither or one).
        if ip_match and mac_match:
            # Normalize to lowercase, colon-separated form regardless of
            # how the OS printed it, so callers get one consistent format.
            table[ip_match.group()] = mac_match.group().replace("-", ":").lower()
    return table


def ping_sweep(subnet: str, timeout: float, max_workers: int = 100) -> List[Device]:
    """Discover devices by pinging every host in a subnet, then reading the ARP cache.

    This is the fallback used when arp_scan() isn't available (no scapy,
    or no root/administrator privileges). It's slower and less reliable
    than an ARP scan - some devices silently drop ICMP pings - but it
    works anywhere `ping` and `arp` are installed and needs no special
    privileges.

    Args:
        subnet: CIDR range to scan, e.g. "192.168.1.0/24".
        timeout: Per-host ping timeout, in seconds.
        max_workers: How many hosts to ping concurrently. A /24 subnet
            has 254 usable addresses, so pinging them one at a time would
            take 254x as long as the timeout; a thread pool lets us ping
            them all in parallel instead.

    Returns:
        Discovered devices sorted by IP address, each with "mac" (empty
        string if not found in the ARP cache) and "hostname" (empty
        string if reverse DNS lookup failed) populated.
    """
    # strict=False: subnet may be given as a host address (e.g. from
    # get_local_subnet()) rather than a "clean" network address.
    network = ipaddress.ip_network(subnet, strict=False)
    # .hosts() excludes the network and broadcast addresses, since those
    # aren't assignable to real devices.
    hosts = list(network.hosts())

    live_ips = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit every ping up front; futures maps each pending result
        # back to the IP it's checking, since as_completed() only hands
        # back the future itself, not its arguments.
        futures = {executor.submit(ping, str(ip), timeout): ip for ip in hosts}
        for future in as_completed(futures):
            ip = futures[future]
            if future.result():
                live_ips.append(ip)

    # Read the ARP cache once, after all pings have completed, rather than
    # once per host - it's a single cheap system call either way, but
    # doing it once avoids 254 redundant subprocess spawns.
    arp_table = read_arp_table()

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
        devices.append({"ip": ip_str, "mac": arp_table.get(ip_str, ""), "hostname": hostname})

    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def scan(subnet: str, timeout: float) -> List[Device]:
    """Scan the subnet, preferring an ARP scan and falling back to a ping sweep.

    Args:
        subnet: CIDR range to scan, e.g. "192.168.1.0/24".
        timeout: Timeout in seconds, passed through to whichever scan
            method actually runs.

    Returns:
        Discovered devices, in whichever format arp_scan()/ping_sweep()
        produced (see their docstrings for the exact shape).
    """
    try:
        return arp_scan(subnet, timeout)
    except (ImportError, PermissionError, OSError):
        # ImportError: scapy isn't installed.
        # PermissionError/OSError: scapy is installed but we can't open
        # the raw socket it needs (not running as root/administrator).
        # Any other exception is unexpected and should propagate, since
        # silently swallowing it could hide a real bug.
        return ping_sweep(subnet, timeout)


def main() -> None:
    """CLI entry point: parse arguments, run the scan, and print a results table."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "subnet",
        nargs="?",
        help="Subnet(s) to scan in CIDR notation, comma-separated for more than one, e.g. 192.168.1.0/24,10.0.0.0/24",
    )
    parser.add_argument(
        "--all-subnets",
        action="store_true",
        help="Auto-detect and scan every local subnet this machine has an interface on (requires `pip install psutil`), instead of just the one on the default route",
    )
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds per host (default: 1.0)")
    args = parser.parse_args()

    # Precedence: an explicit subnet argument always wins; otherwise
    # --all-subnets scans everything psutil can see; otherwise fall back
    # to auto-detecting just the one subnet on the default route.
    if args.subnet:
        subnets: List[str] = [s.strip() for s in args.subnet.split(",")]
    elif args.all_subnets:
        subnets = get_local_subnets()
    else:
        subnets = [get_local_subnet()]

    print(f"Scanning {', '.join(subnets)} ...")

    devices: List[Device] = scan_all_subnets(subnets, args.timeout)

    if not devices:
        print("No devices found.")
        return

    # Fixed-width columns keep the table aligned regardless of how long
    # each IP/MAC/hostname value happens to be.
    print(f"\n{'IP Address':<18}{'MAC Address':<20}Hostname")
    print("-" * 60)
    for device in devices:
        # "-" as a placeholder makes it visually obvious that a MAC
        # address is missing, rather than leaving a confusing blank gap.
        mac_display = device.get("mac") or "-"
        print(f"{device['ip']:<18}{mac_display:<20}{device.get('hostname', '')}")
    print(f"\n{len(devices)} device(s) found.")


if __name__ == "__main__":
    main()
