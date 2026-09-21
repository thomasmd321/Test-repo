#!/usr/bin/env python3
"""Discover devices on the local network.

Uses an ARP scan via scapy when available (fast, returns MAC addresses
directly). Falls back to a multithreaded ping sweep plus the system ARP
table when scapy isn't installed or the process lacks the privileges
ARP scanning requires.

Any device still missing a hostname after that gets a second pass: mDNS/
Bonjour reverse lookup, then DNS-SD Cast service discovery for anything
that looks like it might be a Chromecast (see mdns_reverse_lookup() and
mdns_service_lookup()). Devices with a MAC address also get it looked up
against the IEEE's public OUI registry to identify the manufacturer
(see lookup_mac_vendor()) - this is unlike mobile_network_scanner.py's
iOS target, which can't do any of this due to Apple's sandboxing of
raw-socket multicast traffic; desktop/Termux environments have no such
restriction.

Every scan is also compared against a small local registry of previously
seen devices (see _mark_new_devices()), so a device that's never shown up
before gets flagged "NEW" in the results table. Pair this with --watch to
turn a one-shot scan into a lightweight "alert me when something joins my
network" monitor.

Usage:
    python network_scanner.py                     # auto-detect local subnet
    python network_scanner.py 192.168.1.0/24       # scan a specific subnet
    python network_scanner.py 192.168.1.0/24,10.0.0.0/24  # scan several subnets
    python network_scanner.py --all-subnets        # scan every subnet this
                                                    # machine has an interface
                                                    # on (needs `pip install
                                                    # psutil`)
    python network_scanner.py --timeout 2
    python network_scanner.py --no-vendor-lookup   # skip the OUI vendor lookup
    python network_scanner.py --watch 300          # rescan every 5 minutes,
                                                    # flagging newly-seen devices
"""

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, TypedDict


class Device(TypedDict, total=False):
    """A single discovered device, as returned by arp_scan() and ping_sweep().

    total=False since "port" and "risky_ports" are only ever present
    after scan_all_subnets() has run its optional port-scanning step
    (see _attach_open_ports()/_attach_risky_ports()) - callers should
    use device.get(...) for those two rather than direct indexing.
    """

    ip: str
    mac: str
    # ping_sweep() also sets this key; arp_scan() does not (it has no way to
    # resolve hostnames), so callers should use device.get("hostname", "").
    hostname: str
    # Filled in by _attach_vendor_names() from lookup_mac_vendor(); "" if
    # the device has no known MAC or that MAC isn't in the OUI registry.
    vendor: str
    # Filled in by _attach_open_ports() from probe_open_port(): the first
    # port from DEFAULT_PORTS (or a --ports override) that answered, or
    # None if none of them did. Absent entirely if port scanning was
    # skipped (--no-scan-ports) or hasn't run yet.
    port: Optional[int]
    # Filled in by _attach_risky_ports() from _find_risky_ports(): every
    # open port from RISKY_PORTS, not just the first one found. Absent
    # entirely if that check was skipped or hasn't run yet.
    risky_ports: List[int]


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


def scan_all_subnets(
    subnets: Iterable[str],
    timeout: float,
    mdns_timeout: float = 0.3,
    vendor_lookup: bool = True,
    refresh_vendor_db: bool = False,
    scan_ports: bool = True,
    ports: Optional[Sequence[int]] = None,
    port_timeout: float = 0.3,
    check_risky_ports: bool = True,
) -> List[Device]:
    """Run scan() over multiple subnets and merge the results into one list.

    Args:
        subnets: CIDR ranges to scan, e.g. from get_local_subnets().
        timeout: Passed through to scan() for each subnet.
        mdns_timeout: Timeout in seconds for the mDNS/DNS-SD hostname
            fallback (see _resolve_missing_hostnames()), run once per
            subnet since multicast traffic doesn't cross subnets.
        vendor_lookup: Whether to look up each device's MAC vendor via
            the IEEE OUI registry (see _attach_vendor_names()) - pass
            False to skip it entirely (e.g. for an offline scan).
        refresh_vendor_db: Force a fresh download of the OUI registry
            instead of reusing the cached copy (see lookup_mac_vendor()).
            Ignored if vendor_lookup is False.
        scan_ports: Whether to probe each device for an open port from
            `ports` (see _attach_open_ports()) and check it against
            RISKY_PORTS (see _attach_risky_ports()) - pass False to skip
            both entirely.
        ports: TCP ports to probe on each device, or None to use
            DEFAULT_PORTS (the default can't be used directly as this
            parameter's default value: DEFAULT_PORTS is defined later in
            this file, after this function). Ignored if scan_ports is False.
        port_timeout: Per-port connection timeout, in seconds, for both
            the open-port probe and the risky-ports check.
        check_risky_ports: Whether to run the RISKY_PORTS check at all -
            pass False to keep the open-port probe (for identification)
            without the separate security-hygiene check. Ignored if
            scan_ports is False.

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
        # Hostname resolution happens per subnet, before merging - mDNS/
        # DNS-SD traffic doesn't cross subnet boundaries, so a device on
        # one subnet can never answer a query sent while scanning another.
        for device in _resolve_missing_hostnames(scan(subnet, timeout), mdns_timeout):
            devices_by_ip[device["ip"]] = device

    devices = sorted(devices_by_ip.values(), key=lambda d: ipaddress.ip_address(d["ip"]))

    if vendor_lookup:
        # Vendor lookup isn't subnet-scoped - it's a pure lookup against
        # a MAC already in hand - so it's cheaper and simpler to do once
        # over the final, de-duplicated list rather than per subnet.
        devices = _attach_vendor_names(devices, force_refresh=refresh_vendor_db)

    if scan_ports and devices:
        # Same reasoning as vendor lookup: a TCP connect attempt against
        # an already-known IP isn't subnet-scoped either, so this also
        # runs once over the final list rather than per subnet.
        devices = _attach_open_ports(devices, ports if ports is not None else DEFAULT_PORTS, port_timeout)
        if check_risky_ports:
            devices = _attach_risky_ports(devices, port_timeout)

    return devices


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
        devices.append({"ip": received.psrc, "mac": received.hwsrc, "hostname": "", "vendor": ""})

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

    Raises:
        RuntimeError: the `ping` binary itself isn't installed/on PATH.
            Unlike a per-host timeout, this means the whole ping-sweep
            fallback can't run at all, so it's surfaced clearly rather
            than silently treated as "every host is unreachable".
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

    try:
        # Discard ping's stdout/stderr - we only care about its exit code
        # (0 = got a reply, non-zero = timed out or errored).
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError as exc:
        # Some minimal environments (slim containers, certain CI images)
        # don't ship a `ping` binary at all. That's a missing-dependency
        # problem, not "this one host didn't answer", so raise a clear
        # error instead of letting every host silently look unreachable.
        raise RuntimeError(
            "`ping` command not found. The ping-sweep fallback (used when "
            "scapy or root/administrator privileges for an ARP scan aren't "
            "available) requires the OS's `ping` binary to be installed "
            "and on PATH."
        ) from exc
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
        devices.append({"ip": ip_str, "mac": arp_table.get(ip_str, ""), "hostname": hostname, "vendor": ""})

    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


# --- mDNS/Bonjour and DNS-SD, for hostnames plain reverse DNS misses ---
#
# arp_scan() gets no hostname at all, and ping_sweep()'s reverse-DNS
# lookup usually only resolves the router itself, since consumer/IoT
# devices rarely register a PTR record. Those devices instead announce a
# ".local" hostname over mDNS (reverse lookup) or advertise themselves
# via DNS-SD service discovery (which Chromecasts in particular always
# answer, even though they skip the optional reverse-lookup part of the
# mDNS spec) - see _enrich_devices() below for how these get tried.
#
# This needs no external library (nothing like `zeroconf` is a standard
# dependency); it speaks just enough of the mDNS/DNS-SD wire protocol
# directly with plain sockets.

# mDNS/Bonjour's well-known multicast group and port (RFC 6762). Every
# mDNS-speaking device on the local link listens here, regardless of its
# own IP address.
_MDNS_GROUP = ("224.0.0.251", 5353)

# DNS record type numbers used below (from RFC 1035); mDNS reuses the
# ordinary DNS wire format, just delivered over multicast instead of to a
# configured resolver.
_DNS_TYPE_A = 1
_DNS_TYPE_PTR = 12
_DNS_TYPE_SRV = 33
_DNS_CLASS_IN = 1

# mDNS's "QU" flag (RFC 6762 §5.4): setting the top bit of a question's
# class field asks the responder to reply via ordinary unicast UDP
# straight back to us, instead of its default of multicasting the reply.
# Useful for a one-shot address lookup; service-browsing queries below
# join the multicast group instead, since those replies commonly come
# back multicast regardless of this bit.
_MDNS_QU_BIT = 0x8000

# The DNS-SD (RFC 6763) service type Chromecasts and other Google Cast
# devices advertise themselves under - this is the exact query the
# Google Home app and Chrome's "Cast" button send to find them, and
# unlike reverse address (in-addr.arpa) lookups, it's not optional: a
# Cast device that didn't answer this wouldn't be discoverable at all.
_CAST_SERVICE_TYPE = "_googlecast._tcp.local"


def _encode_dns_name(name: str) -> bytes:
    """DNS-encode a dotted name (e.g. "72.1.168.192.in-addr.arpa") into the
    length-prefixed-label wire format every DNS/mDNS message uses, ending
    in a zero-length label to terminate the name.
    """
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return encoded + b"\x00"


def _decode_dns_name(message: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at offset in message.

    A DNS name is normally a sequence of length-prefixed labels ending in
    a zero-length label - but to avoid repeating common suffixes (like
    ".local") in every record, a label's length byte can instead have its
    top two bits set (0xC0), meaning "the rest of this name is a copy of
    the name at this other offset in the packet" (a compression pointer).

    Args:
        message: The full raw mDNS message (pointers reference offsets
            into the whole message, not just the current record).
        offset: Where this name starts.

    Returns:
        (dotted_name, offset_after_this_name). The second value is where
        to resume reading the *next* field after this name - which, if
        the name ended in a pointer, is right after that 2-byte pointer,
        not wherever the pointer jumped to.
    """
    labels = []
    return_offset = None  # Where to resume after this name, once known.

    while True:
        length = message[offset]

        if length == 0:
            offset += 1
            break

        if length & 0xC0 == 0xC0:
            # Compression pointer: the low 14 bits (of this byte plus the
            # next one) are the offset to jump to for the rest of the name.
            pointer = struct.unpack(">H", message[offset:offset + 2])[0] & 0x3FFF
            if return_offset is None:
                return_offset = offset + 2
            offset = pointer
            continue

        offset += 1
        labels.append(message[offset:offset + length].decode("ascii", errors="replace"))
        offset += length

    return ".".join(labels), return_offset if return_offset is not None else offset


def _build_mdns_ptr_query(qname: str) -> bytes:
    """Build a raw mDNS query packet asking "who is answering to qname?".

    Args:
        qname: The DNS name to query, e.g. a reverse-lookup name like
            "72.1.168.192.in-addr.arpa".

    Returns:
        The raw bytes of a standard DNS query message with one PTR
        question, ready to send to _MDNS_GROUP.
    """
    # Header: transaction ID=0 (fine - we correlate replies by matching
    # the question name instead, and mDNS queries commonly use ID 0),
    # flags=0 (a standard, non-response query), 1 question, 0 answers/
    # authority/additional records.
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    # | _MDNS_QU_BIT: request a unicast reply for this one-shot lookup.
    question = _encode_dns_name(qname) + struct.pack(">HH", _DNS_TYPE_PTR, _DNS_CLASS_IN | _MDNS_QU_BIT)
    return header + question


def _iter_mdns_records(message: bytes):
    """Yield every resource record in an mDNS message, across all sections.

    A DNS/mDNS message has three record sections after its questions
    (answer, authority, additional), and related records for the same
    service are routinely split across them - a device might put its PTR
    answer in "answer" but its supporting SRV/A records in "additional".
    Most one-shot lookups don't care which section a record came from,
    only what type it is, so this walks all of them as a single stream
    rather than making every caller re-implement that traversal.

    Args:
        message: A raw mDNS message, as received over the socket.

    Yields:
        (name, record_type, rdata_offset, rdata_length) for each record,
        in wire order.
    """
    try:
        question_count, answer_count, authority_count, additional_count = struct.unpack(">HHHH", message[4:12])
    except struct.error:
        return  # Too short to even be a valid DNS header - nothing to yield.

    offset = 12  # DNS header is always exactly 12 bytes.

    for _ in range(question_count):
        _name, offset = _decode_dns_name(message, offset)
        offset += 4  # QTYPE + QCLASS, 2 bytes each.

    for _ in range(answer_count + authority_count + additional_count):
        try:
            name, offset = _decode_dns_name(message, offset)
            record_type, _record_class = struct.unpack(">HH", message[offset:offset + 4])
            offset += 4
            offset += 4  # TTL (4 bytes) - not needed for a one-shot lookup.
            rdata_length = struct.unpack(">H", message[offset:offset + 2])[0]
            offset += 2
        except (struct.error, IndexError):
            return  # Malformed/truncated record - stop rather than guess.

        rdata_offset = offset
        offset += rdata_length
        yield name, record_type, rdata_offset, rdata_length


def _extract_ptr_hostname(message: bytes, qname: str) -> str:
    """Pull a matching PTR record's target hostname out of an mDNS response.

    Args:
        message: A raw mDNS response packet, as received over the socket.
        qname: The name we originally queried for - only an answer for
            this exact name is accepted, so unrelated mDNS chatter on
            the shared multicast channel doesn't get misattributed to
            the host we asked about.

    Returns:
        The PTR record's target name, with its trailing root dot
        stripped, or "" if this message has no PTR answer for qname.
    """
    for name, record_type, rdata_offset, _rdata_length in _iter_mdns_records(message):
        if record_type == _DNS_TYPE_PTR and name.lower().rstrip(".") == qname.lower().rstrip("."):
            hostname, _ = _decode_dns_name(message, rdata_offset)
            return hostname.rstrip(".")

    return ""


def _collect_service_records(message: bytes, host_to_ip: Dict[str, str], instance_to_host: Dict[str, str]) -> None:
    """Pull A and SRV records for a DNS-SD service out of an mDNS response.

    Args:
        message: A raw mDNS response packet.
        host_to_ip: Updated in place: hostname (from an A record's own
            name) -> its IPv4 address.
        instance_to_host: Updated in place: service instance name (from
            an SRV record's own name, e.g.
            "Living Room TV._googlecast._tcp.local") -> the hostname it
            runs on (SRV's "target" field).
    """
    for name, record_type, rdata_offset, rdata_length in _iter_mdns_records(message):
        if record_type == _DNS_TYPE_A and rdata_length == 4:
            host_to_ip[name.lower().rstrip(".")] = socket.inet_ntoa(message[rdata_offset:rdata_offset + 4])
        elif record_type == _DNS_TYPE_SRV:
            # SRV rdata is priority(2) + weight(2) + port(2), then the
            # target hostname.
            target, _ = _decode_dns_name(message, rdata_offset + 6)
            instance_to_host[name.rstrip(".")] = target.lower().rstrip(".")


def mdns_reverse_lookup(ip: str, timeout: float) -> str:
    """Look up ip's self-advertised ".local" hostname via mDNS/Bonjour.

    Args:
        ip: The target host's IPv4 address.
        timeout: How long to wait for a response, in seconds.

    Returns:
        The advertised hostname (e.g. "printer.local"), or "" if the
        device didn't respond in time or doesn't support mDNS reverse
        lookup (an optional part of the spec many devices, notably
        Google's Cast stack, don't implement - see
        mdns_service_lookup() for a method that works for those).
    """
    reversed_octets = ".".join(reversed(ip.split(".")))
    qname = f"{reversed_octets}.in-addr.arpa"
    query = _build_mdns_ptr_query(qname)

    # Tracked as a deadline rather than a single socket timeout, since we
    # may need to read and discard several irrelevant packets (other
    # devices' mDNS traffic) before either finding our answer or running
    # out of time.
    deadline = time.monotonic() + timeout

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        try:
            sock.sendto(query, _MDNS_GROUP)
        except OSError:
            return ""

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ""
            sock.settimeout(remaining)
            try:
                message, _sender = sock.recvfrom(4096)
            except OSError:
                return ""

            hostname = _extract_ptr_hostname(message, qname)
            if hostname:
                return hostname


def mdns_service_lookup(service_type: str, timeout: float) -> Dict[str, str]:
    """Discover every device advertising service_type, mapped by IP address.

    Args:
        service_type: A DNS-SD service type, e.g. "_googlecast._tcp.local"
            (see _CAST_SERVICE_TYPE).
        timeout: How long to keep listening for responses, in seconds.
            Unlike mdns_reverse_lookup(), this doesn't return as soon as
            one answer arrives - every matching device on the network
            answers the same broadcast-style query.

    Returns:
        A dict of {ip_address: friendly_name}, covering only devices
        that answered and whose PTR/SRV/A records all arrived before
        the deadline.
    """
    query = _build_mdns_ptr_query(service_type)
    deadline = time.monotonic() + timeout

    host_to_ip: Dict[str, str] = {}
    instance_to_host: Dict[str, str] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            # Service-discovery replies are commonly multicast regardless
            # of the QU bit (browsing is meant to be a shared, many-
            # listener operation) - joining the group lets us receive
            # that multicast reply, not just a unicast one.
            sock.bind(("", _MDNS_GROUP[1]))
            join_request = struct.pack("4sl", socket.inet_aton(_MDNS_GROUP[0]), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, join_request)
        except OSError:
            # Binding/joining can fail (port already owned without
            # SO_REUSEPORT, a sandboxed environment restricting it,
            # etc.) - fall back to an ordinary ephemeral-port socket
            # relying solely on the QU bit for a unicast reply.
            pass

        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        try:
            sock.sendto(query, _MDNS_GROUP)
        except OSError:
            return {}

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                message, _sender = sock.recvfrom(4096)
            except OSError:
                break
            _collect_service_records(message, host_to_ip, instance_to_host)

    suffix = "." + service_type.lower().rstrip(".")
    results: Dict[str, str] = {}
    for instance_name, host in instance_to_host.items():
        ip = host_to_ip.get(host)
        if ip is None:
            continue
        lower_instance = instance_name.lower()
        friendly_name = instance_name[: -len(suffix)] if lower_instance.endswith(suffix) else instance_name
        results[ip] = friendly_name

    return results


# --- MAC vendor (OUI) lookup ---

# The IEEE's public registry mapping each OUI (a MAC address's first 3
# octets) to the organization it's assigned to. Downloaded once and
# cached on disk, since it's a multi-megabyte file that rarely changes -
# not something to re-fetch on every scan (see lookup_mac_vendor() for
# how the cache is used, and --refresh-vendor-db for bypassing it).
_OUI_REGISTRY_URL = "https://standards-oui.ieee.org/oui/oui.txt"
_OUI_CACHE_PATH = Path.home() / ".cache" / "network_scanner_oui.txt"

# Matches the registry's "(hex)" lines, e.g.:
#   00-1A-11   (hex)		Google, Inc.
# (there's a second "(base 16)" line per entry in a different format,
# plus address lines below both - this pattern only matches the one
# we need.)
_OUI_LINE_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$", re.MULTILINE)

_oui_vendor_table: Optional[Dict[str, str]] = None


def _load_oui_registry(timeout: float = 5.0, force_refresh: bool = False) -> Optional[str]:
    """Load the IEEE OUI registry, from the disk cache if present or by downloading it.

    Args:
        timeout: How long to wait for a download, in seconds.
        force_refresh: Skip the cache and download a fresh copy even if
            one is already cached (see --refresh-vendor-db). The cache
            is still used as a fallback if that download then fails.

    Returns:
        The registry's raw text, or None if no cached copy exists and
        downloading one fails (e.g. first run, no internet access).
    """
    if not force_refresh:
        try:
            # A cached copy is used as-is, with no re-download and no
            # network call at all - the registry changes rarely enough
            # that re-fetching it on every single scan (as earlier
            # versions of this function did) was pure waste.
            return _OUI_CACHE_PATH.read_text(encoding="utf-8")
        except OSError:
            pass  # No cache yet - fall through to downloading one.

    try:
        with urllib.request.urlopen(_OUI_REGISTRY_URL, timeout=timeout) as response:
            text = response.read().decode("utf-8", errors="replace")
        _OUI_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _OUI_CACHE_PATH.write_text(text, encoding="utf-8")
        return text
    except (urllib.error.URLError, OSError, ValueError):
        # No internet, DNS failure, firewall block, timeout, etc. - fall
        # back to whatever a previous successful run cached, if anything
        # (covers force_refresh's download failing, or the "no cache
        # yet" branch above also hitting a network error).
        try:
            return _OUI_CACHE_PATH.read_text(encoding="utf-8")
        except OSError:
            return None


def lookup_mac_vendor(mac: str, force_refresh: bool = False) -> str:
    """Look up a MAC address's registered vendor via the IEEE OUI registry.

    The registry is loaded once per process, not at import time, so
    scans that never see a MAC (or run with vendor lookup disabled)
    never pay for it. Once loaded it's kept in memory for the rest of
    the process - force_refresh only affects the very first call within
    a run; every subsequent lookup call reuses whatever that first call
    loaded, refreshed or not.

    Args:
        mac: A colon- or dash-separated MAC address, e.g.
            "aa:bb:cc:dd:ee:ff".
        force_refresh: Passed through to _load_oui_registry() on the
            first call only (see above) - forces a fresh download
            instead of reusing the disk cache.

    Returns:
        The registered vendor's name (e.g. "Google, Inc."), or "" if
        that OUI isn't in the registry, the registry couldn't be loaded
        at all (no internet and no cache from a previous run), or mac
        isn't well-formed.
    """
    global _oui_vendor_table
    if _oui_vendor_table is None:
        text = _load_oui_registry(force_refresh=force_refresh)
        _oui_vendor_table = dict(_OUI_LINE_PATTERN.findall(text)) if text else {}
        # Keys are stored upper-cased for a case-insensitive lookup below.
        _oui_vendor_table = {prefix.upper(): vendor for prefix, vendor in _oui_vendor_table.items()}

    octets = mac.replace(":", "-").split("-")
    if len(octets) < 3:
        return ""
    prefix = "-".join(octets[:3]).upper()
    return _oui_vendor_table.get(prefix, "")


def _resolve_missing_hostnames(devices: List[Device], mdns_timeout: float) -> List[Device]:
    """Fill in "" hostnames via mDNS/DNS-SD, in place.

    Meant to be called per subnet (mDNS/multicast traffic doesn't cross
    subnet boundaries, so there's no point asking about devices that
    couldn't possibly answer).

    Args:
        devices: One subnet's scan results from arp_scan()/ping_sweep().
        mdns_timeout: Timeout in seconds for each mDNS lookup.

    Returns:
        The same devices, in the same order, with "hostname" filled in
        wherever mDNS or DNS-SD found one.
    """
    unresolved = [d for d in devices if not d.get("hostname")]
    if not unresolved:
        return devices

    with ThreadPoolExecutor(max_workers=max(1, len(unresolved))) as executor:
        futures = {executor.submit(mdns_reverse_lookup, d["ip"], mdns_timeout): d for d in unresolved}
        for future in as_completed(futures):
            hostname = future.result()
            if hostname:
                futures[future]["hostname"] = hostname

    # Chromecasts/Cast devices generally skip the optional mDNS
    # reverse-lookup above, but always answer DNS-SD service discovery,
    # since that's the actual mechanism apps use to find them. Only
    # worth asking (one extra query, not per-device) if something here
    # is still unnamed.
    still_unresolved = [d for d in devices if not d.get("hostname")]
    if still_unresolved:
        cast_names = mdns_service_lookup(_CAST_SERVICE_TYPE, timeout=mdns_timeout)
        for device in still_unresolved:
            name = cast_names.get(device["ip"])
            if name:
                device["hostname"] = name

    return devices


def _attach_vendor_names(devices: List[Device], force_refresh: bool = False) -> List[Device]:
    """Fill in "" vendors via the IEEE OUI registry, in place.

    Unlike hostname resolution, this isn't subnet-scoped - it's a pure
    lookup against a MAC address already in hand - so it's meant to be
    called once over the final, de-duplicated device list rather than
    once per subnet.

    Args:
        devices: Scan results with a "mac" field to look up.
        force_refresh: Passed through to lookup_mac_vendor() - forces a
            fresh OUI registry download instead of reusing the cache
            (see --refresh-vendor-db). Only the first call actually
            triggers a load; see lookup_mac_vendor()'s docstring.

    Returns:
        The same devices, in the same order, with "vendor" filled in
        wherever a device had a MAC and it was found in the registry.
    """
    for device in devices:
        mac = device.get("mac")
        if mac and not device.get("vendor"):
            device["vendor"] = lookup_mac_vendor(mac, force_refresh=force_refresh)
    return devices


# --- Known-device tracking, for flagging newly-seen devices ---

# A small local registry of every device this script has ever seen,
# persisted between runs so a scan can tell "this device wasn't here
# last time" apart from "this device is always here". Lives alongside
# the OUI vendor cache for the same reason: it's local state specific to
# this script, not something to check into version control.
_KNOWN_DEVICES_PATH = Path.home() / ".cache" / "network_scanner_known_devices.json"


def _device_identity(device: Device) -> str:
    """Return the key used to recognize a device across scans.

    A MAC address survives a DHCP lease renewal (which can change a
    device's IP), so it's preferred whenever one is known; only ping
    sweep results for a device absent from the ARP cache have no MAC at
    all, in which case IP is the best identifier available.
    """
    return device.get("mac") or device["ip"]


def _load_known_devices(path: Path) -> Dict[str, dict]:
    """Load the known-devices registry from disk.

    Returns:
        The registry (a dict keyed by _device_identity()), or {} if the
        file doesn't exist yet (first run) or is unreadable/corrupt.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_known_devices(known: Dict[str, dict], path: Path) -> None:
    """Persist the known-devices registry to disk.

    Failing to save (read-only filesystem, out of disk space, etc.)
    deliberately doesn't raise - the NEW/known markers for the scan that
    just ran are already correct in memory either way, so losing the
    ability to remember them for *next* time shouldn't crash this run.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(known, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        pass


def _mark_new_devices(devices: List[Device], known_devices_path: Path = _KNOWN_DEVICES_PATH) -> Dict[str, bool]:
    """Compare devices against the known-devices registry, updating it on disk.

    Args:
        devices: This scan's results.
        known_devices_path: Where the registry is stored between runs
            (overridable for tests; production code should just use the
            default).

    Returns:
        A dict mapping each device's _device_identity() to True if this
        is the first time it's ever been seen, or False if it was
        already in the registry from a previous run.
    """
    known = _load_known_devices(known_devices_path)
    now = datetime.now().isoformat(timespec="seconds")

    is_new: Dict[str, bool] = {}
    for device in devices:
        key = _device_identity(device)
        is_new[key] = key not in known
        entry = known.setdefault(key, {"first_seen": now})
        entry["last_seen"] = now
        entry["ip"] = device["ip"]
        entry["hostname"] = device.get("hostname", "")
        entry["vendor"] = device.get("vendor", "")

    _save_known_devices(known, known_devices_path)
    return is_new


def _find_missing_devices(devices: List[Device], known_devices_path: Path = _KNOWN_DEVICES_PATH) -> List[dict]:
    """Find registry entries for devices that didn't show up in this scan.

    The inverse of _mark_new_devices(): instead of flagging what's newly
    *present*, this reports what's newly *absent* - a device seen in some
    previous scan (e.g. a laptop that's asleep, or something unplugged)
    but missing from this one. The registry itself is never pruned here
    (or anywhere) - a device just stops appearing in this list again once
    it's seen in a later scan, the same way it would in real life.

    Args:
        devices: This scan's results.
        known_devices_path: Where the registry is stored between runs
            (overridable for tests; production code should just use the
            default).

    Returns:
        Registry entries (each augmented with its identity key under
        "key") for every known device absent from devices, sorted by
        that key for stable output. This intentionally doesn't
        distinguish "gone for good" from "temporarily offline" - that's
        not something a single scan can tell.
    """
    known = _load_known_devices(known_devices_path)
    current_keys = {_device_identity(device) for device in devices}

    missing = [dict(entry, key=key) for key, entry in known.items() if key not in current_keys]
    return sorted(missing, key=lambda entry: entry["key"])


# --- IPv6 neighbor discovery ---
#
# Everything above assumes IPv4: arp_scan() and ping_sweep() are both
# given a subnet to enumerate, which works because a /24 has only 254
# addresses. An IPv6 /64 has 2**64 - brute-force enumeration the way
# ping_sweep() does for IPv4 simply isn't feasible. IPv6-connected
# devices are still discoverable, just differently: a single ICMPv6
# echo request to the link's all-nodes multicast address (ff02::1)
# reaches every IPv6-enabled device on the local link at once (this is
# IPv6's rough equivalent of arp_scan()'s ARP broadcast), and replies
# populate the OS's IPv6 neighbor cache - NDP's equivalent of the ARP
# cache read_arp_table() already parses - which is then read back out.
#
# This is intentionally more limited than the IPv4 path: Linux and
# macOS only (the neighbor-table command and its output format differ
# enough on Windows that it isn't attempted here), and no hostname
# resolution - mdns_reverse_lookup() builds an IPv4-style
# "x.x.x.x.in-addr.arpa" reverse name that wouldn't mean anything for
# an IPv6 address (IPv6 reverse DNS uses a different "ip6.arpa" nibble
# format entirely). Vendor lookup still works fine, since it's a pure
# MAC-address lookup that doesn't care what IP version found the MAC.


def _list_scan_interfaces() -> List[str]:
    """Return non-loopback network interface names to probe for IPv6 devices.

    Uses socket.if_nameindex() - standard library on Linux and macOS
    (and Windows since Python 3.8) - rather than requiring psutil, so
    IPv6 discovery doesn't need yet another optional dependency on top
    of the ones --all-subnets already introduced.

    Returns:
        Interface names (e.g. ["eth0", "wlan0"]), or [] if the platform
        doesn't support if_nameindex() or none were found.
    """
    try:
        return [name for _index, name in socket.if_nameindex() if name != "lo"]
    except (AttributeError, OSError):
        return []


def _ping_ipv6_multicast(interface: str, timeout: float) -> None:
    """Send ICMPv6 echoes to the local link's all-nodes multicast address.

    This doesn't return anything meaningful - the actual result is
    whatever ends up in the OS's IPv6 neighbor cache afterward, read
    separately by read_ipv6_neighbor_table(). A missing ping binary, an
    unsupported platform, or simply no replies all look the same here:
    nothing happens, and the neighbor cache just doesn't gain any new
    entries from this interface.

    Args:
        interface: The interface name to scope the multicast ping to -
            required for a link-local destination like ff02::1 to mean
            anything (unlike a globally-routable address, it's only
            valid relative to a specific link).
        timeout: Roughly how long to spend probing, in seconds.
    """
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        # Windows' ping needs the interface's numeric *index* after a
        # "%", not its name - resolving that portably is more platform-
        # specific code than this best-effort path is worth, so this
        # will typically just find nothing on Windows rather than crash.
        command = ["ping", "-6", "-n", "3", "-w", str(int(timeout * 1000)), "ff02::1"]
    else:
        # -I scopes the multicast ping to a specific interface; -c 3
        # spaces three requests roughly a second apart, giving slower-
        # to-reply devices more than one chance to be caught.
        ping_binary = "ping6" if shutil.which("ping6") else "ping"
        command = [ping_binary, "-6", "-c", "3", "-I", interface, "-W", str(max(1, int(timeout))), "ff02::1"]

    try:
        subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout + 3)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # No ping binary, this platform's ping doesn't understand these
        # flags, or it just ran long - either way, treat it the same as
        # "no replies," not a fatal error for the whole scan.
        pass


def read_ipv6_neighbor_table() -> Dict[str, str]:
    """Parse the OS's IPv6 neighbor cache into a map of IPv6 address -> MAC.

    IPv6's equivalent of read_arp_table(): the neighbor cache, populated
    by ICMPv6 Neighbor Discovery instead of ARP, mapping addresses to
    the link-layer (MAC) addresses of hosts this machine has recently
    exchanged packets with.

    Linux and macOS only - see this section's module-level comment for
    why Windows isn't attempted.

    Returns:
        A dict mapping IPv6 address strings (with any zone-id suffix
        like "%eth0" stripped) to lowercase, colon-separated MAC
        address strings. Empty on Windows, or if the platform's
        neighbor-table command isn't available.
    """
    is_macos = platform.system().lower() == "darwin"
    command = ["ndp", "-a"] if is_macos else ["ip", "-6", "neigh", "show"]

    try:
        output = subprocess.run(command, capture_output=True, text=True, check=False).stdout
    except FileNotFoundError:
        return {}

    mac_pattern = re.compile(r"([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}")

    table: Dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue

        # Both `ip -6 neigh show` and `ndp -a` put the address first on
        # each line; macOS's ndp suffixes it with a zone id (e.g. "%en0")
        # that isn't part of the address itself. Requiring a colon
        # filters out header/label lines (ndp's column headers, blank
        # separators) that have no address in that position at all.
        address = parts[0].split("%")[0]
        mac_match = mac_pattern.search(line)
        if mac_match and ":" in address:
            table[address] = mac_match.group().replace("-", ":").lower()

    return table


def ipv6_neighbor_scan(timeout: float = 2.0) -> List[Device]:
    """Discover IPv6 devices on the local link via multicast ping + NDP.

    Unlike arp_scan()/ping_sweep(), this takes no subnet argument - see
    this section's module-level comment for why brute-force enumeration
    isn't feasible for IPv6. Instead, every local interface gets a
    multicast ping (see _ping_ipv6_multicast()), and then the OS's own
    neighbor cache is read back out in one pass across however many
    interfaces just got probed.

    Args:
        timeout: Roughly how long to spend probing each interface and
            waiting for replies, in seconds.

    Returns:
        Discovered devices sorted by IPv6 address, with "hostname" and
        "vendor" both left as "" - callers that want vendor names filled
        in should run this through _attach_vendor_names() themselves,
        the same utility scan_all_subnets() uses for IPv4 devices.
    """
    for interface in _list_scan_interfaces():
        _ping_ipv6_multicast(interface, timeout)

    neighbors = read_ipv6_neighbor_table()

    devices: List[Device] = []
    for address, mac in neighbors.items():
        # The neighbor cache can include multicast/loopback entries
        # that aren't real neighboring devices - skip anything that
        # isn't an ordinary unicast address.
        if address == "::1" or address.lower().startswith("ff"):
            continue
        devices.append({"ip": address, "mac": mac, "hostname": "", "vendor": ""})

    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


# --- Single-device deep dive (--identify) ---
#
# scan_all_subnets() is tuned for speed across up to 254 hosts at once,
# which means short timeouts and a narrow, common-case port list - fine
# for a bulk overview, but it's exactly why some devices come back with
# no hostname, no vendor, and no clue what they are. identify_device()
# is the opposite trade-off: given one specific host, it can afford to
# try far more ports, read back whatever each open one reveals about
# itself (a "banner"), and run the full hostname-resolution chain with
# more generous timeouts - a "tell me everything you can" command for
# exactly the kind of mystery device the bulk scan leaves unidentified.

# A much broader set of ports than DEFAULT_PORTS (below) - deliberately
# wider since this only ever probes one host, not up to 254 of them, so
# the extra time cost of a longer list is paid once, not multiplied
# across a whole subnet.
_IDENTIFY_PORTS: Tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 554, 587, 993, 995,
    1883, 1900, 3306, 3389, 5000, 5353, 5432, 6379, 7000, 8000, 8009,
    8080, 8081, 8443, 9100, 32400, 62078,
)

# Short, human-readable labels for both _IDENTIFY_PORTS and DEFAULT_PORTS,
# printed alongside each open port - a hint at what's running there, not
# a certainty (plenty of devices repurpose these ports, or run several
# services and only happen to answer on the one that got probed).
PORT_SERVICES: Dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    554: "rtsp (camera/streaming)",
    587: "smtp-submission",
    993: "imaps",
    995: "pop3s",
    1883: "mqtt",
    1900: "ssdp/upnp",
    3306: "mysql",
    3389: "rdp",
    5000: "upnp/airplay",
    5353: "mdns/bonjour",
    5432: "postgresql",
    6379: "redis",
    7000: "airplay",
    8000: "http-alt",
    8009: "chromecast",
    8080: "http-alt",
    8081: "http-alt",
    8443: "https-alt",
    9100: "printer (jetdirect)",
    32400: "plex",
    62078: "lockdownd (iOS)",
}

# Ports where sending a plain HTTP request makes sense - other ports
# are just listened to, in case the service announces itself unprompted
# (SSH, FTP, SMTP, and several others send a startup banner outright).
_HTTP_PORTS = frozenset({80, 8000, 8080, 8081})
_HTTPS_PORTS = frozenset({443, 8443})


# --- Bulk port scanning (an optional supplement to ARP/ping, not a
# replacement) ---
#
# arp_scan()/ping_sweep() find live hosts and (when available) MACs, but
# say nothing about what a device is actually running - which is often
# the only clue left for something with no hostname and an unrecognized
# vendor. This mirrors mobile_network_scanner.py's TCP-probe approach
# (same DEFAULT_PORTS/PORT_SERVICES concept, since it's the same
# problem), scaled for a bulk scan across up to 254 hosts rather than a
# single-host deep dive: a short, common-case port list checked quickly,
# not _IDENTIFY_PORTS' much longer one.

def _probe_tcp_port(ip: str, port: int, timeout: float) -> bool:
    """Return True if ip accepts a TCP connection on port.

    The same connect_ex-based check mobile_network_scanner.py's
    probe_host() uses, just for a single port rather than trying a list
    of them in order - callers here already parallelize across ports or
    hosts themselves, so there's no need for this to also stop early.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0


# Ports likely to be open on common home/office devices - the same
# rationale as mobile_network_scanner.py's list of the same name, kept
# in sync with it since it's solving the same problem for the desktop/
# Termux target instead of iOS's sandboxed one.
DEFAULT_PORTS: Tuple[int, ...] = (80, 443, 22, 445, 139, 8080, 8443, 62078, 3389, 5000, 7000)


def probe_open_port(ip: str, ports: Iterable[int], timeout: float) -> Optional[int]:
    """Try connecting to each of the given TCP ports on ip, in order.

    Args:
        ip: The target host's IP address (already known to be live).
        ports: TCP ports to try, in order. Stops at the first success.
        timeout: Per-port connection timeout, in seconds.

    Returns:
        The first port that accepted a connection, or None if every
        port timed out or was refused.
    """
    for port in ports:
        if _probe_tcp_port(ip, port, timeout):
            return port
    return None


def _attach_open_ports(devices: List[Device], ports: Sequence[int], timeout: float) -> List[Device]:
    """Fill in each device's "port" via probe_open_port(), in parallel, in place.

    Args:
        devices: Scan results to probe - already known to be live hosts,
            since this is a supplement to ARP/ping, not how liveness
            itself is determined.
        ports: TCP ports to probe on each device (see DEFAULT_PORTS).
        timeout: Per-port connection timeout, in seconds.

    Returns:
        The same devices, in the same order, with "port" set to
        whichever port answered first, or None if none of them did.
    """
    with ThreadPoolExecutor(max_workers=max(1, len(devices))) as executor:
        futures = {executor.submit(probe_open_port, d["ip"], ports, timeout): d for d in devices}
        for future in as_completed(futures):
            futures[future]["port"] = future.result()
    return devices


# A home-network security hygiene check, not an exhaustive audit: ports
# commonly flagged as risky to leave exposed, with a one-line reason
# each. Checked independently of DEFAULT_PORTS/probe_open_port() above,
# which stops at the first open port it finds - a device with both 80
# and 23 (telnet) open would otherwise never reveal the telnet port if
# 80 happened to be checked first.
RISKY_PORTS: Dict[int, str] = {
    21: "FTP transmits credentials in plaintext",
    23: "Telnet transmits everything, including credentials, in plaintext",
    445: "SMB is a common ransomware/worm vector when exposed beyond the LAN",
    3389: "RDP is frequently targeted by credential-stuffing and brute-force scans",
    5900: "VNC often runs with weak or no authentication by default",
}


def _find_risky_ports(ip: str, timeout: float) -> List[int]:
    """Check ip for any of RISKY_PORTS, regardless of what probe_open_port() found.

    Args:
        ip: The target host's IP address.
        timeout: Per-port connection timeout, in seconds.

    Returns:
        Open ports from RISKY_PORTS, sorted numerically. Empty if none
        of them are open (the common, unremarkable case).
    """
    open_risky = []
    with ThreadPoolExecutor(max_workers=len(RISKY_PORTS)) as executor:
        futures = {executor.submit(_probe_tcp_port, ip, port, timeout): port for port in RISKY_PORTS}
        for future in as_completed(futures):
            port = futures[future]
            if future.result():
                open_risky.append(port)
    return sorted(open_risky)


def _attach_risky_ports(devices: List[Device], timeout: float) -> List[Device]:
    """Fill in each device's "risky_ports" via _find_risky_ports(), in parallel, in place."""
    with ThreadPoolExecutor(max_workers=max(1, len(devices))) as executor:
        futures = {executor.submit(_find_risky_ports, d["ip"], timeout): d for d in devices}
        for future in as_completed(futures):
            futures[future]["risky_ports"] = future.result()
    return devices



def _summarize_banner(data: bytes) -> str:
    """Reduce raw banner bytes to one short, printable line.

    Args:
        data: Whatever bytes came back from the service.

    Returns:
        The most identifying single line found - preferring an HTTP
        "Server:" header over that response's generic status line,
        since the status line looks the same for every server - or ""
        if data contained nothing but blank lines.
    """
    text = data.decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return ""

    for line in lines:
        if line.lower().startswith("server:"):
            return line if line == lines[0] else f"{lines[0]}  |  {line}"

    return lines[0][:120]


def grab_banner(ip: str, port: int, timeout: float) -> str:
    """Best-effort read of whatever a service on ip:port reveals about itself.

    Many protocols announce themselves unprompted right after the TCP
    handshake - SSH sends "SSH-2.0-..." outright, for instance - and
    HTTP(S) servers reveal a lot in response to even a bare HEAD request
    with no real path or Host header. Neither is guaranteed: a service
    that stays silent (most binary protocols - SMB, RDP, etc.) just
    yields "" here, the same as if nothing were listening at all.

    Ports outside the recognized HTTP(S) sets get a two-step attempt:
    listen first (catches unprompted-banner protocols like SSH), and if
    nothing arrives, send an HTTP probe anyway - plenty of services
    (especially IoT admin UIs, which is exactly the kind of device this
    whole deep-dive mode exists to help identify) run HTTP on ports
    outside the well-known set. This can take up to roughly 2x timeout
    for a port that answers neither way, which is an acceptable cost
    here: grab_banner() is only ever called on already-open ports in a
    deliberately slow, thorough single-host mode, not across a whole
    subnet.

    Args:
        ip: The target host's address.
        port: A TCP port already confirmed open by the caller - this
            doesn't itself check for a listener.
        timeout: How long to wait for each read attempt, in seconds.

    Returns:
        A short, human-readable snippet of whatever came back, or ""
        if the connection failed or nothing useful was received.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw_sock:
            raw_sock.settimeout(timeout)
            raw_sock.connect((ip, port))

            if port in _HTTPS_PORTS:
                # Most self-hosted admin UIs (routers, cameras, NAS
                # boxes) use a self-signed certificate, so verification
                # is deliberately disabled here - this is read-only
                # reconnaissance against a device on the caller's own
                # network, not a security-sensitive connection that
                # needs certificate trust.
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(raw_sock, server_hostname=ip)
            else:
                sock = raw_sock

            http_request = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii", errors="replace")

            if port in _HTTP_PORTS or port in _HTTPS_PORTS:
                sock.sendall(http_request)
                data = sock.recv(1024)
            else:
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    data = b""
                if not data:
                    sock.sendall(http_request)
                    data = sock.recv(1024)
    except (OSError, ssl.SSLError):
        return ""

    return _summarize_banner(data)


def _get_device_mac(ip: str, timeout: float) -> str:
    """Best-effort single-host MAC lookup for identify_device().

    Tries a direct ARP request first - scapy targeting just this one
    address via a "/32" pseudo-subnet, rather than the whole subnet
    arp_scan() is normally given - falling back to pinging the host and
    reading whatever landed in the OS's ARP cache, the same two-step
    approach ping_sweep() uses across a whole subnet, just for one host.

    Returns:
        A lowercase, colon-separated MAC address, or "" if neither
        method found one (no scapy/permissions for the ARP request, and
        the host either didn't answer a ping or wasn't in the ARP cache
        anyway).
    """
    try:
        answered = arp_scan(f"{ip}/32", timeout)
        if answered:
            return answered[0]["mac"]
    except (ImportError, PermissionError, OSError):
        pass

    try:
        ping(ip, timeout)  # Best-effort: populate the ARP cache if reachable.
    except RuntimeError:
        pass  # No `ping` binary - can't populate the cache this way either.
    return read_arp_table().get(ip, "")


def identify_device(
    ip: str,
    ports: Iterable[int] = _IDENTIFY_PORTS,
    timeout: float = 1.0,
    mdns_timeout: float = 1.0,
    vendor_lookup: bool = True,
) -> dict:
    """Run a slow, thorough investigation of a single host.

    See this section's module-level comment for how this differs from
    scan_all_subnets(): more ports, banner-grabbing, and more generous
    timeouts, all afforded by only ever looking at one host at a time.

    Args:
        ip: The host to investigate.
        ports: TCP ports to probe (see _IDENTIFY_PORTS).
        timeout: Per-port connect/banner timeout, in seconds.
        mdns_timeout: Timeout for the mDNS/DNS-SD hostname fallback.
        vendor_lookup: Whether to look up the MAC vendor, if a MAC is
            found at all.

    Returns:
        {"ip", "mac", "hostname", "vendor", "open_ports"}, where
        open_ports is a list of {"port", "service", "banner"} sorted by
        port number - "service" is a guess from PORT_SERVICES
        (or "?" if the port isn't in it), and "banner" is "" if
        grab_banner() found nothing.
    """
    device: Device = {"ip": ip, "mac": _get_device_mac(ip, timeout), "hostname": "", "vendor": ""}

    ports = list(ports)
    with ThreadPoolExecutor(max_workers=max(1, min(32, len(ports)))) as executor:
        futures = {executor.submit(_probe_tcp_port, ip, port, timeout): port for port in ports}
        open_ports = sorted(futures[future] for future in as_completed(futures) if future.result())

    open_port_info = []
    with ThreadPoolExecutor(max_workers=max(1, min(16, len(open_ports)))) as executor:
        futures = {executor.submit(grab_banner, ip, port, timeout): port for port in open_ports}
        for future in as_completed(futures):
            port = futures[future]
            open_port_info.append(
                {"port": port, "service": PORT_SERVICES.get(port, "?"), "banner": future.result()}
            )

    [device] = _resolve_missing_hostnames([device], mdns_timeout)
    if vendor_lookup and device["mac"]:
        [device] = _attach_vendor_names([device])

    device["open_ports"] = sorted(open_port_info, key=lambda entry: entry["port"])
    return device


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


# --- Colorized terminal output ---
#
# Plain ANSI escape codes, not a library like colorama - this only ever
# targets Unix-like terminals (matching the rest of this script's
# platform assumptions for things like ping/arp), and every terminal
# worth colorizing already understands these codes natively.

_ANSI_CODES: Dict[str, str] = {
    "green": "\033[32m",
    "red": "\033[31m",
    "yellow": "\033[33m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def _use_color(no_color_flag: bool) -> bool:
    """Decide whether to emit ANSI color codes at all.

    Color is skipped if the user passed --no-color, if the NO_COLOR
    environment variable is set (https://no-color.org - a convention
    respected by a wide range of CLI tools), or if stdout isn't
    connected to a terminal at all (piped to a file or another program,
    where raw escape codes would just be noise mixed into the output).

    Args:
        no_color_flag: The --no-color CLI flag's value.

    Returns:
        True if it's safe and wanted to emit color codes.
    """
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _colorize(text: str, color: str, enabled: bool) -> str:
    """Wrap text in an ANSI color code, or return it unchanged if enabled is False."""
    if not enabled:
        return text
    return f"{_ANSI_CODES[color]}{text}{_ANSI_CODES['reset']}"


def _print_identify_report(device: dict, color: bool = False) -> None:
    """Print identify_device()'s result as a readable single-host report."""
    print(f"\n=== {device['ip']} ===")
    print(f"MAC:      {device['mac'] or '(unknown)'}")
    print(f"Vendor:   {device['vendor'] or '(unknown)'}")
    print(f"Hostname: {device['hostname'] or '(none found)'}")

    if not device["open_ports"]:
        print("\nNo open ports found among the ports probed.")
        return

    print(f"\n{len(device['open_ports'])} open port(s):")
    for entry in device["open_ports"]:
        port = entry["port"]
        banner = entry["banner"] or "(no banner)"
        line = f"  {port:<6} {entry['service']:<24} {banner}"
        if port in RISKY_PORTS:
            line = _colorize(line, "red", color)
        print(line)


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
    parser.add_argument(
        "--identify",
        type=str,
        default=None,
        metavar="IP",
        help="Skip the network scan and instead do a slow, thorough investigation of a single host: try many more ports, grab a banner from anything open, and resolve its hostname/vendor (see identify_device())",
    )
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds per host (default: 1.0)")
    parser.add_argument(
        "--mdns-timeout",
        type=float,
        default=0.3,
        help="Timeout in seconds for the mDNS/DNS-SD hostname fallback, used when reverse DNS finds nothing (default: 0.3)",
    )
    parser.add_argument(
        "--no-vendor-lookup",
        action="store_true",
        help="Skip looking up each device's MAC vendor (avoids the first-run IEEE OUI registry download, e.g. for an offline scan)",
    )
    parser.add_argument(
        "--refresh-vendor-db",
        action="store_true",
        help="Force a fresh download of the IEEE OUI registry instead of reusing the cached copy at ~/.cache/network_scanner_oui.txt",
    )
    parser.add_argument(
        "--watch",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Rescan repeatedly every SECONDS instead of running once, printing a NEW marker each time a device wasn't seen in any previous run (Ctrl+C to stop)",
    )
    parser.add_argument(
        "--no-track-devices",
        action="store_true",
        help="Don't persist or consult the known-devices registry - no NEW markers, and this run won't be remembered for next time",
    )
    parser.add_argument(
        "--forget-known-devices",
        action="store_true",
        help="Clear the known-devices registry before scanning, so every device found in this run is marked NEW",
    )
    parser.add_argument(
        "--ipv6",
        action="store_true",
        help="Also discover IPv6 devices on the local link via multicast ping + NDP (Linux/macOS only; see ipv6_neighbor_scan())",
    )
    parser.add_argument(
        "--ipv6-timeout",
        type=float,
        default=2.0,
        help="Roughly how long to spend on IPv6 discovery, in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--no-scan-ports",
        action="store_true",
        help="Skip probing each device for an open port (see DEFAULT_PORTS) and the risky-ports check that depends on it",
    )
    parser.add_argument(
        "--ports",
        type=str,
        default=None,
        help="Comma-separated TCP ports to probe on each device instead of DEFAULT_PORTS",
    )
    parser.add_argument(
        "--port-timeout",
        type=float,
        default=0.3,
        help="Per-port connection timeout in seconds, for both the open-port probe and the risky-ports check (default: 0.3)",
    )
    parser.add_argument(
        "--no-risky-ports",
        action="store_true",
        help="Skip the risky-ports security check (see RISKY_PORTS) while keeping the open-port probe for identification",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in the output (also respects the NO_COLOR env var, and auto-disables when stdout isn't a terminal)",
    )
    args = parser.parse_args()

    color = _use_color(args.no_color)
    ports = tuple(int(p) for p in args.ports.split(",")) if args.ports else None

    if args.identify:
        # A wholly different mode from everything below: one host,
        # investigated thoroughly, instead of many hosts scanned
        # quickly - so it bypasses subnet resolution, known-device
        # tracking, and --watch entirely, and exits as soon as it's done.
        device = identify_device(
            args.identify,
            ports=ports if ports is not None else _IDENTIFY_PORTS,
            timeout=args.timeout,
            mdns_timeout=args.mdns_timeout,
            vendor_lookup=not args.no_vendor_lookup,
        )
        _print_identify_report(device, color=color)
        return

    # Precedence: an explicit subnet argument always wins; otherwise
    # --all-subnets scans everything psutil can see; otherwise fall back
    # to auto-detecting just the one subnet on the default route.
    if args.subnet:
        subnets: List[str] = [s.strip() for s in args.subnet.split(",")]
    elif args.all_subnets:
        subnets = get_local_subnets()
    else:
        subnets = [get_local_subnet()]

    if args.forget_known_devices:
        _save_known_devices({}, _KNOWN_DEVICES_PATH)

    def run_once() -> None:
        """Scan once, mark/print NEW devices, and print the results table."""
        print(f"Scanning {', '.join(subnets)} ...")

        try:
            devices: List[Device] = scan_all_subnets(
                subnets,
                args.timeout,
                mdns_timeout=args.mdns_timeout,
                vendor_lookup=not args.no_vendor_lookup,
                refresh_vendor_db=args.refresh_vendor_db,
                scan_ports=not args.no_scan_ports,
                ports=ports,
                port_timeout=args.port_timeout,
                check_risky_ports=not args.no_risky_ports,
            )
        except RuntimeError as exc:
            # A missing required dependency (e.g. no `ping` binary at
            # all) - print the specific reason instead of a raw
            # traceback, since there's nothing the user can do to
            # retry, only to fix their environment. Fatal even under
            # --watch: if this environment can't scan once, it can't
            # scan on a timer either.
            print(f"Error: {exc}")
            raise SystemExit(1)

        if args.ipv6:
            print("Also probing for IPv6 devices (multicast ping + NDP, Linux/macOS only) ...")
            ipv6_devices = ipv6_neighbor_scan(timeout=args.ipv6_timeout)
            if not args.no_vendor_lookup:
                ipv6_devices = _attach_vendor_names(ipv6_devices, force_refresh=args.refresh_vendor_db)
            if not args.no_scan_ports and ipv6_devices:
                ipv6_devices = _attach_open_ports(
                    ipv6_devices, ports if ports is not None else DEFAULT_PORTS, args.port_timeout
                )
                if not args.no_risky_ports:
                    ipv6_devices = _attach_risky_ports(ipv6_devices, args.port_timeout)
            # Concatenated, not merged into one sorted list: comparing
            # an IPv4Address to an IPv6Address raises in the ipaddress
            # module, so IPv4 and IPv6 devices can't share one sort key.
            # They print in the same table regardless - IPv4 addresses
            # first (already sorted among themselves), then IPv6
            # addresses (also sorted among themselves) below them,
            # rather than interleaved by numeric value.
            devices = devices + ipv6_devices

        if not devices:
            print("No devices found.")
            return

        # known_devices_path is passed explicitly (rather than relying
        # on these functions' own default parameter) so that anything
        # overriding the module-level _KNOWN_DEVICES_PATH - a test, or a
        # future --known-devices-file flag - is actually respected here,
        # instead of these calls silently keeping whatever path was
        # bound to the default argument at function-definition time.
        is_new = {} if args.no_track_devices else _mark_new_devices(devices, known_devices_path=_KNOWN_DEVICES_PATH)
        missing = (
            []
            if args.no_track_devices
            else _find_missing_devices(devices, known_devices_path=_KNOWN_DEVICES_PATH)
        )

        # A leading marker column (rather than reflowing every other
        # column's width) keeps a NEW device visually obvious without
        # disturbing the table's layout when tracking is off. The IP
        # column is 42 wide (not the IPv4-sized 18 from before --ipv6
        # existed) so a full IPv6 address - up to 39 characters - still
        # gets a separating gap before the MAC column instead of running
        # straight into it.
        print(f"\n{'':<5}{'IP Address':<42}{'MAC Address':<20}{'Vendor':<24}{'Port':<8}{'Service':<24}Hostname")
        print("-" * 151)
        new_count = 0
        for device in devices:
            # "-" as a placeholder makes it visually obvious that a
            # value is missing, rather than leaving a confusing blank gap.
            mac_display = device.get("mac") or "-"
            vendor_display = device.get("vendor") or "-"
            port = device.get("port")
            port_display = str(port) if port is not None else "-"
            service_display = PORT_SERVICES.get(port, "?") if port is not None else "-"

            is_device_new = bool(is_new.get(_device_identity(device)))
            if is_device_new:
                new_count += 1
            marker = "NEW  " if is_device_new else "     "

            row = (
                f"{marker}{device['ip']:<42}{mac_display:<20}{vendor_display:<24}"
                f"{port_display:<8}{service_display:<24}{device.get('hostname', '')}"
            )
            # A single color per row, not nested calls: _colorize()
            # wraps text in a start code and a reset, and ANSI's reset
            # clears *all* active styling, not just the innermost one -
            # nesting an inner colorize() inside an outer one would have
            # the inner reset kill the outer color partway through the
            # line. Risky takes priority since it's the more important
            # signal; a NEW+risky device is still visibly NEW from the
            # literal marker text, just not also green.
            if device.get("risky_ports"):
                row = _colorize(row, "red", color)
            elif is_device_new:
                row = _colorize(row, "green", color)
            print(row)

        print(f"\n{len(devices)} device(s) found.", end="")
        if not args.no_track_devices:
            print(f" {new_count} new since last seen.")
        else:
            print()

        if missing:
            print(f"\n{len(missing)} previously-seen device(s) not found in this scan:")
            for entry in missing:
                # Whichever of hostname/vendor is set makes an otherwise
                # bare key (a MAC or IP) recognizable at a glance.
                label = entry.get("hostname") or entry.get("vendor") or ""
                suffix = f"  ({label})" if label else ""
                line = f"  {entry['key']:<20} last seen {entry.get('last_seen', '?')}{suffix}"
                print(_colorize(line, "dim", color))

        risky_devices = [d for d in devices if d.get("risky_ports")]
        if risky_devices:
            print(_colorize(f"\n⚠ {len(risky_devices)} device(s) exposing commonly-risky ports:", "yellow", color))
            all_risky_ports = set()
            for d in risky_devices:
                labels = ", ".join(f"{PORT_SERVICES.get(p, str(p))} ({p})" for p in d["risky_ports"])
                all_risky_ports.update(d["risky_ports"])
                line = f"  {d['ip']:<20} {d.get('mac') or '-':<20} {labels}"
                print(_colorize(line, "red", color))
            print("\nWhy these are flagged:")
            for port in sorted(all_risky_ports):
                print(f"  {port:<6} {RISKY_PORTS[port]}")

    if args.watch:
        print(f"Watch mode: rescanning every {args.watch:g}s (Ctrl+C to stop).")
        try:
            while True:
                print(f"\n=== {datetime.now().isoformat(timespec='seconds')} ===")
                run_once()
                time.sleep(args.watch)
        except KeyboardInterrupt:
            print("\nStopped.")
    else:
        run_once()


if __name__ == "__main__":
    main()
