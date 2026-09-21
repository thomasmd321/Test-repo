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

Hostnames come from reverse DNS first, falling back to mDNS/Bonjour (see
mdns_reverse_lookup()) for devices - Chromecasts, smart speakers,
printers, and most other consumer/IoT gear - that never register a PTR
record but do announce a ".local" name over multicast. This needs no
external library (nothing like `zeroconf` reliably builds in these
sandboxes); it speaks just enough of the mDNS wire protocol directly.

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
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, TypedDict


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


# mDNS/Bonjour's well-known multicast group and port (RFC 6762). Every
# mDNS-speaking device on the local link listens here, regardless of its
# own IP address.
_MDNS_GROUP = ("224.0.0.251", 5353)

# DNS record type numbers used below (from RFC 1035); mDNS reuses the
# ordinary DNS wire format, just delivered over multicast instead of to a
# configured resolver.
_DNS_TYPE_PTR = 12
_DNS_CLASS_IN = 1

# mDNS's "QU" flag (RFC 6762 §5.4): setting the top bit of a question's
# class field asks the responder to reply via ordinary unicast UDP,
# straight back to the address/port the query came from, instead of its
# default of multicasting the reply to every device on the link. This
# matters a lot here: our socket below never joins the mDNS multicast
# group or binds to port 5353 (both of which iOS restricts heavily for
# third-party apps), so it can only ever receive a *unicast* reply on the
# ephemeral port it queried from - a multicast-only reply would never
# reach it, even from a device that answered correctly.
_MDNS_QU_BIT = 0x8000


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
    # | _MDNS_QU_BIT: request a unicast reply - see its comment above for
    # why this socket can't rely on the alternative (a multicast reply).
    question = _encode_dns_name(qname) + struct.pack(">HH", _DNS_TYPE_PTR, _DNS_CLASS_IN | _MDNS_QU_BIT)
    return header + question


def _extract_ptr_hostname(message: bytes, qname: str) -> str:
    """Pull a matching PTR record's target hostname out of an mDNS response.

    Args:
        message: A raw mDNS response packet, as received over the socket.
        qname: The name we originally queried for - only an answer for
            this exact name is accepted, so unrelated mDNS chatter on
            the shared multicast channel (there's often a lot of it)
            doesn't get misattributed to the host we asked about.

    Returns:
        The PTR record's target name (e.g. "Chromecast-abc123.local"),
        with its trailing root dot stripped, or "" if this message has
        no PTR answer for qname.
    """
    try:
        question_count, answer_count = struct.unpack(">HH", message[4:8])
    except struct.error:
        return ""  # Too short to even be a valid DNS header - ignore it.

    offset = 12  # DNS header is always exactly 12 bytes.

    # Skip past the question section (present when this "response" is
    # actually another device's query, which we'll see plenty of on a
    # shared multicast channel) to reach the answers.
    for _ in range(question_count):
        _name, offset = _decode_dns_name(message, offset)
        offset += 4  # QTYPE + QCLASS, 2 bytes each.

    for _ in range(answer_count):
        name, offset = _decode_dns_name(message, offset)
        record_type, _record_class = struct.unpack(">HH", message[offset:offset + 4])
        offset += 4
        offset += 4  # TTL (4 bytes) - not needed for a one-shot lookup.
        rdata_length = struct.unpack(">H", message[offset:offset + 2])[0]
        offset += 2
        rdata_offset = offset
        offset += rdata_length

        if record_type == _DNS_TYPE_PTR and name.lower().rstrip(".") == qname.lower().rstrip("."):
            hostname, _ = _decode_dns_name(message, rdata_offset)
            return hostname.rstrip(".")

    return ""


def mdns_reverse_lookup(ip: str, timeout: float) -> str:
    """Look up ip's self-advertised ".local" hostname via mDNS/Bonjour.

    Ordinary reverse DNS (socket.gethostbyaddr) only works for devices
    that have a PTR record in the router/ISP's unicast DNS - which most
    consumer and IoT devices (Chromecasts, smart speakers, printers,
    etc.) never register. Those devices instead announce a hostname over
    mDNS, a multicast UDP protocol every device on the local link can
    see and respond to, so this asks the same "who is this IP?" question
    the same way.

    This needs no special privileges: it's an ordinary UDP socket, not a
    raw one - the same kind of client socket probe_host() already uses -
    so it works in the same sandboxed environments this whole script
    targets. It deliberately never joins the mDNS multicast group or
    binds to port 5353 (both restricted for third-party apps on iOS);
    instead the query sets mDNS's "QU" bit (see _MDNS_QU_BIT) asking the
    responder to reply via plain unicast UDP to our ephemeral port
    instead of its default multicast reply, which this ordinary socket
    can receive just fine. (On iOS specifically, the OS may still prompt
    for "Local Network" permission the first time an app sends this kind
    of query at all - if that's declined, this will just time out and
    return "" like any other non-responding device.)

    Args:
        ip: The target host's IPv4 address.
        timeout: How long to wait for a response, in seconds.

    Returns:
        The advertised hostname (e.g. "Chromecast-abc123.local"), or ""
        if the device didn't respond in time or doesn't support mDNS.
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
        # TTL 255 is the mDNS convention so the query reaches every
        # device on the local link, not just ones a few hops away.
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        try:
            sock.sendto(query, _MDNS_GROUP)
        except OSError:
            # Multicast send can fail if the sandbox denies local-network
            # access (e.g. iOS permission declined) - treat that the same
            # as "no answer" rather than crashing the whole scan.
            return ""

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ""
            sock.settimeout(remaining)
            try:
                message, _sender = sock.recvfrom(4096)
            except OSError:
                # Covers both a timeout and any other socket error while
                # reading - either way, we're not getting an answer.
                return ""

            hostname = _extract_ptr_hostname(message, qname)
            if hostname:
                return hostname


def _resolve_hostname(ip: str, mdns_timeout: float) -> str:
    """Resolve ip to a hostname, trying reverse DNS first and mDNS second.

    Args:
        ip: The target host's IPv4 address.
        mdns_timeout: How long to wait for an mDNS response if the
            ordinary reverse-DNS lookup comes up empty.

    Returns:
        A hostname from whichever method found one first, or "" if
        neither did.
    """
    try:
        # gethostbyaddr does a reverse-DNS (PTR) lookup; on a home
        # network this usually only resolves for the router itself,
        # since consumer devices rarely register PTR records.
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        # No PTR record, or the lookup timed out/failed outright - try
        # mDNS instead before giving up on a hostname entirely.
        return mdns_reverse_lookup(ip, timeout=mdns_timeout)


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
    mdns_timeout: float = 0.3,
) -> List[Device]:
    """Discover devices by probing common TCP ports across every host in subnet.

    Args:
        subnet: CIDR range to scan, e.g. "192.168.1.0/24".
        timeout: Per-port connection timeout, in seconds. Lower values
            scan faster but may miss slow-to-respond devices.
        ports: TCP ports to probe on each host (see DEFAULT_PORTS).
        max_workers: How many hosts to probe (and later, resolve
            hostnames for) concurrently. A /24 subnet has 254 usable
            addresses, so doing this one at a time would take 254x as
            long as the timeout; a thread pool lets us do them all in
            parallel instead.
        mdns_timeout: How long to wait for an mDNS/Bonjour response when
            a device has no reverse-DNS hostname (see
            mdns_reverse_lookup()). Kept separate from timeout since it's
            a different, typically slower, kind of lookup.

    Returns:
        Discovered devices sorted by IP address, each with "hostname"
        populated from reverse DNS or, failing that, mDNS (or "" if
        neither resolved it) and "port" set to whichever probed port
        answered first.
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
    # Resolving hostnames one at a time would add up fast once mDNS is
    # involved: a device that doesn't support it costs a full
    # mdns_timeout wait, and on a subnet with several such devices that's
    # additive if done sequentially. A thread pool runs them all at once
    # instead, same as the port-probing step above.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_resolve_hostname, ip_str, mdns_timeout): ip_str for ip_str in matched_ports
        }
        for future in as_completed(futures):
            ip_str = futures[future]
            hostname = future.result()
            devices.append({"ip": ip_str, "hostname": hostname, "port": matched_ports[ip_str]})

    # Sort numerically by IP (not lexicographically as strings, which would
    # put "10.0.0.2" after "10.0.0.10").
    return sorted(devices, key=lambda d: ipaddress.ip_address(d["ip"]))


def scan_all_subnets(
    subnets: Iterable[str],
    timeout: float = 0.5,
    ports: Sequence[int] = DEFAULT_PORTS,
    max_workers: int = 100,
    mdns_timeout: float = 0.3,
) -> List[Device]:
    """Run tcp_scan() over multiple subnets and merge the results into one list.

    Args:
        subnets: CIDR ranges to scan, e.g. ["192.168.1.0/24", "10.0.0.0/24"].
        timeout: Passed through to tcp_scan() for each subnet.
        ports: Passed through to tcp_scan() for each subnet.
        max_workers: Passed through to tcp_scan() for each subnet.
        mdns_timeout: Passed through to tcp_scan() for each subnet.

    Returns:
        Every discovered device across all subnets, sorted by IP and
        de-duplicated by IP address (the same device could otherwise be
        listed twice if two of the given subnets overlap).
    """
    # Keyed by IP so a later subnet's result for the same address simply
    # overwrites the earlier one rather than producing a duplicate row.
    devices_by_ip: Dict[str, Device] = {}
    for subnet in subnets:
        for device in tcp_scan(
            subnet, timeout=timeout, ports=ports, max_workers=max_workers, mdns_timeout=mdns_timeout
        ):
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
    parser.add_argument(
        "--mdns-timeout",
        type=float,
        default=0.3,
        help="Timeout in seconds for the mDNS/Bonjour hostname fallback, used when reverse DNS finds nothing (default: 0.3)",
    )
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

    devices: List[Device] = scan_all_subnets(
        subnets, timeout=args.timeout, ports=ports, mdns_timeout=args.mdns_timeout
    )

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
