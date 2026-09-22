#!/usr/bin/env python3
"""Browse every mDNS/DNS-SD service currently advertised on the local network.

network_scanner.py and mobile_network_scanner.py each use mDNS/DNS-SD for
exactly one thing: resolving a *known* IP's hostname, or checking whether
one specific service type (Chromecast's _googlecast._tcp.local) is in use.
Neither ever asks the broader question this script answers: "what services
exist on this network at all?" - printers, AirPlay speakers, SSH-capable
hosts, HomeKit accessories, and anything else advertising itself, without
needing to already know its IP or guess its service type up front.

This works via DNS-SD's own "meta-query" mechanism (RFC 6763 SS9): asking
"who offers _services._dns-sd._udp.local?" returns the actual list of
service types in use on the network, as PTR records whose target is each
service type's own name (e.g. "_googlecast._tcp.local"). That list is then
browsed the normal way (the same PTR/SRV/A join mdns_service_lookup() in
mobile_network_scanner.py already does, generalized here to many types at
once instead of one). Not every device implements the meta-query even when
it implements its own type's browsing, so the result is unioned with a
small built-in list of common service types (see _COMMON_SERVICE_TYPES)
rather than relying on the meta-query alone.

Usage:
    python mdns_browser.py                          # discover + browse everything found
    python mdns_browser.py --timeout 3
    python mdns_browser.py --services _http._tcp.local,_ipp._tcp.local
    python mdns_browser.py --no-discover             # skip the meta-query, use built-ins only
    python mdns_browser.py --output services.json
    python mdns_browser.py --no-color

This is best-effort, not a full mDNS/DNS-SD stack, same as the mDNS code in
the other two scripts: one query per service type, reading whatever comes
back within the timeout. It also shares their platform limitation - on iOS
(a-Shell, Pythonista, etc.), mDNS/DNS-SD sends fail outright with
OSError(65, 'No route to host') due to Apple's Local Network Privacy model
(see mobile_network_scanner.py's module docstring and mdns_diagnostic.py) -
this script has no workaround for that either, since it uses the exact same
underlying socket operations.
"""

import argparse
import csv
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

# --- mDNS/DNS-SD wire format ---
#
# Duplicated from mobile_network_scanner.py rather than imported - see this
# project's README for why: each script here is meant to be independently
# self-contained (copy-pastable on its own, e.g. via a single curl), not
# built on a shared internal module.

_MDNS_GROUP = ("224.0.0.251", 5353)

_DNS_TYPE_A = 1
_DNS_TYPE_PTR = 12
_DNS_TYPE_SRV = 33
_DNS_CLASS_IN = 1

# mDNS's "QU" flag (RFC 6762 SS5.4) - see mobile_network_scanner.py's own
# comment on this constant for the full rationale. Kept here even though
# this script always tries to bind/join the multicast group (see
# browse_services()) and so mostly expects multicast replies instead: a
# device that only knows how to send a unicast QU-flagged reply should
# still get one out of us.
_MDNS_QU_BIT = 0x8000

# RFC 6763 SS9's "meta-query" service type: querying for PTR records under
# this exact name returns the actual service types in use on the network,
# as each PTR record's target.
_DNS_SD_META_QUERY = "_services._dns-sd._udp.local"

# A small, non-exhaustive set of common service types to browse even if
# discover_service_types() comes back empty or missed one - not every
# device implements the SS9 meta-query, even when it implements ordinary
# browsing for its own type. Deliberately similar in spirit to
# RISKY_PORTS/PORT_SERVICES elsewhere in this project: a useful default,
# not a claim of completeness.
_COMMON_SERVICE_TYPES: Tuple[str, ...] = (
    "_googlecast._tcp.local",  # Chromecast and other Google Cast devices.
    "_airplay._tcp.local",  # AirPlay video (Apple TV, some smart TVs).
    "_raop._tcp.local",  # AirPlay audio ("Remote Audio Output Protocol").
    "_ipp._tcp.local",  # Network printers (IPP).
    "_ipps._tcp.local",  # Network printers (IPP over TLS).
    "_printer._tcp.local",  # Older LPR-style network printers.
    "_http._tcp.local",  # Anything with a web-based admin UI.
    "_https._tcp.local",
    "_ssh._tcp.local",
    "_sftp-ssh._tcp.local",
    "_smb._tcp.local",  # Windows/Samba file sharing.
    "_afpovertcp._tcp.local",  # Older Apple file sharing.
    "_workstation._tcp.local",  # Classic Bonjour "computer browser" record.
    "_spotify-connect._tcp.local",
    "_hap._tcp.local",  # HomeKit Accessory Protocol.
    "_device-info._tcp.local",
)


def _encode_dns_name(name: str) -> bytes:
    """DNS-encode a dotted name into length-prefixed-label wire format."""
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return encoded + b"\x00"


def _decode_dns_name(message: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at offset in message.

    See mobile_network_scanner.py's identical function for the full
    explanation of DNS name compression - this is a verbatim copy.
    """
    labels = []
    return_offset = None

    while True:
        length = message[offset]

        if length == 0:
            offset += 1
            break

        if length & 0xC0 == 0xC0:
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
    """Build a raw mDNS query packet asking "who is answering to qname?"."""
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    question = _encode_dns_name(qname) + struct.pack(">HH", _DNS_TYPE_PTR, _DNS_CLASS_IN | _MDNS_QU_BIT)
    return header + question


def _iter_mdns_records(message: bytes):
    """Yield (name, record_type, rdata_offset, rdata_length) for every record in message.

    See mobile_network_scanner.py's identical function for the full
    explanation - this is a verbatim copy.
    """
    try:
        question_count, answer_count, authority_count, additional_count = struct.unpack(">HHHH", message[4:12])
    except struct.error:
        return

    offset = 12

    for _ in range(question_count):
        _name, offset = _decode_dns_name(message, offset)
        offset += 4

    for _ in range(answer_count + authority_count + additional_count):
        try:
            name, offset = _decode_dns_name(message, offset)
            record_type, _record_class = struct.unpack(">HH", message[offset:offset + 4])
            offset += 4
            offset += 4  # TTL
            rdata_length = struct.unpack(">H", message[offset:offset + 2])[0]
            offset += 2
        except (struct.error, IndexError):
            return

        rdata_offset = offset
        offset += rdata_length
        yield name, record_type, rdata_offset, rdata_length


def _open_mdns_socket() -> socket.socket:
    """Open a UDP socket bound for mDNS, joining the multicast group if possible.

    Binding to port 5353 and joining 224.0.0.251 lets this receive
    multicast replies (what most DNS-SD browsing responses actually are -
    see mobile_network_scanner.py's mdns_service_lookup() for why), not
    just a unicast QU-flagged one. Falling back to an ordinary ephemeral
    socket on failure (a sandboxed environment, or another process already
    holding the port without SO_REUSEPORT) still works for a unicast
    reply - worse odds, but not a hard failure.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    try:
        sock.bind(("", _MDNS_GROUP[1]))
        join_request = struct.pack("4sl", socket.inet_aton(_MDNS_GROUP[0]), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, join_request)
    except OSError:
        pass
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    return sock


def discover_service_types(timeout: float) -> List[str]:
    """Ask the network which DNS-SD service types are actually advertised (RFC 6763 SS9).

    Args:
        timeout: How long to listen for responses, in seconds.

    Returns:
        Every distinct service type named in a PTR answer to the
        meta-query, sorted, or [] if nothing answered (or the multicast
        send itself failed - e.g. iOS's Local Network Privacy
        restriction). An empty result isn't necessarily "nothing is
        advertised" - it can also mean nothing on this network implements
        the meta-query itself; see _COMMON_SERVICE_TYPES for a built-in
        fallback list callers should union this with.
    """
    query = _build_mdns_ptr_query(_DNS_SD_META_QUERY)
    deadline = time.monotonic() + timeout
    service_types = set()

    with _open_mdns_socket() as sock:
        try:
            sock.sendto(query, _MDNS_GROUP)
        except OSError:
            return []

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
            try:
                message, _sender = sock.recvfrom(4096)
            except OSError:
                break
            for name, record_type, rdata_offset, _rdata_length in _iter_mdns_records(message):
                if record_type == _DNS_TYPE_PTR and name.lower().rstrip(".") == _DNS_SD_META_QUERY:
                    service_type, _ = _decode_dns_name(message, rdata_offset)
                    service_types.add(service_type.rstrip("."))

    return sorted(service_types)


def _collect_service_records(message: bytes, host_to_ip: Dict[str, str], instance_to_host: Dict[str, str]) -> None:
    """Pull A and SRV records for any DNS-SD service out of an mDNS response.

    Updates host_to_ip and instance_to_host in place - see
    mobile_network_scanner.py's identical function for the full
    explanation of why a full answer needs both maps joined later.
    """
    for name, record_type, rdata_offset, rdata_length in _iter_mdns_records(message):
        if record_type == _DNS_TYPE_A and rdata_length == 4:
            host_to_ip[name.lower().rstrip(".")] = socket.inet_ntoa(message[rdata_offset:rdata_offset + 4])
        elif record_type == _DNS_TYPE_SRV:
            target, _ = _decode_dns_name(message, rdata_offset + 6)
            instance_to_host[name.rstrip(".")] = target.lower().rstrip(".")


def browse_services(service_types: Sequence[str], timeout: float) -> Dict[str, Dict[str, str]]:
    """Discover devices advertising any of service_types, grouped by type.

    Sends one query per service type up front, on a single shared socket,
    then reads whatever comes back until timeout - much cheaper than
    calling something like mobile_network_scanner.py's
    mdns_service_lookup() once per type, which would pay the full timeout
    separately for each one.

    Args:
        service_types: DNS-SD service types to query for, e.g.
            ("_googlecast._tcp.local", "_ipp._tcp.local").
        timeout: How long to listen for responses in total, in seconds -
            shared across every service type, not per type.

    Returns:
        {service_type: {ip: friendly_name}}, one entry per service_type
        (possibly an empty dict if nothing answered for it). A device
        answering for a type not in service_types (e.g. mixed in from
        other multicast traffic on a shared channel) is never attributed
        to the wrong type - only entries whose instance name ends in
        "." + that exact service_type are recorded.
    """
    service_types = list(service_types)
    host_to_ip: Dict[str, str] = {}
    instance_to_host: Dict[str, str] = {}

    with _open_mdns_socket() as sock:
        try:
            for service_type in service_types:
                sock.sendto(_build_mdns_ptr_query(service_type), _MDNS_GROUP)
        except OSError:
            return {service_type: {} for service_type in service_types}

        deadline = time.monotonic() + timeout
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

    results: Dict[str, Dict[str, str]] = {service_type: {} for service_type in service_types}
    for instance_name, host in instance_to_host.items():
        ip = host_to_ip.get(host)
        if ip is None:
            continue
        lower_instance = instance_name.lower()
        for service_type in service_types:
            suffix = "." + service_type.lower().rstrip(".")
            if lower_instance.endswith(suffix):
                results[service_type][ip] = instance_name[: -len(suffix)]
                break

    return results


# --- Colorized terminal output (plain ANSI codes, no dependency) ---

_ANSI_CODES: Dict[str, str] = {
    "cyan": "\033[36m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def _use_color(no_color_flag: bool) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_ANSI_CODES[color]}{text}{_ANSI_CODES['reset']}"


# --- Exporting results ---

def export_results(results: Dict[str, Dict[str, str]], path: Path) -> None:
    """Save results to path as JSON or CSV, chosen by its extension.

    Args:
        results: browse_services()'s return value.
        path: Destination file - ".csv" writes CSV, anything else
            (typically ".json") writes JSON.
    """
    rows = [
        {"service_type": service_type, "ip": ip, "name": name}
        for service_type, devices in results.items()
        for ip, name in devices.items()
    ]
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["service_type", "ip", "name"])
            writer.writeheader()
            writer.writerows(rows)
    else:
        path.write_text(json.dumps(rows, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--timeout", type=float, default=2.0, help="How long to listen in each phase, in seconds (default: 2.0)"
    )
    parser.add_argument(
        "--services",
        type=str,
        default=None,
        metavar="LIST",
        help="Comma-separated DNS-SD service types to browse instead of the built-in list (see _COMMON_SERVICE_TYPES)",
    )
    parser.add_argument(
        "--no-discover",
        action="store_true",
        help="Skip the RFC 6763 SS9 meta-query phase (discover_service_types()) and only browse the built-in/--services list",
    )
    parser.add_argument("--output", type=str, default=None, metavar="FILE", help="Save results to FILE as JSON or CSV")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    color = _use_color(args.no_color)

    service_types = (
        [s.strip() for s in args.services.split(",") if s.strip()] if args.services else list(_COMMON_SERVICE_TYPES)
    )

    if not args.no_discover:
        print(f"Discovering service types in use (meta-query, {args.timeout:g}s) ...")
        discovered = discover_service_types(args.timeout)
        for service_type in discovered:
            if service_type not in service_types:
                service_types.append(service_type)

    print(f"Browsing {len(service_types)} service type(s) ({args.timeout:g}s) ...")
    results = browse_services(service_types, args.timeout)

    total_devices = sum(len(devices) for devices in results.values())
    found_types = {service_type: devices for service_type, devices in results.items() if devices}

    if not found_types:
        print("\nNo mDNS/DNS-SD services found.")
    else:
        print(f"\n{total_devices} device(s) across {len(found_types)} service type(s):\n")
        for service_type, devices in sorted(found_types.items()):
            print(_colorize(service_type, "cyan", color))
            for ip, name in sorted(devices.items()):
                print(f"  {ip:<20} {name}")
            print()

    if args.output:
        export_results(results, Path(args.output))
        print(f"Wrote {total_devices} device(s) to {args.output}.")


if __name__ == "__main__":
    main()
