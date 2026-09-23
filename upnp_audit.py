#!/usr/bin/env python3
"""List every port your router's UPnP has silently opened to the internet.

exposure_check.py answers "is this port reachable from outside" after the
fact, by probing your public IP. This answers a sharper, earlier question:
*why* a port might be open at all, even though nothing in this LAN's own
scan results looks unusual. Many home routers ship with UPnP (Universal
Plug and Play) enabled, letting any device on the network ask the router to
forward a port from the internet straight to itself - a game console, a
BitTorrent client, a smart-home hub - with no further confirmation and no
trace visible from LAN-side scanning at all. This queries the router
itself for its current UPnP port-mapping table, the same information a
malicious LAN device could have used to open that port in the first place.

Protocol, in order:
    1. SSDP discovery - an M-SEARCH multicast UDP query to 239.255.255.250:
       1900, the standard way anything on a LAN finds a UPnP Internet
       Gateway Device (the same request/response shape mDNS/DNS-SD's
       "meta-query" idea is built on, just an older, HTTP-header-flavored
       sibling protocol rather than DNS's wire format).
    2. Fetch the device's XML description from the LOCATION URL the SSDP
       response points to, and find its WANIPConnection or
       WANPPPConnection service - the ones that actually manage port
       forwarding - by walking the XML rather than assuming any one
       nesting depth, since routers vary here.
    3. Call that service's GetGenericPortMappingEntry SOAP action once per
       index (0, 1, 2, ...) until the router reports there are no more -
       a normal SOAP fault (usually error 713), not a real failure.

Usage:
    python upnp_audit.py
    python upnp_audit.py --timeout 5
    python upnp_audit.py --output mappings.json
    python upnp_audit.py --no-color

Known limitation, stated plainly: this project's own development
environment has no reachable UPnP Internet Gateway Device to discover -
the full SSDP -> XML -> SOAP pipeline is verified with a real, unmocked
gateway simulated locally (a genuine SSDP responder plus a genuine HTTP
server serving real XML/SOAP bodies, all communicating over real sockets -
see test_upnp_audit.py), which exercises every wire-format detail this
script actually depends on, but it has never spoken to a real router.
Router UPnP stacks are inconsistent about spec compliance in ways a
simulated one won't reproduce; treat a first real run as the verification
it hasn't had yet, and please report back if your router's real responses
don't parse the way this expects.
"""

import argparse
import csv
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, TypedDict
from urllib.parse import urljoin

_SSDP_ADDR = ("239.255.255.250", 1900)

# Sent as three separate M-SEARCH queries on one socket/listen window
# (see discover_gateway()) rather than picking just one: :1 and :2 are
# the two IGD spec versions actually deployed in the wild, and
# upnp:rootdevice is a broader fallback some routers only answer to.
_IGD_SEARCH_TARGETS = (
    "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
    "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
    "upnp:rootdevice",
)

# Reused verbatim from network_scanner.py/mobile_network_scanner.py's own
# RISKY_PORTS rather than imported - see this project's README for why
# each script here stays independently self-contained. Flagging a mapping
# against the same list means "is this externally-forwarded port also one
# already flagged as risky on the LAN" rather than a separately-curated
# judgment call.
RISKY_PORTS: Dict[int, str] = {
    21: "FTP transmits credentials in plaintext",
    23: "Telnet transmits everything, including credentials, in plaintext",
    445: "SMB is a common ransomware/worm vector when exposed beyond the LAN",
    3389: "RDP is frequently targeted by credential-stuffing and brute-force scans",
    5900: "VNC often runs with weak or no authentication by default",
}


class WanService(TypedDict):
    service_type: str
    control_url: str


class PortMapping(TypedDict):
    external_port: int
    internal_ip: str
    internal_port: int
    protocol: str
    description: str
    enabled: bool


def _build_msearch(search_target: str) -> bytes:
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {_SSDP_ADDR[0]}:{_SSDP_ADDR[1]}\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        f"ST: {search_target}\r\n"
        "\r\n"
    ).encode("ascii")


def _extract_location(response: bytes) -> Optional[str]:
    """Pull the LOCATION header's value out of a raw SSDP response."""
    try:
        text = response.decode("ascii", errors="replace")
    except UnicodeDecodeError:
        return None
    for line in text.splitlines():
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip()
    return None


def discover_gateway(timeout: float = 3.0) -> Optional[str]:
    """SSDP-discover the LAN's UPnP Internet Gateway Device.

    Args:
        timeout: How long to listen for responses, in seconds, after
            sending every search query.

    Returns:
        The LOCATION URL of the first responding device's XML
        description, or None if nothing answered within timeout (SSDP is
        UDP and best-effort, same as mDNS - a device not responding isn't
        necessarily an error).
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        try:
            for search_target in _IGD_SEARCH_TARGETS:
                sock.sendto(_build_msearch(search_target), _SSDP_ADDR)
        except OSError:
            return None

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            sock.settimeout(remaining)
            try:
                data, _sender = sock.recvfrom(4096)
            except OSError:
                return None
            location = _extract_location(data)
            if location:
                return location


def _local_tag(element: ET.Element) -> str:
    """Strip a UPnP XML element's namespace, leaving just its own tag name.

    UPnP device/service descriptions declare a default XML namespace, so
    every tag actually parses as e.g. "{urn:schemas-upnp-org:device-1-0}
    service" rather than plain "service" - stripping it here means every
    other function can match on the plain name without needing to know
    (or hardcode) that namespace URI.
    """
    return element.tag.rsplit("}", 1)[-1]


def _find_child_text(element: ET.Element, tag_name: str) -> Optional[str]:
    for child in element:
        if _local_tag(child) == tag_name:
            return child.text
    return None


def find_wan_service(xml_text: str, base_url: str) -> Optional[WanService]:
    """Find the WANIPConnection/WANPPPConnection service in a device description.

    Args:
        xml_text: The raw XML fetched from a gateway's LOCATION URL.
        base_url: That same LOCATION URL, used to resolve a relative
            controlURL against (routers commonly give a path like
            "/upnp/control/WANIPConn1" rather than a full URL).

    Returns:
        The matching service's type and absolute control URL, or None if
        parsing failed or no matching service was found anywhere in the
        (possibly deeply nested) device tree - walked with .iter() rather
        than assuming any fixed nesting depth, since routers vary here.
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    for element in root.iter():
        if _local_tag(element) != "service":
            continue
        service_type = _find_child_text(element, "serviceType")
        control_url = _find_child_text(element, "controlURL")
        if not service_type or not control_url:
            continue
        if "WANIPConnection" in service_type or "WANPPPConnection" in service_type:
            return {"service_type": service_type, "control_url": urljoin(base_url, control_url)}

    return None


def get_device_description(location_url: str, timeout: float) -> str:
    """Fetch a gateway's XML device description from its LOCATION URL."""
    with urllib.request.urlopen(location_url, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _build_soap_request(service_type: str, index: int) -> bytes:
    return (
        '<?xml version="1.0"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
        's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
        "<s:Body>"
        f'<u:GetGenericPortMappingEntry xmlns:u="{service_type}">'
        f"<NewPortMappingIndex>{index}</NewPortMappingIndex>"
        "</u:GetGenericPortMappingEntry>"
        "</s:Body>"
        "</s:Envelope>"
    ).encode("utf-8")


def parse_port_mapping_response(xml_text: str) -> Optional[PortMapping]:
    """Parse one GetGenericPortMappingEntry SOAP response into a PortMapping.

    Returns None if the response can't be parsed as XML, or has no
    NewExternalPort field at all - either means there's no mapping here
    to report (e.g. a SOAP fault body, which callers should have already
    treated as "stop enumerating" via the HTTP error it usually arrives
    as - see get_port_mappings()).
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None

    fields: Dict[str, str] = {}
    for element in root.iter():
        tag = _local_tag(element)
        if tag.startswith("New") and element.text is not None:
            fields[tag] = element.text

    if "NewExternalPort" not in fields:
        return None

    return {
        "external_port": int(fields["NewExternalPort"]),
        "internal_ip": fields.get("NewInternalClient", ""),
        "internal_port": int(fields.get("NewInternalPort", 0) or 0),
        "protocol": fields.get("NewProtocol", ""),
        "description": fields.get("NewPortMappingDescription", ""),
        "enabled": fields.get("NewEnabled", "0") in ("1", "true", "True"),
    }


def get_port_mappings(control_url: str, service_type: str, timeout: float, max_entries: int = 200) -> List[PortMapping]:
    """Enumerate every port mapping a WAN connection service currently has.

    Args:
        control_url: The service's absolute SOAP control URL (see
            find_wan_service()).
        service_type: That same service's type string, used both in the
            SOAP request body and the required SOAPAction header.
        timeout: Per-request timeout, in seconds.
        max_entries: A hard cap on how many indices to try, purely as a
            safety net against a router that never returns the "no more
            entries" fault at all - 200 is far beyond what any home
            router's mapping table actually holds.

    Returns:
        Every mapping the router reported, in index order, up to
        whichever came first: the router's own "no more entries" fault
        (an HTTP error - the normal, expected way this ends), a
        genuinely unparseable response, or max_entries.
    """
    mappings: List[PortMapping] = []
    for index in range(max_entries):
        request = urllib.request.Request(
            control_url,
            data=_build_soap_request(service_type, index),
            method="POST",
            headers={
                "Content-Type": 'text/xml; charset="utf-8"',
                "SOAPAction": f'"{service_type}#GetGenericPortMappingEntry"',
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = response.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError):
            # Covers both urllib.error.HTTPError (a SOAP fault, almost
            # always meaning "index out of range" - the router's normal
            # way of saying the table ends here) and any other transport
            # failure - either way, there's nothing more to enumerate.
            break

        mapping = parse_port_mapping_response(body)
        if mapping is None:
            break
        mappings.append(mapping)

    return mappings


def audit(timeout: float = 3.0) -> List[PortMapping]:
    """Discover this LAN's gateway and list its current UPnP port mappings.

    Args:
        timeout: Used for every network step - SSDP discovery, fetching
            the device description, and each SOAP call.

    Returns:
        Every current port mapping the gateway's WAN connection service
        reports.

    Raises:
        RuntimeError: No gateway answered SSDP discovery, or the one that
            did doesn't advertise a WANIPConnection/WANPPPConnection
            service to query.
    """
    location = discover_gateway(timeout)
    if location is None:
        raise RuntimeError(
            "No UPnP Internet Gateway Device responded - UPnP may be disabled on your router, "
            "or this network genuinely has none"
        )

    xml_text = get_device_description(location, timeout)
    wan_service = find_wan_service(xml_text, location)
    if wan_service is None:
        raise RuntimeError(f"{location} doesn't advertise a WANIPConnection/WANPPPConnection service")

    return get_port_mappings(wan_service["control_url"], wan_service["service_type"], timeout)


# --- Colorized terminal output (plain ANSI codes, no dependency) ---

_ANSI_CODES: Dict[str, str] = {
    "red": "\033[31m",
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

def export_results(mappings: List[PortMapping], path: Path) -> None:
    """Save mappings to path as JSON or CSV, chosen by its extension."""
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["external_port", "internal_ip", "internal_port", "protocol", "description", "enabled"])
            writer.writeheader()
            writer.writerows(mappings)
    else:
        path.write_text(json.dumps(mappings, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout for each network step, in seconds (default: 3.0)")
    parser.add_argument("--output", type=str, default=None, metavar="FILE", help="Save results to FILE as JSON or CSV")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    color = _use_color(args.no_color)

    print("Discovering your router's UPnP gateway (SSDP) ...")
    try:
        mappings = audit(args.timeout)
    except RuntimeError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)

    if not mappings:
        print("No port mappings found - either none are set, or UPnP mapping enumeration isn't supported here.")
        return

    print(f"\n{len(mappings)} port mapping(s):\n")
    print(f"{'Ext Port':<10}{'Protocol':<10}{'Internal':<24}{'Enabled':<9}Description")
    print("-" * 90)
    risky_count = 0
    for mapping in mappings:
        internal = f"{mapping['internal_ip']}:{mapping['internal_port']}"
        enabled_display = "yes" if mapping["enabled"] else "no"
        row = f"{mapping['external_port']:<10}{mapping['protocol']:<10}{internal:<24}{enabled_display:<9}{mapping['description']}"
        if mapping["external_port"] in RISKY_PORTS:
            risky_count += 1
            row = _colorize(row, "red", color)
        print(row)

    if risky_count:
        print(_colorize(f"\n⚠ {risky_count} mapping(s) forward a commonly-risky port to the internet:", "red", color))
        for port in sorted({m["external_port"] for m in mappings if m["external_port"] in RISKY_PORTS}):
            print(f"  {port:<6} {RISKY_PORTS[port]}")

    if args.output:
        export_results(mappings, Path(args.output))
        print(f"\nWrote {len(mappings)} mapping(s) to {args.output}.")


if __name__ == "__main__":
    main()
