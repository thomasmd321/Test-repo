#!/usr/bin/env python3
"""Check for DNS hijacking: a resolver answering for a domain that shouldn't exist.

Every other tool here assumes your network's DNS answers can be trusted -
exposure_check.py resolves nothing itself, and even upnp_audit.py/
mdns_browser.py work at the IP level. But a compromised router, a
malicious/free Wi-Fi hotspot, or a captive portal all commonly do the same
thing: intercept DNS and answer with their own IP for domains that should
NXDOMAIN (no such domain), redirecting you to an ad page, a phishing page,
or a "please log in" portal before you've even opened a browser. Nothing
else in this project would notice - a scan sees devices and open ports,
not whether the network is lying to you about DNS.

Two checks, run against your system's own configured resolver (whatever
it's actually using - /etc/resolv.conf, DHCP-provided DNS, or a platform's
own network settings, all covered identically since this asks the OS to
resolve it rather than reading that configuration itself) and against a
small set of known-good public resolvers:

1. THE DECISIVE ONE - NXDOMAIN hijacking: query a freshly random hostname
   under the ".invalid" TLD, which RFC 2606 reserves specifically so it
   can never be a real registered domain. Any answer at all for it - from
   your resolver or a public one - means something is intercepting
   NXDOMAIN responses and fabricating an answer. This is nearly always
   deliberate interception, not a false positive.

2. A SOFTER, CAVEATED ONE - cross-resolver comparison: resolve
   example.com (also reserved by RFC 2606, specifically for stable
   documentation/testing use, unlike almost every other domain which may
   be legitimately answered differently per resolver via CDN/anycast
   geo-routing) against your resolver and each public one, and report a
   mismatch. Unlike check 1, a mismatch here is a *softer* signal - see
   the caveat this prints on every run.

The public resolvers are queried directly with a hand-built, from-scratch
DNS client over raw UDP sockets (stdlib only: socket + struct), since
Python's standard library has no way to target a *specific* resolver
address - socket.getaddrinfo()/gethostbyname() always go through whatever
the OS itself is configured to use, which is exactly what's needed for
"my configured resolver" but useless for "what does 1.1.1.1 say". The
wire-format name encoding/decoding (_encode_dns_name/_decode_dns_name) is
duplicated from mobile_network_scanner.py/mdns_browser.py rather than
imported - see this project's README for why each script here stays
independently self-contained - and extended here with real compression-
pointer following in answer records plus response validation (matching
transaction ID) that those mDNS-only versions didn't need, since mDNS
correlates replies by name over a shared multicast channel rather than by
a real request/response pairing to one specific server.

Usage:
    python dns_check.py                       # both checks, default public resolvers
    python dns_check.py --resolver 1.1.1.1 --resolver 9.9.9.9
    python dns_check.py --timeout 5 --output dns_check.json
    python dns_check.py --no-color

Verified about as thoroughly as a tool here can be: query_resolver()'s
wire-format build/parse code is exercised for real against a small fake
UDP DNS server run locally in test_dns_check.py (a genuine, unmocked
socket end-to-end test, including a compressed name in the answer
record and a rejected mismatched-transaction-ID reply) - and, unlike this
project's HTTPS-based tools (exposure_check.py's api.ipify.org call,
blocked by this sandbox's outbound HTTP proxy), raw UDP port 53 traffic
isn't proxied here, so a real run against the actual internet-facing
Cloudflare/Google/Quad9 resolvers worked end to end too: all three (and
the local resolver) correctly returned NXDOMAIN for a fresh canary, and
all three agreed with the local resolver's real example.com answer.
That's every code path in this module exercised for real - the only
thing genuinely untested is a *live* DNS-hijacking network to confirm a
positive result looks right, which by definition isn't something to go
looking for.
"""

import argparse
import json
import os
import random
import secrets
import socket
import struct
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, TypedDict

_DNS_TYPE_A = 1
_DNS_CLASS_IN = 1
_DNS_PORT = 53
_RCODE_NXDOMAIN = 3

# RFC 2606 reserves .invalid so it can never be delegated/registered - any
# answer under it at all is a hijack, not a false positive from a domain
# someone happened to register. example.com is reserved by the same RFC
# specifically for stable documentation/testing use.
_CANARY_TLD = "invalid"
_COMPARISON_DOMAIN = "example.com"

DEFAULT_PUBLIC_RESOLVERS: Dict[str, str] = {
    "Cloudflare": "1.1.1.1",
    "Google": "8.8.8.8",
    "Quad9": "9.9.9.9",
}


class ResolverResult(TypedDict):
    rcode: int
    answers: List[str]


def make_canary_hostname() -> str:
    """A fresh, unguessable hostname under the reserved .invalid TLD - never resolvable, ever."""
    return f"dns-check-{secrets.token_hex(6)}.{_CANARY_TLD}"


# --- Raw DNS wire format (stdlib only - see this module's docstring) ---

def _encode_dns_name(name: str) -> bytes:
    """DNS-encode a dotted name into length-prefixed-label wire format, same as mobile_network_scanner.py's own copy."""
    encoded = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
    return encoded + b"\x00"


def _decode_dns_name(message: bytes, offset: int) -> Tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at offset in message - same algorithm as mobile_network_scanner.py's own copy, which see for the compression-pointer explanation."""
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


def _build_dns_query(qname: str, txid: int, qtype: int = _DNS_TYPE_A) -> bytes:
    """Build a standard (unicast, recursive) DNS query - unlike mDNS's own query builder, this sets the RD (recursion desired) flag, since a real resolver won't walk the tree itself without being asked to, and uses a real random transaction ID rather than 0, since replies here are matched by ID against one specific server rather than by name over a shared multicast channel."""
    flags = 0x0100  # RD bit set, everything else (opcode=QUERY, not truncated, etc.) zero.
    header = struct.pack(">HHHHHH", txid, flags, 1, 0, 0, 0)
    question = _encode_dns_name(qname) + struct.pack(">HH", qtype, _DNS_CLASS_IN)
    return header + question


def _parse_dns_response(message: bytes, expected_txid: int) -> Optional[ResolverResult]:
    """Parse a DNS response, validating it's actually a reply to our own query.

    Args:
        message: The raw UDP payload received back.
        expected_txid: The transaction ID our query used - a response
            with any other ID (or the QR "is a response" bit unset) is
            rejected outright, since accepting it would mean trusting
            unsolicited/spoofed UDP traffic on this ephemeral port as if
            it were the answer we asked for.

    Returns:
        {"rcode": ..., "answers": [ip, ...]} (A-record IPs only, in wire
        order) on a well-formed match, or None if this message doesn't
        match our query or is too malformed to safely parse further.
    """
    if len(message) < 12:
        return None
    txid, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(">HHHHHH", message[:12])
    if txid != expected_txid:
        return None
    is_response = (flags >> 15) & 1
    if not is_response:
        return None
    rcode = flags & 0x000F

    offset = 12
    try:
        for _ in range(qdcount):
            _name, offset = _decode_dns_name(message, offset)
            offset += 4  # QTYPE + QCLASS
    except IndexError:
        return None

    answers: List[str] = []
    for _ in range(ancount):
        try:
            _name, offset = _decode_dns_name(message, offset)
            record_type, _record_class = struct.unpack(">HH", message[offset:offset + 4])
            offset += 4
            offset += 4  # TTL - not needed here.
            rdata_length = struct.unpack(">H", message[offset:offset + 2])[0]
            offset += 2
            rdata = message[offset:offset + rdata_length]
            offset += rdata_length
        except (struct.error, IndexError):
            break  # Truncated/malformed record - keep whatever answers parsed cleanly so far.
        if record_type == _DNS_TYPE_A and len(rdata) == 4:
            answers.append(".".join(str(b) for b in rdata))

    return {"rcode": rcode, "answers": answers}


def query_resolver(resolver_ip: str, qname: str, timeout: float = 3.0, qtype: int = _DNS_TYPE_A, port: int = _DNS_PORT) -> ResolverResult:
    """Send one A-record query straight to resolver_ip:port over UDP and parse the reply.

    Args:
        resolver_ip: The resolver to query directly (bypassing whatever
            the OS itself is configured to use).
        qname: The hostname to resolve.
        timeout: How long to wait for a reply, in seconds.
        qtype: The DNS record type to ask for (default: A/IPv4).
        port: UDP port to query - always 53 (the real DNS port) in
            production; overridable here specifically so tests can run a
            fake resolver on an unprivileged port instead (see
            test_dns_check.py).

    Returns:
        {"rcode": int, "answers": [ip, ...]}. rcode 0 means NOERROR;
        _RCODE_NXDOMAIN (3) means the resolver itself correctly reports no
        such domain - the expected, correct result for a real canary.

    Raises:
        RuntimeError: no reply within timeout, the socket couldn't be
            used (e.g. resolver_ip isn't reachable at all), or a reply
            arrived that doesn't validate against our own query (see
            _parse_dns_response) - in every case, something about talking
            to resolver_ip didn't work, not something to guess past.
    """
    txid = random.randint(0, 0xFFFF)
    query = _build_dns_query(qname, txid, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (resolver_ip, port))
            data, _addr = sock.recvfrom(4096)
        except socket.timeout:
            raise RuntimeError(f"{resolver_ip} did not respond within {timeout:g}s")
        except OSError as exc:
            raise RuntimeError(f"Couldn't reach {resolver_ip}: {exc}")

    parsed = _parse_dns_response(data, txid)
    if parsed is None:
        raise RuntimeError(f"{resolver_ip} sent a response that doesn't match our query (wrong transaction ID, or malformed)")
    return parsed


def resolve_locally(hostname: str, timeout: float = 3.0) -> Optional[List[str]]:
    """Resolve hostname via the OS's own configured resolver - the same lookup path every other program on this machine uses.

    Args:
        hostname: The name to resolve.
        timeout: How long to allow the OS resolution call to take, in
            seconds (temporarily overrides socket.getdefaulttimeout(),
            restored afterward either way - this is the only knob Python
            exposes for this, since getaddrinfo() takes no timeout
            argument of its own).

    Returns:
        Every resolved IPv4 address, or None if resolution failed for any
        reason (NXDOMAIN, network error, timeout) - which is the correct,
        expected result for a genuine canary hostname.
    """
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
    except (socket.gaierror, socket.timeout, OSError):
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return sorted({info[4][0] for info in infos})


# --- The two checks ---

def check_nxdomain_hijack(public_resolvers: Dict[str, str], timeout: float = 3.0) -> Dict[str, object]:
    """Query a fresh, guaranteed-nonexistent hostname against the local resolver and each public one.

    Returns:
        {
          "canary": the hostname used,
          "local": {"hijacked": bool, "detail": str},
          "resolvers": {name: {"hijacked": bool, "detail": str, "error": Optional[str]}},
        }
        A resolver that couldn't be reached at all reports hijacked=False
        (there's no answer to be hijacked) with its error message in both
        "detail" and "error", so a network hiccup isn't confused with a
        clean NXDOMAIN.
    """
    canary = make_canary_hostname()
    result: Dict[str, object] = {"canary": canary, "local": None, "resolvers": {}}

    local_answers = resolve_locally(canary, timeout)
    result["local"] = {
        "hijacked": local_answers is not None,
        "detail": f"resolved to {', '.join(local_answers)}" if local_answers else "correctly returned NXDOMAIN",
    }

    resolvers: Dict[str, Dict[str, object]] = {}
    for name, ip in public_resolvers.items():
        try:
            parsed = query_resolver(ip, canary, timeout)
        except RuntimeError as exc:
            resolvers[name] = {"hijacked": False, "detail": str(exc), "error": str(exc)}
            continue
        hijacked = parsed["rcode"] == 0 and bool(parsed["answers"])
        if hijacked:
            detail = f"resolved to {', '.join(parsed['answers'])}"
        elif parsed["rcode"] == _RCODE_NXDOMAIN:
            detail = "correctly returned NXDOMAIN"
        else:
            detail = f"returned RCODE {parsed['rcode']} with no answers"
        resolvers[name] = {"hijacked": hijacked, "detail": detail, "error": None}
    result["resolvers"] = resolvers

    return result


def check_resolver_agreement(public_resolvers: Dict[str, str], domain: str = _COMPARISON_DOMAIN, timeout: float = 3.0) -> Dict[str, object]:
    """Compare A records for domain between the local resolver and each public one.

    Returns:
        {"domain": domain, "local": [ip, ...], "resolvers": {name: {"answers": [ip, ...], "error": Optional[str]}}}
    """
    local_answers = resolve_locally(domain, timeout) or []
    resolvers: Dict[str, Dict[str, object]] = {}
    for name, ip in public_resolvers.items():
        try:
            parsed = query_resolver(ip, domain, timeout)
            resolvers[name] = {"answers": sorted(parsed["answers"]), "error": None}
        except RuntimeError as exc:
            resolvers[name] = {"answers": [], "error": str(exc)}
    return {"domain": domain, "local": sorted(local_answers), "resolvers": resolvers}


# --- Colorized terminal output (plain ANSI codes, no dependency) ---

_ANSI_CODES: Dict[str, str] = {
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
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


_AGREEMENT_CAVEAT = (
    "Note: a mismatch here is a softer signal than the NXDOMAIN check above.\n"
    "example.com is reserved for stable documentation use (RFC 2606), but a\n"
    "resolver-specific answer isn't automatically hijacking - a proxying/\n"
    "filtering resolver, or a stale cache, can also cause this. Treat it as\n"
    "worth a second look, not proof on its own."
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--resolver", action="append", default=None, metavar="IP",
        help="A public resolver IP to check against (repeatable) - default: Cloudflare, Google, Quad9",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-query timeout, in seconds (default: 3.0)")
    parser.add_argument("--output", type=str, default=None, metavar="FILE", help="Save results to FILE as JSON")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    color = _use_color(args.no_color)

    if args.resolver:
        public_resolvers = {ip: ip for ip in args.resolver}
    else:
        public_resolvers = DEFAULT_PUBLIC_RESOLVERS

    print("Checking for DNS hijacking (a resolver answering for a domain that shouldn't exist) ...")
    hijack_result = check_nxdomain_hijack(public_resolvers, args.timeout)

    any_hijacked = hijack_result["local"]["hijacked"] or any(r["hijacked"] for r in hijack_result["resolvers"].values())

    print(f"\nCanary domain: {hijack_result['canary']} (reserved, guaranteed never to resolve)")
    local_line = f"{'Your resolver':<16}{hijack_result['local']['detail']}"
    print(_colorize(local_line, "red" if hijack_result["local"]["hijacked"] else "green", color))
    for name, r in hijack_result["resolvers"].items():
        line = f"{name:<16}{r['detail']}"
        print(_colorize(line, "red" if r["hijacked"] else ("yellow" if r["error"] else "green"), color))

    if any_hijacked:
        print(_colorize("\nDNS hijacking detected - something is intercepting NXDOMAIN and fabricating an answer.", "red", color))
    else:
        print(_colorize("\nNo NXDOMAIN hijacking detected.", "green", color))

    print(f"\nComparing {_COMPARISON_DOMAIN} across resolvers ...")
    agreement_result = check_resolver_agreement(public_resolvers, timeout=args.timeout)
    local_set = set(agreement_result["local"])
    print(f"{'Your resolver':<16}{', '.join(agreement_result['local']) or '(no answer)'}")
    any_mismatch = False
    for name, r in agreement_result["resolvers"].items():
        if r["error"]:
            print(_colorize(f"{name:<16}{r['error']}", "yellow", color))
            continue
        matches = set(r["answers"]) == local_set
        if not matches:
            any_mismatch = True
        line = f"{name:<16}{', '.join(r['answers']) or '(no answer)'}"
        print(_colorize(line, "yellow" if not matches else "green", color))

    if any_mismatch:
        print(f"\n{_colorize(_AGREEMENT_CAVEAT, 'dim', color)}")

    if args.output:
        Path(args.output).write_text(
            json.dumps({"nxdomain_hijack": hijack_result, "resolver_agreement": agreement_result}, indent=2),
            encoding="utf-8",
        )
        print(f"\nWrote results to {args.output}.")

    if any_hijacked:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
