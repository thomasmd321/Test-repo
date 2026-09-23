#!/usr/bin/env python3
"""Passively watch for a second (possibly rogue) DHCP server on the LAN.

arp_monitor.py watches for a different device answering as an IP that's
already known - this watches for a different class of LAN trouble: an
unauthorized DHCP server handing out its own leases alongside (or instead
of) your real router. A rogue DHCP server is a classic attack (hand out a
malicious gateway/DNS server to every new client) or an equally common
accident (someone plugs a consumer router in backwards, WAN port
unused, and its own DHCP server starts answering on your LAN). Either
way, nothing else in this project would ever notice - a device scan only
sees who's *on* the network, not who's been quietly handing out its
addresses.

Unlike arp_monitor.py, this needs no raw sockets or scapy at all. A DHCP
server's OFFER/ACK replies are ordinary broadcast UDP packets sent to port
68 (the client port) - an ordinary SOCK_DGRAM socket bound there receives
them the same way a real DHCP client does, sharing that port with
whatever DHCP client this OS is already running via
SO_REUSEADDR/SO_REUSEPORT. On Linux/macOS this still needs root: port 68
is a privileged (<1024) port there regardless of socket type, so avoiding
scapy doesn't avoid that requirement. Windows doesn't enforce the same
restriction - it doesn't require administrator to bind a port under 1024
the way POSIX does - but that's not the same as "just works" there: this
would be sharing port 68 with Windows' own DHCP Client service, and
Windows' SO_REUSEADDR has looser (and historically security-relevant)
semantics than POSIX's, so whether that bind actually succeeds, and what
it receives if it does, is genuinely untested rather than assumed fine.

Detection logic: the first DHCP server observed this session (or any
IP(s) named with --trusted-server) is treated as the known-good baseline;
any *additional*, distinct server IP answering after that is flagged. This
is a hygiene signal, not certain proof of an attack - see the caveat
--trusted-server's own help text spells out: without a pre-supplied
baseline, "first observed" is only as trustworthy as whichever server
happened to win that race, which could in principle already be the rogue
one if it's faster to answer than your real router. Naming your router's
actual IP with --trusted-server removes that ambiguity.

Usage:
    python dhcp_monitor.py                          # bind 0.0.0.0:68, first server seen is the baseline
    python dhcp_monitor.py --trusted-server 192.168.1.1
    python dhcp_monitor.py --bind-ip 192.168.1.50 --log rogue_dhcp.jsonl
    python dhcp_monitor.py --no-color

Verified more thoroughly than arp_monitor.py could manage (scapy's
sniff() has no privilege-free substitute to test against at all): this
tool's core wire-format parsing (parse_dhcp_packet()) and detection logic
(process_dhcp_observation()) are pure functions fully unit-tested with
hand-built packets; monitor()'s actual socket-receive loop is verified for
real end-to-end against a real, unmocked UDP socket bound to a
non-privileged loopback port instead of the real port 68, needing no
elevated privileges (see test_dhcp_monitor.py); and - since this
project's development sandbox happens to run as root - the real
production path was also run for real: the actual `python dhcp_monitor.py
--trusted-server ...` CLI, bound to the genuine privileged port 68,
correctly ignored a trusted server's OFFER and flagged a second, untrusted
one, end to end including --log's JSON output.

Known limitation, stated plainly: what's unverified even after all that
is real DHCP traffic from a real, physical network - every packet used
above (including the real-port-68 run) was hand-built to match the RFC
2131 wire format, not captured from an actual router. A real DHCP
server's option ordering, extra vendor-specific options, or other
real-world variation could still surprise parse_dhcp_packet() in ways a
hand-built test packet wouldn't.
"""

import argparse
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Optional, Set

_DHCP_MAGIC_COOKIE = bytes([99, 130, 83, 99])
_DHCP_HEADER_LENGTH = 236  # op..file, before the 4-byte magic cookie.
_DHCP_MESSAGE_TYPE_OPTION = 53
_DHCP_SERVER_ID_OPTION = 54
_DHCP_OFFER = 2
_DHCP_ACK = 5
_DHCP_CLIENT_PORT = 68


def _format_ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _parse_dhcp_options(data: bytes) -> Dict[int, bytes]:
    """Walk a DHCP option list (the TLV data after the magic cookie).

    Each option is (code: 1 byte, length: 1 byte, value: length bytes),
    except code 0 (pad, no length/value) and code 255 (end, stops parsing
    immediately - anything after it, including further garbage, is
    ignored rather than misread as more options).
    """
    options: Dict[int, bytes] = {}
    i = 0
    n = len(data)
    while i < n:
        code = data[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        if i + 1 >= n:
            break
        length = data[i + 1]
        value = data[i + 2:i + 2 + length]
        options[code] = value
        i += 2 + length
    return options


def parse_dhcp_packet(data: bytes) -> Optional[Dict[str, object]]:
    """Parse a raw BOOTP/DHCP packet (RFC 2131).

    Args:
        data: The raw UDP payload received on the DHCP client port.

    Returns:
        A dict with "message_type" (int or None), "server_id" (dotted-quad
        str or None - present on a proper OFFER/ACK per the RFC, though a
        misbehaving server could omit it), "yiaddr" (the offered/assigned
        client IP), and "chaddr" (the requesting client's MAC, or None if
        this packet's hlen field isn't the ordinary Ethernet value of 6) -
        or None if data is too short to be DHCP at all, or its magic
        cookie doesn't match (stray UDP traffic on this port happens; a
        wrong cookie means "not DHCP", not "malformed DHCP").
    """
    if len(data) < _DHCP_HEADER_LENGTH + len(_DHCP_MAGIC_COOKIE):
        return None
    if data[_DHCP_HEADER_LENGTH:_DHCP_HEADER_LENGTH + 4] != _DHCP_MAGIC_COOKIE:
        return None

    hlen = data[2]
    yiaddr = _format_ipv4(data[16:20])
    chaddr = _format_mac(data[28:28 + hlen]) if hlen == 6 else None

    options = _parse_dhcp_options(data[_DHCP_HEADER_LENGTH + 4:])
    message_type_raw = options.get(_DHCP_MESSAGE_TYPE_OPTION)
    message_type = message_type_raw[0] if message_type_raw else None
    server_id_raw = options.get(_DHCP_SERVER_ID_OPTION)
    server_id = _format_ipv4(server_id_raw) if server_id_raw and len(server_id_raw) == 4 else None

    return {"message_type": message_type, "server_id": server_id, "yiaddr": yiaddr, "chaddr": chaddr}


def process_dhcp_observation(server_ip: str, seen: Set[str]) -> bool:
    """Record server_ip as observed this session; report whether it's a rogue candidate.

    Kept as a pure function, independent of sockets entirely, the same
    reasoning arp_monitor.py's process_arp_observation() documents for its
    own detection logic - so it's testable with plain strings and sets.

    Args:
        server_ip: The DHCP server IP an OFFER/ACK came from.
        seen: This session's set of server IPs observed so far (or
            pre-seeded with --trusted-server values) - updated in place.

    Returns:
        True if server_ip is a *new*, additional server beyond whichever
        one(s) were already known (the rogue-candidate signal) - False if
        it's already known, or if it's the very first server this session
        has seen at all (that one is the assumed-legitimate baseline, not
        a "change" to flag against).
    """
    if server_ip in seen:
        return False
    is_rogue_candidate = len(seen) > 0
    seen.add(server_ip)
    return is_rogue_candidate


def monitor(
    on_rogue: Callable[[str, int], None],
    bind_ip: str = "0.0.0.0",
    port: int = _DHCP_CLIENT_PORT,
    trusted_servers: Optional[Set[str]] = None,
    seen: Optional[Set[str]] = None,
    sock: Optional[socket.socket] = None,
) -> None:
    """Listen for DHCP OFFER/ACK broadcasts, calling on_rogue for every server beyond the first.

    Args:
        on_rogue: Called as on_rogue(server_ip, message_type) for every
            detected additional server, in the order observed.
        bind_ip: Local address to bind to (0.0.0.0 for every interface).
        port: UDP port to listen on - always 68 (the real DHCP client
            port) in production; overridable here specifically so tests
            can bind to an unprivileged port instead (see this module's
            docstring and test_dhcp_monitor.py).
        trusted_servers: IP(s) to pre-seed as known-good, so they're never
            flagged even if they aren't the first one observed.
        seen: An existing set of server IPs to start from, instead of
            building one from trusted_servers - updated in place.
        sock: An already-bound socket to read from, instead of building
            and binding one internally - lets a test supply a socket
            that's already bound to an OS-assigned port (and already has
            a receive timeout set) rather than fighting over the real
            privileged port 68. When omitted, a real socket is created,
            bound, and closed on return/error, exactly as production use
            needs.

    Raises:
        PermissionError / OSError: this process lacks permission to bind
            the requested port - typically the real port 68, which needs
            root on Linux/macOS (Windows doesn't gate ports under 1024 on
            administrator status the same way, though see this module's
            docstring for why that doesn't mean the bind is guaranteed to
            succeed there either).

    This call never returns on its own - it listens until interrupted
    (Ctrl+C in production; a closed/timed-out socket in a test), the same
    shape as arp_monitor.py's monitor().
    """
    if seen is None:
        seen = set(trusted_servers or [])

    owns_socket = sock is None
    if sock is None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except (AttributeError, OSError):
            pass  # Not every platform has SO_REUSEPORT (e.g. older Windows) - SO_REUSEADDR alone is enough there.
        sock.bind((bind_ip, port))

    try:
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                # The socket was closed out from under this loop (a test
                # doing exactly that to stop it cleanly, or - in
                # production - whatever external cause). Either way,
                # there's nothing left to listen on: stop quietly rather
                # than raise from inside what's normally a background
                # loop.
                return
            packet = parse_dhcp_packet(data)
            if packet is None or packet["message_type"] not in (_DHCP_OFFER, _DHCP_ACK):
                continue
            server_ip = packet["server_id"] or addr[0]
            if process_dhcp_observation(server_ip, seen):
                on_rogue(server_ip, packet["message_type"])
    finally:
        if owns_socket:
            sock.close()


# --- Colorized terminal output (plain ANSI codes, no dependency) ---

_ANSI_CODES: Dict[str, str] = {
    "magenta": "\033[35m",
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


def _append_log(path: Path, server_ip: str, message_type: int) -> None:
    """Append one detected rogue-server sighting to path as a JSON line - swallows a write failure, same as arp_monitor.py's _append_log()."""
    entry = json.dumps({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "server_ip": server_ip,
        "message_type": "OFFER" if message_type == _DHCP_OFFER else "ACK",
    })
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bind-ip", type=str, default="0.0.0.0", help="Local address to bind to (default: 0.0.0.0, every interface)")
    parser.add_argument(
        "--trusted-server", action="append", default=None, metavar="IP",
        help="A known-good DHCP server IP (repeatable) - pre-seeds the baseline so it's never flagged, "
             "even if it isn't the first server observed this session",
    )
    parser.add_argument("--log", type=str, default=None, metavar="FILE", help="Append each detected rogue server to FILE as one JSON line")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    color = _use_color(args.no_color)

    def on_rogue(server_ip: str, message_type: int) -> None:
        timestamp = time.strftime("%H:%M:%S")
        kind = "OFFER" if message_type == _DHCP_OFFER else "ACK"
        line = f"[{timestamp}] Unexpected DHCP {kind} from {server_ip} - a possible rogue/unauthorized DHCP server"
        print(_colorize(line, "magenta", color))
        if args.log:
            _append_log(Path(args.log), server_ip, message_type)

    print(f"Watching for rogue DHCP servers on {args.bind_ip}:{_DHCP_CLIENT_PORT} (Ctrl+C to stop) ...")
    if args.trusted_server:
        print(f"Trusted server(s): {', '.join(args.trusted_server)}")
    else:
        print("No --trusted-server given - the first DHCP server observed will be treated as the legitimate baseline.")

    try:
        monitor(on_rogue, bind_ip=args.bind_ip, trusted_servers=set(args.trusted_server) if args.trusted_server else None)
    except KeyboardInterrupt:
        print("\nStopped.")
    except PermissionError as exc:
        print(f"Error: couldn't bind to port {_DHCP_CLIENT_PORT} ({exc}) - on Linux/macOS this needs root, since DHCP's client port is privileged there")
        raise SystemExit(1)
    except OSError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
