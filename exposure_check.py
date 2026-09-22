#!/usr/bin/env python3
"""Check whether ports open on your LAN are also reachable from the internet.

network_scanner.py/mobile_network_scanner.py's RISKY_PORTS check flags a
port as worth a second look purely from inside the LAN - but a risky port
reachable only from your own network (telnet on a printer nobody outside
the house can reach) is a much smaller problem than the same port reachable
from the entire internet. This asks the second, sharper question: probing
your own public/WAN IP address, from this machine, for exactly the ports
RISKY_PORTS already flags (or any --ports you name instead).

How the public IP is found: a single plain HTTP(S) GET to
https://api.ipify.org - a small, purpose-built, widely used "what's my IP"
echo service (no account, no API key, returns just the address as plain
text). No other data about your network is sent anywhere; --ip skips this
entirely if you'd rather not make that request, or already know the address.

READ THIS BEFORE TRUSTING A RESULT: probing your own public IP from inside
your own LAN is not a reliable substitute for a real external scan. Most
home routers implement "NAT loopback"/"hairpin NAT" inconsistently:
    - Some routers silently drop this traffic entirely, so a genuinely
      OPEN port reports as unreachable here - a false "closed".
    - Some routers loop the connection back to a LAN device without ever
      routing it out to the internet and back, so a "reachable" result
      here doesn't prove an actual outside host could reach it either -
      a false "open".
A CLOSED result here is therefore never proof of safety, and an OPEN
result is never definitive proof of exposure - both need confirming from
a real external vantage point (a VPS, a friend's network, a phone on
cellular data with Wi-Fi off, or a third-party online port-checking site
you choose and visit yourself) before you act on it either way. This tool
is a cheap first pass, not the final word.

Usage:
    python exposure_check.py                        # RISKY_PORTS, auto-detected public IP
    python exposure_check.py --ports 22,80,443,8080
    python exposure_check.py --ip 203.0.113.5 --ports 22
    python exposure_check.py --output exposure.json
    python exposure_check.py --no-color
"""

import argparse
import csv
import json
import os
import socket
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Sequence, TypedDict

# Duplicated from network_scanner.py/mobile_network_scanner.py rather than
# imported - see this project's README for why each script here is meant
# to stay independently self-contained. Reusing the same list (rather than
# defining a separate one) means "is this risky port also exposed to the
# internet" is asking about literally the same ports the LAN-side check
# already flagged, not a second, differently-curated list.
RISKY_PORTS: Dict[int, str] = {
    21: "FTP transmits credentials in plaintext",
    23: "Telnet transmits everything, including credentials, in plaintext",
    445: "SMB is a common ransomware/worm vector when exposed beyond the LAN",
    3389: "RDP is frequently targeted by credential-stuffing and brute-force scans",
    5900: "VNC often runs with weak or no authentication by default",
}

_IP_ECHO_URL = "https://api.ipify.org"


class PortResult(TypedDict):
    port: int
    reachable: bool
    reason: str


def get_public_ip(timeout: float = 5.0) -> str:
    """Fetch this network's public/WAN IP address from an external echo service.

    Args:
        timeout: How long to wait for a response, in seconds.

    Returns:
        The public IPv4 address as a plain string (e.g. "203.0.113.5").

    Raises:
        RuntimeError: The request failed (no network, DNS failure, the
            service is down) or returned something that isn't a valid
            IPv4 address.
    """
    try:
        with urllib.request.urlopen(_IP_ECHO_URL, timeout=timeout) as response:
            body = response.read().decode("ascii", errors="replace").strip()
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RuntimeError(f"Couldn't determine your public IP via {_IP_ECHO_URL}: {exc}")

    try:
        socket.inet_aton(body)
    except OSError:
        raise RuntimeError(f"{_IP_ECHO_URL} returned something that isn't an IPv4 address: {body!r}")

    return body


def check_port(ip: str, port: int, timeout: float) -> bool:
    """Return True if a plain TCP connect to ip:port succeeds within timeout."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_exposure(ip: str, ports: Sequence[int], timeout: float, max_workers: int = 16) -> List[PortResult]:
    """Probe every port in ports against ip, concurrently.

    Args:
        ip: The address to probe (typically your own public IP - see
            get_public_ip() - though any address works).
        ports: TCP ports to check.
        timeout: Per-port connection timeout, in seconds.
        max_workers: How many ports to probe at once.

    Returns:
        One PortResult per port, in the same order as ports, each noting
        why it's flagged (from RISKY_PORTS) or "" if the port isn't one of
        the named risky ones (e.g. a custom --ports value).
    """
    ports = list(ports)
    reachable_by_port: Dict[int, bool] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(ports) or 1))) as executor:
        futures = {executor.submit(check_port, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            reachable_by_port[port] = future.result()

    return [
        {"port": port, "reachable": reachable_by_port[port], "reason": RISKY_PORTS.get(port, "")}
        for port in ports
    ]


# --- Colorized terminal output (plain ANSI codes, no dependency) ---

_ANSI_CODES: Dict[str, str] = {
    "red": "\033[31m",
    "green": "\033[32m",
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

def export_results(ip: str, results: List[PortResult], path: Path) -> None:
    """Save results to path as JSON or CSV, chosen by its extension."""
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "port", "reachable", "reason"])
            writer.writeheader()
            for result in results:
                writer.writerow({"ip": ip, **result})
    else:
        path.write_text(json.dumps({"ip": ip, "results": results}, indent=2), encoding="utf-8")


_CAVEAT = (
    "Note: a CLOSED result here is not proof a port is safe, and an OPEN\n"
    "result is not definitive proof of exposure - many home routers handle\n"
    "this kind of self-probe (NAT loopback/hairpinning) inconsistently.\n"
    "Confirm from a real external vantage point before acting on this alone."
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--ip", type=str, default=None,
        help="Check this IP instead of auto-detecting your public IP via api.ipify.org",
    )
    parser.add_argument(
        "--ports", type=str, default=None, metavar="LIST",
        help="Comma-separated TCP ports to check instead of RISKY_PORTS's default list",
    )
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-port connection timeout, in seconds (default: 3.0)")
    parser.add_argument("--output", type=str, default=None, metavar="FILE", help="Save results to FILE as JSON or CSV")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    color = _use_color(args.no_color)

    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        except ValueError:
            parser.error(f"--ports: not a comma-separated list of integers: {args.ports!r}")
    else:
        ports = sorted(RISKY_PORTS)

    if args.ip:
        ip = args.ip
    else:
        print(f"Determining your public IP via {_IP_ECHO_URL} ...")
        try:
            ip = get_public_ip(args.timeout)
        except RuntimeError as exc:
            print(f"Error: {exc}")
            raise SystemExit(1)

    print(f"Checking {len(ports)} port(s) on {ip} from the outside in ...")
    results = check_exposure(ip, ports, args.timeout)

    print(f"\n{'Port':<8}{'Reachable':<12}Reason")
    print("-" * 70)
    for result in results:
        reachable_display = "OPEN" if result["reachable"] else "closed"
        row = f"{result['port']:<8}{reachable_display:<12}{result['reason']}"
        if result["reachable"]:
            row = _colorize(row, "red", color)
        print(row)

    open_count = sum(1 for r in results if r["reachable"])
    if open_count:
        print(_colorize(f"\n{open_count} of {len(results)} port(s) answered from the outside.", "red", color))
    else:
        print(_colorize(f"\n0 of {len(results)} port(s) answered from the outside.", "green", color))

    print(f"\n{_colorize(_CAVEAT, 'dim', color)}")

    if args.output:
        export_results(ip, results, Path(args.output))
        print(f"\nWrote {len(results)} result(s) to {args.output}.")


if __name__ == "__main__":
    main()
