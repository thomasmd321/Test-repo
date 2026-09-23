#!/usr/bin/env python3
"""Map the network path to a host, hop by hop, with per-hop round-trip time.

Complements exposure_check.py's "is this port reachable" and
wifi_scanner.py's "is my signal weak": neither tells you *where* along the
path a slow connection is actually slow. This does, by wrapping the OS's
own traceroute tool (there's no cross-platform way to do this without
either raw sockets and root/administrator everywhere, or shelling out - the
same tradeoff network_scanner.py's ping fallback already makes) and always
resolving each hop's hostname itself afterward via plain reverse DNS,
rather than depending on the traceroute binary's own often-inconsistent
DNS behavior across platforms.

Runs each platform's tool numeric-only (no built-in hostname resolution)
specifically to sidestep the biggest source of cross-platform output
differences: `traceroute -n` on Linux/macOS, `tracert -d` on Windows.
    - Linux/macOS: `traceroute -n -w TIMEOUT -m MAX_HOPS TARGET`
    - Windows: `tracert -d -h MAX_HOPS -w TIMEOUT_MS TARGET`

Usage:
    python traceroute_mapper.py 8.8.8.8
    python traceroute_mapper.py google.com --max-hops 20
    python traceroute_mapper.py 192.168.1.1 --no-resolve-hostnames
    python traceroute_mapper.py 8.8.8.8 --output path.json
    python traceroute_mapper.py 8.8.8.8 --no-color

Known limitation, stated plainly: this project's own development
environment has no `traceroute`/`tracert` binary installed at all (and,
per its own outbound network policy, may not be able to send the raw
ICMP/UDP probes either even if it did) - so every platform's parser here
is verified only against mocked command output matching each tool's
documented format (see test_traceroute_mapper.py), never against a real
path on real hardware, on any of the three platforms. Traceroute output
in particular varies more between tool versions/distros than most CLI
formats this project parses elsewhere - treat a first real run on any
platform as the verification it hasn't had yet, and please report back
(or send a patch) if your traceroute/tracert's real output doesn't match
what's parsed here.
"""

import argparse
import csv
import json
import os
import platform
import re
import socket
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, TypedDict


class Hop(TypedDict):
    hop: int
    ip: Optional[str]
    hostname: str
    rtts_ms: List[Optional[float]]


_HOP_LINE = re.compile(r"^\s*(\d+)\s+(.*)$")
_IP_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _parse_unix_traceroute(output: str) -> List[Hop]:
    """Parse `traceroute -n`'s numeric-only output (GNU/inetutils and BSD/macOS agree on this format).

    A normal hop line looks like:
        1  192.168.1.1  0.489 ms  0.410 ms  0.375 ms
    A fully-timed-out hop looks like:
        4  * * *
    and a partially-timed-out one mixes both:
        3  10.0.0.1  5.123 ms  * 5.045 ms
    """
    hops: List[Hop] = []
    for line in output.splitlines():
        match = _HOP_LINE.match(line)
        if not match:
            continue
        hop_num = int(match.group(1))
        rest = match.group(2).split()
        if not rest:
            continue

        if rest[0] == "*":
            hops.append({"hop": hop_num, "ip": None, "hostname": "", "rtts_ms": [None, None, None]})
            continue

        ip = rest[0] if _IP_PATTERN.match(rest[0]) else None
        rtts: List[Optional[float]] = []
        i = 1
        while i < len(rest) and len(rtts) < 3:
            token = rest[i]
            if token == "*":
                rtts.append(None)
                i += 1
                continue
            try:
                rtts.append(float(token))
            except ValueError:
                i += 1
                continue
            i += 1
            if i < len(rest) and rest[i] == "ms":
                i += 1

        hops.append({"hop": hop_num, "ip": ip, "hostname": "", "rtts_ms": rtts})

    return hops


def _run_unix_traceroute(target: str, max_hops: int, timeout: float) -> List[Hop]:
    try:
        result = subprocess.run(
            ["traceroute", "-n", "-w", str(timeout), "-m", str(max_hops), target],
            capture_output=True, text=True, timeout=timeout * max_hops + 10,
        )
    except FileNotFoundError:
        raise RuntimeError("traceroute not found - install it via your package manager (e.g. `apt install traceroute`)")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"traceroute did not finish within its overall time budget ({timeout * max_hops + 10:g}s)")
    return _parse_unix_traceroute(result.stdout)


def _parse_windows_tracert(output: str) -> List[Hop]:
    """Parse `tracert -d`'s numeric-only output.

    A normal hop line looks like:
        1     1 ms     1 ms     1 ms  192.168.1.1
    A fully-timed-out hop looks like:
        2     *        *        *     Request timed out.
    """
    hops: List[Hop] = []
    for line in output.splitlines():
        match = _HOP_LINE.match(line)
        if not match:
            continue
        hop_num = int(match.group(1))
        rest = match.group(2).split()
        if not rest:
            continue

        rtts: List[Optional[float]] = []
        i = 0
        while i < len(rest) and len(rtts) < 3:
            token = rest[i]
            if token == "*":
                rtts.append(None)
                i += 1
                continue
            try:
                rtts.append(float(token))
            except ValueError:
                break
            i += 1
            if i < len(rest) and rest[i] == "ms":
                i += 1

        remainder = " ".join(rest[i:]).strip()
        ip = None if (not remainder or remainder.startswith("Request timed out")) else remainder

        hops.append({"hop": hop_num, "ip": ip, "hostname": "", "rtts_ms": rtts})

    return hops


def _run_windows_tracert(target: str, max_hops: int, timeout: float) -> List[Hop]:
    try:
        result = subprocess.run(
            ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), target],
            capture_output=True, text=True, timeout=timeout * max_hops + 10,
        )
    except FileNotFoundError:
        raise RuntimeError("tracert not found")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"tracert did not finish within its overall time budget ({timeout * max_hops + 10:g}s)")
    return _parse_windows_tracert(result.stdout)


def _resolve_hop_hostname(ip: str, timeout: float) -> str:
    """Best-effort reverse DNS for one hop's IP - "" if it fails or times out."""
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(previous_timeout)


def traceroute(target: str, max_hops: int = 30, timeout: float = 2.0, resolve_hostnames: bool = True) -> List[Hop]:
    """Trace the path to target, dispatching to the right platform's tool.

    Args:
        target: Hostname or IP to trace to.
        max_hops: Give up after this many hops (the target may be closer
            or farther - this just bounds how long an unreachable target
            can run for).
        timeout: Per-probe wait time, in seconds, passed to the
            underlying tool.
        resolve_hostnames: Whether to reverse-resolve each hop's IP
            ourselves afterward (see this module's docstring for why this
            isn't left to the traceroute binary's own DNS handling).

    Returns:
        One Hop per line the tool reported, in hop order. A hop that
        timed out on every probe has ip=None and three None entries in
        rtts_ms rather than being omitted, so gaps in the path are still
        visible.

    Raises:
        RuntimeError: The required OS tool isn't installed, timed out, or
            this platform isn't one of the three supported.
    """
    system = platform.system()
    if system in ("Linux", "Darwin"):
        hops = _run_unix_traceroute(target, max_hops, timeout)
    elif system == "Windows":
        hops = _run_windows_tracert(target, max_hops, timeout)
    else:
        raise RuntimeError(f"Traceroute isn't supported on {system!r} (supported: Linux, macOS, Windows)")

    if resolve_hostnames:
        for hop in hops:
            if hop["ip"]:
                hop["hostname"] = _resolve_hop_hostname(hop["ip"], timeout=1.0)

    return hops


# --- Colorized terminal output (plain ANSI codes, no dependency) ---

_ANSI_CODES: Dict[str, str] = {
    "yellow": "\033[33m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

# A hop whose best RTT exceeds this is called out as slow - a loose,
# non-scientific threshold (like RISKY_PORTS elsewhere in this project),
# not a claim about what's actually "too slow" for any given use case.
_SLOW_HOP_MS = 100.0


def _use_color(no_color_flag: bool) -> bool:
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{_ANSI_CODES[color]}{text}{_ANSI_CODES['reset']}"


# --- Exporting results ---

def export_results(hops: List[Hop], path: Path) -> None:
    """Save hops to path as JSON or CSV, chosen by its extension."""
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["hop", "ip", "hostname", "rtt1_ms", "rtt2_ms", "rtt3_ms"])
            for hop in hops:
                rtts = (hop["rtts_ms"] + [None, None, None])[:3]
                writer.writerow([hop["hop"], hop["ip"] or "", hop["hostname"], *rtts])
    else:
        path.write_text(json.dumps(hops, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="Hostname or IP to trace the path to")
    parser.add_argument("--max-hops", type=int, default=30, help="Give up after this many hops (default: 30)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Per-probe wait time, in seconds (default: 2.0)")
    parser.add_argument(
        "--no-resolve-hostnames", action="store_true",
        help="Skip reverse-DNS lookup for each hop's IP (faster, especially on a path with many timed-out hops)",
    )
    parser.add_argument("--output", type=str, default=None, metavar="FILE", help="Save results to FILE as JSON or CSV")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    color = _use_color(args.no_color)

    print(f"Tracing route to {args.target} (max {args.max_hops} hops) ...")
    try:
        hops = traceroute(
            args.target, max_hops=args.max_hops, timeout=args.timeout,
            resolve_hostnames=not args.no_resolve_hostnames,
        )
    except RuntimeError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)

    if not hops:
        print("No hops reported.")
        return

    print(f"\n{'Hop':<5}{'IP':<18}{'RTT (ms)':<24}Hostname")
    print("-" * 80)
    for hop in hops:
        ip_display = hop["ip"] or "*"
        rtt_display = "  ".join("*" if r is None else f"{r:g}" for r in hop["rtts_ms"])
        row = f"{hop['hop']:<5}{ip_display:<18}{rtt_display:<24}{hop['hostname']}"
        best_rtt = min((r for r in hop["rtts_ms"] if r is not None), default=None)
        if hop["ip"] is None:
            row = _colorize(row, "dim", color)
        elif best_rtt is not None and best_rtt >= _SLOW_HOP_MS:
            row = _colorize(row, "yellow", color)
        print(row)

    if args.output:
        export_results(hops, Path(args.output))
        print(f"\nWrote {len(hops)} hop(s) to {args.output}.")


if __name__ == "__main__":
    main()
