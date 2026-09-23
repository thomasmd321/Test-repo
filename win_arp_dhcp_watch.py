#!/usr/bin/env python3
"""Watch for ARP spoofing and a rogue DHCP server on Windows, using only
Windows' own `arp` and `ipconfig` commands - no scapy, no Npcap, no
administrator privileges.

arp_monitor.py (live ARP sniffing) and network_scanner.py's ARP scan both
need scapy plus raw-socket privileges - root/administrator, plus Npcap on
Windows specifically - to send or capture ARP packets directly. But
Windows already maintains its own ARP cache and DHCP lease records,
readable through two ordinary, unprivileged commands every Windows
install ships with: `arp -a` and `ipconfig /all`. This polls both
periodically instead of sniffing packets - trading "catches a change the
instant it happens" (arp_monitor.py's live capture) for "catches a change
within one poll interval, with zero setup burden" - a fair trade on a
locked-down/managed Windows machine where installing Npcap or getting
administrator rights isn't realistic.

Two independent checks, run every --interval seconds:

1. ARP cache diffing - the exact same signal arp_monitor.py's own
   process_arp_observation() detects (an IP answering from a MAC that
   isn't the one it answered from before), just sourced from `arp -a`
   snapshots instead of live sniffed packets. process_arp_observation()
   is duplicated verbatim from arp_monitor.py - same algorithm, same
   caveat: a MAC change is exactly as likely to be an ordinary DHCP
   lease reassignment as an actual attack, and a change already fully
   established before this started polling won't be caught (there's no
   "before" to compare against yet).

2. DHCP-server-per-adapter diffing - a different vantage point than
   dhcp_monitor.py's own passive sniffing (which watches OFFER/ACK
   broadcasts from any server on the wire, from any machine): this
   instead asks Windows itself, per network adapter, "which DHCP server
   did *you* actually get your own lease from" (parsed from
   `ipconfig /all`), and flags when that answer changes between polls.
   This machine's own DHCP server assignment suddenly changing is a
   strong signal on its own, independent of whether anything else on the
   network happened to notice a rogue server broadcasting.

Windows-only by design: `ipconfig /all`'s DHCP-lease fields have no
equivalent on Linux/macOS in this project - see wifi_scanner.py/
traceroute_mapper.py for the same kind of deliberate, stated platform
split elsewhere here. Running this on another OS prints a clear error
and exits rather than attempting a partial/wrong-format parse.

Usage:
    python win_arp_dhcp_watch.py
    python win_arp_dhcp_watch.py --interval 10 --log alerts.jsonl
    python win_arp_dhcp_watch.py --no-color

Known limitation, stated plainly: this project's own development sandbox
is Linux, with no real Windows machine to run this against - genuinely
untestable end to end the way most tools here manage. Every parsing/
diffing function (parse_arp_a_output(), parse_ipconfig_all(),
process_arp_observation(), find_dhcp_server_changes()) is unit-tested
against hand-built output matching each command's documented format, and
the full subprocess -> parse -> diff -> print pipeline was run for real
(platform.system() patched to report "Windows", with real fake arp/
ipconfig scripts on PATH so subprocess.run() genuinely executes something)
confirming two consecutive polls correctly detect both an ARP MAC change
and a DHCP server change - but the real arp.exe/ipconfig.exe on a real
Windows install, and their real output format, remain unverified. Treat a
first real run on Windows as the verification it hasn't had yet, and
please report back if a real install's output doesn't match what's
parsed here.
"""

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_MAC_PATTERN = re.compile(r"([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2}")
_IP_PATTERN = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")

# Windows' `ipconfig /all` right-aligns every label with an *alternating*
# run of spaces and dots before its colon
# ("DHCP Server . . . . . . . . . . . : 192.168.1.1") - a run that a
# naive \s*\.*\s* can't match (it only allows one block of whitespace
# then one block of dots, not space-dot-space-dot...), so this uses a
# single character class covering both instead of trying to separate them.
_IPCONFIG_FIELD_PATTERN = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 \-\(\)/]*?)[\s.]*:\s*(.*)$")


def _normalize_mac(mac: str) -> str:
    return mac.lower().replace("-", ":")


def parse_arp_a_output(output: str) -> Dict[str, str]:
    """Parse `arp -a`'s output into an IP -> normalized MAC dict.

    Windows formats a MAC with hyphens (aa-bb-cc-dd-ee-ff) rather than
    colons - network_scanner.py's own arp -a parser (read_arp_cache())
    already handles both forms with the same regex approach, duplicated
    here rather than imported, same self-contained convention as every
    other script in this project.

    Returns:
        Only lines with both an IP-shaped and a MAC-shaped token - a
        header row, a blank line, or an unresolved entry (Windows shows
        "<incomplete>" in place of a MAC) has no MAC match and is
        silently skipped rather than guessed at.
    """
    table: Dict[str, str] = {}
    for line in output.splitlines():
        ip_match = _IP_PATTERN.search(line)
        mac_match = _MAC_PATTERN.search(line)
        if ip_match and mac_match:
            table[ip_match.group(0)] = _normalize_mac(mac_match.group(0))
    return table


def get_arp_table(timeout: float = 5.0) -> Dict[str, str]:
    """Run `arp -a` and parse its output - reads the OS's already-populated ARP cache, no privileges needed.

    Raises:
        RuntimeError: `arp` isn't on PATH, or didn't respond in time.
    """
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("arp not found on PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"arp did not respond within {timeout:g}s")
    return parse_arp_a_output(result.stdout)


def process_arp_observation(ip: str, mac: str, seen: Dict[str, str]) -> Optional[Tuple[str, str]]:
    """Record one observed (ip, mac) pair and report a change, if this is one.

    Identical algorithm to arp_monitor.py's own process_arp_observation() -
    duplicated, not imported, same self-contained convention as
    everywhere else in this project. See its docstring for the full
    reasoning; the only difference here is where (ip, mac) pairs come
    from (a polled `arp -a` snapshot instead of a live sniffed packet).
    """
    previous_mac = seen.get(ip)
    seen[ip] = mac
    if previous_mac is not None and previous_mac != mac:
        return previous_mac, mac
    return None


def find_arp_changes(table: Dict[str, str], seen: Dict[str, str]) -> List[Tuple[str, str, str]]:
    """Diff one arp -a snapshot against the running seen state, in place.

    Args:
        table: This poll's IP -> MAC table, as returned by get_arp_table().
        seen: This session's running IP -> MAC state, updated in place.

    Returns:
        (ip, previous_mac, new_mac) for every IP whose MAC changed since
        the last poll - empty on the very first poll, since there's
        nothing yet to compare against (the same reasoning
        process_arp_observation()'s first-observation case documents).
    """
    changes: List[Tuple[str, str, str]] = []
    for ip, mac in table.items():
        result = process_arp_observation(ip, mac, seen)
        if result is not None:
            changes.append((ip, result[0], result[1]))
    return changes


def parse_ipconfig_all(output: str) -> Dict[str, Dict[str, Optional[str]]]:
    """Parse `ipconfig /all`'s output into a per-adapter dict of DHCP-relevant fields.

    Args:
        output: The raw stdout of `ipconfig /all`.

    Returns:
        {adapter_name: {"dhcp_enabled", "dhcp_server", "ipv4_address",
        "lease_obtained", "lease_expires"}}, each value a string or None
        if that field wasn't present for this adapter. An adapter with a
        static IP (DHCP disabled) still appears, with dhcp_server=None -
        that's the expected, unremarkable case, not a parsing failure.
        General fields before the first adapter header (under "Windows IP
        Configuration") are ignored - there's no adapter to attach them to.
    """
    adapters: Dict[str, Dict[str, Optional[str]]] = {}
    current: Optional[str] = None

    for raw_line in output.splitlines():
        if not raw_line.strip():
            continue
        # An adapter header is an unindented line ending in ":" - every
        # field line ("Label . . . : value"), by contrast, is indented.
        if not raw_line[:1].isspace() and raw_line.rstrip().endswith(":"):
            current = raw_line.rstrip().rstrip(":").strip()
            adapters[current] = {
                "dhcp_enabled": None, "dhcp_server": None,
                "ipv4_address": None, "lease_obtained": None, "lease_expires": None,
            }
            continue
        if current is None:
            continue
        match = _IPCONFIG_FIELD_PATTERN.match(raw_line)
        if not match:
            continue
        label = match.group(1).strip().lower()
        value = match.group(2).strip()
        if label == "dhcp enabled":
            adapters[current]["dhcp_enabled"] = value
        elif label == "dhcp server":
            adapters[current]["dhcp_server"] = value
        elif label in ("ipv4 address", "ip address"):
            adapters[current]["ipv4_address"] = value.split("(")[0].strip()
        elif label == "lease obtained":
            adapters[current]["lease_obtained"] = value
        elif label == "lease expires":
            adapters[current]["lease_expires"] = value

    return adapters


def get_ipconfig_all(timeout: float = 5.0) -> Dict[str, Dict[str, Optional[str]]]:
    """Run `ipconfig /all` and parse its output.

    Raises:
        RuntimeError: `ipconfig` isn't on PATH, or didn't respond in time.
    """
    try:
        result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError("ipconfig not found on PATH")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"ipconfig did not respond within {timeout:g}s")
    return parse_ipconfig_all(result.stdout)


def find_dhcp_server_changes(adapters: Dict[str, Dict[str, Optional[str]]], seen: Dict[str, str]) -> List[Tuple[str, str, str]]:
    """Diff each adapter's current DHCP server against the running seen state, in place.

    Args:
        adapters: This poll's per-adapter info, as returned by get_ipconfig_all().
        seen: This session's running adapter-name -> DHCP-server-IP state, updated in place.

    Returns:
        (adapter_name, previous_server, new_server) for every adapter
        whose DHCP server changed since the last poll. An adapter with no
        DHCP server recorded (a static IP) has nothing to compare and is
        skipped, the same reasoning find_arp_changes() applies to an ARP
        entry with no MAC.
    """
    changes: List[Tuple[str, str, str]] = []
    for adapter, info in adapters.items():
        server = info.get("dhcp_server")
        if not server:
            continue
        previous = seen.get(adapter)
        seen[adapter] = server
        if previous is not None and previous != server:
            changes.append((adapter, previous, server))
    return changes


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


def _append_log(path: Path, entry: dict) -> None:
    """Append one detected change to path as a JSON line - swallows a write failure, same as arp_monitor.py's/dhcp_monitor.py's own _append_log()."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--interval", type=float, default=30.0, help="Seconds between polls (default: 30.0)")
    parser.add_argument("--log", type=str, default=None, metavar="FILE", help="Append each detected change to FILE as one JSON line")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    if platform.system() != "Windows":
        print(
            "Error: this tool is Windows-only - it depends on `ipconfig /all`'s DHCP-lease "
            "fields, which have no equivalent on this platform. See arp_monitor.py and "
            "dhcp_monitor.py for cross-platform alternatives."
        )
        raise SystemExit(1)

    color = _use_color(args.no_color)
    arp_seen: Dict[str, str] = {}
    dhcp_seen: Dict[str, str] = {}
    first_poll = True

    print(f"Polling `arp -a` and `ipconfig /all` every {args.interval:g}s (Ctrl+C to stop) ...")
    try:
        while True:
            try:
                arp_table = get_arp_table()
                changes = find_arp_changes(arp_table, arp_seen)
                if first_poll:
                    print(f"Baseline ARP: {len(arp_table)} entr{'y' if len(arp_table) == 1 else 'ies'} recorded.")
                for ip, previous_mac, new_mac in changes:
                    timestamp = time.strftime("%H:%M:%S")
                    line = f"[{timestamp}] {ip} was {previous_mac}, now answering as {new_mac}"
                    print(_colorize(line, "magenta", color))
                    if args.log:
                        _append_log(Path(args.log), {
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": "arp",
                            "ip": ip, "previous_mac": previous_mac, "new_mac": new_mac,
                        })
            except RuntimeError as exc:
                print(f"Warning: arp poll failed ({exc})", file=sys.stderr)

            try:
                adapters = get_ipconfig_all()
                dhcp_changes = find_dhcp_server_changes(adapters, dhcp_seen)
                if first_poll:
                    print(f"Baseline DHCP servers: {dhcp_seen or '(none found)'}")
                for adapter, previous_server, new_server in dhcp_changes:
                    timestamp = time.strftime("%H:%M:%S")
                    line = f"[{timestamp}] {adapter}'s DHCP server changed: was {previous_server}, now {new_server}"
                    print(_colorize(line, "magenta", color))
                    if args.log:
                        _append_log(Path(args.log), {
                            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"), "kind": "dhcp",
                            "adapter": adapter, "previous_server": previous_server, "new_server": new_server,
                        })
            except RuntimeError as exc:
                print(f"Warning: ipconfig poll failed ({exc})", file=sys.stderr)

            first_poll = False
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
