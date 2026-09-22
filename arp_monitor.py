#!/usr/bin/env python3
"""Passively watch ARP traffic and flag a MAC address change for any IP.

network_scanner.py's IP-conflict alert (see its own module comment) only
samples at scan time - a full scan every few minutes at best under
--watch - so a live man-in-the-middle attack (ARP spoofing) happening
*between* scans can go completely unnoticed until the next one, if ever.
This watches continuously instead: every ARP reply/announcement on the
wire is observed as it happens, and any IP whose MAC changes mid-session
is flagged immediately - the same underlying signal the IP-conflict
alert uses (an IP now answering from a MAC that isn't the one that
answered before), just detected passively and in real time rather than
by diffing two periodic snapshots.

This is a hygiene/detection aid, not a full intrusion-detection system:
it only flags a *change*, so it can't catch spoofing already fully
established before this started watching (there's no "before" to compare
against yet), and a change here is exactly as likely to be an ordinary
DHCP lease reassignment as an actual attack - see network_scanner.py's
own IP-conflict alert for the identical caveat. A change on your router/
gateway's own IP is the one case worth treating as urgent.

Needs scapy and the same raw-socket privileges (root/administrator) as
network_scanner.py's ARP scan - there's no way to passively observe
ARP traffic without them on any platform this targets.

Usage:
    python arp_monitor.py                     # watch the default interface
    python arp_monitor.py --interface eth0
    python arp_monitor.py --log conflicts.jsonl
    python arp_monitor.py --no-color

Known limitation, stated plainly: this project's own development
environment has a broken scapy/cryptography install (see --doctor in
network_scanner.py for the exact failure) and no raw-socket privileges
either, so the actual packet-sniffing path here - monitor() itself - has
never run for real in this session. The pure detection logic it calls
(process_arp_observation()) is fully unit-tested and needs nothing from
scapy at all (see test_arp_monitor.py), but the sniff() wiring around it
is unverified against real ARP traffic on real hardware.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple


def process_arp_observation(ip: str, mac: str, seen: Dict[str, str]) -> Optional[Tuple[str, str]]:
    """Record one observed (ip, mac) pair and report a change, if this is one.

    Kept as a pure function, independent of scapy's own packet objects or
    the sniffing loop around it, specifically so the actual detection
    logic can be unit-tested without needing scapy (or root) at all - the
    same reasoning network_scanner.py's _find_ip_conflicts() already
    documents for its own MAC-comparison logic.

    Args:
        ip: The sender IP from an observed ARP reply/announcement.
        mac: The sender MAC from that same packet.
        seen: This session's IP -> last-seen-MAC map, updated in place.

    Returns:
        (previous_mac, new_mac) if ip was already associated with a
        *different* MAC than before, or None if this is the first time
        ip has been seen this session, or its MAC hasn't changed.
    """
    previous_mac = seen.get(ip)
    seen[ip] = mac
    if previous_mac is not None and previous_mac != mac:
        return previous_mac, mac
    return None


def monitor(
    on_conflict: Callable[[str, str, str], None],
    interface: Optional[str] = None,
    seen: Optional[Dict[str, str]] = None,
) -> None:
    """Sniff ARP replies/announcements indefinitely, calling on_conflict for each MAC change.

    Args:
        on_conflict: Called as on_conflict(ip, previous_mac, new_mac) for
            every detected change, in the order observed.
        interface: Network interface to listen on, or None for scapy's
            own default.
        seen: An existing IP->MAC map to start from (e.g. one seeded from
            network_scanner.py's own known-devices registry), or None to
            start empty. Updated in place as packets arrive.

    Raises:
        ImportError: scapy isn't installed.
        PermissionError / OSError: this process lacks the raw-socket
            privileges ARP sniffing needs (typically root/administrator).

    This call never returns on its own - it sniffs until interrupted
    (Ctrl+C), same as network_scanner.py/mobile_network_scanner.py's
    --watch mode.
    """
    # Imported lazily, not at module load time, so this module can still
    # be imported (and process_arp_observation() used/tested) on a
    # machine without scapy installed at all - the same reasoning
    # network_scanner.py's arp_scan() already documents for its own
    # lazy scapy import.
    from scapy.all import ARP, sniff

    if seen is None:
        seen = {}

    def _handle_packet(packet) -> None:
        if not packet.haslayer(ARP) or packet[ARP].op != 2:  # op 2 == "is-at" (a reply or announcement)
            return
        result = process_arp_observation(packet[ARP].psrc, packet[ARP].hwsrc, seen)
        if result is not None:
            previous_mac, new_mac = result
            on_conflict(packet[ARP].psrc, previous_mac, new_mac)

    sniff(filter="arp", prn=_handle_packet, store=False, iface=interface)


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


def _append_log(path: Path, ip: str, previous_mac: str, new_mac: str) -> None:
    """Append one detected conflict to path as a JSON line - swallows a write failure, same as append_scan_history()."""
    entry = json.dumps({
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "ip": ip, "previous_mac": previous_mac, "new_mac": new_mac,
    })
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except OSError:
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--interface", type=str, default=None, help="Network interface to listen on (default: scapy's own default)")
    parser.add_argument("--log", type=str, default=None, metavar="FILE", help="Append each detected change to FILE as one JSON line")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    color = _use_color(args.no_color)

    def on_conflict(ip: str, previous_mac: str, new_mac: str) -> None:
        timestamp = time.strftime("%H:%M:%S")
        line = f"[{timestamp}] {ip} was {previous_mac}, now answering as {new_mac}"
        print(_colorize(line, "magenta", color))
        if args.log:
            _append_log(Path(args.log), ip, previous_mac, new_mac)

    print(f"Watching for ARP MAC changes on {args.interface or 'the default interface'} (Ctrl+C to stop) ...")
    try:
        monitor(on_conflict, interface=args.interface)
    except KeyboardInterrupt:
        print("\nStopped.")
    except (PermissionError, OSError) as exc:
        print(f"Error: couldn't start sniffing ({exc}) - this usually needs root/administrator privileges")
        raise SystemExit(1)
    except BaseException as exc:
        # Broader than "except ImportError" alone: a broken scapy/
        # cryptography install (this project's own development sandbox
        # included) can raise pyo3_runtime.PanicException on import,
        # which subclasses BaseException directly rather than Exception -
        # the exact surprise network_scanner.py's own --doctor scapy
        # check already hit and fixed for the identical reason (see its
        # module comment). This is main()'s last line of defense, so the
        # same broad catch is justified here too.
        print(f"Error: couldn't load scapy ({exc}) - install/repair it with `pip install --force-reinstall scapy cryptography`")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
