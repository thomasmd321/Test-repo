#!/usr/bin/env python3
"""List nearby Wi-Fi networks: SSID, channel, signal, and security.

Complements network_scanner.py/mobile_network_scanner.py rather than
overlapping with them: those two find *devices already on your network*;
this finds *networks in radio range*, including ones you're not connected
to. "Why does my network feel slow" is often channel congestion from a
neighbor's network on the same channel, or a weak signal, neither of which
device discovery can see at all - this is a different, complementary
question.

Shells out to the OS's own Wi-Fi tooling rather than using a raw 802.11
library (no cross-platform one ships in the standard library, and the
alternative - a packet-capture-based scanner - needs monitor mode and
root/administrator on every platform, a much higher bar than this needs):
    - Linux: `nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi list`
      (NetworkManager's own CLI; nmcli's terse `-t` output escapes literal
      colons within a field, e.g. inside a BSSID, with a backslash - see
      _parse_nmcli_line()).
    - macOS: the `airport` command-line tool (Apple marked it "deprecated"
      years ago but it's still present and functional as of this writing;
      see _AIRPORT_PATH). Its columnar text output doesn't reliably
      delimit the SSID column when a name has spaces, so parsing locates
      the BSSID (a MAC address) as an anchor and splits around it instead
      - see _parse_airport_line().
    - Windows: `netsh wlan show networks mode=bssid` (a stable, long
      documented format: indented "SSID N :"/"Authentication :" blocks,
      each followed by one or more "BSSID N :" sub-blocks with their own
      Signal/Channel lines).

Signal strength is reported in whatever unit each platform's own tool
uses - a percentage on Linux/Windows, dBm (RSSI) on macOS - and is kept
as-is (e.g. "78%", "-55 dBm") rather than converted between them: dBm and
"percent" don't have one true conversion (it's vendor/driver-specific), so
pretending to unify them would be less honest than just labeling each.

Usage:
    python wifi_scanner.py
    python wifi_scanner.py --timeout 15
    python wifi_scanner.py --output networks.json
    python wifi_scanner.py --no-color

Known limitation, stated plainly: this sandbox has none of nmcli, airport,
or netsh installed, and no Wi-Fi hardware to scan with even if it did - so
every platform's parser here is verified only against mocked subprocess
output matching each tool's documented format (see test_wifi_scanner.py),
never against a real device on real hardware. Treat a first run on any
platform as the actual verification it hasn't had yet, and please report
back (or send a patch) if a given OS/tool version's real output doesn't
match what's parsed here.
"""

import argparse
import csv
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, TypedDict


class Network(TypedDict):
    ssid: str
    bssid: str
    channel: Optional[int]
    signal: str
    security: str


_MAC_PATTERN = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

# Still present and functional on current macOS despite Apple's
# deprecation notice - see this module's docstring. If a future macOS
# removes it outright, _scan_macos() raises a clear RuntimeError rather
# than a raw FileNotFoundError traceback.
_AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"


def _parse_nmcli_line(line: str) -> List[str]:
    """Split one line of `nmcli -t` terse output on unescaped colons.

    nmcli's terse mode escapes a literal colon or backslash *within* a
    field's own value (most importantly a BSSID's colons) with a leading
    backslash, precisely so a naive line.split(":") wouldn't misparse a
    BSSID as several extra fields. This undoes that escaping while
    splitting correctly, rather than assuming fields never contain a colon.
    """
    fields = []
    current = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def _scan_linux(timeout: float) -> List[Network]:
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY", "dev", "wifi", "list"],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("nmcli not found - install NetworkManager, or scan manually with `iwlist <iface> scan`")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nmcli did not respond within {timeout:g}s")

    if result.returncode != 0:
        raise RuntimeError(f"nmcli failed: {result.stderr.strip() or 'unknown error'}")

    networks: List[Network] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        fields = _parse_nmcli_line(line)
        if len(fields) < 5:
            continue
        ssid, bssid, channel, signal, security = fields[:5]
        networks.append({
            "ssid": ssid or "(hidden)",
            "bssid": bssid,
            "channel": int(channel) if channel.isdigit() else None,
            "signal": f"{signal}%" if signal else "",
            "security": security or "Open",
        })
    return networks


def _parse_airport_line(line: str) -> Optional[Network]:
    """Parse one data row of `airport -s`'s columnar output.

    The SSID column has no reliable delimiter of its own when a network
    name contains spaces (a real, common case), so this locates the BSSID
    - a MAC address, and the one column guaranteed to match a fixed
    pattern - as an anchor: everything before it is the SSID, everything
    after is positional (RSSI, CHANNEL, HT, CC, SECURITY...).

    Returns:
        A Network, or None if this line has no MAC-shaped token at all
        (e.g. the header row).
    """
    tokens = line.split()
    mac_index = next((i for i, token in enumerate(tokens) if _MAC_PATTERN.match(token)), None)
    if mac_index is None:
        return None

    ssid = " ".join(tokens[:mac_index]) or "(hidden)"
    bssid = tokens[mac_index]
    rest = tokens[mac_index + 1:]
    rssi = rest[0] if len(rest) > 0 else ""
    channel = rest[1] if len(rest) > 1 else ""
    # rest[2] is HT (Y/N), rest[3] is the two-letter country code - neither
    # is worth a column of its own here; SECURITY is whatever's left.
    security = " ".join(rest[4:]) if len(rest) > 4 else ""

    return {
        "ssid": ssid,
        "bssid": bssid,
        "channel": int(channel) if channel.lstrip("-").isdigit() else None,
        "signal": f"{rssi} dBm" if rssi else "",
        "security": security or "Open",
    }


def _scan_macos(timeout: float) -> List[Network]:
    try:
        result = subprocess.run([_AIRPORT_PATH, "-s"], capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        raise RuntimeError(f"airport not found at {_AIRPORT_PATH} - Apple may have removed it in this macOS version")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"airport did not respond within {timeout:g}s")

    lines = result.stdout.splitlines()
    networks: List[Network] = []
    for line in lines[1:]:  # First line is the column header.
        network = _parse_airport_line(line)
        if network is not None:
            networks.append(network)
    return networks


def _scan_windows(timeout: float) -> List[Network]:
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        raise RuntimeError("netsh not found")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"netsh did not respond within {timeout:g}s")

    networks: List[Network] = []
    current_ssid = ""
    current_security = ""
    current: Optional[Network] = None

    for raw_line in result.stdout.splitlines():
        line = raw_line.strip()
        if line.startswith("SSID ") and ":" in line:
            current_ssid = line.split(":", 1)[1].strip() or "(hidden)"
        elif line.startswith("Authentication") and ":" in line:
            current_security = line.split(":", 1)[1].strip()
        elif line.startswith("BSSID") and ":" in line:
            if current is not None:
                networks.append(current)
            bssid = line.split(":", 1)[1].strip()
            current = {
                "ssid": current_ssid, "bssid": bssid, "channel": None,
                "signal": "", "security": current_security or "Open",
            }
        elif line.startswith("Signal") and ":" in line and current is not None:
            current["signal"] = line.split(":", 1)[1].strip()
        elif line.startswith("Channel") and ":" in line and current is not None:
            channel = line.split(":", 1)[1].strip()
            current["channel"] = int(channel) if channel.isdigit() else None

    if current is not None:
        networks.append(current)
    return networks


def scan_wifi_networks(timeout: float = 10.0) -> List[Network]:
    """Scan for nearby Wi-Fi networks, dispatching by platform.

    Args:
        timeout: How long to let the underlying OS command run, in
            seconds, before giving up on it.

    Returns:
        Every network the OS's own tool reported, in whatever order it
        gave them (each platform already sorts its own output; imposing
        a different order here would just contradict what a native tool
        on that OS shows).

    Raises:
        RuntimeError: The required OS tool isn't installed, timed out, or
            this platform isn't one of the three supported (see this
            module's docstring for exactly which command runs where).
    """
    system = platform.system()
    if system == "Linux":
        return _scan_linux(timeout)
    if system == "Darwin":
        return _scan_macos(timeout)
    if system == "Windows":
        return _scan_windows(timeout)
    raise RuntimeError(f"Wi-Fi scanning isn't supported on {system!r} (supported: Linux, macOS, Windows)")


# --- Colorized terminal output (plain ANSI codes, no dependency) ---

_ANSI_CODES: Dict[str, str] = {
    "yellow": "\033[33m",
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

def export_results(networks: List[Network], path: Path) -> None:
    """Save networks to path as JSON or CSV, chosen by its extension."""
    if path.suffix.lower() == ".csv":
        with path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ssid", "bssid", "channel", "signal", "security"])
            writer.writeheader()
            writer.writerows(networks)
    else:
        path.write_text(json.dumps(networks, indent=2), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--timeout", type=float, default=10.0, help="How long to wait for the OS scan command, in seconds (default: 10.0)")
    parser.add_argument("--output", type=str, default=None, metavar="FILE", help="Save results to FILE as JSON or CSV")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    color = _use_color(args.no_color)

    print("Scanning for nearby Wi-Fi networks ...")
    try:
        networks = scan_wifi_networks(args.timeout)
    except RuntimeError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)

    if not networks:
        print("No networks found.")
        return

    networks = sorted(networks, key=lambda n: n["ssid"].lower())

    print(f"\n{'SSID':<32}{'BSSID':<20}{'Chan':<6}{'Signal':<10}Security")
    print("-" * 90)
    for network in networks:
        channel_display = str(network["channel"]) if network["channel"] is not None else "-"
        row = f"{network['ssid']:<32}{network['bssid']:<20}{channel_display:<6}{network['signal']:<10}{network['security']}"
        if network["security"].lower() in ("open", "none", "--"):
            row = _colorize(row, "yellow", color)
        print(row)

    open_count = sum(1 for n in networks if n["security"].lower() in ("open", "none", "--"))
    print(f"\n{len(networks)} network(s) found.", end="")
    if open_count:
        print(_colorize(f" {open_count} open/unencrypted.", "yellow", color))
    else:
        print()

    if args.output:
        export_results(networks, Path(args.output))
        print(f"\nWrote {len(networks)} network(s) to {args.output}.")


if __name__ == "__main__":
    main()
