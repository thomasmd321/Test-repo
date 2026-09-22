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

Also compares each scan against a small local registry of previously seen
networks (~/.cache/wifi_scanner_known_networks.json, the same
persisted-between-runs spirit as network_scanner.py's known-devices
registry) to flag two evil-twin/rogue-AP patterns: a familiar SSID
suddenly answering with *weaker* security than it's ever shown before (a
classic downgrade attack - a legitimate AP doesn't just drop encryption on
its own), and a familiar SSID answering from a BSSID never seen before
(a softer signal - could be a genuinely new/roaming AP on a mesh or
enterprise network with many legitimate access points sharing one SSID,
so this is flagged for a second look, not treated as proof). See
_find_evil_twin_candidates(). --no-evil-twin-check skips this entirely;
--forget-known-networks clears the registry. The evil-twin logic itself
is unit-tested with plain dicts (no subprocess/hardware involved at all),
and was also run for real end-to-end against a fake nmcli script on PATH:
a baseline WPA2 scan, an unchanged repeat (correctly silent), then a
simulated downgrade to Open on the same BSSID (correctly flagged) and a
new BSSID appearing under the same SSID (also correctly flagged, as
"new_bssid" rather than "security_downgrade" once security itself hadn't
weakened) - the full scan -> compare -> update-registry -> persist
pipeline, exercised for real.
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


# --- Evil-twin / rogue-AP detection, via a small local known-networks registry ---

_KNOWN_NETWORKS_PATH = Path.home() / ".cache" / "wifi_scanner_known_networks.json"


def _security_rank(security: str) -> int:
    """Rank a security string by strength, for detecting a downgrade.

    Real tool output varies a lot across platforms/versions - nmcli might
    say "WPA2 802.1X", airport "WPA2(PSK/AES/AES)", netsh
    "WPA2-Personal" - so this matches by substring, checked strongest
    first, rather than expecting an exact vocabulary. Anything unrecognized
    (including a genuinely open network) ranks lowest.
    """
    s = (security or "").lower()
    if "wpa3" in s:
        return 4
    if "wpa2" in s:
        return 3
    if "wpa" in s:
        return 2
    if "wep" in s:
        return 1
    return 0


def _load_known_networks(path: Path) -> Dict[str, dict]:
    """Load the known-networks registry from disk - {} if it doesn't exist yet or is unreadable/corrupt."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _save_known_networks(known: Dict[str, dict], path: Path) -> None:
    """Persist the known-networks registry - a failed write deliberately doesn't raise, same as network_scanner.py's _save_known_devices()."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(known, indent=2, sort_keys=True), encoding="utf-8")
    except OSError:
        pass


def _find_evil_twin_candidates(networks: List[Network], known: Dict[str, dict]) -> List[Dict[str, str]]:
    """Compare this scan's networks against the known-networks registry, before it's updated.

    Must run before _update_known_networks() overwrites the registry's
    per-SSID best-security-seen and BSSID list - the same before/after
    ordering network_scanner.py's _find_port_changes() needs relative to
    _mark_new_devices(), for the identical reason.

    Args:
        networks: This scan's results.
        known: The known-networks registry, as loaded by
            _load_known_networks() - read only, not mutated here.

    Returns:
        One dict per flagged network: {"ssid", "bssid", "kind" ("security_downgrade"
        or "new_bssid"), "detail"}. An SSID seen for the very first time
        this session produces nothing here - there's no "before" yet to
        compare against, the same reasoning arp_monitor.py's
        process_arp_observation() documents for a first-ever observation.
    """
    candidates: List[Dict[str, str]] = []
    for network in networks:
        ssid = network["ssid"]
        entry = known.get(ssid)
        if entry is None:
            continue

        current_rank = _security_rank(network["security"])
        best_known_rank = entry.get("best_security_rank", 0)
        if current_rank < best_known_rank:
            candidates.append({
                "ssid": ssid, "bssid": network["bssid"], "kind": "security_downgrade",
                "detail": (
                    f"{ssid} previously showed stronger security ({entry.get('best_security') or 'Open'}) "
                    f"but is now answering as {network['security'] or 'Open'} from {network['bssid']} - "
                    "a classic evil-twin/downgrade pattern"
                ),
            })
        elif network["bssid"] not in entry.get("bssids", []):
            candidates.append({
                "ssid": ssid, "bssid": network["bssid"], "kind": "new_bssid",
                "detail": (
                    f"{ssid} is answering from a new access point ({network['bssid']}) not seen before - "
                    "could be a legitimate new/roaming AP on a mesh network, or worth a second look"
                ),
            })
    return candidates


def _update_known_networks(networks: List[Network], known: Dict[str, dict]) -> None:
    """Record this scan's networks into the known-networks registry, in place.

    For each SSID: remembers every distinct BSSID ever seen for it, and
    the strongest security level ever seen (never *downgrades* what's
    remembered just because one scan happened to see a weaker level - the
    whole point is to keep the high-water mark to compare future scans
    against).
    """
    for network in networks:
        ssid = network["ssid"]
        rank = _security_rank(network["security"])
        entry = known.setdefault(ssid, {"bssids": [], "best_security": network["security"], "best_security_rank": rank})
        if network["bssid"] not in entry["bssids"]:
            entry["bssids"].append(network["bssid"])
        if rank > entry.get("best_security_rank", 0):
            entry["best_security_rank"] = rank
            entry["best_security"] = network["security"]


# --- Colorized terminal output (plain ANSI codes, no dependency) ---

_ANSI_CODES: Dict[str, str] = {
    "yellow": "\033[33m",
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
    parser.add_argument("--no-evil-twin-check", action="store_true", help="Skip comparing against previously seen SSIDs/security (see the known-networks registry)")
    parser.add_argument("--forget-known-networks", action="store_true", help="Clear the known-networks registry used for evil-twin detection")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    color = _use_color(args.no_color)

    if args.forget_known_networks:
        _save_known_networks({}, _KNOWN_NETWORKS_PATH)
        print(f"Cleared {_KNOWN_NETWORKS_PATH}.")

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

    if not args.no_evil_twin_check:
        known = _load_known_networks(_KNOWN_NETWORKS_PATH)
        candidates = _find_evil_twin_candidates(networks, known)
        for candidate in candidates:
            print(_colorize(f"\n⚠ {candidate['detail']}", "magenta", color))
        _update_known_networks(networks, known)
        _save_known_networks(known, _KNOWN_NETWORKS_PATH)

    if args.output:
        export_results(networks, Path(args.output))
        print(f"\nWrote {len(networks)} network(s) to {args.output}.")


if __name__ == "__main__":
    main()
