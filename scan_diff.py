#!/usr/bin/env python3
"""Compare two saved scans and report what changed between them.

network_scanner.py and mobile_network_scanner.py can each save a scan's
results to a file with --output (see export_results() in either one) -
this script takes two of those files and reports which devices were
added, which disappeared, and which changed (a different port, a new
banner, a changed hostname, etc.), the same way the scanners' own
NEW/CHG/missing markers work against the known-devices registry, just
applied to two snapshots on disk instead of "registry vs. this scan".

The two files don't need to come from the same script, or even use the
same format - JSON and CSV (whichever --output produced) both work, and
either side can be either format. Fields the two scripts don't share
(mac/vendor are desktop-only, banner is mobile-only) are compared too,
whenever both files happen to have them, without either script needing
to know about the other's schema.

A device is matched across the two files by MAC address if it has one
(surviving a DHCP lease change), falling back to IP otherwise - the same
identity rule network_scanner.py's own known-devices tracking uses (see
its _device_identity()). mobile_network_scanner.py's exports have no MAC
at all, so its devices are always matched by IP, with the same caveat
its own registry has: a changed IP looks like two different devices.

Usage:
    python scan_diff.py old.json new.json
    python scan_diff.py before.csv after.csv
    python scan_diff.py --no-color old.json new.json
"""

import argparse
import csv
import json
import os
import sys
from pathlib import Path
from typing import Dict, List


def _load_json(path: Path) -> List[dict]:
    """Load a scan export previously written by export_results() as JSON."""
    return json.loads(path.read_text(encoding="utf-8"))


def _load_csv(path: Path) -> List[dict]:
    """Load a scan export previously written by export_results() as CSV.

    Every value comes back as a plain string (that's all a CSV cell can
    hold) - _normalize_device() below is what turns "8080" back into an
    int and "23;445" back into a list, the same shapes the JSON export
    already has natively.
    """
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def load_devices(path: Path) -> List[dict]:
    """Load a scan export, choosing JSON or CSV by path's extension.

    Mirrors export_results()'s own choice of format in both scanner
    scripts: ".csv" reads as CSV, anything else as JSON.
    """
    if path.suffix.lower() == ".csv":
        return _load_csv(path)
    return _load_json(path)


def _normalize_device(device: dict) -> dict:
    """Coerce a loaded device dict into consistent, comparable types.

    CSV round-trips everything through strings, so a port of 8080 reads
    back as "8080" and risky_ports as "23;445" - normalize both formats
    to the same shape (an int-or-None port, a sorted int list for
    risky_ports) so a device that's actually identical doesn't show up
    as "changed" just because one file was CSV and the other JSON.
    """
    normalized = dict(device)

    port = normalized.get("port")
    if isinstance(port, str):
        normalized["port"] = int(port) if port.strip() else None

    risky_ports = normalized.get("risky_ports")
    if isinstance(risky_ports, str):
        normalized["risky_ports"] = sorted(int(p) for p in risky_ports.split(";") if p)
    elif isinstance(risky_ports, list):
        normalized["risky_ports"] = sorted(int(p) for p in risky_ports)
    else:
        normalized["risky_ports"] = []

    return normalized


def _device_identity(device: dict) -> str:
    """Return the key used to match a device across the two files.

    Prefers MAC (present in network_scanner.py's exports, absent from
    mobile_network_scanner.py's) since it survives a DHCP lease change;
    falls back to IP otherwise - the same rule network_scanner.py's own
    known-devices tracking uses.
    """
    return device.get("mac") or device["ip"]


def diff_devices(old_devices: List[dict], new_devices: List[dict]) -> Dict[str, list]:
    """Compare two scans' device lists.

    Args:
        old_devices: Devices from the earlier file (see load_devices()).
        new_devices: Devices from the later file.

    Returns:
        {
            "added": devices present in new_devices but not old_devices,
                sorted by IP,
            "removed": devices present in old_devices but not
                new_devices, sorted by IP,
            "changed": a dict per device present in both whose fields
                differ, each {"key", "ip", "changes"}, where "changes"
                maps a field name to (old_value, new_value) - sorted by
                identity key,
        }
    """
    old_by_key = {_device_identity(_normalize_device(d)): _normalize_device(d) for d in old_devices}
    new_by_key = {_device_identity(_normalize_device(d)): _normalize_device(d) for d in new_devices}

    added = [new_by_key[key] for key in new_by_key if key not in old_by_key]
    removed = [old_by_key[key] for key in old_by_key if key not in new_by_key]

    changed = []
    for key in sorted(set(old_by_key) & set(new_by_key)):
        old_device, new_device = old_by_key[key], new_by_key[key]
        # "ip" is excluded here since it's shown as this row's label
        # already, not itemized as a field-level change.
        fields = sorted((set(old_device) | set(new_device)) - {"ip"})
        changes = {
            field: (old_device.get(field), new_device.get(field))
            for field in fields
            if old_device.get(field) != new_device.get(field)
        }
        if changes:
            changed.append({"key": key, "ip": new_device.get("ip", old_device.get("ip")), "changes": changes})

    return {
        "added": sorted(added, key=lambda d: d["ip"]),
        "removed": sorted(removed, key=lambda d: d["ip"]),
        "changed": changed,
    }


# --- Colorized terminal output ---
#
# The same green/dim/yellow language the scanner scripts themselves use
# for NEW/missing/CHG - added/removed/changed here are the same kind of
# signal, just diffed from two files instead of registry-vs-scan.

_ANSI_CODES: Dict[str, str] = {
    "green": "\033[32m",
    "yellow": "\033[33m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}


def _use_color(no_color_flag: bool) -> bool:
    """Decide whether to emit ANSI color codes at all (see either scanner's own _use_color())."""
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _colorize(text: str, color: str, enabled: bool) -> str:
    """Wrap text in an ANSI color code, or return it unchanged if enabled is False."""
    if not enabled:
        return text
    return f"{_ANSI_CODES[color]}{text}{_ANSI_CODES['reset']}"


def _format_value(value) -> str:
    """Render a field's value for the changed-fields report."""
    if isinstance(value, list):
        return ",".join(str(item) for item in value) if value else "(none)"
    if value in (None, ""):
        return "(none)"
    return str(value)


def _device_label(device: dict) -> str:
    """A short descriptive tag for a device row - whichever of label/hostname is set."""
    return device.get("label") or device.get("hostname") or ""


def print_diff_report(result: Dict[str, list], old_path: str, new_path: str, color: bool) -> None:
    """Print diff_devices()'s result as a readable report."""
    added, removed, changed = result["added"], result["removed"], result["changed"]

    if not added and not removed and not changed:
        print(f"No differences between {old_path} and {new_path}.")
        return

    if added:
        print(_colorize(f"{len(added)} device(s) added:", "green", color))
        for device in added:
            label = _device_label(device)
            suffix = f"  ({label})" if label else ""
            print(_colorize(f"  {device['ip']:<20}{suffix}", "green", color))

    if removed:
        if added:
            print()
        print(_colorize(f"{len(removed)} device(s) removed:", "dim", color))
        for device in removed:
            label = _device_label(device)
            suffix = f"  ({label})" if label else ""
            print(_colorize(f"  {device['ip']:<20}{suffix}", "dim", color))

    if changed:
        if added or removed:
            print()
        print(_colorize(f"{len(changed)} device(s) changed:", "yellow", color))
        for entry in changed:
            print(_colorize(f"  {entry['ip']}", "yellow", color))
            for field, (old_value, new_value) in entry["changes"].items():
                print(f"    {field}: {_format_value(old_value)} -> {_format_value(new_value)}")


def main() -> None:
    """CLI entry point: parse arguments, diff the two files, and print a report."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("old", help="Earlier scan's exported file (from --output on either scanner script)")
    parser.add_argument("new", help="Later scan's exported file to compare against it")
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color in the output (also respects the NO_COLOR env var, and auto-disables when stdout isn't a terminal)",
    )
    args = parser.parse_args()

    try:
        old_devices = load_devices(Path(args.old))
        new_devices = load_devices(Path(args.new))
    except OSError as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)
    except (json.JSONDecodeError, csv.Error) as exc:
        print(f"Error: couldn't parse a scan file - {exc}")
        raise SystemExit(1)

    result = diff_devices(old_devices, new_devices)
    print_diff_report(result, args.old, args.new, color=_use_color(args.no_color))


if __name__ == "__main__":
    main()
