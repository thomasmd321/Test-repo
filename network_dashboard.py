#!/usr/bin/env python3
"""Serve the known-devices registry as a live, glanceable HTML page.

Every scanner here (network_scanner.py, mobile_network_scanner.py) prints
its results to a terminal and moves on - useful for a one-off scan, but
if one of them is left running under --watch on an always-on machine,
"is anyone home right now" is a question you can only answer by SSHing
back in and reading scrollback. This instead serves whatever that
--watch loop has already been persisting to its known-devices registry
(the same JSON file _mark_new_devices() writes in both scanner scripts)
as a small HTML page - open it from a phone's browser on the same
network and it's glanceable the way the terminal output never was.

This is a pure *reader*: it never triggers a scan itself, has no
dependency on scapy/subprocess/raw sockets, and only touches a JSON file
plus stdlib's http.server - so unlike almost everything else in this
project, this specific script's own operation is fully iOS-sandbox-
compatible (though what's usually worth pointing it at - a desktop
machine's --watch registry - typically isn't, since that's the half that
needs subprocess/raw-socket access).

SECURITY, READ THIS FIRST: your device inventory (IPs, hostnames, vendor
strings, MAC addresses) is not public information, and this page has no
transport encryption and no authentication by default. Binding only to
--bind 127.0.0.1 (the default) keeps it reachable from this machine
alone; making it reachable from a phone means binding to a LAN-facing
address instead (e.g. --bind 0.0.0.0), which then serves that inventory,
unencrypted, to anyone who can reach this port on the same network - a
deliberate, explicit choice this script never makes for you. --token adds
a minimal shared-secret query check for that case; it's still plain HTTP,
so treat it as a speed bump against casual access on a trusted home LAN,
not real security against a hostile one - an SSH tunnel back to
--bind 127.0.0.1 is the actually-secure way to reach this from elsewhere.

Every value pulled from the registry (hostname, vendor, label) is
HTML-escaped before being rendered - a hostile device could set a
malicious DHCP hostname or otherwise influence what ends up in this
registry, so treating that data as trusted markup would be a stored-XSS
hole into a page you might load from your phone.

Usage:
    python network_dashboard.py                                    # loopback-only, network_scanner.py's registry
    python network_dashboard.py --bind 0.0.0.0 --token my-secret    # reachable from your phone, minimally gated
    python network_dashboard.py --registry ~/.cache/mobile_network_scanner_known_devices.json
    python network_dashboard.py --port 9000 --refresh 10 --stale-after 300

No new test coverage gap worth calling out here the way most other tools
in this project have to: render_dashboard_html() is pure and fully
unit-tested, and the actual HTTP server wiring (_build_handler() plus a
real ThreadingHTTPServer) is verified end-to-end with genuine, unmocked
sockets - a real GET request over real loopback TCP, covering both the
plain and --token-gated paths (see test_network_dashboard.py). Nothing
here needs privileges, hardware, or a real network to test for real.
"""

import argparse
import hmac
import html
import json
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Optional, Type

# Duplicated from network_scanner.py rather than imported - see this
# project's README for why each script here stays independently
# self-contained. This is the *default* only; --registry points this at
# mobile_network_scanner.py's own registry (or any other compatible file)
# just as easily.
_DEFAULT_REGISTRY_PATH = Path.home() / ".cache" / "network_scanner_known_devices.json"

_escape = html.escape


def load_registry(path: Path) -> Dict[str, dict]:
    """Load a known-devices registry from disk - {} if missing/unreadable/corrupt, same convention as every scanner's own _load_known_devices()."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _format_age(seconds: float) -> str:
    """Render an age in seconds as a short human string: "45s", "12m", "3h 5m", "2d"."""
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours}h {minutes}m" if minutes else f"{hours}h"
    days, hours = divmod(hours, 24)
    return f"{days}d {hours}h" if hours else f"{days}d"


_PAGE_STYLE = """
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 1.5rem; color: #16202a; background: #f4f6f8; }
h1 { font-size: 1.4rem; margin-bottom: 0.2rem; }
p.meta { color: #5b6b7a; font-size: 0.85rem; margin-top: 0; }
table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 1px 2px rgba(16,24,32,0.08); }
th, td { text-align: left; padding: 0.4rem 0.6rem; border-bottom: 1px solid #dbe1e7; font-size: 0.85rem; }
th { background: #eceff2; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.03em; color: #5b6b7a; }
tr.stale td { color: #8497a6; }
tr.online td.status { color: #1c8a5c; }
tr.stale td.status { color: #b1352f; }
p.note { color: #8497a6; font-size: 0.78rem; margin-top: 1rem; }
"""


def render_dashboard_html(
    registry: Dict[str, dict],
    registry_path: Path,
    stale_after: float,
    refresh: int,
    now: Optional[datetime] = None,
) -> str:
    """Render the known-devices registry as a complete standalone HTML page.

    Args:
        registry: As returned by load_registry().
        registry_path: Only used for display (which file this reflects).
        stale_after: A device not seen within this many seconds is shown
            as stale (a dim row, a red status mark) rather than online.
        refresh: Seconds between auto-refreshes via a <meta> tag; 0
            disables auto-refresh entirely.
        now: The current time, for computing each device's age - injected
            rather than always using datetime.now() so this is testable
            with a fixed clock.

    Returns:
        A complete `<!doctype html>` document, ready to serve as-is.
    """
    now = now or datetime.now()
    rows = []
    for key, entry in sorted(registry.items(), key=lambda kv: (kv[1].get("ip") or "", kv[0])):
        last_seen_raw = entry.get("last_seen", "")
        stale = True
        age_display = "unknown"
        if last_seen_raw:
            try:
                last_seen = datetime.fromisoformat(last_seen_raw)
                age_seconds = (now - last_seen).total_seconds()
                stale = age_seconds > stale_after
                age_display = f"{_format_age(age_seconds)} ago"
            except ValueError:
                pass

        label = entry.get("label", "")
        hostname = entry.get("hostname", "")
        if label and hostname and label != hostname:
            display_name = f"{label} ({hostname})"
        else:
            display_name = label or hostname or "–"

        port = entry.get("port")
        row_class = "stale" if stale else "online"
        status_mark = "○" if stale else "●"
        rows.append(
            "<tr class=\"{cls}\">"
            "<td class=\"status\">{status}</td><td>{key}</td><td>{ip}</td>"
            "<td>{name}</td><td>{vendor}</td><td>{port}</td>"
            "<td>{first_seen}</td><td>{age}</td>"
            "</tr>".format(
                cls=row_class,
                status=status_mark,
                key=_escape(key),
                ip=_escape(entry.get("ip", "")),
                name=_escape(display_name),
                vendor=_escape(entry.get("vendor", "")),
                port=_escape(str(port)) if port else "-",
                first_seen=_escape(entry.get("first_seen", "")),
                age=_escape(age_display),
            )
        )

    refresh_tag = f'<meta http-equiv="refresh" content="{refresh}">' if refresh > 0 else ""
    body_rows = "".join(rows) if rows else '<tr><td colspan="8">No devices in the registry yet.</td></tr>'

    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        f"<title>Network Dashboard</title>{refresh_tag}<style>{_PAGE_STYLE}</style></head><body>"
        "<h1>Network Dashboard</h1>"
        f"<p class=\"meta\">{len(registry)} known device(s) &middot; registry: {_escape(str(registry_path))} "
        f"&middot; generated {now.strftime('%Y-%m-%d %H:%M:%S')}</p>"
        "<table><tr><th></th><th>Key</th><th>IP</th><th>Name</th><th>Vendor</th><th>Port</th>"
        f"<th>First seen</th><th>Last seen</th></tr>{body_rows}</table>"
        f"<p class=\"note\">● seen within the last {int(stale_after)}s &middot; ○ stale (not seen recently). "
        "This page has no login beyond an optional --token; only bind it to a network you trust.</p>"
        "</body></html>"
    )


def _build_handler(registry_path: Path, stale_after: float, refresh: int, token: Optional[str]) -> Type[BaseHTTPRequestHandler]:
    """Build a BaseHTTPRequestHandler subclass closed over this run's config.

    A factory rather than a plain class because http.server's API wants a
    *class* (it instantiates one per request itself), so per-run
    configuration (which registry file, what token) has to be captured by
    closure rather than passed as constructor arguments.
    """

    class DashboardHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002 - matches BaseHTTPRequestHandler's own signature
            pass  # Keep stdout to this script's own startup/status lines, not a per-request access log.

        def _unauthorized(self) -> None:
            body = b"401 Unauthorized - missing or incorrect ?token=\n"
            self.send_response(401)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            if token:
                query = urllib.parse.urlsplit(self.path).query
                supplied = urllib.parse.parse_qs(query).get("token", [""])[0]
                if not hmac.compare_digest(supplied, token):
                    self._unauthorized()
                    return

            registry = load_registry(registry_path)
            body = render_dashboard_html(registry, registry_path, stale_after, refresh).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return DashboardHandler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--registry", type=str, default=str(_DEFAULT_REGISTRY_PATH), metavar="FILE", help=f"Known-devices registry to serve (default: {_DEFAULT_REGISTRY_PATH})")
    parser.add_argument("--bind", type=str, default="127.0.0.1", help="Address to bind to (default: 127.0.0.1, loopback-only - see this script's own security notice for --bind 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8765, help="Port to listen on (default: 8765)")
    parser.add_argument("--refresh", type=int, default=30, help="Seconds between auto-refreshes, 0 to disable (default: 30)")
    parser.add_argument("--stale-after", type=float, default=600.0, help="Seconds since last_seen before a device is shown as stale (default: 600)")
    parser.add_argument("--token", type=str, default=None, help="Require ?token=TOKEN on every request - a minimal shared-secret gate, not real security over plain HTTP (see this script's own security notice)")
    args = parser.parse_args()

    registry_path = Path(args.registry)
    if not registry_path.exists():
        print(f"Note: {registry_path} doesn't exist yet - run a scanner (with --watch, ideally) at least once first. Serving an empty dashboard for now.")

    handler_class = _build_handler(registry_path, args.stale_after, args.refresh, args.token)
    server = ThreadingHTTPServer((args.bind, args.port), handler_class)

    url = f"http://{args.bind}:{args.port}/"
    print(f"Serving the network dashboard at {url} (Ctrl+C to stop) ...")
    if args.bind not in ("127.0.0.1", "localhost", "::1"):
        auth_note = "a shared --token" if args.token else "NO authentication"
        print(
            f"Warning: bound to {args.bind!r}, not loopback-only - this page has no encryption and {auth_note}. "
            "Anyone who can reach this address on your network can see your device inventory "
            "(IPs, hostnames, vendors, MACs)."
            + ("" if args.token else " Consider --token, or keep --bind 127.0.0.1 and reach it through an SSH tunnel instead.")
        )

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
