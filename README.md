# Test-repo

Python tools for discovering devices on your local network.

📄 See [`docs/network_scanner_guide.pdf`](docs/network_scanner_guide.pdf) for a
printable setup/usage guide with pipeline diagrams and a full options
reference for both scripts. It's a generated file — see
[`docs/pdf_guide/`](docs/pdf_guide/) for the script that builds it (only
needed if you're updating the guide itself, not for using either scanner).

## Scripts

### `network_scanner.py`

For desktop/server environments (Linux, macOS, Windows, Termux on Android).
Prefers an ARP scan via [scapy](https://scapy.net/) — fast, and returns MAC
addresses directly — and falls back automatically to a multithreaded ping
sweep plus the system ARP table if scapy isn't installed or the process
doesn't have the privileges an ARP scan needs (typically root/administrator).

```
python network_scanner.py                             # auto-detect local subnet
python network_scanner.py 192.168.1.0/24               # scan a specific subnet
python network_scanner.py 192.168.1.0/24,10.0.0.0/24   # scan several subnets
python network_scanner.py --all-subnets                # scan every subnet this
                                                        # machine has a network
                                                        # interface on
python network_scanner.py --timeout 2
```

`--all-subnets` auto-detects and scans every local subnet across all of the
machine's network interfaces (e.g. Wi-Fi *and* Ethernet, or a VPN), instead
of just the one on the default route — useful if you're not sure which
interface a device you're looking for is actually on.

Both optional dependencies below are just that — optional. The script works
out of the box without either, falling back to slower/less detailed methods.

```
pip install scapy   # enables the faster ARP-scan path (returns MAC addresses)
pip install psutil  # enables --all-subnets (interface enumeration)
```

**Hostnames and vendors, filled in automatically, no extra dependency:**
- Any device still missing a hostname after ARP/reverse-DNS gets the same
  mDNS reverse lookup and DNS-SD Cast service discovery as
  `mobile_network_scanner.py` (see that script's section below for how
  these work) — and unlike on iOS, there's no sandboxing here to block it,
  so this reliably resolves things like Chromecast names on desktop/Termux.
- Any device with a MAC address gets it looked up against the IEEE's public
  OUI registry to identify the manufacturer (e.g. `aa:bb:cc:dd:ee:ff` →
  `Apple, Inc.`). The registry (a few MB) is downloaded once and cached at
  `~/.cache/network_scanner_oui.txt`; every run after that reuses the cache
  instantly, with no network call at all, until you ask otherwise. Pass
  `--no-vendor-lookup` to skip this entirely (e.g. for an offline scan, or
  to avoid the first-run download), or `--refresh-vendor-db` to force a
  fresh download instead of reusing the cache (the registry does grow over
  time, and nothing expires the cache automatically).

```
python network_scanner.py --mdns-timeout 0.5
python network_scanner.py --no-vendor-lookup
python network_scanner.py --refresh-vendor-db
```

**IPv6 (`--ipv6`, Linux/macOS only):** everything above is IPv4-only —
ARP and ping-sweep both assume a scannable subnet, which doesn't exist for
IPv6 (a /64 has 2**64 addresses, versus 254 for an IPv4 /24). `--ipv6`
instead sends a single ICMPv6 echo to the local link's all-nodes multicast
address (`ff02::1`) on every network interface, then reads back whatever
answered from the OS's own IPv6 neighbor cache — the same "ping first,
then read the OS's cache" two-step `ping_sweep()` already uses for IPv4,
just with multicast standing in for a brute-force sweep. Results are
appended below the IPv4 table (grouped by address family, not
numerically interleaved — comparing an IPv4 and IPv6 address for sorting
purposes doesn't mean anything).

```
python network_scanner.py --ipv6
python network_scanner.py --ipv6 --ipv6-timeout 5
```

Known limitations of this first pass:
- **Windows isn't supported** — the neighbor-table command and its output
  format differ enough from Linux/macOS that it isn't attempted; the flag
  is safe to pass, it'll just find nothing there.
- **No hostname resolution** for IPv6 devices — `mdns_reverse_lookup()`
  builds an IPv4-style `in-addr.arpa` reverse name that doesn't apply to
  IPv6 addresses (real IPv6 reverse DNS uses a different `ip6.arpa`
  nibble format). MAC vendor lookup still works normally, since it
  doesn't care which IP version found the MAC.

**Port scanning and risky-port flagging (on by default):** every discovered
device also gets probed for an open port from `DEFAULT_PORTS` — the same
port list/labels `mobile_network_scanner.py` uses (`80, 443, 22, 445, 139,
8080, 8443, 62078, 3389, 5000, 7000`), just applied here too so a device
with no hostname and no vendor at least gets a "port 8443, https-alt"
clue. Separately, every device is also checked against `RISKY_PORTS` — a
small, non-exhaustive list of ports worth a second look on a home network
(telnet, FTP, SMB, RDP, VNC) — *independent* of the general port probe
above, which stops at the first open port it finds and could otherwise
miss telnet entirely if port 80 happened to be checked first. Devices
exposing one get called out in a summary section after the table, along
with a one-line reason.

```
python network_scanner.py --no-scan-ports          # skip both entirely
python network_scanner.py --ports 22,80,443        # probe a custom list instead
python network_scanner.py --no-risky-ports          # keep the port probe, skip the security check
python network_scanner.py --port-timeout 0.5
```

**Colorized output:** NEW devices print in green, a device exposing a
risky port prints in red (taking priority if it's also NEW — it's still
visibly NEW from the marker text either way), and the missing-device
report prints dim. Plain ANSI codes, no dependency. Automatically
disabled when stdout isn't a terminal (piped to a file, etc.) or the
[`NO_COLOR`](https://no-color.org) environment variable is set; `--no-color`
disables it explicitly.

**Single-device deep dive (`--identify IP`):** the bulk scan is tuned for
speed across up to 254 hosts, so it can't afford long timeouts or a wide
port list — which is exactly why some devices come back with no
hostname, no vendor, and no clue what they are. `--identify` instead
investigates one specific host thoroughly: many more ports (including
things like FTP, SMTP, MySQL, Redis, Plex, and printers — see
`_IDENTIFY_PORTS`), a banner-grab attempt on each one that's open, and
the full hostname/vendor resolution chain with more generous timeouts.

```
python network_scanner.py --identify 192.168.1.26
```

Banner grabbing (`grab_banner()`) reads whatever a service reveals about
itself right after connecting — many protocols announce themselves
unprompted (SSH sends its version string outright), and HTTP(S) servers
reveal a lot in response to even a bare `HEAD /` request. For a port
outside the well-known HTTP set, it tries listening first and only sends
an HTTP probe if nothing arrived — since plenty of IoT admin UIs (again,
exactly the kind of device this mode exists for) run HTTP on
non-standard ports. Not every service says anything at all: binary
protocols like SMB or RDP just report no banner, the same as a closed
port would.

### `mobile_network_scanner.py`

For sandboxed Python runtimes that can't spawn subprocesses or open raw
sockets — most notably iOS apps like [a-Shell](https://apps.apple.com/us/app/a-shell/id1473805438),
Pythonista, or Pyto. Instead of `ping`/`arp`/scapy, it discovers hosts by
attempting plain TCP connections to a handful of commonly-open ports (80,
443, 22, 445, 3389, etc. — see `DEFAULT_PORTS` in the script), which only
needs an ordinary client socket.

```
python mobile_network_scanner.py                             # auto-detect local subnet
python mobile_network_scanner.py 192.168.1.0/24               # scan a specific subnet
python mobile_network_scanner.py 192.168.1.0/24,10.0.0.0/24   # scan several subnets
python mobile_network_scanner.py --timeout 0.5 --ports 22,80,443
```

This is best-effort: it won't find a device with none of the probed ports
open, so widen `--ports` if you're missing something you expect to see.
Unlike `network_scanner.py`, it can't auto-detect *every* subnet a device
is on — the iOS sandbox doesn't expose interface enumeration — but you can
pass multiple subnets yourself as a comma-separated list if you know them
(e.g. your Wi-Fi range and a VPN range).

Results show which port answered as a hint at what the device is (e.g.
`8009` = Chromecast, `554` = an RTSP camera, `1900`/`5353` = a UPnP/mDNS
smart-home device) — see `PORT_SERVICES` in the script for the full list.
A device with no hostname and an unfamiliar port is worth cross-checking
against your router's admin page (usually `192.168.1.1` in a browser).

Each device's Banner column comes from `grab_banner()`, which reads
whatever the open port sends back: an HTTP `Server:` header (sends a bare
`HEAD /` for recognized web ports, or as a fallback probe on unrecognized
ones if nothing arrives unprompted — many IoT admin UIs run HTTP on
non-standard ports), or a protocol banner volunteered outright (SSH, FTP,
etc.). Unlike mDNS/DNS-SD below, this needs nothing beyond the same plain
`socket`/`ssl` primitives the rest of this script already uses, so it
works on iOS with no platform restrictions — often enough on its own to
identify a device with no hostname. Pass `--no-banners` to skip it for a
faster scan.

```
python mobile_network_scanner.py --no-banners
```

Every live device is also independently checked against `RISKY_PORTS` -
a short list of ports (telnet, FTP, SMB, RDP, VNC) worth a second look if
left open on a home network - regardless of which port the general probe
above happened to match first. A device exposing one gets flagged in a
summary section after the results table, along with why each port is
considered risky. This is a basic hygiene check, not a security audit;
pass `--no-risky-ports` to skip it while keeping the general probe.

```
python mobile_network_scanner.py --no-risky-ports
```

Output is colorized (green for a NEW device, red for one exposing a
risky port - red wins if both apply, though the NEW marker text is still
visible either way) using plain ANSI escape codes; no extra dependency.
Auto-disables when stdout isn't a terminal (e.g. piped to a file), and
also respects `--no-color` or the `NO_COLOR` env var.

```
python mobile_network_scanner.py --no-color
```

Hostnames are resolved in this order, all built in with no extra
dependency:
1. **DNS-SD Cast service discovery** — for anything answering on the
   Chromecast control port (8009). Chromecasts generally *don't* answer
   reverse mDNS lookups (step 3 below) since that part of the spec is
   optional and Google's Cast stack skips it — but they always answer
   "who offers `_googlecast._tcp.local`?", since that's the actual
   mechanism the Google Home app and Chrome's "Cast" button use to find
   them. This gets you the real device name (e.g. "Living Room TV").
2. **Reverse DNS** (`socket.gethostbyaddr`) — works for whatever your
   router/DHCP server names in its own DNS, typically just itself and
   maybe a few statically-configured hosts.
3. **mDNS/Bonjour reverse lookup** — for other devices (printers, NAS
   boxes, smart speakers, etc.) that implement the optional reverse-PTR
   part of mDNS but never register real reverse DNS.

`--timeout`/`--mdns-timeout` control how long each of steps 2–3 wait per
device; step 1 runs once per scan (not per device) and also respects
`--mdns-timeout`. On iOS, the first mDNS query may trigger an OS prompt
asking to allow "Local Network" access — accept it or these fallbacks
will just silently find nothing.

```
python mobile_network_scanner.py --mdns-timeout 0.5
```

Note: this is a *best-effort* implementation, not a full mDNS/DNS-SD
stack — it sends one query per method and reads whatever comes back
within the timeout, which is enough for most devices but won't work
through mDNS reflectors/VLANs that don't forward multicast traffic. The
Cast service-discovery query also joins the mDNS multicast group and
binds to port 5353 (falling back to an ordinary socket if that's denied)
since service-browsing replies are commonly sent via multicast
regardless of the unicast-response bit a one-shot address lookup relies
on.

**Known limitation on iOS:** in testing, every mDNS/DNS-SD query from
a-Shell failed outright with `OSError(65, 'No route to host')` on the
send itself — confirmed with `mdns_diagnostic.py` (see below) — which
points to iOS's Local Network Privacy model rather than a bug here: apps
must declare, at the app-bundle level (`NSBonjourServices` in
`Info.plist`), exactly which Bonjour service types they intend to use.
A generic terminal app has no way to declare that for a script typed at
runtime, so iOS blocks the multicast traffic before it ever leaves the
device - regardless of the general "Local Network" permission toggle,
and regardless of anything this script does differently. Plain TCP port
scanning is unaffected, since that's ordinary unicast traffic and
doesn't require this. If you hit this, your router's admin page or a
native network-scanner app (which declares the right entitlements at
build time) are the practical alternatives.

```
python mdns_diagnostic.py
```

This standalone script isolates each step (socket creation, binding to
port 5353, joining the multicast group, sending a query, receiving any
reply at all) so you can see exactly which layer is failing rather than
guessing from "no hostname" alone.

**Running on iPhone:** install [a-Shell](https://apps.apple.com/us/app/a-shell/id1473805438)
from the App Store (not "a-Shell mini," which strips out `git`), then either
`git clone` this repo or grab just the one file you need with `curl`:

```
curl -O https://raw.githubusercontent.com/thomasmd321/Test-repo/claude/local-network-device-discovery-joawq5/mobile_network_scanner.py
python3 mobile_network_scanner.py
```

## Known-device tracking and watch mode

Both scripts persist a small local registry of every device they've ever
seen (`~/.cache/network_scanner_known_devices.json` and
`~/.cache/mobile_network_scanner_known_devices.json` respectively) and
flag anything not in it with a leading `NEW` marker in the results table.
`network_scanner.py` keys a device by its MAC address when it has one
(falling back to IP otherwise); `mobile_network_scanner.py` has no MAC to
work with at all, so it always keys by IP — meaning a DHCP lease change
there will make an existing device look "new" again.

The registry also powers the inverse report: any previously-seen device
that *didn't* show up in this scan (asleep, unplugged, out of Wi-Fi
range) is listed separately below the table, e.g. "2 previously-seen
device(s) not found in this scan." The registry itself is never pruned —
a device just stops appearing in that list again once a later scan finds
it.

The same registry also enables a `CHG` marker: since it already stores
each device's port from the last scan, comparing that against this
scan's port catches a device that's started (or stopped) answering on a
different port than usual — flagged in a summary section below the
table, e.g. "1 device(s) with a changed port since last seen." This is a
distinct signal from the risky-ports check above: it doesn't care
whether the port is on `RISKY_PORTS`, only that it's *different* from
what this device normally shows, which telnet suddenly appearing on a
device that's never had it open would trip either way. `NEW` and `CHG`
are mutually exclusive by definition — a device with no history at all
can't have a "changed" port, only a first one.

```
python network_scanner.py                      # NEW markers on by default
python network_scanner.py --no-track-devices    # skip tracking entirely
python network_scanner.py --forget-known-devices  # reset the registry, marking
                                                   # everything NEW this run
```

Pair this with `--watch SECONDS` to rescan on a timer instead of once,
turning either script into a lightweight "alert me when something joins
my network" monitor you leave running in a terminal (Ctrl+C to stop):

```
python network_scanner.py --watch 300           # rescan every 5 minutes
python mobile_network_scanner.py --watch 300
```

The very first run (or right after `--forget-known-devices`) will mark
every device `NEW`, since nothing has been seen before yet — that's
expected, not a bug.

## Custom device labels/aliases

Assign a friendly name to a device — useful when its real hostname is
cryptic or blank — with `--set-label KEY=LABEL`, where `KEY` is its MAC
address for `network_scanner.py` (or IP if it has none — see
`_device_identity()`), or always its IP for `mobile_network_scanner.py`.
The label is stored in the same known-devices registry as everything
else above, and shown in the results table in place of/alongside the
real hostname (`Kitchen Server (localhost)` when they differ, just
`Kitchen Server` when there's no hostname to show alongside it).

```
python network_scanner.py --set-label aa:bb:cc:dd:ee:ff="Kitchen Server"
python mobile_network_scanner.py --set-label 192.168.1.42="Kitchen Echo"
python network_scanner.py --remove-label aa:bb:cc:dd:ee:ff
```

Both flags are repeatable (pass `--set-label` more than once to label
several devices in one command) and take effect immediately, including on
the scan that runs in the same command — so a label can be set and see it
applied without waiting for the device to show up in a second run. A
device doesn't need to already be in the registry: labeling one by IP/MAC
you've seen in a previous run's output creates a minimal registry entry
for it, though that also means it won't show as `NEW` the next time it's
actually scanned (labeling it counts as "already known"). A label also
appears in place of the hostname in the "previously-seen device(s) not
found" report if that device goes missing later.

## Exporting results

Both scripts can save a scan's results to a file with `--output FILE`,
independent of the known-devices registry above — useful for feeding
results into another tool, diffing two scans by hand, or just keeping a
record. The format is chosen by the extension: `.csv` writes CSV, anything
else (typically `.json`) writes JSON.

```
python network_scanner.py --output scan.json
python network_scanner.py --output scan.csv
python mobile_network_scanner.py --output scan.json
```

Each run overwrites `FILE` with that scan's results — it's a snapshot of
the latest scan, not an appended history log. A CSV's `risky_ports` column
is `;`-separated (e.g. `23;445`) since a CSV cell can't hold a real list;
the JSON export keeps it as a proper array.

## Diffing two scans

`scan_diff.py` compares two files saved with `--output` above and reports
what changed between them — devices added, devices that disappeared, and
per-field changes (a different port, hostname, banner, etc.) on devices
present in both. It's the same NEW/missing/CHG comparison the scanners do
against their own known-devices registry, just applied to two snapshots on
disk instead.

```
python scan_diff.py old.json new.json
python scan_diff.py before.csv after.csv
```

Either file can be JSON or CSV (independently — comparing a CSV export
against a JSON one works fine), and they don't need to come from the same
script: fields the two scanners don't share (`mac`/`vendor` are
desktop-only, `banner` is mobile-only) are still compared whenever both
files happen to have them. A device is matched across the two files by MAC
when present, falling back to IP — the same identity rule
`network_scanner.py`'s own known-devices tracking uses.

## Notifications for `--watch`

`--notify-webhook URL` POSTs a plain-text summary to `URL` as
`{"text": "..."}` JSON — the format Slack's incoming webhooks (and many
other generic webhook receivers, including most self-hosted alerting
tools) expect directly — whenever a scan has a NEW device, a port change,
a missing device, or a risky port to report. A boring scan sends nothing
at all, the same trigger condition `--quiet` uses.

```
python network_scanner.py --watch 300 --notify-webhook https://hooks.slack.com/services/...
python mobile_network_scanner.py --watch 300 --notify-webhook https://ntfy.sh/your-topic
```

A failed or unreachable webhook prints a warning to stderr and the scan
continues normally — it never crashes the run. This deliberately doesn't
special-case any one service's exact payload shape; a target expecting
something else (Discord's `content` key, ntfy.sh's plain-text body) may
need a small relay in between, or just point it at a service that already
speaks the Slack-compatible format (many push services, including
ntfy.sh's JSON publish endpoint, do).

## Quiet mode and environment diagnostics

`--quiet` suppresses everything — even the scan's own "Scanning..." line —
for a run with nothing to report: no NEW devices, no port changes, no
missing devices, and no risky ports. As soon as one of those is true, the
full report prints exactly as it would without `--quiet`. This is meant
for `--watch` under cron/systemd, where a boring rescan producing zero
output (rather than a full table every time) is what makes "did anything
happen" easy to grep for or alert on — the same trigger condition
`--notify-webhook` above uses, so the two pair naturally.

```
python network_scanner.py --watch 300 --quiet
python mobile_network_scanner.py --watch 300 --quiet
```

`--doctor` skips the network scan and instead checks this environment for
everything the script can use — scapy, `ping`/`arp`, cache-directory
writability, mDNS multicast, and so on — reporting each with a clear
pass/fail and, for most, a note on the fallback that kicks in when it
fails. It exits 0 if every check passed, 1 otherwise, so it's usable as a
pre-flight check in a script.

```
python network_scanner.py --doctor
python mobile_network_scanner.py --doctor
```

A failed check here doesn't necessarily mean a scan will fail — most have
a documented fallback (no `arp` on PATH just means no MAC from that path,
not a crash) — it's diagnostic, not a hard prerequisite. The one exception
worth knowing: a failed mDNS check on `mobile_network_scanner.py` almost
always means iOS's Local Network Privacy restriction (see
`mdns_diagnostic.py`), which no retry or code change here can fix.

## Tests

Unit tests mock all network/subprocess calls, so they run without any real
network access or elevated privileges:

```
pip install -r requirements-dev.txt
pytest
```

A GitHub Actions workflow (`.github/workflows/tests.yml`) runs the same
suite on every push and pull request, across Python 3.9–3.12.
