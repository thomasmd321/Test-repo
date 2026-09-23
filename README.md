# Test-repo

Python tools for understanding your local network: which devices are on
it (`network_scanner.py`, `mobile_network_scanner.py`), what changed
between two scans (`scan_diff.py`), what services they're advertising
(`mdns_browser.py`), what Wi-Fi networks are in range (`wifi_scanner.py`),
whether anything risky is reachable from outside it
(`exposure_check.py`), where a slow connection is actually slow
(`traceroute_mapper.py`), whether something is spoofing another device's
IP right now (`arp_monitor.py`), whether an unauthorized DHCP server is
handing out its own leases (`dhcp_monitor.py`), whether your DNS is being
hijacked (`dns_check.py`), how fast the LAN itself actually is
(`lan_throughput.py`), which ports your router's UPnP has quietly opened
to the internet (`upnp_audit.py`), and a live, glanceable dashboard of
whatever a scanner's `--watch` loop has already found
(`network_dashboard.py`).

📄 See [`docs/network_scanner_guide.pdf`](docs/network_scanner_guide.pdf) for a
printable setup/usage guide with pipeline diagrams and a full options
reference for the two scanner scripts. It's a generated file — see
[`docs/pdf_guide/`](docs/pdf_guide/) for the script that builds it (only
needed if you're updating the guide itself, not for using any of these
tools).

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
interface a device you're looking for is actually on. Multiple subnets
(whether from `--all-subnets` or a comma-separated list) are scanned
concurrently, not one at a time, so having several VLANs doesn't multiply
the wall-clock cost of a scan.

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

## Recovering from a flaky scan (`--retries`)

A single dropped ARP/ping reply (or one flaky TCP connect on the mobile
script) can make a device that's genuinely still there look "missing"
this run — and then "NEW" again next run once it answers normally. That
false signal pollutes every registry-based feature above: NEW/CHG
markers, the missing-device report, IP-conflict alerts, and webhook
notifications all inherit it. `--retries N` re-probes before finalizing
results, giving a flaky device another chance to answer:

```
python network_scanner.py --retries 1
python mobile_network_scanner.py --retries 2
```

The two scripts implement this differently, matching how each one
discovers devices in the first place. `network_scanner.py`'s ARP/ping
sweep is one broadcast across the whole subnet, so each retry re-runs
that same broadcast and merges in anything new that answers — scapy's
raw sockets aren't necessarily safe to hit concurrently from several
targeted single-host requests instead, so a second full broadcast is the
simple, safe option even though it's less targeted.
`mobile_network_scanner.py` already probes each host individually over
plain TCP, so each retry there only re-probes the specific hosts still
missing a match, leaving already-found devices alone. Defaults to `0`
(a single pass) on both scripts, preserving the original behavior exactly.

## IP-conflict / spoofing alerts (`network_scanner.py` only)

The same registry also catches a device's IP being taken over by a
*different* MAC address than last time — a DHCP lease getting handed to
a new device is the ordinary cause, but it's exactly the same signal
something spoofing another device's IP (most notably ARP-poisoning your
router's own address) would produce. A conflicting device prints in
magenta and shows up in a summary section, e.g.:

```
⚠ 1 device(s) with a suspicious IP handoff:
  192.168.1.50         now bb:bb:bb:bb:bb:bb, previously aa:aa:aa:aa:aa:aa
```

This is a hygiene signal, not an intrusion-detection system — a home
network reassigns leases all the time, and most hits here will be
completely benign. A conflict on your router/gateway's own IP is the one
case worth treating as urgent rather than routine. Only compares devices
that both have a real MAC address; a ping-sweep-only device (no MAC at
all — see above) can't meaningfully conflict with anything, so it's
excluded rather than adding noise from the existing no-MAC limitation.
Not available on `mobile_network_scanner.py`, which has no MAC address to
compare in the first place (see the tracking note above). Skipped
entirely with `--no-track-devices`, same as `NEW`/`CHG`/missing tracking.

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

## Excluding devices from a scan

`--exclude IP/CIDR` skips one or more addresses — comma-separated, each
either a bare IP (treated as a /32) or a CIDR range — from the rest of a
scan, without narrowing the whole subnet just to dodge one host: a printer
that crashes under port probes, a NAS you don't want woken from sleep, or
a noisy neighbor you just don't care about.

```
python network_scanner.py --exclude 192.168.1.5
python network_scanner.py --exclude 192.168.1.5,192.168.1.10
python network_scanner.py --exclude 192.168.1.0/28
python mobile_network_scanner.py --exclude 192.168.1.5,10.0.0.0/24
```

On `mobile_network_scanner.py`, exclusion is complete: excluded hosts are
dropped from the list before any TCP connection is ever attempted, so
nothing at all reaches them. On `network_scanner.py`'s ARP path, the
initial ARP broadcast still reaches every host on the subnet — scapy's
`srp()` sends one request across the whole range in a single call, with no
way to carve individual addresses out of that broadcast — but excluded
devices are dropped immediately after discovery, before vendor lookup,
port scanning, the risky-ports check, and the final report/export/tracking,
so in practice they're never touched beyond that one broadcast packet. The
ping-sweep fallback (no scapy, or insufficient privileges) still pings
every host itself — exclusion is applied the same way, right after
discovery — since a ping sweep has no equivalent single-broadcast step to
route around.

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

## Scan history log

`--log-history FILE` appends every scan's results to `FILE` as one JSON
line per run (`{"timestamp": "...", "devices": [...]}`), instead of
overwriting it like `--output` does — useful under `--watch` for keeping a
record of what the network looked like over time, or for feeding into your
own analysis later (each line parses independently, so you don't need to
load the whole file to read one entry).

```
python network_scanner.py --watch 300 --log-history history.jsonl
python mobile_network_scanner.py --log-history history.jsonl
```

The file is capped at 200 entries by default (oldest dropped first) so it
doesn't grow forever under a long-running `--watch`; override with
`--history-max-entries N`.

```
python network_scanner.py --watch 300 --log-history history.jsonl --history-max-entries 1000
```

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

## Browsing mDNS/DNS-SD services (`mdns_browser.py`)

The other two scripts only ever ask mDNS/DNS-SD one narrow question at a
time — "what's this IP's hostname?" or "is anything answering as a
Chromecast?" `mdns_browser.py` asks the broader one: what services exist
on this network at all — printers, AirPlay speakers, SSH-capable hosts,
HomeKit accessories, anything advertising itself — without needing to
already know an IP or guess a service type up front.

```
python mdns_browser.py                          # discover + browse everything found
python mdns_browser.py --timeout 3
python mdns_browser.py --services _http._tcp.local,_ipp._tcp.local
python mdns_browser.py --no-discover             # skip auto-discovery, use built-ins only
python mdns_browser.py --output services.json
```

It works in two phases. First, it asks DNS-SD's own "meta-query"
(`_services._dns-sd._udp.local`, RFC 6763 §9) which service types are
actually in use on the network — not every device implements this even
when it implements browsing for its own type, so the result is unioned
with a small built-in list of common types (Chromecast, AirPlay, IPP
printers, SMB, SSH, HomeKit, and more — see `_COMMON_SERVICE_TYPES`).
Second, it browses all of those types at once on a single socket, joining
each response's PTR/SRV/A records into an `{ip: name}` map per type — the
same join `mobile_network_scanner.py`'s own `mdns_service_lookup()` does
for Chromecast specifically, generalized here to many types in one pass.

Like the mDNS code in the other two scripts, this is best-effort (one
query per type, reading whatever comes back within `--timeout`) and
shares their iOS limitation — mDNS/DNS-SD sends fail outright there due
to Apple's Local Network Privacy model (see `mobile_network_scanner.py`'s
module docstring and `mdns_diagnostic.py`).

## Scanning nearby Wi-Fi networks (`wifi_scanner.py`)

A different, complementary question from the other tools here: not "what
devices are on my network," but "what networks are in radio range at
all," including ones you're not connected to. A network that feels slow
is often channel congestion from a neighbor on the same channel, or a
weak signal — neither of which device discovery can see.

```
python wifi_scanner.py
python wifi_scanner.py --timeout 15
python wifi_scanner.py --output networks.json
```

Shells out to each OS's own Wi-Fi tooling rather than a raw 802.11
library (none ships in the standard library, and a packet-capture-based
scanner would need monitor mode and root/administrator everywhere, a much
higher bar): `nmcli` on Linux, the `airport` command-line tool on macOS
(still present despite Apple's deprecation notice), and `netsh wlan show
networks` on Windows. Signal strength is kept in whatever unit each
platform's own tool reports (a percentage on Linux/Windows, dBm on
macOS) rather than converted between them — there's no one true
conversion, so labeling each honestly beats a false unification. An open/
unencrypted network is called out in the output as a security nod, the
same spirit as `RISKY_PORTS` elsewhere in this project.

Each scan is also compared against a small local registry of previously
seen networks (`~/.cache/wifi_scanner_known_networks.json`) to catch two
evil-twin/rogue-AP patterns: a familiar SSID suddenly answering with
*weaker* security than it's ever shown before (a downgrade attack — a
legitimate AP doesn't just drop encryption on its own), and a familiar
SSID answering from a BSSID never seen before (a softer signal — could be
a genuinely new/roaming AP on a mesh network, so it's flagged for a
second look, not treated as proof). `--no-evil-twin-check` skips this;
`--forget-known-networks` clears the registry.

**Known limitation, stated plainly:** the parsing for all three platforms
is verified only against mocked command output matching each tool's
documented format (see `test_wifi_scanner.py`), not against real Wi-Fi
hardware on any of the three OSes — the environment this was built in has
none of `nmcli`/`airport`/`netsh` and no wireless hardware at all. Treat a
first real run on any platform as the verification it hasn't had yet. The
evil-twin logic itself needs no hardware to verify, though, and was run
for real end to end against a fake `nmcli` script on `PATH`: a baseline
scan, an unchanged repeat (correctly silent), a simulated downgrade to
Open on the same BSSID (correctly flagged), and a new BSSID under the
same SSID (also correctly flagged, as a softer "new access point" signal
rather than a downgrade).

## Checking internet-facing exposure (`exposure_check.py`)

`RISKY_PORTS` elsewhere in this project flags a port from inside the
LAN — but a risky port reachable only from your own network is a much
smaller problem than the same port reachable from the whole internet.
This asks the sharper question: is a LAN-risky port (or any port you
name) also reachable from the outside, by probing your own public IP
from this machine.

```
python exposure_check.py                        # RISKY_PORTS, auto-detected public IP
python exposure_check.py --ports 22,80,443,8080
python exposure_check.py --ip 203.0.113.5 --ports 22
python exposure_check.py --output exposure.json
```

Your public IP is found with a single plain HTTP(S) request to
[api.ipify.org](https://www.ipify.org) — a small, purpose-built "what's my
IP" echo service, no account or API key needed, returning just the
address as plain text. No other data about your network is sent
anywhere; `--ip` skips this request entirely if you'd rather not make it,
or already know the address.

**Read this before trusting a result:** probing your own public IP from
inside your own LAN is not a reliable substitute for a real external
scan. Home routers implement NAT loopback/hairpinning inconsistently —
some silently drop this traffic (a genuinely open port reports as a false
"closed" here), others loop it back to a LAN device without truly routing
it to the internet and back (a false "open" that doesn't prove an actual
outside host could reach it). A closed result here is never proof of
safety, and an open result is never definitive proof of exposure — both
need confirming from a real external vantage point (a VPS, a friend's
network, a phone on cellular data with Wi-Fi off, or a third-party online
port-checking site you choose yourself) before acting on either one. This
tool is a cheap first pass, not the final word — the CLI itself prints
this same caveat after every run.

## Mapping the path to a host (`traceroute_mapper.py`)

Neither `exposure_check.py`'s "is this port reachable" nor
`wifi_scanner.py`'s "is my signal weak" tells you *where* along the path
a slow connection is actually slow. This does: it wraps the OS's own
traceroute tool and reports every hop's IP, hostname, and round-trip time.

```
python traceroute_mapper.py 8.8.8.8
python traceroute_mapper.py google.com --max-hops 20
python traceroute_mapper.py 192.168.1.1 --no-resolve-hostnames
python traceroute_mapper.py 8.8.8.8 --output path.json
```

Runs each platform's tool in numeric-only mode — `traceroute -n` on
Linux/macOS, `tracert -d` on Windows — specifically to sidestep the
biggest source of cross-platform output differences, then resolves each
hop's hostname itself afterward via plain reverse DNS, rather than
depending on the traceroute binary's own often-inconsistent DNS handling.
A hop that timed out on every probe still shows up (with no IP, three
missed replies) rather than being silently dropped, so a gap in the path
stays visible; a hop whose best RTT is notably high is called out in the
output.

**Known limitation, stated plainly:** this project's own development
environment has no `traceroute`/`tracert` binary at all, so every
platform's parser here is verified only against mocked command output
matching each tool's documented format (plus one real subprocess run
against a fake `traceroute` script on `PATH`) — never against a real path
on real hardware, on any of the three platforms. Traceroute output varies
more between tool versions/distros than most formats parsed elsewhere in
this project; treat a first real run as the verification it hasn't had yet.

## Watching for ARP spoofing (`arp_monitor.py`)

The IP-conflict alert built into `network_scanner.py` (see above) only
samples at scan time — a full scan every few minutes at best under
`--watch` — so a live man-in-the-middle attack happening *between* scans
can go unnoticed until the next one, if ever. `arp_monitor.py` watches
continuously instead: every ARP reply on the wire is observed as it
happens, and any IP whose MAC changes mid-session is flagged immediately.

```
python arp_monitor.py                     # watch the default interface
python arp_monitor.py --interface eth0
python arp_monitor.py --log conflicts.jsonl
```

Needs scapy and the same raw-socket privileges (root/administrator) as
`network_scanner.py`'s ARP scan — there's no way to passively observe ARP
traffic without them. Like the IP-conflict alert it complements, this is
a hygiene/detection aid, not a full intrusion-detection system: a MAC
change is exactly as likely to be an ordinary DHCP lease reassignment as
an actual attack, and it can't catch spoofing already fully established
before it started watching (there's no "before" to compare against yet).
A change on your router/gateway's own IP is the one case worth treating
as urgent.

**Known limitation, stated plainly:** this project's own development
environment has a broken scapy/cryptography install (see `--doctor` in
`network_scanner.py`) and no raw-socket privileges either, so the actual
packet-sniffing path has never run for real in this environment. The
pure detection logic it calls (`process_arp_observation()`) is fully
unit-tested and needs nothing from scapy at all; the `sniff()` wiring
around it is verified only by faking out the scapy import in tests, not
against real ARP traffic on real hardware.

## Watching for a rogue DHCP server (`dhcp_monitor.py`)

A different class of LAN trouble than ARP spoofing: an unauthorized DHCP
server handing out its own leases alongside (or instead of) your real
router — a classic attack (hand out a malicious gateway/DNS server to
every new client), or an equally common accident (a consumer router
plugged in backwards, its own DHCP server now answering on your LAN).
Nothing else here would ever notice — a device scan sees who's *on* the
network, not who's been quietly handing out its addresses.

```
python dhcp_monitor.py                          # first server seen is the trusted baseline
python dhcp_monitor.py --trusted-server 192.168.1.1
python dhcp_monitor.py --log rogue_dhcp.jsonl
```

Unlike `arp_monitor.py`, this needs no scapy or raw sockets at all —
DHCPOFFER/DHCPACK replies are ordinary broadcast UDP on port 68 (the
client port), so an ordinary socket bound there receives them the same
way a real DHCP client does. On Linux/macOS this still needs root: port
68 is a privileged port there regardless of socket type. Windows doesn't
gate ports under 1024 on administrator status the same way, but that's
not the same as "just works" there — it'd be sharing port 68 with
Windows' own DHCP Client service, and Windows' looser `SO_REUSEADDR`
semantics make whether that bind actually succeeds genuinely untested
rather than assumed fine. The first server observed (or any named with
`--trusted-server`) is the assumed-good baseline; any additional, distinct
server after that is flagged — `--trusted-server` removes the ambiguity
of "first observed" only being as trustworthy as whichever server
happened to answer first.

Verified more thoroughly than `arp_monitor.py` could manage: the wire-format
parsing and detection logic are unit-tested with hand-built packets, the
socket-receive loop is verified end to end against a real, unmocked UDP
socket on a non-privileged test port, and — since this project's own
sandbox happens to run as root on Linux — the real production path was
also run for real there, against the genuine privileged port 68,
correctly ignoring a trusted server and flagging an untrusted one. What's
still unverified is real DHCP traffic from a real, physical network
(every packet used above was hand-built to match the RFC 2131 wire
format, not captured from an actual router), and the entire Windows path,
including whether the port-68 bind even succeeds there alongside the
built-in DHCP Client service.

## Checking for DNS hijacking (`dns_check.py`)

Every other tool here assumes DNS answers can be trusted. A compromised
router, a malicious/free Wi-Fi hotspot, or a captive portal commonly
intercept DNS and answer with their own IP for domains that should
NXDOMAIN — redirecting to an ad page, a phishing page, or a "please log
in" portal before a browser is even opened.

```
python dns_check.py                       # both checks, default public resolvers
python dns_check.py --resolver 1.1.1.1 --resolver 9.9.9.9
python dns_check.py --output dns_check.json
```

Two checks: the decisive one queries a fresh random hostname under the
`.invalid` TLD (reserved by RFC 2606 so it can never be a real domain) —
any answer at all, from your resolver or a public one, means something is
fabricating NXDOMAIN responses. The softer, caveated one compares
`example.com` (also RFC 2606-reserved, for stable documentation use)
across your resolver and a few public ones (Cloudflare, Google, Quad9 by
default) and flags a mismatch — worth a second look, not proof on its own,
since a proxying/filtering resolver or a stale cache can also cause this.
Public resolvers are queried directly with a from-scratch DNS client over
raw UDP sockets (stdlib only), since `socket.getaddrinfo()` only ever asks
whatever the OS itself is configured to use.

Verified about as thoroughly as a tool here can be: the wire-format code
is exercised against a real, unmocked local fake DNS server, and — since
raw UDP port 53 traffic isn't blocked by this sandbox's outbound proxy the
way HTTPS is — a real run against the actual Cloudflare/Google/Quad9
resolvers worked end to end too, correctly returning NXDOMAIN for a fresh
canary and agreeing on `example.com`'s real answer.

## Measuring LAN throughput (`lan_throughput.py`)

None of the other tools here measure this at all: "my internet feels
slow" and "my LAN itself is slow" are different problems, and only a real
transfer between two devices on the same network tells you which one you
actually have.

```
python lan_throughput.py --serve                    # on the receiving machine
python lan_throughput.py --serve --port 6000 --once
python lan_throughput.py --client 192.168.1.50       # on the sending machine
python lan_throughput.py --client 192.168.1.50 --duration 10 --port 6000
```

Plain TCP sockets, no dependency: one machine listens and reports what it
received; the other streams random data at it for a fixed duration (random,
not zeros, since some links compress a repeating pattern in a way that
would over-report the result) and reports what it actually managed to
send. This measures TCP goodput between exactly these two processes, not
raw link-layer bandwidth or a multi-stream aggregate the way a dedicated
tool like `iperf3` does — treat it as a quick, no-install sanity check,
not a substitute for `iperf3` when you need a rigorous number.

## Auditing UPnP port forwards (`upnp_audit.py`)

`exposure_check.py` answers "is this port reachable from outside" after
the fact, by probing your public IP. This answers a sharper, earlier
question: *why* a port might be open at all, even though nothing in a LAN
scan looks unusual. Many home routers ship with UPnP enabled, letting any
device on the network ask the router to forward a port from the internet
straight to itself — a game console, a BitTorrent client, a smart-home
hub — with no further confirmation and no trace visible from LAN-side
scanning at all. This queries the router itself for its current UPnP
port-mapping table, the same information a device could have used to open
that port in the first place.

```
python upnp_audit.py
python upnp_audit.py --timeout 5
python upnp_audit.py --output mappings.json
```

Works in three steps: SSDP multicast discovery finds your router's UPnP
Internet Gateway Device (the same request/response shape mDNS/DNS-SD's
own discovery is built on, an older HTTP-header-flavored sibling
protocol); its XML device description is fetched and walked — regardless
of nesting depth, since routers vary here — to find the WANIPConnection or
WANPPPConnection service that actually manages port forwarding; then that
service's `GetGenericPortMappingEntry` SOAP action is called once per
index until the router reports there are no more. A mapping forwarding a
port already on `RISKY_PORTS` is called out specifically, the same
hygiene-flagging spirit as the risky-ports check elsewhere in this
project.

**Known limitation, stated plainly:** this project's own development
environment has no reachable UPnP Internet Gateway Device. The full
SSDP → XML → SOAP pipeline is verified against a real, unmocked gateway
simulated locally — a genuine SSDP responder plus a genuine HTTP server
serving real XML/SOAP bodies, all communicating over real sockets, no
mocks anywhere in that chain — which exercises every wire-format detail
this script depends on, but it has never spoken to an actual router.
Router UPnP stacks are inconsistent about spec compliance in ways a
simulated one won't reproduce; treat a first real run as the verification
it hasn't had yet.

## A live dashboard for `--watch` (`network_dashboard.py`)

Every scanner here prints to a terminal and moves on — if one is left
running under `--watch` on an always-on machine, "is anyone home right
now" otherwise means SSHing back in and reading scrollback. This instead
serves whatever `--watch` has already persisted to its known-devices
registry as a small HTML page, glanceable from a phone's browser on the
same network.

```
python network_dashboard.py                                  # loopback-only, network_scanner.py's registry
python network_dashboard.py --bind 0.0.0.0 --token my-secret  # reachable from your phone, minimally gated
python network_dashboard.py --registry ~/.cache/mobile_network_scanner_known_devices.json
```

A pure *reader*: it never triggers a scan itself, and needs nothing
beyond a JSON file and stdlib's `http.server` — no scapy, no subprocess,
no raw sockets, so unlike almost everything else here, this specific
script's own operation is fully iOS-sandbox-compatible (though what's
usually worth pointing it at — a desktop's `--watch` registry — typically
isn't). Auto-refreshes via a plain `<meta>` tag, no JavaScript at all.

**Security, stated plainly:** your device inventory (IPs, hostnames,
vendor strings, MACs) isn't public information, and this page has no
transport encryption and no authentication by default. It defaults to
`--bind 127.0.0.1` (reachable only from this machine) for exactly that
reason — reaching it from a phone means explicitly choosing `--bind
0.0.0.0` (or a LAN address), which then serves that inventory,
unencrypted, to anyone who can reach the port. `--token` adds a minimal
shared-secret query check for that case, but it's still plain HTTP — an
SSH tunnel back to `--bind 127.0.0.1` is the actually-secure way to reach
this from elsewhere. Every value pulled from the registry is HTML-escaped
before rendering, since a hostile device could otherwise set a malicious
hostname designed to inject markup into a page you load from your phone.

Fully verified for real: `render_dashboard_html()` is pure and unit-tested,
and the actual HTTP server (a real `ThreadingHTTPServer`, hit with a real
`urllib` GET over real loopback TCP) is exercised end to end for both the
plain and `--token`-gated paths — nothing here needs privileges, hardware,
or a real network to verify.

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

## Shell tab-completion

`completions.bash` adds bash tab-completion for every script's flag names
(18+ for the two scanners, fewer for the smaller tools, but still easy to
half-remember). Source it from your `~/.bashrc`:

```
source /path/to/Test-repo/completions.bash
```

It only completes flag *names*, not their arguments (a subnet, a port
list, a file path), and only fires for a direct invocation matching a
script's own name (`./network_scanner.py`, or the bare name if it's on
PATH — see `chmod +x`, already set on every script in this repo).
`python3 network_scanner.py <TAB>` does **not** trigger it: bash keys
completion off the first word of the command line, which is `python3` in
that case, not the script — see the comments at the top of
`completions.bash` for the full explanation and workaround (putting the
script on PATH so the bare-name form works).

## Tests

Unit tests mock nearly all network/subprocess calls (a handful instead use
a real loopback socket this same machine both opens and connects to), so
the suite runs without any real *external* network access or elevated
privileges:

```
pip install -r requirements-dev.txt
pytest
```

A GitHub Actions workflow (`.github/workflows/tests.yml`) runs the same
suite on every push and pull request, across Python 3.9–3.12.
