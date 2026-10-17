# Test-repo

Small standalone Python tools for your own home network and local system.
Each script is self-contained (stdlib plus at most one or two optional
third-party packages). The network tools only observe — none of them
alter, redirect, or throttle anyone's traffic; `duplicate_finder.py` and
`lan_file_server.py` do touch the local filesystem (deleting duplicates,
accepting uploads), but only when you explicitly opt in (`--delete`,
`--allow-upload`).

| Tool | What it does |
| --- | --- |
| [`network_scanner.py`](#network_scannerpy) | Discovers devices on the local subnet (ARP scan / ping sweep) |
| [`bandwidth_dashboard.py`](#bandwidth_dashboardpy) | Live per-device bandwidth view (sniff / conntrack / Netgear sources) |
| [`arp_spoof_detector.py`](#arp_spoof_detectorpy) | Alerts on ARP cache poisoning; can repair a poisoned entry |
| [`port_scanner.py`](#port_scannerpy) | TCP connect-scans a host for open ports |
| [`duplicate_finder.py`](#duplicate_finderpy) | Finds byte-identical files in a directory tree by hash |
| [`cert_expiry_checker.py`](#cert_expiry_checkerpy) | Reports days until a host's TLS certificate expires |
| [`log_watcher.py`](#log_watcherpy) | Tails a log file and alerts on regex matches, rotation-aware |
| [`lan_file_server.py`](#lan_file_serverpy) | Shares a directory over HTTP with the LAN; uploads are opt-in |

See [`TODO.md`](TODO.md) for ideas that haven't been built yet, and
[Running the tests](#running-the-tests) below for the test suite.

## network_scanner.py

Discovers devices on the local network.

Uses an ARP scan via scapy when available (fast, returns MAC addresses
directly). Falls back to a multithreaded ping sweep plus the system ARP
table when scapy isn't installed or the process lacks the privileges ARP
scanning requires.

```
python network_scanner.py                 # auto-detect local subnet
python network_scanner.py 192.168.1.0/24   # scan a specific subnet
python network_scanner.py --timeout 2
python network_scanner.py --max-hosts 10000 10.0.0.0/20   # override the size guard
```

Refuses to scan a subnet larger than `--max-hosts` addresses (default 4096)
as a safety net against typos like `/8` instead of `/24`, which would
otherwise try to sweep millions of hosts at once.

Optional dependency: `scapy` (for the faster ARP scan; falls back to
`ping`/`arp` otherwise).

## bandwidth_dashboard.py

Live per-device bandwidth dashboard. Picks between three data sources with
`--source`, since there's no single method that works on every network —
which one is usable depends on where this script runs and what your router
is.

### `--source sniff` (default)

Passively sniffs traffic on a local network interface with scapy.

```
sudo python bandwidth_dashboard.py                  # auto-pick interface
sudo python bandwidth_dashboard.py --interface eth0
sudo python bandwidth_dashboard.py --interval 5
```

**Caveat:** on a typical switched network, an ordinary host only sees its
own unicast traffic plus broadcast/multicast — not other devices' unicast
traffic. For visibility across the whole LAN, run this on the router/gateway
itself, or on a machine connected to a mirror/SPAN port. Otherwise it will
mostly just show your own device.

Requires `scapy`. Sniffing raw packets typically requires root/administrator
privileges.

### `--source conntrack`

Polls `/proc/net/nf_conntrack`, which every Linux-based router/gateway
(OpenWrt, DD-WRT, a Raspberry Pi or other Linux box acting as your router,
etc.) already maintains for NAT. It lists every active connection with
per-connection byte counters tagged by source/destination IP, so this gives
real whole-LAN, per-device totals without needing a vendor-specific router
API.

```
python bandwidth_dashboard.py --source conntrack                       # running on the router itself
python bandwidth_dashboard.py --source conntrack --host root@192.168.1.1  # polled over SSH
```

Requires the router to run Linux, and either running this script on the
router itself or SSH access to it. Byte accounting must be enabled once on
the router:

```
sysctl -w net.netfilter.nf_conntrack_acct=1
```

**Caveat:** it reflects only currently-tracked connections, so a
connection's final bytes can be missed if it closes between polls — fine for
a live "who's using bandwidth right now" view, not for exact totals.

**Not applicable to stock consumer routers** (e.g. Netgear/ASUS/Linksys
out-of-the-box firmware) unless you flash them with Linux-based alternative
firmware such as OpenWrt/DD-WRT/Tomato — and not every router model
supports that. Newer Wi-Fi 6 routers (e.g. the Netgear RAX43v2) generally
don't have alternative-firmware support due to closed-source Wi-Fi drivers.

### `--source netgear`

For stock Netgear firmware (e.g. Nighthawk/Orbi, including models like the
RAX43v2 with no OpenWrt/DD-WRT support), which has no documented per-device
bandwidth API. Uses `pynetgear` to poll the router's local SOAP API (the
same one the Nighthawk app uses) for the attached-devices list and the
router-**wide** traffic meter.

```
pip install pynetgear
NETGEAR_PASSWORD=yourpassword python bandwidth_dashboard.py --source netgear
NETGEAR_PASSWORD=yourpassword python bandwidth_dashboard.py --source netgear --netgear-host routerlogin.net --netgear-user admin
```

Requires **Traffic Meter** enabled in the router's web UI (*Advanced > Setup
> Traffic Meter*) for the daily/monthly totals to populate; the
attached-devices/link-rate table works regardless.

**Important caveat:** this does **not** give true per-device live
throughput. "Link Rate" is each device's negotiated Wi-Fi PHY speed (a
speed ceiling, not actual usage), and the traffic meter is a whole-router
today/month total, not broken out per device. Treat it as "who's connected
and how fast is their link," not "who's using bandwidth right now." Genuine
per-device live throughput on a sealed consumer router generally requires
either the vendor's cloud subscription (e.g. Netgear Armor/Insight) or a
hardware change — a separate Linux box bridged between the router and your
switch, or a router that supports OpenWrt/DD-WRT.

### Common options

| Flag | Applies to | Description |
| --- | --- | --- |
| `--source {sniff,conntrack,netgear}` | all | Data source (default: `sniff`) |
| `--interval SECONDS` | all | Seconds between dashboard refreshes (default: 2) |
| `--interface IFACE` | `sniff` | Network interface to sniff on (default: scapy's default) |
| `--host user@router` | `conntrack` | SSH target for the router (default: read locally) |
| `--ssh-port PORT` | `conntrack` | SSH port (default: 22) |
| `--netgear-host HOST` | `netgear` | Router hostname/IP (default: `routerlogin.net`) |
| `--netgear-user USER` | `netgear` | Router admin username (default: `admin`) |

### Dependencies

- `scapy` — required for `--source sniff`
- `pynetgear` — required for `--source netgear`
- `rich` (optional, all sources) — renders a live-refreshing table; without
  it, the dashboard falls back to a plain periodic text summary

```
pip install scapy pynetgear rich
```

## arp_spoof_detector.py

Passively watches ARP replies on a local interface and alerts when something
looks like ARP cache poisoning (the technique behind "NetCut"-style LAN
disconnect tools) — either an IP's claimed MAC address changing faster than
a real device would ("flapping"), or a reply contradicting a mapping you've
explicitly told it to trust ("pinned"). It never sends, forges, or blocks
any traffic; it only reads and reports.

```
sudo python arp_spoof_detector.py                  # auto-pick interface
sudo python arp_spoof_detector.py --interface eth0
sudo python arp_spoof_detector.py --flap-window 10 --pin 192.168.1.1=aa:bb:cc:11:22:33

# Repair a poisoned entry without sniffing, e.g. after an alert:
python arp_spoof_detector.py --repair 192.168.1.1=aa:bb:cc:11:22:33
```

`--repair` dispatches to the OS's own static-ARP command (`arp -s` on
Linux/macOS, `netsh` on Windows — see `--windows-interface` for the adapter
name Windows needs) so the corrected mapping can't be silently overwritten
again.

| Flag | Description |
| --- | --- |
| `--interface IFACE` | Interface to watch (default: scapy's default) |
| `--flap-window SECONDS` | How fast a MAC change is treated as suspicious (default: 10) |
| `--stale-after SECONDS` | Forget an ip after this many idle seconds, to bound memory use on a long-running watch (default: 300) |
| `--pin IP=MAC` | A mapping to enforce; repeatable |
| `--repair IP=MAC` | Pin one mapping via the OS static-ARP command and exit |
| `--windows-interface NAME` | [Windows only] adapter name for `--repair` (default: `Ethernet`) |

Requires `scapy` for watching traffic; `--repair` alone has no dependencies.
Sniffing raw packets typically requires root/administrator privileges.

## port_scanner.py

TCP connect-scan for a single host on your own network — no raw packets,
no stealth/SYN tricks, just a plain `connect()` per candidate port with a
short timeout. Pairs naturally with `network_scanner.py`: find devices on
the LAN, then scan a specific one's ports.

```
python port_scanner.py 192.168.1.50                  # ~25 common ports
python port_scanner.py 192.168.1.50 --ports 1-1024
python port_scanner.py 192.168.1.50 --ports 22,80,443
python port_scanner.py 192.168.1.50 --ports 1-65535 --timeout 0.3
```

| Flag | Description |
| --- | --- |
| `--ports SPEC` | Comma list and/or ranges, e.g. `22,80,443` or `1-1024` (default: ~25 common ports) |
| `--timeout SECONDS` | Wait per port (default: 0.5) |
| `--workers N` | Concurrent connection attempts (default: 200) |

No dependencies beyond the standard library.

## duplicate_finder.py

Finds duplicate files in a directory tree. Groups by file size first (a
cheap pre-filter), then hashes files within each same-size group — nothing
gets hashed against a file it can't possibly match. Report-only by default;
nothing is deleted unless you pass `--delete`.

```
python duplicate_finder.py ~/Downloads
python duplicate_finder.py ~/Downloads --min-size 1024
python duplicate_finder.py ~/Downloads --delete   # keep first copy, remove the rest
```

| Flag | Description |
| --- | --- |
| `--min-size BYTES` | Ignore files smaller than this (default: 1, skips empty files) |
| `--delete` | Delete all but the first copy in each duplicate group (default: report only) |

No dependencies beyond the standard library.

## cert_expiry_checker.py

Connects to one or more hosts, completes a real TLS handshake, and reports
how many days remain before each presented certificate expires. Exit code
is 0 if everything's healthy, 1 if anything's expiring soon, 2 if anything
is already expired or unreachable — so it's usable as a cron/monitoring check.

```
python cert_expiry_checker.py example.com
python cert_expiry_checker.py example.com:8443 mail.example.com
python cert_expiry_checker.py --warn-days 14 example.com
python cert_expiry_checker.py --file hosts.txt
```

| Flag | Description |
| --- | --- |
| `--file PATH` | Read additional hosts from a file, one per line (`#` comments allowed) |
| `--warn-days N` | Flag certificates expiring within this many days (default: 30) |
| `--timeout SECONDS` | Wait per connection (default: 5) |

No dependencies beyond the standard library.

## log_watcher.py

Watches a log file like `tail -f` and prints an alert for any new line
matching one of your regex patterns. Polling-based and rotation-aware: a
truncated or renamed/replaced file (logrotate, copytruncate, etc.) is
detected and reopened automatically rather than silently going stale.

```
python log_watcher.py /var/log/syslog --pattern "error|failed"
python log_watcher.py app.log --pattern "ERROR" --pattern "WARN:.*timeout"
python log_watcher.py app.log --pattern "ERROR" --from-start
python log_watcher.py app.log --pattern "ERROR" --interval 0.5
```

| Flag | Description |
| --- | --- |
| `--pattern REGEX` | Alert on any line matching; repeatable (any match triggers an alert) |
| `--from-start` | Scan existing content too, not just new lines (default: only new lines) |
| `--interval SECONDS` | Poll interval (default: 1.0) |

No dependencies beyond the standard library.

## lan_file_server.py

Shares a directory over HTTP with other devices on your LAN — browse and
download like `python -m http.server`, plus it prints the URL to use from
another device. Uploads are **off by default**; pass `--allow-upload` to
also accept them (via a simple web form at `/upload-form`, or directly:
`curl -X POST --data-binary @file.txt "http://host:port/upload?name=file.txt"`).
Uploaded filenames are reduced to a bare basename before being written, so
an upload can never escape the served directory via `../`.

```
python lan_file_server.py                      # serve the current directory, port 8000
python lan_file_server.py ~/Public --port 9000
python lan_file_server.py --allow-upload
python lan_file_server.py --bind 127.0.0.1      # local machine only, not the LAN
```

| Flag | Description |
| --- | --- |
| `--port N` | Port to listen on (default: 8000) |
| `--bind ADDR` | Address to bind to (default: `0.0.0.0`, all interfaces) |
| `--allow-upload` | Also accept file uploads (default: read-only) |
| `--max-upload-size BYTES` | Reject uploads larger than this (default: 1 GiB) |

**By default this binds to all interfaces**, so anyone who can reach the
port on your LAN can browse and download everything in the served
directory (and upload, if enabled). Only run it on a network you trust,
and only point it at a directory you're comfortable exposing. No
dependencies beyond the standard library.

## Running the tests

```
python3 -m unittest
```

Runs the full suite in `tests/` (one file per tool, ~120 tests). Almost
everything is a real integration test rather than a mock — a real TCP
listener for `port_scanner.py`, a real self-signed TLS handshake (via the
system `openssl` CLI) for `cert_expiry_checker.py`, a real HTTP server for
`lan_file_server.py` including a live path-traversal attempt against the
upload endpoint, and real temp files/directories for `duplicate_finder.py`
and `log_watcher.py` (including log rotation and truncation). The pieces
that genuinely can't run without root, a real router, or a real external
host (raw packet sniffing, actually pinging a LAN, talking to a Netgear
router) are mocked at that boundary and no further.
