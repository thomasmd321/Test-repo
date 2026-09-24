# Test-repo

Small standalone Python tools for looking at your own home network. Each
script is self-contained (stdlib plus one or two optional third-party
packages) and only observes — none of them alter, redirect, or throttle
anyone's traffic.

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
```

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
| `--pin IP=MAC` | A mapping to enforce; repeatable |
| `--repair IP=MAC` | Pin one mapping via the OS static-ARP command and exit |
| `--windows-interface NAME` | [Windows only] adapter name for `--repair` (default: `Ethernet`) |

Requires `scapy` for watching traffic; `--repair` alone has no dependencies.
Sniffing raw packets typically requires root/administrator privileges.
