# Test-repo

Python tools for discovering devices on your local network.

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

**Running on iPhone:** install [a-Shell](https://apps.apple.com/us/app/a-shell/id1473805438)
from the App Store (not "a-Shell mini," which strips out `git`), then either
`git clone` this repo or grab just the one file you need with `curl`:

```
curl -O https://raw.githubusercontent.com/thomasmd321/Test-repo/claude/local-network-device-discovery-joawq5/mobile_network_scanner.py
python3 mobile_network_scanner.py
```

## Tests

Unit tests mock all network/subprocess calls, so they run without any real
network access or elevated privileges:

```
pip install -r requirements-dev.txt
pytest
```
