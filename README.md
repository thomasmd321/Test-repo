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
python network_scanner.py                 # auto-detect local subnet
python network_scanner.py 192.168.1.0/24   # scan a specific subnet
python network_scanner.py --timeout 2
```

Install scapy to enable the faster ARP-scan path (optional — the script
works without it via the ping-sweep fallback):

```
pip install scapy
```

### `mobile_network_scanner.py`

For sandboxed Python runtimes that can't spawn subprocesses or open raw
sockets — most notably iOS apps like [a-Shell](https://apps.apple.com/us/app/a-shell/id1473805438),
Pythonista, or Pyto. Instead of `ping`/`arp`/scapy, it discovers hosts by
attempting plain TCP connections to a handful of commonly-open ports (80,
443, 22, 445, 3389, etc. — see `DEFAULT_PORTS` in the script), which only
needs an ordinary client socket.

```
python mobile_network_scanner.py                 # auto-detect local subnet
python mobile_network_scanner.py 192.168.1.0/24   # scan a specific subnet
python mobile_network_scanner.py --timeout 0.5 --ports 22,80,443
```

This is best-effort: it won't find a device with none of the probed ports
open, so widen `--ports` if you're missing something you expect to see.

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
