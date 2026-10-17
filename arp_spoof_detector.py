#!/usr/bin/env python3
"""Passive ARP spoofing detector.

Watches ARP replies on a local interface and raises an alert when an
IP's claimed MAC address changes suspiciously quickly -- the classic
signature of ARP cache poisoning (a real device won't do this; an
attacker racing to keep a forged mapping fresh will).

This only observes traffic. It never sends, forges, or blocks anything.

Usage:
    sudo python arp_spoof_detector.py                 # auto-pick interface
    sudo python arp_spoof_detector.py --interface eth0
    sudo python arp_spoof_detector.py --flap-window 10 --pin 192.168.1.1=aa:bb:cc:11:22:33

    # Repair a poisoned entry without sniffing (used after an alert):
    python arp_spoof_detector.py --repair 192.168.1.1=aa:bb:cc:11:22:33
"""

import argparse
import platform
import subprocess
import time

try:
    from scapy.all import ARP, sniff
except ImportError:
    ARP = None


class FlapDetector:
    """Alerts when an IP's claimed MAC changes suspiciously fast,
    or breaks a pinned mapping outright."""

    # flap_window: seconds -- a MAC change faster than this is suspicious
    # pinned:      optional {ip: mac} ground truth supplied by the operator
    # stale_after: seconds of inactivity before an ip is forgotten. Without
    #   this, last_seen grows one entry per unique source IP forever -- and
    #   since this tool watches for exactly the traffic an attacker who
    #   spoofs many forged source IPs would generate, that growth is
    #   adversarially exploitable, not just a theoretical long-run leak.
    def __init__(self, flap_window: float = 10.0, pinned: dict = None, stale_after: float = 300.0):
        self.flap_window = flap_window
        self.pinned = pinned or {}
        self.last_seen = {}   # state: ip -> (mac, timestamp) memory
        self.stale_after = stale_after
        self._observations_since_prune = 0

    # ip, mac: sender fields from one incoming ARP reply
    # now:     current time (seconds), e.g. from time.time()
    # returns: an alert string, or None if the reply looks fine
    def observe(self, ip: str, mac: str, now: float):
        # pinned_mac: the trusted MAC for this ip, if the operator gave one
        pinned_mac = self.pinned.get(ip)
        if pinned_mac and mac.lower() != pinned_mac.lower():
            # claimed MAC contradicts ground truth -- alert immediately,
            # no need to wait and see if it repeats
            return f"PINNED MISMATCH: {ip} claimed by {mac}, expected {pinned_mac}"

        # prev_mac/prev_time: what we last recorded for this ip
        # (both None the first time this ip is ever seen)
        prev_mac, prev_time = self.last_seen.get(ip, (None, None))
        self.last_seen[ip] = (mac, now)   # remember this sighting either way
        self._prune_if_due(now)

        if prev_mac and prev_mac != mac and (now - prev_time) < self.flap_window:
            # MAC changed, and changed faster than flap_window allows
            return (
                f"FLAP: {ip} changed from {prev_mac} "
                f"to {mac} after {now - prev_time:.1f}s"
            )
        return None   # nothing suspicious about this reply

    def _prune_if_due(self, now: float):
        """Forget ips idle longer than stale_after, so last_seen stays
        bounded by recent activity instead of growing for the life of the
        process. Amortized: only sweeps every 1000 observations."""
        self._observations_since_prune += 1
        if self._observations_since_prune < 1000:
            return
        self._observations_since_prune = 0
        stale_ips = [ip for ip, (_, seen_at) in self.last_seen.items() if now - seen_at > self.stale_after]
        for ip in stale_ips:
            del self.last_seen[ip]


# detector: the FlapDetector instance to feed; returns a scapy-compatible
# callback closure so each captured packet can reach it
def make_callback(detector):
    def on_packet(pkt):   # pkt: one captured frame, handed in by scapy's sniff()
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:   # op=2 -> "is-at" reply
            # pkt[ARP].psrc/hwsrc: the (possibly forged) sender IP/MAC
            alert = detector.observe(pkt[ARP].psrc, pkt[ARP].hwsrc, time.time())
            if alert:
                print(f"[!] {alert}")
    return on_packet


# ip, mac:    the trusted mapping to pin (mac in colon notation, e.g. "aa:bb:...")
# interface:  adapter name -- only used on Windows, where netsh requires one
def pin_arp_entry(ip: str, mac: str, interface: str = "Ethernet"):
    # cmd: the OS-appropriate command, built but not yet run
    if platform.system().lower() == "windows":
        mac = mac.replace(":", "-")   # netsh expects hyphens, not colons
        cmd = ["netsh", "interface", "ipv4", "add", "neighbors", interface, ip, mac]
    else:
        cmd = ["sudo", "arp", "-s", ip, mac]   # Linux/macOS static-ARP syntax
    # capture_output/text: return stdout+stderr as strings instead of printing;
    # check=False: don't raise on failure -- let the caller inspect .returncode
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def parse_ip_mac(value: str):
    ip, _, mac = value.partition("=")
    if not ip or not mac:
        raise argparse.ArgumentTypeError(f"expected ip=mac, got {value!r}")
    return ip, mac


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--interface", help="Interface to watch (default: scapy's default)")
    parser.add_argument("--flap-window", type=float, default=10.0, help="Seconds within which a MAC change is treated as suspicious (default: 10)")
    parser.add_argument("--stale-after", type=float, default=300.0, help="Forget an ip after this many idle seconds, to bound memory use (default: 300)")
    parser.add_argument("--pin", action="append", default=[], metavar="IP=MAC", help="A mapping to enforce, e.g. 192.168.1.1=aa:bb:cc:11:22:33 (repeatable)")
    parser.add_argument("--repair", metavar="IP=MAC", help="Pin one mapping via the OS static-ARP command and exit, instead of watching traffic")
    parser.add_argument("--windows-interface", default="Ethernet", help="[Windows only] adapter name for --repair (default: Ethernet)")
    args = parser.parse_args()

    if args.repair:
        ip, mac = parse_ip_mac(args.repair)
        result = pin_arp_entry(ip, mac, interface=args.windows_interface)
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="")
        raise SystemExit(result.returncode)

    if ARP is None:
        raise SystemExit("Watching traffic requires scapy: pip install scapy")

    # pinned: turn ["ip=mac", ...] from --pin into a {ip: mac} dict
    pinned = dict(parse_ip_mac(p) for p in args.pin)
    detector = FlapDetector(flap_window=args.flap_window, pinned=pinned, stale_after=args.stale_after)

    print(f"Watching ARP replies on {args.interface or 'default interface'} ... Ctrl+C to stop.")
    if pinned:
        print(f"Pinned mappings: {pinned}")

    try:
        # filter="arp": let libpcap discard non-ARP traffic before Python sees it;
        # prn: scapy calls this once per matching packet; store=False: don't
        # keep captured packets in memory, this runs indefinitely
        sniff(iface=args.interface, filter="arp", prn=make_callback(detector), store=False)
    except KeyboardInterrupt:
        print("\nStopped.")
    except PermissionError:
        raise SystemExit(
            "Permission denied opening the capture interface.\n"
            "(Are you running with sudo/Administrator privileges?)"
        )


if __name__ == "__main__":
    main()
