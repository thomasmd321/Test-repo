#!/usr/bin/env python3
"""Check TLS certificate expiry for a list of hosts.

Connects to each host:port, completes a TLS handshake, and reports how
many days remain before the presented certificate expires -- useful for
catching a renewal that's about to lapse before it takes a service down.

Usage:
    python cert_expiry_checker.py example.com
    python cert_expiry_checker.py example.com:8443 mail.example.com
    python cert_expiry_checker.py --warn-days 14 example.com
    python cert_expiry_checker.py --file hosts.txt

Exit code is 0 if every certificate is healthy, 1 if any are expiring
within --warn-days, 2 if any are already expired or unreachable.
"""

import argparse
import datetime
import socket
import ssl
import sys


def parse_host_port(spec: str, default_port: int = 443):
    """Split "host" or "host:port" into (host, port)."""
    host, sep, port_str = spec.rpartition(":")
    if not sep:
        return spec, default_port
    return host, int(port_str)


def parse_not_after(not_after: str) -> datetime.datetime:
    """Parse a certificate's notAfter string (e.g. 'Jun  1 12:00:00 2025
    GMT', the format ssl.getpeercert() returns) into a UTC datetime."""
    dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    return dt.replace(tzinfo=datetime.timezone.utc)


def days_remaining(expiry: datetime.datetime, now: datetime.datetime = None) -> int:
    now = now or datetime.datetime.now(datetime.timezone.utc)
    return (expiry - now).days


def get_certificate_expiry(host: str, port: int = 443, timeout: float = 5.0, context: ssl.SSLContext = None) -> datetime.datetime:
    """Connect to host:port, complete a TLS handshake, and return the
    presented certificate's expiry as a timezone-aware UTC datetime.
    context defaults to the standard CA-verifying context; tests can pass
    one that trusts a throwaway test certificate instead."""
    context = context or ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    return parse_not_after(cert["notAfter"])


def check_host(host: str, port: int, timeout: float):
    """Return (days_remaining, error) -- error is None on success, and
    days_remaining is None when error is set."""
    try:
        expiry = get_certificate_expiry(host, port, timeout)
    except Exception as exc:
        return None, str(exc)
    return days_remaining(expiry), None


def classify(days_left, error, warn_days: int):
    """Return (status_text, exit_code_contribution) for one host's result."""
    if error:
        return f"ERROR: {error}", 2
    if days_left < 0:
        return "EXPIRED", 2
    if days_left <= warn_days:
        return "EXPIRING SOON", 1
    return "ok", 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("hosts", nargs="*", help="Hosts to check, e.g. example.com or example.com:8443")
    parser.add_argument("--file", help="Read additional hosts from a file, one per line (# comments allowed)")
    parser.add_argument("--warn-days", type=int, default=30, help="Flag certificates expiring within this many days (default: 30)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Seconds to wait per connection (default: 5)")
    args = parser.parse_args()

    hosts = list(args.hosts)
    if args.file:
        with open(args.file) as f:
            hosts += [line.strip() for line in f if line.strip() and not line.startswith("#")]

    if not hosts:
        raise SystemExit("No hosts given. Pass one or more hosts, or --file.")

    exit_code = 0
    print(f"{'Host':<32}{'Port':<8}{'Days Left':<12}Status")
    print("-" * 72)
    for spec in hosts:
        host, port = parse_host_port(spec)
        days_left, error = check_host(host, port, args.timeout)
        status, contribution = classify(days_left, error, args.warn_days)
        exit_code = max(exit_code, contribution)
        days_text = "?" if days_left is None else str(days_left)
        print(f"{host:<32}{port:<8}{days_text:<12}{status}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
