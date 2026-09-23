#!/usr/bin/env python3
"""Measure actual throughput between two machines on your own LAN.

None of the other tools here measure this at all: exposure_check.py asks
whether a port is reachable from the internet, wifi_scanner.py asks about
radio conditions, traceroute_mapper.py asks about path latency - but "my
internet feels slow" and "my LAN itself is slow" are different problems,
and only a real transfer between two devices on the same network tells
you which one you actually have. A slow result here, with everything else
in this project reporting clean, points at the LAN segment itself (cabling,
switch, Wi-Fi backhaul) rather than your ISP or anything further out.

Plain TCP sockets, no dependency: one machine runs --serve and listens,
the other runs --client HOST and streams data at it for a fixed duration,
timing how long the transfer actually takes on each side.

Usage:
    python lan_throughput.py --serve                    # on the receiving machine
    python lan_throughput.py --serve --port 6000 --once
    python lan_throughput.py --client 192.168.1.50       # on the sending machine
    python lan_throughput.py --client 192.168.1.50 --duration 10 --port 6000

This measures TCP goodput end to end between exactly these two processes,
not raw link-layer bandwidth or a multi-stream aggregate the way a
dedicated tool like iperf3 does - a single TCP stream on a busy network or
a slow disk/CPU on either end can under-report the link's real capacity.
Treat it as a quick, no-install sanity check, not a substitute for iperf3
when you need a rigorous number.
"""

import argparse
import os
import socket
import sys
import time
from typing import Dict, TypedDict

DEFAULT_PORT = 5566
_CHUNK_SIZE = 65536


class ThroughputResult(TypedDict):
    bytes: int
    seconds: float


def _receive_and_measure(conn: socket.socket) -> ThroughputResult:
    """Read from conn until the sender closes it, timing the whole transfer."""
    total = 0
    start = time.monotonic()
    while True:
        chunk = conn.recv(_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
    elapsed = time.monotonic() - start
    return {"bytes": total, "seconds": elapsed}


def serve(host: str = "0.0.0.0", port: int = DEFAULT_PORT, once: bool = False) -> None:
    """Listen for throughput-test connections and report each one's measured rate.

    Args:
        host: Address to bind to (default: all interfaces).
        port: TCP port to listen on.
        once: Exit after measuring a single connection instead of looping
            to accept more (useful for scripting a one-shot test).

    Runs until interrupted (Ctrl+C) unless once is True.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        print(f"Listening on {host}:{port} - run `lan_throughput.py --client <this machine's IP>` from another device.")
        while True:
            conn, addr = server.accept()
            with conn:
                result = _receive_and_measure(conn)
            print(f"{addr[0]}: received {result['bytes']:,} bytes in {result['seconds']:.2f}s ({format_rate(result['bytes'], result['seconds'])})")
            if once:
                return


def run_client(host: str, port: int = DEFAULT_PORT, duration: float = 5.0) -> ThroughputResult:
    """Stream random data at host:port for duration seconds, then report what was actually sent.

    Args:
        host: The --serve machine's address.
        port: TCP port it's listening on.
        duration: How long to keep sending, in seconds (wall-clock, timed
            from the connection, not from a fixed byte count - so a slow
            link sends less data in the same window rather than taking
            longer to finish).

    Returns:
        {"bytes": total bytes actually written, "seconds": elapsed time}.
        Since this is a reliable TCP stream, everything written is
        eventually received by the server (barring a mid-transfer
        failure) - the client's own byte count is what its measured rate
        is computed from, same as the server does on its side.
    """
    # Random, not zeros or a repeating pattern - some links (unlikely on
    # a home LAN, but not impossible over certain VPN/compression layers)
    # compress highly repetitive payloads in transit, which would report
    # a rate faster than the link can actually move arbitrary data.
    payload = os.urandom(_CHUNK_SIZE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        total = 0
        start = time.monotonic()
        while time.monotonic() - start < duration:
            sock.sendall(payload)
            total += len(payload)
        elapsed = time.monotonic() - start

    return {"bytes": total, "seconds": elapsed}


def format_rate(num_bytes: int, seconds: float) -> str:
    """Format a byte count and duration as a human-readable Mbps/MB/s rate."""
    if seconds <= 0:
        return "n/a"
    mbps = (num_bytes * 8) / seconds / 1_000_000
    mb_per_sec = num_bytes / seconds / 1_000_000
    return f"{mbps:.2f} Mbps ({mb_per_sec:.2f} MB/s)"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--serve", action="store_true", help="Listen for incoming throughput tests")
    mode.add_argument("--client", type=str, default=None, metavar="HOST", help="Run a throughput test against a --serve instance at HOST")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"TCP port to use (default: {DEFAULT_PORT})")
    parser.add_argument("--duration", type=float, default=5.0, help="How long the client sends data for, in seconds (default: 5.0)")
    parser.add_argument("--once", action="store_true", help="--serve only: exit after measuring a single connection")
    args = parser.parse_args()

    if args.serve:
        try:
            serve(port=args.port, once=args.once)
        except KeyboardInterrupt:
            print("\nStopped.")
        except OSError as exc:
            print(f"Error: couldn't listen on port {args.port} ({exc})")
            raise SystemExit(1)
    else:
        print(f"Sending to {args.client}:{args.port} for {args.duration:g}s ...")
        try:
            result = run_client(args.client, port=args.port, duration=args.duration)
        except OSError as exc:
            print(f"Error: couldn't connect to {args.client}:{args.port} ({exc})")
            raise SystemExit(1)
        print(f"Sent {result['bytes']:,} bytes in {result['seconds']:.2f}s ({format_rate(result['bytes'], result['seconds'])})")


if __name__ == "__main__":
    main()
