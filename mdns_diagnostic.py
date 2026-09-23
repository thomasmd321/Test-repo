#!/usr/bin/env python3
"""Diagnose whether mDNS multicast actually works from this device/app.

Run this directly (python3 mdns_diagnostic.py) and read the output -
it isolates each step (socket creation, bind, multicast join, send,
receive) so we can see exactly which one is failing, rather than
guessing from "no hostname" alone.
"""
import socket
import struct
import time

MDNS_GROUP = ("224.0.0.251", 5353)

print("Step 1: Can we even create a UDP socket?")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print("  OK")

print("Step 2: Can we bind to port 5353?")
try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("", 5353))
    print("  OK - bound to port 5353")
except OSError as e:
    print(f"  FAILED: {e!r}")

print("Step 3: Can we join the mDNS multicast group?")
try:
    req = struct.pack("4sl", socket.inet_aton(MDNS_GROUP[0]), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, req)
    print("  OK - joined 224.0.0.251")
except OSError as e:
    print(f"  FAILED: {e!r}")

def encode_name(name):
    parts = name.split(".")
    return b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"


print("Step 4: Can we send a UDP packet to the multicast group?")
try:
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    # A standard "list all service types" mDNS query - real devices on
    # the network should respond to this if mDNS is reachable at all.
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    qname = encode_name("_services._dns-sd._udp.local")
    question = qname + struct.pack(">HH", 12, 1)  # PTR, IN
    query = header + question
    sock.sendto(query, MDNS_GROUP)
    print(f"  OK - sent {len(query)} bytes")
except OSError as e:
    print(f"  FAILED: {e!r}")

print("Step 5: Do we receive ANYTHING back within 3 seconds?")
print("  (This should catch replies from EVERY mDNS device on your")
print("   network, not just Chromecasts - routers, printers, phones,")
print("   smart TVs, etc. all typically answer this query.)")
sock.settimeout(3.0)
received_any = False
deadline = time.monotonic() + 3.0
while time.monotonic() < deadline:
    try:
        data, addr = sock.recvfrom(4096)
        print(f"  GOT {len(data)} bytes from {addr}")
        received_any = True
    except socket.timeout:
        break
    except OSError as e:
        print(f"  FAILED: {e!r}")
        break

if not received_any:
    print("  Received nothing at all.")

sock.close()
print()
print("=" * 50)
if received_any:
    print("mDNS multicast IS working - something else is wrong.")
else:
    print("mDNS multicast is NOT reaching this device/app at all.")
    print("This points to a platform/permission restriction, not")
    print("anything fixable in the scanning script's Python code.")
