# TODO

Ideas discussed but not yet implemented, for `network_scanner.py` and
`mobile_network_scanner.py`.

- [ ] **Notifications for `--watch` mode.** Right now a NEW-device alert
      only exists if someone is actively watching the terminal when it
      prints. Add a way to get pinged when something new shows up:
      - Default to a **webhook** POST (e.g. to Slack, or a push service
        like ntfy.sh) — most flexible, no extra dependency beyond
        `urllib`.
      - Optionally support email (needs SMTP config) or a desktop
        notification (needs a platform-specific library) as alternatives.

- [ ] **Export scan results to CSV/JSON.** A `--output results.json` (or
      `.csv`) flag to save each scan's results to a file, so they can be
      diffed with other tools or kept as a paper trail over time,
      independent of the known-devices registry already used for NEW
      markers.

- [x] **`--refresh-vendor-db` flag** (`network_scanner.py` only). Force a
      fresh download of the IEEE OUI registry instead of using the
      cached copy at `~/.cache/network_scanner_oui.txt`.
      Done: also fixed `_load_oui_registry()` to actually use the cache
      by default (it previously re-downloaded on every single run,
      contrary to what the README claimed, only falling back to cache
      if that download failed) — now a cached copy is used as-is unless
      `--refresh-vendor-db` is passed.

- [x] **"Missing device" report** (the inverse of the NEW marker).
      Report previously-known devices that didn't show up in this scan
      (e.g. a laptop that's asleep, something unplugged), using the
      first_seen/last_seen data the known-devices registry already
      tracks.
      Done: `_find_missing_devices()` in both scripts; also fixed a bug
      found while testing it, where `main()` called `_mark_new_devices()`
      without passing `known_devices_path` explicitly, so it silently
      used the function's own default-parameter binding instead of
      whatever the module-level `_KNOWN_DEVICES_PATH` was overridden to
      (harmless for normal use, but meant tests/overrides of that
      constant were quietly ignored).

- [ ] **Custom device labels/aliases.** A way to assign a friendly name
      to a MAC/IP (e.g. "Kitchen Echo") stored in the known-devices
      registry, shown instead of/alongside the hostname - useful for
      devices whose real hostname is cryptic or blank.

- [ ] **MQTT/Home Assistant presence publishing.** Let `--watch` publish
      device presence via MQTT discovery, so it can act as a real
      presence sensor in a home automation setup instead of just a
      terminal log.

- [ ] **Local web dashboard.** A small `http.server`-based page showing
      the live device table, glanceable from a phone browser while
      `--watch` runs on an always-on machine, instead of terminal-only
      output.

- [x] **IPv6 neighbor discovery.** Most ISPs now do dual-stack, so an
      IPv6-only device could go unseen by ARP/ping-based IPv4 scanning.
      Real scope increase: IPv6 uses ICMPv6 Neighbor Discovery (NDP)
      instead of ARP, and can't be brute-force enumerated like a /24
      the way IPv4 is - discovery instead means multicast-pinging the
      link-local all-nodes address (`ff02::1`) and reading back
      whatever answers land in the OS's neighbor cache.
      Done: `--ipv6` flag on `network_scanner.py` only (needs
      `subprocess`, which the iOS sandbox blocks anyway).
      Scoped intentionally: Linux/macOS only (Windows's neighbor-table
      command and format differ too much to be worth matching here),
      and no hostname resolution for IPv6 addresses this round -
      `mdns_reverse_lookup()` assumes IPv4-style `in-addr.arpa` reverse
      names, which don't apply to IPv6's `ip6.arpa` format. MAC vendor
      lookup works fine regardless, since it's IP-version-agnostic.
      Also had to widen the results table's IP column (18 → 42 chars)
      after testing showed a real IPv6 address running straight into
      the MAC column with no separating space.

- [x] **Banner grabbing on open ports** (`network_scanner.py`). Identification
      currently stops at "port 8443 is open" — actually reading what a
      service sends back (an HTTP `Server:` header, an SSH version
      string, etc.) often reveals a device outright without needing a
      browser.
      Done: `grab_banner()` — listens for an unprompted banner (SSH,
      FTP, etc.), sends a bare `HEAD /` for recognized HTTP(S) ports,
      and for everything else tries listening first, falling back to an
      HTTP probe if nothing arrived (many IoT admin UIs run HTTP on
      non-standard ports). Verified against real local HTTP servers,
      including one on an unrecognized port to confirm the fallback
      actually fires.

- [x] **Single-device "deep dive" mode** (`--identify IP`). The bulk scan
      is tuned for speed across up to 254 hosts, so it can't afford long
      timeouts or a wide port list. A dedicated one-off command could
      spend much more time investigating a single host: many more
      ports, a banner-grab on each open one, and the full hostname/
      vendor resolution chain — for exactly the kind of mystery device
      the bulk scan leaves unidentified.
      Done: `identify_device()` + `--identify IP` on `network_scanner.py`.
      Probes `_IDENTIFY_PORTS` (a much broader list than the bulk scan
      uses, since it's paid once per invocation rather than once per
      host in a /24), grabs a banner from each open one, gets a MAC via
      a direct single-host ARP request (falling back to ping + reading
      the ARP cache), and runs the same hostname/vendor resolution the
      bulk scan uses. Bypasses subnet resolution, known-device tracking,
      and `--watch` entirely - it's a one-off investigation, not a scan.

- [ ] **Port scanning for `network_scanner.py`.** It currently only does
      ARP/ping — no port info at all, unlike `mobile_network_scanner.py`'s
      `PORT_SERVICES` fingerprinting. Porting that over (as an optional
      supplement to ARP, not a replacement) would help identify
      blank-hostname devices the same way it already does on the phone.

- [ ] **Risky-port flagging.** Mark devices exposing things like telnet
      (23), unauthenticated RDP (3389), or SMB (445) with a visible
      warning — a basic home-network hygiene check. Cheap once port
      scanning (above) exists.

- [ ] **Colorized terminal output.** Green for NEW, dim/red for missing,
      using plain ANSI escape codes (no new dependency). Readability
      only, no functional change.
