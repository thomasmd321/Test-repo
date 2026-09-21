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

- [ ] **Port-change detection on known devices.** The known-devices
      registry already stores each device's last-matched port/hostname -
      diffing this scan's port against what's stored would flag "this
      device didn't have port 23 open last week," a sharper security
      signal than the static RISKY_PORTS check alone. Nearly free since
      all the data needed is already being collected; just needs a
      small registry-schema/diff addition.

- [ ] **Scan history log.** Beyond the known-devices registry's
      first_seen/last_seen pair, append each scan's snapshot to a
      rolling, capped/rotated log so "when did this device actually show
      up" can be answered, not just "is it new since last time." Really
      only pays off once CSV/JSON export (above) exists to look at it;
      needs a cap/rotation policy so the log doesn't grow unbounded.

- [x] ~~**TTL-based OS fingerprinting.**~~ Investigated and ruled out -
      not just for iOS, for any platform. The premise was wrong:
      `getsockopt(IPPROTO_IP, IP_TTL)` on a connected socket returns
      *this machine's own* outgoing TTL setting, not anything about the
      remote host - verified by connecting to two different real remote
      hosts and getting the same `64` back for both, regardless of what
      either one actually runs. The only route that reads a genuinely
      *received* TTL is `IP_RECVTTL` + ancillary data via `recvmsg()`,
      and that's a dead end too: Python's `socket` module doesn't expose
      the `IP_RECVTTL` constant at all, it's designed around UDP's
      per-datagram model rather than TCP's stream semantics, and the
      alternatives that do reliably work (reading an ICMP echo reply's
      TTL, or sniffing a SYN-ACK's IP header) need `subprocess`/`ping` or
      a raw socket either way - exactly what this idea was supposed to
      avoid, and exactly what iOS blocks regardless.

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

- [x] **Port scanning for `network_scanner.py`.** It currently only does
      ARP/ping — no port info at all, unlike `mobile_network_scanner.py`'s
      `PORT_SERVICES` fingerprinting. Porting that over (as an optional
      supplement to ARP, not a replacement) would help identify
      blank-hostname devices the same way it already does on the phone.
      Done: `DEFAULT_PORTS`/`probe_open_port()`/`_attach_open_ports()`,
      on by default (`--no-scan-ports` to skip, `--ports` to override).
      Hit a real forward-reference bug along the way: `scan_all_subnets()`
      used `DEFAULT_PORTS` as a parameter default before that constant
      was defined later in the file - Python evaluates default values
      at function-definition time, not call time, so this raised
      `NameError` at import. Fixed with a `None` sentinel resolved
      inside the function body instead of reordering large blocks of code.

- [x] **Risky-port flagging.** Mark devices exposing things like telnet
      (23), unauthenticated RDP (3389), or SMB (445) with a visible
      warning — a basic home-network hygiene check. Cheap once port
      scanning (above) exists.
      Done: `RISKY_PORTS`/`_find_risky_ports()`/`_attach_risky_ports()`,
      checked independently of the general port probe above (which
      stops at the first open port, so it could otherwise miss telnet
      entirely if port 80 happened to be checked first). On by default;
      `--no-risky-ports` to skip while keeping the general probe.

- [x] **Colorized terminal output.** Green for NEW, dim/red for missing,
      using plain ANSI escape codes (no new dependency). Readability
      only, no functional change.
      Done: `_use_color()` (respects `--no-color`, the `NO_COLOR` env
      var, and auto-disables when stdout isn't a terminal) and
      `_colorize()`. Real testing caught a genuine bug: nesting two
      `_colorize()` calls (e.g. a NEW device that's also risky) broke,
      since ANSI's reset code clears *all* active styling, not just the
      innermost color - the inner reset was killing the outer color
      partway through the line. Fixed by picking one color per row by
      priority (risky > new > plain) instead of nesting.

## `mobile_network_scanner.py`-specific

Several of the ideas above only got built for `network_scanner.py`. Most
don't apply to iOS at all (IPv6 discovery and MAC vendor lookup both need
`subprocess`/ARP, which the sandbox blocks), but a few use nothing beyond
plain sockets and are fully portable:

- [x] **Banner grabbing.** The standout item here - unlike mDNS/DNS-SD
      (confirmed completely blocked on iOS by `mdns_diagnostic.py`),
      banner grabbing is pure `socket`/`ssl`, the same primitives
      `probe_host()` already uses. Could have identified this session's
      actual mystery devices (`.26`, `.72`, etc.) without ever touching
      the thing iOS blocks.
      Done: ported `grab_banner()`/`_summarize_banner()` from
      `network_scanner.py` verbatim (same listen-first-then-HTTP-fallback
      strategy, same public `ssl.create_default_context()` +
      `check_hostname=False`/`verify_mode=CERT_NONE` pattern). Unlike the
      desktop version - where it's an `--identify IP` single-host deep
      dive - it's wired directly into `tcp_scan()`'s bulk scan here,
      since this script has no deep-dive mode; `--no-banners` skips it
      for a faster scan. Verified against real local HTTP servers on
      both a recognized port (8080) and an unrecognized one, confirming
      the fallback probe fires correctly on the latter.

- [x] **Risky-port flagging.** Pure TCP connect checks against a specific
      port list - no special privileges needed, and the port-probing
      infrastructure already exists in this script.
      Done: ported `RISKY_PORTS`/`_find_risky_ports()`/
      `_attach_risky_ports()` from `network_scanner.py` verbatim (plus a
      `_probe_tcp_port()` single-port helper the mobile script didn't
      have yet), checked independently of the general port probe like on
      desktop. Wired into `tcp_scan()`'s bulk scan; `--no-risky-ports` to
      skip. Verified end-to-end against a real loopback listener on port
      23 (telnet) that was deliberately excluded from `--ports`, and it
      still showed up in the risky-ports summary.

- [x] **Colorized output.** Plain ANSI codes; a-Shell's terminal renders
      them fine.
      Done: ported `_ANSI_CODES`/`_use_color()`/`_colorize()` from
      `network_scanner.py` verbatim, plus the same single-color-per-row
      priority rule (risky > new > plain) that fixed the desktop
      version's nested-reset bug. Verified end-to-end under a real pty
      (`script -qc ...`) with `cat -v`, confirming a single, correctly
      paired start/reset code per line and no color bleeding between
      rows.

- [ ] **Custom device labels/aliases** and **export scan results to
      CSV/JSON** (see the shared ideas above) - neither is platform-
      specific at all, both are just local file I/O.

Weaker fit, not started: a `--identify IP` deep-dive mode would work for
banner grabbing and a wider port list, but would be missing the MAC/
vendor half entirely (no ARP access on iOS) - a strictly smaller version
of the desktop one. MQTT/Home Assistant publishing and a local web
dashboard both assume something staying resident and reachable, which
doesn't fit a phone that isn't left running as a server.
