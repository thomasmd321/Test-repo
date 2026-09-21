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

- [ ] **IPv6 neighbor discovery.** Most ISPs now do dual-stack, so an
      IPv6-only device could go unseen by ARP/ping-based IPv4 scanning.
      Real scope increase: IPv6 uses ICMPv6 Neighbor Discovery (NDP)
      instead of ARP, and can't be brute-force enumerated like a /24
      the way IPv4 is - discovery instead means multicast-pinging the
      link-local all-nodes address (`ff02::1`) and reading back
      whatever answers land in the OS's neighbor cache.
