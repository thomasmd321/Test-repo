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
