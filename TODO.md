# TODO

## Built

- [x] `network_scanner.py` — ARP/ping-sweep device discovery on the local subnet.
- [x] `bandwidth_dashboard.py` — live per-device bandwidth view, three sources
      (`sniff`, `conntrack`, `netgear`) depending on what the network/router
      supports.
- [x] `arp_spoof_detector.py` — passive ARP-spoofing detector (flap detection
      + pinned-mapping alerts) with a `--repair` static-ARP remediation flag.
- [x] `README.md` — usage, flags, and caveats for all three tools above.
- [x] `netcut_explained.pdf` — ARP spoofing / NetCut technical explainer
      (mechanism, Python deep-dive, OS platform reference, worked-example
      appendix). Delivered as a file, not committed to the repo.
- [x] Hardening pass (devil's-advocate subagent review + fixes) across all
      three scripts:
      - `bandwidth_dashboard.py`: sniffer thread no longer dies silently on
        `PermissionError` (e.g. running without `sudo`) — now surfaces a
        clear error instead of showing "no traffic" forever; conntrack
        `RuntimeError`s (missing `sysctl`, permission denied) now exit with
        a friendly message instead of a raw traceback; the SSH conntrack
        path now has a timeout and `BatchMode=yes` so a first-run host-key
        prompt can't hang the process; `Stats.hostname_for()` is now
        actually lock-protected, matching its own docstring; the Netgear
        table's "Band" column (which was silently showing SSID) is now a
        correctly-labeled SSID column plus a real Link Type column.
      - `network_scanner.py`: added `--max-hosts` (default 4096) so a
        typo'd subnet like `/8` is rejected immediately instead of trying
        to sweep millions of hosts; invalid subnet strings now give a
        one-line error instead of a raw traceback; `scan()`'s ARP→ping
        fallback now catches any ARP-scan failure (was a narrow exception
        tuple that missed scapy-specific errors), with a printed reason.
      - `arp_spoof_detector.py`: `FlapDetector.last_seen` is now pruned
        (new `--stale-after`, default 300s) instead of growing one entry
        per unique source IP forever — notable because the realistic
        trigger is the exact attack this tool exists to catch (many
        forged source IPs); running without root now gives a friendly
        "are you running with sudo?" message instead of a raw traceback.

## Ideas raised but not built

Network tools brainstormed earlier that nothing above covers yet:

- [ ] Port scanner (pairs naturally with `network_scanner.py`'s device list)
- [ ] Duplicate file finder (hash-walk a directory tree)
- [ ] SSL/TLS certificate expiry checker for a list of hosts
- [ ] Log tailer/alerter (regex-match a log file, notify on hits)
- [ ] Local HTTP file server / LAN file-share utility
- [ ] iOS-side companion scripts (Pythonista/Pyto only — no raw sockets or
      `subprocess`): clipboard utility, EXIF/GPS stripper, QR/barcode
      scanner feeding a Shortcut

## Open question

- None of the three scripts have an automated test suite checked into the
  repo — every round of testing (including the hardening pass above) has
  been ad hoc, written and run during development, then discarded. This
  has now happened twice; worth adding a real `tests/` directory (even
  just the pure-logic unit tests — `FlapDetector`, `parse_conntrack_line`,
  `pin_arp_entry`'s command construction, etc. — none need real network
  access or root) the next time this repo is touched.
