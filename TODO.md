# TODO

## Built

- [x] `network_scanner.py` — ARP/ping-sweep device discovery on the local subnet.
- [x] `bandwidth_dashboard.py` — live per-device bandwidth view, three sources
      (`sniff`, `conntrack`, `netgear`) depending on what the network/router
      supports.
- [x] `arp_spoof_detector.py` — passive ARP-spoofing detector (flap detection
      + pinned-mapping alerts) with a `--repair` static-ARP remediation flag.
- [x] `port_scanner.py` — TCP connect-scan for a single host, pairs with
      `network_scanner.py`.
- [x] `duplicate_finder.py` — hash-walks a directory tree to find duplicate
      files; report-only unless `--delete` is passed.
- [x] `cert_expiry_checker.py` — TLS certificate expiry checker for one or
      more hosts, with cron-friendly exit codes.
- [x] `log_watcher.py` — `tail -f`-style log watcher with regex alerting,
      handles log rotation/truncation.
- [x] `lan_file_server.py` — HTTP file share for the LAN; read-only by
      default, uploads opt-in via `--allow-upload`.
- [x] `README.md` — usage, flags, and caveats for all eight tools above.
- [x] `netcut_explained.pdf` — ARP spoofing / NetCut technical explainer
      (mechanism, Python deep-dive, OS platform reference, worked-example
      appendix). Delivered as a file, not committed to the repo.
- [x] Hardening pass (devil's-advocate subagent review + fixes) across the
      first three scripts:
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
- [x] `tests/` — a real unit test suite (~120 tests, one file per tool),
      replacing the ad hoc throwaway tests every round of development had
      used before. Favors real integration tests (a real TCP listener, a
      real self-signed TLS handshake, a real HTTP server, real temp files)
      over mocks wherever the thing being tested can run in a sandbox
      without root or a real network. Writing it surfaced one genuine bug
      caught by a real-filesystem test, not just asserted: `log_watcher.py`
      was returning an unterminated partial line as if it were complete,
      so its eventual completion showed up later as a spurious separate
      line — fixed with proper buffering before this was committed.

## Ideas raised but not built

- [ ] iOS-side companion scripts (Pythonista/Pyto only — no raw sockets or
      `subprocess`): clipboard utility, EXIF/GPS stripper, QR/barcode
      scanner feeding a Shortcut. Left out because nothing in this sandbox
      can run or test actual Pythonista/iOS APIs — building it here would
      mean shipping untested code, unlike everything else on this list.

## Open questions

- None of the eight scripts have CI configured to actually run `tests/`
  automatically (e.g. on push) — the suite exists and passes locally, but
  nothing enforces that it keeps passing as the repo grows.
- `port_scanner.py`'s and `lan_file_server.py`'s defaults (200 concurrent
  workers; binding to `0.0.0.0`) are reasonable for a trusted home LAN but
  worth a second look before pointing either at anything less trusted.
