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
- [x] `tests/` — a real unit test suite (119 tests, one file per tool),
      replacing the ad hoc throwaway tests every round of development had
      used before. Favors real integration tests (a real TCP listener, a
      real self-signed TLS handshake, a real HTTP server, real temp files)
      over mocks wherever the thing being tested can run in a sandbox
      without root or a real network. Writing it surfaced one genuine bug
      caught by a real-filesystem test, not just asserted: `log_watcher.py`
      was returning an unterminated partial line as if it were complete,
      so its eventual completion showed up later as a spurious separate
      line — fixed with proper buffering before this was committed.
- [x] Fixed an unclosed-`SSLSocket` resource leak in
      `tests/test_cert_expiry_checker.py`'s real TLS handshake test (the
      server-thread helper closed the raw socket but not the SSL wrapper
      around it). Found by re-running the suite with
      `-W error::ResourceWarning`, not by inspection; confirmed clean
      under that flag afterward.
- [x] README: verified every documented flag against every script's
      actual `--help` output (automated diff, zero mismatches), and made
      every usage example consistently invoke `python3` instead of a mix
      of `python`/`python3` (the bare `python` form silently fails on
      systems where it isn't mapped to Python 3).

## Possible improvements

Findings from a general (non-adversarial) review of all 8 scripts, the
tests, and the docs. Grouped by priority, not by file.

**Worth doing soon:**

- [ ] `lan_file_server.py`: binding fails with a raw `PermissionError`/
      `OSError` traceback (e.g. `--port 80` without root, or a port
      already in use) instead of the friendly `SystemExit` every other
      script gives for a comparable setup failure. This is the script
      most likely to be run casually with a bad `--port`.
- [ ] `chmod +x` all 8 scripts — every one has a `#!/usr/bin/env python3`
      shebang but none are actually marked executable, so the shebang is
      currently dead weight.
- [ ] Add a CI workflow (e.g. GitHub Actions) running `python3 -m
      unittest` on push. Nearly free, and the suite already exists and
      passes locally — nothing currently enforces it stays that way.
      (Closes the "no CI" open question below.)
- [ ] `network_scanner.py`: add an `--ips-only` output mode (one bare IP
      per line). The README already claims it "pairs naturally" with
      `port_scanner.py`, but there's currently no actual mechanism to do
      that (`network_scanner.py` only prints a formatted table,
      `port_scanner.py` takes one positional host). `--ips-only` would
      make `network_scanner.py --ips-only | xargs -n1 port_scanner.py`
      work today without touching `port_scanner.py` at all.
- [ ] `--json` output mode for `network_scanner.py` (device list) and
      `cert_expiry_checker.py` (per-host status) — both have an obvious
      scripting/monitoring consumer and fit the stdlib-only philosophy
      (`json` is stdlib). Lower value for the other scripts.

**Nice-to-have:**

- [ ] `network_scanner.get_local_subnet()` doesn't catch `OSError` the
      way `lan_file_server.get_lan_ip()` does for the identical "guess my
      LAN IP via a UDP connect() trick" logic — a no-route environment
      crashes one script but not the other for the same operation.
- [ ] Meaningful exit codes for scripting: `network_scanner.py`,
      `port_scanner.py`, and `duplicate_finder.py` all exit 0 whether or
      not they found anything, making `if script ...; then` unusable.
      Only `cert_expiry_checker.py` currently has real exit codes.
- [ ] `KeyboardInterrupt` handling for the scripts whose single run can
      take a while (`duplicate_finder.py` on a big tree,
      `network_scanner.py`'s ping sweep, `port_scanner.py` on a large
      `--ports` range) — they dump a raw traceback on Ctrl+C, unlike the
      four continuously-running scripts, which all catch it and print
      "Stopped."
- [ ] State a minimum Python version somewhere (README or docstrings) —
      never written down anywhere today.
- [ ] A `requirements.txt` or `pyproject.toml` collecting the three
      optional deps (`scapy`, `pynetgear`, `rich`) in one installable
      place, instead of only discoverable by reading each script's README
      section individually.
- [ ] A small shared smoke test looping over all 8 scripts asserting
      `--help` exits 0 — current tests exercise the underlying functions
      thoroughly but don't uniformly exercise the actual argparse wiring
      around them, so a typo'd flag definition (duplicate name, bad
      `type=`) could in principle slip through.

**Considered and declined** (recorded so these don't get re-litigated):

- Extracting the duplicated "guess my LAN IP" / hostname-reverse-lookup
  snippets into a shared module — too small and too low-risk either way
  to be worth the coupling; these scripts are deliberately standalone and
  copy-paste-portable.
- A `--version` flag — nothing to report yet (no versioning scheme
  exists); add the scheme first if this ever matters.
- Config-file support (persisted default subnet, pinned ARP mappings,
  etc.) — adds a new failure mode (where is it, what overrides what) for
  marginal benefit in a single-user, ad hoc CLI context.
- A LICENSE file — low priority while this stays a personal-use local
  tool collection, not something distributed or shared publicly.
- Making the repo pip-installable (`setup.py`/entry points) — not
  actually a gap; "run with `python script.py`" is the intended shape,
  not an oversight.

## Ideas raised but not built

- [ ] iOS-side companion scripts (Pythonista/Pyto only — no raw sockets or
      `subprocess`): clipboard utility, EXIF/GPS stripper, QR/barcode
      scanner feeding a Shortcut. Left out because nothing in this sandbox
      can run or test actual Pythonista/iOS APIs — building it here would
      mean shipping untested code, unlike everything else on this list.

## Open questions

- `port_scanner.py`'s and `lan_file_server.py`'s defaults (200 concurrent
  workers; binding to `0.0.0.0`) are reasonable for a trusted home LAN but
  worth a second look before pointing either at anything less trusted.
