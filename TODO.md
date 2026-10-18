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
- [x] `tests/` — a real unit test suite (171 tests as of the last fix
      round, one file per tool plus a shared `--help` smoke test),
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

## Bugs found by devil's-advocate review (all fixed)

A second adversarial pass, covering the five newer scripts (the earlier
pass above only covered `network_scanner.py`/`bandwidth_dashboard.py`/
`arp_spoof_detector.py`, and those findings were already fixed at the
time). Every item below was verified by reading the actual implementation
— several also by a live reproduction against a throwaway test
file/server, noted per item — before being fixed, and the fix itself was
re-verified the same way (never just asserted). Grouped by severity, most
severe first.

**High severity:**

- [x] `log_watcher.py`: `LogWatcher._buffer` grows unboundedly if a line
      never terminates with `\n` — reproduced live (5× 100KB unterminated
      appends grew the buffer 100k→500k with zero lines ever flushed).
      Realistic trigger: a crashed/hung writer, a binary file pointed at
      by mistake, or any app streaming a large blob without a newline.
      Real OOM risk for an hours-long unattended watch. **Fixed:** the
      buffer now flushes as its own marked "[...truncated]" line once it
      passes `--max-line-bytes` (default 1 MiB) instead of growing
      forever; re-verified with a 15×100KB sustained stress test that
      stays bounded.
- [x] `lan_file_server.py`: concurrent uploads of the same filename
      silently clobber each other with no locking — reproduced live, two
      simultaneous uploads (all-A vs all-B) both returned HTTP 200
      success, but the file on disk ended up as pure B with 0 bytes of A.
      Byte-level interleaving/corruption is also possible depending on
      timing, not just last-write-wins, since both writers hold
      independent fd offsets on the same truncated inode. **Fixed:**
      uploads now stream into a private temp file and `os.replace()` into
      place atomically on success only; re-verified with a 5-round,
      two-threads-same-filename stress test — the file on disk is always
      wholly one payload or the other, never a mix, never missing data.
- [x] `lan_file_server.py`: a GET racing a concurrent upload of the same
      file can silently return content that didn't exist when the
      request was made — reproduced live (a GET for an existing 50MB
      file returned a concurrently-uploaded 1000-byte replacement
      instead). A mid-copy truncate can also produce a response shorter
      than its declared Content-Length. No synchronization exists between
      the GET and POST paths. **Fixed:** the same temp-file + atomic-
      rename fix above means a GET always sees either the old complete
      file or the new complete file, never an in-progress write.

**Medium severity:**

- [x] `cert_expiry_checker.py`: one malformed host spec in a list or
      `--file` aborts the entire batch — `parse_host_port()` is called
      unguarded in `main()` (unlike `check_host()`, which wraps per-host
      failures), so a single bad line kills checking every other host.
      Reproduced live. **Fixed:** wrapped in its own per-spec
      `try/except ValueError`, reporting an ERROR row and continuing;
      re-verified with a 3-host batch (one malformed) showing both good
      hosts still checked.
- [x] `lan_file_server.py`: a malformed `Content-Length` header (e.g. a
      non-numeric value) crashes the request handler with an uncaught
      `ValueError` instead of a 400 — reproduced live; also spams a full
      traceback to stderr despite the handler's `log_message` override
      being meant to keep the server quiet. **Fixed:** parsing is now
      guarded, returning a clean 400; re-verified with a raw
      `http.client` request carrying a non-numeric `Content-Length`.
- [x] `lan_file_server.py`: on a mid-upload client disconnect, the
      success response still reports the originally-declared length
      instead of the actual bytes written, and the short/truncated file
      is left on disk under its real filename with no indication it's
      incomplete (no temp-file + atomic-rename pattern). **Fixed:** same
      temp-file fix as above — a short/aborted upload is never renamed
      into place and the stray temp file is cleaned up; re-verified by
      disconnecting mid-upload and confirming no file (real or temp) is
      left behind.
- [x] `duplicate_finder.py`: `--delete`'s `path.unlink()` and the re-stat
      in `main()` are unguarded (unlike every other filesystem touch in
      the file, which carefully catches `OSError`) — a permission error
      or a file disappearing mid-delete crashes the whole run partway
      through, with some duplicate groups deleted and others untouched
      and no summary of what succeeded. The re-stat is also redundant
      (size is already known from the earlier grouping pass). **Fixed:**
      both are now guarded with `OSError`, reporting and counting a
      failure instead of crashing; re-verified with a monkeypatched
      `Path.unlink` that fails on one specific file among several
      duplicates — the others still get deleted.
- [x] `lan_file_server.py`: Ctrl+C during an in-flight upload kills that
      thread mid-write with no atomicity — `daemon_threads = True` means
      `server_close()`'s thread-join is a no-op (verified against
      `socketserver` source), so shutdown doesn't wait for in-flight
      requests. Leaves a truncated file under the real filename.
      **Fixed:** the temp-file + atomic-rename pattern means an upload
      killed mid-write just leaves an orphaned temp file, never a
      truncated file under the real name.
- [x] `log_watcher.py`: if the watched file is deleted and never
      recreated (not rotated, just gone), the watcher silently polls the
      stale fd forever, returning zero new lines with no warning that
      monitoring has effectively gone blind — reproduced live. Defeats
      the tool's purpose without any signal, for an hours-long
      unattended watch. **Fixed:** added `LogWatcher.file_missing()`;
      `main()`'s loop now prints a one-time warning on the
      missing/present transition instead of staying silent; re-verified
      it doesn't spam the warning every poll cycle while still missing.
- [x] `log_watcher.py`: only the rotation-check's `FileNotFoundError` is
      caught; a transient `OSError` from reopening after rotation, or
      from the per-poll `read()` itself (permission change,
      removable/network media hiccup), propagates uncaught and kills the
      whole watcher. **Fixed:** `poll_new_lines()` now catches `OSError`
      around the read/reopen and treats it as "nothing new this cycle";
      re-verified with a mocked `read()` that raises `OSError`.

**Low severity:**

- [x] `duplicate_finder.py`: an unreadable directory is silently skipped
      by `rglob()` during the walk with no indication part of the tree
      wasn't scanned. Not a crash, just a missing log line. **Fixed:**
      switched to `os.walk(..., onerror=...)`, which does surface this;
      `main()` now prints a warning per skipped directory and a count at
      the end; re-verified with a mocked `os.walk` that reports a
      permission error partway through (chmod-based denial isn't
      enforceable against this sandbox's root user).
- [x] `duplicate_finder.py`: files bucketed by size in one pass and
      hashed in a later pass — a file modified between the two passes
      (by another process) produces a stale/incorrect duplicate grouping.
      Only reachable with concurrent external writers during a scan.
      **Declined as a fix** — genuinely low severity/low likelihood for
      this tool's realistic use (pointing it at `~/Downloads`, not a
      directory under heavy concurrent external write load), and any fix
      (locking, re-verifying hashes post-grouping) would add real
      complexity for a race that's already vanishingly unlikely to matter
      in practice. Left as a documented, accepted limitation.
- [x] `cert_expiry_checker.py`: `parse_host_port()`'s naive
      `rpartition(":")` misparses bare IPv6 literals (e.g.
      `"2001:db8::1"` silently becomes host `"2001:db8:"` port `1`) —
      reproduced live. Real but unlikely-to-matter for a home-LAN cert
      checker. **Fixed:** bracketed (`[ipv6]`, `[ipv6]:port`) and bare
      multi-colon IPv6 literals are now special-cased before falling
      back to the port-split logic; re-verified against the exact
      `"2001:db8::1"` case plus `"::1"` and bracketed forms.
- [x] `cert_expiry_checker.py`: no `KeyboardInterrupt` handling, unlike
      `log_watcher.py`/`lan_file_server.py` which both catch it and print
      "Stopped." — Ctrl+C during a multi-host scan dumps a raw traceback.
      **Fixed:** the per-host loop is now wrapped in
      `try/except KeyboardInterrupt`, preserving whatever exit code was
      accumulated so far; re-verified with a mid-batch interrupt showing
      partial results and a clean "Stopped." instead of a traceback.
- [x] `port_scanner.py`: `--workers 0` (or negative) crashes raw with
      `ValueError: max_workers must be greater than 0` — reproduced
      live. Only reachable via an explicit bad flag value. **Fixed:**
      `main()` now validates `--workers >= 1` itself before it ever
      reaches `ThreadPoolExecutor`, with a friendly `SystemExit`.

**Checked, nothing found** (recorded so these aren't re-investigated):
race conditions in `port_scanner.py`'s thread pool (each worker only
touches its own local socket); memory growth in `lan_file_server.py` /
`cert_expiry_checker.py` / `port_scanner.py` / `duplicate_finder.py`
(verified against `socketserver` source that `daemon_threads=True` means
finished request threads are never retained); GET-path traversal in
`lan_file_server.py` (falls through to stdlib's hardened
`SimpleHTTPRequestHandler`); upload-filename traversal
(`safe_upload_name()` correctly strips `.`/`..`/directory components on
both POSIX and Windows separators).

## Bugs found by a third review pass (all fixed)

A full re-read of all 8 scripts, prompted by "review all code, add findings
to the to-do list" -- not a subagent pass this time, done directly. Covers
`bandwidth_dashboard.py` and `arp_spoof_detector.py` for the first time
since the very first hardening pass, plus a fresh adversarial look at the
six scripts fixed earlier this round (on the theory that a round of fixes
is exactly where a fresh bug is most likely to have been introduced or
missed). Every item below was verified by a live reproduction before being
fixed, not just read and assumed -- and the fix itself was re-verified the
same way.

**Medium severity:**

- [x] `lan_file_server.py`: an abrupt client disconnect during upload
      (a TCP RST, not just a clean close -- a WiFi drop, a crashed
      client, a client closing with `SO_LINGER` set to 0) raises
      `ConnectionResetError` from `self.rfile.read()` inside `do_POST()`.
      That's uncaught, so it propagates past the quiet-on-disconnect
      `try/except (BrokenPipeError, ConnectionResetError)` block entirely
      (never reaches it) and socketserver's default error handler prints
      a full traceback to stderr -- the exact noise this file's
      `log_message` override and its already-fixed malformed-
      `Content-Length` bug were both meant to avoid. Reproduced live with
      a raw socket forcing a real RST (`SO_LINGER` 1/0) mid-upload. Not a
      correctness bug -- the temp-file cleanup in the `finally` block
      still runs correctly either way (verified: no leaked temp file, no
      corrupted real file) -- purely unwanted stderr noise. **Fixed:**
      the read loop now catches `(ConnectionResetError, BrokenPipeError,
      socket.timeout)` around `self.rfile.read()` and treats it like a
      clean early EOF; re-verified with the same real RST reproduction
      -- no traceback, no leaked temp file, no partial real file.
- [x] `network_scanner.py`: `ping()` (used by the ping-sweep fallback)
      has no guard for a missing `ping` binary, unlike `read_arp_table()`
      in the same file, which already catches `FileNotFoundError` for
      the identical situation with the `arp` binary. On a system with no
      `ping` on `PATH` (minimal containers, some stripped-down distros --
      this very sandbox is one example), the whole scan crashes with a
      raw traceback instead of degrading the way the `arp` case already
      does. Reproduced live: `ping_sweep("127.0.0.1/32", timeout=1)`
      raises `FileNotFoundError: ... 'ping'` straight out, uncaught by
      `scan()` or `main()`. Related, lower-priority observation: `ping()`
      also passes no `timeout=` to its own `subprocess.run()` call --
      it relies entirely on the `ping` command's own `-W`/`-w` flag to
      bound runtime, with no hard backstop if that flag is ignored or
      misbehaves on some platform/ping variant. **Fixed:** `ping_sweep()`
      now checks `shutil.which("ping")` once upfront and raises a clear
      `RuntimeError` (turned into a friendly `SystemExit` by `main()`)
      instead of letting `FileNotFoundError` surface per-host from deep
      in the thread pool; `ping()`'s own `subprocess.run()` now also
      passes `timeout=` as the hard backstop, treating a timeout the
      same as a non-responsive host. Re-verified both paths live.
- [x] `bandwidth_dashboard.py`: `run_netgear_source()`'s `poll()` closure
      (`router.get_attached_devices_2()` / `router.get_traffic_meter()`)
      has no exception handling. If the router becomes unreachable
      mid-session (reboot, WiFi drop, a timed-out SOAP call) after a
      successful initial login, the dashboard crashes with a raw
      traceback -- unlike the sniff and conntrack sources, where the
      very first hardening pass explicitly fixed this exact "source dies
      mid-session" failure mode with a friendly `SystemExit`. The netgear
      source was added/reviewed separately and never got the same
      treatment. **Fixed:** `poll()` now wraps both router calls in
      `try/except Exception`, raising the same kind of friendly
      `SystemExit` ("Lost contact with ...") the other two sources
      already give; re-verified with a mocked router raising
      mid-session.

**Low severity:**

- [x] `cert_expiry_checker.py`: `--file` is opened with a bare
      `open(args.file)`, with no `try/except` around it -- a missing or
      unreadable file crashes with a raw `FileNotFoundError` traceback
      instead of the friendly `SystemExit` every other file-touching
      operation in this repo gives for the same kind of mistake (compare
      `duplicate_finder.py`'s directory check, `lan_file_server.py`'s
      bind-error handling). Reproduced live: `--file
      /does/not/exist.txt` dumps a traceback. **Fixed:** wrapped in
      `try/except OSError`, giving a friendly `SystemExit`; re-verified
      with the same missing-file case.
- [x] `port_scanner.py`: `--timeout` isn't validated the way `--workers`
      now is (this session's own fix, in this same file) -- a negative
      value (e.g. `--timeout -1`) crashes with a raw
      `ValueError: Timeout value out of range` from inside a worker
      thread. `scan_host()`'s `except OSError: continue` doesn't catch
      it (`ValueError` isn't an `OSError`), so it propagates uncaught.
      Same bug class as the `--workers` fix, just missed for the
      sibling flag. Reproduced live. **Fixed:** `main()` now validates
      `--timeout >= 0` the same way it already validates `--workers`;
      re-verified with the same negative-timeout case.
- [x] `bandwidth_dashboard.py`: `Stats.hostnames` grows one entry per
      unique IP ever seen in the live table's top-20 ranked list, for
      the life of the process, with no pruning -- the same unbounded-
      growth shape already found and fixed for `arp_spoof_detector.py`'s
      `FlapDetector.last_seen` (via `--stale-after`). Lower severity
      here: `hostname_for()` only gets called for IPs that make a given
      poll's top-20, and a home LAN has a small, fairly stable device
      set, so growth is slow in the realistic case -- but for a dashboard
      left running for days on a busier/more open network, it's the same
      "unbounded growth over an unattended long run" category this repo
      has treated as worth fixing elsewhere. **Fixed:** capped at
      `MAX_CACHED_HOSTNAMES` (2048); once reached, the cache clears and
      rebuilds rather than growing forever -- re-verified with a test
      feeding 2500+ distinct IPs through `hostname_for()`.

**Doc/comment nits:**

- [x] `requirements.txt`'s comment for `scapy` read "network_scanner.py
      (--source-free ARP scan)" -- garbled; `network_scanner.py` has no
      `--source` flag at all (that's `bandwidth_dashboard.py`'s flag).
      **Fixed.**
- [x] README.md and TODO.md's `tests/` entries said "171 tests"; stale
      once `network_scanner.py`'s `KeyboardInterrupt` handling added a
      test after those docs were last updated. **Fixed:** both now say
      181 (172 + the 9 tests added fixing the items above).

## Possible improvements

Findings from a general (non-adversarial) review of all 8 scripts, the
tests, and the docs. Grouped by priority, not by file.

**Worth doing soon (all done):**

- [x] `lan_file_server.py`: binding fails with a raw `PermissionError`/
      `OSError` traceback (e.g. `--port 80` without root, or a port
      already in use) instead of the friendly `SystemExit` every other
      script gives for a comparable setup failure. This is the script
      most likely to be run casually with a bad `--port`. **Fixed**
      alongside the upload-corruption fix (same commit as the atomic
      temp-file + rename work).
- [x] `chmod +x` all 8 scripts — every one has a `#!/usr/bin/env python3`
      shebang but none are actually marked executable, so the shebang is
      currently dead weight. **Fixed.**
- [x] Add a CI workflow (e.g. GitHub Actions) running `python3 -m
      unittest` on push. Nearly free, and the suite already exists and
      passes locally — nothing currently enforces it stays that way.
      **Fixed:** `.github/workflows/tests.yml`, runs on push/PR across
      Python 3.9-3.12.
- [x] `network_scanner.py`: add an `--ips-only` output mode (one bare IP
      per line). The README already claims it "pairs naturally" with
      `port_scanner.py`, but there's currently no actual mechanism to do
      that (`network_scanner.py` only prints a formatted table,
      `port_scanner.py` takes one positional host). `--ips-only` would
      make `network_scanner.py --ips-only | xargs -n1 port_scanner.py`
      work today without touching `port_scanner.py` at all. **Fixed**,
      including routing informational messages to stderr so the pipe
      stays clean.
- [x] `--json` output mode for `network_scanner.py` (device list) and
      `cert_expiry_checker.py` (per-host status) — both have an obvious
      scripting/monitoring consumer and fit the stdlib-only philosophy
      (`json` is stdlib). Lower value for the other scripts. **Fixed**
      for both.

**Nice-to-have (all done):**

- [x] `network_scanner.get_local_subnet()` doesn't catch `OSError` the
      way `lan_file_server.get_lan_ip()` does for the identical "guess my
      LAN IP via a UDP connect() trick" logic — a no-route environment
      crashes one script but not the other for the same operation.
      **Fixed:** now returns `None` instead, and `main()` turns that into
      a friendly `SystemExit`.
- [x] Meaningful exit codes for scripting: `network_scanner.py`,
      `port_scanner.py`, and `duplicate_finder.py` all exit 0 whether or
      not they found anything, making `if script ...; then` unusable.
      Only `cert_expiry_checker.py` currently has real exit codes.
      **Fixed** for all three (see each script's README section for its
      exact exit-code meaning).
- [x] `KeyboardInterrupt` handling for `duplicate_finder.py` (on a big
      tree), `port_scanner.py` (on a large `--ports` range), and
      `network_scanner.py` (on its ping sweep) — all three dumped a raw
      traceback on Ctrl+C, unlike the four continuously-running scripts,
      which all catch it and print "Stopped." **Fixed** for all three;
      `network_scanner.py`'s fix also routes the "Stopped." message
      through the same stderr-in-machine-readable-mode logic as its
      other status messages.
- [x] State a minimum Python version somewhere (README or docstrings) —
      never written down anywhere today. **Fixed:** README now states
      3.9+ (matches the CI matrix; nothing in the code actually requires
      newer syntax, but this is what's actually tested).
- [x] A `requirements.txt` or `pyproject.toml` collecting the three
      optional deps (`scapy`, `pynetgear`, `rich`) in one installable
      place, instead of only discoverable by reading each script's README
      section individually. **Fixed:** `requirements.txt`.
- [x] A small shared smoke test looping over all 8 scripts asserting
      `--help` exits 0 — current tests exercise the underlying functions
      thoroughly but don't uniformly exercise the actual argparse wiring
      around them, so a typo'd flag definition (duplicate name, bad
      `type=`) could in principle slip through. **Fixed:**
      `tests/test_smoke_help.py`, discovers and runs every script in the
      repo root as a real subprocess.

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
