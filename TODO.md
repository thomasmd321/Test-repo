# TODO

Ideas discussed but not yet implemented, for `network_scanner.py` and
`mobile_network_scanner.py`.

- [x] **Notifications for `--watch` mode.** Right now a NEW-device alert
      only exists if someone is actively watching the terminal when it
      prints. Add a way to get pinged when something new shows up:
      - Default to a **webhook** POST (e.g. to Slack, or a push service
        like ntfy.sh) — most flexible, no extra dependency beyond
        `urllib`.
      - Optionally support email (needs SMTP config) or a desktop
        notification (needs a platform-specific library) as alternatives.
      Done: `send_webhook_notification()` + `_build_notification_message()`
      in both scripts, plus `--notify-webhook URL`. Fires on the same
      trigger `--quiet` uses (a NEW device, a port change, a missing
      device, or a risky port) - a boring scan sends nothing. POSTs
      `{"text": message}` JSON, the format Slack's incoming webhooks (and
      many other generic receivers) expect directly, deliberately not
      special-cased per service (Discord's `content` key, ntfy.sh's
      plain-text body) - kept to one simple, documented format rather
      than branching on the target URL. A failed/unreachable webhook
      warns to stderr and never crashes the scan. Email/desktop
      notifications not implemented - the webhook covers the
      no-extra-dependency case the TODO called out as the default, and
      both alternatives need something (SMTP config, a platform-specific
      library) neither script currently has any reason to carry.
      Verified end-to-end against a real local HTTP server acting as a
      webhook receiver, on both scripts: a NEW device delivered the
      correct JSON payload, a repeat scan with nothing changed sent
      nothing at all, a port change re-triggered delivery with the
      correct old->new summary, and an unreachable URL printed a warning
      without crashing the scan.

- [x] **Export scan results to CSV/JSON.** A `--output results.json` (or
      `.csv`) flag to save each scan's results to a file, so they can be
      diffed with other tools or kept as a paper trail over time,
      independent of the known-devices registry already used for NEW
      markers.
      Done: `export_results()`/`_export_json()`/`_export_csv()` in both
      scripts, plus `--output FILE`. Format is chosen by FILE's
      extension (`.csv` for CSV, anything else - typically `.json` -
      for JSON), rather than a separate `--format` flag, since the
      extension already says which one you want. A list field
      (`risky_ports`) is flattened to a `;`-separated string for CSV
      (real cells can't hold a list) but stays a proper array in JSON.
      Each run overwrites FILE with a snapshot of that scan alone - not
      an appended history log (see "Scan history log" below, which
      would build on this). Verified end-to-end through the actual
      `main()` CLI path against a real loopback listener, for both
      formats, on both scripts.

- [x] **Port-change detection on known devices.** The known-devices
      registry already stores each device's last-matched port/hostname -
      diffing this scan's port against what's stored would flag "this
      device didn't have port 23 open last week," a sharper security
      signal than the static RISKY_PORTS check alone. Nearly free since
      all the data needed is already being collected; just needs a
      small registry-schema/diff addition.
      Done: `_find_port_changes()` in both scripts, comparing each
      device's current port against what `_mark_new_devices()` last
      persisted - must run *before* that call, since it overwrites the
      registry with the new value. A `CHG` row marker (yellow;
      mutually exclusive with `NEW` by construction - a device with no
      prior registry entry can't have a "changed" port) plus a summary
      section listing old→new for each changed device.
      `network_scanner.py` wasn't even persisting `port` in the registry
      before this (only `mobile_network_scanner.py` was) - added that
      too. Verified end-to-end on both scripts: ran a real scan against
      a loopback listener on one port, killed it, started a second
      listener on a different port, rescanned, and confirmed the real
      `_find_port_changes()`/`_mark_new_devices()` pair (and the full
      `main()` print path, under a real pty for color) correctly
      reported the old→new port and left the device correctly
      unflagged as NEW.

- [x] **Scan history log.** Beyond the known-devices registry's
      first_seen/last_seen pair, append each scan's snapshot to a
      rolling, capped/rotated log so "when did this device actually show
      up" can be answered, not just "is it new since last time." Really
      only pays off once CSV/JSON export (above) exists to look at it;
      needs a cap/rotation policy so the log doesn't grow unbounded.
      Done: `append_scan_history()`/`_trim_scan_history()` in both
      scripts, plus `--log-history FILE` and `--history-max-entries N`
      (default 200). Appends one JSON line per scan
      (`{"timestamp": ..., "devices": [...]}`) rather than rewriting the
      whole file every run, and only rewrites the file at all once it's
      actually over the cap (verified with a test that patches
      `Path.write_text` and asserts it's never called while under the
      cap - append-only stays append-only). A failed write (unwritable
      directory, full disk) is swallowed the same way `--output` already
      handles export failures, rather than crashing the scan.

- [x] **Parallel multi-subnet scanning.** `--all-subnets` scans each
      subnet one at a time - for someone with several VLANs, running
      them concurrently instead (the same `ThreadPoolExecutor` pattern
      already used for per-host/per-port work) would cut wall-clock time
      roughly proportional to subnet count.
      Done: `scan_all_subnets()` (`network_scanner.py` only - the mobile
      script has no multi-subnet auto-detection to parallelize) now runs
      each subnet's `scan()` + hostname resolution in its own
      `ThreadPoolExecutor` worker instead of a sequential loop, merging
      into the final `devices_by_ip` dict only in the main thread as each
      future completes, so nothing but the main thread ever writes to
      it. `max_subnet_workers` (default 8) caps concurrency; not exposed
      as a CLI flag, same as every other internal `max_workers` tuning
      constant in this file (`ping_sweep`, port scanning, etc.). Can't be
      verified against real concurrent ARP scans in this sandbox (its
      scapy/cryptography install is broken - see `--doctor`), so this was
      validated with mocked `scan()` calls using real `time.sleep()`
      delays and wall-clock timing assertions instead: one test confirms
      4 subnets that each "take" 0.2s finish in well under 0.8s with
      `max_subnet_workers=4`, and a second confirms the same 3 subnets
      *do* serialize (>= 0.45s) when `max_subnet_workers=1` - proving the
      executor/merge mechanics actually run concurrently and that the
      worker cap is respected, though scapy's own thread-safety under
      real concurrent scans remains unverified against real hardware.

- [x] **`--exclude IP/CIDR`.** Skip specific addresses from a scan (a
      printer that crashes under port probes, a NAS you don't want woken
      from sleep) without having to narrow the whole subnet just to dodge
      one host.
      Done: `_parse_exclusions()`/`_is_excluded()` in both scripts, plus
      `--exclude LIST` (comma-separated IPs and/or CIDR ranges; a bare IP
      is treated as a /32). On `mobile_network_scanner.py`, exclusion is
      complete - excluded hosts are dropped from `tcp_scan()`'s host list
      before any TCP connection is attempted at all. On
      `network_scanner.py`, true per-host exclusion isn't possible for
      the ARP path: scapy's `srp()` broadcasts one ARP request across the
      whole subnet in a single call, with no way to carve individual
      addresses out of that broadcast - documented as an accepted
      limitation. Excluded devices are still dropped immediately after
      discovery, though, before vendor lookup, port scanning, the
      risky-ports check, and the final report/export/tracking/history, so
      in practice nothing beyond that one broadcast packet reaches them;
      the ping-sweep fallback has no equivalent broadcast step to route
      around, so it pings every host and filters after, same point in the
      pipeline as the ARP path. A malformed `--exclude` value surfaces as
      a clean `argparse` error (exit code 2), not a raw traceback.

- [x] **Shell completion.** A bash/zsh completion script for tab-completing
      flag names - each script has 18+ of them now, easy to half-remember.
      No new runtime dependency needed: a small static completion script
      (`complete -W "..."`) covers it without wiring up `argcomplete`.
      Done: `completions.bash`, with one `complete -F` function per
      script, hand-listing each script's flags (cross-checked against
      each script's actual `--help` output). Only completes flag names,
      not their arguments (a subnet, a port list, a file path all being
      arbitrary), and only fires for a *direct* invocation matching a
      script's own name - `./network_scanner.py` or the bare name on
      PATH, which needed `chmod +x` on all three scripts to even be
      possible. Does NOT work for `python3 network_scanner.py <TAB>`:
      bash keys completion registration off `COMP_WORDS[0]`, which is
      `python3` in that case, not the script - documented honestly in the
      completion script's own header rather than attempting a fragile
      workaround (hijacking every `python3 ...` command's completion
      would break completion for any other Python script being run).
      Static, not generated from argparse at runtime, so it can drift out
      of sync if a flag changes without updating this file too - a
      documented tradeoff against the extra dependency `argcomplete`
      would add.

- [x] **IP-conflict / spoofing alert.** Flag when the same IP shows a
      different MAC across scans than what the known-devices registry
      last recorded - a real class of network issue (a DHCP lease
      reassignment, or something spoofing another device's IP - most
      notably the gateway's own address) that today produces no signal
      at all, even though the registry already has everything needed to
      detect it.
      Done (`network_scanner.py` only - `mobile_network_scanner.py` has
      no MAC to compare against at all, see its own `_device_identity()`
      docstring): `_is_mac_address()` + `_find_ip_conflicts()`, run
      before `_mark_new_devices()` overwrites the registry, the same
      ordering `_find_port_changes()` already needs and for the same
      reason. Builds a reverse IP->MAC index from the registry, restricted
      to entries actually keyed by a real MAC (`_is_mac_address()`, an
      exact six-group hex-colon match - a plain "contains a colon" check
      would misfire on an IPv6 fallback identity, which also contains
      colons but in a different format) so a ping-sweep-only device's
      IP-shaped identity never gets treated as a conflicting MAC. Flagged
      devices get a magenta row (`_ANSI_CODES["magenta"]`, new) and a
      summary section explaining the finding, wired into
      `_build_notification_message()` and `--quiet`'s signal check
      alongside NEW/CHG/missing/risky. Deliberately framed as a hygiene
      signal, not an intrusion-detection system: a home router handing a
      freed-up lease to a new device produces the exact same signal as
      real spoofing, so the summary text calls out the gateway's own IP
      specifically as the one case worth treating as urgent. Verified
      against the real (unmocked) registry read/write path end-to-end
      through `main()` itself: seeded the registry with one real
      `_mark_new_devices()` call, then ran the actual CLI with
      `scan_all_subnets()` faked to return a second MAC at the same IP -
      confirmed the NEW marker, the missing-device report, and the new
      IP-handoff section all fired correctly together, that a repeat scan
      of an unchanged device produces zero false positives, and that
      `--quiet` stays fully silent on that unchanged rescan.

- [ ] **`--diff-only` watch mode.** Instead of reprinting the full results
      table on every `--watch` tick, print just what changed since the
      previous tick - reusing `scan_diff.py`'s comparison logic against
      the last entry in the scan history log (see "Scan history log"
      above) rather than the full table every time. Complements `--quiet`
      (which suppresses a *boring* tick entirely) by making an
      *interesting* tick's output shorter too.

- [ ] **Config file / profiles.** With 20+ flags per script now, a saved
      profile (e.g. `--profile home`, reading from
      `~/.network_scanner.toml` or similar) would beat retyping a long
      `--exclude ... --ports ... --log-history ...` combination every
      time. CLI flags should still override whatever the profile sets, so
      a one-off scan doesn't require editing the file first. Needs care
      to keep argparse's own defaults/help text as the single source of
      truth for what's configurable, rather than drifting out of sync
      with a second, separately-maintained schema.

- [x] **`--retries N`.** A single dropped ARP/ping reply (or one flaky TCP
      connect on the mobile script) currently makes a live device look
      "missing" this run and "NEW" again next run, which pollutes every
      registry-based feature - NEW/CHG/missing tracking, the IP-conflict
      alert above, and webhook notifications all inherit that false
      signal. A cheap re-probe before finalizing results should catch the
      common transient case.
      Done: `scan()` in `network_scanner.py` gained a `retries` parameter
      - each retry re-runs whichever method (ARP or ping-sweep) actually
        worked the first time, as a fresh subnet-wide pass, merging any
        newly-answering IP into the result. Re-running the *whole*
        broadcast rather than targeting only the missing hosts individually
        is deliberate: scapy's raw sockets aren't necessarily safe to hit
        concurrently from several targeted single-host requests (the same
        caveat "Parallel multi-subnet scanning" above already documents),
        so a second full broadcast is the simple, safe option, even though
        it's less targeted.
      `tcp_scan()` in `mobile_network_scanner.py` gained the same
      parameter but a more targeted implementation: each retry only
      re-probes hosts still missing a match (already-found hosts aren't
      re-probed), since this script talks to each host individually over
      plain TCP rather than one subnet-wide broadcast - concurrent TCP
      connects don't share network_scanner.py's raw-socket safety concern.
      Both default to 0 (a single pass), preserving prior behavior exactly.
      `--retries N` added to both CLIs. Verified end-to-end through the
      real `main()` CLI path on both scripts: a flaky discovery function
      that misses a known device on its first call but answers from the
      second call on correctly shows the device as present (not missing,
      not falsely re-flagged NEW) with `--retries 1`, and correctly shows
      it as missing with the default of 0 retries - confirmed by call-count
      assertions on the underlying (unmocked report/registry) scan path.

- [ ] **Prometheus textfile export (`--metrics-file`).** Write scan counts
      (device count, new count, risky count, IP-conflict count) in
      Prometheus exposition format to a file, so `node_exporter`'s
      textfile collector can pick it up - turns any `--watch` box into a
      Grafana-graphable metric with no new runtime dependency. Reuses the
      same data the scan history log and webhook notification already
      compute; mostly a matter of formatting it differently.

- [ ] **Known-devices registry export/import.** A way to back up or move
      `~/.cache/network_scanner_known_devices.json` (and its
      `mobile_network_scanner.py` equivalent) to a new machine, since
      labeling effort (see "Custom device labels/aliases") currently
      lives only on the one box that ran `--set-label`. Simplest version
      is probably just documenting "it's a plain JSON file, copy it" -
      worth checking whether that's actually enough before building
      dedicated import/export flags around it.

- [x] **mDNS/DNS-SD service browser.** The other two scripts only ever ask
      mDNS one narrow question at a time (a specific IP's hostname, or
      whether anything answers as a Chromecast) - a standalone tool that
      asks the broader "what services exist on this network at all"
      question would surface printers, AirPlay speakers, HomeKit
      accessories, and anything else advertising itself, without needing
      to already know an IP or guess a service type first.
      Done: `mdns_browser.py`, a new standalone script. Uses DNS-SD's own
      "meta-query" (`_services._dns-sd._udp.local`, RFC 6763 §9) to
      discover which service types are actually in use, unioned with a
      small built-in list (`_COMMON_SERVICE_TYPES`) since not every
      device implements the meta-query even when it implements browsing
      for its own type. Browses every resulting type on one shared
      socket rather than paying a full timeout per type. The mDNS wire-
      format code (`_encode_dns_name`/`_decode_dns_name`/
      `_build_mdns_ptr_query`/`_iter_mdns_records`/
      `_collect_service_records`) is duplicated from
      `mobile_network_scanner.py` rather than imported, same as every
      other script here - see this file's own module docstring. Shares
      the same iOS Local Network Privacy limitation as the mDNS code in
      the other two scripts. Verified two ways: a real, unmocked
      end-to-end test - a second local thread acting as a genuine mDNS
      responder over real multicast sockets (loopback multicast works in
      this environment; confirmed with a standalone sender/receiver probe
      first) answered both the meta-query and a fake service-type query,
      and `discover_service_types()`/`browse_services()` correctly
      recovered the advertised device - plus a full mocked unit test
      suite (`test_mdns_browser.py`) for CI, since real multicast
      support isn't guaranteed consistent across every CI runner/
      container network configuration.

- [x] **Wi-Fi scanner.** A different, complementary question from device
      discovery: not "what's on my network" but "what networks are in
      radio range at all," including ones not connected to - a slow
      network is often channel congestion or a weak signal, neither of
      which device discovery can see.
      Done: `wifi_scanner.py`, a new standalone script dispatching by
      platform: `nmcli -t -f SSID,BSSID,CHAN,SIGNAL,SECURITY dev wifi
      list` on Linux (its terse-mode colon-escaping needed a small custom
      splitter, `_parse_nmcli_line()`, since a raw `.split(":")` would
      misparse a BSSID's own colons), the `airport` command-line tool on
      macOS (still present despite Apple's deprecation notice; its
      columnar output doesn't reliably delimit an SSID containing spaces,
      so parsing anchors on the BSSID - the one column guaranteed to
      match a fixed MAC pattern - and splits around it), and `netsh wlan
      show networks mode=bssid` on Windows (a stable, well-documented
      indented-block format). Signal strength is kept in each platform's
      own native unit (percentage on Linux/Windows, dBm on macOS) rather
      than converted between them, since there's no one true dBm<->percent
      conversion - only a vendor-specific approximation, which would be
      less honest than just labeling each. An open/unencrypted network is
      called out in the output, the same hygiene-flagging spirit as
      `RISKY_PORTS` elsewhere in this project.
      **Known limitation, stated plainly:** this environment has none of
      `nmcli`/`airport`/`netsh` installed and no Wi-Fi hardware at all, so
      every platform's parser is verified only against mocked subprocess
      output matching each tool's documented format
      (`test_wifi_scanner.py`) - never against a real device on real
      hardware, on any of the three platforms. The Linux path's
      tool-missing error handling *was* verified for real (this sandbox
      genuinely lacks `nmcli`, so that's the actual code path that ran),
      and the full `subprocess.run` -> parse -> print -> `--output`
      pipeline was verified end-to-end against a fake `nmcli` shell
      script placed on `PATH` - but the real command's actual output
      format on real Linux/macOS/Windows systems remains unverified.
      Treat a first real run on any platform as the verification it
      hasn't had yet, and please report back if a given tool version's
      real output doesn't match what's parsed here.

- [x] **External exposure checker.** `RISKY_PORTS` flags a port from
      inside the LAN, but a risky port reachable only from your own
      network is a much smaller problem than the same port reachable from
      the whole internet - worth a sharper, separate check.
      Done: `exposure_check.py`, a new standalone script. Determines your
      public IP with one plain HTTP(S) GET to api.ipify.org (a small,
      purpose-built "what's my IP" echo service - no account/API key, no
      other data about your network sent anywhere; `--ip` skips this
      entirely if you'd rather not make that request), then probes
      `RISKY_PORTS`' ports (or any `--ports` you name) against it with a
      plain TCP connect, concurrently. Deliberately framed around a loud,
      unavoidable caveat rather than a clean pass/fail: probing your own
      public IP from inside your own LAN is not a reliable substitute for
      a real external scan, since home routers implement NAT loopback/
      hairpinning inconsistently - some silently drop this traffic (a
      real open port reports as a false "closed"), others loop it back to
      a LAN device without truly routing to the internet and back (a
      false "open" that doesn't prove external reachability either). The
      CLI prints this caveat after every single run, not just on a
      surprising result, since the ambiguity cuts both ways. Verified
      end-to-end: `check_port()`/`check_exposure()` against a real local
      loopback listener (genuine `socket.accept()`, not mocked) correctly
      reported open vs. closed, and the full `main()` CLI pipeline ran
      correctly end-to-end via `--ip` (bypassing the external IP-lookup
      call). The real `api.ipify.org` call itself was exercised for real
      too, though only its *failure* path: this sandbox's own outbound
      proxy blocks that domain (403 on the CONNECT tunnel), which
      confirmed `get_public_ip()` fails cleanly with a readable
      `RuntimeError` rather than crashing - its success path (reaching
      the real internet) is standard `urllib` code, covered by mocked
      tests, but unverified against the real service from this sandbox.

- [x] **Latency/traceroute mapper.** Neither `exposure_check.py`'s "is
      this port reachable" nor `wifi_scanner.py`'s "is my signal weak"
      says *where* along the path a slow connection is actually slow -
      worth a dedicated tool for that.
      Done: `traceroute_mapper.py`, a new standalone script wrapping each
      platform's own tool numeric-only (`traceroute -n` on Linux/macOS,
      `tracert -d` on Windows) specifically to sidestep the biggest
      source of cross-platform output differences, then resolving each
      hop's hostname itself afterward via plain reverse DNS rather than
      depending on the traceroute binary's own inconsistent DNS handling
      across platforms. A hop that timed out on every probe still shows
      up (no IP, three missed replies) instead of being silently dropped,
      so a gap in the path stays visible; a hop with a notably high best
      RTT is called out in the output, the same hygiene-flagging spirit
      as `RISKY_PORTS` elsewhere.
      **Known limitation, stated plainly:** this environment has no
      `traceroute`/`tracert` binary at all, so every platform's parser is
      verified only against mocked command output matching each tool's
      documented format (`test_traceroute_mapper.py`) - never against a
      real path on real hardware, on any platform. One real subprocess
      run *was* done against a fake `traceroute` script placed on `PATH`,
      which also exercised genuine reverse-DNS resolution for real
      (127.0.0.1 -> localhost, 8.8.8.8 -> dns.google) - confirming the
      full subprocess -> parse -> resolve -> print pipeline works, just
      not the real traceroute binary's actual output format on any
      platform. Traceroute output varies more between tool versions/
      distros than most formats parsed elsewhere in this project; treat a
      first real run on any platform as the verification it hasn't had yet.

- [x] **Passive ARP-spoofing monitor.** `network_scanner.py`'s
      IP-conflict alert only samples at scan time - a full scan every few
      minutes at best under `--watch` - so a live man-in-the-middle
      attack happening *between* scans could go unnoticed until the next
      one, if ever. A tool that watches continuously instead would catch
      it as it happens.
      Done: `arp_monitor.py`, a new standalone script. `sniff()`s ARP
      traffic (scapy, same raw-socket privilege requirement as
      `network_scanner.py`'s ARP scan) and flags any IP whose MAC changes
      mid-session - the identical underlying signal
      `_find_ip_conflicts()` already uses, just detected passively and in
      real time instead of by diffing two periodic snapshots. The actual
      detection logic (`process_arp_observation()`) is a pure function
      completely independent of scapy's packet objects or the sniffing
      loop around it, specifically so it can be unit-tested without
      scapy at all. `--log FILE` appends each detected change as one
      JSON line, the same append-only spirit as the scan history log.
      Caught and fixed a real bug before it shipped, the exact same class
      already found and fixed in `--doctor`'s scapy check earlier in this
      project: `main()`'s original `except ImportError` didn't catch the
      `pyo3_runtime.PanicException` this sandbox's broken scapy/
      cryptography install actually raises on import, since that
      exception subclasses `BaseException` directly, not `Exception` -
      confirmed by actually running the script against this sandbox's
      real broken scapy install and watching it crash with a raw
      traceback, then fixed by broadening to `except BaseException` (with
      `KeyboardInterrupt` and `(PermissionError, OSError)` still caught
      separately first), and reverified against the same real broken
      install afterward, which now prints a clean error and exits 1.
      **Known limitation, stated plainly:** this environment's scapy
      install is broken and it has no raw-socket privileges either, so
      the actual packet-sniffing path (`monitor()`'s `sniff()` call) has
      never captured real ARP traffic in this session. It's tested by
      faking out the `scapy.all` import entirely (`patch.dict(sys.modules,
      ...)`) so `monitor()`'s own wiring runs for real against a fake
      `sniff()`, which is a genuine test of that function's logic - but
      real ARP packets from real hardware remain unverified.

- [x] **LAN throughput tester.** None of the other tools here measure
      this at all - "my internet feels slow" and "my LAN itself is slow"
      are different problems, and only a real transfer between two
      devices on the same network tells you which one you actually have.
      Done: `lan_throughput.py`, a new standalone script - plain TCP
      sockets, no dependency. `--serve` listens and reports what it
      received; `--client HOST` streams `os.urandom()` data (random, not
      zeros or a repeating pattern, since some links compress highly
      repetitive payloads in a way that would over-report the result) for
      a fixed `--duration` and reports what it actually managed to send.
      Measures TCP goodput between exactly these two processes, not raw
      link-layer bandwidth or a multi-stream aggregate the way a
      dedicated tool like `iperf3` does - documented plainly as a quick
      sanity check, not a substitute for `iperf3` when a rigorous number
      is needed. The most thoroughly verified of any tool added this
      round: every test uses real, unmocked sockets (a real loopback
      listener and a real client, not a single mock in the whole test
      file), and was also verified through two genuinely separate `python3
      lan_throughput.py` processes talking over real loopback TCP end to
      end via the actual CLI, confirming both sides agree on the exact
      byte count transferred.

- [x] **UPnP/IGD port-mapping auditor.** `exposure_check.py` answers "is
      this port reachable from outside" after the fact, by probing your
      public IP - a sharper, earlier question is *why* it might be open
      at all. Many home routers ship with UPnP enabled, letting any
      device on the network ask the router to forward a port from the
      internet straight to itself, with no further confirmation and no
      trace visible from LAN-side scanning at all.
      Done: `upnp_audit.py`, a new standalone script implementing the
      three-step UPnP IGD protocol from scratch (stdlib only - `socket`,
      `urllib`, `xml.etree.ElementTree`): SSDP multicast discovery
      (`discover_gateway()`, an M-SEARCH query to 239.255.255.250:1900 -
      the same request/response shape mDNS/DNS-SD's own discovery is
      built on, an older HTTP-header-flavored sibling protocol) to find
      the router's device-description URL; walking that XML
      (`find_wan_service()`, via `.iter()` rather than assuming any fixed
      nesting depth, since routers vary here) to find its
      WANIPConnection/WANPPPConnection service; then calling that
      service's `GetGenericPortMappingEntry` SOAP action once per index
      until the router's normal "no more entries" fault ends the
      enumeration (`get_port_mappings()`). A mapping forwarding a port
      already on `RISKY_PORTS` (duplicated from the scanners, same
      convention as `exposure_check.py`) is called out specifically.
      Verified end-to-end against a real, fully unmocked simulated
      gateway: a genuine SSDP responder thread (real multicast sockets,
      the same loopback-multicast capability confirmed working during
      `mdns_browser.py`'s development) plus a genuine `HTTPServer`
      serving real XML device-description and SOAP response/fault
      bodies - `discover_gateway()`, `get_device_description()`,
      `find_wan_service()`, `get_port_mappings()`, and the full `audit()`
      orchestration were all run for real against this simulated router
      and produced the exact expected port-mapping result, end to end,
      with zero mocks anywhere in that chain. This project's own
      environment has no real UPnP gateway to test against, though, so
      the simulated-router verification (kept as manual verification, not
      part of the committed suite, for the same reason `mdns_browser.py`'s
      real multicast test wasn't committed either: real multicast/SSDP
      behavior isn't guaranteed consistent across every CI runner) is the
      strongest confidence available here - a real router's UPnP stack
      could still diverge from the spec in ways this hasn't seen.

- [x] **Scan-diff tool.** A natural complement to CSV/JSON export above:
      compare two saved scans and report what changed between them
      (devices added/removed, per-field changes on ones present in
      both) - the same NEW/missing/CHG comparison the scanners already
      do against their own registry, just applied to two files instead.
      Done: `scan_diff.py`, a new standalone script (not added to
      either scanner) taking two `--output` files as positional args.
      Works across JSON and CSV interchangeably (`_normalize_device()`
      coerces CSV's string-typed port/risky_ports back to the same
      shape JSON already has, so a device unchanged in substance never
      shows as "changed" just because one file was CSV) and across
      scripts (matches by MAC when present, falling back to IP - the
      same rule `network_scanner.py`'s own registry uses - so
      desktop-only fields like `mac`/`vendor` and mobile-only `banner`
      are compared whenever both files happen to have them, without
      either scanner needing to know about the other's schema). Reuses
      the same green/dim/yellow color language as NEW/missing/CHG.
      Verified end-to-end against two real scans of a real loopback
      listener whose port was changed between them (plus a newly
      appeared second device) - once via JSON, once via CSV, and once
      comparing a CSV file against a JSON one - all three correctly
      reported the same added device and port change.

- [x] **CI workflow.** 293 tests existed with nothing running them
      automatically on push - a regression could land without anyone
      noticing until the next manual `pytest` run.
      Done: `.github/workflows/tests.yml`, running the full suite (plus
      a compile-check of all three scripts) on every push/PR across
      Python 3.9-3.12. Verified locally first: ran the actual suite
      under 3.10 and 3.12 (this sandbox's default is 3.11), all passing,
      before trusting the matrix to do the same in CI.

- [x] **`--doctor` flag.** A diagnostic mode that checks the environment
      up front (scapy, `ping`/`arp`, cache writability, mDNS, etc.)
      instead of discovering a limitation mid-scan as a blank column or
      a silently-skipped feature, in the same spirit as
      `mdns_diagnostic.py`.
      Done: `run_doctor()` + `--doctor` in both scripts, a list of
      (name, check) pairs each reporting pass/fail with a detail
      message and, for most, the fallback that kicks in when it fails.
      Exits 0/1 based on whether every check passed. `mobile_network_scanner.py`'s
      mDNS check runs the exact bind/join/send sequence its own mDNS
      lookups depend on, so a failure there points straight at iOS's
      Local Network Privacy restriction rather than something generic.
      Real end-to-end testing against this actual (broken) sandbox
      caught a genuine bug before it shipped: the scapy check's
      `except Exception` didn't catch the Rust `pyo3_runtime.PanicException`
      this sandbox's broken scapy/cryptography install actually raises
      on import, since that exception subclasses `BaseException`
      directly, not `Exception` - confirmed via `type(e).__mro__`, fixed
      by broadening to `except BaseException`, and locked in with a
      regression test using a fake `BaseException` subclass.

- [x] **`--quiet` flag.** Suppress output for a scan with nothing to
      report, so `--watch` under cron/systemd doesn't flood logs with a
      full table every run - only an interesting one should produce
      output at all.
      Done: `--quiet` in both scripts, suppressing all narration
      ("Scanning ...", the IPv6 probing line, the watch-mode timestamp
      banner, "No devices found.") unconditionally, and the results
      table/summary/reports entirely unless at least one device is NEW,
      changed port, went missing, or exposes a risky port - computed the
      same way the CHG/risky sections already do, just checked earlier
      to decide whether to print anything at all. A risky-port signal
      still fires this even with `--no-track-devices`, since that check
      doesn't depend on the registry. Verified end-to-end against a real
      loopback listener: first scan (NEW) printed the full report,
      second scan with nothing changed produced truly zero output, third
      scan after changing the listener's port printed the full report
      again.

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

- [x] **Custom device labels/aliases.** A way to assign a friendly name
      to a MAC/IP (e.g. "Kitchen Echo") stored in the known-devices
      registry, shown instead of/alongside the hostname - useful for
      devices whose real hostname is cryptic or blank.
      Done: `_set_label()`/`_remove_label()`/`_load_labels()` in both
      scripts, plus `--set-label KEY=LABEL` and `--remove-label KEY`
      (both repeatable), stored as a `"label"` field in the same
      known-devices registry entry as first_seen/last_seen. Display via
      `_display_hostname()`: "label (hostname)" when both are set and
      differ, otherwise whichever one is available - used in both the
      main results table and the missing-devices report. A label can be
      set for a device that isn't in the registry yet (creates a
      minimal entry), with one deliberate side effect documented in the
      docstring: that device won't show as NEW the next time it's
      actually scanned, since being labeled already counts as "known."
      Verified end-to-end against a real loopback listener on both
      scripts: baseline scan (bare hostname) → `--set-label` (combined
      display, confirmed in the saved registry file too) →
      `--remove-label` (reverts to bare hostname) → a separate scan
      with the labeled device absent, confirming the missing-devices
      report shows the label instead of nothing.

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

Custom device labels/aliases and export to CSV/JSON, both formerly
listed here as mobile-relevant open items, are done for both scripts -
see above.

Weaker fit, not started: a `--identify IP` deep-dive mode would work for
banner grabbing and a wider port list, but would be missing the MAC/
vendor half entirely (no ARP access on iOS) - a strictly smaller version
of the desktop one. MQTT/Home Assistant publishing and a local web
dashboard both assume something staying resident and reachable, which
doesn't fit a phone that isn't left running as a server.
