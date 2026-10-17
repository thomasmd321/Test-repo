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

- `arp_spoof_detector.py` has no automated test suite in the repo yet — it
  was verified by ad hoc unit tests during development (not checked in).
  Worth adding a `tests/` file with those if this repo keeps growing.
