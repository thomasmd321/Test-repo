# Bash tab-completion for network_scanner.py, mobile_network_scanner.py,
# scan_diff.py, mdns_browser.py, wifi_scanner.py, and exposure_check.py.
#
# Usage: source this file, e.g. from ~/.bashrc:
#   source /path/to/Test-repo/completions.bash
#
# This only completes flag names - it doesn't understand a flag's
# argument (a subnet, a port list, a file path), so pressing Tab right
# after typing "--ports " or "--output " won't suggest anything, and
# typing a bare subnet/IP won't either. That's a real gap, not a bug:
# useful completion for those would need each script to expose its own
# argument choices, which none of them do (a subnet is arbitrary, a port
# list is arbitrary, etc.) - flag-name completion is what's actually
# tractable without one.
#
# Only fires for a *direct* invocation matching the script's own name
# (./network_scanner.py, or plain network_scanner.py if it's on PATH and
# executable - see chmod +x, already set on every script in this repo).
# "python3 network_scanner.py ..." does NOT trigger this: bash
# keys completion off COMP_WORDS[0], which would be "python3" in that
# case, and hijacking every "python3 ..." command's completion just to
# cover this one case would break completion for any other Python script
# you run - not a tradeoff worth making. Put this repo on your PATH (or
# symlink the scripts somewhere already on it) to get completion for the
# common "python3 network_scanner.py" form too, by invoking the bare
# name instead.
#
# Static, not generated from argparse at runtime: each script's flags
# are listed by hand below, so this can drift out of sync if a flag is
# added, renamed, or removed without updating this file too. No new
# runtime dependency either way - wiring up `argcomplete` instead would
# stay in sync automatically, at the cost of an extra pip install these
# scripts otherwise don't need.

_network_scanner_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="-h --help --all-subnets --identify --doctor --timeout --retries --mdns-timeout --no-vendor-lookup --refresh-vendor-db --watch --no-track-devices --forget-known-devices --set-label --remove-label --ipv6 --ipv6-timeout --no-scan-ports --ports --exclude --port-timeout --no-risky-ports --no-color --output --quiet --notify-webhook --log-history --history-max-entries"
    COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
}
complete -F _network_scanner_completions network_scanner.py

_mobile_network_scanner_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="-h --help --timeout --retries --ports --exclude --mdns-timeout --doctor --watch --no-track-devices --forget-known-devices --set-label --remove-label --no-banners --no-risky-ports --no-color --output --quiet --notify-webhook --log-history --history-max-entries"
    COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
}
complete -F _mobile_network_scanner_completions mobile_network_scanner.py

_scan_diff_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="-h --help --no-color"
    COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
}
complete -F _scan_diff_completions scan_diff.py

_mdns_browser_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="-h --help --timeout --services --no-discover --output --no-color"
    COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
}
complete -F _mdns_browser_completions mdns_browser.py

_wifi_scanner_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="-h --help --timeout --output --no-color"
    COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
}
complete -F _wifi_scanner_completions wifi_scanner.py

_exposure_check_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local opts="-h --help --ip --ports --timeout --output --no-color"
    COMPREPLY=($(compgen -W "${opts}" -- "${cur}"))
}
complete -F _exposure_check_completions exposure_check.py
