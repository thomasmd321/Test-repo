#!/usr/bin/env python3
"""Watch a log file and alert when new lines match a pattern.

Polls the file for new content (like `tail -f`), matching each new
line against one or more regular expressions and printing an alert
for anything that matches. Follows log rotation -- a truncated or
replaced file is detected and reopened automatically.

Usage:
    python log_watcher.py /var/log/syslog --pattern "error|failed"
    python log_watcher.py app.log --pattern "ERROR" --pattern "WARN:.*timeout"
    python log_watcher.py app.log --pattern "ERROR" --from-start
    python log_watcher.py app.log --pattern "ERROR" --interval 0.5
"""

import argparse
import os
import re
import time


def compile_patterns(patterns: list) -> list:
    return [re.compile(p) for p in patterns]


def matches_any(line: str, compiled_patterns: list):
    """Return the first compiled pattern that matches line, or None."""
    for pattern in compiled_patterns:
        if pattern.search(line):
            return pattern
    return None


class LogWatcher:
    """Follows a log file, tolerating truncation/rotation, yielding new
    lines as they're appended."""

    def __init__(self, path: str, from_start: bool = False):
        self.path = path
        self._fh = None
        self._inode = None
        self._open(seek_to_end=not from_start)

    def _open(self, seek_to_end: bool):
        if self._fh:
            self._fh.close()
        self._fh = open(self.path, "r", errors="replace")
        self._inode = os.fstat(self._fh.fileno()).st_ino
        self._buffer = ""  # a reopen means any old partial tail is gone with it
        if seek_to_end:
            self._fh.seek(0, os.SEEK_END)

    def _rotated(self) -> bool:
        """True if the file at self.path is no longer the file we have
        open (replaced) or has shrunk below our read position
        (truncated) -- both are signs of log rotation."""
        try:
            current_inode = os.stat(self.path).st_ino
        except FileNotFoundError:
            return False  # transient during rotation; try again next poll
        if current_inode != self._inode:
            return True
        if os.fstat(self._fh.fileno()).st_size < self._fh.tell():
            return True
        return False

    def poll_new_lines(self) -> list:
        """Return any new *complete* lines appended since the last poll.

        A line with no trailing newline yet (the writer flushed mid-line)
        is buffered rather than returned early -- returning it immediately
        would advance our read position past it, and its eventual
        completion would then show up later as a separate, wrong line.
        """
        if self._rotated():
            self._open(seek_to_end=False)
        self._buffer += self._fh.read()
        parts = self._buffer.split("\n")
        self._buffer = parts.pop()  # last element: incomplete trailing fragment, held back
        return parts

    def close(self):
        if self._fh:
            self._fh.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("path", help="Log file to watch")
    parser.add_argument("--pattern", action="append", required=True, help="Regex to alert on; repeatable (any match triggers an alert)")
    parser.add_argument("--from-start", action="store_true", help="Scan from the beginning of the file instead of only new lines (default: only new lines, like tail -f)")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between polls (default: 1.0)")
    args = parser.parse_args()

    try:
        compiled = compile_patterns(args.pattern)
    except re.error as exc:
        raise SystemExit(f"Invalid --pattern: {exc}")

    try:
        watcher = LogWatcher(args.path, from_start=args.from_start)
    except OSError as exc:
        raise SystemExit(f"Could not open {args.path}: {exc}")

    print(f"Watching {args.path} for {len(compiled)} pattern(s) ... Ctrl+C to stop.")

    try:
        while True:
            for line in watcher.poll_new_lines():
                if matches_any(line, compiled):
                    print(f"[!] {line}")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        watcher.close()


if __name__ == "__main__":
    main()
