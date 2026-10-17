#!/usr/bin/env python3
"""Find duplicate files in a directory tree by content hash.

Groups files by size first (a cheap pre-filter -- files of different
sizes can't be duplicates), then hashes files within each same-size
group to confirm a real match. By default this only reports what it
finds; nothing is deleted unless you pass --delete.

Usage:
    python duplicate_finder.py ~/Downloads
    python duplicate_finder.py ~/Downloads --min-size 1024
    python duplicate_finder.py ~/Downloads --delete   # keep first copy, remove the rest
"""

import argparse
import hashlib
from collections import defaultdict
from pathlib import Path


def iter_files(root: Path):
    for path in root.rglob("*"):
        if path.is_file() and not path.is_symlink():
            yield path


def hash_file(path: Path, chunk_size: int = 1 << 20) -> str:
    """Return the sha256 hex digest of a file's contents, read in chunks
    so this doesn't load an entire large file into memory at once."""
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_duplicates(root: Path, min_size: int = 1) -> dict:
    """Return {hash: [sorted paths]} for every group of 2+ files with
    byte-identical content. Only files of the same size are ever hashed
    against each other."""
    by_size = defaultdict(list)
    for path in iter_files(root):
        try:
            size = path.stat().st_size
        except OSError:
            continue  # e.g. a broken symlink or a file removed mid-walk
        if size < min_size:
            continue
        by_size[size].append(path)

    duplicates = {}
    for size, paths in by_size.items():
        if len(paths) < 2:
            continue  # unique size -- can't have a duplicate
        by_hash = defaultdict(list)
        for path in paths:
            try:
                by_hash[hash_file(path)].append(path)
            except OSError:
                continue  # unreadable file (permissions, race, etc.)
        for digest, group in by_hash.items():
            if len(group) > 1:
                duplicates[digest] = sorted(group)

    return duplicates


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("directory", help="Directory to scan recursively")
    parser.add_argument("--min-size", type=int, default=1, help="Ignore files smaller than this many bytes (default: 1, skips empty files)")
    parser.add_argument("--delete", action="store_true", help="Delete all but the first copy in each duplicate group (default: report only)")
    args = parser.parse_args()

    root = Path(args.directory)
    if not root.is_dir():
        raise SystemExit(f"{args.directory!r} is not a directory")

    print(f"Scanning {root} ...")
    duplicates = find_duplicates(root, args.min_size)

    if not duplicates:
        print("No duplicate files found.")
        return

    total_wasted = 0
    total_dupes = 0
    for digest, paths in sorted(duplicates.items(), key=lambda kv: kv[1][0]):
        size = paths[0].stat().st_size
        wasted = size * (len(paths) - 1)
        total_wasted += wasted
        total_dupes += len(paths) - 1
        print(f"\n{len(paths)} copies ({size:,} bytes each, {wasted:,} bytes wasted):")
        for i, path in enumerate(paths):
            marker = "KEEP" if i == 0 else "DUPE"
            print(f"  [{marker}] {path}")
        if args.delete:
            for path in paths[1:]:
                path.unlink()
                print(f"  Deleted {path}")

    print(f"\n{total_dupes} duplicate file(s) in {len(duplicates)} group(s), {total_wasted:,} bytes wasted.")
    if not args.delete:
        print("Nothing was deleted (pass --delete to remove all but the first copy in each group).")


if __name__ == "__main__":
    main()
