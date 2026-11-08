#!/usr/bin/env python3
"""Check or download an Encryptoglyph release. Does not execute it."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "api"))

from eg_api.http import locate_version
from eg_api.updater import check_release, download_tarball, extract_tarball, github_fetch, read_version


def main() -> int:
    parser = argparse.ArgumentParser(description="Encryptoglyph release updater")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--download", type=Path)
    args = parser.parse_args()
    current = read_version(locate_version())
    report = check_release(current, github_fetch)
    print(
        f"current={report['current']} latest={report['latest']} "
        f"state={report['state']} update_available={report['update_available']}"
    )
    if args.download:
        url = report.get("url")
        if not isinstance(url, str):
            print("no release tarball to download", file=sys.stderr)
            return 1
        extract_tarball(download_tarball(url), args.download)
        print(f"extracted={args.download}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
