#!/usr/bin/env python3
"""Regenerate GS6 checksums and ZIP after native code signing."""

from __future__ import annotations

import argparse
from pathlib import Path

from package_gs6 import write_checksums, write_zip


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    archive = args.archive.resolve()
    write_checksums(root)
    write_zip(root, archive)
    print("GS6 signed package finalized: {}".format(archive))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
