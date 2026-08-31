#!/usr/bin/env python3
"""Check or update the coordinated GS6 public/core/package versions."""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[1]


def core_version(public: str) -> str:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(.*)", public)
    if not match:
        raise SystemExit("GS6 public version must look like 6.x.y[-suffix]")
    return "0.{}.{}{}".format(match.group(1), match.group(2), match.group(4))


def install_version(public: str) -> str:
    return public.replace(".0-dev", "-dev") if public.endswith(".0-dev") else public


def expected_files(version: str) -> Dict[Path, List[str]]:
    core = core_version(version)
    install = install_version(version)
    files = {
        ROOT / "rust" / "Cargo.toml": ['version = "{}"'.format(core)],
        ROOT / "rust" / "crates" / "gs" / "src" / "main.rs": [
            'println!("{} (core {})");'.format(version, core)
        ],
        ROOT / "scripts" / "package_gs6.py": ['"version": "{}"'.format(version)],
        ROOT / "scripts" / "install_gs6.sh": [
            'VERSION="${{GS6_INSTALL_VERSION:-{}}}"'.format(install)
        ],
        ROOT / "scripts" / "uninstall_gs6.sh": [
            'VERSION="${{GS6_INSTALL_VERSION:-{}}}"'.format(install)
        ],
        ROOT / "scripts" / "verify_gs6_install_cycle.sh": [
            'VERSION="${{GS6_INSTALL_VERSION:-{}}}"'.format(install)
        ],
    }
    for manifest in sorted((ROOT / "plugins").glob("*/plugin.toml")):
        files[manifest] = ['version     = "{}"'.format(version)]
    return files


def check(version: str) -> None:
    errors = []
    files = expected_files(version)
    manifests = [path for path in files if path.name == "plugin.toml"]
    if len(manifests) != 15:
        errors.append("expected 15 formal plugin manifests, found {}".format(len(manifests)))
    for path, needles in files.items():
        if not path.is_file():
            errors.append("missing file: {}".format(path.relative_to(ROOT)))
            continue
        text = path.read_text(encoding="utf-8")
        for needle in needles:
            if needle not in text:
                errors.append("{} is missing {!r}".format(path.relative_to(ROOT), needle))
    if errors:
        raise SystemExit("GS6 version check failed:\n- " + "\n- ".join(errors))
    print("GS6 version consistency: PASS ({})".format(version))


def replace_once(path: Path, old: str, new: str) -> None:
    text = path.read_text(encoding="utf-8")
    if old not in text:
        raise SystemExit("cannot update {}: missing {!r}".format(path.relative_to(ROOT), old))
    path.write_text(text.replace(old, new), encoding="utf-8")


def update(old_version: str, new_version: str) -> None:
    old_core = core_version(old_version)
    new_core = core_version(new_version)
    old_install = install_version(old_version)
    new_install = install_version(new_version)
    replace_once(
        ROOT / "rust" / "Cargo.toml",
        'version = "{}"'.format(old_core),
        'version = "{}"'.format(new_core),
    )
    replace_once(
        ROOT / "rust" / "crates" / "gs" / "src" / "main.rs",
        'println!("{} (core {})");'.format(old_version, old_core),
        'println!("{} (core {})");'.format(new_version, new_core),
    )
    replace_once(
        ROOT / "scripts" / "package_gs6.py",
        '"version": "{}"'.format(old_version),
        '"version": "{}"'.format(new_version),
    )
    for script in ("install_gs6.sh", "uninstall_gs6.sh"):
        replace_once(
            ROOT / "scripts" / script,
            'VERSION="${{GS6_INSTALL_VERSION:-{}}}"'.format(old_install),
            'VERSION="${{GS6_INSTALL_VERSION:-{}}}"'.format(new_install),
        )
    replace_once(
        ROOT / "scripts" / "verify_gs6_install_cycle.sh",
        'VERSION="${{GS6_INSTALL_VERSION:-{}}}"'.format(old_install),
        'VERSION="${{GS6_INSTALL_VERSION:-{}}}"'.format(new_install),
    )
    for manifest in sorted((ROOT / "plugins").glob("*/plugin.toml")):
        replace_once(
            manifest,
            'version     = "{}"'.format(old_version),
            'version     = "{}"'.format(new_version),
        )
    for document in sorted((ROOT / "docs").glob("gs6*.md")) + sorted(
        (ROOT / "docs" / "en").glob("gs6*.md")
    ):
        text = document.read_text(encoding="utf-8")
        if old_version in text:
            document.write_text(text.replace(old_version, new_version), encoding="utf-8")
    check(new_version)
    print("Next: cargo check --manifest-path rust/Cargo.toml to refresh Cargo.lock")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--from-version")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    if args.write:
        if not args.from_version:
            parser.error("--write requires --from-version")
        update(args.from_version, args.version)
    else:
        check(args.version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
