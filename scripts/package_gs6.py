#!/usr/bin/env python3
"""Build a portable GS6 directory and optional ZIP from a native Rust binary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import List, Optional, Set


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_NAMES = {"__pycache__"}


def ignored(_directory: str, names: List[str]) -> Set[str]:
    return {
        name
        for name in names
        if name in EXCLUDED_NAMES
        or name.endswith((".pyc", ".pyo"))
        or (name.startswith("test_") and name.endswith(".py"))
    }


def copy_tree(source: Path, target: Path) -> None:
    shutil.copytree(source, target, ignore=ignored, dirs_exist_ok=True)


def copy_plugin(source: Path, target: Path) -> None:
    copy_tree(source, target)
    for legacy_name in ("plugin.json", "plugin.py"):
        legacy = target / legacy_name
        if legacy.exists():
            legacy.unlink()


def run_output(binary: Path, root: Path, *args: str) -> str:
    env = os.environ.copy()
    env.update(
        {
            "GS_ROOT": str(root),
            "GS_COMMAND_NAME": "gs6",
            "GS_COMMAND_PATH": str(binary),
            "GS_COLOR": "0",
        }
    )
    return subprocess.run(
        [str(binary), *args],
        cwd=root,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    ).stdout


def write_checksums(root: Path) -> None:
    lines = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name == "SHA256SUMS":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append("{}  {}".format(digest, path.relative_to(root).as_posix()))
    (root / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_zip(root: Path, archive: Path) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        for path in sorted(root.rglob("*")):
            if path.is_file():
                output.write(path, (Path(root.name) / path.relative_to(root)).as_posix())


def build(binary: Path, output: Path, archive: Optional[Path], target: str) -> None:
    if not binary.is_file():
        raise SystemExit("GS6 binary does not exist: {}".format(binary))
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    binary_name = "gs6.exe" if binary.suffix.lower() == ".exe" else "gs6"
    packaged_binary = output / binary_name
    shutil.copy2(binary, packaged_binary)

    copy_tree(ROOT / "sdk", output / "sdk")
    copy_tree(ROOT / "themes", output / "themes")
    manifests = sorted((ROOT / "plugins").glob("*/plugin.toml"))
    formal_names = {path.parent.name for path in manifests}
    for manifest in manifests:
        copy_plugin(manifest.parent, output / "plugins" / manifest.parent.name)

    legacy_dir = output / "legacy"
    legacy_dir.mkdir()
    for metadata in sorted((ROOT / "custom" / "userspace").glob("*/plugin.json")):
        if metadata.parent.name in formal_names:
            continue
        shutil.copy2(metadata, legacy_dir / (metadata.parent.name + ".json"))

    completion_files = {
        "bash": "gs6.bash",
        "zsh": "_gs6",
        "fish": "gs6.fish",
        "nushell": "gs6.nu",
        "powershell": "gs6.ps1",
    }
    for shell, filename in completion_files.items():
        (output / filename).write_text(
            run_output(packaged_binary, output, "completions", shell), encoding="utf-8"
        )

    shell_dir = output / "shell"
    shell_dir.mkdir()
    shell_init_files = {
        "bash": "gs6-init.bash",
        "zsh": "gs6-init.zsh",
        "fish": "gs6-init.fish",
        "powershell": "gs6-init.ps1",
    }
    for shell, filename in shell_init_files.items():
        (shell_dir / filename).write_text(
            run_output(packaged_binary, output, "shell-init", shell), encoding="utf-8"
        )

    legacy_names = {
        path.parent.name
        for path in (ROOT / "custom" / "userspace").glob("*/plugin.json")
        if path.parent.name not in formal_names
    }
    metadata = {
        "version": "6.0.0-dev",
        "binary": binary_name,
        "platform": sys.platform,
        "target": target,
        "formal_plugins": len(formal_names),
        "legacy_inventory": len(legacy_names),
    }
    (output / "release.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    run_output(packaged_binary, output, "version")
    run_output(packaged_binary, output, "doctor")
    run_output(packaged_binary, output, "plugin", "list")
    run_output(packaged_binary, output, "system", "proxy", "status")
    write_checksums(output)
    if archive is not None:
        write_zip(output, archive)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    build(
        args.binary.resolve(),
        args.output.resolve(),
        args.archive.resolve() if args.archive else None,
        args.target,
    )
    print("GS6 portable package ready: {}".format(args.output.resolve()))
    if args.archive:
        print("Archive: {}".format(args.archive.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
