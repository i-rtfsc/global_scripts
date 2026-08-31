#!/usr/bin/env python3
"""Verify a portable GS6 directory on its native operating system."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path


PRIVATE_NAMES = {
    "config.json",
    "id_rsa",
    "id_rsa.pub",
    "id_ed25519",
    "id_ed25519.pub",
    "rtc_cookies.json",
}
PRIVATE_SUFFIXES = {".db", ".xlsx", ".tar.gz"}


def fail(message: str) -> None:
    raise SystemExit("GS6 package verification failed: {}".format(message))


def verify_checksums(root: Path) -> None:
    checksum_file = root / "SHA256SUMS"
    if not checksum_file.is_file():
        fail("SHA256SUMS is missing")
    expected = {}
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, separator, relative = line.partition("  ")
        if not separator or not relative:
            fail("invalid checksum line: {}".format(line))
        expected[relative] = digest
    actual = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and path != checksum_file:
            actual[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if expected != actual:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        changed = sorted(name for name in set(expected) & set(actual) if expected[name] != actual[name])
        fail("checksum mismatch: missing={} extra={} changed={}".format(missing, extra, changed))


def verify_private_assets(root: Path) -> None:
    leaks = []
    for plugin in ("identity", "sgm"):
        directory = root / "plugins" / plugin
        for path in directory.rglob("*") if directory.is_dir() else []:
            suffix = "".join(path.suffixes[-2:]) if len(path.suffixes) >= 2 else path.suffix
            if path.is_file() and (path.name in PRIVATE_NAMES or suffix in PRIVATE_SUFFIXES):
                leaks.append(path.relative_to(root).as_posix())
    if leaks:
        fail("private assets were packaged: {}".format(", ".join(leaks)))


def run(binary: Path, root: Path, cache: Path, *args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env.update(
        {
            "GS_CACHE_DIR": str(cache),
            "GS_COLOR": "0",
            "GS_LANGUAGE": "zh",
        }
    )
    for name in ("GS_ROOT", "GS_COMMAND_NAME", "GS_COMMAND_PATH", "GS_ALLOW_LEGACY"):
        env.pop(name, None)
    return subprocess.run(
        [str(binary), *args],
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )


def require_success(result: subprocess.CompletedProcess, label: str) -> str:
    if result.returncode != 0:
        fail("{} returned {}: {}".format(label, result.returncode, result.stderr.strip()))
    return result.stdout


def verify_runtime(root: Path, binary: Path, expected_version: str) -> None:
    with tempfile.TemporaryDirectory(prefix="gs6-package-cache-") as cache_name:
        cache = Path(cache_name)
        version = require_success(run(binary, root, cache, "version"), "version")
        if expected_version not in version:
            fail("unexpected version output: {}".format(version.strip()))

        doctor = require_success(run(binary, root, cache, "doctor"), "doctor")
        if "结果:          通过" not in doctor:
            fail("doctor did not pass")

        inventory = require_success(run(binary, root, cache, "plugin", "list"), "plugin list")
        for expected in ("插件库存", "正式 15", "legacy 0"):
            if expected not in inventory:
                fail("plugin inventory is missing {!r}".format(expected))

        system = require_success(
            run(binary, root, cache, "system", "proxy", "status"), "system proxy status"
        )
        if "代理状态" not in system:
            fail("system plugin output is incomplete")

        completion = require_success(
            run(binary, root, cache, "__complete", "plugin", "info", "android", "app"),
            "android completion",
        )
        if "list-3rd\t" not in completion or "列出第三方应用" not in completion:
            fail("multi-level completion descriptions are missing")

        expected_bindings = {
            "bash": "complete -F _gs6_complete gs6",
            "zsh": "compdef _gs6_complete gs6",
            "fish": "complete -c gs6 ",
            "nushell": '== "gs6"',
            "powershell": "-CommandName gs6",
        }
        for shell, binding in expected_bindings.items():
            script = require_success(run(binary, root, cache, "completions", shell), shell + " completions")
            if binding not in script:
                fail("{} completion is not bound to gs6".format(shell))

        for shell in ("bash", "zsh", "fish", "powershell"):
            init = require_success(run(binary, root, cache, "shell-init", shell), shell + " shell-init")
            if "GS_CD_FILE" not in init or "GS_ENV_FILE" not in init:
                fail("{} shell-init is missing shell effects".format(shell))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    metadata_path = root / "release.json"
    if not metadata_path.is_file():
        fail("release.json is missing")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("target") != args.target:
        fail("release target mismatch: {} != {}".format(metadata.get("target"), args.target))
    if metadata.get("formal_plugins") != 15 or metadata.get("legacy_inventory") != 0:
        fail("unexpected inventory metadata: {}".format(metadata))
    if metadata.get("signed") is not False:
        fail("GS6 self-install packages must be marked as unsigned")
    binary = root / str(metadata.get("binary") or "")
    if not binary.is_file():
        fail("native binary is missing: {}".format(binary))
    verify_checksums(root)
    verify_private_assets(root)
    verify_runtime(root, binary, str(metadata.get("version") or ""))
    print("GS6 package verification: PASS ({})".format(args.target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
