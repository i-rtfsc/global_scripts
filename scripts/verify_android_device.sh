#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/rust/target/debug/gs"
[[ -x "$BIN" ]] || { echo "build GS6 first" >&2; exit 2; }
export GS_ROOT="$ROOT"
devices="$(adb devices)"
grep -q $'\tdevice' <<<"$devices"

"$BIN" android device devices >/dev/null
"$BIN" android device current >/dev/null
"$BIN" android device size >/dev/null
"$BIN" android logcat clear >/dev/null
"$BIN" android dump battery >/dev/null
"$BIN" android dump build >/dev/null
"$BIN" android dump activity >/dev/null
"$BIN" android dump packages com.android >/dev/null
"$BIN" android fs exists /system/bin/sh >/dev/null
"$BIN" android fs ls /system/bin >/dev/null
"$BIN" android fs verify >/dev/null
"$BIN" android proc ps_grep zygote >/dev/null
"$BIN" android app list-system >/dev/null
"$BIN" android app version com.android.shell >/dev/null
"$BIN" android logcat filter ActivityManager >/dev/null
"$BIN" android frida status >/dev/null
"$BIN" android emulator status >/dev/null
"$BIN" android input home >/dev/null
test_file="$ROOT/plugins/android/plugin.toml"
remote_file="/data/local/tmp/gs6-plugin-test.toml"
pull_dir="$ROOT/.gs6-device-test"
mkdir -p "$pull_dir"
"$BIN" android fs push "$test_file" "$remote_file" >/dev/null
"$BIN" android fs pull "$remote_file" "$pull_dir/plugin.toml" >/dev/null
cmp "$test_file" "$pull_dir/plugin.toml"
adb shell rm -f "$remote_file"
rm -f "$pull_dir/plugin.toml"
rmdir "$pull_dir"

"$BIN" android frida status >/dev/null
if adb shell pgrep -f frida-server >/dev/null 2>&1; then
  "$BIN" android frida inject -p com.rtfsc.neura -f native-smoke.js >/dev/null
fi

echo 'Android GS6 safe device verification: PASS'
