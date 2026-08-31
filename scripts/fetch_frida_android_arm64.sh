#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${FRIDA_VERSION:-17.17.0}"
BASE="https://github.com/frida/frida/releases/download/${VERSION}"
OUT="$ROOT/plugins/android/frida"
mkdir -p "$OUT"

curl -L --fail --retry 5 --retry-delay 2 --continue-at - \
  "$BASE/frida-server-${VERSION}-android-arm64.xz" -o /tmp/frida-server-${VERSION}.xz
curl -L --fail --retry 5 --retry-delay 2 --continue-at - \
  "$BASE/frida-inject-${VERSION}-android-arm64.xz" -o /tmp/frida-inject-${VERSION}.xz
xz -dc "/tmp/frida-server-${VERSION}.xz" > "$OUT/frida-server"
xz -dc "/tmp/frida-inject-${VERSION}.xz" > "$OUT/frida-inject"
chmod 755 "$OUT/frida-server" "$OUT/frida-inject"
echo "Fetched Frida ${VERSION} Android arm64 binaries into ${OUT}"
