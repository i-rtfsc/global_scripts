#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="$ROOT/dist/gs6-dev"
BACKUP_FILE="$HOME/.config/global-scripts/backups/LATEST_GS52"

[[ -x "$STAGE/gs" ]] || { echo "GS6 staging binary missing" >&2; exit 2; }
[[ -f "$STAGE/SHA256SUMS" ]] || { echo "GS6 staging checksum missing" >&2; exit 2; }
[[ -f "$BACKUP_FILE" ]] || { echo "GS5.2 backup record missing" >&2; exit 2; }
backup="$(cat "$BACKUP_FILE")"
[[ -x "$backup/gs" ]] || { echo "GS5.2 backup binary missing" >&2; exit 2; }
audit_cache="$(mktemp -d "${TMPDIR:-/tmp}/gs6-audit.XXXXXX")"
trap 'rm -rf "$audit_cache"' EXIT

GS_ROOT="$STAGE" GS_CACHE_DIR="$audit_cache" \
  "$STAGE/gs" doctor >/dev/null
plugin_output="$(GS_ROOT="$STAGE" GS_CACHE_DIR="$audit_cache" "$STAGE/gs" plugin list)"
grep -q 'android' <<<"$plugin_output"
bash -n "$ROOT/scripts/rollback_gs52.sh"
(cd "$STAGE" && shasum -c SHA256SUMS >/dev/null)
bash -n "$ROOT/scripts/install_gs6.sh"
test "$(shasum -a 256 "$HOME/.local/bin/gs" | awk '{print $1}')" = "$(shasum -a 256 "$backup/gs" | awk '{print $1}')"

echo "GS6 ready audit: PASS"
echo "Staging: $STAGE"
echo "GS5.2 backup: $backup"
echo "Global gs unchanged: yes"
