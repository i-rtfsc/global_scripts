#!/usr/bin/env bash
set -euo pipefail

BACKUP_FILE="${GS52_BACKUP:-$HOME/.config/global-scripts/backups/LATEST_GS52}"
[[ -f "$BACKUP_FILE" ]] || { echo "GS5.2 backup record not found" >&2; exit 2; }
BACKUP="$(cat "$BACKUP_FILE")"
[[ -d "$BACKUP" && -x "$BACKUP/gs" ]] || { echo "invalid GS5.2 backup: $BACKUP" >&2; exit 2; }
TARGET="$HOME/.local/bin/gs"
mkdir -p "$(dirname "$TARGET")"
cp -p "$BACKUP/gs" "$TARGET"
echo "Restored GS5.2 binary from $BACKUP"
"$TARGET" --version 2>/dev/null || true
