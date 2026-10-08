#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/rust/target/release/gs"
DIST="$ROOT/dist/gs"
[[ -x "$BIN" ]] || { echo "build release gs first" >&2; exit 2; }

mkdir -p "$DIST/plugins"
mkdir -p "$DIST/legacy"
find "$DIST/legacy" -maxdepth 1 -type f -name '*.json' -delete
cp "$BIN" "$DIST/gs"
rsync -a --delete --delete-excluded --exclude '__pycache__' --exclude '*.pyc' "$ROOT/sdk/" "$DIST/sdk/"
rsync -a --delete --delete-excluded "$ROOT/themes/" "$DIST/themes/"
# `config/init.toml` is what `gs init` reads, so the distribution needs it too.
rsync -a --delete --delete-excluded "$ROOT/config/" "$DIST/config/"
for manifest in "$ROOT"/plugins/*/plugin.toml; do
  dir="$(dirname "$manifest")"
  name="$(basename "$dir")"
  rsync -a --delete --delete-excluded \
    --exclude '__pycache__' --exclude '*.pyc' \
    --exclude 'plugin.json' --exclude 'plugin.py' --exclude 'test_*.py' \
    "$dir/" "$DIST/plugins/$name/"
done
# custom/ 是私有区(.gitignore 排除):默认**不进**发布包。
# 需要带私有插件出包时显式 GS_INCLUDE_PRIVATE=1(只用于你自己的私有构建)。
if [[ "${GS_INCLUDE_PRIVATE:-0}" == "1" && -d "$ROOT/custom/userspace" ]]; then
  for legacy_manifest in "$ROOT"/custom/userspace/*/plugin.json; do
    [[ -f "$legacy_manifest" ]] || continue
    legacy_name="$(basename "$(dirname "$legacy_manifest")")"
    [[ -f "$ROOT/plugins/$legacy_name/plugin.toml" ]] && continue
    cp "$legacy_manifest" "$DIST/legacy/$legacy_name.json"
  done
fi
for frida_bin in frida-server frida-inject; do
  if [[ ! -x "$ROOT/plugins/android/frida/$frida_bin" ]]; then
    echo "warning: optional Android asset missing: plugins/android/frida/$frida_bin" >&2
  fi
done
find "$DIST/plugins" -mindepth 1 -maxdepth 1 -type d | while read -r staged_plugin; do
  name="$(basename "$staged_plugin")"
  [[ -f "$ROOT/plugins/$name/plugin.toml" ]] || find "$staged_plugin" -depth -delete
done
if [[ -d "$DIST/cache" ]]; then
  find "$DIST/cache" -depth -delete
fi
cat > "$DIST/gs-launch" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
SOURCE="${BASH_SOURCE[0]}"
while [[ -L "$SOURCE" ]]; do
  DIR="$(cd "$(dirname "$SOURCE")" && pwd)"
  TARGET="$(readlink "$SOURCE")"
  [[ "$TARGET" = /* ]] && SOURCE="$TARGET" || SOURCE="$DIR/$TARGET"
done
ROOT="$(cd "$(dirname "$SOURCE")" && pwd)"
export GS_ROOT="$ROOT"
# The invocation name decides what the tool calls itself, so the same wrapper
# serves whatever name it is linked under.
export GS_COMMAND_NAME="$(basename "$0")"
export GS_COMMAND_PATH="$ROOT/$(basename "$0")"
export GS_CACHE_DIR="${GS_CACHE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/global-scripts/gs}"
exec "$ROOT/gs" "$@"
SH
chmod 755 "$DIST/gs-launch"
GS_ROOT="$DIST" GS_COMMAND_NAME=gs GS_COLOR=1 "$DIST/gs" completions fish > "$DIST/gs.fish"
cp "$DIST/gs.fish" "$DIST/gs-conf.fish"
GS_ROOT="$DIST" GS_COMMAND_NAME=gs GS_COLOR=1 "$DIST/gs" completions bash > "$DIST/gs.bash"
GS_ROOT="$DIST" GS_COMMAND_NAME=gs GS_COLOR=1 "$DIST/gs" completions zsh > "$DIST/_gs"
# Completions for the `gs` name as well, so an install can use either entry.
GS_ROOT="$DIST" GS_COMMAND_NAME=gs "$DIST/gs" completions fish > "$DIST/gs.fish"
GS_ROOT="$DIST" GS_COMMAND_NAME=gs "$DIST/gs" completions bash > "$DIST/gs.bash"
GS_ROOT="$DIST" GS_COMMAND_NAME=gs "$DIST/gs" completions zsh > "$DIST/_gs"
STAGE_CACHE="$(mktemp -d "${TMPDIR:-/tmp}/gs-stage-cache.XXXXXX")"
GS_ROOT="$DIST" GS_CACHE_DIR="$STAGE_CACHE" "$DIST/gs" doctor >/dev/null
GS_ROOT="$DIST" GS_CACHE_DIR="$STAGE_CACHE" "$DIST/gs" plugin list >/dev/null
GS_ROOT="$DIST" GS_CACHE_DIR="$STAGE_CACHE" "$DIST/gs" system proxy status >/dev/null
find "$DIST" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$DIST" -type f -name '*.pyc' -delete
find "$DIST" -maxdepth 1 -type d -name cache -prune -exec rm -rf {} +
rm -rf "$STAGE_CACHE"
(cd "$DIST" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 shasum -a 256 > SHA256SUMS)
printf 'Staging ready: %s\n' "$DIST"
printf 'This directory is not installed globally.\n'
