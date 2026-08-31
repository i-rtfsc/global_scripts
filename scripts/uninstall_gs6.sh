#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${GS6_PREFIX:-$HOME/.local}"
VERSION="${GS6_INSTALL_VERSION:-6.0-dev}"
DEST="$PREFIX/share/global-scripts/$VERSION"
LINK="$PREFIX/bin/gs6"

if [[ "${1:-}" != "--yes" ]]; then
  echo "Usage: $0 --yes" >&2
  echo "Removes the separate GS6 preview installation; global 'gs' is untouched." >&2
  exit 2
fi

case "$DEST" in
  /|"$HOME"|"$PREFIX"|"")
    echo "Refusing unsafe GS6 destination: $DEST" >&2
    exit 2
    ;;
esac

remove_link_to() {
  local link="$1"
  local expected="$2"
  if [[ -L "$link" && "$(readlink "$link")" == "$expected" ]]; then
    unlink "$link"
    echo "Removed link: $link"
  fi
}

remove_link_to "$LINK" "$DEST/gs6"
remove_link_to "$PREFIX/share/bash-completion/completions/gs6" "$DEST/gs6.bash"
remove_link_to "$PREFIX/share/fish/vendor_completions.d/gs6.fish" "$DEST/gs6.fish"
remove_link_to "$PREFIX/share/zsh/site-functions/_gs6" "$DEST/_gs6"

for backup in "$PREFIX"/bin/gs6.backup-*; do
  [[ -L "$backup" ]] || continue
  if [[ "$(readlink "$backup")" == "$DEST/gs6" ]]; then
    unlink "$backup"
    echo "Removed redundant backup link: $backup"
  fi
done

for private_plugin in identity sgm; do
  private_link="$HOME/.config/global-scripts/$private_plugin"
  private_source="$ROOT/custom/userspace/$private_plugin"
  remove_link_to "$private_link" "$private_source"
done

if [[ -d "$DEST" ]]; then
  find "$DEST" -depth -delete
  echo "Removed GS6 files: $DEST"
fi

rmdir "$PREFIX/share/global-scripts" 2>/dev/null || true
echo "GS6 preview uninstalled. Global gs was not modified."
