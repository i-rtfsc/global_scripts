#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${GS6_SOURCE:-$ROOT/dist/gs6-dev}"
PREFIX="${GS6_PREFIX:-$HOME/.local}"
VERSION="${GS6_INSTALL_VERSION:-6.0-dev}"
DEST="$PREFIX/share/global-scripts/$VERSION"
BIN_DIR="$PREFIX/bin"
LINK="$BIN_DIR/gs6"

if [[ "${1:-}" != "--yes" ]]; then
  echo "Usage: $0 --yes" >&2
  echo "Installs GS6 as '$LINK'; the existing global 'gs' is not modified." >&2
  exit 2
fi
[[ -x "$SOURCE/gs6" && -f "$SOURCE/SHA256SUMS" ]] || {
  echo "Invalid GS6 staging source: $SOURCE" >&2
  exit 2
}
(cd "$SOURCE" && shasum -c SHA256SUMS >/dev/null)

mkdir -p "$BIN_DIR" "$(dirname "$DEST")"
link_is_current=0
if [[ -L "$LINK" && "$(readlink "$LINK")" == "$DEST/gs6" ]]; then
  link_is_current=1
elif [[ -e "$LINK" || -L "$LINK" ]]; then
  stamp="$(date -u +%Y%m%d-%H%M%S)"
  mv "$LINK" "$LINK.backup-$stamp"
fi
mkdir -p "$DEST"
rsync -a --delete "$SOURCE/" "$DEST/"
if [[ "$link_is_current" != "1" ]]; then
  ln -s "$DEST/gs6" "$LINK"
fi
for backup in "$BIN_DIR"/gs6.backup-*; do
  [[ -L "$backup" ]] || continue
  if [[ "$(readlink "$backup")" == "$DEST/gs6" ]]; then
    unlink "$backup"
  fi
done
mkdir -p \
  "$PREFIX/share/bash-completion/completions" \
  "$PREFIX/share/fish/vendor_completions.d" \
  "$PREFIX/share/zsh/site-functions"
ln -sfn "$DEST/gs6.bash" "$PREFIX/share/bash-completion/completions/gs6"
ln -sfn "$DEST/gs6.fish" "$PREFIX/share/fish/vendor_completions.d/gs6.fish"
ln -sfn "$DEST/_gs6" "$PREFIX/share/zsh/site-functions/_gs6"
mkdir -p "$PREFIX/share/global-scripts/$VERSION/shell"
GS_COMMAND_NAME=gs6 GS_COMMAND_PATH="$LINK" "$LINK" shell-init bash \
  > "$PREFIX/share/global-scripts/$VERSION/shell/gs6-init.bash"
GS_COMMAND_NAME=gs6 GS_COMMAND_PATH="$LINK" "$LINK" shell-init zsh \
  > "$PREFIX/share/global-scripts/$VERSION/shell/gs6-init.zsh"
GS_COMMAND_NAME=gs6 GS_COMMAND_PATH="$LINK" "$LINK" shell-init fish \
  > "$PREFIX/share/global-scripts/$VERSION/shell/gs6-init.fish"
GS_COMMAND_NAME=gs6 GS_COMMAND_PATH="$LINK" "$LINK" shell-init powershell \
  > "$PREFIX/share/global-scripts/$VERSION/shell/gs6-init.ps1"

if [[ "${GS6_LINK_PRIVATE_ASSETS:-1}" == "1" ]]; then
  private_config_root="$HOME/.config/global-scripts"
  mkdir -p "$private_config_root"
  for private_plugin in identity sgm; do
    private_source="$ROOT/custom/userspace/$private_plugin"
    private_target="$private_config_root/$private_plugin"
    if [[ -d "$private_source" && ! -e "$private_target" && ! -L "$private_target" ]]; then
      ln -s "$private_source" "$private_target"
      echo "Private asset link: $private_target -> $private_source"
    fi
  done
fi

echo "GS6 installed: $LINK -> $DEST/gs6"
echo "Completions installed under: $PREFIX/share"
echo "Shell init files: $PREFIX/share/global-scripts/$VERSION/shell"
echo "Global gs unchanged. Verify with: gs6 version"
