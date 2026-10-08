#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${GS_PREFIX:-$HOME/.local}"
VERSION="${GS_INSTALL_VERSION:-6.0-dev}"
DEST="$PREFIX/share/global-scripts/$VERSION"
NAME="${GS_INSTALL_NAME:-gs}"

usage() {
  echo "Usage: $0 --yes [--name gs]" >&2
  echo "Removes the named Global Scripts entry; other entries are left alone." >&2
  exit 2
}
confirmed=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes) confirmed=1; shift ;;
    --name) [[ $# -ge 2 ]] || usage; NAME="$2"; shift 2 ;;
    --name=*) NAME="${1#--name=}"; shift ;;
    *) usage ;;
  esac
done
[[ "$confirmed" == 1 ]] || usage
LINK="$PREFIX/bin/$NAME"

case "$DEST" in
  /|"$HOME"|"$PREFIX"|"")
    echo "Refusing unsafe destination: $DEST" >&2
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

remove_link_to "$LINK" "$DEST/gs-launch"
remove_link_to "$PREFIX/share/bash-completion/completions/$NAME" "$DEST/$NAME.bash"
remove_link_to "$PREFIX/share/fish/vendor_completions.d/$NAME.fish" "$DEST/$NAME.fish"
remove_link_to "$PREFIX/share/zsh/site-functions/_$NAME" "$DEST/_$NAME"

for backup in "$PREFIX"/bin/"$NAME".backup-*; do
  [[ -L "$backup" ]] || continue
  if [[ "$(readlink "$backup")" == "$DEST/gs-launch" ]]; then
    unlink "$backup"
    echo "Removed redundant backup link: $backup"
  fi
done

# 私有*资产*目录(没有 plugin.toml 的那些)在 ~/.config/global-scripts 下是符号链接。
# 私有*插件*(sgm/flyme 等)是复制进 $DEST/plugins 的实体目录,随下面的 find -delete 一起清除。
for private_source in "$ROOT"/custom/userspace/*/; do
  [[ -d "$private_source" ]] || continue
  [[ -f "${private_source}plugin.toml" ]] && continue
  private_asset="$(basename "$private_source")"
  remove_link_to "$HOME/.config/global-scripts/$private_asset" "${private_source%/}"
done

if [[ -d "$DEST" ]]; then
  find "$DEST" -depth -delete
  echo "Removed files: $DEST"
fi

rmdir "$PREFIX/share/global-scripts" 2>/dev/null || true
echo "Entry '$NAME' uninstalled. Other gs entries were not modified."
