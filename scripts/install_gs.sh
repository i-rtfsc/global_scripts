#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="${GS_SOURCE:-$ROOT/dist/gs}"
PREFIX="${GS_PREFIX:-$HOME/.local}"
VERSION="${GS_INSTALL_VERSION:-6.0-dev}"
DEST="$PREFIX/share/global-scripts/$VERSION"
BIN_DIR="$PREFIX/bin"
# Command name to install under. `gs` shadows any other `gs` on PATH (on this
# machine: Ghostscript in /usr/bin); pass `--name` to pick something else.
NAME="${GS_INSTALL_NAME:-gs}"
usage() {
  echo "Usage: $0 --yes [--name gs]" >&2
  echo "Installs Global Scripts as '$BIN_DIR/<name>'; other 'gs' entries are left alone." >&2
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
[[ -n "$NAME" ]] || usage
LINK="$BIN_DIR/$NAME"
[[ -x "$SOURCE/gs-launch" && -f "$SOURCE/SHA256SUMS" ]] || {
  echo "Invalid staging source: $SOURCE" >&2
  exit 2
}
(cd "$SOURCE" && shasum -c SHA256SUMS >/dev/null)

mkdir -p "$BIN_DIR" "$(dirname "$DEST")"
link_is_current=0
if [[ -L "$LINK" && "$(readlink "$LINK")" == "$DEST/gs-launch" ]]; then
  link_is_current=1
elif [[ -e "$LINK" || -L "$LINK" ]]; then
  stamp="$(date -u +%Y%m%d-%H%M%S)"
  mv "$LINK" "$LINK.backup-$stamp"
fi
mkdir -p "$DEST"
# `shell/` holds files generated *here* (one per installed name, with this
# prefix's paths baked in), so it must survive the mirror — otherwise
# installing a second name would delete the first one's shell integration.
rsync -a --delete --exclude 'shell/' "$SOURCE/" "$DEST/"
if [[ "$link_is_current" != "1" ]]; then
  ln -s "$DEST/gs-launch" "$LINK"
fi
for backup in "$BIN_DIR/$NAME.backup-"*; do
  [[ -L "$backup" ]] || continue
  if [[ "$(readlink "$backup")" == "$DEST/gs-launch" ]]; then
    unlink "$backup"
  fi
done
mkdir -p \
  "$PREFIX/share/bash-completion/completions" \
  "$PREFIX/share/fish/vendor_completions.d" \
  "$PREFIX/share/zsh/site-functions"
ln -sfn "$DEST/$NAME.bash" "$PREFIX/share/bash-completion/completions/$NAME"
ln -sfn "$DEST/$NAME.fish" "$PREFIX/share/fish/vendor_completions.d/$NAME.fish"
ln -sfn "$DEST/_$NAME" "$PREFIX/share/zsh/site-functions/_$NAME"
mkdir -p "$PREFIX/share/global-scripts/$VERSION/shell"
GS_COMMAND_NAME="$NAME" GS_COMMAND_PATH="$LINK" "$LINK" shell-init bash \
  > "$PREFIX/share/global-scripts/$VERSION/shell/$NAME-init.bash"
GS_COMMAND_NAME="$NAME" GS_COMMAND_PATH="$LINK" "$LINK" shell-init zsh \
  > "$PREFIX/share/global-scripts/$VERSION/shell/$NAME-init.zsh"
GS_COMMAND_NAME="$NAME" GS_COMMAND_PATH="$LINK" "$LINK" shell-init fish \
  > "$PREFIX/share/global-scripts/$VERSION/shell/$NAME-init.fish"
GS_COMMAND_NAME="$NAME" GS_COMMAND_PATH="$LINK" "$LINK" shell-init powershell \
  > "$PREFIX/share/global-scripts/$VERSION/shell/$NAME-init.ps1"

# 用户级环境文件:界面语言、Ghostscript 冲突修正、补全与 cd 集成。
# 放在 ~/.config/global-scripts/shell(不在 $DEST),这样升级、重装 dotfiles
# 都不会把它冲掉;rc 里只留一行 `source`(由 dotfiles 载荷或用户自己加)。
SHELL_DIR="$PREFIX/share/global-scripts/$VERSION/shell"
ENV_DIR="$HOME/.config/global-scripts/shell"
mkdir -p "$ENV_DIR"

cat > "$ENV_DIR/$NAME-env.bash" <<SH
# Global Scripts 环境(由 install_gs.sh 生成,可安全重复生成)
export GS_LANGUAGE="\${GS_LANGUAGE:-zh}"
[ -n "\$MAGICK_CONFIGURE_PATH" ] || export MAGICK_CONFIGURE_PATH="\$HOME/.config/ImageMagick"
[ -f "$SHELL_DIR/$NAME-init.bash" ] && source "$SHELL_DIR/$NAME-init.bash"
if command -v "$NAME" >/dev/null; then source <("$NAME" completions bash); fi
SH

cat > "$ENV_DIR/$NAME-env.zsh" <<SH
# Global Scripts 环境(由 install_gs.sh 生成,可安全重复生成)
export GS_LANGUAGE="\${GS_LANGUAGE:-zh}"
[ -n "\$MAGICK_CONFIGURE_PATH" ] || export MAGICK_CONFIGURE_PATH="\$HOME/.config/ImageMagick"
autoload -Uz compinit && compinit
[ -f "$PREFIX/share/zsh/site-functions/_$NAME" ] && source "$PREFIX/share/zsh/site-functions/_$NAME"
[ -f "$SHELL_DIR/$NAME-init.zsh" ] && source "$SHELL_DIR/$NAME-init.zsh"
SH

cat > "$ENV_DIR/$NAME-env.fish" <<SH
# Global Scripts 环境(由 install_gs.sh 生成,可安全重复生成)
set -gx GS_LANGUAGE zh
if not set -q MAGICK_CONFIGURE_PATH
    set -gx MAGICK_CONFIGURE_PATH "\$HOME/.config/ImageMagick"
end
test -f "$SHELL_DIR/$NAME-init.fish"; and source "$SHELL_DIR/$NAME-init.fish"
SH

if [[ "${GS_LINK_PRIVATE_ASSETS:-1}" == "1" ]]; then
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

echo "GS installed: $LINK -> $DEST/gs-launch"
echo "Completions installed under: $PREFIX/share"
echo "Shell init files: $PREFIX/share/global-scripts/$VERSION/shell"
if [[ "$NAME" == "gs" ]]; then
  echo "NOTE: '$BIN_DIR/gs' now shadows any other gs earlier on PATH."
  echo "If you were not after that, remove it with: rm '$LINK'"
else
  echo "Other gs entries were left alone. Verify with: $NAME version"
fi
