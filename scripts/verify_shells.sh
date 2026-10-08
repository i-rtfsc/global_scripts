#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${GS_BIN:-$HOME/.local/bin/gs}"
[[ "$BIN" = /* ]] || BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[[ -x "$BIN" ]] || { echo "GS6 binary is not executable: $BIN" >&2; exit 2; }

VERIFY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gs-shells.XXXXXX")"
VERIFY_DIR="$(cd "$VERIFY_DIR" && pwd -P)"
trap 'find "$VERIFY_DIR" -depth -delete 2>/dev/null || true' EXIT
VERIFY_HOME="$VERIFY_DIR/home"
VERIFY_NAV="$VERIFY_HOME/code/github/global_scripts"
mkdir -p "$(dirname "$VERIFY_NAV")"
ln -s "$ROOT" "$VERIFY_NAV"

GS_COMMAND_NAME=gs GS_COMMAND_PATH="$BIN" "$BIN" shell-init bash > "$VERIFY_DIR/init.bash"
GS_COMMAND_NAME=gs GS_COMMAND_PATH="$BIN" "$BIN" shell-init zsh > "$VERIFY_DIR/init.zsh"
GS_COMMAND_NAME=gs GS_COMMAND_PATH="$BIN" "$BIN" shell-init fish > "$VERIFY_DIR/init.fish"
GS_COMMAND_NAME=gs "$BIN" completions bash > "$VERIFY_DIR/gs.bash"
GS_COMMAND_NAME=gs "$BIN" completions zsh > "$VERIFY_DIR/_gs"
GS_COMMAND_NAME=gs "$BIN" completions fish > "$VERIFY_DIR/gs.fish"

bash -n "$VERIFY_DIR/init.bash" "$VERIFY_DIR/gs.bash"
zsh -n "$VERIFY_DIR/init.zsh" "$VERIFY_DIR/_gs"
fish -n "$VERIFY_DIR/init.fish" "$VERIFY_DIR/gs.fish"

HOME="$VERIFY_HOME" GS_LANGUAGE=zh GS_CACHE_DIR="$VERIFY_DIR/cache-bash" \
  GS_VERIFY_DIR="$VERIFY_DIR" GS_EXPECT_NAV="$VERIFY_NAV" bash --noprofile --norc <<'BASH'
set -e
source "$GS_VERIFY_DIR/init.bash"
source "$GS_VERIFY_DIR/gs.bash"
complete -p gs | grep -q '_gs_complete'
gs system proxy on --yes >/dev/null
[[ "$http_proxy" == "http://127.0.0.1:7890" ]]
gs system proxy off --yes >/dev/null
[[ -z "${http_proxy+x}" ]]
cd /tmp
gs navigator global-scripts >/dev/null
[[ "$PWD" == "$GS_EXPECT_NAV" ]]
gs __complete plugin info android app | grep -q $'list-3rd\t'
BASH
echo "Bash integration: PASS"

HOME="$VERIFY_HOME" GS_LANGUAGE=zh GS_CACHE_DIR="$VERIFY_DIR/cache-zsh" \
  GS_VERIFY_DIR="$VERIFY_DIR" GS_EXPECT_NAV="$VERIFY_NAV" zsh -f <<'ZSH'
autoload -Uz compinit
compinit -d "$GS_VERIFY_DIR/zcompdump" || { print -u2 'zsh compinit failed'; exit 1; }
source "$GS_VERIFY_DIR/init.zsh" || { print -u2 'zsh init source failed'; exit 1; }
source "$GS_VERIFY_DIR/_gs" || { print -u2 'zsh completion source failed'; exit 1; }
[[ "${_comps[gs]-}" == "_gs_complete" ]] || { print -u2 "zsh completion binding: ${_comps[gs]-missing}"; exit 1; }
gs system proxy on --yes >/dev/null || { print -u2 'zsh proxy on failed'; exit 1; }
[[ "$http_proxy" == "http://127.0.0.1:7890" ]] || { print -u2 "zsh proxy value: ${http_proxy-}"; exit 1; }
gs system proxy off --yes >/dev/null || { print -u2 'zsh proxy off failed'; exit 1; }
[[ -z "${http_proxy+x}" ]] || { print -u2 'zsh proxy was not unset'; exit 1; }
cd /tmp
gs navigator global-scripts >/dev/null || { print -u2 'zsh navigator failed'; exit 1; }
[[ "$PWD" == "$GS_EXPECT_NAV" ]] || { print -u2 "zsh cwd: $PWD"; exit 1; }
completion="$(gs __complete plugin info android app)" || { print -u2 'zsh completion command failed'; exit 1; }
[[ "$completion" == *$'list-3rd\t'* ]] || { print -u2 'zsh completion description missing'; exit 1; }
ZSH
echo "Zsh integration: PASS"

HOME="$VERIFY_HOME" GS_LANGUAGE=zh GS_CACHE_DIR="$VERIFY_DIR/cache-fish" \
  GS_VERIFY_DIR="$VERIFY_DIR" GS_EXPECT_NAV="$VERIFY_NAV" fish --no-config <<'FISH'
source "$GS_VERIFY_DIR/init.fish"
source "$GS_VERIFY_DIR/gs.fish"
gs system proxy on --yes >/dev/null
test "$http_proxy" = "http://127.0.0.1:7890"; or exit 1
gs system proxy off --yes >/dev/null
not set -q http_proxy; or exit 1
cd /tmp
gs navigator global-scripts >/dev/null
test "$PWD" = "$GS_EXPECT_NAV"; or exit 1
gs __complete plugin info android app | string match -rq '^list-3rd\t.+'; or exit 1
FISH
echo "Fish integration: PASS"

echo "Shell integration: PASS"
