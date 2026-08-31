#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${GS6_BIN:-$HOME/.local/bin/gs6}"
[[ "$BIN" = /* ]] || BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
[[ -x "$BIN" ]] || { echo "GS6 binary is not executable: $BIN" >&2; exit 2; }

VERIFY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/gs6-shells.XXXXXX")"
VERIFY_DIR="$(cd "$VERIFY_DIR" && pwd -P)"
trap 'find "$VERIFY_DIR" -depth -delete 2>/dev/null || true' EXIT
VERIFY_HOME="$VERIFY_DIR/home"
VERIFY_NAV="$VERIFY_HOME/code/github/global_scripts"
mkdir -p "$(dirname "$VERIFY_NAV")"
ln -s "$ROOT" "$VERIFY_NAV"

GS_COMMAND_NAME=gs6 GS_COMMAND_PATH="$BIN" "$BIN" shell-init bash > "$VERIFY_DIR/init.bash"
GS_COMMAND_NAME=gs6 GS_COMMAND_PATH="$BIN" "$BIN" shell-init zsh > "$VERIFY_DIR/init.zsh"
GS_COMMAND_NAME=gs6 GS_COMMAND_PATH="$BIN" "$BIN" shell-init fish > "$VERIFY_DIR/init.fish"
GS_COMMAND_NAME=gs6 "$BIN" completions bash > "$VERIFY_DIR/gs6.bash"
GS_COMMAND_NAME=gs6 "$BIN" completions zsh > "$VERIFY_DIR/_gs6"
GS_COMMAND_NAME=gs6 "$BIN" completions fish > "$VERIFY_DIR/gs6.fish"

bash -n "$VERIFY_DIR/init.bash" "$VERIFY_DIR/gs6.bash"
zsh -n "$VERIFY_DIR/init.zsh" "$VERIFY_DIR/_gs6"
fish -n "$VERIFY_DIR/init.fish" "$VERIFY_DIR/gs6.fish"

HOME="$VERIFY_HOME" GS_LANGUAGE=zh GS_CACHE_DIR="$VERIFY_DIR/cache-bash" \
  GS6_VERIFY_DIR="$VERIFY_DIR" GS6_EXPECT_NAV="$VERIFY_NAV" bash --noprofile --norc <<'BASH'
set -e
source "$GS6_VERIFY_DIR/init.bash"
source "$GS6_VERIFY_DIR/gs6.bash"
complete -p gs6 | grep -q '_gs6_complete'
gs6 system proxy on --yes >/dev/null
[[ "$http_proxy" == "http://127.0.0.1:7890" ]]
gs6 system proxy off --yes >/dev/null
[[ -z "${http_proxy+x}" ]]
cd /tmp
gs6 navigator global-scripts >/dev/null
[[ "$PWD" == "$GS6_EXPECT_NAV" ]]
gs6 __complete plugin info android app | grep -q $'list-3rd\t'
BASH
echo "Bash integration: PASS"

HOME="$VERIFY_HOME" GS_LANGUAGE=zh GS_CACHE_DIR="$VERIFY_DIR/cache-zsh" \
  GS6_VERIFY_DIR="$VERIFY_DIR" GS6_EXPECT_NAV="$VERIFY_NAV" zsh -f <<'ZSH'
autoload -Uz compinit
compinit -d "$GS6_VERIFY_DIR/zcompdump" || { print -u2 'zsh compinit failed'; exit 1; }
source "$GS6_VERIFY_DIR/init.zsh" || { print -u2 'zsh init source failed'; exit 1; }
source "$GS6_VERIFY_DIR/_gs6" || { print -u2 'zsh completion source failed'; exit 1; }
[[ "${_comps[gs6]-}" == "_gs6_complete" ]] || { print -u2 "zsh completion binding: ${_comps[gs6]-missing}"; exit 1; }
gs6 system proxy on --yes >/dev/null || { print -u2 'zsh proxy on failed'; exit 1; }
[[ "$http_proxy" == "http://127.0.0.1:7890" ]] || { print -u2 "zsh proxy value: ${http_proxy-}"; exit 1; }
gs6 system proxy off --yes >/dev/null || { print -u2 'zsh proxy off failed'; exit 1; }
[[ -z "${http_proxy+x}" ]] || { print -u2 'zsh proxy was not unset'; exit 1; }
cd /tmp
gs6 navigator global-scripts >/dev/null || { print -u2 'zsh navigator failed'; exit 1; }
[[ "$PWD" == "$GS6_EXPECT_NAV" ]] || { print -u2 "zsh cwd: $PWD"; exit 1; }
completion="$(gs6 __complete plugin info android app)" || { print -u2 'zsh completion command failed'; exit 1; }
[[ "$completion" == *$'list-3rd\t'* ]] || { print -u2 'zsh completion description missing'; exit 1; }
ZSH
echo "Zsh integration: PASS"

HOME="$VERIFY_HOME" GS_LANGUAGE=zh GS_CACHE_DIR="$VERIFY_DIR/cache-fish" \
  GS6_VERIFY_DIR="$VERIFY_DIR" GS6_EXPECT_NAV="$VERIFY_NAV" fish --no-config <<'FISH'
source "$GS6_VERIFY_DIR/init.fish"
source "$GS6_VERIFY_DIR/gs6.fish"
gs6 system proxy on --yes >/dev/null
test "$http_proxy" = "http://127.0.0.1:7890"; or exit 1
gs6 system proxy off --yes >/dev/null
not set -q http_proxy; or exit 1
cd /tmp
gs6 navigator global-scripts >/dev/null
test "$PWD" = "$GS6_EXPECT_NAV"; or exit 1
gs6 __complete plugin info android app | string match -rq '^list-3rd\t.+'; or exit 1
FISH
echo "Fish integration: PASS"

echo "GS6 Bash/Zsh/Fish integration: PASS"
