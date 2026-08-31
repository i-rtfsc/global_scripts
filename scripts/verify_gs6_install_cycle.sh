#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${GS6_INSTALL_VERSION:-6.0-dev}"
EXPECTED_VERSION="${GS6_EXPECT_VERSION:-6.0.0-dev}"
VERIFY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/gs6-install-cycle.XXXXXX")"
trap 'find "$VERIFY_ROOT" -depth -delete 2>/dev/null || true' EXIT
TEST_HOME="$VERIFY_ROOT/home"
TEST_PREFIX="$VERIFY_ROOT/prefix"
mkdir -p "$TEST_HOME" "$TEST_PREFIX/bin"
printf 'global-gs-sentinel\n' > "$TEST_PREFIX/bin/gs"

for _ in 1 2; do
  HOME="$TEST_HOME" GS6_PREFIX="$TEST_PREFIX" \
    bash "$ROOT/scripts/install_gs6.sh" --yes >/dev/null
done

test -L "$TEST_PREFIX/bin/gs6"
test "$(find "$TEST_PREFIX/bin" -maxdepth 1 -name 'gs6.backup-*' | wc -l | tr -d ' ')" = 0
test -L "$TEST_HOME/.config/global-scripts/identity"
test -L "$TEST_HOME/.config/global-scripts/sgm"
"$TEST_PREFIX/bin/gs6" version | grep -q "$EXPECTED_VERSION"

HOME="$TEST_HOME" GS6_PREFIX="$TEST_PREFIX" \
  bash "$ROOT/scripts/uninstall_gs6.sh" --yes >/dev/null

test ! -e "$TEST_PREFIX/bin/gs6"
test ! -e "$TEST_PREFIX/share/global-scripts/$VERSION"
test ! -e "$TEST_PREFIX/share/bash-completion/completions/gs6"
test ! -e "$TEST_PREFIX/share/fish/vendor_completions.d/gs6.fish"
test ! -e "$TEST_PREFIX/share/zsh/site-functions/_gs6"
test ! -e "$TEST_HOME/.config/global-scripts/identity"
test ! -e "$TEST_HOME/.config/global-scripts/sgm"
grep -q 'global-gs-sentinel' "$TEST_PREFIX/bin/gs"

echo "GS6 isolated install/uninstall: PASS"
