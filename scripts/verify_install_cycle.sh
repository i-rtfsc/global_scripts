#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${GS_INSTALL_VERSION:-6.0-dev}"
EXPECTED_VERSION="${GS_EXPECT_VERSION:-6.0.0-dev}"
VERIFY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/gs-install-cycle.XXXXXX")"
trap 'find "$VERIFY_ROOT" -depth -delete 2>/dev/null || true' EXIT
TEST_HOME="$VERIFY_ROOT/home"
TEST_PREFIX="$VERIFY_ROOT/prefix"
mkdir -p "$TEST_HOME" "$TEST_PREFIX/bin"
printf 'global-gs-sentinel\n' > "$TEST_PREFIX/bin/gs"

for _ in 1 2; do
  HOME="$TEST_HOME" GS_PREFIX="$TEST_PREFIX" \
    bash "$ROOT/scripts/install_gs.sh" --yes >/dev/null
done

# Installing `gs` replaces an existing entry of that name, but must keep the
# file it displaced instead of clobbering it, and a second install must not
# pile up further backups.
test -L "$TEST_PREFIX/bin/gs"
test "$(find "$TEST_PREFIX/bin" -maxdepth 1 -name 'gs.backup-*' | wc -l | tr -d ' ')" = 1
backup="$(find "$TEST_PREFIX/bin" -maxdepth 1 -name 'gs.backup-*' | head -1)"
grep -q 'global-gs-sentinel' "$backup"

# Private *assets* are not part of the public tree; link checks only apply when
# the asset directory is actually present. (Private *plugins* — sgm/flyme — live
# in custom/userspace with a plugin.toml and are linked into the install tree
# instead, so they are not asserted here.)
if [[ -d "$ROOT/custom/userspace/identity" ]]; then
  test -L "$TEST_HOME/.config/global-scripts/identity"
fi
"$TEST_PREFIX/bin/gs" version | grep -q "$EXPECTED_VERSION"

HOME="$TEST_HOME" GS_PREFIX="$TEST_PREFIX" \
  bash "$ROOT/scripts/uninstall_gs.sh" --yes >/dev/null

test ! -e "$TEST_PREFIX/bin/gs"
test ! -e "$TEST_PREFIX/share/global-scripts/$VERSION"
test ! -e "$TEST_PREFIX/share/bash-completion/completions/gs"
test ! -e "$TEST_PREFIX/share/fish/vendor_completions.d/gs.fish"
test ! -e "$TEST_PREFIX/share/zsh/site-functions/_gs"
if [[ -d "$ROOT/custom/userspace/identity" ]]; then
  test ! -e "$TEST_HOME/.config/global-scripts/identity"
fi
grep -q 'global-gs-sentinel' "$backup"

echo "Isolated install/uninstall: PASS"
