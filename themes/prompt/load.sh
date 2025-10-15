#!/usr/bin/env bash
# Load Global Scripts prompt theme at shell startup
# Priority: user gs.json > project gs.json > environment > default (legacy gs.conf supported for migration)

# Guard against multiple sourcing (which can otherwise re-define functions repeatedly)
if [[ -n "${_GS_PROMPT_LOADED:-}" ]]; then
  return 0 2>/dev/null || exit 0
fi
_GS_PROMPT_LOADED=1

# Ensure GS_ROOT
: "${GS_ROOT:=${GS_PROJECT_ROOT:-$PWD}}"

# Path definitions
_gs_user_cfg="$HOME/.config/global-scripts/config/gs.json"
_gs_project_cfg="$GS_ROOT/config/gs.json"
_gs_user_legacy="$HOME/.config/global-scripts/config/gs.conf"
_gs_project_legacy="$GS_ROOT/config/gs.conf"

# Load from JSON (user first)
_gs_try_load_json() {
  local file="$1"
  [[ -r "$file" ]] || return 1
  # Extract GS_PROMPT_THEME via jq if available else grep
  if command -v jq >/dev/null 2>&1; then
    local theme
    theme=$(jq -r '.GS_PROMPT_THEME // .gs_prompt_theme // .current_theme // empty' "$file" 2>/dev/null)
    if [[ -n "$theme" && "$theme" != "null" ]]; then
      GS_PROMPT_THEME="$theme"
      return 0
    fi
  else
    # naive grep for GS_PROMPT_THEME key
    local line
    line=$(grep -E 'GS_PROMPT_THEME' "$file" 2>/dev/null | head -n1)
    if [[ -n "$line" ]]; then
      GS_PROMPT_THEME=$(echo "$line" | sed -E 's/.*GS_PROMPT_THEME"?[[:space:]]*:[[:space:]]*"?([^",}]+).*/\1/')
      [[ -n "$GS_PROMPT_THEME" ]] && return 0
    fi
  fi
  return 1
}

if _gs_try_load_json "$_gs_user_cfg"; then
  :
elif _gs_try_load_json "$_gs_project_cfg"; then
  :
else
  # Legacy fallback order: user gs.conf then project gs.conf
  if [[ -r "$_gs_user_legacy" ]]; then
    # shellcheck source=/dev/null
    source "$_gs_user_legacy" 2>/dev/null || true
  elif [[ -r "$_gs_project_legacy" ]]; then
    # shellcheck source=/dev/null
    source "$_gs_project_legacy" 2>/dev/null || true
  fi
fi

# Default
GS_PROMPT_THEME=${GS_PROMPT_THEME:-minimalist}

# Source theme file
_gs_theme_file="$GS_ROOT/themes/prompt/${GS_PROMPT_THEME}.sh"
if [[ -r "$_gs_theme_file" ]]; then
  # shellcheck source=/dev/null
  source "$_gs_theme_file"
else
  # Fallback prompt
  PROMPT='[%n@%m %~]$ ' 2>/dev/null || true
  PS1='[\u@\h \w]$ '
fi
