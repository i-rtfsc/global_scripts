#!/usr/bin/env bash
# Minimalist single-line prompt

source "${GS_ROOT:-$PWD}/themes/prompt/_lib.sh" 2>/dev/null || true

if [[ -n "$ZSH_VERSION" ]]; then
PROMPT='%F{075}%~%f %# '
RPROMPT='%F{110}$(_gs_prompt_git_info)%f'
else
PS1='\w \$ '
fi
