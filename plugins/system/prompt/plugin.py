#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import os
from pathlib import Path
from typing import List, Dict, Any

from gscripts.models.result import CommandResult, ConfigManager
from gscripts.plugins.decorators import plugin_function

THEMES_DIR = Path(__file__).resolve().parents[3] / 'themes' / 'prompt'


def _list_theme_names() -> List[str]:
    names: List[str] = []
    try:
        if THEMES_DIR.exists():
            for f in THEMES_DIR.glob('*.sh'):
                if f.name in ('_lib.sh', 'load.sh'):
                    continue
                names.append(f.stem)
    except Exception:
        pass
    return sorted(names)


@plugin_function(
    name="themes",
    description={"zh": "列出可用主题", "en": "List available prompt themes"},
    usage="gs system prompt themes",
    examples=["gs system prompt themes"]
)
def list_themes(args: List[str] | None = None) -> CommandResult:
    names = _list_theme_names()
    if not names:
        return CommandResult(True, output="No themes found")
    return CommandResult(True, output="\n".join(names))


@plugin_function(
    name="current",
    description={"zh": "显示当前主题", "en": "Show current theme"},
    usage="gs system prompt current",
    examples=["gs system prompt current"]
)
def current_theme(args: List[str] | None = None) -> CommandResult:
    # Check environment variable set by config
    env_theme = os.environ.get('GS_PROMPT_THEME')
    if env_theme:
        return CommandResult(True, output=str(env_theme))
    
    # Fallback to default
    return CommandResult(True, output='minimalist')


@plugin_function(
    name="set",
    description={"zh": "设置主题并持久化", "en": "Set theme and persist"},
    usage="gs system prompt set <theme>",
    examples=["gs system prompt set detailed"],
    args=[
        {
            "name": "theme",
            "type": "dynamic_choice",
            "required": True,
            "description": "主题名称",
            "choices_function": "_list_theme_names"
        }
    ]
)
def set_theme(args: List[str] | None = None) -> CommandResult:
    args = args or []
    if not args:
        return CommandResult(False, error="Usage: gs system prompt set <theme>")
    theme = args[0].strip()
    if theme not in _list_theme_names():
        return CommandResult(False, error=f"Theme not found: {theme}")

    # Use ConfigManager JSON config
    try:
        mgr = ConfigManager()
        current_cfg: Dict[str, Any] = mgr.get_config() or {}
        # Normalize to new shape if old keys present
        if 'plugins' in current_cfg or 'system_plugins' in current_cfg and isinstance(current_cfg['system_plugins'], list):
            # Convert list form to dict form
            if isinstance(current_cfg.get('system_plugins'), list):
                current_cfg['system_plugins'] = {p: True for p in current_cfg.get('system_plugins', [])}
            if isinstance(current_cfg.get('custom_plugins'), list):
                current_cfg['custom_plugins'] = {p: True for p in current_cfg.get('custom_plugins', [])}
            # Remove legacy keys
            for k in ['plugins','debug_mode','verbose_output','gs_config_debug','gs_config_verbose','gs_prompt_theme','GS_PROMPT_THEME','config_debug','config_verbose']:
                current_cfg.pop(k, None)
            # Ensure unified logging_level exists after cleanup
            current_cfg.setdefault('logging_level', 'INFO')
        current_cfg['prompt_theme'] = theme
        mgr.save_config(current_cfg)
        
        # Auto-regenerate env.sh after config update
        try:
            import subprocess
            import sys
            gs_root = Path(__file__).resolve().parents[3]
            result = subprocess.run([sys.executable, str(gs_root / 'setup.py')], 
                                  cwd=gs_root, capture_output=True, text=True)
            if result.returncode != 0:
                return CommandResult(False, error=f"Failed to regenerate env.sh: {result.stderr}")
        except Exception as e:
            return CommandResult(False, error=f"Failed to regenerate env.sh: {e}")
            
    except Exception as e:
        return CommandResult(False, error=f"Failed to update config: {e}")

    return CommandResult(True, output=f"Theme set to: {theme}. Environment updated automatically.")
