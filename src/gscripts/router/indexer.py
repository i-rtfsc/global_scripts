#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any



def _get_meta_value(meta: Any, key: str, default: Any = None) -> Any:
    """Get value from meta (supports both dict and object)"""
    if hasattr(meta, "get"):  # Dict-like
        return meta.get(key, default)
    else:  # Object-like
        return getattr(meta, key, default)


def build_router_index(plugins: Dict[str, Any]) -> Dict[str, Any]:
    """Build comprehensive router index with full plugin metadata.

    New Structure (v2):
    {
      "version": "2.0",
      "generated_at": "ISO timestamp",
      "plugins": {
        "plugin_name": {
          "name": "...",
          "version": "...",
          "author": "...",
          "description": {"zh": "...", "en": "..."},
          "homepage": "...",
          "license": "...",
          "enabled": true/false,
          "category": "...",
          "keywords": [],
          "priority": 50,
          "plugin_dir": "/path",
          "type": "python|shell|json|hybrid",
          "subplugins": [],
          "commands": {
            "command_key": {
              "name": "func",
              "kind": "shell|json|python",
              "subplugin": "sub",
              "entry": "/path",
              "command": "tpl",
              "usage": "gs ...",
              "description": {...},
              "examples": []
            }
          }
        }
      }
    }
    """
    # Read enabled status from config
    enabled_map = _load_enabled_status()

    index: Dict[str, Any] = {
        "version": "2.0",
        "generated_at": datetime.now().isoformat(),
        "plugins": {},
    }

    for plugin_name, plugin in plugins.items():
        # Extract plugin metadata
        plugin_meta = {
            "name": getattr(plugin, "name", plugin_name),
            "version": getattr(plugin, "version", ""),
            "author": getattr(plugin, "author", ""),
            "description": _normalize_description(getattr(plugin, "description", "")),
            "homepage": getattr(plugin, "homepage", ""),
            "license": getattr(plugin, "license", ""),
            "enabled": enabled_map.get(plugin_name, True),
            "category": getattr(plugin, "category", ""),
            "keywords": getattr(plugin, "keywords", []) or [],
            "priority": getattr(plugin, "priority", 50),
            "plugin_dir": (
                str(getattr(plugin, "plugin_dir", ""))
                if hasattr(plugin, "plugin_dir")
                else ""
            ),
            "type": _determine_plugin_type(plugin),
            "subplugins": _get_subplugins_with_descriptions(plugin),
            "commands": {},
        }

        # Build commands map
        func_map = (
            getattr(plugin, "functions", {}) if hasattr(plugin, "functions") else {}
        )
        for func_key, meta in func_map.items():
            ftype = _get_meta_value(meta, "type")

            # Normalize kind
            if ftype in ("script", "shell_annotated"):
                kind = "shell"
            elif ftype == "config":
                kind = "json"
            elif ftype in ("python", "python_decorated"):
                kind = "python"
            else:
                kind = ""

            # Determine tokens and names
            sub = _get_meta_value(meta, "subplugin") or ""
            name = _get_meta_value(meta, "name") or func_key

            # Get args
            args = _get_meta_value(meta, "args", []) or []

            # Extract completions from args for shell completion
            # 从args中提取所有choices作为补全选项
            completions = []
            for arg in args:
                if "choices" in arg and arg.get("choices"):
                    completions.extend(arg["choices"])

            # Special handling for config install/init commands
            if (
                plugin_name == "system"
                and sub == "config"
                and name in ("install", "init")
            ):
                # Try to get available configs directly from the config plugin
                try:
                    plugin_obj = plugin  # The plugin object
                    plugin_dir = getattr(plugin_obj, "plugin_dir", None)
                    if plugin_dir:
                        config_plugin_path = Path(plugin_dir) / "config" / "plugin.py"
                        if config_plugin_path.exists():
                            # Import and instantiate the config subplugin
                            import importlib.util

                            spec = importlib.util.spec_from_file_location(
                                "temp_config", config_plugin_path
                            )
                            if spec and spec.loader:
                                import sys

                                temp_module = importlib.util.module_from_spec(spec)
                                # Add parent directories to sys.path temporarily
                                old_path = sys.path.copy()
                                sys.path.insert(
                                    0, str(Path(plugin_dir).parent.parent / "src")
                                )
                                try:
                                    spec.loader.exec_module(temp_module)
                                    # Find the SystemConfigSubplugin class
                                    for attr_name in dir(temp_module):
                                        attr = getattr(temp_module, attr_name)
                                        if (
                                            isinstance(attr, type)
                                            and attr_name == "SystemConfigSubplugin"
                                        ):
                                            instance = attr()
                                            if hasattr(
                                                instance, "get_available_configs"
                                            ):
                                                completions = (
                                                    instance.get_available_configs()
                                                )
                                            break
                                finally:
                                    sys.path = old_path
                except Exception:
                    # Silently fail - completions will remain empty
                    pass

            # Collect entry/command
            entry = ""
            command_tpl = ""
            if kind == "shell":
                script_file = _get_meta_value(meta, "script_file")
                if script_file:
                    entry = str(Path(script_file))
                else:
                    if sub and sub != plugin_name:
                        entry = str(
                            Path("") / "plugins" / plugin_name / sub / "plugin.sh"
                        )
                    else:
                        entry = str(Path("") / "plugins" / plugin_name / "plugin.sh")
            elif kind == "json":
                cfg = _get_meta_value(meta, "config_file")
                if cfg:
                    entry = str(Path(cfg))
                command_tpl = _get_meta_value(meta, "command") or ""
            elif kind == "python":
                python_file = _get_meta_value(meta, "python_file")
                if python_file:
                    entry = str(Path(python_file))
                else:
                    if sub and sub != plugin_name:
                        entry = str(
                            Path("") / "plugins" / plugin_name / sub / "plugin.py"
                        )
                    else:
                        entry = str(Path("") / "plugins" / plugin_name / "plugin.py")

            # Build command metadata
            cmd_meta = {
                "name": name,
                "kind": kind,
                "subplugin": sub,
                "entry": entry,
                "command": command_tpl,
                "usage": _get_meta_value(meta, "usage", ""),
                "description": _normalize_description(
                    _get_meta_value(meta, "description", "")
                ),
                "examples": _get_meta_value(meta, "examples", []) or [],
                "args": args,
                "completions": completions,  # 从args提取的补全选项,仅用于shell补全
            }

            # Determine command key
            if sub and sub != plugin_name:
                # Subplugin command: use "sub func" format
                token = f"{sub} {name}"
            else:
                # Direct plugin command: use function name
                token = name

            plugin_meta["commands"][token] = cmd_meta

        # Add plugin to index
        index["plugins"][plugin_name] = plugin_meta

    return index


def _load_enabled_status() -> Dict[str, bool]:
    """Load plugin enabled status from config."""
    try:
        from ..core.config_manager import ConfigManager

        config_manager = ConfigManager()
        config = config_manager.get_config() or {}

        system_plugins = config.get("system_plugins", {}) or {}
        custom_plugins = config.get("custom_plugins", {}) or {}

        # Merge enabled status
        enabled_map = {}
        for name, enabled in system_plugins.items():
            enabled_map[name] = enabled
        for name, enabled in custom_plugins.items():
            enabled_map[name] = enabled

        return enabled_map
    except Exception:
        return {}


def _normalize_description(desc: Any) -> Dict[str, str]:
    """Normalize description to dict format."""
    if isinstance(desc, dict):
        return desc
    elif isinstance(desc, str):
        return {"zh": desc, "en": desc}
    else:
        return {"zh": "", "en": ""}


def _get_subplugins_with_descriptions(plugin) -> list:
    """Get subplugins with descriptions from plugin.

    Tries to use subplugins_full if available, otherwise falls back to subplugins.
    """
    # Try to get full subplugins info (with descriptions)
    if hasattr(plugin, "subplugins_full") and plugin.subplugins_full:
        return plugin.subplugins_full

    # Fallback: use old subplugins list (strings only)
    subplugins = getattr(plugin, "subplugins", [])
    if not subplugins:
        return []

    # Convert string list to dict format
    return [{"name": sp, "description": {"zh": "", "en": ""}} for sp in subplugins]


def _normalize_subplugins(subplugins: Any) -> list:
    """Normalize subplugins to list of dicts with descriptions.

    Input can be:
    - List of strings: ["sub1", "sub2"]
    - List of dicts: [{"name": "sub1", "description": {...}}, ...]

    Output is always list of dicts with normalized descriptions.
    """
    if not subplugins:
        return []

    result = []
    for item in subplugins:
        if isinstance(item, str):
            # Simple string - convert to dict without description
            result.append({"name": item, "description": {"zh": "", "en": ""}})
        elif isinstance(item, dict):
            # Already a dict - normalize description if present
            name = item.get("name", "")
            desc = item.get("description", {})
            result.append({"name": name, "description": _normalize_description(desc)})

    return result


def _determine_plugin_type(plugin) -> str:
    """Determine plugin type based on available functions."""
    if not hasattr(plugin, "functions"):
        return "unknown"

    func_map = plugin.functions
    if not func_map:
        return "unknown"

    types = set()
    for meta in func_map.values():
        ftype = _get_meta_value(meta, "type", "")
        if ftype in ("script", "shell_annotated"):
            types.add("shell")
        elif ftype == "config":
            types.add("json")
        elif ftype in ("python", "python_decorated"):
            types.add("python")

    if len(types) > 1:
        return "hybrid"
    elif types:
        return types.pop()
    else:
        return "unknown"


def write_router_index(index: Dict[str, Any]) -> Path:
    """Write router index to cache directory."""
    # Write to cache subdirectory
    gs_home = Path.home() / ".config" / "global-scripts"
    cache_dir = gs_home / "cache"
    cache_dir.mkdir(parents=True, exist_ok=True)
    target = cache_dir / "router.json"
    with open(target, "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False, indent=2)
    return target
