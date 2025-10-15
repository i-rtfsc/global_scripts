"""
Android plugin shared helpers for persistent state.
Stores state in ~/.config/global-scripts/config/android.json
Schema example: { "selected_device": "ABCD1234" }
"""

import sys
import json
from pathlib import Path
from typing import Optional, Dict

# Ensure project root on sys.path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.core.config_manager import ConfigManager


def _state_file() -> Path:
    cm = ConfigManager()
    # ~/.config/global-scripts/config/android.json
    return cm._get_config_dir() / "config" / "android.json"


def _read_state() -> Dict:
    path = _state_file()
    if not path.exists():
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _write_state(data: Dict) -> None:
    path = _state_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def get_selected_device() -> Optional[str]:
    state = _read_state()
    value = state.get("selected_device")
    return value if isinstance(value, str) and value.strip() else None


def set_selected_device(serial: Optional[str]) -> None:
    state = _read_state()
    if serial:
        state["selected_device"] = serial
    else:
        # Clear selection
        state.pop("selected_device", None)
    _write_state(state)
