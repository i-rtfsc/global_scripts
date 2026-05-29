"""Schema/version guard tests for the router index.

These lock the documented structure of ``build_router_index`` so that any
change to the on-disk ``router.json`` format is intentional (and updates the
version) rather than a silent drift that breaks shell integration.
"""

import pytest

from gscripts.router.indexer import build_router_index, ROUTER_INDEX_VERSION


# Plugin input in the same dict shape the live loader produces
# (functions keyed by name; paths/strings already serialized).
SAMPLE_PLUGINS = {
    "demo": {
        "name": "demo",
        "version": "1.0.0",
        "author": "Tester",
        "description": {"zh": "演示", "en": "Demo"},
        "homepage": "",
        "license": "",
        "enabled": True,
        "priority": 50,
        "category": "",
        "keywords": [],
        "plugin_dir": "/tmp/demo",
        "plugin_type": "shell",
        "subplugins": [],
        "functions": {
            "hello": {
                "name": "hello",
                "type": "shell",
                "command": "hello",
                "script_file": "/tmp/demo/plugin.sh",
                "subplugin": "",
                "usage": "gs demo hello",
                "description": {"zh": "打招呼", "en": "Say hello"},
                "examples": ["gs demo hello"],
            },
        },
    },
}

TOP_LEVEL_KEYS = {"version", "generated_at", "plugins"}
PLUGIN_KEYS = {
    "name",
    "version",
    "author",
    "description",
    "homepage",
    "license",
    "enabled",
    "category",
    "keywords",
    "priority",
    "plugin_dir",
    "type",
    "subplugins",
    "commands",
}
COMMAND_KEYS = {
    "name",
    "kind",
    "subplugin",
    "entry",
    "command",
    "usage",
    "description",
    "examples",
    "args",
    "completions",
}


@pytest.mark.unit
def test_router_index_version_is_pinned():
    """A version bump must be deliberate; this guards against silent drift."""
    assert ROUTER_INDEX_VERSION == "2.0"
    index = build_router_index(SAMPLE_PLUGINS)
    assert index["version"] == ROUTER_INDEX_VERSION


@pytest.mark.unit
def test_router_index_top_level_shape():
    index = build_router_index(SAMPLE_PLUGINS)
    assert set(index.keys()) == TOP_LEVEL_KEYS
    assert isinstance(index["generated_at"], str) and index["generated_at"]
    assert isinstance(index["plugins"], dict)
    assert "demo" in index["plugins"]


@pytest.mark.unit
def test_router_index_plugin_entry_has_required_keys():
    index = build_router_index(SAMPLE_PLUGINS)
    plugin = index["plugins"]["demo"]
    # Every documented field must be present (superset is allowed for forward-compat).
    missing = PLUGIN_KEYS - set(plugin.keys())
    assert not missing, f"plugin entry missing keys: {missing}"
    assert plugin["name"] == "demo"
    assert plugin["enabled"] is True
    assert plugin["type"] in {"python", "shell", "json", "hybrid"}
    assert isinstance(plugin["commands"], dict)


@pytest.mark.unit
def test_router_index_command_entry_has_required_keys():
    index = build_router_index(SAMPLE_PLUGINS)
    commands = index["plugins"]["demo"]["commands"]
    assert "hello" in commands
    cmd = commands["hello"]
    missing = COMMAND_KEYS - set(cmd.keys())
    assert not missing, f"command entry missing keys: {missing}"
    assert cmd["name"] == "hello"
    assert cmd["kind"] == "shell"
    # Shell commands point their entry at the script file.
    assert cmd["entry"].endswith("plugin.sh")


@pytest.mark.unit
def test_router_index_empty_plugins_is_well_formed():
    index = build_router_index({})
    assert set(index.keys()) == TOP_LEVEL_KEYS
    assert index["version"] == ROUTER_INDEX_VERSION
    assert index["plugins"] == {}
