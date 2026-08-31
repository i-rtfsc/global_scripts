# GS 6.0 Migration Status

[中文](../gs6-migration-status.md)

GS 6.0 uses the formal plugin names and the in-place `plugins/` tree. All formal
plugins currently report `6.0.0-dev`; the global 5.2 entry remains unchanged.
`scripts/setup.py` is the legacy 5.2 installer and is not part of the GS6
development or verification path.

The default GS6 source mode is isolated: it loads only `$GS_ROOT/plugins` and
ignores examples, user plugins, `GS_PLUGIN_PATH`, and legacy `router.json`.
Set `GS_INCLUDE_EXAMPLES=1` for development examples, or
`GS_ALLOW_LEGACY=1` for explicit compatibility fallback.

All non-Android offline gates currently pass. Android code migration is complete;
only real-device read-only regression remains pending when an ADB device is
available. Menubar and the agent status light are permanently excluded from GS6.

The inventory now contains 15 formal GS6 plugins and no metadata-only legacy
plugins. Flyme, Sync, VPS, Identity, SGM, and the remaining MultiRepo commands have been migrated.
Command parity is complete, but staging success alone
does not mean full GS5.2 feature parity.

See [the release checklist](../gs6-release-checklist.md) before changing the
global `gs` entry.
