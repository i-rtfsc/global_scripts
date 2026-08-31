# ADR 002: GS 6.0 In-Place Plugin Migration

## Status

Accepted

## Decision

GS 6.0 migrates plugins in the existing `plugins/` tree and keeps their
正式 names unchanged. Version isolation is provided by the selected `gs`
front door and runtime environment, not by suffixing plugin names or creating
a second `plugins-v6/` tree.

Examples:

```text
plugins/system/plugin.toml
plugins/grep/plugin.toml
plugins/spider/plugin.toml
plugins/multirepo/plugin.toml
```

During migration a directory may contain both `plugin.json` (5.2 compatibility)
and `plugin.toml` (GS 6.0). The GS 6.0 Rust front door prefers `plugin.toml`;
the installed 5.2 entry continues to use its existing Python/router path.

## Compatibility Boundary

- The repository branch is the GS 6.0 development branch.
- `GS_ROOT=<repository>` plus `rust/target/debug/gs` validates the new system.
- The user's installed `~/.local/bin/gs`, Fish function, user config, and cache
  remain untouched until GS 6.0 is accepted for upgrade.
- Temporary names such as `system6` or `grep6` are not valid final plugin names
  and must not be introduced for migration isolation.

## Consequences

This keeps command names, documentation, and eventual upgrade behavior stable.
It also means migration code must preserve the old `plugin.json` behavior until
the corresponding `plugin.toml` implementation has passed the GS 6.0 front-door
E2E suite.
