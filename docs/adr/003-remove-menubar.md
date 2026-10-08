# ADR 003: Remove Menubar from GS 6.0

## Status

Accepted

## Decision

GS 6.0 does not include the macOS `menubar` application. The existing Python
menubar implementation remains in the repository only as a GS 5.2 legacy
compatibility component; it is not migrated to `plugin.toml`, not included in
the Rust workspace, and not part of the GS 6.0 acceptance gate.

The agent status-light feature has already been removed permanently and must not
be reintroduced through the legacy menubar path.

## Rationale

Menubar is macOS-specific, depends on `rumps`, and couples command history,
system monitoring, shortcuts and IPC to the old Python runtime. These features
are not required by the GS 6.0 plugin protocol or command front door. A future
desktop companion, if needed, should be a separate project with an explicit
IPC contract.

## Compatibility

- GS 5.2 users may continue using the existing Python menubar commands.
- GS 6.0 discovery ignores `plugins/menubar` because it has no `plugin.toml`.
- No global 5.2 installation, user config, cache or shell entry is changed by
  this decision.
