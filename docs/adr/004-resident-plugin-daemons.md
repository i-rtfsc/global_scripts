# ADR 004: T3 Resident Plugin Daemons

## Status

Accepted

## Context

The Rust front door made dispatch and completion fast (single-digit
milliseconds), but a plugin `invoke` still paid for a Python cold start on every
call. Measured on the development machine:

| Step | Cost |
|---|---|
| `python3` bare start | ~23 ms |
| + import the `gs_plugin` SDK | ~41 ms |
| + load the plugin module | ~63 ms |
| full `gs <plugin> …` call | ~65 ms |

Only 2–3 ms of that was the Rust front door; the rest was interpreter startup
that the plugin protocol (`tier = "script"`) pays once per invocation.

## Decision

GS 6.0 formal plugins run as **T3 (`tier = "rpc"`)**: a resident process kept
alive behind a Unix socket, with the Rust core proxying framed JSON-RPC between
the socket and the plugin's stdio.

- One daemon per `(plugin, generation)`, where the generation hash covers the
  manifest and entry file, so editing a plugin yields a new socket path and the
  old daemon simply ages out.
- The daemon exits after `GS_DAEMON_IDLE_MS` (default 30 s) with no client, so
  an unused interpreter (~25 MB RSS each) stops holding memory.
- A client that disconnects with requests still in flight retires the daemon:
  its late replies would otherwise reach the next caller.
- Connections are served one at a time — the plugin's stdio is a single pipe
  pair with no request multiplexing.
- **Every failure on the resident path falls back to the one-shot transport**,
  so a cold, busy, or broken daemon degrades to the pre-T3 behavior rather than
  failing a command.
- Unix only. Windows keeps the one-shot path; `GS_DAEMON=0` opts out everywhere.

No plugin source changes were needed: `gs_plugin.Plugin.run()` is already a read
loop that ends at stdin EOF, which is exactly what a resident process needs.

## Consequences

- A warm call drops from ~65 ms to ~2–6 ms (measured; see the migration status
  document for the current numbers).
- The interpreter is resolved through `$PATH` only when a daemon starts, so the
  earlier per-spawn `PATH` scan no longer happens per command.
- Plugins that cache state at import time now hold it for the daemon's lifetime
  (bounded by the idle timeout). Handlers that re-read their inputs per call —
  which the current plugins do — are unaffected.
- Plugin stderr goes to `$GS_CACHE_DIR/daemon/<plugin>.<generation>.log` instead
  of the caller's terminal, because the daemon outlives any single invocation.
- Resident daemons add background processes to `ps`; `GS_DAEMON=0` and the idle
  timeout are the escape hatches.

## Alternatives Considered

- **Port plugins to Rust (T4/native).** Removes Python entirely, but `android`
  alone is ~2400 lines of plugin logic; rejected as disproportionate for now.
- **Ship an embedded Python.** Removes the "user must install python3"
  prerequisite but keeps the ~60 ms cold start and adds bundle size.
- **Keep T2 and accept the cost.** Rejected: the plugin is invoked per command,
  and in prompt/completion paths that cost lands on every keystroke or prompt.
