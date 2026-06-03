//! Global Scripts core (PoC scope).
//!
//! Holds the data model for the generated `router.json` index (schema v2.0,
//! produced by the Python `gscripts.router.indexer`), the path-resolution
//! rules for locating that index, and the pure command-resolution logic the
//! `gs` front door uses to decide *how* to dispatch a command.
//!
//! Execution (spawning processes) lives in the `gs` binary; this crate stays
//! side-effect free so it can be unit-tested and reused by `gsd`.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub mod caps;
pub mod cache;
pub mod engine;
pub mod exec;
pub mod index;
pub mod manifest;
pub mod migrate;
pub mod rpc;

/// Top-level `router.json` shape. Unknown fields are ignored on purpose: the
/// Python indexer writes many more keys (description, author, …) the front
/// door does not need on the hot path.
#[derive(Debug, Default, Deserialize)]
pub struct RouterIndex {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub plugins: BTreeMap<String, PluginEntry>,
}

#[derive(Debug, Deserialize)]
pub struct PluginEntry {
    /// Bilingual (or arbitrary-locale) description, e.g. `{ "zh": …, "en": … }`.
    #[serde(default)]
    pub description: BTreeMap<String, String>,
    /// Absent/null is treated as enabled (matches the shell wrapper).
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub commands: BTreeMap<String, CommandEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CommandEntry {
    /// The command token (function name). Hyphens map to underscores for shell.
    #[serde(default)]
    pub name: String,
    /// "shell" | "json" | "python" (normalized by the indexer).
    #[serde(default)]
    pub kind: String,
    /// Subplugin name, or "" for a direct plugin command.
    #[serde(default)]
    pub subplugin: String,
    /// Absolute path: `.sh` for shell, the `config_file` for json, `.py` for python.
    #[serde(default)]
    pub entry: String,
    /// Command template — only populated for `kind == "json"`.
    #[serde(default)]
    pub command: String,
    /// Bilingual (or arbitrary-locale) one-line summary, e.g. `{ "zh": …, "en": … }`.
    #[serde(default)]
    pub description: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

/// Outcome of resolving an argv against the router index.
#[derive(Debug)]
pub enum Resolution {
    /// A plugin command matched. `consumed` is how many leading argv tokens the
    /// match used (1 = `gs <plugin>`, 2 = `gs <plugin> <cmd>`, 3 = subplugin form).
    Command {
        plugin: String,
        consumed: usize,
        entry: CommandEntry,
        enabled: bool,
    },
    /// Not a recognized native command — hand off to the Python CLI.
    Delegate,
}

/// Resolve `args` (everything after `gs`) against the router index.
///
/// Tries the two-token subplugin form (`"<a> <b>"`) first, then the single
/// command token, then the bare-plugin form. Anything unmatched delegates.
pub fn resolve(router: &RouterIndex, args: &[String]) -> Resolution {
    let Some(plugin) = args.first() else {
        return Resolution::Delegate;
    };
    let Some(p) = router.plugins.get(plugin) else {
        return Resolution::Delegate;
    };

    // Subplugin form: `gs <plugin> <sub> <cmd> …` keyed as "<sub> <cmd>".
    if args.len() >= 3 {
        let key = format!("{} {}", args[1], args[2]);
        if let Some(c) = p.commands.get(&key) {
            return command(plugin, 3, c, p.enabled);
        }
    }
    // Direct command: `gs <plugin> <cmd> …`.
    if args.len() >= 2 {
        if let Some(c) = p.commands.get(&args[1]) {
            return command(plugin, 2, c, p.enabled);
        }
    }
    // Bare plugin: `gs <plugin>` where a command shares the plugin name.
    if let Some(c) = p.commands.get(plugin) {
        return command(plugin, 1, c, p.enabled);
    }
    Resolution::Delegate
}

fn command(plugin: &str, consumed: usize, entry: &CommandEntry, enabled: bool) -> Resolution {
    Resolution::Command {
        plugin: plugin.to_string(),
        consumed,
        entry: entry.clone(),
        enabled,
    }
}

/// Home directory from `$HOME` (POSIX) or `$USERPROFILE` (Windows).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Locate `router.json`, trying the most specific source first.
///
/// `$ROUTER_INDEX`, then `$GS_CACHE_DIR/{router,cache/router}.json`, then the
/// two well-known `~/.config/global-scripts` locations. Returns the first that
/// exists (the Python writer and the legacy `env.sh` disagree on `/cache`, so
/// we accept both).
pub fn router_index_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("ROUTER_INDEX") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(cache) = std::env::var_os("GS_CACHE_DIR") {
        let c = PathBuf::from(cache);
        candidates.push(c.join("router.json"));
        candidates.push(c.join("cache").join("router.json"));
    }
    if let Some(home) = home_dir() {
        candidates.push(home.join(".config/global-scripts/cache/router.json"));
        candidates.push(home.join(".config/global-scripts/router.json"));
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// Parse a `router.json` file into a [`RouterIndex`].
pub fn load_router(path: &Path) -> std::io::Result<RouterIndex> {
    let data = std::fs::read(path)?;
    serde_json::from_slice(&data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// ---------------------------------------------------------------------------
// Status-light event bus — shared by `gs event emit` and `gsd`.
// Canonical events & color semantics: see tmp/phase0-status-light.md §2–§3.
// ---------------------------------------------------------------------------

/// Traffic-light state. Higher severity wins when aggregating sessions.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Color {
    Green,
    Yellow,
    Red,
}

impl Color {
    pub fn severity(self) -> u8 {
        match self {
            Color::Green => 0,
            Color::Yellow => 1,
            Color::Red => 2,
        }
    }
    pub fn emoji(self) -> &'static str {
        match self {
            Color::Green => "🟢",
            Color::Yellow => "🟡",
            Color::Red => "🔴",
        }
    }
    /// RGB for the tray dot.
    pub fn rgb(self) -> (u8, u8, u8) {
        match self {
            Color::Green => (60, 184, 90),
            Color::Yellow => (240, 180, 0),
            Color::Red => (224, 64, 56),
        }
    }
    /// Short human label for the light state.
    pub fn label(self) -> &'static str {
        match self {
            Color::Green => "idle",
            Color::Yellow => "busy",
            Color::Red => "attention",
        }
    }
}

/// What a canonical event does to a single session's light.
#[derive(Clone, Copy, Debug)]
pub enum Transition {
    Set(Color),
    Remove,
}

/// A session's phase — finer-grained than [`Color`] because two phases map to
/// red but expire differently (see [`SessionStore::sweep`]): `Error` is a
/// transient red that auto-clears, `NeedsYou` is a sticky red that waits for you.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Phase {
    Idle,
    Busy,
    NeedsYou,
    Error,
}

impl Phase {
    pub fn color(self) -> Color {
        match self {
            Phase::Idle => Color::Green,
            Phase::Busy => Color::Yellow,
            Phase::NeedsYou | Phase::Error => Color::Red,
        }
    }
}

/// What a canonical event does to a single session's phase.
#[derive(Clone, Copy, Debug)]
enum PhaseChange {
    Set(Phase),
    Remove,
    Ignore,
}

/// Map a canonical event name to a phase change. The single source of truth for
/// both [`transition_for`] and [`SessionStore`].
fn phase_for(event: &str) -> PhaseChange {
    match event {
        // idle/green: session opened, turn finished cleanly, or the agent is
        // simply waiting for your next prompt (idle nudge — NOT "needs you").
        "session.start" | "turn.ok" | "idle" => PhaseChange::Set(Phase::Idle),
        // busy: stays yellow through tool start/end until the turn ends.
        "turn.start" | "tool.start" | "tool.end" => PhaseChange::Set(Phase::Busy),
        // sticky red: approval needed, or the agent is asking you something.
        "needs.approval" | "needs.input" => PhaseChange::Set(Phase::NeedsYou),
        // transient red: a turn that ended in error (auto-clears, spec §3.3).
        "turn.error" => PhaseChange::Set(Phase::Error),
        "session.end" => PhaseChange::Remove,
        _ => PhaseChange::Ignore,
    }
}

/// Map a canonical event name to a color transition. Unknown events → `None`.
pub fn transition_for(event: &str) -> Option<Transition> {
    match phase_for(event) {
        PhaseChange::Set(p) => Some(Transition::Set(p.color())),
        PhaseChange::Remove => Some(Transition::Remove),
        PhaseChange::Ignore => None,
    }
}

/// One event from a hook adapter, sent over the gsd socket as one JSON line.
#[derive(Debug, serde::Serialize, Deserialize)]
pub struct Envelope {
    pub source: String,
    pub event: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub reason: String,
}

/// Resolve the gsd control socket path (`$GS_GSD_SOCK` › `$GS_RUNTIME_DIR` › home › /tmp).
pub fn gsd_socket_path() -> PathBuf {
    if let Some(p) = std::env::var_os("GS_GSD_SOCK") {
        return PathBuf::from(p);
    }
    if let Some(rt) = std::env::var_os("GS_RUNTIME_DIR") {
        return PathBuf::from(rt).join("gsd.sock");
    }
    if let Some(home) = home_dir() {
        return home.join(".config/global-scripts/gsd.sock");
    }
    PathBuf::from("/tmp/gsd.sock")
}

/// Windows has no Unix-domain socket, so the gsd control endpoint is a **named
/// pipe** instead (spec §7). `$GS_GSD_PIPE` overrides; otherwise the name is
/// scoped per-user under the `\\.\pipe\` namespace so two users on one machine
/// don't collide. The pipe lives in the kernel object namespace, not the
/// filesystem — there is no on-disk path to stat.
#[cfg(windows)]
pub fn gsd_pipe_name() -> String {
    if let Some(p) = std::env::var_os("GS_GSD_PIPE") {
        return p.to_string_lossy().into_owned();
    }
    let user = std::env::var("USERNAME").unwrap_or_else(|_| "default".into());
    format!(r"\\.\pipe\global-scripts-gsd-{user}")
}

/// Default timeouts (spec §9). Overridable by `gsd` (e.g. via env).
pub const BUSY_IDLE_MS: u64 = 90_000;
pub const ERROR_RESET_MS: u64 = 8_000;

#[derive(Clone, Copy)]
struct SessionState {
    phase: Phase,
    /// Millisecond timestamp (caller's clock) of the last activity in this
    /// session — used to age `Busy`/`Error` out per [`SessionStore::sweep`].
    since: u64,
}

/// Live status-light state: a [`Phase`] per `(source, session_id)` with the
/// time of its last event, plus the rule that aggregates them to one tray
/// light. Pure and testable (the caller supplies the clock); `gsd` wraps it
/// with socket I/O, a sweep timer, and rendering.
#[derive(Default)]
pub struct SessionStore {
    sessions: BTreeMap<(String, String), SessionState>,
}

impl SessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one envelope at logical time `now_ms`; returns the aggregate color
    /// afterwards (`None` when no sessions are live). Unknown events are ignored.
    pub fn apply_at(&mut self, env: &Envelope, now_ms: u64) -> Option<Color> {
        let key = (env.source.clone(), env.session_id.clone());
        match phase_for(&env.event) {
            PhaseChange::Set(phase) => {
                self.sessions.insert(
                    key,
                    SessionState {
                        phase,
                        since: now_ms,
                    },
                );
            }
            PhaseChange::Remove => {
                self.sessions.remove(&key);
            }
            PhaseChange::Ignore => {}
        }
        self.aggregate()
    }

    /// Time-agnostic convenience (`now = 0`), used where timeouts don't matter.
    pub fn apply(&mut self, env: &Envelope) -> Option<Color> {
        self.apply_at(env, 0)
    }

    /// Age sessions out (spec §9): a `Busy` session with no activity for
    /// `busy_ms` falls back to idle (covers a user interrupt that emits no
    /// `Stop`); a transient `Error` red clears after `error_ms`. A `NeedsYou`
    /// red is sticky and never times out here. Returns whether anything changed.
    pub fn sweep(&mut self, now_ms: u64, busy_ms: u64, error_ms: u64) -> bool {
        let mut changed = false;
        for st in self.sessions.values_mut() {
            let idle_after = match st.phase {
                Phase::Busy => busy_ms,
                Phase::Error => error_ms,
                _ => continue,
            };
            if now_ms.saturating_sub(st.since) >= idle_after {
                st.phase = Phase::Idle;
                st.since = now_ms;
                changed = true;
            }
        }
        changed
    }

    /// Highest-severity color across live sessions (RED > YELLOW > GREEN).
    pub fn aggregate(&self) -> Option<Color> {
        self.sessions
            .values()
            .map(|st| st.phase.color())
            .max_by_key(|c| c.severity())
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Per-session breakdown for a tooltip, e.g. `"🟡 claude-code/abc; 🟢 codex/x"`.
    pub fn tooltip(&self) -> String {
        self.sessions
            .iter()
            .map(|((src, sid), st)| {
                let who = if sid.is_empty() {
                    src.clone()
                } else {
                    format!("{src}/{sid}")
                };
                format!("{} {who}", st.phase.color().emoji())
            })
            .collect::<Vec<_>>()
            .join("; ")
    }
}

// ---------------------------------------------------------------------------
// `gs hooks install/uninstall` — write the status-light hook config into the
// agent configs (`~/.claude/settings.json`, `~/.codex/config.toml`), so each
// agent's lifecycle drives `gs event emit … --source <agent>`.
//
// Spec: tmp/phase0-status-light.md §4.2 (Claude Code) / §5.3 (Codex) / §10 #3.
//
// This module is pure (text in → text out) and side-effect free so it is
// unit-testable; the file I/O lives in the `gs` binary. Two idempotency
// strategies, one per config format:
//   - Claude Code (JSON, no comments): identify *our* entries by their command
//     signature and rewrite only the events we manage.
//   - Codex (TOML): splice a marker-delimited block, leaving the rest of the
//     file (including the user's `notify`) byte-for-byte untouched.
// ---------------------------------------------------------------------------
pub mod hooks {
    use serde_json::{json, Map, Value};

    /// `--source` values the adapters tag events with (see [`super::Envelope`]).
    pub const SOURCE_CLAUDE: &str = "claude-code";
    pub const SOURCE_CODEX: &str = "codex";

    /// Marker lines bracketing the managed block we splice into Codex's TOML.
    pub const CODEX_BEGIN: &str = "# >>> global-scripts status-light hooks (managed) >>>";
    pub const CODEX_END: &str = "# <<< global-scripts status-light hooks (managed) <<<";

    /// The Claude Code hook plan: event → groups, each group = (optional tool
    /// matcher, canonical event to emit).
    type ClaudePlan = Vec<(&'static str, Vec<(Option<&'static str>, &'static str)>)>;

    /// Build the Claude Code hook plan. Mirrors spec §4.2 — but with omitted
    /// matchers for "match all" instead of the spec's `"*"`, since Claude Code
    /// matchers are regular expressions and a bare `*` is not a valid one.
    fn claude_plan() -> ClaudePlan {
        vec![
            ("SessionStart", vec![(None, "session.start")]),
            ("UserPromptSubmit", vec![(None, "turn.start")]),
            (
                "PreToolUse",
                vec![
                    (Some("AskUserQuestion|ExitPlanMode"), "needs.input"),
                    (None, "tool.start"),
                ],
            ),
            ("PermissionRequest", vec![(None, "needs.approval")]),
            (
                "Notification",
                vec![
                    (Some("permission_prompt"), "needs.approval"),
                    // a real "agent needs structured input from you" dialog → red
                    (Some("elicitation_dialog"), "needs.input"),
                    // idle nudge ("Claude is waiting for your input") → idle/green,
                    // NOT red: finishing a turn and waiting is not "needs you".
                    (Some("idle_prompt"), "idle"),
                ],
            ),
            ("Stop", vec![(None, "turn.ok")]),
            ("StopFailure", vec![(None, "turn.error")]),
            ("SessionEnd", vec![(None, "session.end")]),
        ]
    }

    /// The Codex hook plan (spec §5.3): event → canonical event, all match-all.
    /// Codex exposes neither a turn-failure event nor free-form questions over
    /// hooks, so there is no `turn.error` / `needs.input` here — a documented
    /// downgrade vs. Claude Code (spec §5.2 / §6).
    fn codex_plan() -> &'static [(&'static str, &'static str)] {
        &[
            ("SessionStart", "session.start"),
            ("UserPromptSubmit", "turn.start"),
            ("PreToolUse", "tool.start"),
            ("PermissionRequest", "needs.approval"),
            ("Stop", "turn.ok"),
        ]
    }

    /// One Claude Code hook entry in *exec form* (`command` + `args`, no shell).
    /// The Claude docs recommend exec form: argv is passed verbatim, so there is
    /// no word-splitting or quoting hazard. The hook payload still arrives on
    /// stdin, where `gs event emit` reads the `session_id`.
    fn claude_hook(emit_event: &str, gs: &str) -> Value {
        json!({
            "type": "command",
            "command": gs,
            "args": ["event", "emit", emit_event, "--source", SOURCE_CLAUDE],
        })
    }

    fn claude_group(matcher: Option<&str>, emit_event: &str, gs: &str) -> Value {
        let hooks = json!([claude_hook(emit_event, gs)]);
        match matcher {
            Some(m) => json!({ "matcher": m, "hooks": hooks }),
            None => json!({ "hooks": hooks }),
        }
    }

    /// Does this hook object look like one of *our* `gs event emit … --source
    /// <source>` entries? Recognizes both exec form (command=`gs`, args=[…]) and
    /// a hand-written shell-string form, so we clean those up too.
    pub fn hook_is_gs_emit(hook: &Value, source: &str) -> bool {
        if hook.get("type").and_then(Value::as_str) != Some("command") {
            return false;
        }
        let cmd = hook.get("command").and_then(Value::as_str).unwrap_or("");
        let base = cmd.rsplit(['/', '\\']).next().unwrap_or(cmd);
        // exec form: command is the gs binary, args carry `emit … --source <source>`.
        if base == "gs" || base == "gs.exe" {
            if let Some(args) = hook.get("args").and_then(Value::as_array) {
                let strs: Vec<&str> = args.iter().filter_map(Value::as_str).collect();
                let has_emit = strs.contains(&"emit");
                let has_src = strs.windows(2).any(|w| w == ["--source", source]);
                if has_emit && has_src {
                    return true;
                }
            }
        }
        // shell-string form: "… gs event emit <evt> --source <source>".
        cmd.contains("event emit") && cmd.contains("--source") && cmd.contains(source)
    }

    /// A matcher group is ours iff it is non-empty and *every* hook in it is one
    /// of our emit hooks — so a user group sitting next to ours, or a mixed
    /// group, is never removed.
    fn group_is_ours(group: &Value, source: &str) -> bool {
        group
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hs| !hs.is_empty() && hs.iter().all(|h| hook_is_gs_emit(h, source)))
    }

    fn parse_settings(existing: &str) -> Result<Value, String> {
        let t = existing.trim();
        if t.is_empty() {
            return Ok(Value::Object(Map::new()));
        }
        serde_json::from_str(t).map_err(|e| e.to_string())
    }

    /// Apply (`install=true`) or remove (`install=false`) our Claude Code hooks
    /// in the given `settings.json` text. Returns `(new_text, changed)`. Returns
    /// `Err` only when the existing text is not a JSON object (or its `hooks`
    /// field is malformed) — we refuse to clobber a file we cannot safely parse.
    pub fn apply_claude(existing: &str, install: bool, gs: &str) -> Result<(String, bool), String> {
        let mut root = parse_settings(existing)?;
        if !root.is_object() {
            return Err("settings.json 顶层不是 JSON 对象".into());
        }
        if let Some(h) = root.get("hooks") {
            if !h.is_object() {
                return Err("settings.json 的 \"hooks\" 字段不是对象".into());
            }
        }
        let before = root.clone();
        {
            let obj = root.as_object_mut().expect("checked object above");
            let mut hooks = obj
                .get("hooks")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for (event, groups) in claude_plan() {
                // Start from the user's groups minus any stale ones of ours, so a
                // re-install never duplicates and an uninstall just drops ours.
                let mut arr: Vec<Value> = hooks
                    .get(event)
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|g| !group_is_ours(g, SOURCE_CLAUDE))
                    .collect();
                if install {
                    for (matcher, emit) in groups {
                        arr.push(claude_group(matcher, emit, gs));
                    }
                }
                if arr.is_empty() {
                    hooks.remove(event);
                } else {
                    hooks.insert(event.to_string(), Value::Array(arr));
                }
            }
            if hooks.is_empty() {
                obj.remove("hooks");
            } else {
                obj.insert("hooks".to_string(), Value::Object(hooks));
            }
        }
        let changed = root != before;
        let mut out = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
        out.push('\n');
        Ok((out, changed))
    }

    /// True if our Claude Code hooks appear present in this settings text.
    pub fn claude_installed(existing: &str) -> bool {
        let Ok(root) = parse_settings(existing) else {
            return false;
        };
        root.get("hooks")
            .and_then(Value::as_object)
            .is_some_and(|hooks| {
                hooks.values().any(|v| {
                    v.as_array()
                        .is_some_and(|a| a.iter().any(|g| group_is_ours(g, SOURCE_CLAUDE)))
                })
            })
    }

    /// Render a TOML basic string (double-quoted, minimal escaping). Used for
    /// the Codex `command = "..."` line, so a `gs` path with spaces or quotes
    /// survives intact.
    fn toml_str(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
        out
    }

    /// POSIX-shell-quote one argument. Codex runs a `type = "command"` hook by
    /// handing the `command` string to a shell, so a `gs` path containing spaces
    /// (or other shell metacharacters) must be quoted to survive word splitting.
    /// The common `~/.local/bin/gs` path is all-safe and emitted bare.
    fn shell_quote(arg: &str) -> String {
        let safe = !arg.is_empty()
            && arg
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'));
        if safe {
            arg.to_string()
        } else {
            format!("'{}'", arg.replace('\'', r"'\''"))
        }
    }

    /// `command = "<gs> event emit <evt> --source codex"` — unlike Claude Code's
    /// argv (`command` + `args`), Codex's hook handler takes the command as a
    /// single *string*; passing a TOML array there fails config loading with
    /// `invalid type: sequence, expected a string`. We shell-quote the `gs` path
    /// (Codex runs the string through a shell), append the rest of the argv —
    /// all space-free literals — and render the line as one TOML basic string.
    /// The hook payload still arrives on stdin, where `gs event emit` reads the
    /// session id.
    fn codex_command(emit_event: &str, gs: &str) -> String {
        let line = format!(
            "{} event emit {emit_event} --source {SOURCE_CODEX}",
            shell_quote(gs)
        );
        toml_str(&line)
    }

    /// The TOML array-of-tables for Codex (no markers), each block trailing in a
    /// newline so the section concatenates cleanly.
    pub fn codex_block(gs: &str) -> String {
        let mut s = String::new();
        for (i, (event, emit)) in codex_plan().iter().enumerate() {
            if i > 0 {
                s.push('\n');
            }
            s.push_str(&format!(
                "[[hooks.{event}]]\n[[hooks.{event}.hooks]]\ntype = \"command\"\ncommand = {}\n",
                codex_command(emit, gs)
            ));
        }
        s
    }

    /// The full managed section, markers included, ending in a newline.
    fn codex_section(gs: &str) -> String {
        format!("{CODEX_BEGIN}\n{}{CODEX_END}\n", codex_block(gs))
    }

    /// True if our managed Codex block is present.
    pub fn codex_installed(existing: &str) -> bool {
        existing.contains(CODEX_BEGIN)
    }

    /// Apply/remove our Codex hooks by splicing a marker-delimited block. The
    /// rest of the file (including the user's `notify`) is never parsed or
    /// rewritten. Returns `(new_text, changed)`.
    pub fn apply_codex(existing: &str, install: bool, gs: &str) -> (String, bool) {
        let section = codex_section(gs);
        // Existing block present → replace it (install) or cut it out (uninstall).
        if let (Some(b), Some(e)) = (existing.find(CODEX_BEGIN), existing.find(CODEX_END)) {
            if e >= b {
                let start = existing[..b].rfind('\n').map_or(0, |n| n + 1);
                let tail = &existing[e..];
                let end = e + tail.find('\n').map_or(tail.len(), |n| n + 1);
                let prefix = &existing[..start];
                let suffix = &existing[end..];
                let new = if install {
                    format!("{prefix}{section}{suffix}")
                } else {
                    // Drop the block and collapse the blank line it left behind.
                    let mut p = prefix.to_string();
                    while p.ends_with("\n\n") {
                        p.pop();
                    }
                    let s = suffix.trim_start_matches('\n');
                    if s.is_empty() {
                        p
                    } else if p.is_empty() || p.ends_with('\n') {
                        format!("{p}{s}")
                    } else {
                        format!("{p}\n{s}")
                    }
                };
                let changed = new != existing;
                return (new, changed);
            }
        }
        if !install {
            return (existing.to_string(), false);
        }
        // No block yet → append, separated by a blank line.
        let mut new = String::with_capacity(existing.len() + section.len() + 2);
        new.push_str(existing);
        if !existing.is_empty() {
            if !existing.ends_with('\n') {
                new.push('\n');
            }
            new.push('\n');
        }
        new.push_str(&section);
        (new, true)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // ---- Claude Code ----

        #[test]
        fn claude_install_into_empty_is_valid_and_detectable() {
            let (out, changed) = apply_claude("", true, "gs").unwrap();
            assert!(changed);
            let v: Value = serde_json::from_str(&out).unwrap(); // must be valid JSON
            assert!(v["hooks"]["SessionStart"].is_array());
            assert!(out.contains("session.start"));
            assert!(out.contains("claude-code"));
            assert!(claude_installed(&out));
            // exec form (command + args), not a shell string
            let h = &v["hooks"]["Stop"][0]["hooks"][0];
            assert_eq!(h["command"], json!("gs"));
            assert_eq!(
                h["args"],
                json!(["event", "emit", "turn.ok", "--source", "claude-code"])
            );
            // PreToolUse carries both the needs.input matcher group and the catch-all
            let pre = v["hooks"]["PreToolUse"].as_array().unwrap();
            assert_eq!(pre.len(), 2);
            assert_eq!(pre[0]["matcher"], json!("AskUserQuestion|ExitPlanMode"));
            assert!(pre[1].get("matcher").is_none(), "catch-all omits matcher");
        }

        #[test]
        fn idle_prompt_maps_to_green_not_red() {
            let (out, _) = apply_claude("", true, "gs").unwrap();
            let v: Value = serde_json::from_str(&out).unwrap();
            // collect each Notification group's matcher → emitted canonical event
            let mut map = std::collections::BTreeMap::new();
            for g in v["hooks"]["Notification"].as_array().unwrap() {
                let m = g["matcher"].as_str().unwrap().to_string();
                let emit = g["hooks"][0]["args"][2].as_str().unwrap().to_string();
                map.insert(m, emit);
            }
            // the idle nudge must be green/idle, not a sticky red
            assert_eq!(map.get("idle_prompt").map(String::as_str), Some("idle"));
            assert_eq!(
                map.get("elicitation_dialog").map(String::as_str),
                Some("needs.input"),
                "a real input dialog stays red"
            );
            assert_eq!(
                map.get("permission_prompt").map(String::as_str),
                Some("needs.approval")
            );
        }

        #[test]
        fn claude_install_is_idempotent() {
            let once = apply_claude("", true, "gs").unwrap().0;
            let (twice, changed) = apply_claude(&once, true, "gs").unwrap();
            assert!(!changed, "second install must be a no-op");
            assert_eq!(once, twice);
        }

        #[test]
        fn claude_uninstall_removes_only_ours() {
            let user = r#"{
                "model": "x",
                "hooks": {
                    "PreToolUse": [
                        { "matcher": "Bash", "hooks": [ { "type": "command", "command": "echo hi" } ] }
                    ]
                }
            }"#;
            let installed = apply_claude(user, true, "gs").unwrap().0;
            assert!(claude_installed(&installed));
            assert!(
                installed.contains("echo hi"),
                "user's Bash hook survives install"
            );

            let (removed, changed) = apply_claude(&installed, false, "gs").unwrap();
            assert!(changed);
            assert!(!claude_installed(&removed));
            assert!(!removed.contains("claude-code"), "all of ours gone");
            let v: Value = serde_json::from_str(&removed).unwrap();
            assert_eq!(v["model"], json!("x"));
            let pre = v["hooks"]["PreToolUse"].as_array().unwrap();
            assert_eq!(pre.len(), 1, "only the user's group remains");
            assert_eq!(pre[0]["matcher"], json!("Bash"));
        }

        #[test]
        fn claude_uninstall_introduces_no_empty_hooks() {
            let (out, changed) = apply_claude(r#"{"model":"x"}"#, false, "gs").unwrap();
            assert!(!changed);
            let v: Value = serde_json::from_str(&out).unwrap();
            assert!(v.get("hooks").is_none());
        }

        #[test]
        fn claude_invalid_json_errors() {
            assert!(apply_claude("{not json", true, "gs").is_err());
            assert!(apply_claude("[1,2,3]", true, "gs").is_err()); // top-level not an object
        }

        #[test]
        fn claude_preserves_unrelated_keys_and_absolute_path() {
            let (out, _) = apply_claude(r#"{"env":{"A":"B"}}"#, true, "/opt/bin/gs").unwrap();
            let v: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["env"]["A"], json!("B"));
            assert_eq!(
                v["hooks"]["Stop"][0]["hooks"][0]["command"],
                json!("/opt/bin/gs")
            );
            assert!(
                claude_installed(&out),
                "detection works for an absolute path too"
            );
        }

        #[test]
        fn hook_detection_distinguishes_source_and_user_hooks() {
            let user = json!({ "type": "command", "command": "echo hi" });
            assert!(!hook_is_gs_emit(&user, SOURCE_CLAUDE));
            let ours = claude_hook("turn.ok", "gs");
            assert!(hook_is_gs_emit(&ours, SOURCE_CLAUDE));
            assert!(
                !hook_is_gs_emit(&ours, SOURCE_CODEX),
                "wrong source must not match"
            );
            // shell-string form is also recognized
            let shell = json!({ "type": "command", "command": "gs event emit turn.ok --source claude-code" });
            assert!(hook_is_gs_emit(&shell, SOURCE_CLAUDE));
        }

        // ---- Codex ----

        #[test]
        fn codex_install_appends_block_with_markers() {
            let (out, changed) = apply_codex("model = \"x\"\n", true, "gs");
            assert!(changed);
            assert!(
                out.starts_with("model = \"x\"\n"),
                "user content preserved at top"
            );
            assert!(out.contains(CODEX_BEGIN) && out.contains(CODEX_END));
            assert!(out.contains("[[hooks.SessionStart]]"));
            assert!(out.contains("[[hooks.SessionStart.hooks]]"));
            assert!(out.contains("command = \"gs event emit session.start --source codex\""));
            assert!(codex_installed(&out));
        }

        #[test]
        fn codex_install_is_idempotent() {
            let once = apply_codex("model = \"x\"\n", true, "gs").0;
            let (twice, changed) = apply_codex(&once, true, "gs");
            assert!(!changed, "second install must be a no-op");
            assert_eq!(once, twice);
        }

        #[test]
        fn codex_uninstall_restores_surroundings() {
            let user = "model = \"x\"\n\n[features]\njs = false\n";
            let installed = apply_codex(user, true, "gs").0;
            let (removed, changed) = apply_codex(&installed, false, "gs");
            assert!(changed);
            assert!(!codex_installed(&removed));
            assert!(removed.contains("model = \"x\""));
            assert!(removed.contains("[features]"));
            assert!(!removed.contains("hooks."));
        }

        #[test]
        fn codex_uninstall_noop_when_absent() {
            let (out, changed) = apply_codex("model = \"x\"\n", false, "gs");
            assert!(!changed);
            assert_eq!(out, "model = \"x\"\n");
        }

        #[test]
        fn codex_command_path_with_space_is_quoted() {
            let (out, _) = apply_codex("", true, "/Apps/My Tools/gs");
            // Codex runs the command via a shell, so a spaced path is single-quoted
            // inside the TOML string rather than split into argv elements.
            assert!(out.contains(
                "command = \"'/Apps/My Tools/gs' event emit session.start --source codex\""
            ));
            assert!(codex_installed(&out));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_from(json: &str) -> RouterIndex {
        serde_json::from_str(json).unwrap()
    }

    const SAMPLE: &str = r#"{
        "version": "2.0",
        "plugins": {
            "demo": {
                "enabled": true,
                "commands": {
                    "echo": {"name": "echo", "kind": "json", "subplugin": "", "entry": "/x/commands.json", "command": "echo hi {args}"},
                    "greet": {"name": "greet", "kind": "shell", "subplugin": "", "entry": "/x/plugin.sh", "command": ""},
                    "tools build": {"name": "build", "kind": "shell", "subplugin": "tools", "entry": "/x/tools/plugin.sh", "command": ""}
                }
            },
            "off": {"enabled": false, "commands": {"x": {"name": "x", "kind": "json", "command": "true"}}}
        }
    }"#;

    #[test]
    fn resolves_direct_command() {
        let idx = index_from(SAMPLE);
        let args = vec!["demo".into(), "echo".into(), "world".into()];
        match resolve(&idx, &args) {
            Resolution::Command {
                consumed,
                entry,
                enabled,
                ..
            } => {
                assert_eq!(consumed, 2);
                assert_eq!(entry.kind, "json");
                assert!(enabled);
            }
            _ => panic!("expected command"),
        }
    }

    #[test]
    fn resolves_subplugin_form_first() {
        let idx = index_from(SAMPLE);
        let args = vec![
            "demo".into(),
            "tools".into(),
            "build".into(),
            "--release".into(),
        ];
        match resolve(&idx, &args) {
            Resolution::Command {
                consumed, entry, ..
            } => {
                assert_eq!(consumed, 3);
                assert_eq!(entry.subplugin, "tools");
                assert_eq!(entry.name, "build");
            }
            _ => panic!("expected subplugin command"),
        }
    }

    #[test]
    fn unknown_plugin_delegates() {
        let idx = index_from(SAMPLE);
        let args = vec!["nope".into(), "x".into()];
        assert!(matches!(resolve(&idx, &args), Resolution::Delegate));
    }

    #[test]
    fn disabled_plugin_reports_enabled_false() {
        let idx = index_from(SAMPLE);
        let args = vec!["off".into(), "x".into()];
        match resolve(&idx, &args) {
            Resolution::Command { enabled, .. } => assert!(!enabled),
            _ => panic!("expected command with enabled=false"),
        }
    }

    #[test]
    fn missing_enabled_defaults_true() {
        let idx = index_from(
            r#"{"plugins":{"p":{"commands":{"c":{"name":"c","kind":"json","command":"true"}}}}}"#,
        );
        match resolve(&idx, &["p".to_string(), "c".to_string()]) {
            Resolution::Command { enabled, .. } => assert!(enabled),
            _ => panic!("expected command"),
        }
    }

    // ---- status-light state machine ----

    fn env(source: &str, event: &str, session: &str) -> Envelope {
        Envelope {
            source: source.into(),
            event: event.into(),
            session_id: session.into(),
            reason: String::new(),
        }
    }

    #[test]
    fn single_session_walks_the_state_machine() {
        let mut s = SessionStore::new();
        assert_eq!(
            s.apply(&env("claude-code", "session.start", "a")),
            Some(Color::Green)
        );
        assert_eq!(
            s.apply(&env("claude-code", "turn.start", "a")),
            Some(Color::Yellow)
        );
        assert_eq!(
            s.apply(&env("claude-code", "tool.start", "a")),
            Some(Color::Yellow)
        );
        assert_eq!(
            s.apply(&env("claude-code", "needs.approval", "a")),
            Some(Color::Red)
        );
        assert_eq!(
            s.apply(&env("claude-code", "turn.ok", "a")),
            Some(Color::Green)
        );
        assert_eq!(s.apply(&env("claude-code", "session.end", "a")), None);
        assert!(s.is_empty());
    }

    #[test]
    fn aggregate_takes_highest_severity_across_sessions() {
        let mut s = SessionStore::new();
        s.apply(&env("claude-code", "session.start", "a")); // green
        s.apply(&env("codex", "turn.start", "b")); // codex busy
        assert_eq!(s.aggregate(), Some(Color::Yellow), "one busy → yellow");
        s.apply(&env("claude-code", "needs.approval", "a")); // claude red
        assert_eq!(s.aggregate(), Some(Color::Red), "any red → red");
        s.apply(&env("claude-code", "turn.ok", "a")); // claude green again
        assert_eq!(s.aggregate(), Some(Color::Yellow), "codex still busy");
    }

    #[test]
    fn unknown_event_does_not_change_state() {
        let mut s = SessionStore::new();
        s.apply(&env("codex", "session.start", "x"));
        assert_eq!(
            s.apply(&env("codex", "bogus.event", "x")),
            Some(Color::Green)
        );
    }

    #[test]
    fn idle_event_is_green_and_sticky_red_clears_on_idle() {
        // The `idle` nudge (Claude's idle_prompt) means "your turn" → green,
        // and it also lifts a lingering needs-you red (you've come back).
        let mut s = SessionStore::new();
        s.apply(&env("claude-code", "needs.input", "a"));
        assert_eq!(s.aggregate(), Some(Color::Red));
        assert_eq!(
            s.apply(&env("claude-code", "idle", "a")),
            Some(Color::Green)
        );
    }

    #[test]
    fn busy_times_out_to_idle_and_activity_resets_it() {
        let mut s = SessionStore::new();
        s.apply_at(&env("claude-code", "turn.start", "a"), 0); // busy at t=0
        assert!(!s.sweep(50, 100, 100), "not expired yet");
        assert_eq!(s.aggregate(), Some(Color::Yellow));
        // fresh activity at t=80 resets the busy timer…
        s.apply_at(&env("claude-code", "tool.start", "a"), 80);
        assert!(!s.sweep(120, 100, 100), "120-80 < 100, still busy");
        assert_eq!(s.aggregate(), Some(Color::Yellow));
        // …then a quiet stretch ages it back to idle (user interrupt, no Stop)
        assert!(s.sweep(200, 100, 100));
        assert_eq!(s.aggregate(), Some(Color::Green));
    }

    #[test]
    fn error_red_auto_clears_but_needs_you_is_sticky() {
        let mut s = SessionStore::new();
        s.apply_at(&env("codex", "turn.error", "e"), 0); // transient red
        s.apply_at(&env("claude-code", "needs.approval", "n"), 0); // sticky red
        assert_eq!(s.aggregate(), Some(Color::Red));
        // error clears after error_ms; needs.you persists → still red overall
        assert!(s.sweep(10, /* busy */ 1000, /* error */ 5));
        assert_eq!(s.aggregate(), Some(Color::Red), "needs.you keeps it red");
        // drop the sticky session → only the now-idle (formerly error) one remains
        s.apply_at(&env("claude-code", "session.end", "n"), 20);
        assert_eq!(s.aggregate(), Some(Color::Green));
        // a NeedsYou never times out, no matter how long
        s.apply_at(&env("codex", "needs.input", "q"), 20);
        assert!(!s.sweep(10_000_000, 1, 1), "NeedsYou never times out");
        assert_eq!(s.aggregate(), Some(Color::Red));
    }
}

// ---------------------------------------------------------------------------
// F8 — native, jq-free Tab completion. The `gs __complete` engine: given the
// words already typed after `gs` (excluding the partial word at the cursor),
// return the candidates for the next position, each with an optional
// locale-picked description (zsh/fish show it). Pure & testable; the front door
// wires argv/printing and the per-shell scripts call it. Spec: design.md §14 /
// §13 Q5 and tmp/phase0-plugin-protocol.md §3–§4.
// ---------------------------------------------------------------------------
pub mod completion {
    use crate::{PluginEntry, RouterIndex};
    use std::collections::BTreeMap;

    /// One completion candidate: the token plus an optional description (shown
    /// by zsh/fish; ignored by bash).
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct Candidate {
        pub value: String,
        pub description: Option<String>,
    }

    impl Candidate {
        fn new(value: impl Into<String>, description: Option<String>) -> Self {
            Self {
                value: value.into(),
                description,
            }
        }
    }

    /// Pick a description for `locale` from a `{locale: text}` map, falling back
    /// to en → zh → any. Empty strings count as absent.
    fn pick(d: &BTreeMap<String, String>, locale: &str) -> Option<String> {
        [locale, "en", "zh"]
            .into_iter()
            .filter_map(|k| d.get(k))
            .chain(d.values())
            .find(|s| !s.is_empty())
            .cloned()
    }

    /// Candidates for the position *after* `completed` (the words typed after
    /// `gs`, without the partial word at the cursor). `system` is
    /// (command, description, subcommands) for the front door's own commands.
    /// Returns value-sorted, value-unique, non-empty candidates with
    /// descriptions picked for `locale`; the shell does the prefix filtering.
    pub fn complete(
        router: &RouterIndex,
        system: &[(&str, &str, &[&str])],
        completed: &[String],
        locale: &str,
    ) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = match completed {
            // first token: front-door commands + enabled plugins
            [] => system
                .iter()
                .map(|(c, d, _)| Candidate::new(*c, (!d.is_empty()).then(|| (*d).to_string())))
                .chain(
                    router
                        .plugins
                        .iter()
                        .filter(|(_, p)| p.enabled)
                        .map(|(name, p)| {
                            Candidate::new(name.clone(), pick(&p.description, locale))
                        }),
                )
                .collect(),
            // second token: a front-door command's subcommands, else a plugin's commands
            [head] => {
                let head = head.as_str();
                if let Some((_, _, subs)) = system.iter().find(|(c, _, _)| *c == head) {
                    subs.iter().map(|s| Candidate::new(*s, None)).collect()
                } else if let Some(p) = router.plugins.get(head) {
                    plugin_tokens(p, locale)
                } else {
                    Vec::new()
                }
            }
            // third token: commands under a subplugin (keys are "<sub> <cmd>")
            [head, sub] => router
                .plugins
                .get(head.as_str())
                .map(|p| subplugin_cmds(p, sub, locale))
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        out.retain(|c| !c.value.is_empty());
        out.sort_by(|a, b| a.value.cmp(&b.value));
        out.dedup_by(|a, b| a.value == b.value);
        out
    }

    /// A plugin's first-level tokens: direct commands (with description) +
    /// subplugin group names (router.json has no per-group description).
    fn plugin_tokens(p: &PluginEntry, locale: &str) -> Vec<Candidate> {
        p.commands
            .iter()
            .map(|(key, cmd)| {
                if cmd.subplugin.is_empty() {
                    Candidate::new(key.clone(), pick(&cmd.description, locale)) // direct (key == name)
                } else {
                    Candidate::new(cmd.subplugin.clone(), None) // subplugin group (deduped by caller)
                }
            })
            .collect()
    }

    /// Commands under subplugin `sub` within a plugin.
    fn subplugin_cmds(p: &PluginEntry, sub: &str, locale: &str) -> Vec<Candidate> {
        p.commands
            .values()
            .filter(|c| c.subplugin == sub)
            .map(|c| Candidate::new(c.name.clone(), pick(&c.description, locale)))
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SYSTEM: &[(&str, &str, &[&str])] = &[
            ("version", "show version", &[]),
            (
                "hooks",
                "status-light hooks",
                &["install", "uninstall", "status"],
            ),
            ("completions", "", &["bash", "zsh", "fish"]),
        ];

        fn router() -> RouterIndex {
            serde_json::from_str(
                r#"{
                "plugins": {
                    "demo": { "enabled": true,
                      "description": {"zh":"演示插件","en":"Demo plugin"},
                      "commands": {
                        "echo": {"name":"echo","kind":"json","subplugin":"","command":"echo {args}","description":{"zh":"打印","en":"Echo"}},
                        "greet": {"name":"greet","kind":"shell","subplugin":"","entry":"/x.sh"},
                        "tools build": {"name":"build","kind":"shell","subplugin":"tools","entry":"/x.sh","description":{"zh":"构建","en":"Build"}},
                        "tools run": {"name":"run","kind":"shell","subplugin":"tools","entry":"/x.sh"}
                    }},
                    "off": { "enabled": false, "commands": {
                        "x": {"name":"x","kind":"json","subplugin":"","command":"true"}
                    }}
                }
            }"#,
            )
            .unwrap()
        }

        fn vals(cs: Vec<Candidate>) -> Vec<String> {
            cs.into_iter().map(|c| c.value).collect()
        }

        #[test]
        fn top_level_lists_system_and_enabled_plugins() {
            let got = vals(complete(&router(), SYSTEM, &[], "en"));
            assert!(got.contains(&"version".to_string()));
            assert!(got.contains(&"hooks".to_string()));
            assert!(got.contains(&"demo".to_string()));
            assert!(
                !got.contains(&"off".to_string()),
                "disabled plugin hidden at top level"
            );
        }

        #[test]
        fn plugin_tokens_merge_direct_and_subplugin() {
            // direct commands + the subplugin group name, sorted & deduped
            assert_eq!(
                vals(complete(&router(), SYSTEM, &["demo".into()], "en")),
                vec!["echo", "greet", "tools"]
            );
        }

        #[test]
        fn subplugin_commands() {
            assert_eq!(
                vals(complete(
                    &router(),
                    SYSTEM,
                    &["demo".into(), "tools".into()],
                    "en"
                )),
                vec!["build", "run"]
            );
        }

        #[test]
        fn system_subcommands_and_unknowns() {
            assert_eq!(
                vals(complete(&router(), SYSTEM, &["hooks".into()], "en")),
                vec!["install", "status", "uninstall"]
            );
            assert!(complete(&router(), SYSTEM, &["nope".into()], "en").is_empty());
        }

        #[test]
        fn descriptions_follow_locale_with_fallback() {
            let find = |cs: &[Candidate], v: &str| {
                cs.iter()
                    .find(|c| c.value == v)
                    .unwrap()
                    .description
                    .clone()
            };
            let zh = complete(&router(), SYSTEM, &[], "zh");
            assert_eq!(find(&zh, "demo").as_deref(), Some("演示插件"));
            let en = complete(&router(), SYSTEM, &[], "en");
            assert_eq!(find(&en, "demo").as_deref(), Some("Demo plugin"));
            // unknown locale falls back en → zh → any
            let cmds = complete(&router(), SYSTEM, &["demo".into()], "fr");
            assert_eq!(find(&cmds, "echo").as_deref(), Some("Echo"));
            assert_eq!(find(&cmds, "greet"), None, "no description → None");
            // system command descriptions: present, and "" → None
            assert_eq!(find(&en, "version").as_deref(), Some("show version"));
            assert_eq!(find(&en, "completions"), None);
        }
    }
}
