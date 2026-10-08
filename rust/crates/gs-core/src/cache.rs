//! On-disk caches for the completion hot path. Each `gs __complete` is a fresh
//! process, so any reuse across Tab presses must be persisted to disk. Two caches:
//!   - **describe** (`cache/describe/<plugin>.json`): a T2+ plugin's command tree
//!     keyed by `(plugin.toml mtime, entry mtime, protocol, locale)`. Spec §2.4.
//!   - **complete** (`cache/complete/<plugin>.json`): dynamic candidate values
//!     keyed by `(command, arg, source, locale)` with a TTL. Spec §3.2 (`ttl`).
//!
//! Everything here is best-effort: any IO/parse error degrades to a cache miss
//! or a no-op write — the cache must never break or block completion.

use crate::completion::Candidate;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cache root: `$GS_CACHE_DIR` if set, else `~/.config/global-scripts/cache`.
pub fn cache_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("GS_CACHE_DIR") {
        return Some(PathBuf::from(d));
    }
    crate::home_dir().map(|h| h.join(".config/global-scripts/cache"))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// File mtime in whole seconds since the epoch, or 0 if unavailable.
fn mtime_secs(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_json<T: Serialize>(path: &Path, value: &T) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = serde_json::to_vec(value) {
        let _ = std::fs::write(path, bytes);
    }
}

// ---- describe cache ------------------------------------------------------

/// Identity of a cached describe: any change to these invalidates it (§2.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescribeKey {
    pub toml_mtime: u64,
    pub entry_mtime: u64,
    pub protocol: u32,
    pub locale: String,
}

impl DescribeKey {
    /// Build the key from the plugin directory + its `entry` (relative) path.
    pub fn new(dir: &Path, entry: &str, protocol: u32, locale: &str) -> Self {
        DescribeKey {
            toml_mtime: mtime_secs(&dir.join("plugin.toml")),
            entry_mtime: mtime_secs(&dir.join(entry)),
            protocol,
            locale: locale.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct DescribeEntry {
    key: DescribeKey,
    result: Value,
}

fn describe_path(plugin: &str) -> Option<PathBuf> {
    Some(cache_dir()?.join("describe").join(format!("{plugin}.json")))
}

/// The cached `describe` result `Value` if present and the key still matches.
pub fn read_describe(plugin: &str, key: &DescribeKey) -> Option<Value> {
    let bytes = std::fs::read(describe_path(plugin)?).ok()?;
    let entry: DescribeEntry = serde_json::from_slice(&bytes).ok()?;
    (entry.key == *key).then_some(entry.result)
}

/// Persist a fresh `describe` result under `key`.
pub fn write_describe(plugin: &str, key: &DescribeKey, result: &Value) {
    if let Some(path) = describe_path(plugin) {
        write_json(
            &path,
            &DescribeEntry {
                key: key.clone(),
                result: result.clone(),
            },
        );
    }
}

// ---- dynamic complete cache ----------------------------------------------

#[derive(Serialize, Deserialize)]
struct CompleteEntry {
    expires: u64,
    values: Vec<Candidate>,
}

fn complete_path(plugin: &str) -> Option<PathBuf> {
    Some(cache_dir()?.join("complete").join(format!("{plugin}.json")))
}

fn read_complete_map(plugin: &str) -> BTreeMap<String, CompleteEntry> {
    complete_path(plugin)
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// A completion cache key from the parts that determine the candidate set.
/// (`current` is excluded: the engine fetches the full set and the shell
/// filters by prefix.)
pub fn complete_key(command: &str, arg: &str, source: &str, locale: &str) -> String {
    format!("{command}\u{0}{arg}\u{0}{source}\u{0}{locale}")
}

/// Cached candidates for `key` if present and not past their TTL.
pub fn read_complete(plugin: &str, key: &str) -> Option<Vec<Candidate>> {
    let map = read_complete_map(plugin);
    let entry = map.get(key)?;
    (entry.expires > now_secs()).then(|| entry.values.clone())
}

/// Cache `values` under `key` for `ttl` seconds (no-op if `ttl == 0`). Prunes
/// already-expired siblings so the per-plugin file can't grow without bound.
pub fn write_complete(plugin: &str, key: &str, values: &[Candidate], ttl: u64) {
    if ttl == 0 {
        return;
    }
    let Some(path) = complete_path(plugin) else {
        return;
    };
    let now = now_secs();
    let mut map = read_complete_map(plugin);
    map.retain(|_, e| e.expires > now);
    map.insert(
        key.to_string(),
        CompleteEntry {
            expires: now + ttl,
            values: values.to_vec(),
        },
    );
    write_json(&path, &map);
}

// ---- program (interpreter) resolution cache ------------------------------

/// Absolute paths for bare program names (`python3`, `bash`, …), keyed by the
/// `PATH` they were resolved against. Every `gs` invocation is a fresh process,
/// so this is what lets the core hand the OS an absolute path for a plugin's
/// interpreter and skip probing each `PATH` directory for it on every
/// `describe` / `complete` / `invoke`. The `PATH` key means activating a venv
/// (or otherwise changing `PATH`) misses and re-resolves rather than pinning
/// the previous interpreter.
#[derive(Serialize, Deserialize, Default)]
struct ProgramCache {
    path_env: String,
    programs: BTreeMap<String, String>,
}

fn program_cache_path() -> Option<PathBuf> {
    Some(cache_dir()?.join("programs.json"))
}

fn current_path_env() -> String {
    std::env::var("PATH").unwrap_or_default()
}

fn read_program_cache() -> Option<ProgramCache> {
    serde_json::from_slice(&std::fs::read(program_cache_path()?).ok()?).ok()
}

/// The cached absolute path for `prog`, valid only while `PATH` is unchanged.
pub fn read_program(prog: &str) -> Option<PathBuf> {
    let cache = read_program_cache()?;
    if cache.path_env != current_path_env() {
        return None;
    }
    let path = PathBuf::from(cache.programs.get(prog)?);
    (!path.as_os_str().is_empty()).then_some(path)
}

/// Remember `prog` → absolute `path` for the current `PATH`. When `PATH` has
/// changed the entry map is rebuilt rather than merged, so a stale interpreter
/// from a previous environment can't linger here.
pub fn write_program(prog: &str, path: &Path) {
    let Some(file) = program_cache_path() else {
        return;
    };
    let path_env = current_path_env();
    let mut cache = match read_program_cache() {
        Some(c) if c.path_env == path_env => c,
        _ => ProgramCache {
            path_env,
            programs: BTreeMap::new(),
        },
    };
    cache
        .programs
        .insert(prog.to_string(), path.to_string_lossy().into_owned());
    write_json(&file, &cache);
}

/// Test-only: serialize cache-touching tests (they mutate the process-global
/// `GS_CACHE_DIR`) behind one lock, and point the cache at a unique, empty temp
/// dir so a test never reads or pollutes the real cache. Hold the returned guard
/// for the whole test. Shared by the `index` / `engine` tests too.
#[cfg(test)]
pub fn test_isolate(tag: &str) -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = std::env::temp_dir().join(format!("gs-cache-iso-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::env::set_var("GS_CACHE_DIR", &dir);
    // Tests spawn freshly-written scripts; on macOS the first exec of a new file
    // can hit a security scan that dwarfs the production budget. Be generous so
    // what's under test is the mechanism, not the (cold) timeout.
    std::env::set_var("GS_COMPLETE_TIMEOUT_MS", "10000");
    std::env::set_var("GS_DESCRIBE_TIMEOUT_MS", "10000");
    guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::completion::Candidate;

    fn cand(v: &str) -> Candidate {
        Candidate {
            value: v.into(),
            description: None,
        }
    }

    #[test]
    fn describe_roundtrip_and_key_mismatch_misses() {
        let _g = test_isolate("describe");
        let k1 = DescribeKey {
            toml_mtime: 1,
            entry_mtime: 2,
            protocol: 1,
            locale: "en".into(),
        };
        assert!(read_describe("p", &k1).is_none(), "cold → miss");
        let result = serde_json::json!({"name":"p","commands":[]});
        write_describe("p", &k1, &result);
        assert_eq!(read_describe("p", &k1).as_ref(), Some(&result), "hit");
        // A newer entry mtime invalidates the cache.
        let k2 = DescribeKey {
            entry_mtime: 3,
            ..k1.clone()
        };
        assert!(read_describe("p", &k2).is_none(), "changed mtime → miss");
    }

    #[test]
    fn complete_respects_ttl_and_zero_is_noop() {
        let _g = test_isolate("complete");
        let key = complete_key("co", "branch", "br", "en");
        assert!(read_complete("g", &key).is_none(), "cold → miss");
        write_complete("g", &key, &[cand("main"), cand("dev")], 0);
        assert!(read_complete("g", &key).is_none(), "ttl=0 → not written");
        write_complete("g", &key, &[cand("main"), cand("dev")], 60);
        assert_eq!(
            read_complete("g", &key).unwrap(),
            vec![cand("main"), cand("dev")],
            "fresh entry hits"
        );
    }

    #[test]
    fn program_resolution_roundtrips_and_is_keyed_by_path() {
        let _g = test_isolate("program");
        assert!(read_program("python3").is_none(), "cold → miss");
        write_program("python3", Path::new("/opt/venv/bin/python3"));
        write_program("bash", Path::new("/bin/bash"));
        assert_eq!(
            read_program("python3"),
            Some(PathBuf::from("/opt/venv/bin/python3"))
        );
        assert_eq!(read_program("bash"), Some(PathBuf::from("/bin/bash")));

        // A different PATH belongs to a different environment: the old mapping
        // must not leak across it. Simulated by rewriting the key in place —
        // other tests share this process and must not see `PATH` move.
        let file = program_cache_path().expect("cache dir");
        let mut stored: ProgramCache =
            serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
        stored.path_env = "/somewhere/else/bin".into();
        write_json(&file, &stored);

        assert!(read_program("python3").is_none(), "PATH change → miss");
        assert!(read_program("bash").is_none(), "PATH change → miss");
        write_program("python3", Path::new("/somewhere/else/bin/python3"));
        assert_eq!(
            read_program("python3"),
            Some(PathBuf::from("/somewhere/else/bin/python3"))
        );
        assert!(
            read_program("bash").is_none(),
            "an entry from the previous PATH is dropped, not merged"
        );
    }
}
