//! T3: resident plugin daemons.
//!
//! A `tier = "rpc"` plugin is started once and kept alive behind a Unix socket,
//! so successive `gs` calls skip the interpreter cold start — which is the
//! dominant cost of a Python plugin (measured: ~63 ms of a ~65 ms invoke;
//! `python3` alone is ~23 ms, importing the plugin SDK ~41 ms).
//!
//! Every `gs` invocation is a fresh process, so the daemon lives *outside* it:
//! it owns the plugin's stdio and proxies framed JSON-RPC between the socket and
//! the plugin. The plugin side needs no changes — `gs_plugin.Plugin.run()` is
//! already a read loop that ends at stdin EOF.
//!
//! Lifecycle rules:
//!   - the socket path embeds a [`generation`] hash of the plugin's files, so
//!     editing a plugin yields a new path and the old daemon simply ages out;
//!   - a daemon exits after `GS_DAEMON_IDLE_MS` (default 30 s) with no client,
//!     releasing the interpreter (~25 MB RSS) it is holding;
//!   - a client that vanishes with requests still in flight poisons the daemon
//!     (its replies would otherwise reach the next caller), so it exits and the
//!     next call respawns it;
//!   - connections are served one at a time: the plugin's stdio is a single
//!     pipe pair with no request multiplexing, so concurrent callers queue;
//!   - any failure on the resident path falls back to the T2 one-shot transport,
//!     so a broken daemon can never break a command.
//!
//! Unix only (Windows keeps using the one-shot transport); set `GS_DAEMON=0` to
//! disable T3 entirely.

use crate::index::LoadedManifest;
use crate::manifest::Tier;
use crate::rpc::{self, Exchange};
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};

/// Idle lifetime of a daemon with no client. Sized to cover a burst of related
/// commands (and a prompt that re-renders through `gs`), not a whole session: a
/// resident Python interpreter is ~25 MB, so an unused one should let go quickly.
/// Re-paying the ~65 ms cold start after a real pause is cheaper than holding a
/// dozen interpreters for minutes.
const DEFAULT_IDLE_MS: u64 = 30_000;
/// How long a client waits for a freshly spawned daemon to accept connections.
const DEFAULT_START_MS: u64 = 5_000;

/// Everything a daemon and its clients must agree on.
#[derive(Debug, Clone)]
pub struct DaemonSpec {
    /// Plugin name — identifies the manifest the daemon must load.
    pub plugin: String,
    /// Unix socket the daemon listens on.
    pub socket: PathBuf,
    /// Where the plugin's stderr goes (its stdout is the RPC channel).
    pub log: PathBuf,
    /// Interpreter, e.g. `python3` (already resolved to an absolute path).
    pub program: String,
    /// Interpreter argv, i.e. the plugin entry file.
    pub args: Vec<String>,
    /// Plugin directory — the plugin process's cwd.
    pub cwd: PathBuf,
}

/// Is the resident transport available and enabled? `GS_DAEMON=0/false/off`
/// opts out; the T2 one-shot path is always there as the fallback.
pub fn enabled() -> bool {
    cfg!(unix)
        && !matches!(
            std::env::var("GS_DAEMON").ok().as_deref(),
            Some("0") | Some("false") | Some("off")
        )
}

/// Deliver `requests` to the plugin, over its daemon for a T3 plugin and over
/// the one-shot transport otherwise. A resident attempt that fails for any
/// reason (spawn, connect, protocol, timeout) retries once-shot rather than
/// surfacing an error, so enabling T3 can't turn a working command into a
/// broken one.
pub fn send(m: &LoadedManifest, requests: &[Value], stderr_to_null: bool) -> io::Result<Exchange> {
    let Some((program, args)) = m.spawn() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "插件没有可执行的入口",
        ));
    };
    if let Some(spec) = resident_spec(m) {
        if let Ok(exchange) = call_resident(&spec, requests) {
            return Ok(exchange);
        }
        // Fall through: a cold, busy, or muddled daemon must not fail the call.
    }
    rpc::call_oneshot(&program, &args, Some(&m.dir), requests, stderr_to_null)
}

/// The resident spec for `m`, or `None` when it isn't a T3 plugin, T3 is
/// disabled, or there is no cache directory to put the socket in.
pub fn resident_spec(m: &LoadedManifest) -> Option<DaemonSpec> {
    if !enabled() || m.manifest.tier != Tier::Rpc {
        return None;
    }
    let (program, args) = m.spawn()?;
    let dir = daemon_dir()?;
    let stem = format!("{}.{}", m.manifest.name, generation(m));
    Some(DaemonSpec {
        plugin: m.manifest.name.clone(),
        socket: dir.join(format!("{stem}.sock")),
        log: dir.join(format!("{stem}.log")),
        program,
        args,
        cwd: m.dir.clone(),
    })
}

/// Stable id for the plugin *content*: any change to the manifest, entry file,
/// runtime, or protocol yields a different id, which changes the socket path and
/// so retires the daemon holding the previous code.
pub fn generation(m: &LoadedManifest) -> String {
    let mut h = DefaultHasher::new();
    m.dir.hash(&mut h);
    m.manifest.name.hash(&mut h);
    m.manifest.runtime.hash(&mut h);
    m.manifest.entry.hash(&mut h);
    m.manifest.protocol.hash(&mut h);
    fingerprint(&mut h, &m.dir.join("plugin.toml"));
    fingerprint(&mut h, &m.dir.join(&m.manifest.entry));
    format!("{:016x}", h.finish())
}

/// Fold a file's size and modification time (nanosecond resolution) into `h`.
/// Size is included because some filesystems only record whole seconds, where a
/// quick edit could otherwise leave the fingerprint unchanged — and an unchanged
/// fingerprint means the daemon holding the *old* code stays in service.
fn fingerprint(h: &mut DefaultHasher, path: &Path) {
    match fs::metadata(path) {
        Ok(md) => {
            md.len().hash(h);
            let nanos = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            nanos.hash(h);
        }
        Err(_) => {
            0u64.hash(h);
            0u128.hash(h);
        }
    }
}

fn daemon_dir() -> Option<PathBuf> {
    let dir = crate::cache::cache_dir()?.join("daemon");
    fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn env_ms(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

// ---- client ---------------------------------------------------------------

#[cfg(unix)]
mod unix_transport {
    use super::*;
    use std::io::{BufReader, BufWriter, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Poll granularity while a connection is open: bounds the extra latency a
    /// resident call adds on top of the plugin's own work.
    const POLL: Duration = Duration::from_millis(1);
    /// How often an idle daemon re-checks whether its plugin is still alive.
    const IDLE_TICK: Duration = Duration::from_millis(500);

    /// Connect to the plugin's daemon, starting one if needed.
    fn connect_or_start(spec: &DaemonSpec) -> io::Result<UnixStream> {
        if let Ok(stream) = UnixStream::connect(&spec.socket) {
            return Ok(stream);
        }
        start(spec)?;
        let deadline =
            Instant::now() + Duration::from_millis(env_ms("GS_DAEMON_START_MS", DEFAULT_START_MS));
        loop {
            if let Ok(stream) = UnixStream::connect(&spec.socket) {
                return Ok(stream);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("常驻插件未在期限内启动: {}", spec.socket.display()),
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Launch the daemon for this plugin detached: it must outlive this client.
    /// Concurrent starters are harmless — losing a bind race makes a daemon
    /// notice the winner and exit (see [`bind_listener`]).
    fn start(spec: &DaemonSpec) -> io::Result<()> {
        let daemon_bin = match std::env::var_os("GS_DAEMON_BIN") {
            Some(path) => PathBuf::from(path),
            None => std::env::current_exe()?,
        };
        if let Some(parent) = spec.log.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let log = fs::File::create(&spec.log)?;
        let mut cmd = Command::new(daemon_bin);
        cmd.arg("__daemon")
            .arg(&spec.plugin)
            .arg(&spec.socket)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log));
        cmd.current_dir(&spec.cwd);
        cmd.spawn()?; // deliberately not waited on
        Ok(())
    }

    /// One resident call: send every request, then read until every id has an
    /// answer. The connection stays open until this function returns, which is
    /// what tells the daemon the exchange is finished.
    pub fn call(spec: &DaemonSpec, requests: &[Value]) -> io::Result<Exchange> {
        let stream = connect_or_start(spec)?;
        let mut writer = stream.try_clone()?;
        for req in requests {
            rpc::write_message(&mut writer, req)?;
        }
        let mut reader = BufReader::new(stream);
        let want = requests.iter().filter(|r| r.get("id").is_some()).count();
        let mut exchange = Exchange::default();
        while exchange.responses.len() < want {
            match rpc::read_message(&mut reader)? {
                None => break, // daemon went away; caller falls back to one-shot
                Some(msg) => {
                    rpc::absorb(msg, &mut exchange);
                }
            }
        }
        Ok(exchange)
    }

    /// Bind the listening socket, taking over a stale one when its owner is
    /// gone. Returns `None` when another live daemon already owns the path —
    /// then this process is redundant and should exit quietly.
    fn bind_listener(socket: &Path) -> io::Result<Option<UnixListener>> {
        match UnixListener::bind(socket) {
            Ok(listener) => return Ok(Some(listener)),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {}
            Err(e) => return Err(e),
        }
        // AddrInUse: a live daemon, or a socket file left by a killed one.
        // Give a just-starting sibling a moment to begin listening before
        // declaring the path abandoned.
        for _ in 0..20 {
            if UnixStream::connect(socket).is_ok() {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        fs::remove_file(socket)?;
        UnixListener::bind(socket).map(Some)
    }

    /// Remove the socket file when the daemon stops, so the next client sees a
    /// clean miss instead of a dangling path.
    ///
    /// Only removes *its own* socket: if the cache directory was wiped and a
    /// newer daemon bound the same path, that socket belongs to the newcomer.
    struct SocketFile {
        path: PathBuf,
        identity: Option<(u64, u64)>,
    }
    impl SocketFile {
        fn new(path: PathBuf) -> Self {
            let identity = socket_identity(&path);
            SocketFile { path, identity }
        }
    }
    impl Drop for SocketFile {
        fn drop(&mut self) {
            if self.identity.is_some() && socket_identity(&self.path) == self.identity {
                let _ = fs::remove_file(&self.path);
            }
        }
    }

    /// `(device, inode)` of a path, for telling "the file I bound" apart from
    /// "a file some later daemon put at the same name".
    fn socket_identity(path: &Path) -> Option<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).ok().map(|md| (md.dev(), md.ino()))
    }

    /// Run the daemon for `spec` until it goes idle or the plugin dies.
    pub fn run(spec: DaemonSpec) -> io::Result<()> {
        let Some(listener) = bind_listener(&spec.socket)? else {
            return Ok(()); // another daemon is already serving this generation
        };
        let _socket_guard = SocketFile::new(spec.socket.clone());
        let idle = Duration::from_millis(env_ms("GS_DAEMON_IDLE_MS", DEFAULT_IDLE_MS));

        if let Some(parent) = spec.log.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let mut plugin = Command::new(&spec.program)
            .args(&spec.args)
            .current_dir(&spec.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(fs::File::create(&spec.log)?))
            .spawn()?;
        let mut plugin_in = plugin
            .stdin
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "no plugin stdin"))?;
        let plugin_out = plugin
            .stdout
            .take()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "no plugin stdout"))?;

        // One reader for the whole plugin lifetime: frames are picked up as the
        // plugin produces them and handed to whichever client is being served.
        let (frames_tx, frames_rx) = mpsc::channel::<Value>();
        let plugin_alive = Arc::new(AtomicBool::new(true));
        {
            let plugin_alive = Arc::clone(&plugin_alive);
            std::thread::spawn(move || {
                let mut reader = BufReader::new(plugin_out);
                while let Ok(Some(msg)) = rpc::read_message(&mut reader) {
                    if frames_tx.send(msg).is_err() {
                        break;
                    }
                }
                plugin_alive.store(false, Ordering::SeqCst);
            });
        }

        // Accept on a dedicated thread and hand connections over a channel: a
        // client that connects while the daemon is idle is then served at once,
        // rather than waiting out an accept-polling interval — polling here cost
        // 30–50 ms of jitter on every otherwise-warm call.
        let (conn_tx, conn_rx) = mpsc::channel::<UnixStream>();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(stream) => {
                        if conn_tx.send(stream).is_err() {
                            return; // daemon is shutting down
                        }
                    }
                    Err(_) => return,
                }
            }
        });

        let mut last_used = Instant::now();
        while plugin_alive.load(Ordering::SeqCst) {
            // Wake at least twice a second so a dead plugin is noticed promptly,
            // but treat a connection as the real event.
            let slice = idle.saturating_sub(last_used.elapsed()).min(IDLE_TICK);
            match conn_rx.recv_timeout(slice) {
                Ok(stream) => {
                    // Linux does not propagate O_NONBLOCK through accept(); some
                    // BSDs do. Be explicit so the framed reads below can block.
                    stream.set_nonblocking(false)?;
                    last_used = Instant::now();
                    if serve(stream, &mut plugin_in, &frames_rx)? {
                        break; // poisoned: the next call gets a fresh daemon
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    if last_used.elapsed() >= idle {
                        break;
                    }
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        // Closing stdin makes the SDK's read loop hit EOF and exit cleanly.
        drop(plugin_in);
        reap(plugin);
        Ok(())
    }

    /// Serve one client until it disconnects. Returns true when the daemon must
    /// stop afterwards (plugin gone, or the client left requests unanswered).
    fn serve(
        stream: UnixStream,
        plugin_in: &mut ChildStdin,
        frames: &Receiver<Value>,
    ) -> io::Result<bool> {
        let write_half = stream.try_clone()?;
        // A reader thread keeps the client side from blocking the plugin pump.
        let (req_tx, req_rx) = mpsc::channel::<Option<Value>>();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream);
            loop {
                match rpc::read_message(&mut reader) {
                    Ok(Some(req)) => {
                        if req_tx.send(Some(req)).is_err() {
                            return;
                        }
                    }
                    _ => break,
                }
            }
            let _ = req_tx.send(None); // EOF marker
        });

        let mut out = BufWriter::new(write_half);
        let mut pending = 0usize;
        let mut plugin_gone = false;
        let mut client_closed = false;
        loop {
            // Forward whatever the client has sent so far. The client writes all
            // of its requests up front, so this normally moves the whole batch
            // in one pass and the plugin starts working immediately.
            loop {
                match req_rx.try_recv() {
                    Ok(Some(req)) => {
                        if req.get("id").is_some() {
                            pending += 1;
                        }
                        // The plugin may have exited between requests.
                        if rpc::write_message(plugin_in, &req).is_err() {
                            plugin_gone = true;
                            break;
                        }
                    }
                    Ok(None) => {
                        client_closed = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        client_closed = true;
                        break;
                    }
                }
            }
            if client_closed {
                // The client waits for all of its answers before closing, so an
                // outstanding request here means it died mid-exchange: its reply
                // would be misdelivered to the next caller. Retire the daemon.
                break;
            }
            if plugin_gone {
                break;
            }
            // Block on plugin output — that is the event that matters, and it
            // wakes the moment the plugin answers. New client requests are
            // picked up at worst one POLL later, before the plugin can reply.
            match frames.recv_timeout(POLL) {
                Ok(msg) => {
                    if msg.get("id").is_some() {
                        pending = pending.saturating_sub(1);
                    }
                    // A caller that timed out or was interrupted mid-request is
                    // gone: stop serving it, and let the pending count decide
                    // whether the daemon is still safe to reuse.
                    if rpc::write_message(&mut out, &msg).is_err() || out.flush().is_err() {
                        break;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    plugin_gone = true;
                    break;
                }
            }
        }
        // An unanswered request leaves a reply in flight that would be delivered
        // to the next client: retire this daemon instead of desyncing.
        Ok(plugin_gone || pending > 0)
    }

    /// Close the plugin down: wait briefly for the EOF-triggered exit, then kill.
    fn reap(mut child: Child) {
        let deadline = Instant::now() + Duration::from_millis(500);
        while Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => break,
            }
        }
        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(unix)]
fn call_resident(spec: &DaemonSpec, requests: &[Value]) -> io::Result<Exchange> {
    unix_transport::call(spec, requests)
}

#[cfg(not(unix))]
fn call_resident(_spec: &DaemonSpec, _requests: &[Value]) -> io::Result<Exchange> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "常驻插件传输仅支持 Unix",
    ))
}

/// Run a plugin daemon until it idles out or its plugin exits. Called by the
/// `gs __daemon` subcommand; blocks for the daemon's whole lifetime.
#[cfg(unix)]
pub fn run(spec: DaemonSpec) -> io::Result<()> {
    unix_transport::run(spec)
}

#[cfg(not(unix))]
pub fn run(_spec: DaemonSpec) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "常驻插件传输仅支持 Unix",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::manifest::PluginManifest;
    use serde_json::json;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    /// A `sh` plugin that answers every request with a fixed framed response.
    /// `delay` makes the reply late enough to exercise the in-flight rule.
    fn plugin_script(delay: f32) -> String {
        format!(
            r#"while :; do
  len=""
  while IFS= read -r line; do
    clean=$(printf '%s' "$line" | tr -d '\r')
    [ -z "$clean" ] && break
    case "$clean" in
      Content-Length:*) len=${{clean#Content-Length: }} ;;
    esac
  done
  [ -z "$len" ] && exit 0
  dd bs=1 count="$len" of=/dev/null 2>/dev/null
  sleep {delay}
  body='{{"jsonrpc":"2.0","id":1,"result":{{"pong":true}}}}'
  printf 'Content-Length: %s\r\n\r\n%s' "${{#body}}" "$body"
done
"#
        )
    }

    /// A T3 manifest plus a daemon spec wired to a fresh `sh` fixture, with the
    /// socket/log under the isolated cache dir.
    fn fixture(tag: &str, delay: f32) -> (LoadedManifest, DaemonSpec) {
        let dir = std::env::temp_dir().join(format!("gs-daemon-unit-{tag}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("plugin.sh"), plugin_script(delay)).unwrap();
        fs::write(
            dir.join("plugin.toml"),
            "name = \"fake\"\ntier = \"rpc\"\nruntime = \"sh\"\nentry = \"plugin.sh\"\n",
        )
        .unwrap();
        let m = LoadedManifest {
            manifest: PluginManifest::parse(
                "name = \"fake\"\ntier = \"rpc\"\nruntime = \"sh\"\nentry = \"plugin.sh\"\n",
            )
            .unwrap(),
            dir: dir.clone(),
        };
        let cache = crate::cache::cache_dir().expect("cache dir");
        fs::create_dir_all(cache.join("daemon")).unwrap();
        let spec = DaemonSpec {
            plugin: "fake".into(),
            socket: cache.join("daemon").join(format!("{tag}.sock")),
            log: cache.join("daemon").join(format!("{tag}.log")),
            program: "sh".into(),
            args: vec![dir.join("plugin.sh").to_string_lossy().into_owned()],
            cwd: dir,
        };
        (m, spec)
    }

    fn wait_for_socket(socket: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if UnixStream::connect(socket).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("daemon never listened on {}", socket.display());
    }

    #[test]
    fn generation_tracks_plugin_content() {
        let (m, _) = fixture("generation", 0.0);
        assert_eq!(generation(&m), generation(&m), "stable while unchanged");

        let before = generation(&m);
        fs::write(m.dir.join("plugin.sh"), plugin_script(0.5)).unwrap();
        assert_ne!(
            before,
            generation(&m),
            "an edited entry file changes the id"
        );
    }

    #[test]
    fn resident_spec_requires_the_rpc_tier_and_an_enabled_cache() {
        let _g = crate::cache::test_isolate("daemon-spec");
        let (m, _) = fixture("spec", 0.0);
        assert!(resident_spec(&m).is_some(), "T3 plugin ⇒ resident");

        let oneshot = LoadedManifest {
            manifest: PluginManifest::parse(
                "name = \"fake\"\ntier = \"script\"\nruntime = \"sh\"\nentry = \"plugin.sh\"\n",
            )
            .unwrap(),
            dir: m.dir.clone(),
        };
        assert!(resident_spec(&oneshot).is_none(), "T2 stays one-shot");

        std::env::set_var("GS_DAEMON", "0");
        assert!(resident_spec(&m).is_none(), "GS_DAEMON=0 opts out");
        std::env::remove_var("GS_DAEMON");
    }

    #[test]
    fn daemon_serves_successive_clients_and_exits_when_idle() {
        let _g = crate::cache::test_isolate("daemon-serve");
        std::env::set_var("GS_DAEMON_IDLE_MS", "300");
        let (_, spec) = fixture("serve", 0.0);

        let handle = {
            let spec = spec.clone();
            std::thread::spawn(move || unix_transport::run(spec))
        };
        wait_for_socket(&spec.socket);

        for _ in 0..2 {
            let ex = call_resident(&spec, &[rpc::request(1, "ping", json!({}))]).unwrap();
            assert_eq!(ex.result_for(1).unwrap()["pong"], true);
        }

        handle.join().unwrap().unwrap();
        assert!(
            !spec.socket.exists(),
            "socket removed when the daemon stops"
        );
        std::env::remove_var("GS_DAEMON_IDLE_MS");
    }

    #[test]
    fn client_that_vanishes_with_a_request_in_flight_retires_the_daemon() {
        let _g = crate::cache::test_isolate("daemon-poison");
        std::env::set_var("GS_DAEMON_IDLE_MS", "30000");
        let (_, spec) = fixture("poison", 0.5); // reply still in flight on drop

        let handle = {
            let spec = spec.clone();
            std::thread::spawn(move || unix_transport::run(spec))
        };
        wait_for_socket(&spec.socket);

        // Connect, ask, disconnect without listening for the answer: that reply
        // would otherwise be handed to whichever caller comes next.
        {
            let mut stream = UnixStream::connect(&spec.socket).unwrap();
            rpc::write_message(&mut stream, &rpc::request(1, "ping", json!({}))).unwrap();
        }
        let started = Instant::now();
        handle.join().unwrap().unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "poisoned daemon should retire at once, not idle out: {:?}",
            started.elapsed()
        );
        std::env::remove_var("GS_DAEMON_IDLE_MS");
    }

    #[test]
    fn send_falls_back_to_one_shot_when_a_daemon_cannot_start() {
        let _g = crate::cache::test_isolate("daemon-fallback");
        let (_, spec) = fixture("fallback", 0.0);
        // A canned one-shot plugin: one response, then exit at stdin EOF.
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"pong":true}}"#;
        let m = LoadedManifest {
            manifest: PluginManifest::parse(
                "name = \"fake\"\ntier = \"rpc\"\nruntime = \"sh\"\nentry = \"emit.sh\"\n",
            )
            .unwrap(),
            dir: spec.cwd.clone(),
        };
        fs::write(
            m.dir.join("emit.sh"),
            format!(
                "printf 'Content-Length: {}\\r\\n\\r\\n%s' '{body}'\n",
                body.len()
            ),
        )
        .unwrap();
        // Point the launcher at nothing: the resident attempt cannot succeed.
        std::env::set_var("GS_DAEMON_BIN", "/nonexistent/gs-daemon");
        std::env::set_var("GS_DAEMON_START_MS", "200");

        let ex = send(&m, &[rpc::request(1, "ping", json!({}))], true).unwrap();
        assert_eq!(ex.result_for(1).unwrap()["pong"], true);

        std::env::remove_var("GS_DAEMON_BIN");
        std::env::remove_var("GS_DAEMON_START_MS");
    }
}
