//! `gsd` — status-light host.
//!
//! Listens on the gsd control endpoint for `gs event emit` envelopes (one JSON
//! line each), keeps a [`SessionStore`] of per-(source, session) phase, ages
//! stale sessions out on a timer (spec §9), aggregates everything to a single
//! traffic-light color (RED > YELLOW > GREEN), and pushes each change to a
//! [`Sink`]. Spec: tmp/phase0-status-light.md §7–§9.
//!
//! The endpoint is a **Unix-domain socket** on unix and a **named pipe** on
//! Windows (spec §7); both feed the same platform-independent event hub
//! ([`run_hub`]), so the state machine, aggregation and sink logic are shared.
//!
//! Two sinks:
//!   - **terminal** (default): prints each transition — headless, CI-friendly.
//!   - **tray** (`--features tray`): a breathing macOS/Linux menu-bar dot
//!     (spec §8) with a right-click menu listing each session's state and a Quit
//!     item. On macOS it runs dock-less (accessory activation policy). With the
//!     feature compiled, `gsd --terminal` forces the terminal sink. (The Windows
//!     tray is a follow-up; on Windows gsd ships the terminal sink today.)
//!
//! Timeouts are overridable via env (millis) for testing/demos:
//!   GS_LIGHT_BUSY_MS  (default 90000) — idle a quiet `busy` session (covers a
//!                                        user interrupt that emits no `Stop`).
//!   GS_LIGHT_ERROR_MS (default 8000)  — clear a transient `turn.error` red.

use gs_core::{Color, Envelope, SessionStore, BUSY_IDLE_MS, ERROR_RESET_MS};

use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::net::UnixListener;

/// Where status changes are sent: a terminal line, or the tray icon + menu.
/// `tooltip` is the per-session breakdown (`"🟡 claude-code/a; 🟢 codex/b"`).
trait Sink: Send + Sync {
    fn update(&self, agg: Option<Color>, tooltip: String, cause: &str);
}

/// Prints one line per change.
struct Terminal;

impl Sink for Terminal {
    fn update(&self, agg: Option<Color>, tooltip: String, cause: &str) {
        let light = match agg {
            Some(c) => format!("{} {}", c.emoji(), c.label()),
            None => "⚫ off".to_string(),
        };
        let detail = if tooltip.is_empty() {
            "（无活跃会话）".to_string()
        } else {
            tooltip
        };
        println!("  {light:<13}  ← {cause:<14}  | {detail}");
        let _ = std::io::stdout().flush();
    }
}

#[cfg(unix)]
fn main() {
    let path = gs_core::gsd_socket_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Clear any stale socket from a previous run so bind() succeeds.
    let _ = std::fs::remove_file(&path);

    let listener = match UnixListener::bind(&path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("gsd: 无法绑定 {}: {e}", path.display());
            std::process::exit(1);
        }
    };

    let busy_ms = env_ms("GS_LIGHT_BUSY_MS", BUSY_IDLE_MS);
    let error_ms = env_ms("GS_LIGHT_ERROR_MS", ERROR_RESET_MS);
    println!("gsd: 监听 {} （Ctrl-C 退出）", path.display());
    println!(
        "gsd: 超时 busy→idle {}s · error→idle {}s",
        busy_ms / 1000,
        error_ms / 1000
    );

    #[cfg(feature = "tray")]
    {
        if !std::env::args().any(|a| a == "--terminal") {
            println!("gsd: 托盘模式（菜单栏状态灯）；加 --terminal 改为纯终端");
            tray::run(listener, busy_ms, error_ms);
            return;
        }
    }
    serve(listener, busy_ms, error_ms, Arc::new(Terminal));
}

#[cfg(windows)]
fn main() {
    let busy_ms = env_ms("GS_LIGHT_BUSY_MS", BUSY_IDLE_MS);
    let error_ms = env_ms("GS_LIGHT_ERROR_MS", ERROR_RESET_MS);
    let name = gs_core::gsd_pipe_name();
    println!("gsd: 监听命名管道 {name} （Ctrl-C 退出）");
    println!(
        "gsd: 超时 busy→idle {}s · error→idle {}s",
        busy_ms / 1000,
        error_ms / 1000
    );
    // The cross-platform tray on Windows is a follow-up; ship the headless
    // terminal sink first so the event hub + named pipe are usable now.
    serve_pipe(busy_ms, error_ms, Arc::new(Terminal));
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("gsd: 不支持的平台（需要 Unix 域套接字或 Windows 命名管道）");
    std::process::exit(1);
}

/// The platform-independent event/sweep hub: drive a [`SessionStore`] from a
/// stream of connections plus a 500 ms sweep timer, pushing each change to
/// `sink`. `accept` blocks until the next inbound connection (a `gs event emit`)
/// and yields it as a reader; it returns `None` only when the endpoint is gone.
/// Both transports ([`serve`] over UDS, [`serve_pipe`] over a named pipe) feed
/// this same loop. Blocks until `accept` is exhausted.
fn run_hub(
    busy_ms: u64,
    error_ms: u64,
    sink: Arc<dyn Sink>,
    mut accept: impl FnMut() -> Option<Box<dyn Read>>,
) {
    let store = Arc::new(Mutex::new(SessionStore::new()));
    // De-dupe on (aggregate color, per-session breakdown) so the menu refreshes
    // when a non-dominant session changes even if the overall color doesn't.
    let last = Arc::new(Mutex::new((None::<Color>, String::new())));
    let base = Instant::now(); // single shared clock for apply_at + sweep

    push(&sink, &last, None, &store.lock().unwrap(), "started");

    // Sweep timer: age out stale busy/error sessions even with no traffic.
    {
        let (store, last, sink) = (Arc::clone(&store), Arc::clone(&last), Arc::clone(&sink));
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_millis(500));
            let now = base.elapsed().as_millis() as u64;
            let mut s = store.lock().unwrap();
            if s.sweep(now, busy_ms, error_ms) {
                let agg = s.aggregate();
                push(&sink, &last, agg, &s, "timeout");
            }
        });
    }

    // One connection per `gs event emit`: accept, drain its line(s), repeat.
    while let Some(conn) = accept() {
        for line in BufReader::new(conn).lines() {
            let Ok(line) = line else { break };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let env: Envelope = match serde_json::from_str(line) {
                Ok(e) => e,
                Err(e) => {
                    eprintln!("gsd: 跳过无法解析的帧 ({e}): {line}");
                    continue;
                }
            };
            let now = base.elapsed().as_millis() as u64;
            let mut s = store.lock().unwrap();
            let agg = s.apply_at(&env, now);
            push(&sink, &last, agg, &s, &env.event);
        }
    }
}

/// UDS transport: accept connections off the listener and feed [`run_hub`].
/// A transient accept error is skipped (matches the listener's own resilience);
/// the loop never ends, so the daemon serves forever.
#[cfg(unix)]
fn serve(listener: UnixListener, busy_ms: u64, error_ms: u64, sink: Arc<dyn Sink>) {
    run_hub(busy_ms, error_ms, sink, move || loop {
        match listener.accept() {
            Ok((conn, _)) => return Some(Box::new(conn) as Box<dyn Read>),
            Err(_) => continue,
        }
    });
}

/// Named-pipe transport (Windows): each `accept` creates a fresh pipe instance
/// and blocks until a client connects, then feeds [`run_hub`]. A failed accept
/// is logged and retried after a short pause rather than tearing the daemon
/// down, so a single bad connect can't stop the light.
#[cfg(windows)]
fn serve_pipe(busy_ms: u64, error_ms: u64, sink: Arc<dyn Sink>) {
    let name = gs_core::gsd_pipe_name();
    run_hub(busy_ms, error_ms, sink, move || loop {
        match winpipe::accept(&name) {
            Ok(conn) => return Some(Box::new(conn) as Box<dyn Read>),
            Err(e) => {
                eprintln!("gsd: 命名管道 accept 失败: {e}；0.5s 后重试");
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    });
}

/// Push to the sink only when the color *or* the per-session breakdown changed
/// (de-bounces churn and serializes the writer threads via the `last` lock).
fn push(
    sink: &Arc<dyn Sink>,
    last: &Mutex<(Option<Color>, String)>,
    agg: Option<Color>,
    store: &SessionStore,
    cause: &str,
) {
    let tip = store.tooltip();
    let mut l = last.lock().unwrap();
    if l.0 != agg || l.1 != tip {
        sink.update(agg, tip.clone(), cause);
        *l = (agg, tip);
    }
}

/// Parse a millisecond env override, falling back to `default`.
fn env_ms(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Windows named-pipe server, hand-wrapped over Win32 because std offers no
/// named-pipe API. Each [`accept`] is one server instance: create it, block on
/// `ConnectNamedPipe`, and hand back a [`Conn`] that reads the client's bytes
/// and tears the instance down on drop. `gs event emit` is the client and opens
/// the pipe as a plain file (no FFI needed on that side).
#[cfg(windows)]
mod winpipe {
    use std::io::{self, Read};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_BROKEN_PIPE, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{PIPE_ACCESS_INBOUND, ReadFile};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };

    /// A connected pipe instance. Reads stream the client's bytes; dropping it
    /// disconnects the client and closes the kernel handle.
    pub struct Conn {
        handle: *mut std::ffi::c_void,
    }

    impl Read for Conn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let mut read: u32 = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    buf.as_mut_ptr(),
                    buf.len() as u32,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // The client closing its end surfaces as ERROR_BROKEN_PIPE —
                // that's a clean EOF for us, not an error.
                let err = unsafe { GetLastError() };
                if err == ERROR_BROKEN_PIPE {
                    return Ok(0);
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
            Ok(read as usize)
        }
    }

    impl Drop for Conn {
        fn drop(&mut self) {
            unsafe {
                let _ = DisconnectNamedPipe(self.handle);
                let _ = CloseHandle(self.handle);
            }
        }
    }

    /// Create a fresh inbound pipe instance and block until a client connects.
    pub fn accept(name: &str) -> io::Result<Conn> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_INBOUND, // server reads, client writes
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                0,           // out buffer: unused (we never write back)
                64 * 1024,   // in buffer
                0,           // default timeout
                std::ptr::null(), // default security: this user only
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // Block for a client. ERROR_PIPE_CONNECTED = one connected between
        // create and connect; that's success, not failure.
        let connected = unsafe { ConnectNamedPipe(handle, std::ptr::null_mut()) };
        if connected == 0 {
            let err = unsafe { GetLastError() };
            if err != ERROR_PIPE_CONNECTED {
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(io::Error::from_raw_os_error(err as i32));
            }
        }
        Ok(Conn { handle })
    }
}

/// Tray renderer: a breathing menu-bar dot with a per-session menu + Quit.
#[cfg(all(unix, feature = "tray"))]
mod tray {
    use crate::{serve, Sink};
    use gs_core::Color;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use tao::event::{Event, StartCause};
    use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
    use tray_icon::menu::{Menu, MenuId, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

    const QUIT_ID: &str = "gsd:quit";

    /// Woken into the tao loop: a state change, or a menu click.
    enum UserEvent {
        Update(Option<Color>, Vec<String>), // aggregate color + per-session lines
        Menu(MenuId),
    }

    /// Forwards each change onto the event loop (the only place allowed to touch
    /// the tray, since it must live on the main thread on macOS).
    struct TraySink {
        proxy: Mutex<EventLoopProxy<UserEvent>>,
    }

    impl Sink for TraySink {
        fn update(&self, agg: Option<Color>, tooltip: String, _cause: &str) {
            let sessions = if tooltip.is_empty() {
                Vec::new()
            } else {
                tooltip.split("; ").map(str::to_string).collect()
            };
            let _ = self
                .proxy
                .lock()
                .unwrap()
                .send_event(UserEvent::Update(agg, sessions));
        }
    }

    pub fn run(listener: UnixListener, busy_ms: u64, error_ms: u64) {
        #[allow(unused_mut)]
        let mut event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();

        // Wake the loop on menu clicks (so Quit works even while idle on `Wait`).
        let menu_proxy = Mutex::new(event_loop.create_proxy());
        tray_icon::menu::MenuEvent::set_event_handler(Some(
            move |ev: tray_icon::menu::MenuEvent| {
                if let Ok(p) = menu_proxy.lock() {
                    let _ = p.send_event(UserEvent::Menu(ev.id));
                }
            },
        ));

        let sink: Arc<dyn Sink> = Arc::new(TraySink {
            proxy: Mutex::new(event_loop.create_proxy()),
        });
        std::thread::spawn(move || serve(listener, busy_ms, error_ms, sink));

        // Dock-less on macOS: menu-bar only, no Dock icon.
        #[cfg(target_os = "macos")]
        {
            use tao::platform::macos::{ActivationPolicy, EventLoopExtMacOS};
            event_loop.set_activation_policy(ActivationPolicy::Accessory);
        }

        // ≤10 fps cap, and we only tick while a light is lit. The breath is slow,
        // so this is plenty smooth — and we redraw the menu-bar icon only when its
        // *visible* state actually changed (see `drawn` below).
        let frame = Duration::from_millis(100);
        let start = Instant::now();
        let mut tray: Option<TrayIcon> = None;
        let mut current: Option<Color> = None;
        let mut sessions: Vec<String> = Vec::new();
        // (color, quantized brightness) last actually pushed to the status bar.
        // macOS turns every `set_icon` into an AppKit/WindowServer redraw, so we
        // skip it whenever the visible icon would be identical.
        let mut drawn: Option<(Option<Color>, u8)> = None;

        event_loop.run(move |event, _, control_flow| {
            // Only these events advance a frame. tao emits several housekeeping
            // events per loop turn (MainEventsCleared, RedrawEventsCleared, …);
            // redrawing on each of them turned one tick into ~40 menu-bar redraws
            // a second — the source of the whole-machine lag.
            let tick = match event {
                Event::NewEvents(StartCause::Init) => {
                    match TrayIconBuilder::new()
                        .with_tooltip("gsd — 状态灯")
                        .with_menu(Box::new(build_menu(&sessions)))
                        .with_icon(icon_for(current, breath(start.elapsed())))
                        .build()
                    {
                        Ok(t) => tray = Some(t),
                        Err(e) => eprintln!("gsd: 创建托盘失败: {e}"),
                    }
                    true
                }
                Event::NewEvents(StartCause::ResumeTimeReached { .. }) => true,
                Event::UserEvent(UserEvent::Update(agg, sess)) => {
                    current = agg;
                    sessions = sess;
                    if let Some(t) = &tray {
                        t.set_menu(Some(Box::new(build_menu(&sessions))));
                        let _ = t.set_tooltip(Some(tooltip_text(&sessions)));
                    }
                    true
                }
                Event::UserEvent(UserEvent::Menu(id)) => {
                    if id.0 == QUIT_ID {
                        // Clean exit; the launchd agent uses KeepAlive{SuccessfulExit=false},
                        // so a deliberate Quit (exit 0) is NOT relaunched.
                        std::process::exit(0);
                    }
                    false
                }
                _ => false,
            };

            // Breathe only when there's motion to convey: busy (yellow) or
            // needs-you (red). Idle/green and off hold steady, so the loop parks
            // on `Wait` — zero redraws whenever you're not being worked for, which
            // is most of the day.
            let breathing = matches!(current, Some(Color::Yellow) | Some(Color::Red));

            if tick {
                if let Some(t) = &tray {
                    let b = if breathing { breath(start.elapsed()) } else { 1.0 };
                    // Quantize to ~16 levels: imperceptible on a 4 s breath, but it
                    // collapses per-frame churn to a handful of redraws a second.
                    let key = (current, (b * 16.0) as u8);
                    if drawn != Some(key) {
                        let _ = t.set_icon(Some(icon_for(current, b)));
                        drawn = Some(key);
                    }
                }
            }

            *control_flow = if breathing {
                ControlFlow::WaitUntil(Instant::now() + frame)
            } else {
                ControlFlow::Wait
            };
        });
    }

    fn tooltip_text(sessions: &[String]) -> String {
        if sessions.is_empty() {
            "gsd — 无活跃会话".to_string()
        } else {
            format!("gsd · {}", sessions.join("   "))
        }
    }

    /// Rebuild the right-click menu: a header, one disabled line per session
    /// (who's busy / who needs you), then a Quit item.
    fn build_menu(sessions: &[String]) -> Menu {
        let menu = Menu::new();
        let _ = menu.append(&MenuItem::with_id("gsd:hdr", "gsd 状态灯", false, None));
        let _ = menu.append(&PredefinedMenuItem::separator());
        if sessions.is_empty() {
            let _ = menu.append(&MenuItem::with_id(
                "gsd:none",
                "（无活跃会话）",
                false,
                None,
            ));
        } else {
            for (i, s) in sessions.iter().enumerate() {
                let _ = menu.append(&MenuItem::with_id(format!("gsd:s{i}"), s, false, None));
            }
        }
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&MenuItem::with_id(
            QUIT_ID,
            "退出 gsd（停止状态灯）",
            true,
            None,
        ));
        menu
    }

    /// Breathing brightness in [0.4, 1.0] — a smooth cosine ease, ~4s/cycle.
    fn breath(elapsed: Duration) -> f32 {
        const PERIOD: f32 = 4.0;
        let phase = (elapsed.as_secs_f32() / PERIOD) * std::f32::consts::TAU;
        let eased = 0.5 - 0.5 * phase.cos(); // 0 → 1 → 0, eased at both ends
        0.4 + 0.6 * eased
    }

    fn icon_for(agg: Option<Color>, brightness: f32) -> Icon {
        let (rgba, w, h) = dot_rgba(agg, 36, brightness);
        Icon::from_rgba(rgba, w, h).expect("valid rgba icon")
    }

    /// A dot in the color's hue; `brightness` scales its opacity (the breathing
    /// effect). When off (no sessions) we draw a steady, dim hollow ring.
    fn dot_rgba(agg: Option<Color>, size: u32, brightness: f32) -> (Vec<u8>, u32, u32) {
        let s = size as f32;
        let (cx, cy) = (s / 2.0, s / 2.0);
        let r = s / 2.0 - 2.0;
        let (cr, cg, cb) = agg.map(Color::rgb).unwrap_or((150, 150, 150));
        let mut buf = Vec::with_capacity((size * size * 4) as usize);
        for y in 0..size {
            for x in 0..size {
                let (dx, dy) = (x as f32 + 0.5 - cx, y as f32 + 0.5 - cy);
                let dist = (dx * dx + dy * dy).sqrt();
                let alpha = if agg.is_some() {
                    (r - dist + 0.5).clamp(0.0, 1.0) * brightness
                } else {
                    let inner = r - 3.0; // hollow ring for "off"
                    (dist - inner + 0.5).clamp(0.0, 1.0) * (r - dist + 0.5).clamp(0.0, 1.0)
                };
                buf.extend_from_slice(&[cr, cg, cb, (alpha * 255.0) as u8]);
            }
        }
        (buf, size, size)
    }
}
