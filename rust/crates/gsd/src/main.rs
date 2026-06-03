//! `gsd` — status-light host.
//!
//! Listens on the gsd control socket for `gs event emit` envelopes (one JSON
//! line each), keeps a [`SessionStore`] of per-(source, session) phase, ages
//! stale sessions out on a timer (spec §9), aggregates everything to a single
//! traffic-light color (RED > YELLOW > GREEN), and pushes each change to a
//! [`Sink`]. Spec: tmp/phase0-status-light.md §7–§9.
//!
//! Two sinks:
//!   - **terminal** (default): prints each transition — headless, CI-friendly.
//!   - **tray** (`--features tray`): a breathing macOS/Linux/Windows menu-bar
//!     dot (spec §8) with a right-click menu listing each session's state and a
//!     Quit item. On macOS it runs dock-less (accessory activation policy).
//!     With the feature compiled, `gsd --terminal` forces the terminal sink.
//!
//! Timeouts are overridable via env (millis) for testing/demos:
//!   GS_LIGHT_BUSY_MS  (default 90000) — idle a quiet `busy` session (covers a
//!                                        user interrupt that emits no `Stop`).
//!   GS_LIGHT_ERROR_MS (default 8000)  — clear a transient `turn.error` red.

use gs_core::{gsd_socket_path, Color, Envelope, SessionStore, BUSY_IDLE_MS, ERROR_RESET_MS};

#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
#[cfg(unix)]
use std::os::unix::net::UnixListener;
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::time::{Duration, Instant};

/// Where status changes are sent: a terminal line, or the tray icon + menu.
/// `tooltip` is the per-session breakdown (`"🟡 claude-code/a; 🟢 codex/b"`).
#[cfg(unix)]
trait Sink: Send + Sync {
    fn update(&self, agg: Option<Color>, tooltip: String, cause: &str);
}

/// Prints one line per change.
#[cfg(unix)]
struct Terminal;

#[cfg(unix)]
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
    let path = gsd_socket_path();
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

#[cfg(not(unix))]
fn main() {
    // The control socket is a Unix domain socket; the Windows named-pipe path is
    // not implemented in this MVP.
    eprintln!("gsd: 目前仅支持 Unix（Windows 命名管道待实现）");
    std::process::exit(1);
}

/// The event/sweep loop: drive a [`SessionStore`] from the socket plus a 500 ms
/// sweep timer, pushing each change to `sink`. Blocks forever.
#[cfg(unix)]
fn serve(listener: UnixListener, busy_ms: u64, error_ms: u64, sink: Arc<dyn Sink>) {
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
    for conn in listener.incoming() {
        let Ok(conn) = conn else { continue };
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

/// Push to the sink only when the color *or* the per-session breakdown changed
/// (de-bounces churn and serializes the writer threads via the `last` lock).
#[cfg(unix)]
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
#[cfg(unix)]
fn env_ms(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
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
