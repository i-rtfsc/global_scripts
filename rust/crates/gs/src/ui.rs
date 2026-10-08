//! One presentation layer for every `gs` command.
//!
//! Nothing here draws a border, pads a column, or counts a character by hand:
//! `tabled` owns tables, titles and alignment (its `ansi` feature keeps widths
//! correct when a cell carries colour), `anstyle`/`anstream` own colour and the
//! "is anyone watching" decision, `indicatif` reports long work and `inquire`
//! drives pickers. Keeping this in one module is what stops `gs status` and
//! `gs plugin list` from drifting into different visual languages.

use anstream::{AutoStream, ColorChoice};
use anstyle::{AnsiColor, Color as AnsiColorStyle, Effects, Style as AnsiStyle};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::io::{IsTerminal, Write};
use std::time::Duration;
use tabled::settings::object::{Columns, Rows};
use tabled::settings::style::{BorderColor, Style};
use tabled::settings::{Alignment, Color, Format, Margin, Modify, Panel, Remove};
use tabled::{Table, Tabled};
use unicode_width::UnicodeWidthStr;

// ---- palette -------------------------------------------------------------

fn cyan() -> AnsiStyle {
    AnsiStyle::new().fg_color(Some(AnsiColorStyle::Ansi(AnsiColor::Cyan)))
}

/// Section titles and command names.
pub fn accent() -> AnsiStyle {
    cyan().effects(Effects::BOLD)
}

/// Verdicts. Green passes, yellow warns, red fails.
pub fn ok() -> AnsiStyle {
    AnsiStyle::new().fg_color(Some(AnsiColorStyle::Ansi(AnsiColor::Green)))
}
pub fn warn() -> AnsiStyle {
    AnsiStyle::new().fg_color(Some(AnsiColorStyle::Ansi(AnsiColor::Yellow)))
}
pub fn fail() -> AnsiStyle {
    AnsiStyle::new().fg_color(Some(AnsiColorStyle::Ansi(AnsiColor::Red)))
}

/// Notes and secondary text.
pub fn dim() -> AnsiStyle {
    AnsiStyle::new().effects(Effects::DIMMED)
}

/// Wrap `text` in `style`'s escape sequences.
pub fn styled(text: &str, style: AnsiStyle) -> String {
    format!("{style}{text}{style:#}")
}

// ---- output --------------------------------------------------------------

/// Every line of `gs` output goes through `anstream`, which strips colour when
/// stdout is not a terminal, when `NO_COLOR` is set, and honours
/// `CLICOLOR_FORCE`. Callers can therefore style unconditionally.
pub fn write_line(text: &str) {
    let mut out = AutoStream::new(std::io::stdout(), color_choice());
    let _ = writeln!(out, "{text}");
}

/// A dimmed footnote (hints, counts, "nothing to do" notes).
pub fn note(text: &str) {
    write_line(&styled(text, dim()));
}

// ---- geometry ------------------------------------------------------------

/// Usable width: `COLUMNS` when a caller sets it, else the terminal, clamped so
/// a table stays readable on a very narrow or a very wide screen.
pub fn width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .or_else(|| terminal_size::terminal_size().map(|(terminal_size::Width(w), _)| w as usize))
        .unwrap_or(80)
        .clamp(40, 120)
}

/// Clip `text` to `max` display columns, marking the cut with `…`.
pub fn truncate(text: &str, max: usize) -> String {
    if UnicodeWidthStr::width(text) <= max {
        return text.to_string();
    }
    let mut out = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let w = UnicodeWidthStr::width(ch.to_string().as_str());
        if used + w > max.saturating_sub(1) {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push('…');
    out
}

// ---- tables --------------------------------------------------------------

/// The house style: rounded outline, dim border, accent-coloured header row.
fn dress(table: &mut Table, header: bool) {
    table
        .with(Style::rounded())
        .with(BorderColor::filled(Color::FG_BRIGHT_BLACK));
    if header {
        table.with(Modify::new(Rows::first()).with(Format::content(|s| styled(s, accent()))));
    }
}

/// A table with a header row drawn from the type's field names.
pub fn table<T: Tabled>(rows: Vec<T>) -> Table {
    let mut table = Table::new(rows);
    dress(&mut table, true);
    table
}

/// A titled table: the title takes the header row's place, so columns need no
/// names of their own.
pub fn titled<T: Tabled>(title: &str, rows: Vec<T>, keep_header: bool) -> Table {
    let mut table = Table::new(rows);
    if !keep_header {
        table.with(Remove::row(Rows::first()));
    }
    table.with(Panel::header(styled(title, accent())));
    dress(&mut table, keep_header);
    table
}

/// Label/value facts under a title — the shape `status`, `doctor` and
/// `plugin info` all share.
pub fn facts<T: Tabled>(title: &str, rows: Vec<T>) -> Table {
    titled(title, rows, false)
}

/// Right-align a column; counts read better that way.
pub fn right(table: &mut Table, column: usize) {
    table.with(Modify::new(Columns::single(column)).with(Alignment::right()));
}

/// Print a table through the colour-aware stream.
pub fn print(table: &Table) {
    write_line(&table.to_string());
}

/// A section heading inside a listing: `app · 应用管理`, followed by a dim rule.
///
/// Listings are made of sections rather than one flat table, because a group
/// header that sits *inside* the table reads as just another row (that was the
/// `app  Application management` problem); here it clearly frames what follows.
pub fn section(name: &str, detail: &str) {
    let detail = detail.trim();
    let head = if detail.is_empty() {
        styled(name, accent())
    } else {
        format!(
            "{} {}",
            styled(name, accent()),
            styled(&format!("· {detail}"), dim())
        )
    };
    write_line(&format!("  {head}"));
    write_line(&styled(
        &format!("  {}", "─".repeat(width().saturating_sub(4))),
        dim(),
    ));
}

/// A borderless, aligned list — the rows under a [`section`]. Columns still come
/// from `tabled`; only the frames are left off, and the whole block is indented
/// with a margin so it reads as belonging to the heading above it.
pub fn listing<T: Tabled>(rows: Vec<T>) -> Table {
    let mut table = Table::new(rows);
    // The derived header row carries empty names but still renders a blank
    // line, so drop it — the section heading above is the only title.
    table
        .with(Remove::row(Rows::first()))
        .with(Style::blank())
        .with(Margin::new(4, 0, 0, 1));
    table
}

// ---- long work -----------------------------------------------------------

/// A spinner for work that can take a moment (resolving plugin command trees,
/// scanning plugin roots). It draws to stderr only in front of a person, so it
/// never pollutes a pipe or a log, and only appears after
/// [`SPINNER_DELAY`] — a fast call should not flash anything at the user.
pub fn spinner(message: &str) -> ProgressBar {
    if plain() || !std::io::stderr().is_terminal() {
        return ProgressBar::hidden();
    }
    let bar = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::stderr());
    bar.set_style(
        ProgressStyle::with_template("{spinner} {msg}")
            .unwrap_or_else(|_| ProgressStyle::default_spinner())
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    bar.set_message(message.to_string());
    let delayed = bar.clone();
    std::thread::spawn(move || {
        std::thread::sleep(SPINNER_DELAY);
        if !delayed.is_finished() {
            delayed.enable_steady_tick(Duration::from_millis(80));
        }
    });
    bar
}

/// How long work may run silently before a spinner is warranted.
const SPINNER_DELAY: Duration = Duration::from_millis(150);

// ---- input ---------------------------------------------------------------

/// Read a boolean-ish environment flag (`1/true/on` vs `0/false/off`).
fn flag(name: &str) -> Option<bool> {
    match std::env::var(name).ok()?.to_ascii_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Some(true),
        "0" | "false" | "off" | "no" => Some(false),
        _ => None,
    }
}

/// When to colour. `Auto` is the default; the explicit switches exist because
/// "auto" cannot know that a caller piping into `less -R` still wants colour.
pub fn color_choice() -> ColorChoice {
    if flag("GS_FORCE_COLOR") == Some(true)
        || flag("GS_COLOR") == Some(true)
        || flag("CLICOLOR_FORCE") == Some(true)
    {
        return ColorChoice::Always;
    }
    if flag("GS_PLAIN") == Some(true)
        || flag("GS_COLOR") == Some(false)
        || std::env::var_os("NO_COLOR").is_some()
    {
        return ColorChoice::Never;
    }
    ColorChoice::Auto
}

/// Is this output going somewhere other than a person's terminal?
pub fn plain() -> bool {
    matches!(color_choice(), ColorChoice::Never) || !std::io::stdout().is_terminal()
}

/// May we ask the user a question? Only in front of a real terminal, and never
/// in a scripted or `--plain` run.
pub fn interactive() -> bool {
    !plain() && std::io::stdin().is_terminal() && std::env::var_os("GS_NO_INPUT").is_none()
}
