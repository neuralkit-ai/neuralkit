//! Terminal styling for the line-based commands (`auth login`, the session REPL).
//!
//! Thin wrappers over `crossterm::style` — already a dependency (the dashboard uses
//! it through ratatui), so this costs no crates. Line-based on purpose: output
//! scrolls into the shell's own history, so scrollback, selection and copy all keep
//! working. Full-screen widgets are ratatui's job (the dashboard), not the REPL's.
//!
//! Colour is emitted ONLY when stdout is a real terminal and `NO_COLOR` is unset —
//! piped output stays plain, which keeps scripts and the headless E2E (which scrapes
//! stdout) reading exactly what they read before.

use crossterm::style::{Color, Stylize};
use std::io::IsTerminal;
use std::sync::OnceLock;

static ENABLED: OnceLock<bool> = OnceLock::new();

fn enabled() -> bool {
    *ENABLED.get_or_init(|| {
        std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
    })
}

fn paint(s: &str, f: impl Fn(&str) -> String) -> String {
    if enabled() { f(s) } else { s.to_string() }
}

/// Chrome — labels, hints, anything the eye should skip on the way to the content.
pub fn dim(s: &str) -> String { paint(s, |s| s.dark_grey().to_string()) }
/// The one or two words a line is actually about.
pub fn bold(s: &str) -> String { paint(s, |s| s.bold().to_string()) }
pub fn green(s: &str) -> String { paint(s, |s| s.with(Color::Green).to_string()) }
pub fn red(s: &str) -> String { paint(s, |s| s.with(Color::Red).to_string()) }
pub fn cyan(s: &str) -> String { paint(s, |s| s.with(Color::Cyan).to_string()) }
