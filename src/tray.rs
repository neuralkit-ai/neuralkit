//! `neuralkit tray` — a menu-bar presence for this machine.
//!
//! WHY THIS LIVES IN THE CLI, TODAY. The decided end-state is the Docker model: the desktop
//! app owns the privileged parts and a thin CLI asks it (plan §C — "the Docker-Desktop
//! shape"). That app does not exist yet, and a tray is useful before it does: status at a
//! glance, the site a click away. So v0 is READ-ONLY — it reports what the files already
//! say and starts no ceremonies. When the desktop app lands, this code migrates: tray-icon
//! and tao are Tauri's own extracted crates, so the menu built here is the menu it would
//! build there.
//!
//! WHAT IT DELIBERATELY DOES NOT DO YET: sign in, approve terminals, or touch the enclave.
//! Those need either a session mutation or an `NSWindow` for the ceremony, and both belong
//! to the socket protocol the desktop app will own. A tray that only tells the truth about
//! the machine's state has no failure modes worth designing around.
//!
//! The status lines are read ONCE at launch. A tray that watches files needs fsevents and a
//! refresh story; v0 would rather be honestly static than subtly stale.

use anyhow::{Context, Result};
use serde_json::Value;
use std::time::{Duration, Instant};
use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

/// Who this machine is signed in as, read from the same file every other command trusts.
/// Absent file = signed out; that is a normal state, not an error.
fn status_line() -> String {
    let read = || -> Option<String> {
        let home = std::env::var("HOME").ok()?;
        let raw = std::fs::read_to_string(format!("{home}/.config/neuralkit/credentials.json")).ok()?;
        let v: Value = serde_json::from_str(&raw).ok()?;
        let who = v
            .get("email")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .or_else(|| v.get("user").and_then(Value::as_str).map(String::from))?;
        Some(who)
    };
    match read() {
        Some(who) => format!("signed in as {who}"),
        None => "signed out".into(),
    }
}

/// Which tier of key this machine holds — the capability-legibility line plan §C asks for:
/// the weaker tier should be visible, not merely present.
fn key_line() -> String {
    let read = || -> Option<Value> {
        let home = std::env::var("HOME").ok()?;
        let raw = std::fs::read_to_string(format!("{home}/.config/neuralkit/passkey.json")).ok()?;
        serde_json::from_str(&raw).ok()
    };
    match read() {
        Some(v) if v.get("gate").and_then(Value::as_str).is_some() => "key: Secure Enclave, behind a person".into(),
        Some(v) if v.get("key").and_then(Value::as_str).is_some() => "key: software".into(),
        Some(_) => "key: hardware (metadata only on disk)".into(),
        None => "no passkey on this machine".into(),
    }
}

/// The template glyph, drawn rather than shipped: a small waveform, which is what this tool
/// is about. Template form (black + alpha) so macOS tints it for light/dark menu bars.
fn icon() -> Result<Icon> {
    const W: usize = 22;
    const H: usize = 22;
    let mut rgba = vec![0u8; W * H * 4];
    let mut set = |x: usize, y: usize| {
        if x < W && y < H {
            let i = (y * W + x) * 4;
            rgba[i] = 0;
            rgba[i + 1] = 0;
            rgba[i + 2] = 0;
            rgba[i + 3] = 255;
        }
    };
    // One period of a wave across the width, 2px thick — legible at 22px, unmistakable at a
    // glance next to neighbouring template icons.
    for x in 2..W - 2 {
        let t = (x - 2) as f32 / (W - 5) as f32 * std::f32::consts::TAU;
        let y = (H as f32 / 2.0 - t.sin() * 6.0) as usize;
        set(x, y);
        set(x, y + 1);
    }
    Icon::from_rgba(rgba, W as u32, H as u32).context("build tray icon")
}

/// Runs the menu bar item until Quit. Never returns on success — the event loop owns the
/// process from here, which is what a menu-bar agent is.
pub fn run(url: &str) -> Result<()> {
    let url = url.trim_end_matches('/').to_string();

    let menu = Menu::new();
    let status = MenuItem::new(status_line(), false, None);
    let key = MenuItem::new(key_line(), false, None);
    let open = MenuItem::new("Open neuralkit.ai", true, None);
    let quit = MenuItem::new("Quit", true, None);
    menu.append_items(&[
        &status,
        &key,
        &PredefinedMenuItem::separator(),
        &open,
        &PredefinedMenuItem::separator(),
        &quit,
    ])
    .context("build tray menu")?;

    let open_id = open.id().clone();
    let quit_id = quit.id().clone();
    let icon = icon()?;

    // The icon must be created AFTER the event loop starts on macOS — tray-icon's own
    // documented ordering — so it is built inside StartCause::Init rather than here.
    let mut tray = None;
    let event_loop = EventLoopBuilder::new().build();
    let menu_events = MenuEvent::receiver();

    event_loop.run(move |event, _, control_flow| {
        // WaitUntil, not Wait: menu events arrive on a crossbeam channel with nothing to
        // wake the loop, so a fully-parked loop would sit on a click until some other event
        // happened by. A 150ms poll is imperceptible for a menu and free for the battery.
        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(150));

        if let Event::NewEvents(StartCause::Init) = event {
            tray = Some(
                TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_tooltip("neuralkit")
                    .with_icon(icon.clone())
                    .with_icon_as_template(true)
                    .build()
                    .expect("create the menu-bar item"),
            );
        }

        if let Ok(e) = menu_events.try_recv() {
            if e.id() == &open_id {
                // Same shape login.rs uses for the browser path — macOS's `open`, no crate.
                let _ = std::process::Command::new("open").arg(&url).spawn();
            } else if e.id() == &quit_id {
                // Dropping the TrayIcon is what removes it from the bar — exiting with it
                // alive leaves a ghost icon until the system notices the process died.
                tray.take();
                *control_flow = ControlFlow::Exit;
            }
        }
    });
}
