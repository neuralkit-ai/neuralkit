//! `neuralkit tray` — a menu-bar presence for this machine.
//!
//! WHY THIS LIVES IN THE CLI, TODAY. The decided end-state is the Docker model: the desktop
//! app owns the privileged parts and a thin CLI asks it (plan §C — "the Docker-Desktop
//! shape"). That app does not exist yet, and a tray is useful before it does: status at a
//! glance, the site a click away. So the tray REPORTS what the files already say and starts
//! no ceremonies. When the desktop app lands, this code migrates: tray-icon and tao are
//! Tauri's own extracted crates, so the menu built here is the menu it would build there.
//!
//! TWO KINDS OF TRUTH, KEPT VISIBLY APART. The top block is the SESSION — transient,
//! expiring, gone on logout. "This machine" is the REGISTRATION — the credential and its
//! owner, which deliberately outlive every session (passkey.rs's whole reason for a second
//! file). Blurring these is how "signed in but expired" confusion happens, so the menu
//! keeps the same boundary the files do.
//!
//! NOISE BUDGET. One line per fact-cluster, and the exception rather than the norm: an
//! authenticator that IS set up says nothing — only the actionable absence gets a row.
//!
//! THE ONE WRITE: the hardware-gate toggle. A local file edit (`passkey::set_gate`) — no
//! server, no session, no NSWindow — so it fits the "no ceremonies" boundary, and it is
//! the surface the dropped `auth passkey presence` subcommand was waiting for.
//!
//! Status is read ONCE at launch. A tray that watches files needs fsevents and a refresh
//! story; this one would rather be honestly static than subtly stale.

use anyhow::{Context, Result};
use serde_json::Value;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tao::event::{Event, StartCause};
use tao::event_loop::{ControlFlow, EventLoopBuilder};
use tray_icon::menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIconBuilder};

/// Everything the menu says, read from the two files the CLI already trusts. Collected in
/// one pass so the menu is a consistent snapshot rather than a mix of moments.
struct Snapshot {
    signed_in: Option<String>,
    /// Absolute ms timestamp the session record carries — the same `expires` the REPL's
    /// deadline uses, so the tray and the session agree about when the end is.
    expires_ms: Option<i64>,
    totp: Option<bool>,
    /// Who the credential was REGISTERED to — written at registration time, because the
    /// session file only knows who is signed in now, which is a different question.
    account: Option<String>,
    has_software_key: bool,
    registered: bool,
    gated: bool,
}

fn read_json(path: &str) -> Option<Value> {
    let home = std::env::var("HOME").ok()?;
    let raw = std::fs::read_to_string(format!("{home}/.config/neuralkit/{path}")).ok()?;
    serde_json::from_str(&raw).ok()
}

fn snapshot() -> Snapshot {
    let creds = read_json("credentials.json");
    let pk = read_json("passkey.json");
    let field = |v: &Option<Value>, k: &str| -> Option<String> {
        v.as_ref()?
            .get(k)?
            .as_str()
            .filter(|s| !s.is_empty())
            .map(String::from)
    };
    Snapshot {
        signed_in: field(&creds, "email").or_else(|| field(&creds, "user")),
        expires_ms: creds.as_ref().and_then(|v| v.get("expires")).and_then(Value::as_i64),
        totp: creds.as_ref().and_then(|v| v.get("totp_enabled")).and_then(Value::as_bool),
        // Owner precedence: an `account` field beside the credential would win — none is
        // written today (the registration path is tested and frozen), so the identity the
        // bootstrap left in credentials.json stands in. It survives expiry (only logout /
        // the REPL deadline remove the file), which is exactly the residue this reads.
        // Known edge, accepted: a machine registered as A whose last sign-in was B would
        // caption A's credential with B — the true fix is writing the owner at
        // registration time, and that waits for the auth freeze to lift.
        account: field(&pk, "account")
            .or_else(|| field(&creds, "email"))
            .or_else(|| field(&creds, "user")),
        has_software_key: field(&pk, "key").is_some(),
        registered: field(&pk, "credential_id").is_some(),
        gated: field(&pk, "gate").is_some(),
    }
}

/// "2h 04m" / "3d" — coarse on purpose: a menu is a glance, not a clock.
fn left(expires_ms: i64, now_ms: i64) -> String {
    let mins = (expires_ms - now_ms).max(0) / 60_000;
    match mins {
        m if m >= 2880 => format!("{}d", m / 1440),
        m if m >= 60 => format!("{}h {:02}m", m / 60, m % 60),
        m => format!("{m}m"),
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
    for x in 2..W - 2 {
        let t = (x - 2) as f32 / (W - 5) as f32 * std::f32::consts::TAU;
        let y = (H as f32 / 2.0 - t.sin() * 6.0) as usize;
        set(x, y);
        set(x, y + 1);
    }
    Icon::from_rgba(rgba, W as u32, H as u32).context("build tray icon")
}

/// The one-instance lock — flock, not a PID file, because the kernel releases a flock
/// with the process (crash, kill -9, anything), so there is no stale state to repair and
/// no liveness probing. Holding the returned file IS holding the lock. Two icons were
/// tolerable while the tray was a status card; the moment it owns processes (the relay is
/// next), two owners fighting over one port is a UX bug, so singleness lands first.
fn instance_lock() -> Result<Option<std::fs::File>> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let dir = format!("{home}/.config/neuralkit");
    std::fs::create_dir_all(&dir)?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(format!("{dir}/tray.lock"))?;
    use std::os::unix::io::AsRawFd as _;
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    Ok(if rc == 0 { Some(f) } else { None })
}

/// Whether a tray already holds the lock — for callers (the REPL) that want to say
/// "already up" instead of spawning a child that will only exit. Probe-and-release:
/// the momentary acquisition is invisible to anyone else.
pub fn is_running() -> bool {
    matches!(instance_lock(), Ok(None))
}

/// Turn OFF a running tray from outside: the pid lives in the lock file (written
/// by the holder at startup), SIGTERM asks it to leave, and the flock releasing is
/// the proof it did — kernel truth, not a guess. False = nothing was running, or
/// it didn't die within the grace window.
pub fn stop_running() -> bool {
    if !is_running() {
        return false;
    }
    let Ok(home) = std::env::var("HOME") else { return false };
    let Some(pid) = std::fs::read_to_string(format!("{home}/.config/neuralkit/tray.lock"))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
    else {
        return false;
    };
    unsafe { libc::kill(pid, libc::SIGTERM) };
    for _ in 0..20 {
        if !is_running() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    false
}

/// What a detached spawn actually did — callers render it their own way (the REPL
/// prints lines; the front-door menu writes an in-place status row).
pub enum SpawnOutcome {
    AlreadyRunning,
    /// The child HOLDS THE LOCK — confirmed, not assumed. This is what makes a
    /// menu label drawn immediately afterwards truthful (the naive version raced
    /// the child's startup and redrew "off" over a tray that was coming up).
    Started,
    /// Spawned, but the lock didn't appear within the grace window.
    Unconfirmed,
    Failed(String),
}

/// Spawn the status tray detached and wait for the flock to CONFIRM it's up.
pub fn spawn_detached_quiet() -> SpawnOutcome {
    if is_running() {
        return SpawnOutcome::AlreadyRunning;
    }
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => return SpawnOutcome::Failed(e.to_string()),
    };
    use std::os::unix::process::CommandExt as _;
    match std::process::Command::new(exe)
        .arg("tray")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0)
        .spawn()
    {
        Ok(mut child) => {
            // Reap on a throwaway thread so a menu-Quit before the parent exits
            // doesn't leave a zombie at the table.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            for _ in 0..30 {
                if is_running() {
                    return SpawnOutcome::Started;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            SpawnOutcome::Unconfirmed
        }
        Err(e) => SpawnOutcome::Failed(e.to_string()),
    }
}

/// The printing wrapper — the REPL's `tray` verb.
pub fn spawn_detached() {
    match spawn_detached_quiet() {
        SpawnOutcome::AlreadyRunning => println!(
            "  {} {}",
            crate::style::green("✓"),
            crate::style::dim("the tray is already in the menu bar"),
        ),
        SpawnOutcome::Started => println!(
            "  {} {}",
            crate::style::green("✓"),
            crate::style::dim("tray is up — quit it from its menu"),
        ),
        SpawnOutcome::Unconfirmed => println!(
            "  {} {}",
            crate::style::green("✓"),
            crate::style::dim("tray starting — icon should appear momentarily"),
        ),
        SpawnOutcome::Failed(e) => println!("  {} could not start the tray: {e}", crate::style::red("✗")),
    }
}

/// The relay's glyph — a ring, distinct from the status card's waveform at a glance:
/// two icons, two processes, two shapes.
fn icon_ring() -> Result<Icon> {
    const W: usize = 22;
    const H: usize = 22;
    let mut rgba = vec![0u8; W * H * 4];
    let mut set = |x: i32, y: i32| {
        if (0..W as i32).contains(&x) && (0..H as i32).contains(&y) {
            let i = (y as usize * W + x as usize) * 4;
            rgba[i + 3] = 255;
        }
    };
    let (cx, cy, r) = (11.0f32, 11.0f32, 7.0f32);
    for step in 0..256 {
        let a = step as f32 / 256.0 * std::f32::consts::TAU;
        set((cx + a.cos() * r) as i32, (cy + a.sin() * r) as i32);
        set((cx + a.cos() * (r - 1.0)) as i32, (cy + a.sin() * (r - 1.0)) as i32);
    }
    // A center dot: a ring alone reads as "off"; a nucleus reads as "carrying something".
    for dx in -1i32..=1 {
        for dy in -1i32..=1 {
            set(11 + dx, 11 + dy);
        }
    }
    Icon::from_rgba(rgba, W as u32, H as u32).context("build relay icon")
}

/// The relay's own menu-bar presence — its whole lifetime, on the same one-icon-one-process
/// contract as the status card. Never returns: Quit exits the process (the flock and the
/// relay task die with it), and a relay that stops on its own takes the icon down rather
/// than leaving a lie in the menu bar.
pub fn relay_icon(
    bind: String,
    lock: std::fs::File,
    dead: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    let menu = Menu::new();
    // Which relay this is — the same tell-me-what-it's-wired-to rule the dashboard's
    // relay/protocol label follows.
    menu.append(&MenuItem::new(format!("relay — {bind}"), false, None)).context("menu")?;
    menu.append(&MenuItem::new(format!("logs: {}", crate::relay::log_path().unwrap_or_default()), false, None))
        .context("menu")?;
    menu.append(&MenuItem::new("view: run `neuralkit relay` in a terminal", false, None)).context("menu")?;
    menu.append(&PredefinedMenuItem::separator()).context("menu")?;
    let quit = MenuItem::new("Quit relay", true, None);
    menu.append(&quit).context("menu")?;

    let quit_id = quit.id().clone();
    let icon = icon_ring()?;
    let mut tray = None;
    let event_loop = EventLoopBuilder::new().build();
    let menu_events = MenuEvent::receiver();

    event_loop.run(move |event, _, control_flow| {
        let _hold = &lock;
        *control_flow = ControlFlow::WaitUntil(Instant::now() + Duration::from_millis(150));

        if let Event::NewEvents(StartCause::Init) = event {
            tray = Some(
                TrayIconBuilder::new()
                    .with_menu(Box::new(menu.clone()))
                    .with_tooltip(format!("neuralkit relay — {bind}"))
                    .with_icon(icon.clone())
                    .with_icon_as_template(true)
                    .build()
                    .expect("create the relay menu-bar item"),
            );
        }

        // The relay task ended (port taken, cert failure, crash): the icon must not
        // outlive the thing it stands for. The reason is already in relay.log.
        if dead.load(std::sync::atomic::Ordering::Relaxed) {
            tray.take();
            std::process::exit(1);
        }

        if let Ok(e) = menu_events.try_recv() {
            if e.id() == &quit_id {
                tray.take();
                std::process::exit(0);
            }
        }
    });
}

/// Runs the menu bar item until Quit. Never returns on success — the event loop owns the
/// process from here, which is what a menu-bar agent is.
pub fn run() -> Result<()> {
    // One tray per machine, enforced before anything touches the menu bar.
    let Some(lock) = instance_lock()? else {
        println!("  the tray is already in the menu bar");
        return Ok(());
    };
    // The holder's PID goes INTO the lock file — that's what lets the front-door
    // menu's toggle turn a tray OFF that it didn't spawn: read pid, SIGTERM, and
    // confirm by the flock releasing (kernel truth). Always current: whoever holds
    // the lock wrote it.
    {
        use std::io::Write as _;
        let _ = lock.set_len(0);
        let _ = write!(&lock, "{}", std::process::id());
    }
    let s = snapshot();
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    let expired = s.expires_ms.is_some_and(|ms| ms <= now_ms);

    let menu = Menu::new();

    // ── the session — transient by nature ─────────────────────────────────
    // Identity and liveness on ONE line: "signed in" is only claimed while the record's own
    // deadline agrees. Nothing deletes credentials.json AT expiry — cleanup happens when
    // the next command touches it — so a header trusting mere existence would say "signed
    // in" for days after the session died.
    // When it died, not just that it died — "expired" alone reads as an accusation; a
    // timestamp reads as a fact. Local time, coarse to the minute: menus are glances.
    let expired_at = s
        .expires_ms
        .filter(|_| expired)
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|t| t.with_timezone(&chrono::Local).format("%b %-d, %H:%M").to_string());
    menu.append(&MenuItem::new(
        match (&s.signed_in, &expired_at, s.expires_ms) {
            (Some(w), Some(when), _) => format!("session expired {when} — was {w}"),
            (Some(w), None, Some(ms)) => format!("signed in as {w} · {} left", left(ms, now_ms)),
            (Some(w), None, None) => format!("signed in as {w}"),
            (None, ..) => "signed out".into(),
        },
        false,
        None,
    ))
    .context("menu")?;
    // The exception, not the norm: set up = silence, absence = the one actionable line.
    if s.totp == Some(false) {
        menu.append(&MenuItem::new("authenticator app: not set up", false, None)).context("menu")?;
    }

    // ── this machine — the registration, which outlives sessions ─────────
    menu.append(&PredefinedMenuItem::separator()).context("menu")?;
    let tier = if s.gated { "Secure Enclave" } else { "software key" };
    menu.append(&MenuItem::new(
        match (&s.account, s.registered, s.has_software_key) {
            (Some(a), true, _) => format!("registered to {a} · {tier}"),
            (None, true, _) => format!("registered · {tier}"),
            (_, false, true) => "passkey created, not registered".into(),
            (_, false, false) => "no passkey yet".into(),
        },
        false,
        None,
    ))
    .context("menu")?;

    // The tray's one write. ON stores `biometry_or_watch` — the "never the password" gate
    // the signed bundle proved against a real Watch. OFF removes the choice. A stored
    // `user_presence`/`device_passcode` also shows checked: the box means "a hardware gate
    // is chosen", and unchecking clears whichever it was.
    let gate_toggle = CheckMenuItem::new("Require Apple Watch or Touch ID", true, s.gated, None);
    menu.append(&gate_toggle).context("menu")?;
    // The one fact a toggle cannot express: it decides which key signs NEXT time, so the
    // server needs a re-register — and (today) the signed bundle to satisfy it.
    menu.append(&MenuItem::new("  applies at next sign-in — re-register", false, None)).context("menu")?;

    // ── actions ───────────────────────────────────────────────────────────
    menu.append(&PredefinedMenuItem::separator()).context("menu")?;
    let quit = MenuItem::new("Quit", true, None);
    menu.append(&quit).context("menu")?;

    let quit_id = quit.id().clone();
    let gate_id = gate_toggle.id().clone();
    let icon = icon()?;

    // The icon must be created AFTER the event loop starts on macOS — tray-icon's own
    // documented ordering — so it is built inside StartCause::Init rather than here.
    let mut tray = None;
    let event_loop = EventLoopBuilder::new().build();
    let menu_events = MenuEvent::receiver();

    event_loop.run(move |event, _, control_flow| {
        // The lock lives in the closure so it is held for exactly the icon's lifetime —
        // the event loop never returns, and process exit is what releases it.
        let _hold = &lock;
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
            if e.id() == &gate_id {
                // The item has already toggled itself by the time the event arrives, so its
                // state IS the user's answer — persist it through the same single write
                // path the CLI uses, and let the caption explain when it bites.
                let on = gate_toggle.is_checked();
                if let Err(err) = crate::passkey::set_gate(if on { Some("biometry_or_watch") } else { None }) {
                    eprintln!("could not store the gate choice: {err:#}");
                    gate_toggle.set_checked(!on);
                }
            } else if e.id() == &quit_id {
                // Dropping the TrayIcon is what removes it from the bar — exiting with it
                // alive leaves a ghost icon until the system notices the process died.
                tray.take();
                *control_flow = ControlFlow::Exit;
            }
        }
    });
}
