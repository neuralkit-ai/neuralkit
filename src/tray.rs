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
//! NOISE BUDGET. One line per fact-cluster. Each line states a FACT rather than only a lack —
//! an authenticator says whether it is set up or not, because silence and "the tray has no
//! opinion" are indistinguishable in a menu. Only genuine ignorance stays silent.
//!
//! TWO WRITES, BOTH LOCAL FILE EDITS, and that is the boundary this file keeps: no server, no
//! session, no NSWindow. The hardware-gate toggle (`passkey::set_gate`) — the surface the
//! dropped `auth passkey presence` subcommand was waiting for — and the `neuralkit` symlink into
//! `~/.local/bin` (`publish_command`, at startup). The symlink is the tray's because only a
//! BUNDLED copy can hold an enclave key, so the app that owns the privileged binary is the one
//! that should publish the command name.
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
    has_software_key: bool,
    registered: bool,
    gated: bool,
    /// WHICH SLOT holds a registration — the machine can have both, one per key. `gated` is the
    /// CHOICE; these two are what is actually registered, and the tier line needs the difference.
    software_registered: bool,
    enclave_registered: bool,
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
        has_software_key: field(&pk, "key").is_some(),
        // EITHER registration counts. The machine can hold both — one per key — so asking
        // only about the software slot would report "no passkey yet" on a machine whose
        // enclave key is registered.
        registered: field(&pk, "credential_id").is_some()
            || field(&pk, "enclave_credential_id").is_some(),
        gated: field(&pk, "gate").is_some(),
        software_registered: field(&pk, "credential_id").is_some(),
        enclave_registered: field(&pk, "enclave_credential_id").is_some(),
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

/// The session line, rebuilt from the clock.
///
/// THE ONE LINE THAT TICKS, and the reason it can is that it needs no file watch. `expires_ms` is
/// captured once at launch and never changes; only `now` moves. The module's "read ONCE at launch"
/// rule is about noticing that a FILE changed — which identity and registration genuinely need and
/// still do not get — and it does not reach a countdown, which is arithmetic on a stamp the tray
/// already holds.
///
/// Left static it was actively WRONG rather than merely stale: with `SESSION_TTL` at ten minutes
/// while the flows are being exercised, "9 min left" is false sixty seconds later and stays false
/// for as long as the icon lives.
///
/// "Expired" carries WHEN, not just that it did — a bare "expired" reads as an accusation, a
/// timestamp reads as a fact. Local time, coarse to the minute, because menus are glances.
fn session_line(signed_in: Option<&str>, expires_ms: Option<i64>, now_ms: i64) -> String {
    let expired = expires_ms.is_some_and(|ms| ms <= now_ms);
    let expired_at = expires_ms
        .filter(|_| expired)
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|t| t.with_timezone(&chrono::Local).format("%b %-d, %H:%M").to_string());
    match (signed_in, &expired_at, expires_ms) {
        (Some(w), Some(when), _) => format!("session expired {when} · {w}"),
        (Some(w), None, Some(ms)) => format!("signed in as {w} · {} left", left(ms, now_ms)),
        (Some(w), None, None) => format!("signed in as {w}"),
        (None, ..) => "signed out".into(),
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

/// Put `neuralkit` on PATH — the Docker Desktop move, and it belongs to the tray because the app
/// that OWNS the privileged copy is the one that should publish the command: only a bundled copy
/// can hold an enclave key.
///
/// `~/.local/bin`, never `/usr/local/bin`. The latter is root-owned, and a drag-install that
/// stops to ask for an admin password is not a drag-install. Measured 2026-08-29 on this machine:
/// `~/.local/bin` is PATH position 39 and user-writable, `/usr/local/bin` is 25 and is not. It
/// also lands ABOVE `~/Library/pnpm` (40), so a bundled install wins over an npm one rather than
/// racing it.
///
/// ONLY FROM THE BUNDLE. `running_bundle()` reports what the SYSTEM thinks is running rather than
/// what signed it — a bare npm binary answers `<no bundleIdentifier>` and is skipped. Handing the
/// name to the copy that CANNOT gate on hardware is worse than not publishing it at all.
///
/// REPLACES ONLY ITS OWN LINK. A regular file at that path belongs to some other install, and
/// taking the name from it silently is the behaviour Docker gets criticised for.
///
/// Best-effort and silent: the icon must appear whether or not this works.
///
/// RETURNS WHETHER IT PUBLISHED, and that bool is the first-run signal. No flag file is needed —
/// the link ALREADY POINTING AT US is the durable record that this has happened before, and it
/// lives exactly as long as the thing it describes. A flag in `passkey.json` could say "shown"
/// while the link was gone, which is the state where someone most needs to be told again.
fn publish_command() -> bool {
    if phaze_auth::system_passkey::running_bundle().0 != "ai.neuralkit.cli" {
        return false
    }
    let Ok(exe) = std::env::current_exe() else { return false };
    // NEVER LINK TO A TRANSLOCATED COPY. Since Sierra, macOS runs a QUARANTINED app opened from
    // a dmg or Downloads — without being moved first — from a randomised read-only path under
    // `/AppTranslocation/`, silently. That path is destroyed when the app quits, so a symlink
    // into it would be dead the moment the panel it advertised disappeared.
    //
    // There is no public API for this: `SecTranslocateIsTranslocatedURL` is not in the SDK
    // headers, so the path is the test. Someone in this state has not installed the app yet;
    // the honest answer is to publish nothing rather than a link that breaks later.
    if exe.to_string_lossy().contains("/AppTranslocation/") {
        return false
    }
    let Ok(home) = std::env::var("HOME") else { return false };
    let dir = std::path::Path::new(&home).join(".local/bin");
    if std::fs::create_dir_all(&dir).is_err() {
        return false
    }
    let link = dir.join("neuralkit");
    match std::fs::symlink_metadata(&link) {
        Ok(m) if m.file_type().is_symlink() => {
            // Already ours and already correct — a re-launch must not churn the link, and must
            // not announce itself again.
            if std::fs::read_link(&link).ok().as_deref() == Some(exe.as_path()) {
                return false
            }
            let _ = std::fs::remove_file(&link);
        }
        Ok(_) => return false, // a real file — someone else's install, leave it
        Err(_) => {}           // absent
    }
    std::os::unix::fs::symlink(&exe, &link).is_ok()
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
    // After the lock, so only the instance that actually came up claims the command name.
    // The panel is SHOWN LATER, in StartCause::Init — a window ordered front before the loop
    // runs has nothing driving it yet.
    let first_run = publish_command();

    let s = snapshot();
    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);

    let menu = Menu::new();

    // ── the session — transient by nature ─────────────────────────────────
    // Identity and liveness on ONE line: "signed in" is only claimed while the record's own
    // deadline agrees. Nothing deletes credentials.json AT expiry — cleanup happens when
    // the next command touches it — so a header trusting mere existence would say "signed
    // in" for days after the session died.
    // When it died, not just that it died — "expired" alone reads as an accusation; a
    // timestamp reads as a fact. Local time, coarse to the minute: menus are glances.
    let session_item = MenuItem::new(session_line(s.signed_in.as_deref(), s.expires_ms, now_ms), false, None);
    menu.append(&session_item).context("menu")?;
    // SAYS IT EITHER WAY. This used to print only the absence, on the reasoning that a working
    // thing needs no row — but silence and "no opinion" look identical in a menu, so a person who
    // HAD set one up could not tell the tray knew. The line beside it ("registered · Secure
    // Enclave") states a fact rather than a lack, and this now matches.
    //
    // `None` still says nothing, and that is a different case: it means credentials.json carries
    // no `totp_enabled` at all, so the tray genuinely does not know.
    if let Some(on) = s.totp {
        menu.append(&MenuItem::new(
            if on { "authenticator app: enabled" } else { "authenticator app: not enabled" },
            false,
            None,
        ))
        .context("menu")?;
    }

    // ── this machine — the registration, which outlives sessions ─────────
    menu.append(&PredefinedMenuItem::separator()).context("menu")?;
    // "on device (P-256)" rather than "software key": the curve is the SAME on both tiers, so
    // naming it software says only what it is not. The real difference is where the private half
    // lives — a file this machine can copy, versus a key that cannot leave the chip.
    //
    // THE TIER IS WHAT IS REGISTERED, not what is chosen. Reading the `gate` field alone made
    // this claim "Secure Enclave" the moment the checkbox was ticked — before any enclave key
    // existed, while the only registration was still the software one. The choice and the
    // reality diverge for exactly one sign-in, and this is the line that used to hide it.
    let tier = match (s.gated, s.enclave_registered, s.software_registered) {
        (true, true, _) => "Secure Enclave",
        // Chosen but not yet minted — say so rather than claim a key that does not exist.
        (true, false, _) => "Secure Enclave at next sign-in",
        (false, _, true) => "on device (P-256)",
        // Gate off with only an enclave registration: the software key will be minted and
        // registered on the next run, so no tier is true yet.
        (false, _, false) => "on device (P-256) at next sign-in",
    };
    menu.append(&MenuItem::new(
        // NO OWNER HERE. The session line directly above already names who this is, and
        // repeating it spent a whole line on a word the eye had just read. It was also the
        // weaker of the two: `account` has no source of its own, so it fell back to the
        // session's email — meaning a machine registered as A whose last sign-in was B would
        // have captioned A's credential with B.
        match (s.registered, s.has_software_key) {
            (true, _) => format!("registered · {tier}"),
            (false, true) => "passkey created, not registered".into(),
            (false, false) => "no passkey yet".into(),
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

    // Carried into the loop so the countdown can be rebuilt: who it belongs to and when it
    // dies never change, only the clock does. `last_second` starts at the second the menu was
    // first rendered, so the first redraw is a real tick rather than a duplicate of what is
    // already on screen.
    let sess_who = s.signed_in.clone();
    let sess_expires = s.expires_ms;
    let mut last_second = now_ms / 1000;

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

        // THE COUNTDOWN, and only the countdown. Rebuilt when the wall SECOND changes rather
        // than on every 150ms wake, so a menu measured in minutes redraws at most once a second
        // — and not at all when there is no deadline to count, which is the signed-out case.
        //
        // Everything else here stays as it was at launch: identity, registration and the gate
        // all describe FILES, and noticing those change needs the fsevents and refresh story
        // this module deliberately does not have. A stamp already in hand is a different
        // problem, and leaving it frozen made the line actively wrong rather than merely stale.
        if sess_expires.is_some() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            if now / 1000 != last_second {
                last_second = now / 1000;
                session_item.set_text(session_line(sess_who.as_deref(), sess_expires, now));
            }
        }

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
            // FIRST RUN ONLY — the run that actually published the command is the run that has
            // something new to say. `NEURALKIT_PANEL=1` forces it for a look without having to
            // delete the symlink first.
            if first_run || std::env::var_os("NEURALKIT_PANEL").is_some() {
                let _ = crate::panel::welcome(None);
            }
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
