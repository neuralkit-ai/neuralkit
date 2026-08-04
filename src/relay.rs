//! `neuralkit relay` — the local MoQ relay, owned by its own menu-bar icon.
//!
//! THE LAUNCHER SHAPE. `neuralkit relay` is idempotent "make the relay exist": it spawns
//! the real process detached (the hidden `--icon` mode), says where it lives, and gives
//! the terminal back. The icon IS the lifetime — its Quit is the stop button — the same
//! contract the status tray set: one icon, one process, one truth. Running it again
//! reports "already running" instead of a second relay.
//!
//! `--foreground` keeps terminal ownership for the two citizens an icon cannot serve:
//! debugging (live logs on stdout) and SSH/headless, where no GUI exists to hold an icon
//! — the same bottom-row rule the sign-in paths follow. One flock covers every mode, so
//! there is exactly one relay however it was started.
//!
//! This is deliberately NOT a child of the status tray. Each icon owns exactly its own
//! process; the status tray stays a read-only card. Folding the fleet under one icon is
//! the desktop app's job, when it exists.

use anyhow::{Context, Result};

pub struct Opts {
    pub bind: std::net::SocketAddr,
    pub cert_listen: std::net::SocketAddr,
    pub tls_generate: String,
}

fn dir() -> Result<String> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(format!("{home}/.config/neuralkit"))
}

pub fn log_path() -> Result<String> {
    Ok(format!("{}/relay.log", dir()?))
}

/// One relay per machine — flock, kernel-released on any death, no stale state.
/// Held by whichever mode runs the relay; probed by launchers and menus.
#[cfg(target_os = "macos")]
fn instance_lock() -> Result<Option<std::fs::File>> {
    let dir = dir()?;
    std::fs::create_dir_all(&dir)?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(format!("{dir}/relay.lock"))?;
    use std::os::unix::io::AsRawFd as _;
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    Ok(if rc == 0 { Some(f) } else { None })
}

#[cfg(target_os = "macos")]
pub fn is_running() -> bool {
    matches!(instance_lock(), Ok(None))
}

fn config(o: &Opts) -> phaze_relay::RelayConfig {
    phaze_relay::RelayConfig {
        bind: Some(o.bind),
        // `tls::Args` derives Default (all-empty PEM lists), which is exactly "no real
        // certs" — tls_generate below is what makes local TLS exist.
        tls: Default::default(),
        tls_generate: Some(o.tls_generate.clone()),
        cert_listen: Some(o.cert_listen),
        events: None,
    }
}

/// `--foreground`: the terminal owns it, Ctrl-C stops it. The only shape on platforms
/// with no menu bar, and the debugging shape everywhere.
pub async fn run_foreground(o: Opts) -> Result<()> {
    #[cfg(target_os = "macos")]
    let _lock = match instance_lock()? {
        Some(l) => l,
        None => {
            println!("  the relay is already running");
            return Ok(());
        }
    };
    println!(
        "  {} {}",
        crate::style::bold("neuralkit"),
        crate::style::dim(&format!("· relay on {} · cert hash on {} · Ctrl-C to stop", o.bind, o.cert_listen)),
    );
    phaze_relay::run(config(&o)).await.map_err(|e| anyhow::anyhow!("{e:#}"))
}

/// The launcher: spawn the icon-owned relay detached and come straight back.
#[cfg(target_os = "macos")]
pub fn launch(o: &Opts) -> Result<()> {
    if is_running() {
        println!(
            "  {} {}",
            crate::style::green("✓"),
            crate::style::dim("the relay is already running — its icon is in the menu bar"),
        );
        return Ok(());
    }
    let exe = std::env::current_exe()?;
    // Logs survive the terminal that launched them — the icon has no stdout, so the file
    // IS the relay's voice. Append, so restarts tell one continuous story.
    let log = std::fs::OpenOptions::new().create(true).append(true).open(log_path()?)?;
    use std::os::unix::process::CommandExt as _;
    let mut child = std::process::Command::new(exe)
        .args([
            "relay",
            "--icon",
            "--bind",
            &o.bind.to_string(),
            "--cert-listen",
            &o.cert_listen.to_string(),
            "--tls-generate",
            &o.tls_generate,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log)
        .process_group(0)
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    println!(
        "  {} {}",
        crate::style::green("✓"),
        crate::style::dim(&format!("relay is up on {} — the ring icon owns it · logs: {}", o.bind, log_path()?)),
    );
    Ok(())
}

/// The spawned process: run the relay as a task, stand in the menu bar for its lifetime.
#[cfg(target_os = "macos")]
pub async fn run_icon(o: Opts) -> Result<()> {
    // Silent when beaten to the lock — the launcher already told the human.
    let Some(lock) = instance_lock()? else { return Ok(()) };
    let dead = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = dead.clone();
    let cfg = config(&o);
    tokio::spawn(async move {
        if let Err(e) = phaze_relay::run(cfg).await {
            // The log file is this process's only voice — say why before the icon goes.
            eprintln!("relay died: {e:#}");
        }
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    });
    crate::tray::relay_icon(o.bind.to_string(), lock, dead)
}
