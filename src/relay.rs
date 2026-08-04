//! `neuralkit relay` — a MoQ relay of your own: loopback for dev, LAN for a lab.
//!
//! WHO THIS IS FOR. The hosted default is Cloudflare's relay; this command is the
//! ON-PREMISE story — a research lab or partner running the relay on their own machine
//! so the EEG pipeline (rigs publish, viewers subscribe) never leaves their network.
//! Dev's loopback relay is just the smallest deployment of the same thing.
//!
//! NO MODES, NO FLAGS — where you run it decides its face:
//!   terminal   → the live relay dashboard (the same one the standalone binary draws),
//!                and the terminal visibly owns the lifetime: q stops the relay.
//!   REPL/tray  → detached under its own ring icon; the icon is the truth, its Quit is
//!                the stop. One icon, one process — the status-tray contract.
//!   piped      → headless IN-PROCESS — the systemd/launchd/service shape a lab runs;
//!                a service manager owns its process, so no self-detaching here.
//!
//! One flock covers every face, so there is exactly one relay however it was started.
//! Deliberately NOT a child of the status tray; folding the fleet under one icon is the
//! desktop app's job, when it exists.

use anyhow::{Context, Result};

pub struct Opts {
    pub bind: std::net::SocketAddr,
    pub cert_listen: std::net::SocketAddr,
    pub tls_generate: String,
}

impl Default for Opts {
    /// Mirrors the clap defaults on the `relay` subcommand (main.rs), which stay the
    /// authority — this exists for spawn sites (the REPL) that never touch clap.
    fn default() -> Self {
        Self {
            bind: "[::]:4443".parse().expect("static addr"),
            cert_listen: "[::]:4444".parse().expect("static addr"),
            tls_generate: "localhost".into(),
        }
    }
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
        // `tls::Args` derives Default (all-empty PEM lists) — "no real certs"; the
        // self-signed `tls_generate` below is what makes local TLS exist. Real-cert
        // flags for on-premise relays arrive when a lab actually needs them.
        tls: Default::default(),
        tls_generate: Some(o.tls_generate.clone()),
        cert_listen: Some(o.cert_listen),
        events: None,
    }
}

#[cfg(target_os = "macos")]
fn sock_path() -> Result<String> {
    Ok(format!("{}/relay.sock", dir()?))
}

/// `neuralkit relay`, attended — THE MODEL: the icon owns, the terminal is a LENS.
///
/// In a terminal: make sure the icon-owned relay exists (start it if absent), then
/// attach the live dashboard to its event socket. q / Ctrl-C / closing the terminal
/// closes the LENS ONLY — the relay and its icon do not notice. Run the command again
/// any time to look again. The icon's Quit is the one real stop.
///
/// Piped (systemd/launchd/CI): headless IN-PROCESS — a service manager expects to own
/// its process, and a self-detaching service reads as died.
pub async fn run_attended(o: Opts) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
            if !is_running() {
                launch(&o)?;
            }
            return match attach(&o).await {
                Ok(()) => Ok(()),
                Err(attach_err) => {
                    // No GUI to hold an icon (SSH), or a relay predating the socket:
                    // fall back to OWNING it in this terminal — but only if nothing
                    // else holds the relay.
                    match instance_lock()? {
                        Some(_lock) => {
                            eprintln!(
                                "  {}",
                                crate::style::dim(&format!("no attachable relay ({attach_err:#}) — owning it in this terminal instead")),
                            );
                            phaze_relay::tui::run(config(&o)).await.map_err(|e| anyhow::anyhow!("{e:#}"))
                        }
                        None => Err(attach_err),
                    }
                }
            };
        }
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
        return phaze_relay::run(config(&o)).await.map_err(|e| anyhow::anyhow!("{e:#}"));
    }
    #[cfg(not(target_os = "macos"))]
    {
        if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
            return phaze_relay::tui::run(config(&o)).await.map_err(|e| anyhow::anyhow!("{e:#}"));
        }
        println!(
            "  {} {}",
            crate::style::bold("neuralkit"),
            crate::style::dim(&format!("· relay on {} · cert hash on {} · Ctrl-C to stop", o.bind, o.cert_listen)),
        );
        phaze_relay::run(config(&o)).await.map_err(|e| anyhow::anyhow!("{e:#}"))
    }
}

/// Attach the dashboard lens to the running icon-owned relay: connect its event
/// socket, deserialize the stream, and hand it to the SAME renderer the standalone
/// binary uses. Retries briefly because the icon process may still be booting.
#[cfg(target_os = "macos")]
async fn attach(o: &Opts) -> Result<()> {
    use tokio::io::AsyncBufReadExt as _;
    let sock = sock_path()?;
    let mut tries = 0u32;
    let stream = loop {
        match tokio::net::UnixStream::connect(&sock).await {
            Ok(s) => break s,
            Err(_) if tries < 30 => {
                tries += 1;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(e) => return Err(anyhow::anyhow!("could not reach the relay's event socket: {e}")),
        }
    };
    let (vtx, vrx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stream).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            if let Ok(ev) = serde_json::from_str::<phaze_relay::RelayEvent>(&l) {
                if vtx.send(ev).is_err() {
                    break;
                }
            }
        }
        // Sender drops here: the view sees the stream end (relay quit) and exits
        // cleanly instead of rendering a corpse.
    });
    phaze_relay::tui::view(o.bind.to_string(), Some(o.cert_listen), vrx)
        .await
        .map_err(|e| anyhow::anyhow!("{e:#}"))?;
    println!(
        "  {} {}",
        crate::style::green("✓"),
        crate::style::dim("view closed — the relay keeps running under its icon (`neuralkit relay` to look again)"),
    );
    Ok(())
}

/// The launcher: spawn the icon-owned relay detached and come straight back. The
/// REPL's `relay` command and the status tray are its callers — always the LOCAL
/// self-signed shape (no PEM forwarding): an on-premise relay with real certs is a
/// service or an attended terminal, not a click.
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

/// The spawned process: run the relay as a task, stand in the menu bar for its
/// lifetime, and serve the event stream to any attached lens.
#[cfg(target_os = "macos")]
pub async fn run_icon(o: Opts) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    // Silent when beaten to the lock — the launcher already told the human.
    let Some(lock) = instance_lock()? else { return Ok(()) };

    // The relay's birth, for every lens that ever attaches: uptime must be the
    // RELAY's age, not the viewer's attachment age.
    let started_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);

    // The event tap: the relay reports lifecycle on this channel; we keep a snapshot
    // and rebroadcast to every connected lens as JSON lines.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<phaze_relay::RelayEvent>();
    let mut cfg = config(&o);
    cfg.events = Some(tx.clone());

    // This process owns the relay, so it owns the tracing too — fanned to every lens
    // as Log events (main() skipped its file subscriber for exactly this mode). The
    // moq stack's own lines (session accepted, negotiated, terminated) are the log
    // pane's whole content; without this tap a lens shows an empty pane forever.
    struct FanWriter(tokio::sync::mpsc::UnboundedSender<phaze_relay::RelayEvent>);
    impl std::io::Write for FanWriter {
        fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
            for line in String::from_utf8_lossy(data).lines() {
                let line = line.trim_end();
                if !line.is_empty() {
                    let _ = self.0.send(phaze_relay::RelayEvent::Log { line: line.to_string() });
                }
            }
            Ok(data.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let fan_tx = tx.clone();
    let _ = tracing_subscriber::fmt()
        .with_writer(move || FanWriter(fan_tx.clone()))
        .with_ansi(false)
        .try_init();

    // The flock is held, so a stale socket file from a crash is ours to clear.
    let sock = sock_path()?;
    let _ = std::fs::remove_file(&sock);
    let listener = tokio::net::UnixListener::bind(&sock).context("bind relay.sock")?;
    let (fan, _) = tokio::sync::broadcast::channel::<String>(512);

    // A lens can attach at ANY time, so events alone are not enough — a viewer joining
    // an hour in would see an empty dashboard over a busy relay. Keep the truth
    // (ready + live sessions + last traffic) and replay it as synthetic events first.
    #[derive(Default, Clone)]
    struct Snap {
        ready: Option<String>,
        sessions: std::collections::BTreeSet<u64>,
        traffic: Option<(u64, u64)>,
        // The pane's recent history — the standalone binary shows its ring from boot,
        // and a lens deserves the same: boot lines are most of what a quiet relay ever
        // says. Bounded well under the renderer's own 1000-line cap.
        logs: std::collections::VecDeque<String>,
    }
    let snap = Arc::new(Mutex::new(Snap::default()));
    {
        let fan = fan.clone();
        let snap = snap.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                {
                    let mut s = snap.lock().expect("snap");
                    match &ev {
                        phaze_relay::RelayEvent::Ready { fingerprint } => s.ready = Some(fingerprint.clone()),
                        phaze_relay::RelayEvent::SessionUp { id } => {
                            s.sessions.insert(*id);
                        }
                        phaze_relay::RelayEvent::SessionDown { id } => {
                            s.sessions.remove(id);
                        }
                        phaze_relay::RelayEvent::Traffic { broadcasts, subscriptions } => {
                            s.traffic = Some((*broadcasts, *subscriptions))
                        }
                        // Synthesized by US into the replay, never received from the relay.
                        phaze_relay::RelayEvent::Started { .. } => {}
                        phaze_relay::RelayEvent::Log { line } => {
                            s.logs.push_back(line.clone());
                            while s.logs.len() > 300 {
                                s.logs.pop_front();
                            }
                        }
                    }
                }
                if let Ok(line) = serde_json::to_string(&ev) {
                    let _ = fan.send(line);
                }
            }
        });
    }
    {
        let snap = snap.clone();
        let fan = fan.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let mut live = fan.subscribe();
                let replay = snap.lock().expect("snap").clone();
                tokio::spawn(async move {
                    use tokio::io::AsyncWriteExt as _;
                    let mut w = stream;
                    let mut lines: Vec<String> = Vec::new();
                    // Birth first, so the lens's uptime clock rebases before anything renders.
                    lines.push(serde_json::to_string(&phaze_relay::RelayEvent::Started { unix_ms: started_ms }).expect("json"));
                    if let Some(fp) = &replay.ready {
                        lines.push(serde_json::to_string(&phaze_relay::RelayEvent::Ready { fingerprint: fp.clone() }).expect("json"));
                    }
                    for id in &replay.sessions {
                        lines.push(serde_json::to_string(&phaze_relay::RelayEvent::SessionUp { id: *id }).expect("json"));
                    }
                    if let Some((broadcasts, subscriptions)) = replay.traffic {
                        lines.push(serde_json::to_string(&phaze_relay::RelayEvent::Traffic { broadcasts, subscriptions }).expect("json"));
                    }
                    for l in &replay.logs {
                        lines.push(serde_json::to_string(&phaze_relay::RelayEvent::Log { line: l.clone() }).expect("json"));
                    }
                    for l in lines {
                        if w.write_all(l.as_bytes()).await.is_err() || w.write_all(b"\n").await.is_err() {
                            return;
                        }
                    }
                    loop {
                        match live.recv().await {
                            Ok(l) => {
                                if w.write_all(l.as_bytes()).await.is_err() || w.write_all(b"\n").await.is_err() {
                                    return;
                                }
                            }
                            // A slow lens that lagged the ring just misses a few
                            // frames — the next Traffic tick corrects the picture.
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(_) => return,
                        }
                    }
                });
            }
        });
    }

    let dead = Arc::new(AtomicBool::new(false));
    let flag = dead.clone();
    tokio::spawn(async move {
        if let Err(e) = phaze_relay::run(cfg).await {
            // The log file is this process's only voice — say why before the icon goes.
            eprintln!("relay died: {e:#}");
        }
        flag.store(true, Ordering::Relaxed);
    });
    crate::tray::relay_icon(o.bind.to_string(), lock, dead)
}
