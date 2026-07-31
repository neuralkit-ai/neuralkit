//! `neuralkit auth totp enroll` — set up an authenticator app from the terminal.
//!
//! WHY THIS EXISTS. Of the three ways into this CLI, the authenticator code was the only one it
//! could USE but not CREATE: the QR scan registers the machine as it goes, a sign-in mints a
//! passkey silently, and TOTP required a browser trip to enrol. That asymmetry is the whole
//! reason `auth login` could offer a path the machine had no way of providing.
//!
//! IT CANNOT BE SILENT, and that is the honest difference from the other two. Enrolment needs a
//! human to scan a code into their authenticator app and type six digits back to prove it
//! worked — there is nothing to automate, only somewhere to do it. So this is a command rather
//! than a side effect, and `auth login` points at it instead of interrupting to ask.
//!
//! ZERO NEW SERVER SURFACE: `Totp.enrollStart` and `Totp.enrollFinish` already exist and are
//! `transport: rpc` + `use: [session]`, which the CLI reaches with a cookie exactly as it
//! reaches `Totp.login` and `QrCode.approve`. The browser page uses the same two.

use anyhow::{anyhow, Context, Result};
use serde_json::Value;
use std::io::Write as _;
use tokio::io::AsyncBufReadExt;

/// Enrol an authenticator app against the account this machine is signed in as.
pub async fn enroll(base_url: &str) -> Result<()> {
    let base_url = base_url.trim_end_matches('/');
    let token = crate::passkey::session_token()?;
    let cookie = format!("session={token}; __Secure-session={token}");
    let client = crate::passkey::http(base_url)?;

    // 1. The server mints the secret and holds it PENDING for ten minutes. Nothing is written
    //    to the account until a code proves the app actually received it — which is why an
    //    abandoned enrolment leaves no trace and simply expires.
    let start: Value = serde_json::from_str(
        &client
            .post(format!("{base_url}/transport/action/Totp/enrollStart"))
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .body("{}")
            .send()
            .await?
            .text()
            .await?,
    )?;
    if let Some(m) = start.pointer("/error/message").and_then(Value::as_str) {
        return Err(anyhow!("enrollStart: {m}"))
    }
    let uri = start
        .pointer("/data/otpauthUri")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("enrollStart returned no otpauth URI"))?;
    let secret = start.pointer("/data/secret").and_then(Value::as_str).unwrap_or_default();

    println!();
    println!("  {} {}", crate::style::bold("neuralkit"), crate::style::dim("· set up an authenticator app"));
    println!();
    // The QR carries the otpauth:// URI — the same thing the browser page renders, so either
    // surface enrols the same way and the app cannot tell them apart.
    match crate::login::qr_art(uri) {
        Some(art) => println!("{art}"),
        None => println!("  {}", crate::style::red("✗ could not render the QR")),
    }
    println!("  {}", crate::style::dim("Scan with your authenticator app."));
    if !secret.is_empty() {
        // Printed for the case the camera route is unavailable — an authenticator app takes
        // the secret typed by hand, and this is the one place it is ever shown.
        println!("  {} {}", crate::style::dim("or enter this secret:"), crate::style::bold(secret));
    }
    println!();

    // 2. The code proves the app holds the same secret. Only now does the account change.
    print!("  {} ", crate::style::dim("6-digit code from the app:"));
    std::io::stdout().flush()?;
    let mut line = String::new();
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    if stdin.read_line(&mut line).await? == 0 {
        println!();
        return Err(anyhow!("no code entered"))
    }
    let code = line.trim();
    if code.is_empty() {
        println!();
        return Err(anyhow!("no code entered"))
    }

    let finish: Value = serde_json::from_str(
        &client
            .post(format!("{base_url}/transport/action/Totp/enrollFinish"))
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .body(serde_json::json!({ "code": code }).to_string())
            .send()
            .await?
            .text()
            .await?,
    )?;
    if let Some(m) = finish.pointer("/error/message").and_then(Value::as_str) {
        println!();
        println!("  {} {}\n", crate::style::red("✗"), m);
        return Err(anyhow!("enrolment refused"))
    }

    // The sign-in menu reads this to decide whether to offer the code path. Updating it here
    // means the option appears on the NEXT sign-in rather than the one after — without it the
    // machine would know less about the account than the account does.
    mark_enrolled()?;

    println!();
    println!("  {} authenticator enrolled", crate::style::green("✓"));
    println!("  {}\n", crate::style::dim("`auth login` can now use a code from the app"));
    Ok(())
}

/// Record on this machine that the account has an authenticator, so the sign-in menu offers it.
fn mark_enrolled() -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = format!("{home}/.config/neuralkit/credentials.json");
    let Ok(raw) = std::fs::read_to_string(&path) else { return Ok(()) };
    let mut v: Value = serde_json::from_str(&raw)?;
    v["totp_enabled"] = Value::Bool(true);
    std::fs::write(&path, serde_json::to_string_pretty(&v)?)?;
    Ok(())
}
