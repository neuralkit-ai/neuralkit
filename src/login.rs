//! `neuralkit login` — passkey QR device flow.
//!
//! The CLI generates a SECRET `device_code`, holds the `CliAuth` SSE stream, and
//! renders the returned `user_code` as a terminal QR. The phone scans it →
//! `/passkey?code=…` → the passkey login (which signs the phone in) → `Cli.authorize`
//! broadcasts a fresh session token to `cli:<device_code>`, which this held
//! connection alone receives. The channel is plain over TLS (no per-frame seal) — the token is
//! one-time + revocable, so a distributed `neuralkit login` needs nothing but
//! the URL: no keys, no config.

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use serde_json::Value;
use std::io::Write;

pub async fn run(base_url: &str) -> Result<()> {
    let base_url = base_url.trim_end_matches('/');

    // The CLI's secret device_code (32 random bytes → 64 hex) — only ever in this
    // connection URL. `cli:<device_code>` is the tag the token broadcasts to.
    let mut dc = [0u8; 32];
    getrandom::getrandom(&mut dc).map_err(|e| anyhow!("rng: {e}"))?;
    let device_code = to_hex(&dc);

    // Self-signed cert on localhost (the dev app/relay); real cert in prod/tunnel.
    let insecure = base_url.contains("127.0.0.1") || base_url.contains("localhost");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()?;
    let url = format!("{base_url}/transport/stream/CliAuth?device={device_code}");
    let resp = client.get(&url).send().await?.error_for_status()?;

    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    let mut qr_shown = false;

    while let Some(chunk) = stream.next().await {
        buf.extend_from_slice(&chunk?);
        // SSE frames are separated by a blank line.
        while let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
            let raw: Vec<u8> = buf.drain(..pos + 2).collect();
            for line in std::str::from_utf8(&raw)?.lines() {
                let Some(data) = line.strip_prefix("data: ") else { continue };
                if data == "null" {
                    continue; // rejected/kill frame — keep waiting
                }
                let v: Value = serde_json::from_str(data).context("frame is not JSON")?;
                if let Some(code) = v.get("userCode").and_then(Value::as_str) {
                    if !qr_shown {
                        render_qr(base_url, code);
                        qr_shown = true;
                    }
                } else if let Some(token) = v.get("token").and_then(Value::as_str) {
                    let user = v.get("user").and_then(Value::as_str).unwrap_or("");
                    save_credentials(base_url, token, user)?;
                    println!("\n✓ Signed in as {user}");
                    return Ok(());
                }
            }
        }
    }
    Err(anyhow!("the stream closed before sign-in completed"))
}

fn render_qr(base_url: &str, code: &str) {
    let url = format!("{base_url}/passkey?code={code}");
    if let Ok(qr) = qrcode::QrCode::new(url.as_bytes()) {
        // module_dimensions(2, 1) compensates for the 1×2 terminal cell so the
        // modules read as square — phone cameras fail on stretched codes.
        let art = qr
            .render::<char>()
            .quiet_zone(true)
            .module_dimensions(2, 1)
            .light_color(' ')
            .dark_color('█')
            .build();
        println!("{art}");
    }
    println!("Scan the code above with your phone, or open:\n  {url}\n");
    println!("code: {code}\n");
    let _ = std::io::stdout().flush();
}

fn save_credentials(origin: &str, token: &str, user: &str) -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let dir = format!("{home}/.config/neuralkit");
    std::fs::create_dir_all(&dir)?;
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "token": token, "user": user, "origin": origin,
    }))?;
    std::fs::write(format!("{dir}/credentials.json"), body)?;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
