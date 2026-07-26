//! `neuralkit auth login` — passkey QR device flow.
//!
//! The CLI generates a SECRET `device_code`, holds the `CliAuth` SSE stream, and
//! renders the returned `user_code` as a terminal QR. The phone scans it →
//! `/passkey?code=…` → the passkey login (which signs the phone in) → `Cli.authorize`
//! broadcasts a fresh session token to `cli:<device_code>`, which this held
//! connection alone receives. The channel is plain over TLS (no per-frame seal) — the token is
//! one-time + revocable, so a distributed `neuralkit auth login` needs nothing
//! but the URL: no keys, no config.

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use phaze_crypto::ml_kem;
use serde_json::Value;
use std::io::Write;

pub async fn run(base_url: &str) -> Result<()> {
    let base_url = base_url.trim_end_matches('/');

    // The CLI's secret device_code (32 random bytes → 64 hex) — only ever in this
    // connection URL. `cli:<device_code>` is the tag the token broadcasts to.
    let mut dc = [0u8; 32];
    getrandom::getrandom(&mut dc).map_err(|e| anyhow!("rng: {e}"))?;
    let device_code = to_hex(&dc);

    // This install's ML-KEM-768 keypair, minted HERE so the secret never travels. The public
    // half rides the device flow and Cli.authorize binds it to the session it mints; the
    // session channel's per-connection DEK is then encapsulated to it, so only this machine
    // can open those frames. Nothing is shared between installs and nothing is in the binary.
    let (kem_pk, kem_sk) = ml_kem::generate().map_err(|e| anyhow!("ml-kem generate: {e}"))?;

    // Self-signed cert on localhost (the dev app/relay); real cert in prod/tunnel.
    let insecure = base_url.contains("127.0.0.1") || base_url.contains("localhost");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .build()?;
    // Register this install's PUBLIC key against the device_code — a POST body, never the
    // URL: an ML-KEM-768 key is 1184 bytes (2368 hex chars) and has no business in a query
    // string or an access log. Best-effort: if it fails the login still completes, the
    // session channel just isn't PQC-sealed.
    // The reply carries the app's ed25519 PUBLIC key, so the session channel can verify
    // each frame's signature without the user configuring anything.
    let sign_key = async {
        let res = client
            .post(format!("{base_url}/transport/action/Cli/register"))
            .header("content-type", "application/json")
            .body(serde_json::json!({ "device": device_code, "pk": kem_pk.to_hex() }).to_string())
            .send()
            .await
            .ok()?;
        let body: Value = serde_json::from_str(&res.text().await.ok()?).ok()?;
        body.pointer("/data/signKey").and_then(Value::as_str).map(String::from)
    }
    .await;

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
                    save_credentials(base_url, token, user, &kem_sk.to_hex(), sign_key.as_deref())?;
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
        // Dense1x2 packs two vertical modules into each character cell (▀▄█),
        // rendering at ~half the width AND height of the full-block char form
        // while staying square + scannable — no stretched modules. (Was
        // `render::<char>().module_dimensions(2, 1)` — 2N×N chars; this is N×N/2.)
        let art = qr
            .render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .module_dimensions(1, 1)
            .build();
        println!("{art}");
    }
    println!("Scan with your mobile device to sign in.\n");
    // The QR is the ONLY way in, on purpose — neither the URL nor the user_code is
    // printed. The device-flow phishing case (RFC 8628 §5.4) is an attacker getting you
    // to authorize THEIR code; the usual mitigation is displaying the code so you can
    // compare it against the one the page shows. Here the phishable channel is REMOVED
    // instead of mitigated: with nothing pasteable on screen, the only path is scanning
    // your own QR, which matches by construction. Re-adding a printed URL re-opens
    // "someone sent me this link"; if a printed code ever comes back, it is that
    // comparison — not decoration — so keep it next to the page's own code display.
    // The headless E2E has no camera, so it opts into the URL via this env var.
    if std::env::var_os("NEURALKIT_LOGIN_PRINT_URL").is_some() {
        println!("{url}");
    }
    let _ = std::io::stdout().flush();
}

fn save_credentials(origin: &str, token: &str, user: &str, kem_secret: &str, sign_key: Option<&str>) -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let dir = format!("{home}/.config/neuralkit");
    std::fs::create_dir_all(&dir)?;
    // `kem_secret` is the ML-KEM secret whose public half the server bound to this session —
    // the only thing that can open the session channel's frames. It is paired with `token`:
    // a new login mints a new keypair, and the server drops the old binding with the session.
    // `sign_key` is the app's PUBLIC ed25519 key (not a secret), kept here so frame signatures
    // can be verified with no configuration.
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "token": token, "user": user, "origin": origin,
        "kem_secret": kem_secret, "sign_key": sign_key,
    }))?;
    // 0600, set at CREATE time rather than chmod'd afterwards — a plain write lands 0644
    // under the usual umask, and fixing it after the fact leaves a window where the file is
    // readable. This holds a session token AND the ML-KEM secret, and unlike the token the
    // secret is not made harmless by revoking the session: whoever has it can still open any
    // traffic they recorded while it was live. Directory 0700 for the same reason.
    let path = format!("{dir}/credentials.json");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        opts.mode(0o600);
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    opts.open(&path)?.write_all(body.as_bytes())?;
    Ok(())
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
