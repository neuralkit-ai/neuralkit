//! `neuralkit login` — passkey QR device flow.
//!
//! The CLI generates a SECRET `device_code`, holds the `CliAuth` SSE stream, and
//! renders the returned `user_code` as a terminal QR. The phone scans it →
//! `/cli/auth` → the existing passkey ceremony → `Cli.bindDevice` broadcasts a
//! fresh session token to `cli:<device_code>`, which this held connection alone
//! receives. Frames are sealed (`sign: ed25519` + `encrypt: aes-gcm-256`) and
//! decoded with the SAME public keys the browser uses — `PUBLIC_PHAZE_SIGN_KEY`
//! (verify) + `PUBLIC_PHAZE_ENCRYPT_KEY` (the shared aes-gcm key), read from env.

use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::rand_core::RngCore;
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures_util::StreamExt;
use phaze_crypto::ed25519::{PublicKey, Signature};
use serde_json::Value;
use std::io::Write;

pub async fn run(base_url: &str) -> Result<()> {
    let base_url = base_url.trim_end_matches('/');

    // The same values `phaze:env/client` inlines for the browser consumer.
    let sign_pk = PublicKey::from_hex(
        std::env::var("PUBLIC_PHAZE_SIGN_KEY")
            .context("set PUBLIC_PHAZE_SIGN_KEY (the app's ed25519 verify key)")?
            .trim(),
    )?;
    let enc = hex_decode(
        std::env::var("PUBLIC_PHAZE_ENCRYPT_KEY")
            .context("set PUBLIC_PHAZE_ENCRYPT_KEY (the app's aes-gcm-256 key)")?
            .trim(),
    )?;
    let aes = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&enc));

    // The CLI's secret device_code (32 random bytes → 64 hex) — only ever in this
    // connection URL. `cli:<device_code>` is the tag the token broadcasts to.
    let mut dc = [0u8; 32];
    aes_gcm::aead::OsRng.fill_bytes(&mut dc);
    let device_code = to_hex(&dc);

    // Self-signed cert on localhost (the dev app/relay); real cert in prod.
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
                let payload = open_frame(data, &aes, &sign_pk)?;
                let v: Value = serde_json::from_str(&payload)?;
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

/// `{ e, iv }` (aes-gcm outer) → decrypt → `{ v, s }` (ed25519 inner) → verify → `v`.
fn open_frame(data: &str, aes: &Aes256Gcm, pk: &PublicKey) -> Result<String> {
    let env: Value = serde_json::from_str(data).context("frame is not JSON")?;
    let ct = B64.decode(env.get("e").and_then(Value::as_str).context("no `e`")?)?;
    let iv = B64.decode(env.get("iv").and_then(Value::as_str).context("no `iv`")?)?;
    let signed = aes
        .decrypt(Nonce::from_slice(&iv), ct.as_ref())
        .map_err(|_| anyhow!("aes-gcm decrypt failed"))?;
    let vs: Value = serde_json::from_str(std::str::from_utf8(&signed)?)?;
    let v = vs.get("v").and_then(Value::as_str).context("no `v`")?;
    let s = B64.decode(vs.get("s").and_then(Value::as_str).context("no `s`")?)?;
    let s: [u8; 64] = s.as_slice().try_into().map_err(|_| anyhow!("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&s);
    pk.verify(v.as_bytes(), &sig)
        .map_err(|_| anyhow!("frame signature verification failed"))?;
    Ok(v.to_string())
}

fn render_qr(base_url: &str, code: &str) {
    let url = format!("{base_url}/cli/auth?code={code}");
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

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("odd hex length"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(Into::into))
        .collect()
}
