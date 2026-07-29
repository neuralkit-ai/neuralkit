//! `neuralkit auth login` — passkey QR device flow.
//!
//! The CLI generates a SECRET `device_code`, holds the `QrCode.request` SSE stream, and
//! renders the returned `user_code` as a terminal QR. The phone scans it →
//! `/passkey?code=…` → the passkey login (which signs the phone in) → `QrCode.approve`
//! broadcasts a fresh session token to `cli:<device_code>`, which this held
//! connection alone receives. The channel is plain over TLS (no per-frame seal) — the token is
//! one-time + revocable, so a distributed `neuralkit auth login` needs nothing
//! but the URL: no keys, no config.

use anyhow::{anyhow, Context, Result};
use futures_util::StreamExt;
use phaze_crypto::ml_kem;
use serde_json::Value;
use std::io::Write;

/// How this machine proves who it is. Resolved in main.rs from the `--qr` / `--totp`
/// flags, which clap keeps mutually exclusive, so `None` means only one thing here:
/// nothing was asked for, decide at runtime.
#[derive(Clone, Copy, Debug)]
pub enum Method {
    Qr,
    Totp,
}

pub async fn run(base_url: &str, method: Option<Method>) -> Result<()> {
    let base_url = base_url.trim_end_matches('/');

    // The CLI's secret device_code (32 random bytes → 64 hex) — only ever in this
    // connection URL. `cli:<device_code>` is the tag the token broadcasts to.
    let mut dc = [0u8; 32];
    getrandom::getrandom(&mut dc).map_err(|e| anyhow!("rng: {e}"))?;
    let device_code = to_hex(&dc);

    // This install's ML-KEM-768 keypair, minted HERE so the secret never travels. The public
    // half rides the device flow and QrCode.approve binds it to the session it mints; the
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
            .post(format!("{base_url}/transport/action/Cli/registerKey"))
            .header("content-type", "application/json")
            .body(serde_json::json!({ "device": device_code, "pk": kem_pk.to_hex() }).to_string())
            .send()
            .await
            .ok()?;
        let body: Value = serde_json::from_str(&res.text().await.ok()?).ok()?;
        body.pointer("/data/signKey").and_then(Value::as_str).map(String::from)
    }
    .await;

    let url = format!("{base_url}/transport/stream/QrCode/request?device={device_code}");
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
                        qr_shown = true;
                        // A machine that has signed in here before can approve its OWN
                        // device flow with an authenticator code instead of a phone. The
                        // flow itself is untouched — same device_code, same held stream,
                        // same QrCode.approve doing the mint and the key promotion. Only
                        // WHERE the approving session comes from changes: a code typed
                        // here rather than a passkey on a second screen. Anything that
                        // does not complete falls through to the QR, so a fresh machine
                        // and a declined menu land in the same place.
                        if !choose_method(&client, base_url, code, method).await? {
                            render_qr(base_url, code);
                        }
                    }
                } else if let Some(token) = v.get("token").and_then(Value::as_str) {
                    let user = v.get("user").and_then(Value::as_str).unwrap_or("");
                    // Resolve our OWN session rather than having identity pushed through the
                    // QR handshake — the token is an ordinary session record, so it answers
                    // this the same way a browser cookie does. Best-effort: a passkey-only
                    // account has no address, and the id remains what identifies it.
                    let (email, expires) = resolve_session(&client, base_url, token).await;
                    save_credentials(base_url, token, user, email.as_deref(), expires, &kem_sk.to_hex(), sign_key.as_deref())?;
                    // Two lines, because a login does two things: it authenticates you and
                    // it registers the machine. Naming the second is what makes the code
                    // option on the next run — and `auth unregister` — make sense.
                    println!("\n  {} signed in as {}", crate::style::green("✓"), crate::style::bold(email.as_deref().unwrap_or(user)));
                    println!("  {}", crate::style::dim("cli registered"));
                    return Ok(());
                }
            }
        }
    }
    Err(anyhow!("the stream closed before sign-in completed"))
}

/// `neuralkit auth unregister` — end this machine's session AND forget the registration.
///
/// NOT the same as the REPL's `logout`, and the difference is the point. Logging out ends
/// a session; the machine stays registered, which is exactly why the next sign-in needs
/// only a code. This removes what makes it registered — the account id on disk — so the
/// next `auth login` starts from a QR, as a machine that had never signed in would.
///
/// Server FIRST, disk second, the ordering `session.rs` already states for logout:
/// deleting the file first would leave a token valid for its full TTL with nothing left
/// on disk to revoke it with. The revoke is best-effort, because an ALREADY-dead session
/// must not block the delete — reaching a clean state after an expiry is the main case.
pub async fn unregister() -> Result<()> {
    let Ok(prev) = read_credentials_json() else {
        println!("\n  {}\n", crate::style::dim("this machine is not registered"));
        return Ok(())
    };
    let who = prev
        .get("email")
        .or_else(|| prev.get("user"))
        .and_then(Value::as_str)
        .unwrap_or("this machine")
        .to_string();

    // Origin from the FILE, never an argument: the machine recorded where it registered,
    // so there is no way to revoke against the wrong host while deleting the right file.
    let origin = prev.get("origin").and_then(Value::as_str).unwrap_or_default().trim_end_matches('/');
    if let Some(token) = prev.get("token").and_then(Value::as_str).filter(|t| !t.is_empty()) {
        if !origin.is_empty() {
            let insecure = origin.contains("127.0.0.1") || origin.contains("localhost");
            let client = reqwest::Client::builder().danger_accept_invalid_certs(insecure).build()?;
            let _ = client
                .post(format!("{origin}/transport/action/Session/delete"))
                .header("cookie", format!("session={token}; __Secure-session={token}"))
                .send()
                .await;
        }
    }

    // Unconditional, and AFTER the revoke. Reaching a clean state once the session has
    // already lapsed is the main reason this exists, so a failed or skipped revoke must
    // not stop the delete — the token it would have revoked is worthless by then anyway.
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = format!("{home}/.config/neuralkit/credentials.json");
    if let Err(e) = std::fs::remove_file(&path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err(anyhow!("could not remove {path}: {e}"))
        }
    }

    println!();
    println!("  {} unregistered {}", crate::style::green("✓"), crate::style::dim(&format!("· {who}")));
    println!("  {}\n", crate::style::dim("the next `auth login` will show a QR"));
    Ok(())
}

/// Decide how this machine signs in, and run it.
///
/// Three ways the answer arrives, in order: `--method` decides outright; otherwise a
/// machine with nothing on disk has no choice to make and takes the QR; otherwise ask.
/// That ordering is what keeps a scripted caller from ever meeting a prompt, and a
/// first-run machine from being offered an option that cannot identify it.
///
/// `Ok(false)` means "use the QR" — including an unrecognised answer, so a stray
/// keystroke costs nothing.
async fn choose_method(
    client: &reqwest::Client,
    base_url: &str,
    user_code: &str,
    method: Option<Method>,
) -> Result<bool> {
    if matches!(method, Some(Method::Qr)) {
        return Ok(false)
    }
    // Both remaining cases need the account id, so read it once. Its absence is what
    // makes this a first run: nothing deletes credentials.json, so a machine that has
    // ever signed in still names its account long after the token died.
    let Ok(prev) = read_credentials_json() else { return Ok(false) };
    let Some(user) = prev.get("user").and_then(Value::as_str).map(String::from) else { return Ok(false) };
    let who = prev.get("email").and_then(Value::as_str).unwrap_or(&user).to_string();

    if matches!(method, Some(Method::Totp)) {
        return totp_approve(client, base_url, user_code, &user).await
    }

    // The picker takes over the terminal, so it runs OFF the async runtime — crossterm's
    // event::read blocks, and this task is holding the SSE connection open.
    let header = format!("  {} {}", crate::style::bold("neuralkit"), crate::style::dim(&format!("· {who}")));
    let picked = tokio::task::spawn_blocking(move || {
        select(&header, &["scan a QR code with your phone", "enter a code from your authenticator app"])
    })
    .await??;

    match picked {
        Some(1) => totp_approve(client, base_url, user_code, &user).await,
        _ => Ok(false),
    }
}

/// A one-of-N picker on the arrow keys. `None` = declined, or no terminal to draw on.
///
/// Not a TTY means nobody is there to choose — a pipe, a CI runner, the E2E — so it
/// declines rather than blocking forever on an event that never arrives. That check is
/// also what keeps raw mode off a terminal that isn't one.
///
/// Raw mode is entered and left around ONE closure so no early return can strand the
/// terminal without an echo, which is the classic way a picker breaks a shell.
fn select(header: &str, options: &[&str]) -> Result<Option<usize>> {
    use crossterm::{
        cursor,
        event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
    };
    use std::io::IsTerminal;

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Ok(None)
    }

    let mut out = std::io::stdout();
    println!();
    println!("{header}");
    println!();

    let mut sel = 0usize;
    enable_raw_mode()?;
    execute!(out, cursor::Hide)?;
    let outcome = (|| -> Result<Option<usize>> {
        loop {
            // Raw mode means the terminal no longer translates \n, so rows need \r\n.
            for (i, o) in options.iter().enumerate() {
                if i == sel {
                    print!("  {} {}\r\n", crate::style::cyan("❯"), crate::style::bold(o));
                } else {
                    print!("    {}\r\n", crate::style::dim(o));
                }
            }
            out.flush()?;

            let key = loop {
                if let Event::Key(k) = event::read()? {
                    // Windows reports press AND release; acting on both moves twice.
                    if k.kind != KeyEventKind::Release {
                        break k
                    }
                }
            };
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => sel = (sel + options.len() - 1) % options.len(),
                KeyCode::Down | KeyCode::Char('j') => sel = (sel + 1) % options.len(),
                KeyCode::Enter => return Ok(Some(sel)),
                KeyCode::Esc | KeyCode::Char('q') => return Ok(None),
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(None),
                _ => {}
            }
            execute!(out, cursor::MoveUp(options.len() as u16), Clear(ClearType::FromCursorDown))?;
        }
    })();

    execute!(out, cursor::Show)?;
    disable_raw_mode()?;
    println!();
    outcome
}

/// Approve THIS device flow with an authenticator code instead of a phone.
///
/// The QR flow has three parties' worth of steps but only two roles: the terminal, which
/// generates the device_code and holds the stream, and a signed-in session, which approves.
/// A machine that has logged in before can supply the second role itself — `credentials.json`
/// outlives the token it holds, so the account id is still on disk when the session dies,
/// and six digits prove the owner is present.
///
/// So this is two ordinary calls, not a new mechanism: sign in with the code, then perform
/// the SAME approval step the phone performs. `QrCode.approve` still does the minting and
/// still promotes `cli:pk:code:<device>` onto the token it mints, which is why the command
/// channel comes up sealed exactly as it does after a scan.
///
/// `Ok(false)` for every "nothing to try" case — no file, no id, a blank line, a refused
/// code — so the caller renders the QR instead. Never a dead end.
async fn totp_approve(client: &reqwest::Client, base_url: &str, user_code: &str, user: &str) -> Result<bool> {
    // Nothing is read from disk here: `user` came from the caller's read, and the keys +
    // the new token are written by the stream branch once QrCode.approve broadcasts —
    // the same path the QR takes, with this run's fresh keypair.
    println!();
    print!("  {} ", crate::style::dim("authenticator code:"));
    std::io::stdout().flush()?;

    let mut line = String::new();
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    if tokio::io::AsyncBufReadExt::read_line(&mut stdin, &mut line).await? == 0 {
        return Ok(false)
    }
    let code = line.trim();
    if code.is_empty() {
        println!();
        return Ok(false)
    }

    // 1. The code buys a session. `mint:` lands it in a cookie, so it arrives as a
    //    Set-Cookie header — httpOnly is a browser rule and says nothing to a client
    //    reading headers. Both names, because the app picks one by build mode.
    // `client: "terminal"` is the declaration the server can't derive: this id is an
    // ACCOUNT id, not a credential id, because a terminal has never run a WebAuthn
    // ceremony. It grants nothing — the same secret lookup and the same code check run
    // either way; it only picks which column resolves the account.
    let res = client
        .post(format!("{base_url}/transport/action/Totp/login"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "id": user, "code": code, "client": "terminal" }).to_string())
        .send()
        .await?;
    let token = res
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            let (name, rest) = c.split_once('=')?;
            matches!(name.trim(), "session" | "__Secure-session")
                .then(|| rest.split(';').next().unwrap_or("").to_string())
        });
    let body: Value = serde_json::from_str(&res.text().await?).unwrap_or(Value::Null);
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        let msg = body.pointer("/error/message").and_then(Value::as_str).unwrap_or("that code was not accepted");
        println!("  {} {}\n", crate::style::red("✗"), msg);
        return Ok(false)
    };
    let cookie = format!("session={token}; __Secure-session={token}");

    // 2. Approve, from that session — the step the phone would have performed.
    let ap = client
        .post(format!("{base_url}/transport/action/QrCode/approve"))
        .header("content-type", "application/json")
        .header("cookie", &cookie)
        .body(serde_json::json!({ "code": user_code }).to_string())
        .send()
        .await?;
    let ap_body: Value = serde_json::from_str(&ap.text().await?).unwrap_or(Value::Null);
    if ap_body.pointer("/data/ok").and_then(Value::as_bool) != Some(true) {
        let msg = ap_body.pointer("/error/message").and_then(Value::as_str).unwrap_or("approval refused");
        println!("  {} {}\n", crate::style::red("✗"), msg);
        return Ok(false)
    }

    // 3. Drop the session the code bought. Its whole purpose was to authorize the
    //    approval, and the terminal's own token is minted by that approval — leaving this
    //    one behind would accumulate a dead session per login, which is the growth the
    //    E2E already measures. Best-effort: a failure here costs a stale record, not a login.
    let _ = client
        .post(format!("{base_url}/transport/action/Session/delete"))
        .header("cookie", &cookie)
        .send()
        .await;

    Ok(true)
}

/// credentials.json as raw JSON. Deliberately not session.rs's typed loader: this path
/// exists for a file whose token has already lapsed, and reads only what outlives it.
fn read_credentials_json() -> Result<Value> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let raw = std::fs::read_to_string(format!("{home}/.config/neuralkit/credentials.json"))?;
    Ok(serde_json::from_str(&raw)?)
}

/// Ask the session we were just granted who it belongs to, and when it dies.
/// `expires` is the record's own absolute ms timestamp — storing the deadline rather than
/// a duration means the remaining time stays correct however long the file sits unread.
async fn resolve_session(client: &reqwest::Client, base_url: &str, token: &str) -> (Option<String>, Option<i64>) {
    let fetch = async {
        let res = client
            .post(format!("{base_url}/transport/action/Session/request"))
            .header("cookie", format!("session={token}; __Secure-session={token}"))
            .send()
            .await
            .ok()?;
        serde_json::from_str::<Value>(&res.text().await.ok()?).ok()
    };
    match fetch.await {
        Some(v) => (
            v.pointer("/data/user/email").and_then(Value::as_str).map(String::from),
            v.pointer("/data/expires").and_then(Value::as_i64),
        ),
        None => (None, None),
    }
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
    println!("{}\n", crate::style::dim("Scan with your mobile device to sign in."));
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

fn save_credentials(origin: &str, token: &str, user: &str, email: Option<&str>, expires: Option<i64>, kem_secret: &str, sign_key: Option<&str>) -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let dir = format!("{home}/.config/neuralkit");
    std::fs::create_dir_all(&dir)?;
    // `kem_secret` is the ML-KEM secret whose public half the server bound to this session —
    // the only thing that can open the session channel's frames. It is paired with `token`:
    // a new login mints a new keypair, and the server drops the old binding with the session.
    // `sign_key` is the app's PUBLIC ed25519 key (not a secret), kept here so frame signatures
    // can be verified with no configuration.
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "token": token, "user": user, "email": email, "expires": expires, "origin": origin,
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
