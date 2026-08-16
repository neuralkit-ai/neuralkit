//! `neuralkit auth login` — passkey QR device flow.
//!
//! The CLI generates a SECRET `device_code`, holds the `QR.request` SSE stream, and
//! renders the returned `user_code` as a terminal QR. The phone scans it →
//! `/qr?code=…` → the passkey login (which signs the phone in) → `QR.approve`
//! broadcasts a fresh session token to `qr:<device_code>`, which this held
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
    Passkey,
    Email,
    /// A passkey asserted in this machine's BROWSER rather than by the CLI itself.
    ///
    /// THERE IS ONLY ONE KIND OF PASSKEY, and both paths mint a real WebAuthn credential through
    /// the same `Passkey/register*` + `Passkey/login*` fences into the same `credentials` table —
    /// `phaze-auth` IS an authenticator, it does not imitate one. What differs is WHICH
    /// authenticator answered, which is what `aaguid` exists to say:
    ///
    ///   fbfc3007-154e-4ecc-8c0b-6e020557d7bd  Apple Passwords  transports ["hybrid","internal"]
    ///   91eec8ac-7c27-4485-9d3b-4b98f7b3027e  ours             transports []
    ///
    /// The empty transports are the whole difference. Our own credential's private half is sealed
    /// in this Mac's enclave and cannot travel; Apple's syncs across the account's devices. So a
    /// machine that has never signed in has no credential of ours to assert — but it may already
    /// hold the person's, put there by iCloud. That is the only reason this path can bootstrap
    /// and `Passkey` cannot, and it is a property of the AUTHENTICATOR, not of the credential.
    Browser,
}

pub async fn run(base_url: &str, method: Option<Method>) -> Result<()> {
    let base_url = base_url.trim_end_matches('/');

    // The CLI's secret device_code (32 random bytes → 64 hex) — only ever in this
    // connection URL. `cli:<device_code>` is the tag the token broadcasts to.
    let mut dc = [0u8; 32];
    getrandom::getrandom(&mut dc).map_err(|e| anyhow!("rng: {e}"))?;
    let device_code = to_hex(&dc);

    // This install's ML-KEM-768 keypair, minted HERE so the secret never travels. The public
    // half rides the device flow and QR.approve binds it to the session it mints; the
    // session channel's per-connection DEK is then encapsulated to it, so only this machine
    // can open those frames. Nothing is shared between installs and nothing is in the binary.
    let (kem_pk, kem_sk) = ml_kem::generate().map_err(|e| anyhow!("ml-kem generate: {e}"))?;

    // THE ONE-CALL PATH, TRIED FIRST. A machine the server already knows has nothing to be
    // approved — it is authenticating and enrolling itself, so the device flow below (stage a
    // key, hold a stream, draw a user_code, wait for something to approve it) is a protocol
    // built for a SECOND device that this one does not need. `Cli.login` does the whole thing in
    // one request, signing a challenge the server handed over on the way out of the last one.
    //
    // ANY miss falls through rather than failing: no stored challenge, one already spent, an
    // expired one, a revoked credential, a device row that is no longer this account's. A
    // shortcut that could strand a machine would be worse than no shortcut, so the only thing a
    // refusal costs is the four extra calls it was trying to save.
    //
    // ONLY WHEN NOTHING WAS ASKED FOR. `--totp`/`--email`/`--qr`/`--passkey` name a path, and a
    // shortcut that overrode them would make the flag silently do nothing — the machine would
    // answer a question the caller did not ask. `None` means "decide at runtime", which is the
    // only case where deciding is ours to do.
    match if method.is_some() { Ok(None) } else { crate::passkey::quick_login(base_url, &kem_pk.to_hex()).await } {
        Ok(Some((token, d))) => {
            let user = d.get("user").and_then(Value::as_str).unwrap_or("");
            let email = d.get("email").and_then(Value::as_str);
            let expires = d.get("expires").and_then(Value::as_i64);
            let totp = d.get("totpEnabled").and_then(Value::as_bool);
            let device_id = d.get("deviceId").and_then(Value::as_str);
            let sign_key = d.get("signKey").and_then(Value::as_str);
            save_credentials(base_url, &token, user, email, expires, &kem_sk.to_hex(), sign_key, device_id, totp)?;
            if let Some(id) = device_id {
                crate::passkey::save_device_id(id)?;
            }
            println!("\n  {} signed in as {}", crate::style::green("✓"), crate::style::bold(email.unwrap_or(user)));
            println!("  {}", crate::style::dim("cli registered"));
            if crate::passkey::is_registered() {
                println!(
                "  {}",
                crate::style::dim(if crate::passkey::gate_armed() {
                    "passkey registered · Secure Enclave"
                } else {
                    "passkey registered"
                }),
            );
            }
            if totp == Some(true) {
                println!("  {}", crate::style::dim("authenticator registered"));
            }
            return Ok(())
        }
        Ok(None) => {}
        // The gate refusing is not a failure to report as one — it is the machine saying the
        // key is locked, which the menu below then explains and routes around.
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains("Apple Watch") && !msg.contains("verify a person") {
                println!("  {}", crate::style::dim(&format!("one-step sign-in unavailable ({msg}) — falling back")));
            }
        }
    }

    // The registration this machine already holds, if any. A fresh keypair every login
    // means the row's key must be replaced, not duplicated — so the id travels with it.
    // Option, never an empty string: the field is `.optional()` server-side, which permits
    // ABSENT and not "" — an empty value fails the length check and takes the whole
    // registration down with it.
    // From the DURABLE file, never the session one. credentials.json is deleted on logout and
    // on expiry, so an id kept there is lost exactly when a machine stops being used — and the
    // next sign-in, with nothing to claim, registers the same machine as a second device.
    let prior_device_id = crate::passkey::device_id();

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
            // The hostname rides along as a LABEL — cosmetic, so a device list reads as
            // machines rather than opaque ids. Never interpreted server-side.
            //
            // `deviceId` is this machine's existing registration, when it has one. Sending
            // it is what makes a re-login UPDATE the row rather than mint a second device;
            // the server honours it only if that row already belongs to the account that
            // authenticates, so it is a claim rather than a credential.
            .body({
                let mut b = serde_json::json!({
                    "device": device_code,
                    "pk": kem_pk.to_hex(),
                    "label": hostname(),
                    "os": os_label(),
                    "terminal": terminal_type(),
                });
                if let Some(id) = &prior_device_id {
                    b["deviceId"] = Value::String(id.clone());
                }
                b.to_string()
            })
            .send()
            .await
            .ok()?;
        let body: Value = serde_json::from_str(&res.text().await.ok()?).ok()?;
        body.pointer("/data/signKey").and_then(Value::as_str).map(String::from)
    }
    .await;

    // Registration is no longer optional decoration. It stages the key QR.approve
    // promotes AND the row that names this machine — so a silent failure here surfaces
    // much later as a REPL that never reaches its prompt, because the channel declares a
    // seal, no DEK is ever established, and the signed-but-unsealed frames that result are
    // a shape the client cannot read. Say so here, where the cause still is the effect.
    if sign_key.is_none() {
        println!(
            "  {} {}",
            crate::style::red("✗"),
            crate::style::dim("could not register this machine — the session channel will not be sealed"),
        );
    }

    let url = format!("{base_url}/transport/stream/QR/request?device={device_code}");
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
                        // same QR.approve doing the mint and the key promotion. Only
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
                    // The registration the server just wrote or refreshed. Kept so the NEXT
                    // login names the same machine instead of registering a second one, and
                    // so `unregister` has a row to revoke rather than only a file to delete.
                    let device_id = v.get("deviceId").and_then(Value::as_str);
                    // THE GRANT CARRIES THE PROJECTION. `QR.approve` holds the user row
                    // and the minted expiry when it broadcasts, so it says both — this used to
                    // be a second round trip asking the server who we had just become.
                    // Falls back to asking only if a field is genuinely absent.
                    let email = v.get("email").and_then(Value::as_str).map(String::from);
                    let expires = v.get("expires").and_then(Value::as_i64);
                    let totp_enabled = v.get("totpEnabled").and_then(Value::as_bool);
                    let (email, expires, totp_enabled) = if expires.is_some() {
                        (email, expires, totp_enabled)
                    } else {
                        resolve_session(&client, base_url, token).await
                    };
                    save_credentials(base_url, token, user, email.as_deref(), expires, &kem_sk.to_hex(), sign_key.as_deref(), device_id, totp_enabled)?;
                    // Two lines, because a login does two things: it authenticates you and
                    // it registers the machine. Naming the second is what makes the code
                    // option on the next run — and `auth unregister` — make sense.
                    println!("\n  {} signed in as {}", crate::style::green("✓"), crate::style::bold(email.as_deref().unwrap_or(user)));
                    println!("  {}", crate::style::dim("cli registered"));

                    // BOOTSTRAP, DONE ONCE AND INVISIBLY. Whichever path just signed this
                    // machine in, it now holds the one thing registering a passkey needs: a
                    // session. Doing it here is what makes the passkey a real option rather
                    // than a command someone has to know about — the NEXT sign-in can use it,
                    // on a machine whose owner never asked for one.
                    //
                    // Best-effort and quiet: a sign-in must not fail because a convenience
                    // did, and the paths that already work are unaffected either way.
                    if !crate::passkey::is_registered() {
                        if let Err(e) = crate::passkey::register(base_url, true).await {
                            println!("  {} {}", crate::style::dim("no passkey registered:"), crate::style::dim(&e.to_string()));
                        }
                    }

                    // WHAT THIS MACHINE HOLDS, said every time — not only when it changed. The
                    // passkey line used to print solely on the run that created one, so every
                    // later sign-in was silent about it and there was no way to tell a machine
                    // that has one from a machine that never got one. A sign-in should state
                    // where you stand, not just what happened in the last few seconds.
                    if crate::passkey::is_registered() {
                        println!(
                "  {}",
                crate::style::dim(if crate::passkey::gate_armed() {
                    "passkey registered · Secure Enclave"
                } else {
                    "passkey registered"
                }),
            );
                    }
                    if totp_enabled == Some(true) {
                        println!("  {}", crate::style::dim("authenticator registered"));
                    }

                    // AFTER the registration, not before — that is what creates passkey.json.
                    // Writing the id earlier found no file and silently did nothing, which left
                    // the id only in the session file and defeated the point of moving it.
                    if let Some(id) = device_id {
                        let _ = crate::passkey::save_device_id(id);
                    }

                    // THE CHALLENGE THAT MAKES THE NEXT LOGIN ONE CALL. Handed over on this
                    // grant precisely because the machine has just proved itself and been
                    // enrolled; storing it here is what arms `quick_login` above. Best-effort —
                    // without it the next run simply takes this same path again.
                    if let Some(next) = v.get("nextChallenge").and_then(Value::as_str) {
                        let _ = crate::passkey::save_next_challenge(next);
                    }

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
    // TWO INDEPENDENT THINGS now live on this machine, and the passkey is the one that
    // outlives sessions — so an absent credentials.json can no longer end this early. A
    // machine with no session but a live passkey is the ordinary state after a logout, and
    // it is exactly the state this command exists to clear.
    let had_passkey = crate::passkey::exists();

    let Ok(prev) = read_credentials_json() else {
        if had_passkey {
            if let Err(e) = crate::passkey::forget() {
                println!("\n  {} {}\n", crate::style::red("✗"), e);
                return Err(e)
            }
            println!("\n  {} {}", crate::style::green("✓"), "this machine's passkey was deleted");
            println!("  {}\n", crate::style::dim("no session was signed in"));
        } else {
            println!("\n  {}\n", crate::style::dim("this machine is not registered"));
        }
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
            // THE MACHINE'S PASSKEY IS ITS PROOF, so the stored token is only a shortcut.
            // Unregistering happens when someone has finished with a machine, which is exactly
            // when its session has expired — so depending on that token meant the revocation
            // almost never fired and orphaned rows accumulated on every cycle. Asserting the
            // credential we are about to destroy always works while it still exists, and the
            // case with no credential needs no revoke at all: nothing was ever registered.
            let live = match crate::passkey::revoke(origin, token).await {
                Ok(counts) => Some(Ok(counts)),
                // Only an auth failure is worth a second attempt — a network error would fail
                // the same way twice, and the passkey path is a round trip, not a retry.
                Err(_) if crate::passkey::is_registered() => None,
                Err(e) => Some(Err(e)),
            };
            let outcome = match live {
                Some(r) => r,
                None => match crate::passkey::assert_session(origin).await {
                    Ok(fresh) => crate::passkey::revoke(origin, &fresh).await,
                    Err(e) => Err(e),
                },
            };
            match outcome {
                Ok((d, c)) if d + c > 0 => println!(
                    "  {} {}",
                    crate::style::green("✓"),
                    crate::style::dim(&format!("server forgot this machine · {d} device, {c} credential")),
                ),
                Ok(_) => {}
                Err(e) => println!("  {} {}", crate::style::dim("could not revoke server-side:"), crate::style::dim(&e.to_string())),
            }

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

    // The machine's own credential goes too. `unregister` is the command that means "forget
    // this machine", and the passkey is the most durable thing that makes it recognisable —
    // leaving it behind would mean a machine that still holds a credential for an account it
    // no longer has a session for. `logout` deliberately does NOT do this.
    if let Err(e) = crate::passkey::forget() {
        println!("  {} {}", crate::style::red("✗"), e);
    }

    println!();
    println!("  {} unregistered {}", crate::style::green("✓"), crate::style::dim(&format!("· {who}")));
    if had_passkey {
        println!("  {}", crate::style::dim("this machine's passkey was deleted"));
    }
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

    // WHAT THIS MACHINE CAN ACTUALLY OFFER, asked separately for each path — they do not
    // expire together. An authenticator code needs the ACCOUNT ID, which lives in
    // credentials.json and outlives the token there. A passkey needs a REGISTRATION, which
    // lives in its own file and outlives credentials.json entirely. Reading only the session
    // file would hide the passkey on exactly the machine most likely to have one: signed out.
    let prev = read_credentials_json().ok();
    let user = prev.as_ref().and_then(|v| v.get("user").and_then(Value::as_str)).map(String::from);
    let who = prev
        .as_ref()
        .and_then(|v| v.get("email").and_then(Value::as_str))
        .map(String::from)
        .or_else(|| user.clone())
        .unwrap_or_else(|| "this machine".to_string());
    // A KEY THIS MACHINE CANNOT USE IS NOT AN OPTION. The gate is the owner's choice and is
    // honoured rather than worked around — but it locks one path, not the person out. Say why
    // once, drop that path, and offer the others: QR, an authenticator code and an emailed code
    // never touch this machine's key.
    let blocked = crate::passkey::presence_blocked();
    let mut can_passkey = crate::passkey::is_registered() && blocked.is_none();
    if let Some(why) = &blocked {
        println!();
        for line in why.lines() {
            println!("  {}", crate::style::dim(line.trim()));
        }
    }

    if matches!(method, Some(Method::Passkey)) {
        return passkey_approve(client, base_url, user_code).await
    }
    if matches!(method, Some(Method::Email)) {
        return email_approve(client, base_url, user_code).await
    }
    if matches!(method, Some(Method::Totp)) {
        let Some(user) = &user else { return Ok(false) };
        return totp_approve(client, base_url, user_code, user).await
    }

    // A REGISTERED MACHINE JUST SIGNS IN. Holding a credential the server already knows is
    // not a decision to put to someone — it is the answer. So the passkey is TRIED rather
    // than offered, and the menu only appears if there is something left to choose.
    //
    // A refusal falls through instead of dead-ending: a credential can be revoked
    // server-side, or the account deleted from under it, and the machine cannot know that
    // until it asks. Dropping to the other paths is what turns that from a lockout into a
    // slower sign-in. An ungated key that was refused is dropped from the menu — offering
    // it again would only invite the same failure — but a GATED key earns a retry row
    // below: that refusal is usually the Watch situation of the moment, fixable on the
    // spot, and the person decides when to stop trying.
    let mut machine_key_refused = false;
    if can_passkey {
        if passkey_approve(client, base_url, user_code).await? {
            return Ok(true)
        }
        can_passkey = false;
        machine_key_refused = true;
        println!("  {}", crate::style::dim("this machine's passkey was refused — other ways in:"));
    }

    // Offer only what is usable — the same rule the REPL's `help` follows. A machine with
    // nothing to choose between never sees a menu, which keeps a first run to one path.
    // The email path needs NOTHING on this machine — just an address someone can read mail
    // at — which is what makes it the only option that works on a machine that has never
    // signed in. Every other path is downstream of a session that already happened.
    // The QR's job is bridging TWO devices — the terminal cannot show a browser, so the code
    // travels by eye. When the browser is on THIS machine there is nothing to bridge: the code
    // goes straight there. Same code, same held stream, same QR.approve; only how the code
    // reaches the page changes.
    let mut labels: Vec<&str> = vec![
        "scan a QR code with your phone",
        "use your passkey",
        "email me a sign-in code",
    ];
    let mut paths: Vec<Method> = vec![Method::Qr, Method::Browser, Method::Email];
    // Absent means an older credentials.json that predates the field — offer it rather than
    // hide a path that may well work.
    let has_totp = prev
        .as_ref()
        .and_then(|v| v.get("totp_enabled"))
        .map(|t| t.as_bool().unwrap_or(true))
        .unwrap_or(true);
    if user.is_some() && has_totp {
        labels.push("use your authenticator app");
        paths.push(Method::Totp);
    }
    if can_passkey {
        labels.push("use this machine's passkey");
        paths.push(Method::Passkey);
    }
    // THE LOCKED PATH STAYS ON THE MENU AS A RETRY — and it LEADS the menu. One label for
    // every situation that involves fetching the Watch: blocked before trying, refused
    // mid-attempt, or the unregistered CATCH-22 (registration itself needs the key to
    // sign, so hiding the wait left "put it on — then try again" with no way to try
    // again). First and pre-selected, because reconnecting the Watch is the primary
    // action whenever the row exists — the other doors wait below. Re-checking at the
    // moment it is picked is what makes it a retry rather than a stale entry, since
    // availability changes minute to minute; an unregistered pick hands over to the QR
    // once the Watch is found, so the register step can finally land.
    let watch_row = if crate::passkey::is_registered() {
        blocked.is_some() || (machine_key_refused && crate::passkey::gate_armed())
    } else {
        blocked.is_some()
    };
    if watch_row {
        labels.insert(0, "connect to Apple Watch");
        paths.insert(0, Method::Passkey);
    }
    if paths.len() == 1 {
        return Ok(false)
    }

    // The picker takes over the terminal, so it runs OFF the async runtime — crossterm's
    // event::read blocks, and this task is holding the SSE connection open.
    // A LOOP, because the Watch row is a RETRY: a failed attempt returns to this menu — the
    // person keeps trying until it signs, or picks another door, or declines. Every other
    // row still decides once.
    let header = format!("  {} {}", crate::style::bold("neuralkit"), crate::style::dim(&format!("· {who}")));
    let owned: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
    loop {
        let (h, o) = (header.clone(), owned.clone());
        let picked = tokio::task::spawn_blocking(move || {
            let refs: Vec<&str> = o.iter().map(String::as_str).collect();
            select(&h, &refs)
        })
        .await??;

        return match picked.map(|i| paths[i]) {
            Some(Method::Totp) => match &user {
                Some(u) => totp_approve(client, base_url, user_code, u).await,
                None => Ok(false),
            },
            Some(Method::Passkey) => {
                // Asked AGAIN here, not reused from above: the menu may have been on screen a
                // while, and the whole point of that entry is that the answer can have changed.
                // Keep asking for a few seconds rather than answering once — a wrist raise, a
                // Bluetooth reconnect and an unlock all take a moment, and the person has just
                // told us they are fetching it.
                // Two minutes. The person has just walked off to fetch the Watch, and a wrist
                // raise, a Bluetooth reconnect and an unlock stack up on top of the walk. Giving up
                // while they are still on their way back is the wrong failure, and Ctrl-C is always
                // there for someone who changed their mind.
                if let Some(why) = crate::passkey::wait_for_presence(120) {
                    println!();
                    println!("  {} {}", crate::style::red("✗"), crate::style::dim(why.lines().next().unwrap_or("still unavailable")));
                    continue
                }
                if !crate::passkey::is_registered() {
                    // Watch found, but there is no credential to assert yet — Ok(false)
                    // means "use the QR", and THAT flow registers this machine now that
                    // the key can sign.
                    return Ok(false)
                }
                if passkey_approve(client, base_url, user_code).await? {
                    return Ok(true)
                }
                // The ✗ and its reason were just printed by the attempt itself — nothing to
                // add; the reappearing menu IS the "again, or another way?" question.
                continue
            }
            Some(Method::Email) => email_approve(client, base_url, user_code).await,
            Some(Method::Browser) => browser_approve(base_url, user_code),
            _ => Ok(false),
        }
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
pub(crate) fn select(header: &str, options: &[&str]) -> Result<Option<usize>> {
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
/// the SAME approval step the phone performs. `QR.approve` still does the minting and
/// still promotes `cli:pk:code:<device>` onto the token it mints, which is why the command
/// channel comes up sealed exactly as it does after a scan.
///
/// `Ok(false)` for every "nothing to try" case — no file, no id, a blank line, a refused
/// code — so the caller renders the QR instead. Never a dead end.
async fn totp_approve(client: &reqwest::Client, base_url: &str, user_code: &str, user: &str) -> Result<bool> {
    // Nothing is read from disk here: `user` came from the caller's read, and the keys +
    // the new token are written by the stream branch once QR.approve broadcasts —
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
    approve_and_release(client, base_url, user_code, &token, "totp").await
}

/// Approve this device flow with an emailed code — the path that needs nothing but an inbox.
///
/// THE ONE THAT BOOTSTRAPS. Every other path is downstream of a session that already existed:
/// the QR needs a passkey to scan with, the code path needs a prior sign-in to leave an account
/// id behind, the passkey path needs a credential registered against the account. This needs
/// only an address that is already approved — so it is what a machine that has never signed in
/// can actually do, with no browser and no phone.
///
/// It also binds the RIGHT identity, which the alternatives do not: `EmailCode.login`
/// find-or-creates by address, so the session is the approved account's rather than a fresh
/// anonymous one. Everything downstream — the device row, the passkey registered afterwards —
/// then belongs to the person who owns that inbox.
async fn email_approve(client: &reqwest::Client, base_url: &str, user_code: &str) -> Result<bool> {
    println!();
    // THE ONE PATH WITH AN UNBOUNDED WAIT IN IT. Both the staged key and the user code are
    // held for five minutes from the moment this command started, and every other path
    // finishes in seconds — a scan, six digits, a signature. Waiting on an inbox is the only
    // way to overrun it, so the deadline is said out loud rather than discovered.
    println!("  {}", crate::style::dim("finish within 5 minutes — the sign-in window is already open"));
    print!("  {} ", crate::style::dim("email address:"));
    std::io::stdout().flush()?;
    let mut line = String::new();
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    if tokio::io::AsyncBufReadExt::read_line(&mut stdin, &mut line).await? == 0 {
        return Ok(false)
    }
    let email = line.trim().to_string();
    if email.is_empty() {
        println!();
        return Ok(false)
    }

    // The SUCCESS answer is deliberately the same whether or not an address has access — the
    // server will not say which, so neither does this. A REFUSAL is a different thing and must
    // be shown: rate limiting describes the caller, not the address, so surfacing it leaks
    // nothing and hiding it turns "you have used your five attempts this hour" into "the mail
    // never arrived", which sends someone looking in the wrong place entirely.
    let res = client
        .post(format!("{base_url}/transport/action/Cli/requestCode"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "email": email }).to_string())
        .send()
        .await?;
    let body: Value = serde_json::from_str(&res.text().await?).unwrap_or(Value::Null);
    if let Some(m) = body.pointer("/error/message").and_then(Value::as_str) {
        println!("  {} {}\n", crate::style::red("✗"), m);
        return Ok(false)
    }
    println!("  {}", crate::style::dim("if that address has access, a code is on its way"));

    print!("  {} ", crate::style::dim("code:"));
    std::io::stdout().flush()?;
    let mut line = String::new();
    if tokio::io::AsyncBufReadExt::read_line(&mut stdin, &mut line).await? == 0 {
        return Ok(false)
    }
    let code = line.trim().to_string();
    if code.is_empty() {
        println!();
        return Ok(false)
    }

    let res = client
        .post(format!("{base_url}/transport/action/EmailCode/login"))
        .header("content-type", "application/json")
        .body(serde_json::json!({ "email": email, "code": code }).to_string())
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

    approve_and_release(client, base_url, user_code, &token, "email").await
}

/// Approve this device flow with THIS machine's own passkey.
///
/// The third way to supply the approving session, and structurally the same move the
/// authenticator code makes: obtain a session, perform the approval the phone would have
/// performed, drop the session afterwards. The device flow itself is untouched — same
/// device_code, same held stream, same QR.approve doing the mint and promoting this
/// install's key, which is why the sealed channel comes up exactly as it does after a scan.
///
/// It is also the path that needs nothing from the person: no phone, no code, no typing.
/// Hand the code to THIS machine's browser instead of to a phone's camera.
///
/// Returns true meaning "the QR is not needed", NOT "signed in" — nothing is approved here. The
/// stream this task is already holding stays open, the person authorizes on the page, and the
/// token arrives on that stream exactly as it does after a scan. Same `QR.approve`, same mint.
///
/// THE ANTI-PHISHING PROPERTY SURVIVES, and it is worth being explicit about because `render_qr`
/// deliberately prints no URL (RFC 8628 §5.4 — an attacker's danger is getting you to authorize
/// THEIR code). Handing the URL to a local process is not the same channel as putting it on
/// screen: nothing pasteable appears, nothing leaves this machine, and the code still came from
/// the flow this terminal started. Do not "helpfully" print it on failure.
fn browser_approve(base_url: &str, user_code: &str) -> Result<bool> {
    let url = format!("{base_url}/qr?code={user_code}");
    #[cfg(target_os = "macos")]
    let mut cmd = { let mut c = std::process::Command::new("open"); c.arg(&url); c };
    #[cfg(target_os = "windows")]
    let mut cmd = { let mut c = std::process::Command::new("cmd"); c.args(["/C", "start", "", &url]); c };
    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    let mut cmd = { let mut c = std::process::Command::new("xdg-open"); c.arg(&url); c };

    println!();
    match cmd.status() {
        Ok(s) if s.success() => {
            println!("  {}", crate::style::dim("opened your browser — approve there to sign in."));
            println!();
            Ok(true)
        }
        // No browser, or none that could be launched (a headless box, a bare SSH session).
        // Falling through hands the caller back to the QR, which is the path that still works
        // when this machine has no screen of its own.
        _ => {
            println!("  {} {}", crate::style::red("✗"), crate::style::dim("could not open a browser here"));
            Ok(false)
        }
    }
}

async fn passkey_approve(client: &reqwest::Client, base_url: &str, user_code: &str) -> Result<bool> {
    println!();
    println!("  {}", crate::style::dim("signing in with this machine's passkey…"));
    let token = match crate::passkey::assert_session(base_url).await {
        Ok(t) => t,
        Err(e) => {
            println!("  {} {}\n", crate::style::red("✗"), e);
            return Ok(false)
        }
    };
    approve_and_release(client, base_url, user_code, &token, "passkey").await
}

/// The half every self-approval shares: approve the flow with a session we just obtained, then
/// give that session back.
///
/// `via` records WHICH path did it. The approver is this machine either way, so the row's
/// `approved_by_*` columns will repeat its own network — the field is what stops that reading
/// as a second party, and what tells a device list apart later.
///
/// Releasing the session is not tidiness. Its whole purpose was to authorise one call, and the
/// terminal's real token is minted BY that call — leaving this one behind would accumulate a
/// dead record per login, which is exactly the growth the E2E measures.
async fn approve_and_release(
    client: &reqwest::Client,
    base_url: &str,
    user_code: &str,
    token: &str,
    via: &str,
) -> Result<bool> {
    let cookie = format!("session={token}; __Secure-session={token}");

    let ap = client
        .post(format!("{base_url}/transport/action/QR/approve"))
        .header("content-type", "application/json")
        .header("cookie", &cookie)
        // `release` asks the handler to drop this session as it finishes — it exists only to
        // authorise this one call, and deleting it from here cost a third round trip.
        .body(serde_json::json!({ "code": user_code, "via": via, "release": true }).to_string())
        .send()
        .await?;
    let ap_body: Value = serde_json::from_str(&ap.text().await?).unwrap_or(Value::Null);
    if ap_body.pointer("/data/ok").and_then(Value::as_bool) != Some(true) {
        let msg = ap_body.pointer("/error/message").and_then(Value::as_str).unwrap_or("approval refused");
        println!("  {} {}", crate::style::red("✗"), msg);
        // The server can only say the code is unknown or expired; it cannot know that five
        // minutes passed while someone waited for mail. Say the part it cannot, because the
        // recovery is different from every other failure here — run the command again, and
        // note that an emailed code is spent whether or not the approval landed.
        if msg.contains("expired") || msg.contains("unknown") {
            println!("  {}", crate::style::dim("the 5-minute sign-in window closed — run `auth login` again"));
        }
        println!();
        return Ok(false)
    }

    Ok(true)
}

/// credentials.json as raw JSON. Deliberately not session.rs's typed loader: this path
/// exists for a file whose token has already lapsed, and reads only what outlives it.
/// Whether the account this machine is signed in as has an authenticator. Absent means an
/// older credentials.json that predates the field — treated as "has one" for the same reason
/// `choose_method` does: offer a path that may well work rather than hide it.
pub(crate) fn totp_enabled() -> Option<bool> {
    read_credentials_json().ok()?.get("totp_enabled")?.as_bool()
}

fn read_credentials_json() -> Result<Value> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let raw = std::fs::read_to_string(format!("{home}/.config/neuralkit/credentials.json"))?;
    Ok(serde_json::from_str(&raw)?)
}

/// Ask the session we were just granted who it belongs to, and when it dies.
/// `expires` is the record's own absolute ms timestamp — storing the deadline rather than
/// a duration means the remaining time stays correct however long the file sits unread.
async fn resolve_session(client: &reqwest::Client, base_url: &str, token: &str) -> (Option<String>, Option<i64>, Option<bool>) {
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
            // The session projection already carries this, so knowing it costs no extra call.
            // D1 returns INTEGER as a NUMBER while the resolver's type says string, so read
            // every shape rather than comparing against one.
            v.pointer("/data/user/totp_enabled").map(|t| {
                t.as_i64().map(|n| n == 1).or_else(|| t.as_str().map(|s| s == "1")).or_else(|| t.as_bool()).unwrap_or(false)
            }),
        ),
        None => (None, None, None),
    }
}

/// A scannable QR, as terminal art. Shared because the device flow and TOTP enrolment need the
/// same thing pointed at different URIs — one at the approval page, one at an `otpauth://` URI.
///
/// Dense1x2 packs two vertical modules per character cell (▀▄█), so it renders at ~half the
/// width AND height of the full-block form while staying square and scannable — no stretched
/// modules.
pub(crate) fn qr_art(data: &str) -> Option<String> {
    let qr = qrcode::QrCode::new(data.as_bytes()).ok()?;
    Some(
        qr.render::<qrcode::render::unicode::Dense1x2>()
            .quiet_zone(true)
            .module_dimensions(1, 1)
            .build(),
    )
}

fn render_qr(base_url: &str, code: &str) {
    // /qr, not /passkey. The authorization screen is its own surface: it resolves the code
    // server-side, NAMES the machine that is waiting from what registerKey staged, and offers
    // only routes that need no typing — a button when already signed in, a biometric when this
    // phone holds a credential. /passkey is a test surface and stays one.
    let url = format!("{base_url}/qr?code={code}");
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

fn save_credentials(origin: &str, token: &str, user: &str, email: Option<&str>, expires: Option<i64>, kem_secret: &str, sign_key: Option<&str>, device_id: Option<&str>, totp_enabled: Option<bool>) -> Result<()> {
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
        // The server-minted registration id. Unlike the token it is not a secret and does
        // not expire — it names this machine's row for as long as the row exists.
        "device_id": device_id,
        // Which paths this account can actually offer next time. Recorded so the sign-in menu
        // lists only what will work — offering an authenticator code to someone who never
        // enrolled one is a dead end the machine could have known about.
        "totp_enabled": totp_enabled,
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

/// The OS environment this install runs in — "macos", "linux", "windows", or
/// "wsl:Ubuntu" when it is Linux hosted by Windows.
///
/// `std::env::consts::OS` is resolved at COMPILE time for the target, so a binary built for
/// linux and run under WSL reports plain "linux" — indistinguishable from a native machine,
/// which is precisely wrong when someone asks for help. `WSL_DISTRO_NAME` is set only by
/// WSL, names the distribution, and is the one signal that separates them.
///
/// Folded into `os` rather than given its own column: it IS the OS environment, the column
/// is free-form and client-claimed already, and a dedicated column would be empty on all
/// but a handful of rows. Bounded to fit the field's 32-char limit.
pub(crate) fn os_label() -> String {
    // WSL first: it is Linux, and /etc/os-release below would answer "ubuntu" without
    // saying that Windows is hosting it — which is the part that changes the answer.
    if let Ok(distro) = std::env::var("WSL_DISTRO_NAME") {
        let distro = distro.trim();
        if !distro.is_empty() {
            return truncate(&format!("wsl:{distro}"), 32)
        }
    }
    // Linux: /etc/os-release is the freedesktop standard and present on every modern
    // distro. A plain file read — no subprocess, no crate, and it answers "ubuntu 24.04"
    // where consts::OS only ever says "linux".
    if std::env::consts::OS == "linux" {
        if let Ok(text) = std::fs::read_to_string("/etc/os-release") {
            let field = |key: &str| {
                text.lines()
                    .find_map(|l| l.strip_prefix(key))
                    .map(|v| v.trim_matches(['"', '\'']).trim().to_string())
                    .filter(|v| !v.is_empty())
            };
            if let Some(id) = field("ID=") {
                return match field("VERSION_ID=") {
                    Some(ver) => truncate(&format!("{id} {ver}"), 32),
                    None => truncate(&id, 32),
                }
            }
        }
    }
    // macOS keeps no os-release file, so the version costs a subprocess. Paid once at
    // login, which is not a hot path — and "macos 15.2" is the difference between a
    // support answer and a guess. Best-effort: a missing or unreadable sw_vers falls
    // through to the bare family name rather than failing a login over a label.
    if std::env::consts::OS == "macos" {
        if let Some(v) = first_line("sw_vers", &["-productVersion"]) {
            return truncate(&format!("macos {v}"), 32)
        }
    }
    // Windows stays the bare family name: its version needs `wmic`/`ver` parsing that
    // varies by shell and edition, for a value nothing yet reads.
    std::env::consts::OS.to_string()
}

/// First trimmed line of a command's stdout, or None if it cannot run. Every caller here
/// is decorating a label, so a failure must never propagate.
fn first_line(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    let s = String::from_utf8(out.stdout).ok()?;
    let line = s.lines().next()?.trim().to_string();
    (!line.is_empty()).then_some(line)
}

/// Byte-safe truncation for the label fields, which the fence bounds. Cuts on a char
/// boundary so a multi-byte distro name cannot panic the slice.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string()
    }
    let end = (0..=max).rev().find(|i| s.is_char_boundary(*i)).unwrap_or(0);
    s[..end].to_string()
}

/// What is driving this session — iTerm.app, vscode, tmux, xterm-256color.
///
/// A multiplexer is checked FIRST and wins: inside tmux the outer terminal is still named
/// in `TERM_PROGRAM`, but the multiplexer is the environment the session actually lives in,
/// and it is what survives a detach. `TERM` is the last resort because it describes a
/// capability set rather than an application.
///
/// Every source here is an environment variable, so this is a claim like the hostname —
/// context for someone reading a device list, never something to decide on.
pub(crate) fn terminal_type() -> String {
    if std::env::var_os("TMUX").is_some() {
        return "tmux".to_string()
    }
    for key in ["TERM_PROGRAM", "TERM"] {
        if let Ok(v) = std::env::var(key) {
            if !v.trim().is_empty() {
                return v.trim().to_string()
            }
        }
    }
    String::new()
}

/// This machine's name, for the device list. Best-effort and cosmetic: `HOSTNAME` is not
/// exported by every shell, so `hostname(1)` is the fallback, and an empty label is fine.
pub(crate) fn hostname() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        if !h.trim().is_empty() {
            return h.trim().to_string()
        }
    }
    first_line("hostname", &[]).unwrap_or_default()
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
