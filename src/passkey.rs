//! `neuralkit auth passkey` — this machine's own credential, created and used with no browser.
//!
//! WHAT THIS IS FOR. Today a CLI session is always DERIVED: the QR flow needs a browser to
//! authenticate first, so the terminal can only ever receive a token some other session minted.
//! A key held here changes the direction — the machine can PROVE something, which is what an
//! authenticator does. This command is the first half of that: mint the key, and show that an
//! assertion made with it satisfies the same verifier the server runs.
//!
//! WHY IT IS A SEPARATE FILE FROM credentials.json, and this is the important part. That file
//! is deleted on logout, on expiry, and by `auth unregister` — it holds a SESSION. A credential
//! that died with a session would have to be re-registered on every sign-in, which is exactly
//! what having a credential is supposed to stop. So the key lives in its own file, outlives
//! every session, and only `auth unregister` removes it.
//!
//! WHY A SOFTWARE KEY, FOR NOW. `phaze_auth::enclave` holds the key in hardware, and it works —
//! but persisting a Secure Enclave key needs the binary signed and carrying a provisioning
//! profile inside an `.app`, which `cargo run` does not produce. The key here is an ordinary
//! in-process P-256 key, the same class of secret as the ML-KEM secret this CLI already keeps
//! beside its token. Swapping in the enclave later changes which `Signer` is constructed and
//! nothing else — everything below is written against the trait.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use phaze_auth::authenticator::{assert, attestation_object, client_data, cose_key, Signer, SoftwareKey};
use phaze_auth::webauthn::{verify_assertion, AssertionInput};
use serde_json::Value;
use std::io::Write as _;

/// Where the credential lives. Deliberately NOT `credentials.json` — see the module header.
fn path() -> Result<String> {
    let home = std::env::var("HOME").context("HOME not set")?;
    Ok(format!("{home}/.config/neuralkit/passkey.json"))
}

/// This machine's key, minted on first use. Returns whether it had to be created, because the
/// caller says something different in each case and only one of them is news.
pub fn load_or_create() -> Result<(SoftwareKey, bool)> {
    let path = path()?;
    if let Ok(raw) = std::fs::read_to_string(&path) {
        let v: Value = serde_json::from_str(&raw).context("passkey.json is not JSON")?;
        let hex = v
            .get("key")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("passkey.json is missing `key` — delete it and register again"))?;
        let bytes = decode_hex(hex)?;
        let key = SoftwareKey::from_bytes(&bytes).map_err(|e| anyhow!("passkey.json holds an invalid key: {e}"))?;
        return Ok((key, false));
    }

    let key = SoftwareKey::generate();
    save(&key)?;
    Ok((key, true))
}

/// 0600 at CREATE time, not chmod'd afterwards — a plain write lands 0644 under the usual
/// umask, and fixing it after the fact leaves a window where the private key is readable.
/// Directory 0700 for the same reason. This is the same treatment `credentials.json` gets, and
/// for a stronger reason: a session token expires, this does not.
fn save(key: &SoftwareKey) -> Result<()> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let dir = format!("{home}/.config/neuralkit");
    std::fs::create_dir_all(&dir)?;
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "key": encode_hex(&key.to_bytes()),
        "created_at": chrono::Local::now().to_rfc3339(),
    }))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        opts.mode(0o600);
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    opts.open(path()?)?.write_all(body.as_bytes())?;
    Ok(())
}

/// Tell the server to forget this machine — delete its device row and its credential.
///
/// SERVER FIRST, DISK SECOND, the ordering the rest of `unregister` already follows: the ids
/// live in the files this is about to delete, so removing them first would leave rows nothing
/// can ever name again. Both ids are claims scoped server-side by `user_id`, so a stale one
/// deletes nothing rather than someone else's row.
///
/// Best-effort by design. An expired session cannot revoke, and reaching a clean local state
/// after an expiry is the main reason this command exists — so a refusal must not block the
/// delete. The cost of that is an orphaned row, which is strictly better than a machine that
/// cannot forget itself.
pub(crate) async fn revoke(base_url: &str, token: &str) -> Result<(u64, u64)> {
    let base_url = base_url.trim_end_matches('/');
    let mut body = serde_json::Map::new();
    if let Some(id) = device_id() {
        body.insert("deviceId".into(), Value::String(id));
    }
    if let Some(c) = read_credential_id()? {
        body.insert("credentialId".into(), Value::String(URL_SAFE_NO_PAD.encode(c)));
    }
    if body.is_empty() {
        return Ok((0, 0))
    }
    let res = http(base_url)?
        .post(format!("{base_url}/transport/action/Cli/unregister"))
        .header("content-type", "application/json")
        .header("cookie", format!("session={token}; __Secure-session={token}"))
        .body(Value::Object(body).to_string())
        .send()
        .await?;
    let v: Value = serde_json::from_str(&res.text().await?).unwrap_or(Value::Null);
    if let Some(m) = v.pointer("/error/message").and_then(Value::as_str) {
        return Err(anyhow!("{m}"))
    }
    Ok((
        v.pointer("/data/devices").and_then(Value::as_u64).unwrap_or(0),
        v.pointer("/data/credentials").and_then(Value::as_u64).unwrap_or(0),
    ))
}

/// The server-minted id naming this machine's `cli_devices` row.
///
/// IT LIVES HERE, NOT IN credentials.json, and that placement is the whole point: the session
/// file is deleted on logout and on expiry, so an id kept there is lost the moment a session
/// ends — and the next sign-in, having nothing to claim, registers the SAME machine as a new
/// device. Measured: a passkey login at 11:39, expiry at 11:49, a QR login at 11:56, two rows.
/// Not a secret and not expiring; it names a row, so it belongs with the credential that
/// outlives sessions rather than the token that does not.
pub(crate) fn save_device_id(device_id: &str) -> Result<()> {
    let path = path()?;
    let Ok(raw) = std::fs::read_to_string(&path) else { return Ok(()) };
    let mut v: Value = serde_json::from_str(&raw)?;
    v["device_id"] = Value::String(device_id.to_string());
    std::fs::write(&path, serde_json::to_string_pretty(&v)?)?;
    Ok(())
}

pub(crate) fn device_id() -> Option<String> {
    let raw = std::fs::read_to_string(path().ok()?).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    v.get("device_id").and_then(Value::as_str).filter(|s| !s.is_empty()).map(String::from)
}

/// Whether this machine holds a credential at all. Cheap, and the caller needs it BEFORE
/// deleting so it can say which of the two things it removed.
pub fn exists() -> bool {
    path().map(|p| std::fs::metadata(p).is_ok()).unwrap_or(false)
}

/// Remove this machine's credential. Called by `auth unregister`, which is the command that
/// means "forget this machine" — logout only ends a session and deliberately leaves this alone.
pub fn forget() -> Result<()> {
    match std::fs::remove_file(path()?) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(anyhow!("could not remove the passkey: {e}")),
    }
}

/// `neuralkit auth passkey` — show this machine's credential, and prove it works.
///
/// The self-test is not decoration. It runs the SAME `verify_assertion` the server calls
/// through `rpc_passkey_login_verify`, so a pass here means the bytes this machine produces are
/// bytes the server already knows how to check — no new server code, and no guessing about
/// formats. A failure is therefore a real problem, not a test artifact.
pub fn run(url: &str) -> Result<()> {
    let rp_id = url_host(url)?;
    let origin = url.trim_end_matches('/').to_string();

    let (key, created) = load_or_create()?;
    let cose = cose_key(&key).map_err(|e| anyhow!("COSE_Key: {e}"))?;

    println!();
    println!("  {} {}", crate::style::bold("neuralkit"), crate::style::dim("· native passkey"));
    println!();
    println!(
        "  {}  {}",
        crate::style::dim(&format!("{:<13}", "credential")),
        if created { crate::style::green("created") } else { crate::style::dim("existing") },
    );
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "held by")), crate::style::dim(key.describe()));
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "public key")), crate::style::dim(&short(&cose)));
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "server")), crate::style::dim(&rp_id));

    // A server-issued challenge is what a real login signs; this one is local, which is why
    // this proves the FORMAT and not freshness. Freshness is the server's KV challenge record.
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| anyhow!("rng: {e}"))?;
    let challenge = URL_SAFE_NO_PAD.encode(raw);

    let a = assert(&key, &rp_id, &origin, &challenge, 0).map_err(|e| anyhow!("assert: {e}"))?;
    println!(
        "  {}  {}",
        crate::style::dim(&format!("{:<13}", "assertion")),
        crate::style::dim(&format!(
            "authData {} B · clientData {} B · signature {} B DER",
            a.authenticator_data.len(),
            a.client_data_json.len(),
            a.signature.len(),
        )),
    );

    match verify_assertion(AssertionInput {
        credential_public_key: &cose,
        authenticator_data: &a.authenticator_data,
        client_data_json: &a.client_data_json,
        signature: &a.signature,
        expected_challenge_b64url: &challenge,
        expected_origin: &origin,
        expected_rp_id: &rp_id,
        stored_sign_count: 0,
    }) {
        Ok(_) => {
            println!();
            println!("  {} {}", crate::style::green("✓"), "verified — the same check the server runs");
        }
        Err(e) => {
            println!();
            println!("  {} verification failed: {e}", crate::style::red("✗"));
            return Err(anyhow!("the assertion did not verify"));
        }
    }

    // Say plainly what this does NOT yet do, so nobody reads a passing self-test as a
    // working login. Registering the public half needs a fence that does not exist.
    println!("  {}", crate::style::dim("not yet registered with the server — that surface is still to build"));
    println!();
    Ok(())
}

/// The `rp_id` is the HOST, never the origin — WebAuthn hashes it into authenticatorData and
/// the server compares against its own hostname, so a scheme or port here fails the check.
fn url_host(url: &str) -> Result<String> {
    let s = url.trim_end_matches('/');
    let rest = s.split_once("://").map(|(_, r)| r).unwrap_or(s);
    let host = rest.split(['/', ':']).next().unwrap_or("");
    if host.is_empty() {
        return Err(anyhow!("could not read a host out of `{url}`"));
    }
    Ok(host.to_string())
}

fn short(bytes: &[u8]) -> String {
    let head: String = bytes.iter().take(6).map(|b| format!("{b:02x}")).collect();
    let tail: String = bytes.iter().rev().take(4).rev().map(|b| format!("{b:02x}")).collect();
    format!("{head}…{tail} ({} B COSE_Key)", bytes.len())
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(anyhow!("key is not valid hex"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| anyhow!("key is not valid hex: {e}")))
        .collect()
}


// ── talking to the server ──────────────────────────────────────────────
//
// SCENARIO A, UNDER TEST: register through the EXISTING Passkey.* fences rather than adding
// native ones. The server never learns this key is native — it parses the same
// attestationObject and verifies the same assertion a browser produces. Whether that is the
// right home for a MACHINE credential is the open question these calls exist to answer, by
// showing what actually lands in the database.

pub(crate) fn http(base_url: &str) -> Result<reqwest::Client> {
    let insecure = base_url.contains("127.0.0.1") || base_url.contains("localhost");
    Ok(reqwest::Client::builder().danger_accept_invalid_certs(insecure).build()?)
}

/// The session this machine already holds. Registration needs one: `registerStart` binds the
/// ceremony to whoever is signed in AT THAT MOMENT, and with no session it would mint a fresh
/// unrelated account instead of attaching to yours.
pub(crate) fn session_token() -> Result<String> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let raw = std::fs::read_to_string(format!("{home}/.config/neuralkit/credentials.json"))
        .context("not signed in — run `neuralkit auth login` first")?;
    let v: Value = serde_json::from_str(&raw)?;
    v.get("token")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
        .map(String::from)
        .ok_or_else(|| anyhow!("credentials.json holds no token — sign in again"))
}

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Register this machine's key with the server, from an existing session.
pub async fn register(base_url: &str, quiet: bool) -> Result<()> {
    let base_url = base_url.trim_end_matches('/');
    let origin = base_url.to_string();
    let token = session_token()?;
    let cookie = format!("session={token}; __Secure-session={token}");
    let client = http(base_url)?;
    let (key, _) = load_or_create()?;

    if !quiet {
        println!();
        println!("  {} {}", crate::style::bold("neuralkit"), crate::style::dim("· registering this machine's passkey"));
    }

    // 1. A challenge, bound server-side to the account this session belongs to.
    let start: Value = serde_json::from_str(
        &client
            .post(format!("{base_url}/transport/action/Passkey/registerStart"))
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .body("{}")
            .send()
            .await?
            .text()
            .await?,
    )?;
    if let Some(m) = start.pointer("/error/message").and_then(Value::as_str) {
        return Err(anyhow!("registerStart: {m}"))
    }
    let challenge = start
        .pointer("/data/challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("registerStart returned no challenge: {start}"))?;
    let rp_id = start
        .pointer("/data/rp/id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("registerStart returned no rp.id"))?;
    if !quiet {
        println!("  {}  {}", crate::style::dim(&format!("{:<13}", "challenge")), crate::style::dim("issued"));
    }

    // 2. A credential id of our own — the server stores whatever we put in the attestation.
    let mut cred_id = [0u8; 16];
    getrandom::getrandom(&mut cred_id).map_err(|e| anyhow!("rng: {e}"))?;
    let reg = attestation_object(&key, rp_id, &cred_id).map_err(|e| anyhow!("attestationObject: {e}"))?;
    let cdj = client_data("webauthn.create", challenge, &origin).map_err(|e| anyhow!("clientDataJSON: {e}"))?;

    // 3. The same request a browser sends. `transports` is EMPTY and that is the honest value:
    //    the column holds WebAuthn's AuthenticatorTransport set — ble/hybrid/internal/nfc/usb,
    //    what `getTransports()` returns — and it describes how a BROWSER reaches an
    //    authenticator. No browser can reach this one, so it has none. Identification is the
    //    `aaguid`'s job, which is the field WebAuthn already has for naming an authenticator
    //    model, and the attestation carries ours.
    let finish_res = client
            .post(format!("{base_url}/transport/action/Passkey/registerFinish"))
            .header("content-type", "application/json")
            .header("cookie", &cookie)
            .body(
                serde_json::json!({
                    "id": b64(&reg.credential_id),
                    "attestationObject": b64(&reg.attestation_object),
                    "clientDataJSON": b64(&cdj),
                    "transports": [],
                })
                .to_string(),
            )
            .send()
            .await?;
    // registerFinish declares `mint: [session]`, so a successful registration hands back a
    // SECOND session. The caller already holds the one it wants — the one QR.approve
    // minted, which has this install's key promoted onto it — so this one is released rather
    // than kept, the same discipline the authenticator-code path follows.
    let minted = session_cookie(&finish_res);
    let finish: Value = serde_json::from_str(&finish_res.text().await?)?;
    if let Some(m) = finish.pointer("/error/message").and_then(Value::as_str) {
        return Err(anyhow!("registerFinish: {m}"))
    }
    let user_id = finish.pointer("/data/userId").and_then(Value::as_str).unwrap_or("").to_string();
    if let Some(t) = minted {
        let _ = client
            .post(format!("{base_url}/transport/action/Session/delete"))
            .header("cookie", format!("session={t}; __Secure-session={t}"))
            .send()
            .await;
    }

    save_credential_id(&reg.credential_id)?;
    if !quiet {
        println!("  {}  {}", crate::style::dim(&format!("{:<13}", "credential id")), crate::style::dim(&b64(&reg.credential_id)));
        println!("  {}  {}", crate::style::dim(&format!("{:<13}", "account")), crate::style::dim(&user_id));
        println!();
        println!("  {} registered — `auth login` can now use this machine's passkey", crate::style::green("✓"));
        println!();
    }
    Ok(())
}

/// Assert this machine's passkey and return the session token it mints.
///
/// Split out from `login` because the CLI needs the TOKEN, not a report: a native login is the
/// third way to supply an approving session to the device flow, exactly as an authenticator
/// code is. Everything downstream — the mint, the key promotion, the sealed channel — stays
/// the path that already works.
pub async fn assert_session(base_url: &str) -> Result<String> {
    let base_url = base_url.trim_end_matches('/');
    let origin = base_url.to_string();
    let client = http(base_url)?;
    let (key, created) = load_or_create()?;
    if created {
        return Err(anyhow!("this machine has no passkey yet"))
    }
    let cred_id = read_credential_id()?.ok_or_else(|| anyhow!("this machine's passkey is not registered"))?;

    let start: Value = serde_json::from_str(
        &client
            .post(format!("{base_url}/transport/action/Passkey/loginStart"))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await?
            .text()
            .await?,
    )?;
    if let Some(m) = start.pointer("/error/message").and_then(Value::as_str) {
        return Err(anyhow!("loginStart: {m}"))
    }
    let challenge = start
        .pointer("/data/challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("loginStart returned no challenge"))?;
    let rp_id = start.pointer("/data/rpId").and_then(Value::as_str).unwrap_or_default().to_string();

    let a = assert(&key, &rp_id, &origin, challenge, 0).map_err(|e| anyhow!("assert: {e}"))?;
    let res = client
        .post(format!("{base_url}/transport/action/Passkey/loginFinish"))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "id": b64(&cred_id),
                "authenticatorData": b64(&a.authenticator_data),
                "clientDataJSON": b64(&a.client_data_json),
                "signature": b64(&a.signature),
            })
            .to_string(),
        )
        .send()
        .await?;
    let token = session_cookie(&res);
    let body: Value = serde_json::from_str(&res.text().await?).unwrap_or(Value::Null);
    if let Some(m) = body.pointer("/error/message").and_then(Value::as_str) {
        return Err(anyhow!("{m}"))
    }
    token.filter(|t| !t.is_empty()).ok_or_else(|| anyhow!("no session cookie came back"))
}

/// Whether this machine holds a passkey the server already knows about.
pub fn is_registered() -> bool {
    read_credential_id().ok().flatten().is_some()
}

fn session_cookie(res: &reqwest::Response) -> Option<String> {
    res.headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find_map(|c| {
            let (name, rest) = c.split_once('=')?;
            matches!(name.trim(), "session" | "__Secure-session")
                .then(|| rest.split(';').next().unwrap_or("").to_string())
        })
}

/// Sign in with this machine's key. No browser, no phone, no code.
pub async fn login(base_url: &str) -> Result<()> {
    let base_url = base_url.trim_end_matches('/');
    let origin = base_url.to_string();
    let client = http(base_url)?;
    let (key, created) = load_or_create()?;
    if created {
        return Err(anyhow!("this machine has no registered passkey — run `neuralkit auth passkey register`"))
    }
    let cred_id = read_credential_id()?
        .ok_or_else(|| anyhow!("this machine's passkey is not registered — run `neuralkit auth passkey register`"))?;

    println!();
    println!("  {} {}", crate::style::bold("neuralkit"), crate::style::dim("· signing in with this machine's passkey"));

    // 1. A challenge. No session needed — this fence is the anonymous half of a login.
    let start: Value = serde_json::from_str(
        &client
            .post(format!("{base_url}/transport/action/Passkey/loginStart"))
            .header("content-type", "application/json")
            .body("{}")
            .send()
            .await?
            .text()
            .await?,
    )?;
    if let Some(m) = start.pointer("/error/message").and_then(Value::as_str) {
        return Err(anyhow!("loginStart: {m}"))
    }
    let challenge = start
        .pointer("/data/challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("loginStart returned no challenge"))?;
    let rp_id = start.pointer("/data/rpId").and_then(Value::as_str).unwrap_or_default().to_string();
    let offered = start.pointer("/data/allowCredentials").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0);
    println!(
        "  {}  {}",
        crate::style::dim(&format!("{:<13}", "challenge")),
        crate::style::dim(&format!("issued · {offered} credential(s) offered")),
    );

    // 2. Sign it — the same bytes a browser authenticator would produce.
    let a = assert(&key, &rp_id, &origin, challenge, 0).map_err(|e| anyhow!("assert: {e}"))?;

    // 3. The server verifies with the key it stored at registration and mints a session.
    let res = client
        .post(format!("{base_url}/transport/action/Passkey/loginFinish"))
        .header("content-type", "application/json")
        .body(
            serde_json::json!({
                "id": b64(&cred_id),
                "authenticatorData": b64(&a.authenticator_data),
                "clientDataJSON": b64(&a.client_data_json),
                "signature": b64(&a.signature),
            })
            .to_string(),
        )
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
    if let Some(m) = body.pointer("/error/message").and_then(Value::as_str) {
        return Err(anyhow!("loginFinish: {m}"))
    }
    let Some(token) = token.filter(|t| !t.is_empty()) else {
        return Err(anyhow!("no session cookie came back: {body}"))
    };

    // Ask the session who it belongs to — the same way `auth login` does, so the answer comes
    // from the server rather than from anything this machine claimed.
    let who: Value = serde_json::from_str(
        &client
            .post(format!("{base_url}/transport/action/Session/request"))
            .header("cookie", format!("session={token}; __Secure-session={token}"))
            .send()
            .await?
            .text()
            .await?,
    )
    .unwrap_or(Value::Null);
    let email = who.pointer("/data/user/email").and_then(Value::as_str).unwrap_or("");

    println!();
    println!(
        "  {} signed in as {} {}",
        crate::style::green("✓"),
        crate::style::bold(if email.is_empty() { "(no address on the account)" } else { email }),
        crate::style::dim("· no browser, no phone"),
    );
    println!("  {}", crate::style::dim("session not saved — this run is a proof, not a login"));
    println!();
    Ok(())
}

/// The credential id the server knows this machine by. Kept beside the key: without it, the
/// key cannot be looked up at login even though it would still verify.
fn save_credential_id(cred_id: &[u8]) -> Result<()> {
    let path = path()?;
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    v["credential_id"] = Value::String(encode_hex(cred_id));
    std::fs::write(&path, serde_json::to_string_pretty(&v)?)?;
    Ok(())
}

fn read_credential_id() -> Result<Option<Vec<u8>>> {
    let Ok(raw) = std::fs::read_to_string(path()?) else { return Ok(None) };
    let v: Value = serde_json::from_str(&raw)?;
    match v.get("credential_id").and_then(Value::as_str) {
        Some(h) => Ok(Some(decode_hex(h)?)),
        None => Ok(None),
    }
}
