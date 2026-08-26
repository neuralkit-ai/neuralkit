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
/// The keychain label this machine's hardware key lives under. Stable, because the key is
/// found by it on every run — changing it strands the old key rather than migrating it.
#[cfg(target_os = "macos")]
const ENCLAVE_LABEL: &str = "neuralkit cli";

/// Whether this machine should hold its key in hardware, behind a human.
///
/// OPT-IN, and asked at USE. `capabilities()` is cheap and does not prompt, so the answer
/// reflects right now — a Watch off the wrist means no verification is available, and a gate
/// that could not be satisfied would lock someone out of their own terminal.
/// WHICH factor this machine's owner chose. A preference, stored per machine, because the
/// answer is hardware and taste at once — a MacBook owner may want Touch ID only, a Mac mini
/// owner has a Watch or a password and nothing else.
#[cfg(target_os = "macos")]
fn stored_gate() -> Option<phaze_auth::enclave::Gate> {
    use phaze_auth::enclave::Gate;
    if std::env::var_os("NEURALKIT_ENCLAVE").is_some() {
        return Some(Gate::BiometryOrWatch)
    }
    let raw = std::fs::read_to_string(path().ok()?).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    match v.get("gate")?.as_str()? {
        "biometry_or_watch" => Some(Gate::BiometryOrWatch),
        "user_presence" => Some(Gate::UserPresence),
        "device_passcode" => Some(Gate::DevicePasscode),
        _ => None,
    }
}

/// Whether a hardware gate is CHOSEN on this machine — nothing about whether it can be
/// satisfied right now. The sign-in menu reads this to decide if a refused machine key
/// deserves a "connect to Apple Watch" retry row: a gated refusal is usually the Watch
/// situation of the moment; an ungated one is a revoked credential, where retrying only
/// invites the same failure.
pub(crate) fn gate_armed() -> bool {
    #[cfg(target_os = "macos")]
    {
        stored_gate().is_some()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// The chosen factor, IF this Mac can still satisfy it right now. Asked at use — a Watch off
/// the wrist is not available, and a gate that cannot be met would lock someone out of their
/// own terminal rather than protect it.
/// `Ok(None)` = no gate chosen, use the software key. `Err` = a gate WAS chosen and cannot be
/// satisfied right now.
///
/// REFUSING BEATS FALLING BACK, and the reason is not purity. Silently dropping to a software
/// key would MINT A NEW KEY the server has never seen, so the sign-in fails later with a
/// credential error that says nothing about a Watch being off a wrist. Worse, a machine that
/// asked for hardware protection would quietly stop having it. The honest failure names the
/// thing that is missing and the two ways out.
#[cfg(target_os = "macos")]
fn enclave_gate() -> Result<Option<phaze_auth::enclave::Gate>> {
    use phaze_auth::enclave::Gate;
    let Some(gate) = stored_gate() else { return Ok(None) };
    let c = phaze_auth::enclave::capabilities().unwrap_or_default();
    let usable = match gate {
        Gate::BiometryOrWatch => c.biometrics_or_watch,
        Gate::UserPresence | Gate::DevicePasscode => c.device_owner,
        _ => false,
    };
    if usable {
        return Ok(Some(gate))
    }
    Err(anyhow!(
        "{}\n  {}\n  {}",
        if matches!(gate, Gate::BiometryOrWatch) && !c.biometrics {
            "your Apple Watch isn't available — this machine's key won't sign without it"
        } else {
            "this Mac can't verify a person right now — its key won't sign without that"
        },
        "put it on, unlock it, and keep it near this Mac — then try again",
        "or unset the `gate` field in ~/.config/neuralkit/passkey.json to use the software key",
    ))
}

/// This machine's key. Hardware-held behind a human when that is asked for and available,
/// otherwise the software key that works everywhere.
///
/// Returns a trait object because the two backends are interchangeable BELOW this line and
/// nothing above it should know which one answered — the only visible difference is that a
/// gated key reports `user_verified() == true`, which is a fact the server reads rather than
/// something the caller asserts.
pub fn load_or_create() -> Result<(Box<dyn Signer>, bool)> {
    #[cfg(target_os = "macos")]
    if let Some(gate) = enclave_gate()? {
        use phaze_auth::enclave::{Key, Storage};
        let existed = Key::find(ENCLAVE_LABEL).ok().flatten().is_some();
        let key = Key::find_or_create_with_prompt(
            ENCLAVE_LABEL,
            Storage::Enclave,
            gate,
            "authorize this terminal",
        )
        .map_err(|e| anyhow!("hardware key: {e}"))?;
        // passkey.json still exists on this path — it holds credential_id, device_id and
        // next_challenge, none of which are secrets and all of which must outlive a session.
        // What changes is that `key` is ABSENT: the private half is in the enclave, where
        // nothing can read it, including us.
        ensure_metadata_file()?;
        return Ok((Box::new(key), !existed))
    }
    let (key, created) = load_or_create_software()?;
    Ok((Box::new(key), created))
}

/// Create passkey.json without a key in it, for the hardware path. Same 0600 at create time
/// as `save`, for a weaker reason — nothing here is secret — but the file is the same file and
/// a second permission story would be one to get wrong later.
#[cfg(target_os = "macos")]
fn ensure_metadata_file() -> Result<()> {
    let path = path()?;
    if std::fs::metadata(&path).is_ok() {
        return Ok(())
    }
    let home = std::env::var("HOME").context("HOME not set")?;
    let dir = format!("{home}/.config/neuralkit");
    std::fs::create_dir_all(&dir)?;
    let body = serde_json::to_string_pretty(&serde_json::json!({
        "gate": "user_presence",
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
    opts.open(&path)?.write_all(body.as_bytes())?;
    Ok(())
}

/// Record that this machine wants its key in hardware, behind a human. Written to the same
/// file the credential id lives in, so "forget this machine" still removes the choice with it.
#[cfg(target_os = "macos")]
pub(crate) fn set_gate(choice: Option<&str>) -> Result<()> {
    ensure_metadata_file()?;
    let path = path()?;
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    match choice {
        Some(g) => { v["gate"] = Value::String(g.into()); }
        None => { v.as_object_mut().map(|o| o.remove("gate")); }
    }
    std::fs::write(&path, serde_json::to_string_pretty(&v)?)?;
    Ok(())
}

fn load_or_create_software() -> Result<(SoftwareKey, bool)> {
    let path = path()?;
    if let Ok(raw) = std::fs::read_to_string(&path) {
        let v: Value = serde_json::from_str(&raw).context("passkey.json is not JSON")?;
        // A KEYLESS FILE IS NORMAL, not corruption. `ensure_metadata_file` writes exactly that for
        // the hardware path — the private half is in the enclave, so there is nothing to record —
        // which means "the file exists" never implied "a key is in it". `presence --off` is when
        // that meets this function: the gate is gone, the enclave is no longer chosen, and the
        // software path finds a file it did not write. Erroring here made that command promise a
        // fallback it could not deliver, and the advice it gave — delete the file — would take
        // device_id and next_challenge with it.
        if let Some(hex) = v.get("key").and_then(Value::as_str) {
            let bytes = decode_hex(hex)?;
            let key = SoftwareKey::from_bytes(&bytes).map_err(|e| anyhow!("passkey.json holds an invalid key: {e}"))?;
            return Ok((key, false));
        }
        let key = SoftwareKey::generate();
        save(&key)?;
        return Ok((key, true));
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
    // MERGE, NEVER REPLACE. This file also carries device_id and next_challenge — the machine's
    // registration and its one-call shortcut. Truncating would silently unregister the machine:
    // the next login would find no id to claim and enrol a SECOND device row beside the live one.
    //
    // AND DROP credential_id, because this function only runs when a key was just MINTED. The
    // credential registered against the previous key cannot be signed for any more, so keeping
    // its id would leave `is_registered()` true, the login skipping re-registration, and every
    // assertion failing verification server-side with nothing to say why.
    let mut v: Value = std::fs::read_to_string(path()?)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    if let Some(o) = v.as_object_mut() {
        o.remove("credential_id");
    }
    v["key"] = Value::String(encode_hex(&key.to_bytes()));
    v["created_at"] = Value::String(chrono::Local::now().to_rfc3339());
    let body = serde_json::to_string_pretty(&v)?;
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

/// The challenge the server handed this machine on its way out of the last sign-in.
///
/// STORED BESIDE THE KEY, not with the session, for the same reason the credential is: a session
/// dies and this must not, or the machine would fall back to the long flow after every expiry —
/// which is exactly the cost it exists to remove. Single-use server-side; a spent or lapsed one
/// simply means the fast path is skipped this run.
pub(crate) fn save_next_challenge(challenge: &str) -> Result<()> {
    let path = path()?;
    let Ok(raw) = std::fs::read_to_string(&path) else { return Ok(()) };
    let mut v: Value = serde_json::from_str(&raw)?;
    v["next_challenge"] = Value::String(challenge.to_string());
    std::fs::write(&path, serde_json::to_string_pretty(&v)?)?;
    Ok(())
}

pub(crate) fn next_challenge() -> Option<String> {
    let raw = std::fs::read_to_string(path().ok()?).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    v.get("next_challenge").and_then(Value::as_str).filter(|s| !s.is_empty()).map(String::from)
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
    // THE PREFERENCE OUTLIVES THE CREDENTIAL. `unregister` means "forget this machine", not
    // "go back to a software key" — and since the gate marker shares a file with the credential,
    // deleting the file silently downgraded the machine's security posture. Measured: presence
    // was turned on, `unregister` ran, and the next sign-in minted a software key with no
    // prompt. A credential is a thing you revoke; a policy is a thing you chose.
    #[cfg(target_os = "macos")]
    let gated = stored_gate_name();

    // The hardware key goes too. It is this machine's credential just as the file was, and
    // leaving it behind means a later run silently adopts a key the server no longer knows —
    // `find_or_create` would FIND it and never mint a fresh one.
    #[cfg(target_os = "macos")]
    let _ = phaze_auth::enclave::Key::delete(ENCLAVE_LABEL);

    match std::fs::remove_file(path()?) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        Err(e) => return Err(anyhow!("could not remove the passkey: {e}")),
    }

    #[cfg(target_os = "macos")]
    if let Some(g) = gated {
        set_gate(Some(&g))?;
    }
    Ok(())
}

/// Whether this machine ASKED for a hardware-held key — read from the file, unlike
/// `enclave_wanted()` which also asks the OS. Here only the choice matters.
#[cfg(target_os = "macos")]
fn stored_gate_name() -> Option<String> {
    let raw = std::fs::read_to_string(path().ok()?).ok()?;
    let v: Value = serde_json::from_str(&raw).ok()?;
    Some(v.get("gate")?.as_str()?.to_string())
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
    let cose = cose_key(&*key).map_err(|e| anyhow!("COSE_Key: {e}"))?;

    println!();
    println!("  {} {}", crate::style::bold("neuralkit"), crate::style::dim("· native passkey"));
    println!();
    println!(
        "  {}  {}",
        crate::style::dim(&format!("{:<13}", "credential")),
        if created { crate::style::green("created") } else { crate::style::dim("existing") },
    );
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "held by")), crate::style::dim(key.describe()));
    // WHAT THIS MAC CAN VERIFY A HUMAN WITH, asked at USE rather than cached — whether a paired
    // Watch can answer depends on it being worn, unlocked and in range right now. The OS picks
    // between Touch ID, a Watch and the account password, which is why the gate is declared as
    // "verify the human" and never as "use Touch ID": a desktop with no sensor still has an
    // answer, and naming a mechanism would report nothing on hardware that can do better.
    #[cfg(target_os = "macos")]
    if let Ok(c) = phaze_auth::enclave::capabilities() {
        let how = if c.biometrics { "Touch ID" }
            else if c.watch { "a paired Apple Watch" }
            else if c.device_owner { "your account password" }
            else { "nothing — no user verification available here" };
        println!("  {}  {}", crate::style::dim(&format!("{:<13}", "verified by")), crate::style::dim(how));
    }
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "public key")), crate::style::dim(&short(&cose)));
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "server")), crate::style::dim(&rp_id));

    // A server-issued challenge is what a real login signs; this one is local, which is why
    // this proves the FORMAT and not freshness. Freshness is the server's KV challenge record.
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| anyhow!("rng: {e}"))?;
    let challenge = URL_SAFE_NO_PAD.encode(raw);

    let a = assert(&*key, &rp_id, &origin, &challenge, 0).map_err(|e| anyhow!("assert: {e}"))?;
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
    let reg = attestation_object(&*key, rp_id, &cred_id).map_err(|e| anyhow!("attestationObject: {e}"))?;
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

    let a = assert(&*key, &rp_id, &origin, challenge, 0).map_err(|e| anyhow!("assert: {e}"))?;
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
    let a = assert(&*key, &rp_id, &origin, challenge, 0).map_err(|e| anyhow!("assert: {e}"))?;

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

/// `Cli.login` — the whole sign-in in ONE request, for a machine the server already knows.
///
/// WHAT IT SKIPS, and why that is the point: the device flow (stage a key, hold a stream, draw a
/// user_code, have something approve it) exists so a SECOND device can do the approving. A
/// machine holding its own passkey is authenticating and enrolling ITSELF, so all of that is
/// ceremony it does not need — four round trips spent borrowing a phone's protocol.
///
/// It can sign before it speaks because the server handed it a challenge on the way out of the
/// last sign-in. Everything else — the assertion, the session, the device row, the ML-KEM key —
/// happens inside the one handler.
///
/// RETURNS Ok(None) WHEN THE FAST PATH SIMPLY DOES NOT APPLY (no challenge stored, no device id,
/// no credential yet) so the caller falls through to the full flow. Err is reserved for a request
/// that was made and refused, which the caller also treats as "fall back" — a machine must never
/// be left unable to sign in because its shortcut failed.
pub(crate) async fn quick_login(
    base_url: &str,
    kem_pk_hex: &str,
) -> Result<Option<(String, Value)>> {
    let base_url = base_url.trim_end_matches('/');
    let (Some(device_id), Some(challenge)) = (device_id(), next_challenge()) else { return Ok(None) };
    let Some(cred_id) = read_credential_id()? else { return Ok(None) };
    let (key, created) = load_or_create()?;
    if created { return Ok(None) }

    // The device_code is fresh per run — it keys nothing durable here (the row is named by
    // device_id), but `enrollMachine` still deletes a staging key by it, so it must be present.
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| anyhow!("rng: {e}"))?;
    let device_code: String = raw.iter().map(|b| format!("{b:02x}")).collect();

    let a = assert(&*key, &url_host(base_url)?, base_url, &challenge, 0).map_err(|e| anyhow!("assert: {e}"))?;
    // Bound rather than built inline, because the token fetch below rides the SAME client — a
    // second one would negotiate its own TLS for one small GET.
    let client = http(base_url)?;
    let fp = crate::fingerprint::value(&client, base_url).await;
    let res = client
        .post(format!("{base_url}/transport/action/Cli/login"))
        .header("content-type", "application/json")
        .body(serde_json::json!({
            "deviceId": device_id,
            "device":   device_code,
            "pk":       kem_pk_hex,
            "label":    crate::login::hostname(),
            "os":       crate::login::os_label(),
            "terminal": crate::login::terminal_type(),
            // The one-call path never stages, so without this a machine that only ever takes it
            // would never record one. Null when absent — the fence is nullish and fails open.
            "fingerprint": fp,
            "id":                b64(&cred_id),
            "authenticatorData": b64(&a.authenticator_data),
            "clientDataJSON":    b64(&a.client_data_json),
            "signature":         b64(&a.signature),
        }).to_string())
        .send()
        .await?;
    let body: Value = serde_json::from_str(&res.text().await?).unwrap_or(Value::Null);
    if let Some(m) = body.pointer("/error/message").and_then(Value::as_str) {
        return Err(anyhow!("{m}"))
    }
    let Some(token) = body.pointer("/data/token").and_then(Value::as_str) else {
        return Err(anyhow!("no token came back"))
    };
    // The NEXT challenge, immediately — a run that forgot to store it would silently take the
    // long path forever after.
    if let Some(next) = body.pointer("/data/nextChallenge").and_then(Value::as_str) {
        save_next_challenge(next)?;
    }
    Ok(Some((token.to_string(), body.pointer("/data").cloned().unwrap_or(Value::Null))))
}

/// Choose what must happen before this machine's key signs. NOT wired to a command today.
///
/// A PREFERENCE, not a policy we impose: the answer is hardware and taste at once. A MacBook
/// owner may want Touch ID and nothing else; a Mac mini owner has a Watch, or a password, or
/// neither. So the menu offers only what THIS Mac can satisfy right now, read from
/// `capabilities()` — offering a factor that cannot be met would be a promise the machine
/// cannot keep, and the person only finds out when they are locked out of their own terminal.
#[cfg(target_os = "macos")]
// NOT WIRED TO A COMMAND (2026-08-03). The `auth passkey presence` subcommand is removed
// until the release can ship a signed `.app`: an access control on a persisted key needs
// `keychain-access-groups`, which needs a provisioning profile in a bundle, and the npm
// package is a bare binary. Left in place because the flow is PROVEN — the Watch prompted
// through NeuralkitCLI.app, and again 2026-08-03 through release/macos/bundle.sh — and
// re-deriving it would cost the Apple round trip again.
// The gate CAN still be stored without this command: the tray's checkbox (tray.rs) writes
// it through `set_gate`, and `NEURALKIT_ENCLAVE=1` forces it for a single run. Both are
// deliberate choices by someone holding the signed bundle; this MENU is what stays off
// until the npm binary can tell a bundled install from a bare one.
#[allow(dead_code)]
pub fn set_presence(off: bool) -> Result<()> {
    if off {
        set_gate(None)?;
        println!("\n  {} {}\n", crate::style::green("✓"), "back to the software key on the next sign-in");
        return Ok(())
    }

    let c = phaze_auth::enclave::capabilities().unwrap_or_default();
    let mut labels: Vec<String> = Vec::new();
    let mut keys: Vec<&str> = Vec::new();

    // NARROWEST FIRST. `UserPresence` is a cascade that ENDS at the login password and lets the
    // OS pick — measured: a Mac mini with a Watch in range raised a PASSWORD dialog. Naming the
    // factors is the only way to say "not the password", so it leads.
    if c.biometrics_or_watch {
        labels.push(format!(
            "{} — and never the password",
            if c.biometrics && c.watch { "Touch ID or my Apple Watch" }
            else if c.biometrics { "Touch ID" }
            else { "my Apple Watch" },
        ));
        keys.push("biometry_or_watch");
    }
    if c.device_owner {
        labels.push("whatever this Mac offers — including the login password".into());
        keys.push("user_presence");
        labels.push("the login password, always".into());
        keys.push("device_passcode");
    }
    if keys.is_empty() {
        return Err(anyhow!(
            "this Mac cannot verify a person right now — no Touch ID, no paired Watch in range, no password policy"
        ))
    }
    labels.push("nothing — keep the software key".into());
    keys.push("");

    let header = format!(
        "  {} {}",
        crate::style::bold("neuralkit"),
        crate::style::dim("· what should this machine ask for before it signs?"),
    );
    let owned = labels.clone();
    let picked = crate::login::select(&header, &owned.iter().map(String::as_str).collect::<Vec<_>>())?;
    let Some(i) = picked else { return Ok(()) };

    if keys[i].is_empty() {
        set_gate(None)?;
        println!("\n  {} {}\n", crate::style::green("✓"), "keeping the software key");
        return Ok(())
    }
    set_gate(Some(keys[i]))?;
    println!();
    println!("  {} {}", crate::style::green("✓"), labels[i]);
    println!();
    println!("  {}", crate::style::dim("the hardware key is a NEW credential — run `auth unregister` then `auth login`"));
    println!("  {}", crate::style::dim("so the old one is removed instead of left behind"));
    println!();
    Ok(())
}

/// Why this machine's key cannot be used right now, if it cannot.
///
/// A CHOSEN GATE IS HONOURED, NOT WORKED AROUND — but a machine is never left with no way in.
/// The gate protects THIS MACHINE'S KEY and nothing else, so QR, an authenticator code and an
/// emailed code are all unaffected: the answer to "my Watch is in the other room" is another
/// path, not a downgrade of the one the person deliberately locked.
#[cfg(target_os = "macos")]
pub(crate) fn presence_blocked() -> Option<String> {
    match enclave_gate() {
        Err(e) => Some(e.to_string()),
        Ok(_) => None,
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn presence_blocked() -> Option<String> {
    None
}

/// Wait for the chosen factor to become available, showing that we are still looking.
///
/// THERE IS NO "WHERE IS THE WATCH" API. `canEvaluatePolicy` is the only signal the OS gives,
/// and it is a boolean answered for right now — so the honest way to wait is to keep asking.
/// The spinner is not decoration: without it a retry either returns instantly (looks like it
/// did nothing) or sits silent for ten seconds (looks hung), and both read as broken.
///
/// Returns `None` once it becomes available, or the reason it did not.
#[cfg(target_os = "macos")]
pub(crate) fn wait_for_presence(seconds: u64) -> Option<String> {
    use std::io::Write as _;
    const FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(seconds);
    let mut i = 0usize;
    loop {
        if let Some(why) = presence_blocked() {
            if std::time::Instant::now() >= deadline {
                print!("\r\x1b[2K");
                let _ = std::io::stdout().flush();
                return Some(why)
            }
        } else {
            print!("\r\x1b[2K");
            let _ = std::io::stdout().flush();
            return None
        }
        print!(
            "\r  {} {}",
            crate::style::cyan(FRAMES[i % FRAMES.len()]),
            crate::style::dim("looking for your Apple Watch — raise your wrist"),
        );
        let _ = std::io::stdout().flush();
        i += 1;
        std::thread::sleep(std::time::Duration::from_millis(120));
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn wait_for_presence(_seconds: u64) -> Option<String> { None }

/// `neuralkit auth passkey system` — ask macOS to assert the ACCOUNT's own passkey.
///
/// THE PROBE THAT DECIDES A DESIGN. Everything else this CLI does with passkeys uses a key the
/// MACHINE holds; this asks the OS for one the ACCOUNT holds, synced through iCloud Keychain from
/// whichever device registered it. If it works, a brand-new Mac on the same Apple ID can sign in
/// with no email, no code and no QR — the only path that removes email from bootstrap.
///
/// The open question is not the API, it is the PLATFORM: whether macOS will draw its passkey sheet
/// for an accessory app with an offscreen window. If it refuses, the same request belongs in a tray
/// app and nothing in `phaze_auth::system_passkey` changes.
#[cfg(target_os = "macos")]
pub async fn system(base_url: &str) -> Result<()> {
    let base_url = base_url.trim_end_matches('/');
    let rp_id = url_host(base_url)?;
    let client = http(base_url)?;

    println!();
    println!("  {} {}", crate::style::bold("neuralkit"), crate::style::dim("· the account's own passkey"));
    println!();
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "relying party")), crate::style::dim(&rp_id));
    // WHAT THE OS THINKS IS RUNNING. The association is resolved against this, not against the
    // code signature — so an empty identifier here would explain a refusal that every other
    // input says should have worked.
    let (bundle_id, bundle_path) = phaze_auth::system_passkey::running_bundle();
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "running as")), crate::style::dim(&bundle_id));
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "bundle")), crate::style::dim(&bundle_path));

    // The SERVER's challenge, exactly as every other assertion path uses. Nothing about this is
    // local: a challenge we invented would prove the sheet appeared and nothing about identity.
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
    let challenge_b64 = start
        .pointer("/data/challenge")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("loginStart returned no challenge"))?;
    let challenge = URL_SAFE_NO_PAD.decode(challenge_b64).map_err(|e| anyhow!("challenge: {e}"))?;
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "challenge")), crate::style::dim(&format!("{} B from the server", challenge.len())));

    // NO allow-list ON PURPOSE. An empty list is the discoverable form — "any credential for this
    // domain" — which is what a machine that does not yet know whose it is has to ask.
    println!();
    println!("  {}", crate::style::dim("macOS should now show its passkey sheet — approve it"));
    let asrt = phaze_auth::system_passkey::assert(&rp_id, &challenge, &[], 60.0)
        .map_err(|e| anyhow!("{e}"))?;

    println!();
    println!("  {} {}", crate::style::green("✓"), "the OS returned an assertion");
    println!("  {}  {}", crate::style::dim(&format!("{:<13}", "credential")), crate::style::dim(&b64(&asrt.credential_id)));
    println!(
        "  {}  {}",
        crate::style::dim(&format!("{:<13}", "sizes")),
        crate::style::dim(&format!(
            "authData {} B · clientData {} B · signature {} B",
            asrt.authenticator_data.len(), asrt.client_data_json.len(), asrt.signature.len(),
        )),
    );

    // THE REAL PROOF is the server accepting it, not the sheet appearing. `loginFinish` resolves
    // the user from the credential id, so a success here means this machine just authenticated as
    // an account it was never told the name of.
    let res = client
        .post(format!("{base_url}/transport/action/Passkey/loginFinish"))
        .header("content-type", "application/json")
        .body(serde_json::json!({
            "id": b64(&asrt.credential_id),
            "authenticatorData": b64(&asrt.authenticator_data),
            "clientDataJSON": b64(&asrt.client_data_json),
            "signature": b64(&asrt.signature),
        }).to_string())
        .send()
        .await?;
    let body: Value = serde_json::from_str(&res.text().await?).unwrap_or(Value::Null);
    if let Some(m) = body.pointer("/error/message").and_then(Value::as_str) {
        println!("  {} {}", crate::style::red("✗"), crate::style::dim(&format!("the server rejected it — {m}")));
        return Ok(())
    }
    let user = body.pointer("/data/userId").and_then(Value::as_str).unwrap_or("");
    println!();
    println!("  {} signed in as {}", crate::style::green("✓"), crate::style::bold(user));
    println!("  {}", crate::style::dim("no email, no code, no QR — the account's own credential"));
    println!();
    Ok(())
}
