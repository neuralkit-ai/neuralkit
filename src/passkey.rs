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
use phaze_auth::authenticator::{assert, cose_key, Signer, SoftwareKey};
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
