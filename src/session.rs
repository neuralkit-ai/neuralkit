//! The interactive session — `neuralkit auth login` drops in here once the
//! token lands (TTY only; headless callers exit after sign-in). This is NOT
//! the EEG dashboard (main.rs TUI) — it's a command REPL holding ONE WebSocket
//! to the `---Cli.session` fence.
//!
//! That fence is a DISPATCHER stream, so it is served by the app itself at
//! `/transport/stream/Cli/session` — the same wire the browser's streams use,
//! which is what makes it behave identically in dev, preview and prod.
//!
//! Frames are sealed per connection. At login this install mints its own ML-KEM-768
//! keypair and registers the PUBLIC half; the server encapsulates each connection's
//! DEK to it and sends the ciphertext once as `{"__grant":{kem}}`. Decapsulating that
//! with the secret in credentials.json yields the AES-256-GCM key every later frame is
//! sealed with — so no key is shared between installs and none is embedded here.
//! The session token is an ordinary session record, resolved exactly as a browser cookie.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use phaze_crypto::{aes, ed25519, ml_kem};
use serde_json::{json, Value};
use crate::style;
use std::io::Write as _;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// The session's command table — `help` renders it. A new command = one row here +
/// one dispatch arm in the `---Cli.session` fence body (transport.phaze).
///
/// The third column is the role a command needs, and it only decides whether `help`
/// LISTS it. Enforcement stays server-side: typing a hidden command still reaches the
/// fence and is still refused there, so this table can never grant anything.
const COMMANDS: &[(&str, &str, Option<&str>)] = &[
    ("list", "list all users", Some("admin")),
    ("help", "show this table", None),
    ("exit", "leave the session", None),
];

struct Credentials {
    token: String,
    user: String,
    origin: String,
    /// This install's ML-KEM secret, minted at login (see login.rs). Absent for a
    /// credentials file written before that existed — the channel then falls back
    /// to whatever the fence sends unsealed.
    kem_secret: Option<String>,
    /// The app's PUBLIC ed25519 key, handed over at login. Not a secret — it only
    /// verifies signatures, and the browser bundle carries the same value.
    sign_key: Option<String>,
}

/// The per-frame seal. `aes_key` is the DEK the server encapsulated to THIS install's
/// ML-KEM public key and handed over in the one-time `__grant` frame — so it is fresh per
/// connection and openable only here. Verification of the inner ed25519 signature is
/// best-effort: it needs the app's PUBLIC sign key, and on a PQC stream the AES-GCM tag is
/// already the per-frame integrity (internals/pqc: signature = provenance once, AEAD tag =
/// tamper-evidence per frame).
struct Seal {
    aes_key: [u8; 32],
    verify_key: Option<ed25519::PublicKey>,
}

impl Seal {
    /// Open the `{__grant:{kem}}` frame: decapsulate the ML-KEM ciphertext with this
    /// install's secret to recover the 32-byte DEK the dispatcher is sealing with.
    fn from_grant(kem_b64: &str, secret_hex: &str, sign_key: Option<&str>) -> Result<Self> {
        let sk = ml_kem::SecretKey::from_hex(secret_hex).map_err(|e| anyhow!("kem secret: {e}"))?;
        let ct = ml_kem::Ciphertext::from_bytes(&STANDARD.decode(kem_b64)?)
            .map_err(|e| anyhow!("kem ciphertext: {e}"))?;
        let ss = sk.decapsulate(&ct).map_err(|e| anyhow!("decapsulate: {e}"))?;
        Ok(Seal {
            aes_key: *ss.as_bytes(),
            // From login (credentials.json); the env var stays as an override for a
            // credentials file written before the key was handed over. A key that is
            // PRESENT but unparseable is an error, not a silent skip — otherwise a
            // corrupted value turns verification off while everything still appears
            // to work, which is the worst of both.
            verify_key: match sign_key.map(String::from).or_else(|| std::env::var("PUBLIC_PHAZE_SIGN_KEY").ok()) {
                Some(h) => Some(
                    ed25519::PublicKey::from_hex(&h)
                        .map_err(|e| anyhow!("sign_key in credentials.json is not a valid ed25519 public key: {e}"))?,
                ),
                None => None,
            },
        })
    }

    /// One sealed frame → its payload. The wire is the dispatcher's
    /// `sealStreamFrame`, read in reverse: `{e,iv}` → AES-256-GCM → `{v,s}` →
    /// verify `s` over `v`'s bytes → `v` is the JSON the fence returned.
    fn open(&self, frame: &Value) -> Result<Value> {
        let (Some(e), Some(iv)) = (
            frame.get("e").and_then(Value::as_str),
            frame.get("iv").and_then(Value::as_str),
        ) else {
            return Ok(frame.clone()) // not sealed — pass through
        };
        let nonce: [u8; aes::NONCE_LEN] = STANDARD
            .decode(iv)?
            .try_into()
            .map_err(|_| anyhow!("iv is not {} bytes", aes::NONCE_LEN))?;
        let plain = aes::open(&self.aes_key, &nonce, &STANDARD.decode(e)?)
            .map_err(|e| anyhow!("decrypt: {e}"))?;
        let signed: Value = serde_json::from_slice(&plain).context("sealed payload is not JSON")?;
        // Sign-then-encrypt, so the signature is INSIDE the envelope: verify last.
        let (Some(v), Some(s)) = (
            signed.get("v").and_then(Value::as_str),
            signed.get("s").and_then(Value::as_str),
        ) else {
            return Ok(signed) // encrypt: without sign: — no inner envelope
        };
        // Verify only when the app's PUBLIC sign key is available. On a PQC stream the
        // AES-GCM tag already proved this frame came from a DEK holder; the signature is
        // the provenance layer, so its absence degrades rather than fails.
        if let Some(vk) = &self.verify_key {
            let sig_bytes: [u8; 64] = STANDARD
                .decode(s)?
                .try_into()
                .map_err(|_| anyhow!("signature is not 64 bytes"))?;
            vk.verify(v.as_bytes(), &ed25519::Signature::from_bytes(&sig_bytes))
                .map_err(|e| anyhow!("signature rejected: {e}"))?;
        }
        serde_json::from_str(v).context("signed payload is not JSON")
    }
}

pub async fn run() -> Result<()> {
    let creds = load_credentials()?;
    let (mut ws, seal, roles) = connect(&creds).await?;

    // Header: one bright line (who you are), then dimmed chrome. The crypto line is
    // status, not content — it should be legible on demand, not competing for the eye.
    println!();
    println!("  {} {}", style::bold("neuralkit"), style::dim(&format!("· {}", creds.user)));
    println!("  {} {}", style::green("●"), style::dim(match &seal {
        Some(s) if s.verify_key.is_some() => "ML-KEM-768 → AES-256-GCM · ed25519 verified",
        Some(_) => "ML-KEM-768 → AES-256-GCM",
        None => "plaintext over TLS",
    }));
    println!("  {}\n", style::dim("help for commands · exit to leave"));

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        print!("{} ", style::cyan("›"));
        std::io::stdout().flush()?;
        let Some(line) = lines.next_line().await? else { break };
        match line.trim() {
            "" => continue,
            "exit" | "quit" => break,
            "help" => {
                println!();
                for (cmd, what, needs) in COMMANDS {
                    // Hide what this account can't run — the server still enforces it.
                    if needs.is_some_and(|r| !roles.iter().any(|held| held == r)) { continue }
                    println!("  {}  {}", style::cyan(&format!("{cmd:<6}")), style::dim(what));
                }
                println!();
            }
            "list" => match command(&mut ws, seal.as_ref(), "list").await {
                Ok(reply) => render_users(&reply),
                Err(e) => println!("  {} {}", style::red("✗"), e),
            },
            other => println!(
                "  {} unknown command {} {}",
                style::red("✗"),
                style::bold(other),
                style::dim("— try help"),
            ),
        }
    }
    let _ = ws.close(None).await;
    println!("{}", style::dim("bye"));
    Ok(())
}

/// Read `~/.config/neuralkit/credentials.json` (written by `auth login`).
fn load_credentials() -> Result<Credentials> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = format!("{home}/.config/neuralkit/credentials.json");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read {path} — run `neuralkit auth login` first"))?;
    let v: Value = serde_json::from_str(&raw).context("credentials.json is not JSON")?;
    let field = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| anyhow!("credentials.json missing `{k}`"))
    };
    Ok(Credentials {
        token: field("token")?,
        user: field("user")?,
        origin: field("origin")?,
        kem_secret: v.get("kem_secret").and_then(Value::as_str).map(String::from),
        sign_key: v.get("sign_key").and_then(Value::as_str).map(String::from),
    })
}

/// Upgrade to the command channel. (The ML-KEM handshake is temporarily removed —
/// see the fence comment; restore both ends together from git.)
async fn connect(creds: &Credentials) -> Result<(Ws, Option<Seal>, Vec<String>)> {
    // rustls picks its process-level provider by crate-feature detection, which
    // PANICS when several are compiled in — quinn (via phaze-moq) brings both
    // aws-lc-rs and ring. Choose ring, the one moq-native-ietf installs for the
    // MoQ side. Err = already installed by another path, which is equally fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // http→ws / https→wss. The fence is a DISPATCHER stream, so it is served by the
    // app itself at /transport/stream/<Group>/<action> — the same wire the browser's
    // streams use, identical in dev, preview and prod.
    let ws_origin = creds.origin.replacen("http", "ws", 1);
    let url = format!("{ws_origin}/transport/stream/Cli/session");
    let mut req = url.into_client_request()?;
    // Send BOTH names. The app picks its cookie name from BUILD MODE
    // (`env.prod ? '__Secure-session' : 'session'`, auth.ts), which a client can't
    // infer from the URL — an https tunnel in front of a dev build wants the plain
    // name, a deployed build wants the prefixed one. Offering both lets the
    // resolver read whichever it is configured for; only one is ever looked up.
    let cookie = format!("session={0}; __Secure-session={0}", creds.token);
    req.headers_mut().insert("cookie", cookie.parse()?);

    let (mut ws, _) = connect_async(req)
        .await
        .context("connect to the session channel (is the API reachable?)")?;

    // The grant arrives ONCE, before any data frame: {"__grant":{"kem":…}} carries the
    // ML-KEM ciphertext encapsulated to this install's public key. Decapsulating it yields
    // the DEK every later frame is sealed with — so the seal is built here, not up front.
    // Then the readiness ack; anything else first is an auth/setup error.
    let mut seal: Option<Seal> = None;
    while let Some(msg) = ws.next().await {
        let Message::Text(t) = msg? else { continue };
        let raw: Value = serde_json::from_str(&t).context("first frame is not JSON")?;
        if raw.get("__ping").is_some() {
            continue
        }
        if let Some(kem) = raw.pointer("/__grant/kem").and_then(Value::as_str) {
            let secret = creds.kem_secret.as_deref().ok_or_else(|| {
                anyhow!("this stream is ML-KEM sealed but credentials.json has no kem_secret — re-run `neuralkit auth login`")
            })?;
            seal = Some(Seal::from_grant(kem, secret, creds.sign_key.as_deref())?);
            continue
        }
        let v = match &seal {
            Some(s) => s.open(&raw)?,
            None => raw,
        };
        if v.get("ready").is_some() {
            // Roles ride the ready frame so `help` can hide what this account can't run.
            let roles = v
                .get("roles")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
                .unwrap_or_default();
            return Ok((ws, seal, roles));
        }
        if let Some(m) = v.pointer("/error/message").and_then(Value::as_str) {
            bail!("{m}");
        }
    }
    bail!("the channel closed before it was ready")
}

/// One request/response turn: send `{"cmd":…}`, read the reply.
async fn command(ws: &mut Ws, seal: Option<&Seal>, cmd: &str) -> Result<Value> {
    ws.send(Message::Text(json!({ "cmd": cmd }).to_string())).await?;
    while let Some(msg) = ws.next().await {
        let Message::Text(t) = msg? else { continue };
        let raw: Value = serde_json::from_str(&t).context("reply is not JSON")?;
        // Control frames ride PLAIN, outside the seal — the dispatcher sends
        // `{"__ping":1}` as a keepalive (SSE's `: ping` has no ws equivalent) and
        // `{"__grant":…}` for a PQC stream's key grant. The browser's s.bind recipe
        // drops both before setting a value; drop them BEFORE opening, or a
        // keepalive is read as the reply (and would fail to decrypt).
        if raw.get("__ping").is_some() || raw.get("__grant").is_some() {
            continue
        }
        let v = match seal {
            Some(s) => s.open(&raw)?,
            None => raw,
        };
        if let Some(m) = v.pointer("/error/message").and_then(Value::as_str) {
            bail!("{m}");
        }
        if v.get("ready").is_some() {
            continue // a late readiness ack, not a reply
        }
        return Ok(v);
    }
    bail!("the channel closed mid-command")
}

/// Aligned columns, no box-drawing: borders would make the rows painful to copy out
/// of the scrollback, which is the whole reason this stays a line-based REPL.
fn render_users(reply: &Value) {
    let Some(users) = reply.get("users").and_then(Value::as_array) else {
        println!("{reply}");
        return;
    };
    let width = users
        .iter()
        .filter_map(|u| u.get("email").and_then(Value::as_str))
        .map(str::len)
        .max()
        .unwrap_or(5)
        .max(5);
    println!();
    println!("  {}  {}", style::dim(&format!("{:<width$}", "EMAIL")), style::dim("VERIFIED"));
    for u in users {
        let email = u.get("email").and_then(Value::as_str).unwrap_or("?");
        let verified = u.get("verified").and_then(Value::as_i64).unwrap_or(0) == 1;
        // ✓/· carries the state on its own, so the row text stays unstyled and readable.
        let mark = if verified { style::green("✓") } else { style::dim("·") };
        println!("  {email:<width$}  {mark}");
    }
    println!(
        "  {}\n",
        style::dim(&format!("{} user{}", users.len(), if users.len() == 1 { "" } else { "s" })),
    );
}
