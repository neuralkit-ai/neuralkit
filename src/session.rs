//! The interactive session — `neuralkit auth login` drops in here once the
//! token lands (TTY only; headless callers exit after sign-in). This is NOT
//! the EEG dashboard (main.rs TUI) — it's a command REPL holding ONE WebSocket
//! to the `---Cli.session` fence.
//!
//! That fence is a DISPATCHER stream, so it is served by the app itself at
//! `/transport/stream/Cli/session` — the same wire the browser's streams use,
//! which is what makes it behave identically in dev, preview and prod.
//!
//! No per-frame seal: the channel is TLS and the token is one-time + revocable,
//! so a distributed CLI carries no keys and needs no crypto deps (the same
//! reasoning that keeps `---CliAuth` unsealed). The session token is an ordinary
//! session record, so the server resolves it exactly as it would a browser cookie.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use phaze_crypto::{aes, ed25519};
use serde_json::{json, Value};
use std::io::Write as _;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// The session's command table — `help` renders it. A new command = one row
/// here + one dispatch arm in the `---Cli.session` fence body (transport.phaze).
const COMMANDS: &[(&str, &str)] = &[
    ("list", "list all users (admin)"),
    ("help", "show this table"),
    ("exit", "leave the session"),
];

struct Credentials {
    token: String,
    user: String,
    origin: String,
}

/// The fence's per-frame seal, read from the app's PUBLIC key values — the same
/// two the browser bundle already carries (`env.public.*`), so the CLI holds
/// nothing the shipped client doesn't. Absent → frames are read as plain JSON,
/// which is what an unsealed fence sends.
struct Seal {
    aes_key: [u8; 32],
    verify_key: ed25519::PublicKey,
}

impl Seal {
    fn from_env() -> Option<Self> {
        let hex_key = std::env::var("PUBLIC_PHAZE_ENCRYPT_KEY").ok()?;
        let sign_key = std::env::var("PUBLIC_PHAZE_SIGN_KEY").ok()?;
        let raw = (0..hex_key.len() / 2)
            .map(|i| u8::from_str_radix(&hex_key[i * 2..i * 2 + 2], 16).ok())
            .collect::<Option<Vec<u8>>>()?;
        Some(Seal {
            aes_key: raw.try_into().ok()?,
            verify_key: ed25519::PublicKey::from_hex(&sign_key).ok()?,
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
        let sig_bytes: [u8; 64] = STANDARD
            .decode(s)?
            .try_into()
            .map_err(|_| anyhow!("signature is not 64 bytes"))?;
        self.verify_key
            .verify(v.as_bytes(), &ed25519::Signature::from_bytes(&sig_bytes))
            .map_err(|e| anyhow!("signature rejected: {e}"))?;
        serde_json::from_str(v).context("signed payload is not JSON")
    }
}

pub async fn run() -> Result<()> {
    let creds = load_credentials()?;
    let seal = Seal::from_env();
    let mut ws = connect(&creds, seal.as_ref()).await?;

    println!("\nneuralkit session — signed in as {}", creds.user);
    println!("{}", match seal {
        Some(_) => "channel up (per-frame ed25519 + AES-256-GCM)",
        None => "channel up (JSON over TLS)",
    });
    println!("type 'help' for commands, 'exit' to leave\n");

    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    loop {
        print!("neuralkit> ");
        std::io::stdout().flush()?;
        let Some(line) = lines.next_line().await? else { break };
        match line.trim() {
            "" => continue,
            "exit" | "quit" => break,
            "help" => {
                for (cmd, what) in COMMANDS {
                    println!("  {cmd:<8}{what}");
                }
            }
            "list" => match command(&mut ws, seal.as_ref(), "list").await {
                Ok(reply) => render_users(&reply),
                Err(e) => println!("✗ {e:#}"),
            },
            other => println!("unknown command: {other} — try 'help'"),
        }
    }
    let _ = ws.close(None).await;
    println!("bye");
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
    Ok(Credentials { token: field("token")?, user: field("user")?, origin: field("origin")? })
}

/// Upgrade to the command channel. (The ML-KEM handshake is temporarily removed —
/// see the fence comment; restore both ends together from git.)
async fn connect(creds: &Credentials, seal: Option<&Seal>) -> Result<Ws> {
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

    // Frame 1 is the readiness ack. Anything else first = an auth/setup error.
    while let Some(msg) = ws.next().await {
        let Message::Text(t) = msg? else { continue };
        let raw: Value = serde_json::from_str(&t).context("first frame is not JSON")?;
        if raw.get("__ping").is_some() || raw.get("__grant").is_some() {
            continue // control frame — see the note in `command`
        }
        let v = match seal {
            Some(s) => s.open(&raw)?,
            None => raw,
        };
        if v.get("ready").is_some() {
            return Ok(ws);
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
    println!("  {:<width$}  VERIFIED", "EMAIL");
    for u in users {
        let email = u.get("email").and_then(Value::as_str).unwrap_or("?");
        let verified = u.get("verified").and_then(Value::as_i64).unwrap_or(0) == 1;
        println!("  {email:<width$}  {}", if verified { "✓" } else { "·" });
    }
    println!("  {} user{}", users.len(), if users.len() == 1 { "" } else { "s" });
}
