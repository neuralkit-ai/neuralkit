//! The interactive session — `neuralkit auth login` drops in here once the
//! token lands (TTY only; headless callers exit after sign-in). This is NOT
//! the EEG dashboard (main.rs TUI) — it's a command REPL holding ONE sealed
//! WebSocket to the `---Cli.session` fence (rust-api, direct).
//!
//! The seal is client-supplied-pk ML-KEM: an EPHEMERAL keypair per session,
//! the public key rides `?pk=` on the upgrade, the server encapsulates the
//! per-connection DEK to it and pushes the `{kem}` grant as frame 1; every
//! data reply is AES-256-GCM `{e,iv}` opened with that DEK. phaze-crypto on
//! both ends of the wire — no app key ever ships in a distributed CLI.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use phaze_crypto::{aes, ml_kem};
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

pub async fn run() -> Result<()> {
    let creds = load_credentials()?;
    let (mut ws, dek) = connect(&creds).await?;

    println!("\nneuralkit session — signed in as {}", creds.user);
    println!("sealed channel up (ML-KEM-768 grant → AES-256-GCM frames)");
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
            "list" => match command(&mut ws, &dek, "list").await {
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

/// Upgrade to the sealed channel: ephemeral ML-KEM keypair → `?pk=` →
/// consume the `{kem}` grant → decapsulate → the 32-byte DEK.
async fn connect(creds: &Credentials) -> Result<(Ws, [u8; 32])> {
    let (pk, sk) = ml_kem::generate().map_err(|e| anyhow!("ml-kem generate: {e}"))?;

    // http→ws / https→wss; the /api/* route reaches rust-api (CF route in prod,
    // dev proxy locally) — same origin credentials.json already stores.
    let ws_origin = creds.origin.replacen("http", "ws", 1);
    let url = format!("{ws_origin}/api/cli/session?pk={}", pk.to_hex());
    let mut req = url.into_client_request()?;
    // Cookie name mirrors the server's own pick (rust-api current_user: the
    // ORIGIN var's scheme decides) — https origin ⇒ the __Secure- name.
    let cookie = if creds.origin.starts_with("https") {
        format!("__Secure-session={}", creds.token)
    } else {
        format!("session={}", creds.token)
    };
    req.headers_mut().insert("cookie", cookie.parse()?);

    let (mut ws, _) = connect_async(req)
        .await
        .context("connect to the session channel (is the API reachable?)")?;

    // Frame 1 is the grant. Anything else first = an auth/setup error.
    while let Some(msg) = ws.next().await {
        let Message::Text(t) = msg? else { continue };
        let v: Value = serde_json::from_str(&t).context("grant frame is not JSON")?;
        if let Some(kem) = v.get("kem").and_then(Value::as_str) {
            let ct = ml_kem::Ciphertext::from_bytes(&STANDARD.decode(kem)?)
                .map_err(|e| anyhow!("kem ciphertext: {e}"))?;
            let ss = sk.decapsulate(&ct).map_err(|e| anyhow!("decapsulate: {e}"))?;
            return Ok((ws, *ss.as_bytes()));
        }
        if let Some(m) = v.pointer("/error/message").and_then(Value::as_str) {
            bail!("{m}");
        }
    }
    bail!("the channel closed before the key grant")
}

/// One request/response turn: send `{"cmd":…}`, open the sealed reply.
async fn command(ws: &mut Ws, dek: &[u8; 32], cmd: &str) -> Result<Value> {
    ws.send(Message::Text(json!({ "cmd": cmd }).to_string())).await?;
    while let Some(msg) = ws.next().await {
        let Message::Text(t) = msg? else { continue };
        let v: Value = serde_json::from_str(&t).context("reply is not JSON")?;
        if let Some(m) = v.pointer("/error/message").and_then(Value::as_str) {
            bail!("{m}");
        }
        let (Some(e), Some(iv)) = (
            v.get("e").and_then(Value::as_str),
            v.get("iv").and_then(Value::as_str),
        ) else {
            continue // not a data frame
        };
        let iv: [u8; aes::NONCE_LEN] = STANDARD
            .decode(iv)?
            .try_into()
            .map_err(|_| anyhow!("iv is not {} bytes", aes::NONCE_LEN))?;
        let plain = aes::open(dek, &iv, &STANDARD.decode(e)?)
            .map_err(|e| anyhow!("open sealed frame: {e}"))?;
        return serde_json::from_slice(&plain).context("sealed payload is not JSON");
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
