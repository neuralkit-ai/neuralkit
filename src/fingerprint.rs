//! This install's device token — the CLI's half of the fingerprint's ASSIGNED axis.
//!
//! The browser carries `<measured>.<token>`: a WebGL hash that describes the machine, and a token
//! minted once and kept in three stores that restore each other. A terminal produces only the
//! second half, and that is deliberate rather than a gap — `.{token}` is a value the wire already
//! accepts and the server already resolves, because *"the token axis alone is STILL proof —
//! assigned, can't collide"*. The measured half is a CLAIM about hardware; this is a value the
//! server itself minted, which is a different and better thing to be sending.
//!
//! WHY THE KEYCHAIN AND NOT `passkey.json`. That file is the machine's REGISTRATION, and clearing
//! it is a supported act — `auth unregister` exists to do exactly that. A token stored beside it
//! would reset with it, and then the one question it exists to answer (is this the same machine
//! coming back?) is unanswerable precisely when it matters. The keychain is the terminal's
//! analogue of the HttpOnly cookie the browser keeps: it survives the partial clear a person
//! actually performs, `rm -rf ~/.config/neuralkit`.
//!
//! IT IS STILL A CLAIM, and nothing here pretends otherwise — a terminal writes its own HTTP, so
//! there is no cookie to outrank a forged value. What makes it usable is the asymmetry that makes
//! the browser's usable: it is read to COUNT and to BLOCK, never to admit. Forging one earns
//! someone else's block.
//!
//! CLEARING IT is deliberately not a subcommand. `auth unregister` means forget this machine's
//! REGISTRATION, and folding this in would make the abuse signal resettable by the very act it
//! exists to observe. A person who genuinely wants it gone has the OS's own tool:
//! `security delete-generic-password -s "neuralkit cli" -a "device"`.
//!
//! MACOS ONLY, and the column says so. Elsewhere nothing is stored and nothing is sent, which the
//! server records as `fingerprint_type = 'none'` — the value 0018 keeps precisely so that absence
//! is legible instead of invisible.

const SERVICE: &str = "neuralkit cli";
const ACCOUNT: &str = "device";

/// The token route, shaped in the app's `vite.config.ts` and served as a real 16×16 icon with the
/// token appended to the bytes. Threaded from ONE place there to the emitted route and the
/// browser's fetch; this is the third reader, and it must agree with them.
const TOKEN_PATH: &str = "/neuralkit.ico";

/// `<measured>.<token>` as this machine can produce it — always `.{token}`, never a measured half.
///
/// `None` on every failure, and callers must FAIL OPEN on it: the server's own rule is that a null
/// fingerprint skips the check entirely, *"because refusing a real person to stop one duplicate is
/// the worse error."* An offline terminal, a cleared keychain and a non-macOS host all land here
/// and must all still be able to sign in.
pub(crate) async fn value(client: &reqwest::Client, base_url: &str) -> Option<String> {
    if let Some(t) = stored() {
        return Some(format!(".{t}"))
    }
    // Ask the server for one, exactly as the browser does — read the raw body, take the tail. The
    // icon half is the browser's concern, never ours; what matters is the last 8 bytes.
    let res = client.get(format!("{base_url}{TOKEN_PATH}")).send().await.ok()?;
    if !res.status().is_success() {
        return None
    }
    let bytes = res.bytes().await.ok()?;
    let tail = String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(8)..]).trim().to_string();
    // A stale or corrupt value is DISCARDED rather than trusted — the same rule the browser half
    // applies to a caller-supplied token. The bound is the wire's own token shape; anything
    // outside it is, by definition, not a token.
    if !valid(&tail) {
        return None
    }
    store(&tail);
    Some(format!(".{tail}"))
}

fn valid(t: &str) -> bool {
    !t.is_empty() && t.len() <= 16 && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(target_os = "macos")]
fn stored() -> Option<String> {
    let bytes = phaze_auth::secret::get(SERVICE, ACCOUNT).ok().flatten()?;
    let t = String::from_utf8(bytes).ok()?;
    valid(&t).then_some(t)
}

#[cfg(target_os = "macos")]
fn store(token: &str) {
    // Best effort by design. A keychain that refuses the write costs this machine its durable
    // half, not its sign-in — the token still rides this request, and the next run asks again.
    let _ = phaze_auth::secret::set(SERVICE, ACCOUNT, token.as_bytes());
}

#[cfg(not(target_os = "macos"))]
fn stored() -> Option<String> {
    None
}

#[cfg(not(target_os = "macos"))]
fn store(_token: &str) {}

#[cfg(test)]
mod tests {
    use super::valid;

    #[test]
    fn token_shape_matches_the_wire() {
        // The server's schema is `[A-Za-z0-9_-]{1,16}` after the dot. These are the cases that
        // decide whether a value is sent at all, so they are worth pinning rather than assuming.
        assert!(valid("aB3_-xyz"));
        assert!(valid("a"));
        assert!(valid(&"a".repeat(16)));
        assert!(!valid(""), "empty is not a token");
        assert!(!valid(&"a".repeat(17)), "17 exceeds the wire's bound");
        assert!(!valid("has space"), "the icon tail is trimmed; a space means we read padding");
        assert!(!valid("dots.not.ok"), "a dot would split the value the server parses");
    }
}
