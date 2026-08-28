//! This machine's device fingerprint — `<machine>.<install>`.
//!
//! TWO HALVES BECAUSE THEY FAIL IN OPPOSITE DIRECTIONS, which is the only thing borrowed from the
//! browser's design. The MACHINE half is `SHA-256(IOPlatformUUID ‖ gpu pixels)`, re-derived from the
//! hardware every run, so it survives any amount of deleting and a fresh macOS user account. The
//! INSTALL half is a token minted once and kept on disk, so it survives a driver update or a
//! logic-board swap that moves what the hardware reads. Neither alone is durable; together they are.
//!
//! The install half is also the axis that tells two PEOPLE on one Mac apart — the machine half is
//! identical for both, so without it a shared machine is one account and the second person can
//! never enrol.
//!
//! WHY NOT `passkey.json`: that file is the machine's REGISTRATION and `auth unregister` deletes it
//! on purpose, so a value stored there is resettable by the very act it exists to observe. This one
//! lives outside the CLI's config directory entirely, and nothing in the binary removes it.
//!
//! AND WHY A FILE RATHER THAN THE KEYCHAIN, which is where this started. The keychain's only
//! advantage is an ACL, and an ACL guards a SECRET — this is not one; it blocks rather than admits,
//! so forging it earns someone else's block. What the ACL actually buys is a prompt on every read
//! from a binary the item does not already trust, which for an unsigned dev build is every build.
//! And a dismissed prompt does not fail loudly: the read returns nothing, a fresh token is minted,
//! and the identity rotates silently while appearing to work. A store whose read can fail
//! INTERACTIVELY cannot carry an identity. A file cannot be dismissed.
//!
//! NOTHING OF THE BROWSER'S SHAPE IS COPIED, and that was a real detour. `hb.ts` hashes thirteen
//! GPU limits, drops WebGL2, excludes canvas and screen size, and pins `navigator.platform` —
//! every one of those a defence against a BROWSER: Brave farbles WebGL2 per origin and per
//! session, Safari under-reports cores, privacy modes randomise canvas. A terminal has none of
//! those problems, so it has no reason to inherit their solutions. An earlier cut of this file
//! reproduced the browser's material byte-for-byte, including casting f32 to f64 to imitate
//! JavaScript's float printing. The two are separate identity spaces and this one has its own
//! shape.
//!
//! IT IS A CLAIM. A terminal writes its own HTTP, so there is no HttpOnly cookie to outrank a
//! forged value. What makes it usable is the asymmetry that makes the browser's usable: it is read
//! to COUNT and to BLOCK, never to admit — forging one earns someone else's block.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

/// `<machine>.<install>`, or `None` where the machine half cannot be read.
///
/// `None` is not a failure the caller handles — it omits the field, the fence accepts absence, and
/// every read fails open. That is the server's own rule: a null fingerprint skips the check
/// entirely, because refusing a real person to stop one duplicate is the worse error.
///
/// The dot is a separator the server can split on, giving it the same two tiers the browser's
/// value has — an exact match is this machine AND this install, a prefix match is this machine
/// after a reinstall. Unlike the browser's, the prefix is per-UNIT rather than per-model, so a
/// prefix hit is proof rather than evidence.
pub(crate) fn value() -> Option<(String, &'static str)> {
    let (m, axes) = machine()?;
    Some((format!("{m}.{}", install()), axes))
}

#[cfg(target_os = "macos")]
fn machine() -> Option<(String, &'static str)> {
    phaze_auth::fingerprint::machine()
}

#[cfg(not(target_os = "macos"))]
fn machine() -> Option<(String, &'static str)> {
    None
}

/// The install half. NEVER fails — the file answers, or this machine mints one.
///
/// Minted locally rather than fetched. The browser gets its token from a server route because it
/// needs a store that survives with JavaScript disabled; a terminal has no such constraint, and a
/// token's job is to be unique rather than to be issued. Six bytes cannot collide by chance
/// whichever side generates them, and minting removes a network round trip from every sign-in.
fn install() -> String {
    if let Some(t) = stored() {
        return t
    }
    let t = mint();
    store(&t);
    t
}

fn mint() -> String {
    let mut raw = [0u8; 6];
    // A failed RNG is neither survivable nor maskable: a fixed fallback would hand every machine
    // in that state the SAME install id, which is worse than having none.
    getrandom::getrandom(&mut raw).expect("system RNG");
    URL_SAFE_NO_PAD.encode(raw)
}

/// Applied to anything read back rather than trusted, so a truncated or hand-edited file is
/// discarded and re-minted instead of riding into the value.
fn valid(t: &str) -> bool {
    !t.is_empty() && t.len() <= 16 && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Deliberately NOT under `~/.config/neuralkit`, which `auth unregister` clears — the platform's
/// ordinary per-user data directory instead, which nothing in this binary touches.
fn path() -> Option<std::path::PathBuf> {
    let home = std::env::var_os("HOME")?;
    let dir = if cfg!(target_os = "macos") {
        std::path::Path::new(&home).join("Library/Application Support/neuralkit")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(|d| std::path::Path::new(&d).join("neuralkit"))
            .unwrap_or_else(|| std::path::Path::new(&home).join(".local/share/neuralkit"))
    };
    Some(dir.join("device"))
}

fn stored() -> Option<String> {
    let t = std::fs::read_to_string(path()?).ok()?.trim().to_string();
    valid(&t).then_some(t)
}

fn store(token: &str) {
    // Best effort: a write that fails costs this machine its install half, not its sign-in — the
    // machine half still identifies it, and the next run tries again. No 0600 dance, because the
    // value is not a secret; the file's job is to be somewhere nobody clears by accident.
    let Some(p) = path() else { return };
    if p.parent().map(|d| std::fs::create_dir_all(d).is_ok()) == Some(true) {
        let _ = std::fs::write(p, token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minted_token_is_usable() {
        let t = mint();
        assert_eq!(t.len(), 8, "six bytes is eight b64url chars: {t}");
        assert!(valid(&t), "{t}");
        assert_ne!(t, mint(), "minted tokens must not repeat");
    }

    #[test]
    fn corrupt_stored_values_are_rejected() {
        assert!(valid("aB3_-xyz"));
        assert!(!valid(""), "empty is not a token");
        assert!(!valid(&"a".repeat(17)), "17 exceeds the bound");
        assert!(!valid("has space"));
        assert!(!valid("dots.not.ok"), "a dot would split the value the server parses");
    }

    /// Both halves present, one dot, and the machine half stable across calls — the shape the
    /// server splits on. Skips where there is no IOPlatformUUID.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_value_is_two_halves_split_by_one_dot() {
        let Some((v, axes)) = value() else {
            eprintln!("neither axis available — skipped");
            return
        };
        assert!(["both", "uuid", "gpu"].contains(&axes), "axes names a reachable combination: {axes}");
        assert_eq!(v.matches('.').count(), 1, "exactly one separator: {v}");
        let (m, i) = v.split_once('.').unwrap();
        assert_eq!(m.len(), 43, "the machine half is a SHA-256: {m}");
        assert!(valid(i), "the install half is a token: {i}");
        assert_eq!(value().unwrap().0.split_once('.').unwrap().0, m, "the machine half must not move");
        assert_eq!(
            value().unwrap().0.split_once('.').unwrap().1, i,
            "and the install half must come back from the store — a token that re-minted on every \
             read would rotate this machine's identity silently, which is the failure the store exists \
             to prevent"
        );
    }
}
