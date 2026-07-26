//! What crossterm can do to text, shown next to the call that does it.
//!
//!     cargo run --example styles
//!
//! Not part of the binary — a cargo example, so it costs nothing at ship time.
//! Anything printed here renders the same way in the session REPL, which styles
//! through `src/style.rs` (the same crate, TTY-gated).

use crossterm::style::{Attribute, Color, Stylize};

fn row(label: &str, painted: String) {
    println!("  {painted:<38}  {}", label.dark_grey());
}

fn main() {
    println!("\n{}\n", "── colours (foreground) ──".bold());
    for (name, c) in [
        ("Red", Color::Red), ("DarkRed", Color::DarkRed),
        ("Green", Color::Green), ("DarkGreen", Color::DarkGreen),
        ("Yellow", Color::Yellow), ("DarkYellow", Color::DarkYellow),
        ("Blue", Color::Blue), ("DarkBlue", Color::DarkBlue),
        ("Magenta", Color::Magenta), ("DarkMagenta", Color::DarkMagenta),
        ("Cyan", Color::Cyan), ("DarkCyan", Color::DarkCyan),
        ("White", Color::White), ("Grey", Color::Grey),
        ("DarkGrey", Color::DarkGrey), ("Black", Color::Black),
    ] {
        row(&format!(".with(Color::{name})"), "the quick brown fox".with(c).to_string());
    }

    println!("\n{}\n", "── backgrounds ──".bold());
    for (name, c) in [("Red", Color::Red), ("Green", Color::Green), ("Blue", Color::Blue), ("Grey", Color::Grey)] {
        row(&format!(".on(Color::{name})"), format!(" on {name} ").on(c).to_string());
    }

    println!("\n{}\n", "── attributes ──".bold());
    for (name, a) in [
        ("Bold", Attribute::Bold), ("Dim", Attribute::Dim), ("Italic", Attribute::Italic),
        ("Underlined", Attribute::Underlined), ("DoubleUnderlined", Attribute::DoubleUnderlined),
        ("Undercurled", Attribute::Undercurled), ("Underdotted", Attribute::Underdotted),
        ("Reverse", Attribute::Reverse), ("CrossedOut", Attribute::CrossedOut),
        ("OverLined", Attribute::OverLined), ("SlowBlink", Attribute::SlowBlink),
    ] {
        row(&format!(".attribute(Attribute::{name})"), "the quick brown fox".attribute(a).to_string());
    }
    println!("  {}", "(italic / undercurled / blink depend on the terminal — many ignore them)".dark_grey());

    println!("\n{}\n", "── 256-colour ──".bold());
    print!("  ");
    for i in (16..232).step_by(6) { print!("{}", "██".with(Color::AnsiValue(i))); }
    println!("   {}", ".with(Color::AnsiValue(n))".dark_grey());

    println!("\n{}\n", "── true colour (RGB) ──".bold());
    print!("  ");
    for i in 0..40 {
        let t = i as f32 / 39.0;
        let c = Color::Rgb { r: (60.0 + t * 120.0) as u8, g: (180.0 - t * 60.0) as u8, b: (200.0 - t * 40.0) as u8 };
        print!("{}", "█".with(c));
    }
    println!("   {}", ".with(Color::Rgb { r, g, b })".dark_grey());

    println!("\n{}\n", "── chained ──".bold());
    row(r#""x".green().bold()"#, "the quick brown fox".green().bold().to_string());
    row(r#""x".cyan().underlined()"#, "the quick brown fox".cyan().underlined().to_string());
    row(r#""x".white().on_dark_red().bold()"#, " FAILED ".white().on_dark_red().bold().to_string());
    row(r#".underline(Color::Red)"#, "misspelled".underline(Color::Red).to_string());

    // Plain Unicode only. Nerd Font glyphs need a patched font, and emoji are
    // double-width — both break column alignment on someone else's machine.
    println!("\n{}\n", "── symbols ──".bold());
    for (group, syms) in [
        ("state",       "✓ ✔ ✗ ✘ ● ○ ◉ ◌ ◆ ◇ ■ □ ▲ ▼ ★ ☆ ⚠ !"),
        ("prompt/flow", "› » ❯ → ⟶ ⇒ ▸ ▶ ↳ ⤷ ⏎"),
        ("bullets",     "· • ◦ ‣ ∙ ⋅ – — |"),
        ("spinner",     "⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏   ◐ ◓ ◑ ◒"),
        ("sparkline",   "▁ ▂ ▃ ▄ ▅ ▆ ▇ █"),
        ("meter",       "▏ ▎ ▍ ▌ ▋ ▊ ▉ █   ░ ▒ ▓"),
        ("box",         "─ │ ┌ ┐ └ ┘ ├ ┤ ┬ ┴ ┼   ━ ┃ ╭ ╮ ╰ ╯   ═ ║ ╔ ╗ ╚ ╝"),
        ("half-block",  "▀ ▄ █  (what render_qr uses for the QR)"),
    ] {
        println!("  {}  {syms}", format!("{group:<11}").dark_grey());
    }

    println!("\n{}\n", "── symbols in use ──".bold());
    println!("  {} {}", "●".green(), "connected".dark_grey());
    println!("  {} {}", "●".dark_grey(), "idle".dark_grey());
    println!("  {} {}", "●".red(), "disconnected".dark_grey());
    println!("  {} {}   {}", "⠹".cyan(), "waiting for your phone…".dark_grey(), "(spinner while the QR is unscanned)".dark_grey());
    println!("  {} {}   {}", "rtt".dark_grey(), "▁▂▃▅▇▆▄▂▁ 6.2ms".cyan(), "(sparkline for a latency monitor)".dark_grey());
    println!("  {} {}", "▉▉▉▉▉▉░░░░".green(), "62%".dark_grey());

    println!("\n{}\n", "── the recipes the REPL actually uses ──".bold());
    println!("  {} {}", "●".green(), "ML-KEM-768 → AES-256-GCM · ed25519 verified".dark_grey());
    println!("  {} {}", "✗".red(), "FORBIDDEN: the list command needs the admin role");
    println!("  {}  {}", "list  ".cyan(), "list all users".dark_grey());
    println!("  {} list", "›".cyan());
    println!("  {}  {}", "EMAIL            ".dark_grey(), "VERIFIED".dark_grey());
    println!("  r@madenowhere.com  {}", "✓".green());
    println!();
}
