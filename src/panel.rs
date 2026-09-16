//! A first-run panel — a small floating card with words in it.
//!
//! AN `NSPanel`, NOT AN `NSWindow`. A panel is AppKit's utility window, and two of its
//! properties are the whole reason to prefer it here: `NonactivatingPanel` in the style mask
//! means showing it does NOT pull focus out of whatever the person was typing in, and
//! `setFloatingPanel:` keeps it above ordinary windows without claiming to be one. A menu-bar
//! accessory that stole the frontmost app's focus to say hello would be the wrong first
//! impression.
//!
//! NO `tao` HERE, AND THAT IS THE POINT. An earlier cut built the window with `WindowBuilder`
//! and then reached through `ns_view()` for the text — which works, but ties the panel to an
//! `EventLoopWindowTarget` it does not otherwise need, and mixes two idioms to do one job. The
//! `tao` + `ns_window()` bridge earns its keep when the window is the app's MAIN one and needs
//! the event loop's resize/focus/close events; this one's only interaction is a button that
//! messages the panel directly, so the bridge would attach a dependency to a window that
//! consumes nothing from it.
//!
//! `objc2-app-kit`, NOT RAW `objc_msgSend`. An earlier cut spoke to AppKit through 26
//! hand-transmuted `objc_msgSend` signatures and 45 string selectors, on the belief that a
//! binding crate would be a new dependency. It is not: `tao` already resolves `objc2`,
//! `objc2-foundation` and `objc2-app-kit` for the tray, so they were compiled into this binary
//! either way. Naming them buys checked signatures (a wrong transmute was UB, not an error),
//! ARC instead of leak-by-omission, and constants that say what they are —
//! `NSGlassEffectViewStyle::Clear` rather than `1`, `NSFloatingWindowLevel` rather than `3`.
//!
//! EVERY STEP IS BEST-EFFORT. A panel that fails to draw must never stop the icon appearing, so
//! nothing here returns an error — the worst case is no panel.

use objc2::rc::{Retained, Weak};
use objc2::runtime::{AnyObject, NSObject};
use objc2::{define_class, msg_send, sel, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSAutoresizingMaskOptions, NSBackingStoreType, NSButton, NSCellImagePosition, NSColor,
    NSFloatingWindowLevel,
    NSBezierPath, NSGlassEffectView, NSGlassEffectViewStyle, NSImage, NSPanel, NSView,
    NSVisualEffectBlendingMode, NSVisualEffectMaterial, NSVisualEffectState, NSVisualEffectView,
    NSResponder, NSWindow, NSWindowButton, NSWindowCollectionBehavior, NSWindowStyleMask,
    NSWindowTitleVisibility,
};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
use raw_window_handle::{
    AppKitWindowHandle, HandleError, HasWindowHandle, RawWindowHandle, WindowHandle,
};
use std::ffi::c_void;
use std::ptr::NonNull;
use wry::{dpi, Rect, WebView, WebViewBuilder};

/// One factor so the panel scales as a whole. Doubling W and H alone would stretch the box and
/// leave the type marooned in it — every inset and radius is derived from this instead. Type is
/// the deliberate exception: macOS sizes text against the system font, not against its container.
const SCALE: f64 = 2.0;
/// MEASURED, NOT TUNED. Windows captured by id (`screencapture -l<id>` keeps the alpha), each
/// corner's edge located to SUB-PIXEL precision by coverage (a row's uncovered width = its summed
/// alpha), then least-squares fitted to a circle:
///
/// | window            | r     | rms  |
/// |-------------------|-------|------|
/// | Arc               | 15.85 | 0.24 |
/// | VS Code           | 15.85 | 0.24 |
/// | iTerm2            | 14.95 | 0.23 |
/// | this panel        | 14.95 | 0.23 |
/// | Warp              | 10.80 | 0.24 |
///
/// Ordinary document windows agree at 15.85; Warp rounds itself tighter. An earlier THRESHOLD fit
/// gave 13.75/12.75/8.75 for the same windows — do not trust it, it reads where the antialiased
/// ramp STARTS rather than where the edge is, and it called two visibly different corners equal.
///
/// The rendered corner is not this constant: 12 here measures 14.95.
///
/// NOT SCALED BY `SCALE`. A native window's corner is the same size on a 400pt window and a 1400pt
/// one, so scaling this with the panel is what made it disagree with everything beside it.
///
/// Read by every arm: `Terminal` rounds its fill with it, `Vibrancy` and `Glass` pass it to their
/// own `setCornerRadius:`. `Terminal` ships, so here it rounds only the tint fill: the corner you
/// see is the system's, because the panel is titled (see `welcome`).
const RADIUS: f64 = 12.0;
const W: f64 = 400.0 * SCALE;
const H: f64 = 400.0 * SCALE;
/// The left/right inset, and the width every label gets.
const PAD: f64 = 12.0 * SCALE;

/// THE DARKNESS DIAL — live in `Backdrop::Terminal` and in `Backdrop::Glass`, inert in `Vibrancy`
/// (a material owns its own colour and takes no tint).
///
/// In Terminal mode this is not decoration, it IS the window's backdrop: the fill this paints is
/// the only thing standing between the desktop and the page. **ALPHA MUST BE > 0** — the server
/// blurs "non-fully-transparent pixels", so at alpha 0 there is nothing to blur and the panel goes
/// clear. Terminal.app uses 0.01 for a near-invisible pane; a card wants more.
///
/// WHITE lightens, BLACK darkens; alpha is the strength.
const TINT_WHITE: f64 = 0.0;   // 1.0 = white (lighten) · 0.0 = black (darken)
const TINT_ALPHA: f64 = 0.10;  // "smooth warp" — tuned by eye, NOT Warp's 30

/// THE VIBRANCY DIAL. `NSVisualEffectView` has no lightness/tint knob — the material IS the
/// appearance, each one a fixed recipe of blur, saturation and tint that the system owns.
///
/// MEASURED, darkest to lightest — each material rendered in this panel and its centre sampled
/// from a window-id capture (background-independent: that buffer carries the material's own colour,
/// not the desktop, so position does not matter):
///
/// | material                | lightness | variation |
/// |-------------------------|-----------|-----------|
/// | `UnderPageBackground`   | 120.7     | 52.8      |
/// | `ContentBackground`     | 122.6     | 49.1      |
/// | `WindowBackground`      | 122.6     | 49.1      |
/// | `ToolTip`               | 124.3     | 38.9      |
/// | `Sheet`                 | 125.8     | 43.1      |
/// | `HeaderView`            | 129.1     | 37.2      |
/// | `Sidebar`               | 130.7     | 34.3      |
/// | `UnderWindowBackground` | 130.7     | 34.3      |
/// | `Menu`                  | 133.7     | 29.1      |
/// | `Titlebar`              | 133.9     | 28.8      |
/// | `Selection`             | 134.6     | 25.7      |
/// | `Popover`               | 136.7     | 24.2      |
/// | `FullScreenUI`          | 139.7     | 20.0      |
/// | `HUDWindow`             | 142.7     | 15.5      |
///
/// THE SECOND COLUMN IS NOT TRANSMISSION. It comes from a window-id capture, which carries the
/// material's own colour and NOT the desktop, so it says how much of OUR OWN content the material
/// washes out — nothing about seeing through. An earlier draft of this comment read it as desktop
/// transmission and concluded "lighter means more obscuring", which measuring on screen contradicts.
///
/// TRANSMISSION, measured properly — five materials rendered at one fixed screen position and the
/// composited result sampled, so the desktop behind is identical for all of them:
///
/// | material              | structure through | light through |
/// |-----------------------|-------------------|---------------|
/// | `UnderPageBackground` | 41.8              | 35.5          |
/// | `Sheet`               | 37.8              | 46.6          |
/// | `FullScreenUI`        | 34.2              | 61.0          |
/// | `Popover`             | 34.1              | 59.6          |
/// | `HUDWindow`           | 33.4              | 61.6          |
///
/// The two run OPPOSITE, which is why "most translucent" needs saying carefully. `HUDWindow` passes
/// the most LIGHT and the least STRUCTURE — it blurs hardest, so the desktop arrives as a bright
/// wash rather than as shapes. Over a light desktop that is what reads as most see-through, and it
/// is the one picked by eye. `UnderPageBackground` is the reverse: you can make out what is behind
/// it, but it is dark.
///
/// (`Light`/`Dark`/`MediumLight`/`UltraDark`/`AppearanceBased` also exist but are deprecated.)
const MATERIAL: NSVisualEffectMaterial = NSVisualEffectMaterial::HUDWindow;

/// Backdrop blur radius, in points. 0 = off.
///
/// 64 IS WARP'S OWN NUMBER, read from its preferences: `OverrideBlur = 64`, `OverrideOpacity = 30`
/// (`defaults read dev.warp.Warp-Stable`). This sat at 20 and was reported by eye as "the iTerm2
/// blur" — which it was, to two decimal places: iTerm2's profile carries `Blur Radius = 20.294`.
/// Warp and iTerm2 call the SAME private function (neither links it; both resolve it at runtime,
/// and neither binary contains any other blur API); the whole difference between the two looks is
/// this number and the opacity beside it.
///
/// LIVE IN `Backdrop::Terminal`, and MEASURED INERT IN `Vibrancy`. In vibrancy the call still
/// succeeds (rc=0) but has nothing to do — the material already sampled the desktop, blurred it and
/// painted it in, so no pixel is see-through for the server to blur behind. Radius 0 and radius 200
/// were captured over the same desktop and came back pixel-identical inside the panel (2026-09-01).
/// That is why `Terminal` is the default: it is the only mode where this number means anything.
///
/// This is the trade iTerm2/Terminal.app/Warp/Alacritty make — the PRIVATE SkyLight call INSTEAD
/// OF a visual effect view, never alongside one.
/// Private API, so: it can break on any macOS release, and it bars the Mac App Store — not a
/// constraint here, since this ships via npm + Developer ID.
const BLUR_RADIUS: i32 = 64;

/// How the panel gets its backdrop. Three real implementations, not three settings — each is a
/// different macOS mechanism with a different set of dials, and none of them is a superset.
///
/// · **`Terminal` — "SMOOTH WARP", the shipped configuration.** Warp's structure, reached in
///   AppKit. The whole recipe, because every piece of it was paid for:
///
///   | piece | value | why |
///   |---|---|---|
///   | `BACKDROP` | `Terminal` | no material, so nothing samples focus |
///   | window background | **alpha 0.01** | NOT `clearColor` — see `setBackgroundColor` below |
///   | `BLUR_RADIUS` | 64 | Warp's own `OverrideBlur` |
///   | `TINT_ALPHA` | **0.10** | tuned by eye. Warp's own is 30, which reads too heavy here |
///   | style mask | `Titled` + `FullSizeContentView` | the system shadow, and its window shape |
///   | fill | rounded `NSBezierPath` | no mask, no material, no CALayer |
///
///   MEASURED: focused vs unfocused delta **0.0** on every channel, the same as Warp itself.
///   Corner r=14.95 rms=0.23, against Warp's 10.80 rms=0.24 — same curve quality, larger radius.
///
///   **what Warp, iTerm2, Terminal.app and Alacritty do.** The window paints
///   its OWN low-alpha rounded fill and the WINDOW SERVER blurs whatever shows through it. The
///   server blurs by ALPHA CHANNEL, so the rounded fill gives a rounded blur for free — no mask, no
///   clip. Dials: `BLUR_RADIUS` (a real number, only here), `TINT_WHITE`/`TINT_ALPHA`, `RADIUS`.
///   Colour cannot shift with focus because nothing is sampling focus — we drew it.
///   Warp is not a webview and not Tauri: it paints via wgpu/Metal. This is the same STRUCTURE —
///   own alpha, server blur — reached with AppKit drawing instead.
///
///
/// · **`Vibrancy` — `NSVisualEffectView`, and exactly what Tauri does** (`window-vibrancy`'s
///   `apply_vibrancy` is its only macOS entry point; that crate's `apply_blur` is Windows-ONLY, so
///   Tauri has no macOS blur radius at all). The system material owns blur, saturation and colour
///   as one recipe, so `MATERIAL` is the whole dial and `BLUR_RADIUS` is inert. `state = .active`
///   pins the appearance; its own `setCornerRadius:` rounds the effect.
///
/// · **`Glass` — `NSGlassEffectView`, macOS 26.** The newest material. It has NO state property to
///   pin its appearance — Apple's Liquid Glass guide documents only `cornerRadius`, `tintColor` and
///   `contentView`, and the forum thread asking exactly this (818901) is unanswered.
///
///   IT STAYS GLASS WHEN INACTIVE — it does NOT fall back to a material, which an earlier note
///   here claimed. Observed by eye, the inactive state differs by STYLE:
///
///   · `Clear`   — more blur, plus a faded white veil over it.
///   · `Regular` — blur unchanged; it DESATURATES.
///
///   Neither is reachable from the API. `setTintColor` applies to both states equally, so it cannot
///   close a gap that only exists in one of them, and there is no saturation knob at all.
///
///   Do not try to measure this with mean RGB. That metric reported delta 0.0 on configurations
///   where the shift is plainly visible — it cannot see blur changing or saturation dropping, only
///   average colour, which barely moves.
#[derive(PartialEq)]
#[allow(dead_code)] // the two non-selected arms are switchable configuration, not dead ends
enum Backdrop {
    Terminal,
    Vibrancy,
    Glass,
}
const BACKDROP: Backdrop = Backdrop::Terminal;

// SAFETY: SkyLight's undocumented per-window blur, signature per the long-standing public
// reverse-engineering of it. A wrong signature would be UB, so it is written once, here.
unsafe extern "C" {
    fn CGSDefaultConnectionForThread() -> *mut c_void;
    fn CGSSetWindowBackgroundBlurRadius(conn: *mut c_void, window: isize, radius: i32) -> i32;
}

/// AppKit's frame: origin bottom-left, y counted UP.
fn rect(x: f64, y: f64, w: f64, h: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(w, h))
}

/// The close button — an `NSButton` whose target is the panel itself, so no custom class and no
/// delegate is needed to make it work.
///
/// `orderOut:` AND NOT `close`. `-close` can reach `applicationShouldTerminateAfterLastWindowClosed:`
/// and take the whole process — including the tray — with it. `orderOut:` only removes the panel
/// from the screen, which is the entire intent: dismissing a welcome card must never quit the
/// menu-bar icon it just introduced. It also takes a sender argument, which is exactly what a
/// button action supplies.
///
/// `xmark.circle.fill` is an SF Symbol (macOS 11+), so it is the system's own glyph at the
/// system's own weight rather than a typed "✕". No symbol means no button rather than a
/// substitute.
fn close_button(parent: &NSView, panel: &NSPanel, frame: NSRect, mtm: MainThreadMarker) {
    let Some(img) = NSImage::imageWithSystemSymbolName_accessibilityDescription(
        &NSString::from_str("xmark.circle.fill"),
        Some(&NSString::from_str("Close")),
    ) else {
        return;
    };
    let target: &AnyObject = panel.as_ref();
    let button = unsafe {
        NSButton::buttonWithImage_target_action(&img, Some(target), Some(sel!(orderOut:)), mtm)
    };
    button.setFrame(frame);
    button.setBordered(false);
    button.setImagePosition(NSCellImagePosition::ImageOnly);
    // PIN TO THE TOP-RIGHT. AppKit's origin is bottom-left, so a fixed frame keeps its distance
    // from the BOTTOM — grow the panel and the button appears to slide down. Flexible left and
    // bottom margins are what make "stays in the corner" mean the corner it was put in.
    button.setAutoresizingMask(
        NSAutoresizingMaskOptions::ViewMinXMargin | NSAutoresizingMaskOptions::ViewMinYMargin,
    );
    parent.addSubview(&button);
}

define_class!(
/// An `NSPanel` that will accept key status.
///
/// A BORDERLESS WINDOW REFUSES TO BECOME KEY. `NSWindow.canBecomeKeyWindow` is documented as true
/// only when the window has a title bar or a resize bar; this panel has neither, so AppKit answered
/// NO and `makeKeyAndOrderFront:` silently did nothing (measured: canBecomeKey=false, isKey=false).
///
/// That is what starved the page of hover. `mouseMoved:` is delivered ONLY to the key window, so
/// with no key window the WKWebView never saw a move event and never forwarded one to JS —
/// measured as 20 move events, every one with a button held, and zero on hover. Dragging worked
/// because `performWindowDragWithEvent:` runs AppKit's own tracking loop, which bypasses all of it.
///
/// Overriding the property is the documented remedy, and it is safe HERE specifically because
/// `NonactivatingPanel` is in the style mask: that bit exists so a panel can take key status
/// WITHOUT activating its owning application — so the card can follow the cursor while the
/// frontmost app keeps its focus.
    #[unsafe(super(NSPanel, NSWindow, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NKWelcomePanel"]
    struct KeyablePanel;

    impl KeyablePanel {
        #[unsafe(method(canBecomeKeyWindow))]
        fn can_become_key_window(&self) -> bool {
            true
        }

    }
);

define_class!(
/// The `Backdrop::Terminal` backdrop: one squircle fill, at the window's own alpha.
///
/// The window server blurs "non-fully-transparent pixels", so whatever alpha this paints IS the
/// shape of the blur — rounding the fill rounds the blur, the shadow and the window together, with
/// nothing clipped and nothing masked.
///
/// A SQUIRCLE, NOT A ROUNDED RECT, and that distinction is the whole reason this is a hand-built
/// path instead of `cornerRadius`. Apple rounds a corner with a cubic whose control points sit at
/// `0.1765 * R` from the corner; a circular arc puts them at `0.4477 * R`. The squircle's controls
/// are far closer in, so it hugs the corner and eases out into a long near-straight tail, while a
/// circle meets the edge at a visible break. NO value of `cornerRadius` produces this curve, and
/// `cornerCurve = .continuous` is a different curve again — measured, it renders straighter than a
/// native window, not smoother.
///
/// The constant is read off the path `tailwind-ios-corners` ships (`index.js`, the mask SVG):
/// `M0 50 C0 8.825 8.825 0 50 0 …` — over a quadrant of 50, the controls sit at 8.825.
    #[unsafe(super(NSView, NSResponder, NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "NKBackdropView"]
    struct BackdropView;

    impl BackdropView {
        #[unsafe(method(drawRect:))]
        fn draw_rect(&self, _dirty: NSRect) {
            if TINT_ALPHA <= 0.0 { return }
            // THE WARP METHOD: we paint the card ourselves and nothing else does. No material, so
            // nothing samples window focus and the colour cannot shift — Warp measures a delta of
            // exactly 0.0 between focused and unfocused for that reason.
            //
            // This only draws cleanly because the WINDOW's background carries alpha 0.01. With a
            // truly clear background the server derived the blur region from THIS path's
            // antialiased edge and treated any non-zero alpha as fully covered, so the corner came
            // out ringed by full-strength backdrop under a fraction of the tint.
            NSColor::colorWithWhite_alpha(TINT_WHITE, TINT_ALPHA).setFill();
            NSBezierPath::bezierPathWithRoundedRect_xRadius_yRadius(self.bounds(), RADIUS, RADIUS).fill();
        }
    }
);

#[allow(non_snake_case)]
impl BackdropView {
    /// `define_class!` does not inherit initialisers, so the superclass one is forwarded by hand —
    /// the same shim Tauri's `window-vibrancy` writes for its own subclass. Dispatched on the
    /// subclass rather than through `super(...)`: we do not override `initWithFrame:`, so the
    /// message finds `NSView`'s implementation anyway.
    fn initWithFrame(this: objc2::rc::Allocated<Self>, frame: NSRect) -> Retained<Self> {
        unsafe { msg_send![this, initWithFrame: frame] }
    }
}

/// A `HasWindowHandle` over an `NSView` WE own.
///
/// `build_as_child` wants that trait and objc2's `NSView` does not implement it — the two crates
/// have no knowledge of each other. `AppKitWindowHandle` is just a pointer to a view, which is
/// exactly what we are holding, so the bridge is a newtype rather than a conversion.
struct ViewHandle(NonNull<c_void>);

impl HasWindowHandle for ViewHandle {
    fn window_handle(&self) -> Result<WindowHandle<'_>, HandleError> {
        let raw = RawWindowHandle::AppKit(AppKitWindowHandle::new(self.0));
        // SAFETY: the view outlives this handle — `welcome` holds the panel, the panel holds the
        // glass, and the glass holds this view, all for as long as the caller keeps the panel.
        Ok(unsafe { WindowHandle::borrow_raw(raw) })
    }
}

/// The card, as a build — not written here. `app/` is a phaze app on the native target
/// (`@madenowhere/phaze-native`); this is its output, the whole directory, embedded at COMPILE
/// time and served by the custom protocol below: `index.html` (the page GENERATED at build, so
/// its copy is in the HTML before any script runs, referencing the entry as a file), the entry
/// and stylesheet under `assets/` (gzip'd by the build, decoded here), and fabric's lazy chunks,
/// which the entry `import()`s by filename at runtime. The directory is committed (see
/// `app/.gitignore`) because `include_dir!` reads it at compile time; a fresh clone cannot
/// build without it.
///
/// Why a protocol and not `with_html`: a page loaded from a string has a **`null` origin** (wry's
/// own docs) — no secure context, so `navigator.gpu` is withheld and the cube cannot render. The
/// card is fabric over WebGPU, so the string delivery was retired (2026-09-04) along with the
/// inlined document it needed.
///
/// What used to be written here moved INTO the app and is still doing the same job: the
/// transparency and `canvastext` rules are in `app/src/styles.css`, the drag handler in
/// `app/src/app.phaze` (`drag()` from `@madenowhere/phaze-native/wry`).
#[cfg(feature = "embed")]
static DIST: include_dir::Dir<'_> = include_dir::include_dir!("$CARGO_MANIFEST_DIR/app/dist");

/// A DEV BUILD IS THE CRATE WITHOUT `embed` (Tauri's `custom-protocol` model, Cargo.toml
/// [features]). It embeds nothing — `app/dist` need not exist — and loads the panel from the
/// Vite dev server URL that build.rs bakes in from `PHAZE_NATIVE_DEV_URL`, which `phaze native
/// dev` sets before `cargo run --no-default-features`. Baked at COMPILE time, so a release
/// binary has no dev URL to be pointed at, and a dev build without one does not compile.
/// Which API the binary talks to is a different thing entirely: `--url` (main.rs), at runtime,
/// as always.
#[cfg(not(feature = "embed"))]
const DEV_URL: Option<&str> = option_env!("PHAZE_NATIVE_DEV_URL");
#[cfg(not(feature = "embed"))]
const _: () = assert!(
    DEV_URL.is_some(),
    "a build without the `embed` feature is a dev build and needs PHAZE_NATIVE_DEV_URL (`phaze native dev` sets it)"
);

/// `phaze native dev` already waits for the dev server's port before `cargo run`; this second
/// wait covers a bare `cargo run --no-default-features` with the URL set by hand. Every address
/// the host name resolves to is tried (Vite may be listening on `::1`, `127.0.0.1`, or both),
/// every 500 ms, for up to 30 s; then the URL is loaded anyway, so a stuck dev server shows as
/// WebKit's own error rather than a panel that never appears. Dev-only, so blocking the main
/// thread here costs nothing that matters.
#[cfg_attr(feature = "embed", allow(dead_code))]
fn wait_for_dev(origin: &str) {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::{Duration, Instant};
    let hostport = origin.trim_start_matches("http://");
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().unwrap_or(80)),
        None => (hostport, 80),
    };
    let addrs: Vec<_> = (host, port).to_socket_addrs().map(|a| a.collect()).unwrap_or_default();
    let started = Instant::now();
    let mut said = false;
    while !addrs.iter().any(|a| TcpStream::connect_timeout(a, Duration::from_millis(500)).is_ok()) {
        if started.elapsed() > Duration::from_secs(30) {
            eprintln!("[panel] {origin} is not answering after 30 s — loading it anyway");
            return;
        }
        if !said {
            eprintln!("[panel] waiting for {origin} …");
            said = true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    eprintln!("[panel] dev: loading {origin} — the embedded build is not used");
}

/// Fill `parent` with a `WKWebView` rendering the panel app out of `DIST` over `nk://`.
///
/// THE CARD, since 2026-09-06. It began as a test path behind a flag, beside the original
/// NSTextField labels, to check that HTML over `NSGlassEffectView` keeps the material — a
/// webview that paints its own background would defeat the panel's whole appearance. It does
/// keep it (`with_transparent`), and the type renders the same as AppKit's, so the labels and
/// the flag are gone.
///
/// DEV IS A BUILD, NOT A SWITCH. `phaze native dev` (app/package.json `wry:dev`) starts the panel's
/// Vite dev server, waits for its port, and runs this crate without the `embed` feature with the
/// dev URL baked in (`DEV_URL` above) — edits reload in the webview, and nothing is rebuilt,
/// bundled or signed to see them. In that build the protocol handler is not registered and the
/// allowlist widens by exactly the dev origin. The embedded build is what ships, so `phaze native
/// build` remains the proof before a commit.
fn web_card(parent: &NSView, panel: &Retained<NSPanel>, mtm: MainThreadMarker) -> Option<WebView> {
    let view = NonNull::new(parent as *const NSView as *mut c_void)?;
    // WEAK, NOT RETAINED. The webview lives inside the panel's view tree, so a handler holding
    // the panel strongly would close the loop — panel → glass → view → webview → handler →
    // panel — and neither refcount would ever reach zero. `load()` returning None is the honest
    // answer once the panel is gone.
    let weak = Weak::from_retained(panel);
    #[cfg(feature = "embed")]
    let dev: Option<&'static str> = None;
    #[cfg(not(feature = "embed"))]
    let dev: Option<&'static str> = DEV_URL.map(|u| u.trim_end_matches('/'));

    let builder = WebViewBuilder::new()
        .with_transparent(true)
        // NO DISK RESIDUE. WebKit's default data store is persistent: this panel had written
        // `~/Library/WebKit/ai.neuralkit.cli/WebsiteData` and a 1 MB WebKit network cache under
        // `~/Library/Caches/ai.neuralkit.cli` — for a page that stores nothing and is served out
        // of the binary. A non-persistent store keeps all of that in the process.
        .with_incognito(true)
        // THE ALLOWLIST, AT THE NAVIGATION LEVEL. The protocol handler already answers 404 for a
        // path it does not have; this refuses any other ORIGIN, so no link and no `location`
        // assignment can turn the card into a browser. wry's default allows every navigation.
        // In dev the one extra origin is the dev server's.
        .with_navigation_handler(move |url| {
            url.starts_with("nk://localhost") || dev.is_some_and(|o| url.starts_with(o))
        })
        // A real Web Inspector (right-click → Inspect): wry has it on in debug builds, and a
        // release build gets it only with `--features panel-devtools` (see Cargo.toml).
        .with_devtools(cfg!(any(debug_assertions, feature = "panel-devtools")))
        .with_ipc_handler(move |req| {
            if req.body() != "drag" {
                // Anything that is not the drag ping is a diagnostic from the page — its channel
                // back to the process in a build without the inspector.
                eprintln!("[panel] {}", req.body());
                return
            }
            // The event AppKit is dispatching right now IS the mousedown the page just saw, which
            // is exactly what `performWindowDragWithEvent:` wants.
            let (Some(panel), Some(event)) = (weak.load(), NSApplication::sharedApplication(mtm).currentEvent())
            else {
                return
            };
            panel.performWindowDragWithEvent(&event);
        });

    // A REAL ORIGIN, WITHOUT A PORT. WebGPU is SECURE-CONTEXT gated, so a string-loaded document
    // (`null` origin) never gets `navigator.gpu`, no matter what WebKit's own WebGPU switch says
    // (measured: the switch was already on). W3C Secure Contexts decides trustworthiness on the
    // HOST, not only the scheme — `127.0.0.0/8`, `::1`, `localhost` and `*.localhost` all qualify
    // — and wry's macOS custom protocol serves at `<scheme>://localhost`. So the build over
    // `nk://localhost` is a secure context WITHOUT a local port, a certificate, or any private
    // API. Measured: the cube renders.
    #[cfg(feature = "embed")]
    let builder = builder
            .with_custom_protocol("nk".into(), |_id, req| {
                // Serve the whole build, not just the document. Fabric code-splits its engine —
                // the entry runs `import("./sdfEngine-….js")`, which reaches `sdf.wgsl` in turn —
                // so a handler that answered every path with the HTML would hand a <script> a
                // document and fail with a syntax error.
                // The document must reference the entry AS A FILE, never inline it: the lazy
                // chunks import the entry BY FILENAME (`sdfEngine` → `./phaze-native-<hash>.js`),
                // so an inlined entry would load twice, as two module instances, and its
                // top-level `render()` would run twice. Measured as the card drawn twice
                // (`c8a4a61`).
                let path = req.uri().path().trim_start_matches('/');
                let path = if path.is_empty() { "index.html" } else { path };
                let mime = match path.rsplit('.').next() {
                    Some("html") => "text/html",
                    Some("js") => "text/javascript",
                    Some("css") => "text/css",
                    Some("wasm") => "application/wasm",
                    _ => "application/octet-stream",
                };
                // Static precompression: the build (`native({ compress })`) replaces each
                // `assets/*.js|css` with `<name>.gz` or `<name>.br`, so the directory names its
                // decoder. Raw first — documents are never compressed — then by suffix. WebKit
                // does NOT decode a scheme-handler body — measured: a `Content-Encoding: br`
                // response reached the parser as raw bytes — so the decode happens here and
                // the response carries no encoding header.
                let found = DIST
                    .get_file(path)
                    .map(|f| (f, ""))
                    .or_else(|| DIST.get_file(format!("{path}.gz")).map(|f| (f, "gz")))
                    .or_else(|| DIST.get_file(format!("{path}.br")).map(|f| (f, "br")));
                match found {
                    // Vite emits `<script type="module" crossorigin>`, so the entry is fetched in
                    // CORS mode. Same origin, but a custom scheme with no ACAO header can still be
                    // refused — and the failure mode is a blank panel, not an error.
                    Some((f, enc)) => {
                        use std::io::Read;
                        let started = std::time::Instant::now();
                        let mut out = Vec::with_capacity(f.contents().len() * 4);
                        let decoded: Result<std::borrow::Cow<'static, [u8]>, String> = match enc {
                            "gz" => flate2::read::GzDecoder::new(f.contents())
                                .read_to_end(&mut out)
                                .map(|_| std::borrow::Cow::Owned(out))
                                .map_err(|e| format!("gunzip {path}.gz: {e}")),
                            #[cfg(feature = "panel-brotli")]
                            "br" => brotli_decompressor::Decompressor::new(f.contents(), 4096)
                                .read_to_end(&mut out)
                                .map(|_| std::borrow::Cow::Owned(out))
                                .map_err(|e| format!("brotli {path}.br: {e}")),
                            #[cfg(not(feature = "panel-brotli"))]
                            "br" => Err(format!(
                                "{path}.br: the panel was built with `compress: 'brotli'` but this binary has no brotli decoder — build with `--features panel-brotli`, or rebuild the panel with `compress: 'gzip'`"
                            )),
                            _ => Ok(std::borrow::Cow::Borrowed(f.contents())),
                        };
                        match decoded {
                            Ok(body) => {
                                if !enc.is_empty() && std::env::var_os("NEURALKIT_PANEL_TIMING").is_some() {
                                    eprintln!("[panel] {enc} {path} {}B → {}B in {:?}", f.contents().len(), body.len(), started.elapsed());
                                }
                                wry::http::Response::builder()
                                    .header(wry::http::header::CONTENT_TYPE, mime)
                                    // The exact origin, not `*` — measured as `location.origin`
                                    // under the custom scheme.
                                    .header(wry::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, "nk://localhost")
                                    .body(body)
                                    .unwrap()
                            }
                            Err(why) => {
                                // Loud: served as-is, compressed bytes reach the parser and the
                                // panel is blank with nothing on stderr.
                                eprintln!("[panel] {why}");
                                wry::http::Response::builder()
                                    .status(500)
                                    .body(std::borrow::Cow::Owned(why.into_bytes()))
                                    .unwrap()
                            }
                        }
                    }
                    None => {
                        // Loud on purpose. A chunk the build's shaker stripped (a fabric
                        // `import()` behind a condition this card's source never turns on)
                        // that the page asks for anyway lands here — the only sign would
                        // otherwise be a feature silently missing from the card.
                        eprintln!("[panel] 404 {path} — not in the embedded build (stripped by the shaker, yet requested?)");
                        wry::http::Response::builder()
                            .status(404)
                            .body(std::borrow::Cow::Borrowed(&b"not found"[..]))
                            .unwrap()
                    }
                }
            });
    let builder = builder.with_url(match dev {
        Some(origin) => {
            wait_for_dev(origin);
            format!("{origin}/")
        }
        None => "nk://localhost".to_string(),
    });

    builder
        .with_bounds(Rect {
            position: dpi::LogicalPosition::new(0.0, 0.0).into(),
            size: dpi::LogicalSize::new(W, H).into(),
        })
        .build_as_child(&ViewHandle(view))
        .ok()
        .inspect(|wv| {
            // `with_bounds` is a one-shot placement; without an autoresizing mask the webview keeps
            // the launch rect and the page is clipped (or floats) the moment the panel is dragged.
            use wry::WebViewExtMacOS;
            let v: &NSView = unsafe { &*(Retained::as_ptr(&wv.webview()) as *const NSView) };
            v.setAutoresizingMask(
                NSAutoresizingMaskOptions::ViewWidthSizable | NSAutoresizingMaskOptions::ViewHeightSizable,
            );

        })
}

/// Show the panel, handing back the owner.
///
/// THE CALLER MUST HOLD IT. `Retained` is ARC, so dropping the returned value releases the panel
/// and it disappears — which is the trade for no longer leaking one per run. The tray parks it
/// beside its `TrayIcon` for exactly this reason.
///
/// `anchor` is the tray icon's screen position when it is known; the panel hangs below it,
/// centred on the icon. Without one it lands centred-ish, which is the honest fallback for a
/// tray that has not drawn yet.
pub fn welcome(anchor: Option<(f64, f64)>) -> Option<(Retained<NSPanel>, Option<WebView>)> {
    // AppKit is main-thread-only, and this is the proof of it rather than the assumption. The
    // tray's event loop runs here, so it always succeeds; asking is what makes the rest safe.
    let mtm = MainThreadMarker::new()?;

    // AppKit's origin is bottom-left, so "below the icon" is a SUBTRACTION from the icon's y.
    // With no anchor the rect here is a placeholder — `center()` below replaces it.
    let (x, y) = match anchor {
        Some((ix, iy)) => (ix - W / 2.0, iy - H - 8.0),
        None => (0.0, 0.0),
    };

    // TITLED, AND THAT IS WHAT ROUNDS THE CORNERS. A borderless window has NO SHAPE as far as the
    // window server is concerned — it is a square frame that happens to contain transparent pixels.
    // That is fine for the shadow, which is derived from content alpha, but the server-side blur is
    // composited over the FRAME, so it fills the corners straight back in no matter what shape the
    // content paints. Measured: a squircle fill of extent 24 rendered a corner of 9 with the blur
    // on, and the correct squircle with it off.
    //
    // iTerm2 is the proof by counter-example — with "No Title Bar" its corners go square, and that
    // is a long-standing open issue there, not a bug we can out-draw. Every translucent terminal
    // with round corners has a real titlebar; the SYSTEM shapes those windows, and the blur is
    // clipped because the server knows the shape.
    //
    // So the titlebar is present and invisible: `FullSizeContentView` lets our content run under
    // it, `titlebarAppearsTransparent` stops it painting, `TitleVisibility::Hidden` drops the text,
    // and the three traffic lights are hidden — the panel already draws its own close button.
    // `NonactivatingPanel` still keeps focus with the frontmost app.
    //
    // `Resizable` gives the window's edges the resize hit-area and cursors. Everything below — the
    // backdrop, its contentView, the webview — has to be told to follow, or the window grows while
    // its contents stay the launch size.
    let panel: Retained<KeyablePanel> = unsafe {
        msg_send![
            KeyablePanel::alloc(mtm),
            initWithContentRect: rect(x, y, W, H),
            styleMask: NSWindowStyleMask::Titled
                | NSWindowStyleMask::FullSizeContentView
                | NSWindowStyleMask::NonactivatingPanel
                | NSWindowStyleMask::Resizable,
            backing: NSBackingStoreType::Buffered,
            defer: false,
        ]
    };
    let panel: Retained<NSPanel> = panel.into_super();

    // WE ALLOCATED THIS PANEL, SO WE OWN IT. AppKit's default is `releasedWhenClosed = YES`: a
    // `-close` would deallocate it out from under the `Retained` handed back. Nothing reaches
    // `-close` today — every path here is `orderOut:` — but that is a property of the current
    // wiring, not a promise.
    unsafe { panel.setReleasedWhenClosed(false) };

    // TITLED PURELY FOR THE SHADOW. A borderless window gets no shadow of its own — macOS derives
    // one from whatever alpha the content paints, which for a translucent card is far weaker than
    // every window beside it. A titled window gets the SYSTEM shadow, the same one Warp and every
    // other app has. The titlebar itself never appears: `FullSizeContentView` puts our content
    // under it, the bar is transparent, the title text hidden, and the traffic lights hidden
    // because the panel draws its own close button.
    panel.setTitlebarAppearsTransparent(true);
    panel.setTitleVisibility(NSWindowTitleVisibility::Hidden);
    for kind in [
        NSWindowButton::CloseButton,
        NSWindowButton::MiniaturizeButton,
        NSWindowButton::ZoomButton,
    ] {
        if let Some(b) = panel.standardWindowButton(kind) {
            b.setHidden(true);
        }
    }

    // ON TOP BY LEVEL, which is AppKit's only supported way to sit above OTHER APPS' windows.
    // There are eleven levels — Normal, Floating, Submenu, TornOffMenu, MainMenu, Status,
    // ModalPanel, PopUpMenu, ScreenSaver, Dock, FullScreenMode — and nothing else does this: the
    // collection behaviours govern spaces, full-screen and cycling, not cross-app z-order.
    //
    // An observer that re-ordered the window on app deactivation was tried instead, to test whether
    // the LEVEL rather than app-activation drives the inactive glass. It was machinery around an
    // API that already exists, and the glass degraded either way.
    panel.setFloatingPanel(true);
    panel.setLevel(NSFloatingWindowLevel);
    // KEY ONLY WHEN IT NEEDS TO BE. Without this, clicking the card makes it key and resigns the
    // frontmost app's — the same focus theft `NonactivatingPanel` prevents on show, arriving one
    // click later.
    panel.setBecomesKeyOnlyIfNeeded(true);
    // HOVER IS OPT-IN. An NSWindow does NOT deliver `mouseMoved:` unless asked — the default is
    // off because most windows only care about clicks. Without this the page sees mousemove ONLY
    // while a button is held (a drag is tracked separately), which reads as "the camera follows
    // the pointer, but only when I drag the panel".
    panel.setAcceptsMouseMovedEvents(true);
    // FOLLOWS THE PERSON ACROSS SPACES. A welcome card left behind on the desktop it opened on is
    // a card nobody reads; joining all spaces is what a menu-bar accessory's window should do.
    panel.setCollectionBehavior(NSWindowCollectionBehavior::CanJoinAllSpaces);

    // THE PANEL MUST BE CLEAR AND NON-OPAQUE, or it paints a square fill behind the glass and the
    // corners come back — measured, the first cut coloured the window and drew a square panel.
    // The glass view below is what carries the material and the shape.
    panel.setOpaque(false);
    panel.setHasShadow(true);
    // ALPHA 0.01, NOT CLEAR — and that distinction is the whole CGS recipe. Applied ONLY when the
    // CGS blur is on: a material blurs for itself, and this veil would just sit behind it dulling
    // it, which is what stopped `Glass` looking like glass. The server blurs
    // "non-fully-transparent pixels", so with a truly clear background the only non-zero alpha in
    // the window is our CONTENT, and the blur region gets derived from the content's antialiased
    // edge. It treats any non-zero alpha as fully covered, so a 10%-covered edge pixel receives
    // 100% of the blurred backdrop under 10% of the tint — measured as a bright rim, interior
    // luminance 133 against 187-192 at the corner.
    //
    // A hair of alpha across the whole rect makes the blur uniform, and the SHAPE then comes from
    // AppKit — here `NSGlassEffectView`'s own `cornerRadius` plus `clipsToBounds`. It has to: CGS
    // has no window-shape call at all (CGSPrivate.h carries only `CGSSetWindowTransform`, which is
    // affine). Terminal.app uses exactly 0.01, and it is the documented form of the recipe.
    if BLUR_RADIUS > 0 {
        panel.setBackgroundColor(Some(&NSColor::colorWithWhite_alpha(0.0, 0.01)));
    } else {
        panel.setBackgroundColor(Some(&NSColor::clearColor()));
    }
    // DRAGGABLE BY ITS BODY. There is no titlebar to grab, so the background IS the handle —
    // AppKit does the whole drag, including the screen-edge behaviour, from this one flag.
    panel.setMovableByWindowBackground(true);

    // CENTRE IT — `center()` is AppKit's own placement, horizontally centred and slightly ABOVE
    // true centre, which is where macOS puts a dialog. Doing the arithmetic by hand off
    // `NSScreen` would land it lower and would have to guess which screen. The literal rect
    // passed to the initialiser above was a placeholder; this replaces it.
    if anchor.is_none() {
        panel.center();
    }

    // NO APPEARANCE PIN. Naming Aqua flattened the glass into a solid light surface — a forced
    // appearance stops the material sampling what is behind it. Following the system is what
    // keeps it reading as glass, and `labelColor` follows the same way so text stays legible in
    // either mode.

    // LIQUID GLASS — `NSGlassEffectView`, macOS 26 (AppKit header dated 2025).
    //
    // AND NO MASK. This is the whole reason to use it over `NSVisualEffectView`: the glass owns
    // its own `cornerRadius`, so the shape is the view's, not a clip applied on top of it.
    // Rounding a visual-effect view meant `setMasksToBounds:` on its layer inside a square
    // window — and a window's shadow is computed from the WINDOW, never from a layer mask, which
    // is exactly the glitched corner shadow that kept showing up. Nothing here masks anything.
    //
    // THE LABELS GO IN A PLAIN NSView set as the glass's `contentView`, not added to it as bare
    // subviews. The header is explicit: it "only guarantees the `contentView` will be placed
    // inside the glass effect; arbitrary subviews aren't guaranteed specific behavior with
    // regard to z-order".
    let frame = rect(0.0, 0.0, W, H);
    let inner = NSView::initWithFrame(NSView::alloc(mtm), frame);
    inner.setAutoresizingMask(
        NSAutoresizingMaskOptions::ViewWidthSizable | NSAutoresizingMaskOptions::ViewHeightSizable,
    );

    match BACKDROP {
        // WARP / iTERM2 / TERMINAL.APP: we paint the backdrop, the server blurs behind it.
        Backdrop::Terminal => {
            let back = BackdropView::initWithFrame(BackdropView::alloc(mtm), frame);
            back.setAutoresizingMask(
                NSAutoresizingMaskOptions::ViewWidthSizable
                    | NSAutoresizingMaskOptions::ViewHeightSizable,
            );
            back.addSubview(&inner);
            panel.setContentView(Some(&back));
        }
        // TAURI'S ANSWER: a system material. No blur radius exists in this mode, by construction.
        Backdrop::Vibrancy => {
            let vev = NSVisualEffectView::initWithFrame(NSVisualEffectView::alloc(mtm), frame);
            vev.setMaterial(MATERIAL);
            // BEHIND the window — blend with what is on screen behind the panel, not with our own
            // content, which is what makes it read as a translucent card rather than a tinted box.
            vev.setBlendingMode(NSVisualEffectBlendingMode::BehindWindow);
            // Pin the appearance. The default is FollowsWindowActiveState, which is exactly the
            // clear-on-focus / frosted-off-focus shift the glass cannot escape.
            vev.setState(NSVisualEffectState::Active);
            // NSVisualEffectView's OWN `setCornerRadius:` — undocumented, but it is what Tauri's
            // `window-vibrancy` calls (macos/internal.rs:47). It rounds the EFFECT, so the blur and
            // the window shadow follow the shape; a CALayer `cornerRadius` is view-local and frays.
            unsafe { let _: () = msg_send![&*vev, setCornerRadius: RADIUS]; };
            vev.setAutoresizingMask(
                NSAutoresizingMaskOptions::ViewWidthSizable
                    | NSAutoresizingMaskOptions::ViewHeightSizable,
            );
            // NSVisualEffectView has no `contentView` slot — content is an ordinary subview.
            vev.addSubview(&inner);
            panel.setContentView(Some(&vev));
        }
        // MACOS 26 LIQUID GLASS. Newest material; cannot pin its appearance.
        Backdrop::Glass => {
            let glass = NSGlassEffectView::initWithFrame(NSGlassEffectView::alloc(mtm), frame);
            // Regular is the DENSE variant — Liquid Glass is designed to sit under content, so it
            // reads as a dark slab rather than as glass. Clear is the one that stays transparent.
            glass.setStyle(NSGlassEffectViewStyle::Regular);
            glass.setCornerRadius(RADIUS);
            // NOT a layer mask — `clipsToBounds` is an NSView property. Without it the rounded
            // material still paints its square bounds, showing as a thin dark box under `Regular`.
            glass.setClipsToBounds(true);
            glass.setTintColor(Some(&NSColor::colorWithWhite_alpha(TINT_WHITE, TINT_ALPHA)));
            // The header is explicit that the contentView is the supported slot: it "only
            // guarantees the `contentView` will be placed inside the glass effect; arbitrary
            // subviews aren't guaranteed specific behavior with regard to z-order".
            glass.setContentView(Some(&inner));
            panel.setContentView(Some(&glass));
        }
    }
    // Small enough to still be a card, large enough that the glass corners never overlap.
    panel.setContentMinSize(NSSize::new(W / 2.0, H / 2.0));

    // THE PHAZE CARD FILLS THE MIDDLE. The window, the glass and the close button are AppKit;
    // what sits inside is the panel app in a WKWebView. Until 2026-09-06 four NSTextField labels
    // were the default and the webview a flag (`NEURALKIT_PANEL_WEB`), kept so the two could be
    // compared rather than argued about. Measured side by side at 4×: the same system font at the
    // same sizes renders the same over the glass — the only visible text difference was the
    // stylesheet's own `opacity: .8` on the subtitle. So the labels went, and with them the flag.
    let web = web_card(&inner, &panel, mtm);
    // ON TOP OF EITHER. Added after the webview so it stays above it in z-order — a subview added
    // first would end up behind the WKWebView and be unclickable.
    // Top-right, inset by half the padding so it sits in the corner rather than in the text
    // column. y is measured UP, so the top edge is H minus the button's own height.
    const BTN: f64 = 22.0;
    close_button(&inner, &panel, rect(W - PAD / 2.0 - BTN, H - PAD / 2.0 - BTN, BTN, BTN), mtm);

    // KEY, BUT NOT ACTIVE — and those are different things. `mouseMoved:` is delivered ONLY to
    // the KEY window (Apple: "the window will receive mouse-moved events when it is the key
    // window"), so `orderFrontRegardless` — which shows without making key — left the page with
    // no hover at all. The tell was that the camera tracked ONLY while the window was being
    // dragged: `performWindowDragWithEvent:` runs AppKit's own tracking loop, which delivers
    // events irrespective of key status.
    //
    // `makeKeyAndOrderFront:` activating the app is a property of a normal NSWindow.
    // `NonactivatingPanel` exists precisely so a panel can take key WITHOUT activating its owner,
    // which is the whole reason that bit is in the style mask.
    if BLUR_RADIUS > 0 {
        // Window must exist and be non-opaque before this lands.
        unsafe {
            CGSSetWindowBackgroundBlurRadius(
                CGSDefaultConnectionForThread(),
                panel.windowNumber(),
                BLUR_RADIUS,
            );
        }
    }

    panel.makeKeyAndOrderFront(None);


    Some((panel, web))
}
