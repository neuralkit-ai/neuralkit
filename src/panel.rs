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
use objc2::runtime::AnyObject;
use objc2::{sel, MainThreadMarker, MainThreadOnly};
use objc2_app_kit::{
    NSApplication, NSBackingStoreType, NSButton, NSCellImagePosition, NSColor, NSFloatingWindowLevel, NSFont,
    NSGlassEffectView, NSGlassEffectViewStyle, NSImage, NSPanel, NSTextField, NSView,
    NSWindowCollectionBehavior, NSWindowStyleMask,
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
/// macOS 26 rounds windows noticeably more than Big Sur–Sequoia did, and a 10pt panel next to a
/// system window reads as the odd one out. There is no public API for the system value, so this
/// is tuned by eye against a real window rather than derived.
const RADIUS: f64 = 12.0 * SCALE;
const W: f64 = 360.0 * SCALE;
const H: f64 = 140.0 * SCALE;
/// The left/right inset, and the width every label gets.
const PAD: f64 = 12.0 * SCALE;

/// AppKit's frame: origin bottom-left, y counted UP.
fn rect(x: f64, y: f64, w: f64, h: f64) -> NSRect {
    NSRect::new(NSPoint::new(x, y), NSSize::new(w, h))
}

/// One label, added to `parent`.
///
/// `labelWithString:` IS THE DE-CONTROLLING. A bare `NSTextField` is an editable control that
/// paints an opaque background over whatever is behind it; this constructor hands back one
/// already non-editable, non-selectable, unbezeled and transparent — four setters this file used
/// to spell out by hand, and one bug (the white box) it used to have to explain.
fn label(parent: &NSView, text: &str, size: f64, bold: bool, frame: NSRect, mtm: MainThreadMarker) {
    let field = NSTextField::labelWithString(&NSString::from_str(text), mtm);
    field.setFrame(frame);
    let font = if bold {
        NSFont::boldSystemFontOfSize(size)
    } else {
        NSFont::systemFontOfSize(size)
    };
    field.setFont(Some(&font));
    // `labelColor` is SEMANTIC — it follows light and dark mode, where a literal white or black
    // would be wrong in one of them.
    field.setTextColor(Some(&NSColor::labelColor()));
    parent.addSubview(&field);
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
    parent.addSubview(&button);
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

/// The card, as markup — now BUILT rather than written here. `panel/` is a phaze app; this is its
/// output. Inline rather than a file or a local server, for the same reasons as before: it ships
/// in the binary, has no path to get wrong, and `with_html` is the whole delivery mechanism.
///
/// `panel/dist/panel.html` is ONE self-contained file because `panel/inline.mjs` folds the module
/// and the stylesheet back into the document after `vite build`. That is not tidiness — `with_html`
/// hands WKWebView a string with NO BASE URL, so anything left as a `src`/`href` has nothing to
/// resolve against and silently never loads. The file is committed (see `panel/.gitignore`)
/// because `include_str!` reads it at COMPILE time; a fresh clone cannot build without it.
///
/// THE TRADE, from wry's own docs: a page loaded from a string has a **`null` origin** — no
/// localStorage, no fetch, no relative URLs. This card needs none of them. A panel that grows to
/// need any wants `with_custom_protocol` + `with_url("wry://localhost")` instead — the same build
/// output, served under a real origin, which is what Tauri does.
///
/// What used to be written here moved INTO the app and is still doing the same job: the
/// transparency and `canvastext` rules are in `panel/src/styles.css`, the drag handler in
/// `panel/index.html`.
const PANEL: &str = include_str!("../panel/dist/panel.html");

/// Fill `parent` with a `WKWebView` rendering `PANEL`.
///
/// A TEST PATH, not the default — `NEURALKIT_PANEL_WEB=1` picks it, and the NSTextField labels
/// stay exactly as they were so the two can be compared side by side. What it is testing is
/// whether HTML over `NSGlassEffectView` keeps the material, since a webview that paints its own
/// background would defeat the panel's whole appearance.
fn web_card(parent: &NSView, panel: &Retained<NSPanel>, mtm: MainThreadMarker) -> Option<WebView> {
    let view = NonNull::new(parent as *const NSView as *mut c_void)?;
    // WEAK, NOT RETAINED. The webview lives inside the panel's view tree, so a handler holding
    // the panel strongly would close the loop — panel → glass → view → webview → handler →
    // panel — and neither refcount would ever reach zero. `load()` returning None is the honest
    // answer once the panel is gone.
    let weak = Weak::from_retained(panel);
    WebViewBuilder::new()
        .with_transparent(true)
        .with_ipc_handler(move |req| {
            if req.body() != "drag" {
                return
            }
            // The event AppKit is dispatching right now IS the mousedown the page just saw, which
            // is exactly what `performWindowDragWithEvent:` wants.
            let (Some(panel), Some(event)) = (weak.load(), NSApplication::sharedApplication(mtm).currentEvent())
            else {
                return
            };
            panel.performWindowDragWithEvent(&event);
        })
        .with_html(PANEL)
        .with_bounds(Rect {
            position: dpi::LogicalPosition::new(0.0, 0.0).into(),
            size: dpi::LogicalSize::new(W, H).into(),
        })
        .build_as_child(&ViewHandle(view))
        .ok()
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

    // Borderless is the EMPTY style set, so `NonactivatingPanel` alone is the whole mask: no
    // titlebar, and no focus taken from the frontmost app when it appears.
    let panel = NSPanel::initWithContentRect_styleMask_backing_defer(
        NSPanel::alloc(mtm),
        rect(x, y, W, H),
        NSWindowStyleMask::NonactivatingPanel,
        NSBackingStoreType::Buffered,
        false,
    );

    // WE ALLOCATED THIS PANEL, SO WE OWN IT. AppKit's default is `releasedWhenClosed = YES`: a
    // `-close` would deallocate it out from under the `Retained` handed back. Nothing reaches
    // `-close` today — every path here is `orderOut:` — but that is a property of the current
    // wiring, not a promise.
    unsafe { panel.setReleasedWhenClosed(false) };
    // Above ordinary windows, below the menu bar. `setFloatingPanel:` is the panel-native way to
    // say it; the level is the blunt instrument underneath, set too so the intent is explicit.
    panel.setFloatingPanel(true);
    panel.setLevel(NSFloatingWindowLevel);
    // KEY ONLY WHEN IT NEEDS TO BE. Without this, clicking the card makes it key and resigns the
    // frontmost app's — the same focus theft `NonactivatingPanel` prevents on show, arriving one
    // click later.
    panel.setBecomesKeyOnlyIfNeeded(true);
    // FOLLOWS THE PERSON ACROSS SPACES. A welcome card left behind on the desktop it opened on is
    // a card nobody reads; joining all spaces is what a menu-bar accessory's window should do.
    panel.setCollectionBehavior(NSWindowCollectionBehavior::CanJoinAllSpaces);

    // THE PANEL MUST BE CLEAR AND NON-OPAQUE, or it paints a square fill behind the glass and the
    // corners come back — measured, the first cut coloured the window and drew a square panel.
    // The glass view below is what carries the material and the shape.
    panel.setOpaque(false);
    panel.setHasShadow(true);
    panel.setBackgroundColor(Some(&NSColor::clearColor()));
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
    let glass = NSGlassEffectView::initWithFrame(NSGlassEffectView::alloc(mtm), frame);
    // Regular is the DENSE variant — Liquid Glass is designed to sit under content, so it reads
    // as a dark slab rather than as glass. Clear is the one that stays transparent.
    glass.setStyle(NSGlassEffectViewStyle::Clear);
    glass.setCornerRadius(RADIUS);
    glass.setContentView(Some(&inner));
    panel.setContentView(Some(&glass));

    // y counts UP, so the title sits highest and the commands sit near the floor.
    // TYPE STAYS AT SYSTEM SIZE while the panel scales. Doubling the point size would make the
    // panel bigger without making it more readable — macOS text is sized against the system
    // font, not against its container.
    // TWO WAYS TO FILL THE SAME CARD, so they can be compared rather than argued about.
    // `NEURALKIT_PANEL_WEB=1` renders the content as HTML in a WKWebView; without it the
    // NSTextField labels run exactly as before. The window, the glass and the close button are
    // shared by both — only what fills the middle differs.
    let web = if std::env::var_os("NEURALKIT_PANEL_WEB").is_some() {
        web_card(&inner, &panel, mtm)
    } else {
        let line = W - PAD * 2.0;
        label(&inner, "Neuralkit CLI is installed", 15.0, true,
            rect(PAD, H - 42.0 * SCALE, line, 22.0), mtm);
        label(&inner, "The neuralkit command is now on your PATH.", 12.0, false,
            rect(PAD, H - 66.0 * SCALE, line, 18.0), mtm);
        label(&inner, "neuralkit auth login     sign in", 11.5, false,
            rect(PAD, 36.0 * SCALE, line, 16.0), mtm);
        label(&inner, "neuralkit --help         everything else", 11.5, false,
            rect(PAD, 16.0 * SCALE, line, 16.0), mtm);
        None
    };
    // ON TOP OF EITHER. Added after the webview so it stays above it in z-order — a subview added
    // first would end up behind the WKWebView and be unclickable.
    // Top-right, inset by half the padding so it sits in the corner rather than in the text
    // column. y is measured UP, so the top edge is H minus the button's own height.
    const BTN: f64 = 22.0;
    close_button(&inner, &panel, rect(W - PAD / 2.0 - BTN, H - PAD / 2.0 - BTN, BTN, BTN), mtm);

    // `orderFrontRegardless` AND NOT `makeKeyAndOrderFront:`. The latter activates the app, which
    // is the focus theft this whole panel style is arranged to avoid; this shows the card and
    // leaves the frontmost app frontmost.
    panel.orderFrontRegardless();
    Some((panel, web))
}
