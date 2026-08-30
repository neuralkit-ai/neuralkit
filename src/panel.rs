//! A first-run panel — a small borderless window with words in it.
//!
//! MODELLED ON `phaze_auth::system_passkey`, WHICH ALREADY BUILDS AN NSWindow. That one is 1×1
//! and offscreen because it exists only to be a presentation anchor; this one is visible and
//! has subviews. Everything else is the same shape, deliberately: `initWithContentRect:
//! styleMask:backing:defer:` with the rect as `[f64; 4]`, styleMask 0 for borderless, backing 2
//! for buffered, and `makeKeyAndOrderFront:` to show it.
//!
//! NO `tao` HERE, AND THAT IS THE POINT. An earlier cut built the window with `WindowBuilder`
//! and then reached through `ns_view()` for the text — which works, but ties the panel to an
//! `EventLoopWindowTarget` it does not otherwise need, and mixes two idioms to do one job. The
//! codebase already had the answer: AppKit makes windows, and `tao` is only here for the tray's
//! event loop.
//!
//! THE OBJC IDIOM IS DUPLICATED ON PURPOSE. `phaze-auth` carries its own copy in `enclave` and
//! again in `system_passkey` — that file's header names the choice, "the same
//! transmute-per-signature `objc_msgSend` idiom `enclave` uses". Its helpers are private to
//! those modules, so a third copy here costs fifteen lines and saves editing phaze core.
//!
//! EVERY STEP IS BEST-EFFORT. A panel that fails to draw must never stop the icon appearing, so
//! nothing here returns an error — the worst case is no window.

use std::ffi::{c_void, CStr};

type Id = *const c_void;
type Sel = *const c_void;

// AppKit for the window and its views; objc for the runtime itself. `system_passkey` links
// only `objc` because AuthenticationServices comes in through its own attribute — this file
// needs NSWindow, NSGlassEffectView, NSView, NSTextField, NSButton, NSImage, NSColor and NSFont,
// all of which are AppKit.
#[link(name = "AppKit", kind = "framework")]
unsafe extern "C" {}

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const i8) -> Id;
    fn sel_registerName(name: *const i8) -> Sel;
    fn objc_msgSend();
}

unsafe fn cls(name: &CStr) -> Id {
    unsafe { objc_getClass(name.as_ptr()) }
}
unsafe fn sel(name: &CStr) -> Sel {
    unsafe { sel_registerName(name.as_ptr()) }
}

/// `[NSString stringWithUTF8String:]` — AppKit copies the bytes, so the CString may die here.
unsafe fn ns_string(s: &str) -> Id {
    unsafe {
        let send: extern "C" fn(Id, Sel, *const i8) -> Id = core::mem::transmute(objc_msgSend as *const ());
        let c = std::ffi::CString::new(s).unwrap_or_default();
        send(cls(c"NSString"), sel(c"stringWithUTF8String:"), c.as_ptr())
    }
}

/// One NSTextField turned back into a label, added to `parent`.
///
/// A text field is an EDITABLE CONTROL by default. Each of these four undoes part of that, and
/// `setDrawsBackground:` is the one that matters visually — without it the field paints an
/// opaque white box over the panel's own colour.
///
/// Frame is AppKit's: `[x, y, w, h]` with y counted UP from the bottom of the parent view.
unsafe fn label(parent: Id, text: &str, size: f64, bold: bool, frame: [f64; 4]) {
    unsafe {
        let alloc: extern "C" fn(Id, Sel) -> Id = core::mem::transmute(objc_msgSend as *const ());
        let init_frame: extern "C" fn(Id, Sel, [f64; 4]) -> Id = core::mem::transmute(objc_msgSend as *const ());
        let set_obj: extern "C" fn(Id, Sel, Id) = core::mem::transmute(objc_msgSend as *const ());
        let set_bool: extern "C" fn(Id, Sel, bool) = core::mem::transmute(objc_msgSend as *const ());
        let font_of: extern "C" fn(Id, Sel, f64) -> Id = core::mem::transmute(objc_msgSend as *const ());
        let class_get: extern "C" fn(Id, Sel) -> Id = core::mem::transmute(objc_msgSend as *const ());

        let field = init_frame(alloc(cls(c"NSTextField"), sel(c"alloc")), sel(c"initWithFrame:"), frame);
        if field.is_null() {
            return;
        }
        set_obj(field, sel(c"setStringValue:"), ns_string(text));
        set_bool(field, sel(c"setEditable:"), false);
        set_bool(field, sel(c"setSelectable:"), false);
        set_bool(field, sel(c"setBezeled:"), false);
        set_bool(field, sel(c"setDrawsBackground:"), false);
        set_obj(
            field,
            sel(c"setFont:"),
            font_of(
                cls(c"NSFont"),
                if bold { sel(c"boldSystemFontOfSize:") } else { sel(c"systemFontOfSize:") },
                size,
            ),
        );
        // `labelColor` is SEMANTIC — it follows light and dark mode, where a literal white or black
        // would be wrong in one of them.
        set_obj(field, sel(c"setTextColor:"), class_get(cls(c"NSColor"), sel(c"labelColor")));
        set_obj(parent, sel(c"addSubview:"), field);
    }
}

/// The close button — an `NSButton` whose target is the window itself, so no custom class and no
/// delegate is needed to make it work.
///
/// `orderOut:` AND NOT `close`. `-close` can reach `applicationShouldTerminateAfterLastWindowClosed:`
/// and take the whole process — including the tray — with it. `orderOut:` only removes the window
/// from the screen, which is the entire intent: dismissing a welcome panel must never quit the
/// menu-bar icon it just introduced. It also takes a sender argument, which is exactly what a
/// button action supplies.
///
/// `xmark.circle.fill` is an SF Symbol (`imageWithSystemSymbolName:`, macOS 11+), so it is the
/// system's own glyph at the system's own weight rather than a typed "✕".
unsafe fn close_button(parent: Id, window: Id, frame: [f64; 4]) {
    unsafe {
        let alloc: extern "C" fn(Id, Sel) -> Id = core::mem::transmute(objc_msgSend as *const ());
        let init_frame: extern "C" fn(Id, Sel, [f64; 4]) -> Id = core::mem::transmute(objc_msgSend as *const ());
        let set_obj: extern "C" fn(Id, Sel, Id) = core::mem::transmute(objc_msgSend as *const ());
        let set_bool: extern "C" fn(Id, Sel, bool) = core::mem::transmute(objc_msgSend as *const ());
        let set_i: extern "C" fn(Id, Sel, i64) = core::mem::transmute(objc_msgSend as *const ());
        let set_sel: extern "C" fn(Id, Sel, Sel) = core::mem::transmute(objc_msgSend as *const ());
        let symbol: extern "C" fn(Id, Sel, Id, Id) -> Id = core::mem::transmute(objc_msgSend as *const ());

        let b = init_frame(alloc(cls(c"NSButton"), sel(c"alloc")), sel(c"initWithFrame:"), frame);
        if b.is_null() {
            return;
        }
        let img = symbol(
            cls(c"NSImage"),
            sel(c"imageWithSystemSymbolName:accessibilityDescription:"),
            ns_string("xmark.circle.fill"),
            ns_string("Close"),
        );
        if !img.is_null() {
            set_obj(b, sel(c"setImage:"), img);
            // NSImageOnly = 1 (NSNoImage = 0, NSImageLeft = 2), from NSCell.h.
            set_i(b, sel(c"setImagePosition:"), 1);
        } else {
            set_obj(b, sel(c"setTitle:"), ns_string("✕"));
        }
        set_bool(b, sel(c"setBordered:"), false);
        set_obj(b, sel(c"setTarget:"), window);
        set_sel(b, sel(c"setAction:"), sel(c"orderOut:"));
        set_obj(parent, sel(c"addSubview:"), b);
    }
}

/// One factor so the panel scales as a whole. Doubling W and H alone would stretch the box and
/// leave the type marooned in it — every inset and radius is derived from this instead. Type is
/// the deliberate exception: macOS sizes text against the system font, not against its container.
const SCALE: f64 = 2.0;
/// macOS 26 rounds windows noticeably more than Big Sur–Sequoia did, and a 10pt panel next to a
/// system window reads as the odd one out. There is no public API for the system value, so this
/// is tuned by eye against a real window rather than derived.
const RADIUS: f64 = 16.0 * SCALE;
const W: f64 = 360.0 * SCALE;
const H: f64 = 140.0 * SCALE;
/// The left/right inset, and the width every label gets.
const PAD: f64 = 20.0 * SCALE;

/// Show the panel. Returns the NSWindow as a `usize` so the caller can close it later — a raw
/// pointer is not `Send`, and the tray's event-loop closure is where the handle has to live.
///
/// `anchor` is the tray icon's screen position when it is known; the panel hangs below it,
/// centred on the icon. Without one it lands centred-ish, which is the honest fallback for a
/// tray that has not drawn yet.
pub fn welcome(anchor: Option<(f64, f64)>) -> Option<usize> {
    unsafe {
        let alloc: extern "C" fn(Id, Sel) -> Id = core::mem::transmute(objc_msgSend as *const ());
        let init: extern "C" fn(Id, Sel, [f64; 4], u64, u64, bool) -> Id =
            core::mem::transmute(objc_msgSend as *const ());
        let set_obj: extern "C" fn(Id, Sel, Id) = core::mem::transmute(objc_msgSend as *const ());
        let set_bool: extern "C" fn(Id, Sel, bool) = core::mem::transmute(objc_msgSend as *const ());
        let get: extern "C" fn(Id, Sel) -> Id = core::mem::transmute(objc_msgSend as *const ());
        let set_f: extern "C" fn(Id, Sel, f64) = core::mem::transmute(objc_msgSend as *const ());

        // AppKit's origin is bottom-left, so "below the icon" is a SUBTRACTION from the icon's y.
        // With no anchor the rect here is a placeholder — `-center` below replaces it.
        let (x, y) = match anchor {
            Some((ix, iy)) => (ix - W / 2.0, iy - H - 8.0),
            None => (0.0, 0.0),
        };

        let win_cls = cls(c"NSWindow");
        if win_cls.is_null() {
            return None;
        }
        // styleMask 0 = borderless, backing 2 = buffered, defer false — the same three constants
        // `system_passkey` passes, for the same reasons.
        let w = init(
            alloc(win_cls, sel(c"alloc")),
            sel(c"initWithContentRect:styleMask:backing:defer:"),
            [x, y, W, H],
            0,
            2,
            false,
        );
        if w.is_null() {
            return None;
        }

        // THE WINDOW MUST BE CLEAR AND NON-OPAQUE, or it paints a square fill behind the glass and
        // the corners come back — measured, the first cut coloured the window and drew a square
        // panel. The glass view below is what carries the material and the shape.
        set_bool(w, sel(c"setOpaque:"), false);
        set_bool(w, sel(c"setHasShadow:"), true);
        set_obj(w, sel(c"setBackgroundColor:"), get(cls(c"NSColor"), sel(c"clearColor")));
        // Level 3 = NSFloatingWindowLevel: above ordinary windows, below the menu bar.
        let set_level: extern "C" fn(Id, Sel, i64) = core::mem::transmute(objc_msgSend as *const ());
        set_level(w, sel(c"setLevel:"), 3);
        // DRAGGABLE BY ITS BODY. There is no titlebar to grab, so the background IS the handle —
        // AppKit does the whole drag, including the screen-edge behaviour, from this one flag.
        set_bool(w, sel(c"setMovableByWindowBackground:"), true);

        // CENTRE IT — `-center` is AppKit's own placement, horizontally centred and slightly ABOVE
        // true centre, which is where macOS puts a dialog. Doing the arithmetic by hand off
        // `NSScreen` would land it lower and would have to guess which screen. The literal rect
        // passed to `initWithContentRect:` above was a placeholder; this replaces it.
        if anchor.is_none() {
            let center: extern "C" fn(Id, Sel) = core::mem::transmute(objc_msgSend as *const ());
            center(w, sel(c"center"));
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
        let set_i: extern "C" fn(Id, Sel, i64) = core::mem::transmute(objc_msgSend as *const ());
        let init_frame: extern "C" fn(Id, Sel, [f64; 4]) -> Id = core::mem::transmute(objc_msgSend as *const ());
        let frame = [0.0, 0.0, W, H];

        // The labels' container, on BOTH paths — inside the glass on 26, the contentView itself
        // below that. Nothing can be drawn without it, so a failure here is the one case that
        // genuinely means "no window" rather than an empty one.
        let inner = init_frame(alloc(cls(c"NSView"), sel(c"alloc")), sel(c"initWithFrame:"), frame);
        if inner.is_null() {
            return None;
        }

        let glass = init_frame(alloc(cls(c"NSGlassEffectView"), sel(c"alloc")), sel(c"initWithFrame:"), frame);
        if !glass.is_null() {
            // Style 1 = Clear, 0 = Regular. Regular is the DENSE variant — Liquid Glass is designed to
            // sit under content, so it reads as a dark slab rather than as glass. Clear is the one
            // that stays transparent.
            set_i(glass, sel(c"setStyle:"), 1);
            set_f(glass, sel(c"setCornerRadius:"), RADIUS);
            set_obj(glass, sel(c"setContentView:"), inner);
            set_obj(w, sel(c"setContentView:"), glass);
        } else {
            // BEFORE macOS 26 THERE IS NO GLASS — and `NSGlassEffectView` is the ONLY thing above that
            // ever called `setContentView:`. Without this arm `inner`, which carries every label and
            // the close button, was never attached: the window still opened, borderless and clear, as
            // an empty shadowed rectangle with nothing to click. Info.plist declares a 13.0 floor, so
            // that is a shipped configuration and not a hypothetical.
            //
            // The window pays for its own background here, because a plain view over a clear window
            // leaves the text floating on nothing. Square corners on old macOS is the honest trade for
            // a panel that works — and it is the masking path this file avoids on 26, where the glass
            // owns its radius and a layer mask would fight the window's shadow.
            set_bool(w, sel(c"setOpaque:"), true);
            set_obj(w, sel(c"setBackgroundColor:"), get(cls(c"NSColor"), sel(c"windowBackgroundColor")));
            set_obj(w, sel(c"setContentView:"), inner);
        }

        // The labels' parent is the plain view, never the glass itself — on 26 it lives inside the
        // glass, below that it IS the contentView. Either way `inner` is what they attach to.
        {
            // y counts UP, so the title sits highest and the commands sit near the floor.
            // TYPE STAYS AT SYSTEM SIZE while the panel scales. Doubling the point size would make
            // the panel bigger without making it more readable — macOS text is sized against the
            // system font, not against its container.
            label(inner, "Neuralkit CLI is installed", 15.0, true,
                [PAD, H - 42.0 * SCALE, W - PAD * 2.0, 22.0]);
            label(inner, "The neuralkit command is now on your PATH.", 12.0, false,
                [PAD, H - 66.0 * SCALE, W - PAD * 2.0, 18.0]);
            label(inner, "neuralkit auth login     sign in", 11.5, false,
                [PAD, 36.0 * SCALE, W - PAD * 2.0, 16.0]);
            label(inner, "neuralkit --help         everything else", 11.5, false,
                [PAD, 16.0 * SCALE, W - PAD * 2.0, 16.0]);
            // Top-right, inset by half the padding so it sits in the corner rather than in the text
            // column. y is measured UP, so the top edge is H minus the button's own height.
            const BTN: f64 = 22.0;
            close_button(inner, w, [W - PAD / 2.0 - BTN, H - PAD / 2.0 - BTN, BTN, BTN]);
        }

        let show: extern "C" fn(Id, Sel, Id) = core::mem::transmute(objc_msgSend as *const ());
        show(w, sel(c"makeKeyAndOrderFront:"), core::ptr::null());
        Some(w as usize)
    }
}

/// Close a panel opened by `welcome`. `orderOut:` removes it without destroying it, which is the
/// right verb for a window the caller still holds a pointer to.
#[allow(dead_code)] // the panel dismisses itself through the close button; kept for a caller that outlives it
pub fn close(handle: usize) {
    unsafe {
        let out: extern "C" fn(Id, Sel, Id) = core::mem::transmute(objc_msgSend as *const ());
        out(handle as Id, sel(c"orderOut:"), core::ptr::null());
    }
}
