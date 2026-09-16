use std::io::Result;
fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "src/proto/neuralkit.proto",
            "src/proto/takmessage.proto",
            "src/proto/cotevent.proto",
            "src/proto/cotdetail.proto",
        ],
        &["src/proto/"],
    )?;

    // FlatBuffer codegen for the eeg-track encoding (the browser-native, zero-copy
    // format). flatc emits neuro_generated.rs into OUT_DIR; streaming.rs include!s it.
    let out = std::env::var("OUT_DIR").unwrap();
    let status = std::process::Command::new("flatc")
        .args(["--rust", "-o", &out, "src/proto/neuro.fbs"])
        .status()
        .expect("flatc not found — install flatbuffers (brew install flatbuffers)");
    assert!(status.success(), "flatc failed on neuro.fbs");
    println!("cargo:rerun-if-changed=src/proto/neuro.fbs");

    // THE PANEL EMBED — feature `embed`, on by default (Cargo.toml [features]). A dev build
    // (`phaze native dev` → `cargo run --no-default-features`) embeds nothing and gets the Vite
    // dev server URL baked in from PHAZE_NATIVE_DEV_URL, Tauri's `devUrl` model: panel.rs reads
    // it with option_env! and refuses to compile a dev build without it. Tracked as an input, so
    // changing the URL rebuilds.
    println!("cargo:rerun-if-env-changed=PHAZE_NATIVE_DEV_URL");
    if let Ok(url) = std::env::var("PHAZE_NATIVE_DEV_URL") {
        println!("cargo:rustc-env=PHAZE_NATIVE_DEV_URL={url}");
    }
    if std::env::var_os("CARGO_FEATURE_EMBED").is_some() {
        // Only when embedding: cargo re-runs this script when the panel's build changes, so a
        // the app's build in app/ recompiles without a `touch`. NOT in a dev build — measured: a
        // tracked path that does not exist makes cargo re-run this script (protobuf, flatc) and
        // recompile on EVERY build.
        println!("cargo:rerun-if-changed=app/dist/app");
        // A `.br` asset needs the `panel-brotli` feature (the decoder); without it the panel
        // answers a 500 at runtime. Fail here instead, where the message can say what to do.
        if std::env::var_os("CARGO_FEATURE_PANEL_BROTLI").is_none() {
            if let Some(br) = find_with_ext(std::path::Path::new("app/dist/app"), "br") {
                panic!(
                    "{} — the panel was built with `compress: 'brotli'` but this build has no brotli decoder: build with `--features panel-brotli`, or rebuild the panel with `compress: 'gzip'`",
                    br.display()
                );
            }
        }
    }
    Ok(())
}

fn find_with_ext(dir: &std::path::Path, ext: &str) -> Option<std::path::PathBuf> {
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir() {
            if let Some(hit) = find_with_ext(&p, ext) {
                return Some(hit);
            }
        } else if p.extension().is_some_and(|e| e == ext) {
            return Some(p);
        }
    }
    None
}
