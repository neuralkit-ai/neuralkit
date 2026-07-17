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
    Ok(())
}
