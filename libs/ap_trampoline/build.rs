#![allow(clippy::cargo_common_metadata)]

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set"));
    let source = manifest_dir.join("src/ap_trampoline.asm");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is not set"));
    let output = out_dir.join("ap_trampoline.bin");

    println!("cargo:rerun-if-changed={}", source.display());

    let status = Command::new("nasm")
        .arg("-f")
        .arg("bin")
        .arg("-o")
        .arg(&output)
        .arg(&source)
        .status()
        .expect("failed to execute nasm for AP trampoline");

    if !status.success() {
        panic!(
            "nasm failed while assembling {} -> {}",
            source.display(),
            output.display()
        );
    }
}
