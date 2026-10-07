#![allow(clippy::cargo_common_metadata)]
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

#[path = "build/abi_hash.rs"]
mod abi_hash;
use abi_hash::calculate_abi_hash;
fn main() {
    println!("cargo:rerun-if-changed=build/abi_hash.rs");
    println!("cargo:rerun-if-changed=src/driver_abi/async_driver.rs");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let mut content = String::new();
    for input in [
        "src/driver_abi.rs",
        "src/driver_abi/task.rs",
        "src/driver_abi/time.rs",
        "src/driver_abi/block.rs",
        "src/balloon.rs",
    ] {
        println!("cargo:rerun-if-changed={input}");
        content.push_str(
            &fs::read_to_string(Path::new(&manifest_dir).join(input))
                .unwrap_or_else(|error| panic!("cannot read ABI input {input}: {error}")),
        );
        content.push('\n');
    }

    // Extract struct definitions to hash
    // We want to detect changes in DriverContext or DriverVTable layout
    let hash = calculate_abi_hash(&content);

    // Write the hash to a file in OUT_DIR so it can be included as a u64 constant
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("abi_hash.rs");
    fs::write(
        &dest_path,
        format!(
            "/// Hash of the ABI struct definitions\npub const DRIVER_TYPE_HASH: u64 = {hash};"
        ),
    )
    .unwrap();

    // Notification clones retain the kernel's RawWakerVTable, whose Rust
    // representation is not covered by the C declaration hash. Check this
    // contract separately so ordinary C driver operations remain independent
    // of the compiler used for the kernel's task runtime.
    println!("cargo:rerun-if-env-changed=RUSTC");
    println!("cargo:rerun-if-env-changed=CARGO_ENCODED_RUSTFLAGS");
    let rustc = env::var_os("RUSTC").expect("Cargo must identify its compiler");
    let compiler = Command::new(rustc)
        .args(["--version", "--verbose"])
        .output()
        .expect("Failed to identify task notification ABI compiler");
    assert!(
        compiler.status.success(),
        "compiler ABI identification failed"
    );
    let mut runtime = abi_hash::Fnv1aHasher::new();
    runtime.write(&compiler.stdout);
    // Kernel and cell images use separately named target specifications. Their
    // names do not determine Rust value layout; hash the representation inputs.
    for coordinate in [
        "CARGO_CFG_TARGET_ARCH",
        "CARGO_CFG_TARGET_POINTER_WIDTH",
        "CARGO_CFG_TARGET_ENDIAN",
        "CARGO_CFG_TARGET_ABI",
    ] {
        runtime.write(coordinate.as_bytes());
        runtime.write(env::var(coordinate).unwrap_or_default().as_bytes());
    }
    let flags = env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    if flags
        .split('\u{1f}')
        .any(|flag| flag.contains("randomize-layout") || flag.contains("layout-seed"))
    {
        // A layout seed may be a separate argument; retain the whole sequence
        // whenever layout flags are present instead of losing that argument.
        runtime.write(flags.as_bytes());
    }
    fs::write(
        Path::new(&out_dir).join("task_waker_abi.rs"),
        format!(
            "/// Build identity of the Rust notification representation.\npub const TASK_WAKER_ABI: u64 = {};",
            runtime.finish(),
        ),
    )
    .expect("Failed to write task notification ABI identity");
    println!("cargo:rerun-if-changed=build.rs");
}
