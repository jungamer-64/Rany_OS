#![allow(clippy::cargo_common_metadata)]
use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn main() {
    // Rerun this script if driver_abi.rs changes
    println!("cargo:rerun-if-changed=src/driver_abi.rs");

    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let abi_path = Path::new(&manifest_dir).join("src/driver_abi.rs");
    let content = fs::read_to_string(&abi_path).expect("Failed to read driver_abi.rs");

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
    println!("cargo:rerun-if-changed=build.rs");
}

fn calculate_abi_hash(content: &str) -> u64 {
    let mut hasher = Fnv1aHasher::new();

    // 1. Mix in rustc version
    // This ensures that if the compiler changes (potentially affecting layout), the hash changes.
    let rustc_version = Command::new("rustc")
        .arg("--version")
        .output()
        .expect("Failed to get rustc version")
        .stdout;
    hasher.write(&rustc_version);

    // 2. Hash `#[repr(...)]` attributes only for ABI-critical declarations.
    // This avoids unrelated repr additions from changing DRIVER_TYPE_HASH.
    for line in repr_lines_for_decls(
        content,
        &[
            "pub struct DriverContext",
            "pub struct DriverVTable",
            "pub struct DriverCapabilities",
            "pub enum AbiDriverType",
            "pub enum AbiError",
        ],
    ) {
        hasher.write(line.as_bytes());
    }

    // 3. Extract and hash specific ABI types
    extract_and_hash_decl(content, "pub struct DriverContext", &mut hasher);
    extract_and_hash_decl(content, "pub struct DriverVTable", &mut hasher);
    extract_and_hash_decl(content, "pub struct DriverCapabilities", &mut hasher);
    extract_and_hash_decl(content, "pub enum AbiDriverType", &mut hasher);
    extract_and_hash_decl(content, "pub enum AbiError", &mut hasher);

    hasher.finish()
}

fn extract_and_hash_decl(content: &str, decl_start: &str, hasher: &mut Fnv1aHasher) {
    if let Some(start_idx) = content.find(decl_start) {
        let rest = &content[start_idx..];
        let mut depth = 0;
        let mut check = false;

        let mut buffer = String::new();

        for line in rest.lines() {
            // Strip comments
            let line_content = line.find("//").map_or(line, |idx| &line[..idx]);

            // Count braces in the effective content
            for c in line_content.chars() {
                match c {
                    '{' => {
                        depth += 1;
                        check = true;
                    }
                    '}' => {
                        depth -= 1;
                    }
                    _ => {}
                }
            }

            // Normalize: remove all whitespace for the hash
            let normalized: String = line_content
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            buffer.push_str(&normalized);

            // If we have entered the block and returned to depth 0, we can stop
            if check && depth == 0 {
                break;
            }
        }

        hasher.write(buffer.as_bytes());
    }
}

fn repr_lines_for_decls(content: &str, decls: &[&str]) -> Vec<String> {
    let lines: Vec<&str> = content.lines().collect();
    let mut repr_lines = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if !trimmed.starts_with("#[repr") {
            continue;
        }

        // Scan forward to the next non-empty, non-comment, non-attribute line.
        let mut j = idx + 1;
        while j < lines.len() {
            let next = lines[j].trim();
            if next.is_empty() || next.starts_with("//") {
                j += 1;
                continue;
            }
            if next.starts_with('#') {
                j += 1;
                continue;
            }

            if decls.iter().any(|decl| next.starts_with(decl)) {
                repr_lines.push(trimmed.to_string());
            }
            break;
        }
    }

    repr_lines
}

// Simple FNV-1a 64-bit hash implementation
struct Fnv1aHasher {
    state: u64,
}

impl Fnv1aHasher {
    const fn new() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state ^= u64::from(b);
            self.state = self.state.wrapping_mul(0x0100_0000_01b3);
        }
    }

    const fn finish(&self) -> u64 {
        self.state
    }
}
