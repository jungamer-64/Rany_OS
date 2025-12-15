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
            "/// Hash of the ABI struct definitions\npub const DRIVER_TYPE_HASH: u64 = {};",
            hash
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

    // 2. Hash all `#[repr(...)]` attributes found in the file
    // This catches if a struct loses #[repr(C)] or changes packing,
    // even if the struct body parser doesn't catch it.
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("#[repr") {
            hasher.write(trimmed.as_bytes());
        }
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
            let line_content = if let Some(idx) = line.find("//") {
                &line[..idx]
            } else {
                line
            };

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

// Simple FNV-1a 64-bit hash implementation
struct Fnv1aHasher {
    state: u64,
}

impl Fnv1aHasher {
    fn new() -> Self {
        Self {
            state: 0xcbf29ce484222325,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.state ^= b as u64;
            self.state = self.state.wrapping_mul(0x100000001b3);
        }
    }

    fn finish(&self) -> u64 {
        self.state
    }
}
