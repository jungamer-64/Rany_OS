use std::env;
use std::fs;
use std::path::Path;

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
        format!("/// Hash of the ABI struct definitions\npub const DRIVER_TYPE_HASH: u64 = {};", hash),
    ).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
}

fn calculate_abi_hash(content: &str) -> u64 {
    let mut hasher = Fnv1aHasher::new();

    // extract_struct(content, "DriverContext", &mut hasher); // DriverContext is layout stable but fields matter
    // extract_struct(content, "DriverVTable", &mut hasher);
    // Actually, simply hashing the "meaningful" lines of the file might be safer/easier
    // to catch *any* definition change.
    // Let's look for the structs specifically to avoid comment changes affecting hash.

    extract_and_hash_decl(content, "pub struct DriverContext", &mut hasher);
    extract_and_hash_decl(content, "pub struct DriverVTable", &mut hasher);
    extract_and_hash_decl(content, "pub struct DriverCapabilities", &mut hasher);
    extract_and_hash_decl(content, "pub enum AbiDriverType", &mut hasher);
    extract_and_hash_decl(content, "pub enum AbiError", &mut hasher);

    hasher.finish()
}

fn extract_and_hash_decl(content: &str, decl_start: &str, hasher: &mut Fnv1aHasher) {
    if let Some(start) = content.find(decl_start) {
        let rest = &content[start..];
        // Find closing brace. Simple counter.
        let mut depth = 0;
        let mut check = false;
        for (i, c) in rest.char_indices() {
            if c == '{' {
                depth += 1;
                check = true;
            } else if c == '}' {
                depth -= 1;
                if check && depth == 0 {
                    // decl body ends here
                    let body = &rest[..=i];
                    // Clean up whitespace to avoid formatting affecting hash too much?
                    // For now, strict hashing of the text is fine.
                    hasher.write(body.as_bytes());
                    return;
                }
            }
        }
    }
}

// Simple FNV-1a 64-bit hash implementation
struct Fnv1aHasher {
    state: u64,
}

impl Fnv1aHasher {
    fn new() -> Self {
        Self { state: 0xcbf29ce484222325 }
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
