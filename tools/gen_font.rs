use std::fs::File;
use std::io::Write;
use std::path::Path;

fn main() {
    let out_path = Path::new("assets/fonts/vga_8x16.bin");

    if out_path.exists() {
        match out_path.metadata() {
            Ok(meta) => {
                println!(
                    "assets/fonts/vga_8x16.bin already exists ({} bytes).",
                    meta.len()
                );
            }
            Err(e) => {
                eprintln!("Failed to stat {}: {}", out_path.display(), e);
                std::process::exit(1);
            }
        }
        return;
    }

    println!("assets/fonts/vga_8x16.bin not found. Creating a placeholder 4096-byte VGA font.");

    // Create a blank 256 glyphs * 16 bytes per glyph file (4096 bytes)
    let mut buf = vec![0u8; 256 * 16];

    // Optionally fill printable range (0x20..0x7E) with a simple pattern for visibility
    for ch in 0x20..=0x7E {
        let idx = ch as usize;
        let start = idx * 16;
        // Simple pattern: first byte 0xFF to mark printable glyphs (placeholder)
        buf[start] = 0xFF;
    }

    let mut f = File::create(out_path).expect("Cannot create font file");
    f.write_all(&buf).expect("Failed to write font file");
    println!("Written assets/fonts/vga_8x16.bin (placeholder)");
}
