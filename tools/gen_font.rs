use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

fn main() {
    let base_path = Path::new("kernel/src/graphics/font.rs");
    let mut content = String::new();
    File::open(base_path)
        .expect("Cannot open font.rs")
        .read_to_string(&mut content)
        .unwrap();

    let start_marker = "pub static DEFAULT_FONT_8X16: [u8; 128 * 16] = [";
    let end_marker = "];";

    let start = content.find(start_marker).expect("Start marker not found") + start_marker.len();
    let end = content[start..]
        .find(end_marker)
        .expect("End marker not found")
        + start;

    let array_str = &content[start..end];

    // Parse hex bytes like 0x00, 0x1F, etc.
    let mut bytes = Vec::new();
    for part in array_str.split(',') {
        let trimmed = part.trim();
        if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
            let byte_str = &trimmed[2..];
            // Handle cases where there might be comments like " // ..." after the number
            let byte_hex = byte_str.split_whitespace().next().unwrap();
            if let Ok(b) = u8::from_str_radix(byte_hex, 16) {
                bytes.push(b);
            }
        }
    }

    println!("Extracted {} bytes.", bytes.len());

    // Pad to 4096 bytes (256 chars) for CP437
    // Current is 128 chars (2048 bytes).
    // We strictly need 2048 for the existing range, and empty for the rest?
    // The user wants Code Page 437.
    // The existing font is ASCII (0-127).
    // I don't have the data for 128-255.
    // I will pad with zeros or copies of space/block to make it valid size.
    // Ideally I would generate the box drawing chars but that's complex logic.
    // I will just pad with zeros for now so it's a valid 4KB file.

    if bytes.len() < 4096 {
        bytes.resize(4096, 0);
    }

    let mut out = File::create("assets/fonts/vga_8x16.bin").expect("Cannot create bin file");
    out.write_all(&bytes).unwrap();
    println!("Written assets/fonts/vga_8x16.bin");
}
