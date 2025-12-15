// ============================================================================
// src/graphics/psf.rs - PC Screen Font (PSF) Support
// ============================================================================
//!
//! PC Screen Font (PSF) Support
//! Supports both PSF1 and PSF2 formats.
//!

use super::framebuffer::Framebuffer;
use super::{Color, Font, Rect};
use alloc::collections::BTreeMap;
use core::str::from_utf8;

// ============================================================================
// PSF1
// ============================================================================

const PSF1_MAGIC0: u8 = 0x36;
const PSF1_MAGIC1: u8 = 0x04;

const PSF1_MODE512: u8 = 0x01;
const PSF1_MODEHASTAB: u8 = 0x02;
const PSF1_MODEHASSEQ: u8 = 0x04;
const PSF1_MAXMODE: u8 = 0x05;

const PSF1_SEPARATOR: u16 = 0xFFFF;
const PSF1_STARTSEQ: u16 = 0xFFFE;

#[repr(C, packed)]
struct Psf1Header {
    magic: [u8; 2],
    mode: u8,
    charsize: u8,
}

// ============================================================================
// PSF2
// ============================================================================

const PSF2_MAGIC0: u8 = 0x72;
const PSF2_MAGIC1: u8 = 0xb5;
const PSF2_MAGIC2: u8 = 0x4a;
const PSF2_MAGIC3: u8 = 0x86;

const PSF2_HAS_UNICODE_TABLE: u32 = 0x01;

const PSF2_SEPARATOR: u8 = 0xFF;
const PSF2_STARTSEQ: u8 = 0xFE;

#[repr(C, packed)]
struct Psf2Header {
    magic: [u8; 4],
    version: u32,
    headersize: u32,
    flags: u32,
    length: u32,
    charsize: u32,
    height: u32,
    width: u32,
}

// ============================================================================
// PsfFont
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsfVersion {
    Psf1,
    Psf2,
}

pub struct PsfFont<T: AsRef<[u8]>> {
    data: T,
    version: PsfVersion,
    width: u32,
    height: u32,
    num_glyphs: u32,
    bytes_per_glyph: u32,
    header_size: usize,
    /// Maps Unicode character to Glyph Index
    unicode_map: Option<BTreeMap<char, u32>>,
}

impl<T: AsRef<[u8]>> PsfFont<T> {
    /// Create a new PsfFont from a byte slice or owned Vec.
    pub fn new(data: T) -> Option<Self> {
        let slice = data.as_ref();
        if slice.len() < 4 {
            return None;
        }

        // Check PSF1
        if slice[0] == PSF1_MAGIC0 && slice[1] == PSF1_MAGIC1 {
            let header: &Psf1Header = unsafe { &*(slice.as_ptr() as *const Psf1Header) };
            let mode = header.mode;
            let num_glyphs = if (mode & PSF1_MODE512) != 0 { 512 } else { 256 };
            let header_size = 4;
            let bytes_per_glyph = header.charsize as u32;

            let mut unicode_map = None;
            if (mode & PSF1_MODEHASTAB) != 0 {
                // PSF1 Unicode table parsing could be added here
                // For now, we only implement PSF2 table parsing as it's more common for large fonts
                // TODO: Implement PSF1 Unicode table
            }

            return Some(Self {
                data,
                version: PsfVersion::Psf1,
                width: 8,
                height: header.charsize as u32,
                num_glyphs,
                bytes_per_glyph,
                header_size,
                unicode_map,
            });
        }

        // Check PSF2
        if slice[0] == PSF2_MAGIC0
            && slice[1] == PSF2_MAGIC1
            && slice[2] == PSF2_MAGIC2
            && slice[3] == PSF2_MAGIC3
        {
            if slice.len() < core::mem::size_of::<Psf2Header>() {
                return None;
            }
            let header: &Psf2Header = unsafe { &*(slice.as_ptr() as *const Psf2Header) };
            let num_glyphs = header.length;
            let bytes_per_glyph = header.charsize;
            let header_size = header.headersize as usize;

            let mut unicode_map = None;
            if (header.flags & PSF2_HAS_UNICODE_TABLE) != 0 {
                let table_offset = header_size + (num_glyphs as usize * bytes_per_glyph as usize);
                if table_offset < slice.len() {
                    unicode_map = Some(Self::parse_psf2_table(&slice[table_offset..], num_glyphs));
                }
            }

            return Some(Self {
                data,
                version: PsfVersion::Psf2,
                width: header.width,
                height: header.height,
                num_glyphs,
                bytes_per_glyph,
                header_size,
                unicode_map,
            });
        }

        None
    }

    /// Parse PSF2 Unicode Table
    fn parse_psf2_table(table_data: &[u8], num_glyphs: u32) -> BTreeMap<char, u32> {
        let mut map = BTreeMap::new();
        let mut glyph_idx = 0;
        let mut i = 0;

        while i < table_data.len() && glyph_idx < num_glyphs {
            let b = table_data[i];

            if b == PSF2_SEPARATOR {
                glyph_idx += 1;
                i += 1;
                continue;
            }

            if b == PSF2_STARTSEQ {
                // Composite sequences not fully supported, skip to separator
                // (We could support mapping the first char of sequence to this glyph)
                i += 1;
                while i < table_data.len()
                    && table_data[i] != PSF2_SEPARATOR
                    && table_data[i] != PSF2_STARTSEQ
                {
                    i += 1;
                }
                continue;
            }

            // Parse UTF-8 character
            // Check byte length based on first byte
            let char_len = if b & 0x80 == 0 {
                1
            } else if b & 0xE0 == 0xC0 {
                2
            } else if b & 0xF0 == 0xE0 {
                3
            } else if b & 0xF8 == 0xF0 {
                4
            } else {
                1
            }; // Invalid or fallback

            if i + char_len > table_data.len() {
                break;
            }

            if let Ok(s) = from_utf8(&table_data[i..i + char_len]) {
                if let Some(c) = s.chars().next() {
                    map.insert(c, glyph_idx);
                }
            }

            i += char_len;
        }

        map
    }

    /// Get font version
    pub fn version(&self) -> &PsfVersion {
        &self.version
    }

    /// Get font width
    pub fn width(&self) -> u32 {
        self.width
    }

    /// Get font height
    pub fn height(&self) -> u32 {
        self.height
    }
}

impl<T: AsRef<[u8]>> Font for PsfFont<T> {
    fn height(&self) -> u32 {
        self.height
    }

    fn char_width(&self, c: char) -> u32 {
        if c == '\n' { 0 } else { self.width }
    }

    fn glyph(&self, c: char) -> Option<&[u8]> {
        let idx = if let Some(map) = &self.unicode_map {
            *map.get(&c).unwrap_or(&0) // Fallback to 0 (usually replacement char or space) or strict None?
        // Actually, typical fallback logic:
        // 1. Try unicode map
        // 2. If ASCII/Latin-1 compatible (Psf1/NoTable), direct cast?
        // If map exists, we should rely on it. If not found in map, check if direct index fits?
        // But if map exists, direct index is meaningless for char > 255.
        // For now: if map exists, use it. If not found, try direct cast if char < 128 (ASCII compatibility assumption).
        // Better: if not found, return None. 0 might be a valid glyph but "wrong" one.
        } else {
            c as u32
        };

        if self.unicode_map.is_some() && !self.unicode_map.as_ref().unwrap().contains_key(&c) {
            // If we have a map but key not found, try simple ASCII fallback if c < 128?
            // Many fonts map ASCII 1:1 at start.
            if (c as u32) < 128 {
                c as u32
            } else {
                return None;
            }
        } else if idx >= self.num_glyphs {
            return None;
        } else {
            idx
        };

        // Double check calculated idx vs bounds, 'idx' variable here is slightly confusing due to re-assignment logic above
        // Let's refine:
        let glyph_index = if let Some(map) = &self.unicode_map {
            if let Some(&i) = map.get(&c) {
                i
            } else if (c as u32) < self.num_glyphs {
                // Heuristic: If char code equals glyph index (e.g. ASCII), use it?
                // Most Linux console fonts put ASCII at 0-127.
                c as u32
            } else {
                return None;
            }
        } else {
            c as u32
        };

        if glyph_index >= self.num_glyphs {
            return None;
        }

        let slice = self.data.as_ref();
        let glyph_offset =
            self.header_size + (glyph_index as usize * self.bytes_per_glyph as usize);
        if glyph_offset + self.bytes_per_glyph as usize > slice.len() {
            return None;
        }
        Some(&slice[glyph_offset..glyph_offset + self.bytes_per_glyph as usize])
    }

    fn draw_char(
        &self,
        fb: &mut Framebuffer,
        x: i32,
        y: i32,
        c: char,
        color: Color,
        bg: Option<Color>,
    ) {
        // Resolve glyph index
        let glyph_index = if let Some(map) = &self.unicode_map {
            if let Some(&i) = map.get(&c) {
                i
            } else if (c as u32) < self.num_glyphs {
                c as u32
            } else {
                return; // Character not found
            }
        } else {
            c as u32
        };

        if glyph_index >= self.num_glyphs {
            return;
        }

        let slice = self.data.as_ref();
        let glyph_offset =
            self.header_size + (glyph_index as usize * self.bytes_per_glyph as usize);
        if glyph_offset + self.bytes_per_glyph as usize > slice.len() {
            return;
        }

        let glyph_data = &slice[glyph_offset..glyph_offset + self.bytes_per_glyph as usize];

        // Use optimized framebiffer drawing
        fb.draw_glyph_bitmap(x, y, glyph_data, self.width, self.height, color, bg);
    }
}
