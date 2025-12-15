// ============================================================================
// src/graphics/psf.rs - PC Screen Font (PSF) Support
// ============================================================================
//!
//! PC Screen Font (PSF) Support
//! Supports both PSF1 and PSF2 formats.
//!

use super::framebuffer::Framebuffer;
use super::{Color, Font, Rect};

// ============================================================================
// PSF1
// ============================================================================

const PSF1_MAGIC0: u8 = 0x36;
const PSF1_MAGIC1: u8 = 0x04;

const PSF1_MODE512: u8 = 0x01;
const PSF1_MODEHASTAB: u8 = 0x02;
const PSF1_MODEHASSEQ: u8 = 0x04;
const PSF1_MAXMODE: u8 = 0x05;

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

pub enum PsfVersion {
    Psf1,
    Psf2,
}

pub struct PsfFont<'a> {
    data: &'a [u8],
    version: PsfVersion,
    width: u32,
    height: u32,
    num_glyphs: u32,
    bytes_per_glyph: u32,
    header_size: usize,
}

impl<'a> PsfFont<'a> {
    /// Create a new PsfFont from a byte slice.
    pub fn new(data: &'a [u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }

        // Check PSF1
        if data[0] == PSF1_MAGIC0 && data[1] == PSF1_MAGIC1 {
            let header: &Psf1Header = unsafe { &*(data.as_ptr() as *const Psf1Header) };
            let mode = header.mode;
            let num_glyphs = if (mode & PSF1_MODE512) != 0 { 512 } else { 256 };

            return Some(Self {
                data,
                version: PsfVersion::Psf1,
                width: 8,
                height: header.charsize as u32,
                num_glyphs,
                bytes_per_glyph: header.charsize as u32,
                header_size: 4, // PSF1 header is 4 bytes
            });
        }

        // Check PSF2
        if data[0] == PSF2_MAGIC0
            && data[1] == PSF2_MAGIC1
            && data[2] == PSF2_MAGIC2
            && data[3] == PSF2_MAGIC3
        {
            if data.len() < core::mem::size_of::<Psf2Header>() {
                return None;
            }
            let header: &Psf2Header = unsafe { &*(data.as_ptr() as *const Psf2Header) };

            return Some(Self {
                data,
                version: PsfVersion::Psf2,
                width: header.width,
                height: header.height,
                num_glyphs: header.length,
                bytes_per_glyph: header.charsize,
                header_size: header.headersize as usize,
            });
        }

        None
    }

    /// Get font version
    pub fn version(&self) -> &PsfVersion {
        &self.version
    }
}

impl<'a> Font for PsfFont<'a> {
    fn width(&self) -> u32 {
        self.width
    }

    fn height(&self) -> u32 {
        self.height
    }

    fn char_width(&self, c: char) -> u32 {
        if c == '\n' { 0 } else { self.width }
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
        let idx = c as u32; // Simplified ASCII/Latin-1 mapping
        // TODO: Proper Unicode mapping using the table if available

        if idx >= self.num_glyphs {
            return;
        }

        let glyph_offset = self.header_size + (idx as usize * self.bytes_per_glyph as usize);
        if glyph_offset + self.bytes_per_glyph as usize > self.data.len() {
            return;
        }

        let glyph_data = &self.data[glyph_offset..glyph_offset + self.bytes_per_glyph as usize];

        // Draw background
        if let Some(bg_color) = bg {
            fb.fill_rect(Rect::new(x, y, self.width, self.height), bg_color);
        }

        match self.version {
            PsfVersion::Psf1 => {
                // PSF1 is always 8 pixels wide
                for row in 0..self.height {
                    let byte = glyph_data[row as usize];
                    for col in 0..8 {
                        if (byte >> (7 - col)) & 1 != 0 {
                            fb.set_pixel(x + col, y + row as i32, color);
                        }
                    }
                }
            }
            PsfVersion::Psf2 => {
                // PSF2 can be any width. Row are byte-aligned.
                let bytes_per_row = ((self.width + 7) / 8) as usize;

                for row in 0..self.height {
                    for col in 0..self.width {
                        let byte_idx = (col / 8) as usize;
                        let bit_idx = 7 - (col % 8);
                        let row_offset = row as usize * bytes_per_row;

                        let byte = glyph_data[row_offset + byte_idx];
                        if (byte >> bit_idx) & 1 != 0 {
                            fb.set_pixel(x + col as i32, y + row as i32, color);
                        }
                    }
                }
            }
        }
    }
}
