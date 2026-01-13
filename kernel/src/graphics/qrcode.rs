// ============================================================================
// src/graphics/qrcode.rs - Standard Compliant QR Code Generator (Version 1-L)
// ============================================================================
//!
//! # QR Code Generator (Version 1, Low Error Correction)
//!
//! Generates a 21x21 QR code.
//!
//! ## Implemented Features
//! - Version 1 (21x21 modules)
//! - Error Correction Level L (7%)
//! - Reed-Solomon Error Correction (GF(2^8))
//! - Alphanumeric Mode only
//! - Standard Quiet Zone (4 modules)
//! - Reserved Module Protection
//! - Optimal Mask Selection (ISO/IEC 18004)
//!

#![allow(dead_code)]

use super::{Color, Framebuffer, Rect};

/// QR Code Version 1 Size (21x21)
const QR_SIZE: usize = 21;
/// Maximum characters for Version 1-L Alphanumeric
const MAX_CHARS: usize = 25;

// Data Capacity Constants (Version 1-L)
const DATA_CODEWORDS: usize = 19;
const EC_CODEWORDS: usize = 7;
const TOTAL_CODEWORDS: usize = DATA_CODEWORDS + EC_CODEWORDS; // 26

/// Bits available for Data (19 * 8 = 152 bits)
/// The terminator and padding MUST NOT exceed this in the payload.
const DATA_PAYLOAD_BITS: usize = DATA_CODEWORDS * 8;

/// Total modules available for data+EC (26 * 8 = 208 bits)
/// This is used for verification of module placement.
const DATA_MODULES: usize = TOTAL_CODEWORDS * 8;

/// Module State
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
enum Module {
    Unset,
    /// Data module (Dark) - affected by mask
    DataDark,
    /// Data module (Light) - affected by mask
    DataLight,
    /// Function/Reserved module (Dark) - Immutable
    FuncDark,
    /// Function/Reserved module (Light) - Immutable
    FuncLight,
}

impl Default for Module {
    fn default() -> Self {
        Module::Unset
    }
}

impl Module {
    fn is_dark(&self) -> bool {
        match self {
            Module::DataDark | Module::FuncDark => true,
            _ => false,
        }
    }

    fn is_reserved(&self) -> bool {
        match self {
            Module::FuncDark | Module::FuncLight => true,
            _ => false,
        }
    }
}

// Format Info Coordinates (Version 1)
// 0(=MSB) -> 14(=LSB)
const FORMAT_POS_TL: [(usize, usize); 15] = [
    (0, 8), (1, 8), (2, 8), (3, 8), (4, 8), (5, 8),
    (7, 8), (8, 8),
    (8, 7), (8, 5), (8, 4), (8, 3), (8, 2), (8, 1), (8, 0),
];

const FORMAT_POS_TR: [(usize, usize); 8] = [
    (20, 8), (19, 8), (18, 8), (17, 8), (16, 8), (15, 8), (14, 8), (13, 8),
];

const FORMAT_POS_BL: [(usize, usize); 7] = [
    (8, 20), (8, 19), (8, 18), (8, 17), (8, 16), (8, 15), (8, 14),
];

/// Error types for QR Code generation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QrError {
    TooLong,
    NonAscii,
    InvalidChar,
    EncodingError,
}

/// QR Code Buffer
#[derive(Debug)]
pub struct QrCode {
    modules: [[Module; QR_SIZE]; QR_SIZE],
}

impl QrCode {
    /// Create a new QR Code with automatic sanitization (Lossy).
    /// Safe: NEVER panics.
    /// 1. Tries to sanitize input and encode.
    /// 2. If that fails, falls back to "ERROR".
    /// 3. If that fails, returns a valid empty QR frame.
    pub fn new_lossy(data: &str) -> Self {
         let mut ascii_buf = [0u8; MAX_CHARS];
         let mut len = 0;

         // Use take(MAX_CHARS) to prevent buffer overflow
         for c in data.chars().take(MAX_CHARS) {
             ascii_buf[len] = sanitize_to_qr_alnum_ascii(c);
             len += 1;
         }
         
         // Try encoded sanitized input
         if let Ok(qr) = Self::new_from_ascii(&ascii_buf[..len]) {
             return qr;
         }

         // Fallback 1: "ERROR"
         if let Ok(qr) = Self::new_from_ascii(b"ERROR") {
             return qr;
         }

         // Fallback 2: Minimal valid QR (Emergency)
         let mut qr = QrCode {
             modules: [[Module::Unset; QR_SIZE]; QR_SIZE],
         };
         qr.place_function_patterns();
         qr.reserve_format_info();
         // Fill data area with light modules (valid blank)
         for y in 0..QR_SIZE {
             for x in 0..QR_SIZE {
                 if !qr.modules[y][x].is_reserved() {
                     qr.modules[y][x] = Module::DataLight;
                 }
             }
         }
         qr.place_format_info(0);
         qr
    }

    /// Create a new QR Code strict mode.
    /// Returns error if input contains non-ASCII characters, invalid alphanumeric characters, or exceeds length.
    pub fn new_strict(data: &str) -> Result<Self, QrError> {
        if data.len() > MAX_CHARS { return Err(QrError::TooLong); }
        if !data.is_ascii() { return Err(QrError::NonAscii); }
        
        let bytes = data.as_bytes();
        for &b in bytes {
            if qr_alnum_value(b).is_none() { return Err(QrError::InvalidChar); }
        }
        
        Self::new_from_ascii(bytes)
    }

    /// Convenience wrapper alias for new_strict.
    pub fn new(data: &str) -> Option<Self> {
        Self::new_strict(data).ok()
    }

    /// Core creation from raw ASCII bytes.
    fn new_from_ascii(data: &[u8]) -> Result<Self, QrError> {
        if data.len() > MAX_CHARS {
            return Err(QrError::TooLong);
        }

        let mut qr = QrCode {
            modules: [[Module::Unset; QR_SIZE]; QR_SIZE],
        };

        // 1. Place Function Patterns
        qr.place_function_patterns();

        // 2. Place Format Information (Reserved areas)
        qr.reserve_format_info();
        
        // Debug Check: Reserved Layout
        #[cfg(debug_assertions)]
        qr.debug_assert_reserved_layout();

        // 3. Encode Data and calculate Error Correction
        let encoded_data = encode_alphanumeric_v1_l(data).ok_or(QrError::EncodingError)?;

        // 4. Place Data and EC codewords
        qr.place_data(&encoded_data);

        // Verification (Debug only)
        #[cfg(debug_assertions)]
        qr.debug_assert_invariants();

        // 5. Select Best Mask
        let base_modules = qr.modules; // Save state
        let mut best_mask = 0;
        let mut min_penalty = u32::MAX;

        for mask in 0..8 {
            qr.modules = base_modules; // Restore baseline
            qr.apply_mask(mask);
            
            // Verify mask didn't touch reserved modules (User request)
            #[cfg(debug_assertions)]
            qr.debug_assert_mask_does_not_touch_reserved(mask, &base_modules);

            qr.place_format_info(mask); // Use intentional overwrite
            let score = qr.calculate_penalty_score();
            if score < min_penalty {
                min_penalty = score;
                best_mask = mask;
            }
        }

        // 6. Apply Best Mask
        qr.modules = base_modules;
        qr.apply_mask(best_mask);
        qr.place_format_info(best_mask);

        Ok(qr)
    }

    /// Place Finder Patterns, Separators, and Timing Patterns
    fn place_function_patterns(&mut self) {
        // Finder Patterns
        self.place_finder_pattern(0, 0);
        self.place_finder_pattern(QR_SIZE - 7, 0);
        self.place_finder_pattern(0, QR_SIZE - 7);

        // Timing Patterns
        for i in 8..QR_SIZE - 8 {
            let module = if i % 2 == 0 { Module::FuncDark } else { Module::FuncLight };
            self.set_reserved(i, 6, module);
            self.set_reserved(6, i, module);
        }

        // Dark Module (Always dark)
        self.set_reserved(8, QR_SIZE - 8, Module::FuncDark);
    }

    fn place_finder_pattern(&mut self, x: usize, y: usize) {
        for dy in 0..7 {
            for dx in 0..7 {
                let is_border = dx == 0 || dx == 6 || dy == 0 || dy == 6;
                let is_inner = dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4;
                let module = if is_border || is_inner {
                    Module::FuncDark
                } else {
                    Module::FuncLight
                };
                self.set_reserved(x + dx, y + dy, module);
            }
        }

        // Separators (White border around finder patterns)
        if x == 0 && y == 0 {
            for i in 0..8 {
                self.set_reserved(7, i, Module::FuncLight);
                self.set_reserved(i, 7, Module::FuncLight);
            }
        }
        if x > 0 && y == 0 {
             for i in 0..8 {
                 self.set_reserved(QR_SIZE - 8, i, Module::FuncLight);
                 self.set_reserved(QR_SIZE - 8 + i, 7, Module::FuncLight);
             }
        }
        if x == 0 && y > 0 {
             for i in 0..8 {
                 self.set_reserved(i, QR_SIZE - 8, Module::FuncLight);
                 self.set_reserved(7, QR_SIZE - 8 + i, Module::FuncLight);
             }
        }
    }

    fn reserve_format_info(&mut self) {
        for &(x, y) in FORMAT_POS_TL.iter() { self.set_reserved(x, y, Module::FuncLight); }
        for &(x, y) in FORMAT_POS_TR.iter() { self.set_reserved(x, y, Module::FuncLight); }
        for &(x, y) in FORMAT_POS_BL.iter() { self.set_reserved(x, y, Module::FuncLight); }

        #[cfg(debug_assertions)]
        {
            debug_assert!(!FORMAT_POS_TL.contains(&(8, 13)));
            debug_assert!(!FORMAT_POS_TR.contains(&(8, 13)));
            debug_assert!(!FORMAT_POS_BL.contains(&(8, 13)));
        }
    }

    fn place_format_info(&mut self, mask: u8) {
        let data = ((0b01u16) << 3) | (mask as u16);
        let mut rem = data << 10;
        let generator = 0b10100110111u16;
        for i in (10..=14).rev() {
            if ((rem >> i) & 1) != 0 { rem ^= generator << (i - 10); }
        }
        let bch = (data << 10) | (rem & 0x03FF);
        let format = bch ^ 0b101010000010010u16;

        for (i, (x, y)) in FORMAT_POS_TL.iter().enumerate() {
            let bit = ((format >> (14 - i)) & 1) != 0;
            self.force_reserved(*x, *y, if bit { Module::FuncDark } else { Module::FuncLight });
        }
        for (i, (x, y)) in FORMAT_POS_TR.iter().enumerate() {
            let bit = ((format >> (14 - i)) & 1) != 0;
            self.force_reserved(*x, *y, if bit { Module::FuncDark } else { Module::FuncLight });
        }
        for (i, (x, y)) in FORMAT_POS_BL.iter().enumerate() {
            let bit = ((format >> (6 - i)) & 1) != 0;
            self.force_reserved(*x, *y, if bit { Module::FuncDark } else { Module::FuncLight });
        }
    }

    fn place_data(&mut self, data: &[u8]) {
        #[cfg(debug_assertions)]
        debug_assert_eq!(data.len(), TOTAL_CODEWORDS);

        let mut placed_bits = 0usize;

        let mut right = QR_SIZE - 1;
        while right > 0 {
            if right == 6 { right -= 1; }
            let left = right - 1;
            let upward = ((QR_SIZE - 1 - right) / 2) % 2 == 0;

            for i in 0..QR_SIZE {
                let y = if upward { QR_SIZE - 1 - i } else { i };
                for x in [right, left] {
                    if self.modules[y][x].is_reserved() { continue; }

                    let bi = placed_bits;
                    if bi < data.len() * 8 {
                        let byte = data[bi >> 3];
                        let bit  = (byte >> (7 - (bi & 7))) & 1;
                        self.modules[y][x] = if bit != 0 { Module::DataDark } else { Module::DataLight };
                    } else {
                        // Should not happen if data invariants hold
                        self.modules[y][x] = Module::DataLight;
                    }

                    placed_bits += 1;
                }
            }
            if right < 2 { break; }
            right -= 2;
        }

        #[cfg(debug_assertions)]
        debug_assert_eq!(placed_bits, DATA_MODULES);
    }

    fn apply_mask(&mut self, mask: u8) {
        for y in 0..QR_SIZE {
            for x in 0..QR_SIZE {
                if !self.modules[y][x].is_reserved() {
                    if self.get_mask_bit(mask, x, y) {
                        self.modules[y][x] = match self.modules[y][x] {
                            Module::DataDark => Module::DataLight,
                            Module::DataLight => Module::DataDark,
                            _ => self.modules[y][x],
                        };
                    }
                }
            }
        }
    }

    fn get_mask_bit(&self, mask: u8, x: usize, y: usize) -> bool {
        let (r, c) = (y, x);
        match mask {
            0 => (r + c) % 2 == 0,
            1 => r % 2 == 0,
            2 => c % 3 == 0,
            3 => (r + c) % 3 == 0,
            4 => ((r / 2) + (c / 3)) % 2 == 0,
            5 => ((r * c) % 2) + ((r * c) % 3) == 0,
            6 => (((r * c) % 2) + ((r * c) % 3)) % 2 == 0,
            7 => (((r + c) % 2) + ((r * c) % 3)) % 2 == 0,
            _ => false,
        }
    }

    fn calculate_penalty_score(&self) -> u32 {
        let mut score = 0;

        // Rule 1: 5+ consecutive same color
        let check_run = |run_len: u32| -> u32 {
            if run_len >= 5 { 3 + (run_len - 5) } else { 0 }
        };

        for y in 0..QR_SIZE { // Horizontal
            let mut run_len = 0;
            let mut last_dark = false;
            for x in 0..QR_SIZE {
                let dark = self.modules[y][x].is_dark();
                if x == 0 || dark != last_dark {
                    score += check_run(run_len);
                    last_dark = dark;
                    run_len = 1;
                } else {
                    run_len += 1;
                }
            }
            score += check_run(run_len);
        }
        for x in 0..QR_SIZE { // Vertical
            let mut run_len = 0;
            let mut last_dark = false;
            for y in 0..QR_SIZE {
                let dark = self.modules[y][x].is_dark();
                if y == 0 || dark != last_dark {
                    score += check_run(run_len);
                    last_dark = dark;
                    run_len = 1;
                } else {
                    run_len += 1;
                }
            }
            score += check_run(run_len);
        }

        // Rule 2: 2x2 blocks
        for y in 0..QR_SIZE - 1 {
            for x in 0..QR_SIZE - 1 {
                let d = self.modules[y][x].is_dark();
                if self.modules[y][x+1].is_dark() == d && 
                   self.modules[y+1][x].is_dark() == d && 
                   self.modules[y+1][x+1].is_dark() == d {
                    score += 3;
                }
            }
        }

        // Rule 3: 1:1:3:1:1 pattern
        // Helper to check 11-bit sequence with quiet zone handling
        let check_rule3_pattern = |x_start: i32, y_start: i32, dx: i32, dy: i32| -> bool {
            let mut pattern = 0u16;
            for k in 0..11 {
                let mx = x_start + k * dx;
                let my = y_start + k * dy;
                
                // Outside is Light (Quiet Zone logic)
                let is_dark = if mx >= 0 && mx < QR_SIZE as i32 && my >= 0 && my < QR_SIZE as i32 {
                    self.modules[my as usize][mx as usize].is_dark()
                } else {
                    false
                };
                if is_dark { pattern |= 1 << (10 - k); }
            }
            pattern == 0x5D0 || pattern == 0x05D
        };

        for y in 0..QR_SIZE {
             for x in -4..=(QR_SIZE as i32 - 7) {
                 if check_rule3_pattern(x, y as i32, 1, 0) { score += 40; }
             }
        }
        for x in 0..QR_SIZE {
             for y in -4..=(QR_SIZE as i32 - 7) {
                 if check_rule3_pattern(x as i32, y, 0, 1) { score += 40; }
             }
        }

        // Rule 4: Dark module ratio
        let mut dark_count = 0;
        let total = (QR_SIZE * QR_SIZE) as u32;
        for y in 0..QR_SIZE {
            for x in 0..QR_SIZE {
                if self.modules[y][x].is_dark() { dark_count += 1; }
            }
        }
        let percent = (dark_count * 100) / total;
        let diff = if percent > 50 { percent - 50 } else { 50 - percent };
        score += (diff / 5) * 10;

        score
    }

    fn set_reserved(&mut self, x: usize, y: usize, module: Module) {
        if x < QR_SIZE && y < QR_SIZE {
             #[cfg(debug_assertions)]
             {
                 let current = self.modules[y][x];
                 debug_assert!(!current.is_reserved() || current == module, 
                    "Overwrite reserved module conflict at ({}, {}): {:?} -> {:?}", x, y, current, module);
             }
            self.modules[y][x] = module;
        }
    }

    fn force_reserved(&mut self, x: usize, y: usize, module: Module) {
         if x < QR_SIZE && y < QR_SIZE {
            #[cfg(debug_assertions)]
            debug_assert!(self.modules[y][x].is_reserved(), "force_reserved on non-reserved area ({},{})", x, y);

            self.modules[y][x] = module;
        }
    }

    #[cfg(debug_assertions)]
    fn debug_assert_invariants(&self) {
        // 1. Verify capacity (module usage)
        let mut data_modules = 0usize;
        for y in 0..QR_SIZE {
            for x in 0..QR_SIZE {
                if !self.modules[y][x].is_reserved() { 
                    data_modules += 1; 
                    debug_assert!(self.modules[y][x] != Module::Unset, "Unset module in data area at ({},{})", x, y);
                } else {
                     debug_assert!(self.modules[y][x] != Module::Unset, "Unset module in reserved area at ({},{})", x, y);
                }
            }
        }
        debug_assert_eq!(data_modules, DATA_MODULES, "QR Data Module Count mismatch! Expected {}, found {}", DATA_MODULES, data_modules);
    }
    
    #[cfg(debug_assertions)]
    fn debug_assert_reserved_layout(&self) {
        let mut seen = [[false; QR_SIZE]; QR_SIZE];
        let mut count = 0;

        for &(x, y) in FORMAT_POS_TL.iter()
            .chain(FORMAT_POS_TR.iter())
            .chain(FORMAT_POS_BL.iter())
        {
            debug_assert!(!seen[y][x], "Duplicate format pos coordinate ({},{})", x, y);
            seen[y][x] = true;
            // Verify that this position is indeed marked as reserved
            debug_assert!(self.modules[y][x].is_reserved(), "Format Info POS ({},{}) is improperly NOT reserved", x, y);
            count += 1;
        }
        
        debug_assert_eq!(count, 15 + 8 + 7, "Total format info bits mismatch");
    }

    #[cfg(debug_assertions)]
    fn debug_assert_mask_does_not_touch_reserved(&self, mask: u8, base: &[[Module; QR_SIZE]; QR_SIZE]) {
        for y in 0..QR_SIZE {
            for x in 0..QR_SIZE {
                if base[y][x].is_reserved() {
                     // The mask operation should NOT have modified reserved modules.
                    debug_assert_eq!(self.modules[y][x], base[y][x], 
                        "Mask {} modified reserved module at ({},{})", mask, x, y);
                }
            }
        }
    }

    pub fn debug_ascii(&self) -> [[u8; QR_SIZE]; QR_SIZE] {
        let mut out = [[b'.'; QR_SIZE]; QR_SIZE];
        for y in 0..QR_SIZE {
            for x in 0..QR_SIZE {
                out[y][x] = if self.modules[y][x].is_dark() { b'#' } else { b'.' };
            }
        }
        out
    }

    pub fn draw(
        &self,
        fb: &mut Framebuffer,
        x: i32,
        y: i32,
        module_size: u32,
        dark_color: Color,
        light_color: Color,
    ) {
        let quiet_zone = 4;
        let total_modules = QR_SIZE as i32 + (quiet_zone * 2);
        let total_size = total_modules as u32 * module_size;

        fb.fill_rect(Rect::new(x, y, total_size, total_size), light_color);

        for row in 0..QR_SIZE {
            let py = y + ((quiet_zone as i32 + row as i32) * module_size as i32);
            let mut col = 0;
            while col < QR_SIZE {
                if self.modules[row][col].is_dark() {
                    let start = col;
                    while col < QR_SIZE && self.modules[row][col].is_dark() { col += 1; }
                    let px = x + ((quiet_zone as i32 + start as i32) * module_size as i32);
                    let width = (col - start) as u32 * module_size;
                    fb.fill_rect(Rect::new(px, py, width, module_size), dark_color);
                } else {
                    col += 1;
                }
            }
        }
    }
}

// ============================================================================
// Reed-Solomon Error Correction (GF(256))
// ============================================================================

fn gf_mul(mut x: u8, mut y: u8) -> u8 {
    let mut r = 0u8;
    while y != 0 {
        if (y & 1) != 0 { r ^= x; }
        let hi = x & 0x80;
        x <<= 1;
        if hi != 0 { x ^= 0x1d; } // Primitive polynomial 0x11D
        y >>= 1;
    }
    r
}

// Generator polynomial for 7 error correction codewords (RS(26,19))
// g(x) = (x - a^0)...(x - a^6)
// g(x) = x^7 + 127x^6 + 122x^5 + 154x^4 + 164x^3 + 11x^2 + 68x + 117
// Stored as coefficients [127, 122, 154, 164, 11, 68, 117] (skipping lead 1)
const RS_GEN_COEFFS: [u8; 7] = [127, 122, 154, 164, 11, 68, 117];

fn rs_encode_ec7(data19: &[u8; 19]) -> [u8; 7] {
    let mut ec = [0u8; 7];

    for &d in data19.iter() {
        // Divide by generator polynomial: factor = input + lead_coeff
        let factor = d ^ ec[0];
        
        // Shift left
        for i in 0..6 {
             // ec[i] = ec[i+1] + factor * COEFF[i]
            ec[i] = ec[i+1] ^ gf_mul(factor, RS_GEN_COEFFS[i]);
        }
        // Last term: ec[6] = 0 + factor * COEFF[6]
        ec[6] = gf_mul(factor, RS_GEN_COEFFS[6]);
    }
    ec
}

// ============================================================================
// Encoding Helpers
// ============================================================================

/// Encode alphanumeric string into Version 1-L QR data (26 bytes)
fn encode_alphanumeric_v1_l(data: &[u8]) -> Option<[u8; TOTAL_CODEWORDS]> {
    let mut buffer = [0u8; TOTAL_CODEWORDS]; // Final buffer (26 bytes)
    let mut bit_stream = [0u8; DATA_CODEWORDS]; // 19 bytes for data
    let mut bit_idx = 0;

    if !append_bits(&mut bit_stream, &mut bit_idx, 0b0010, 4) { return None; }
    if !append_bits(&mut bit_stream, &mut bit_idx, data.len() as u32, 9) { return None; }

    let mut i = 0;
    while i < data.len() {
        let val1 = qr_alnum_value(data[i])?;
        if i + 1 < data.len() {
             let val2 = qr_alnum_value(data[i+1])?;
             i += 2;
             if !append_bits(&mut bit_stream, &mut bit_idx, (val1 as u32) * 45 + (val2 as u32), 11) { return None; }
        } else {
             i += 1;
             if !append_bits(&mut bit_stream, &mut bit_idx, val1 as u32, 6) { return None; }
        }
    }

    if bit_idx > DATA_PAYLOAD_BITS { return None; }

    let term_len = core::cmp::min(4, DATA_PAYLOAD_BITS - bit_idx);
    if !append_bits(&mut bit_stream, &mut bit_idx, 0, term_len) { return None; }

    if bit_idx % 8 != 0 {
        let pad = 8 - (bit_idx % 8);
        if !append_bits(&mut bit_stream, &mut bit_idx, 0, pad) { return None; }
    }

    let mut pad_val = 0xEC;
    // Pad up to payload limit
    while bit_idx < DATA_PAYLOAD_BITS {
        if !append_bits(&mut bit_stream, &mut bit_idx, pad_val as u32, 8) { return None; }
        pad_val = if pad_val == 0xEC { 0x11 } else { 0xEC };
    }

    for i in 0..DATA_CODEWORDS { buffer[i] = bit_stream[i]; }

    let mut data19 = [0u8; DATA_CODEWORDS];
    data19.copy_from_slice(&buffer[0..DATA_CODEWORDS]);
    let ec = rs_encode_ec7(&data19);
    
    for i in 0..EC_CODEWORDS { buffer[DATA_CODEWORDS + i] = ec[i]; }

    Some(buffer)
}

fn append_bits(buf: &mut [u8], bit_idx: &mut usize, val: u32, len: usize) -> bool {
    if *bit_idx + len > buf.len() * 8 { return false; }

    for i in (0..len).rev() {
        let bit = (val >> i) & 1;
        let byte_pos = *bit_idx / 8;
        let bit_pos = 7 - (*bit_idx % 8);
        
        if byte_pos < buf.len() {
             if bit == 1 { buf[byte_pos] |= 1 << bit_pos; }
        }
        *bit_idx += 1;
    }
    true
}

// Strict Alphanumeric Value Mapping (0-44 or None)
fn qr_alnum_value(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'A'..=b'Z' => Some(c - b'A' + 10),
        b' ' => Some(36),
        b'$' => Some(37),
        b'%' => Some(38),
        b'*' => Some(39),
        b'+' => Some(40),
        b'-' => Some(41),
        b'.' => Some(42),
        b'/' => Some(43),
        b':' => Some(44),
        _ => None,
    }
}

// Sanitization to valid Alphanumeric ASCII char (char -> u8)
fn sanitize_to_qr_alnum_ascii(c: char) -> u8 {
    match c {
        '0'..='9' | 'A'..='Z' | ' ' | '$' | '%' | '*' | '+' | '-' | '.' | '/' | ':' => c as u8,
        'a'..='z' => (c as u8).to_ascii_uppercase(),
        _ => b'-', // Replace invalid with DASH for visibility
    }
}

pub fn generate_error_qr(error_code: &str) -> Option<QrCode> {
    // new_lossy handles sanitization and truncation safely
    Some(QrCode::new_lossy(error_code))
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_rs_ec7_known_vector() {
        // Known vector test for Reed-Solomon RS(26,19) over GF(256) with primitive 0x11D.
        // Data derived from standard example but adapted for 19 data bytes (V1-L).
        let data19: [u8; 19] = [
            0x41, 0x17, 0x77, 0x77, 0x72, 0xE7, 0x76, 0x96, 0xB6, 0x97,
            0x06, 0x56, 0x46, 0x96, 0x12, 0xE6, 0xF7, 0x26, 0x70,
        ];
        let ec = rs_encode_ec7(&data19);
        // Correct EC codewords for this input using our generator polynomial
        assert_eq!(ec, [0xAE, 0xAD, 0xEF, 0x06, 0x97, 0x8F, 0x25]);
    }
}

