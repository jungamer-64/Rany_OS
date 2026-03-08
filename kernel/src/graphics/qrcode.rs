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
mod reed_solomon;
pub use reed_solomon::*;
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
    (0, 8),
    (1, 8),
    (2, 8),
    (3, 8),
    (4, 8),
    (5, 8),
    (7, 8),
    (8, 8),
    (8, 7),
    (8, 5),
    (8, 4),
    (8, 3),
    (8, 2),
    (8, 1),
    (8, 0),
];

const FORMAT_POS_TR: [(usize, usize); 8] = [
    (20, 8),
    (19, 8),
    (18, 8),
    (17, 8),
    (16, 8),
    (15, 8),
    (14, 8),
    (13, 8),
];

const FORMAT_POS_BL: [(usize, usize); 7] = [
    (8, 20),
    (8, 19),
    (8, 18),
    (8, 17),
    (8, 16),
    (8, 15),
    (8, 14),
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
        if data.len() > MAX_CHARS {
            return Err(QrError::TooLong);
        }
        if !data.is_ascii() {
            return Err(QrError::NonAscii);
        }

        let bytes = data.as_bytes();
        for &b in bytes {
            if qr_alnum_value(b).is_none() {
                return Err(QrError::InvalidChar);
            }
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
            let module = if i % 2 == 0 {
                Module::FuncDark
            } else {
                Module::FuncLight
            };
            self.set_reserved(i, 6, module);
            self.set_reserved(6, i, module);
        }

        // Dark Module (Always dark)
        self.set_reserved(8, QR_SIZE - 8, Module::FuncDark);
    }

    fn place_finder_pattern(&mut self, x: usize, y: usize) {
        for dy in 0..7 {
            for dx in 0..7 {
                self.set_reserved(x + dx, y + dy, Self::finder_module(dx, dy));
            }
        }
        self.place_finder_separators(x, y);
    }

    /// Determine whether a cell in the 7×7 finder pattern is dark or light.
    fn finder_module(dx: usize, dy: usize) -> Module {
        // Ring distance from edge: border=0, white ring=1, inner center=2..3
        let ring = dx.min(6 - dx).min(dy.min(6 - dy));
        if ring == 1 {
            Module::FuncLight
        } else {
            Module::FuncDark
        }
    }

    /// データビットを1モジュールに配置する
    fn place_data_bit(&mut self, data: &[u8], placed_bits: &mut usize, y: usize, x: usize) {
        let bi = *placed_bits;
        if bi < data.len() * 8 {
            let byte = data[bi >> 3];
            let bit = (byte >> (7 - (bi & 7))) & 1;
            self.modules[y][x] = if bit != 0 {
                Module::DataDark
            } else {
                Module::DataLight
            };
        } else {
            self.modules[y][x] = Module::DataLight;
        }
        *placed_bits += 1;
    }

    /// Place the white separator rows/columns around a finder pattern.
    fn place_finder_separators(&mut self, x: usize, y: usize) {
        self.place_separator_at(x, y);
    }

    /// ファインダーパターン位置に基づきセパレータを配置
    fn place_separator_at(&mut self, fx: usize, fy: usize) {
        let (vx, vy_start, hx_start, hy) = match (fx == 0, fy == 0) {
            (true, true) => (7, 0, 0, 7),
            (false, true) => (QR_SIZE - 8, 0, QR_SIZE - 8, 7),
            (true, false) => (7, QR_SIZE - 8, 0, QR_SIZE - 8),
            (false, false) => return,
        };
        for i in 0..8 {
            self.set_reserved(vx, vy_start + i, Module::FuncLight);
            self.set_reserved(hx_start + i, hy, Module::FuncLight);
        }
    }

    fn reserve_format_info(&mut self) {
        for &(x, y) in FORMAT_POS_TL.iter() {
            self.set_reserved(x, y, Module::FuncLight);
        }
        for &(x, y) in FORMAT_POS_TR.iter() {
            self.set_reserved(x, y, Module::FuncLight);
        }
        for &(x, y) in FORMAT_POS_BL.iter() {
            self.set_reserved(x, y, Module::FuncLight);
        }

        #[cfg(debug_assertions)]
        {
            debug_assert!(!FORMAT_POS_TL.contains(&(8, 13)));
            debug_assert!(!FORMAT_POS_TR.contains(&(8, 13)));
            debug_assert!(!FORMAT_POS_BL.contains(&(8, 13)));
        }
    }

    /// Place format information bits at the given positions.
    fn place_format_bits(&mut self, format: u16, positions: &[(usize, usize)], shift_start: u8) {
        for (i, (x, y)) in positions.iter().enumerate() {
            let bit = ((format >> (shift_start - i as u8)) & 1) != 0;
            self.force_reserved(
                *x,
                *y,
                if bit {
                    Module::FuncDark
                } else {
                    Module::FuncLight
                },
            );
        }
    }

    fn place_format_info(&mut self, mask: u8) {
        let data = ((0b01u16) << 3) | (mask as u16);
        let mut rem = data << 10;
        let generator = 0b10100110111u16;
        for i in (10..=14).rev() {
            if ((rem >> i) & 1) != 0 {
                rem ^= generator << (i - 10);
            }
        }
        let bch = (data << 10) | (rem & 0x03FF);
        let format = bch ^ 0b101010000010010u16;

        self.place_format_bits(format, &FORMAT_POS_TL, 14);
        self.place_format_bits(format, &FORMAT_POS_TR, 14);
        self.place_format_bits(format, &FORMAT_POS_BL, 6);
    }

    fn place_data(&mut self, data: &[u8]) {
        #[cfg(debug_assertions)]
        debug_assert_eq!(data.len(), TOTAL_CODEWORDS);

        let mut placed_bits = 0usize;

        let mut right = QR_SIZE - 1;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while right > 0 {
            if right == 6 {
                right -= 1;
            }
            let left = right - 1;
            let upward = ((QR_SIZE - 1 - right) / 2) % 2 == 0;

            for i in 0..QR_SIZE {
                let y = if upward { QR_SIZE - 1 - i } else { i };
                for x in [right, left] {
                    if self.modules[y][x].is_reserved() {
                        continue;
                    }
                    self.place_data_bit(data, &mut placed_bits, y, x);
                }
            }
            if right < 2 {
                break;
            }
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

    /// Penalty helper: score for a single consecutive run length (Rule 1).
    fn penalty_run_score(run_len: u32) -> u32 {
        if run_len >= 5 { 3 + (run_len - 5) } else { 0 }
    }

    /// Penalty Rule 1 helper: scan one axis for consecutive same-color runs.
    /// When `horizontal` is true, the outer loop iterates rows (y) and inner
    /// iterates columns (x); when false the axes are swapped.
    fn penalty_line_runs(&self, horizontal: bool) -> u32 {
        let mut score = 0;
        for outer in 0..QR_SIZE {
            let mut run_len = 0u32;
            let mut last_dark = false;
            for inner in 0..QR_SIZE {
                let (y, x) = if horizontal {
                    (outer, inner)
                } else {
                    (inner, outer)
                };
                let dark = self.modules[y][x].is_dark();
                if inner == 0 || dark != last_dark {
                    score += Self::penalty_run_score(run_len);
                    last_dark = dark;
                    run_len = 1;
                } else {
                    run_len += 1;
                }
            }
            score += Self::penalty_run_score(run_len);
        }
        score
    }

    /// Penalty Rule 1: 5+ consecutive same-color modules (horizontal + vertical).
    fn penalty_rule1_runs(&self) -> u32 {
        self.penalty_line_runs(true) + self.penalty_line_runs(false)
    }

    /// Penalty Rule 2: 2×2 blocks of same color.
    fn penalty_rule2_blocks(&self) -> u32 {
        let mut score = 0;
        for y in 0..QR_SIZE - 1 {
            for x in 0..QR_SIZE - 1 {
                let d = self.modules[y][x].is_dark();
                if self.modules[y][x + 1].is_dark() == d
                    && self.modules[y + 1][x].is_dark() == d
                    && self.modules[y + 1][x + 1].is_dark() == d
                {
                    score += 3;
                }
            }
        }
        score
    }

    /// Penalty Rule 3 helper: check whether an 11-module sequence starting at
    /// (`x_start`, `y_start`) in direction (`dx`, `dy`) matches the
    /// finder-like 1:1:3:1:1 pattern (with quiet-zone treatment).
    fn is_rule3_pattern(&self, x_start: i32, y_start: i32, dx: i32, dy: i32) -> bool {
        let mut pattern = 0u16;
        for k in 0..11 {
            let mx = x_start + k * dx;
            let my = y_start + k * dy;

            // Outside the grid is treated as Light (Quiet Zone)
            let is_dark = if mx >= 0 && mx < QR_SIZE as i32 && my >= 0 && my < QR_SIZE as i32 {
                self.modules[my as usize][mx as usize].is_dark()
            } else {
                false
            };
            if is_dark {
                pattern |= 1 << (10 - k);
            }
        }
        pattern == 0x5D0 || pattern == 0x05D
    }

    /// Penalty Rule 3: 1:1:3:1:1 finder-like patterns (horizontal + vertical).
    fn penalty_rule3_patterns(&self) -> u32 {
        let mut score = 0;
        for y in 0..QR_SIZE {
            for x in -4..=(QR_SIZE as i32 - 7) {
                if self.is_rule3_pattern(x, y as i32, 1, 0) {
                    score += 40;
                }
            }
        }
        for x in 0..QR_SIZE {
            for y in -4..=(QR_SIZE as i32 - 7) {
                if self.is_rule3_pattern(x as i32, y, 0, 1) {
                    score += 40;
                }
            }
        }
        score
    }

    /// Penalty Rule 4: dark-module ratio deviation from 50%.
    fn penalty_rule4_ratio(&self) -> u32 {
        let mut dark_count = 0u32;
        let total = (QR_SIZE * QR_SIZE) as u32;
        for y in 0..QR_SIZE {
            for x in 0..QR_SIZE {
                if self.modules[y][x].is_dark() {
                    dark_count += 1;
                }
            }
        }
        let percent = (dark_count * 100) / total;
        let diff = if percent > 50 {
            percent - 50
        } else {
            50 - percent
        };
        (diff / 5) * 10
    }

    /// Calculate the total penalty score across all four QR masking rules.
    fn calculate_penalty_score(&self) -> u32 {
        self.penalty_rule1_runs()
            + self.penalty_rule2_blocks()
            + self.penalty_rule3_patterns()
            + self.penalty_rule4_ratio()
    }

    fn set_reserved(&mut self, x: usize, y: usize, module: Module) {
        if x < QR_SIZE && y < QR_SIZE {
            #[cfg(debug_assertions)]
            {
                let current = self.modules[y][x];
                debug_assert!(
                    !current.is_reserved() || current == module,
                    "Overwrite reserved module conflict at ({}, {}): {:?} -> {:?}",
                    x,
                    y,
                    current,
                    module
                );
            }
            self.modules[y][x] = module;
        }
    }

    fn force_reserved(&mut self, x: usize, y: usize, module: Module) {
        if x < QR_SIZE && y < QR_SIZE {
            #[cfg(debug_assertions)]
            debug_assert!(
                self.modules[y][x].is_reserved(),
                "force_reserved on non-reserved area ({},{})",
                x,
                y
            );

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
                    debug_assert!(
                        self.modules[y][x] != Module::Unset,
                        "Unset module in data area at ({},{})",
                        x,
                        y
                    );
                } else {
                    debug_assert!(
                        self.modules[y][x] != Module::Unset,
                        "Unset module in reserved area at ({},{})",
                        x,
                        y
                    );
                }
            }
        }
        debug_assert_eq!(
            data_modules, DATA_MODULES,
            "QR Data Module Count mismatch! Expected {}, found {}",
            DATA_MODULES, data_modules
        );
    }

    #[cfg(debug_assertions)]
    fn debug_assert_reserved_layout(&self) {
        let mut seen = [[false; QR_SIZE]; QR_SIZE];
        let mut count = 0;

        for &(x, y) in FORMAT_POS_TL
            .iter()
            .chain(FORMAT_POS_TR.iter())
            .chain(FORMAT_POS_BL.iter())
        {
            debug_assert!(!seen[y][x], "Duplicate format pos coordinate ({},{})", x, y);
            seen[y][x] = true;
            // Verify that this position is indeed marked as reserved
            debug_assert!(
                self.modules[y][x].is_reserved(),
                "Format Info POS ({},{}) is improperly NOT reserved",
                x,
                y
            );
            count += 1;
        }

        debug_assert_eq!(count, 15 + 8 + 7, "Total format info bits mismatch");
    }

    #[cfg(debug_assertions)]
    fn debug_assert_mask_does_not_touch_reserved(
        &self,
        mask: u8,
        base: &[[Module; QR_SIZE]; QR_SIZE],
    ) {
        for y in 0..QR_SIZE {
            for x in 0..QR_SIZE {
                if base[y][x].is_reserved() {
                    // The mask operation should NOT have modified reserved modules.
                    debug_assert_eq!(
                        self.modules[y][x], base[y][x],
                        "Mask {} modified reserved module at ({},{})",
                        mask, x, y
                    );
                }
            }
        }
    }

    pub fn debug_ascii(&self) -> [[u8; QR_SIZE]; QR_SIZE] {
        let mut out = [[b'.'; QR_SIZE]; QR_SIZE];
        for y in 0..QR_SIZE {
            for x in 0..QR_SIZE {
                out[y][x] = if self.modules[y][x].is_dark() {
                    b'#'
                } else {
                    b'.'
                };
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
            // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
            while col < QR_SIZE {
                if self.modules[row][col].is_dark() {
                    let start = col;
                    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
                    while col < QR_SIZE && self.modules[row][col].is_dark() {
                        col += 1;
                    }
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
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while y != 0 {
        if (y & 1) != 0 {
            r ^= x;
        }
        let hi = x & 0x80;
        x <<= 1;
        if hi != 0 {
            x ^= 0x1d;
        } // Primitive polynomial 0x11D
        y >>= 1;
    }
    r
}
