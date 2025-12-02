// ============================================================================
// src/graphics/mod.rs - Graphics and Framebuffer Driver
// ============================================================================
//!
//! # グラフィックスサブシステム
//!
//! フレームバッファベースのグラフィックス出力を提供。
//! VESAモード、GOP（UEFI）、VBEをサポート。
//!
//! ## 機能
//! - フレームバッファ直接描画
//! - 基本図形（線、矩形、円）
//! - ビットマップフォントによるテキスト描画
//! - ダブルバッファリング
//! - 画像描画（BMP）

#![allow(dead_code)]

// サブモジュール
pub mod image;
pub mod window;

use core::ptr;
use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::vec;
use alloc::string::String;
use spin::Mutex;

// ============================================================================
// Color Types
// ============================================================================

/// 32ビットRGBAカラー
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Color {
    pub blue: u8,
    pub green: u8,
    pub red: u8,
    pub alpha: u8,
}

impl Color {
    /// 新しいカラーを作成
    pub const fn new(red: u8, green: u8, blue: u8) -> Self {
        Self {
            red,
            green,
            blue,
            alpha: 255,
        }
    }

    /// アルファ付きカラーを作成
    pub const fn with_alpha(red: u8, green: u8, blue: u8, alpha: u8) -> Self {
        Self {
            red,
            green,
            blue,
            alpha,
        }
    }

    /// 32ビット値に変換（BGRA）
    pub const fn to_u32(self) -> u32 {
        ((self.alpha as u32) << 24)
            | ((self.red as u32) << 16)
            | ((self.green as u32) << 8)
            | (self.blue as u32)
    }

    /// 32ビット値から変換
    pub const fn from_u32(value: u32) -> Self {
        Self {
            blue: (value & 0xFF) as u8,
            green: ((value >> 8) & 0xFF) as u8,
            red: ((value >> 16) & 0xFF) as u8,
            alpha: ((value >> 24) & 0xFF) as u8,
        }
    }

    // 基本色定義
    pub const BLACK: Color = Color::new(0, 0, 0);
    pub const WHITE: Color = Color::new(255, 255, 255);
    pub const RED: Color = Color::new(255, 0, 0);
    pub const GREEN: Color = Color::new(0, 255, 0);
    pub const BLUE: Color = Color::new(0, 0, 255);
    pub const YELLOW: Color = Color::new(255, 255, 0);
    pub const CYAN: Color = Color::new(0, 255, 255);
    pub const MAGENTA: Color = Color::new(255, 0, 255);
    pub const GRAY: Color = Color::new(128, 128, 128);
    pub const DARK_GRAY: Color = Color::new(64, 64, 64);
    pub const LIGHT_GRAY: Color = Color::new(192, 192, 192);
    pub const ORANGE: Color = Color::new(255, 165, 0);
    pub const PURPLE: Color = Color::new(128, 0, 128);
    pub const TRANSPARENT: Color = Color::with_alpha(0, 0, 0, 0);
}

impl Default for Color {
    fn default() -> Self {
        Self::BLACK
    }
}

// ============================================================================
// Pixel Format
// ============================================================================

/// ピクセルフォーマット
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    /// RGB888 (24-bit)
    Rgb888,
    /// RGBA8888 (32-bit)
    Rgba8888,
    /// BGR888 (24-bit)
    Bgr888,
    /// BGRA8888 (32-bit)
    Bgra8888,
    /// RGB565 (16-bit)
    Rgb565,
}

impl PixelFormat {
    /// バイト数を取得
    pub const fn bytes_per_pixel(&self) -> usize {
        match self {
            PixelFormat::Rgb888 | PixelFormat::Bgr888 => 3,
            PixelFormat::Rgba8888 | PixelFormat::Bgra8888 => 4,
            PixelFormat::Rgb565 => 2,
        }
    }
}

// ============================================================================
// Framebuffer Info
// ============================================================================

/// フレームバッファ情報
#[derive(Clone, Debug)]
pub struct FramebufferInfo {
    /// フレームバッファの物理アドレス
    pub address: u64,
    /// 幅（ピクセル）
    pub width: u32,
    /// 高さ（ピクセル）
    pub height: u32,
    /// 1行のバイト数（stride/pitch）
    pub stride: u32,
    /// ピクセルフォーマット
    pub format: PixelFormat,
    /// 色深度（ビット）
    pub bpp: u8,
}

impl FramebufferInfo {
    /// フレームバッファの総バイト数
    pub fn size(&self) -> usize {
        self.stride as usize * self.height as usize
    }
}

// ============================================================================
// Point and Rectangle
// ============================================================================

/// 2D座標
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

/// 矩形
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self { x, y, width, height }
    }

    /// 右端のX座標
    pub fn right(&self) -> i32 {
        self.x + self.width as i32
    }

    /// 下端のY座標
    pub fn bottom(&self) -> i32 {
        self.y + self.height as i32
    }

    /// 点が矩形内にあるか
    pub fn contains(&self, point: Point) -> bool {
        point.x >= self.x
            && point.x < self.right()
            && point.y >= self.y
            && point.y < self.bottom()
    }

    /// 矩形が交差するか
    pub fn intersects(&self, other: &Rect) -> bool {
        self.x < other.right()
            && self.right() > other.x
            && self.y < other.bottom()
            && self.bottom() > other.y
    }

    /// 交差領域を取得
    pub fn intersection(&self, other: &Rect) -> Option<Rect> {
        if !self.intersects(other) {
            return None;
        }

        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let right = self.right().min(other.right());
        let bottom = self.bottom().min(other.bottom());

        Some(Rect::new(
            x,
            y,
            (right - x) as u32,
            (bottom - y) as u32,
        ))
    }
}

// ============================================================================
// Framebuffer
// ============================================================================

/// フレームバッファ
pub struct Framebuffer {
    /// フレームバッファ情報
    info: FramebufferInfo,
    /// フレームバッファへのポインタ
    buffer: *mut u8,
    /// バックバッファ（ダブルバッファリング用）
    back_buffer: Option<Vec<u8>>,
    /// クリップ領域
    clip: Rect,
}

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    /// 新しいフレームバッファを作成
    pub unsafe fn new(info: FramebufferInfo) -> Self {
        let clip = Rect::new(0, 0, info.width, info.height);
        Self {
            buffer: info.address as *mut u8,
            info,
            back_buffer: None,
            clip,
        }
    }

    /// ダブルバッファリングを有効化
    pub fn enable_double_buffering(&mut self) {
        let size = self.info.size();
        self.back_buffer = Some(vec![0u8; size]);
    }

    /// バックバッファをフロントにコピー
    pub fn swap_buffers(&mut self) {
        if let Some(ref back) = self.back_buffer {
            unsafe {
                ptr::copy_nonoverlapping(
                    back.as_ptr(),
                    self.buffer,
                    self.info.size(),
                );
            }
        }
    }

    /// 描画先バッファを取得
    fn draw_buffer(&mut self) -> *mut u8 {
        if let Some(ref mut back) = self.back_buffer {
            back.as_mut_ptr()
        } else {
            self.buffer
        }
    }

    /// フレームバッファ情報を取得
    pub fn info(&self) -> &FramebufferInfo {
        &self.info
    }

    /// 幅を取得
    pub fn width(&self) -> u32 {
        self.info.width
    }

    /// 高さを取得
    pub fn height(&self) -> u32 {
        self.info.height
    }

    /// クリップ領域を設定
    pub fn set_clip(&mut self, rect: Rect) {
        self.clip = rect;
    }

    /// クリップ領域をリセット
    pub fn reset_clip(&mut self) {
        self.clip = Rect::new(0, 0, self.info.width, self.info.height);
    }

    /// ピクセルをセット
    pub fn set_pixel(&mut self, x: i32, y: i32, color: Color) {
        if x < 0 || y < 0 {
            return;
        }
        let x = x as u32;
        let y = y as u32;

        if x >= self.info.width || y >= self.info.height {
            return;
        }

        if !self.clip.contains(Point::new(x as i32, y as i32)) {
            return;
        }

        let offset = (y * self.info.stride) as usize
            + (x as usize * self.info.format.bytes_per_pixel());

        let buffer = self.draw_buffer();

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                let pixel = buffer.add(offset) as *mut u32;
                ptr::write_volatile(pixel, color.to_u32());
            },
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                ptr::write_volatile(buffer.add(offset), color.blue);
                ptr::write_volatile(buffer.add(offset + 1), color.green);
                ptr::write_volatile(buffer.add(offset + 2), color.red);
            },
            PixelFormat::Rgb565 => unsafe {
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                let pixel = (r << 11) | (g << 5) | b;
                let ptr = buffer.add(offset) as *mut u16;
                ptr::write_volatile(ptr, pixel);
            },
        }
    }

    /// ピクセルを取得
    pub fn get_pixel(&self, x: u32, y: u32) -> Color {
        if x >= self.info.width || y >= self.info.height {
            return Color::BLACK;
        }

        let offset = (y * self.info.stride) as usize
            + (x as usize * self.info.format.bytes_per_pixel());

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                let pixel = *(self.buffer.add(offset) as *const u32);
                Color::from_u32(pixel)
            },
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                let b = *self.buffer.add(offset);
                let g = *self.buffer.add(offset + 1);
                let r = *self.buffer.add(offset + 2);
                Color::new(r, g, b)
            },
            PixelFormat::Rgb565 => unsafe {
                let pixel = *(self.buffer.add(offset) as *const u16);
                let r = ((pixel >> 11) & 0x1F) as u8 * 8;
                let g = ((pixel >> 5) & 0x3F) as u8 * 4;
                let b = (pixel & 0x1F) as u8 * 8;
                Color::new(r, g, b)
            },
        }
    }

    /// 画面をクリア
    pub fn clear(&mut self, color: Color) {
        let buffer = self.draw_buffer();
        let bytes_per_pixel = self.info.format.bytes_per_pixel();

        for y in 0..self.info.height {
            for x in 0..self.info.width {
                let offset = (y * self.info.stride) as usize + x as usize * bytes_per_pixel;

                match self.info.format {
                    PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                        let pixel = buffer.add(offset) as *mut u32;
                        ptr::write_volatile(pixel, color.to_u32());
                    },
                    PixelFormat::Bgr888 | PixelFormat::Rgb888 => unsafe {
                        ptr::write_volatile(buffer.add(offset), color.blue);
                        ptr::write_volatile(buffer.add(offset + 1), color.green);
                        ptr::write_volatile(buffer.add(offset + 2), color.red);
                    },
                    PixelFormat::Rgb565 => unsafe {
                        let r = (color.red as u16 >> 3) & 0x1F;
                        let g = (color.green as u16 >> 2) & 0x3F;
                        let b = (color.blue as u16 >> 3) & 0x1F;
                        let pixel = (r << 11) | (g << 5) | b;
                        let ptr = buffer.add(offset) as *mut u16;
                        ptr::write_volatile(ptr, pixel);
                    },
                }
            }
        }
    }

    /// 水平線を描画
    pub fn draw_hline(&mut self, x1: i32, x2: i32, y: i32, color: Color) {
        let start = x1.min(x2);
        let end = x1.max(x2);

        for x in start..=end {
            self.set_pixel(x, y, color);
        }
    }

    /// 垂直線を描画
    pub fn draw_vline(&mut self, x: i32, y1: i32, y2: i32, color: Color) {
        let start = y1.min(y2);
        let end = y1.max(y2);

        for y in start..=end {
            self.set_pixel(x, y, color);
        }
    }

    /// 線を描画（Bresenhamアルゴリズム）
    pub fn draw_line(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        let dx = (x2 - x1).abs();
        let dy = -(y2 - y1).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;

        let mut x = x1;
        let mut y = y1;

        loop {
            self.set_pixel(x, y, color);

            if x == x2 && y == y2 {
                break;
            }

            let e2 = 2 * err;

            if e2 >= dy {
                if x == x2 {
                    break;
                }
                err += dy;
                x += sx;
            }

            if e2 <= dx {
                if y == y2 {
                    break;
                }
                err += dx;
                y += sy;
            }
        }
    }

    /// 矩形を描画（枠のみ）
    pub fn draw_rect(&mut self, rect: Rect, color: Color) {
        self.draw_hline(rect.x, rect.right() - 1, rect.y, color);
        self.draw_hline(rect.x, rect.right() - 1, rect.bottom() - 1, color);
        self.draw_vline(rect.x, rect.y, rect.bottom() - 1, color);
        self.draw_vline(rect.right() - 1, rect.y, rect.bottom() - 1, color);
    }

    /// 塗りつぶし矩形を描画
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        for y in rect.y..rect.bottom() {
            for x in rect.x..rect.right() {
                self.set_pixel(x, y, color);
            }
        }
    }

    /// 円を描画（Midpointアルゴリズム）
    pub fn draw_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        let mut x = radius;
        let mut y = 0;
        let mut err = 0;

        while x >= y {
            self.set_pixel(cx + x, cy + y, color);
            self.set_pixel(cx + y, cy + x, color);
            self.set_pixel(cx - y, cy + x, color);
            self.set_pixel(cx - x, cy + y, color);
            self.set_pixel(cx - x, cy - y, color);
            self.set_pixel(cx - y, cy - x, color);
            self.set_pixel(cx + y, cy - x, color);
            self.set_pixel(cx + x, cy - y, color);

            y += 1;
            if err <= 0 {
                err += 2 * y + 1;
            }
            if err > 0 {
                x -= 1;
                err -= 2 * x + 1;
            }
        }
    }

    /// 塗りつぶし円を描画
    pub fn fill_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        let mut x = radius;
        let mut y = 0;
        let mut err = 0;

        while x >= y {
            self.draw_hline(cx - x, cx + x, cy + y, color);
            self.draw_hline(cx - y, cx + y, cy + x, color);
            self.draw_hline(cx - x, cx + x, cy - y, color);
            self.draw_hline(cx - y, cx + y, cy - x, color);

            y += 1;
            if err <= 0 {
                err += 2 * y + 1;
            }
            if err > 0 {
                x -= 1;
                err -= 2 * x + 1;
            }
        }
    }
}

// ============================================================================
// Bitmap Font
// ============================================================================

/// 8x16ビットマップフォント（基本ASCII）
pub struct BitmapFont {
    /// フォントデータ（各文字16バイト）
    data: &'static [u8],
    /// 文字幅
    width: u32,
    /// 文字高さ
    height: u32,
}

impl BitmapFont {
    /// 組み込みの8x16フォントを取得
    pub fn default_8x16() -> Self {
        Self {
            data: &DEFAULT_FONT_8X16,
            width: 8,
            height: 16,
        }
    }

    /// 文字を描画
    pub fn draw_char(&self, fb: &mut Framebuffer, x: i32, y: i32, c: char, color: Color, bg: Option<Color>) {
        let c = c as usize;
        if c >= 128 {
            return;
        }

        let glyph_start = c * self.height as usize;
        let glyph_end = glyph_start + self.height as usize;

        if glyph_end > self.data.len() {
            return;
        }

        for (row, &byte) in self.data[glyph_start..glyph_end].iter().enumerate() {
            for col in 0..self.width {
                let pixel_on = (byte >> (7 - col)) & 1 != 0;
                let py = y + row as i32;
                let px = x + col as i32;

                if pixel_on {
                    fb.set_pixel(px, py, color);
                } else if let Some(bg_color) = bg {
                    fb.set_pixel(px, py, bg_color);
                }
            }
        }
    }

    /// 文字列を描画
    pub fn draw_string(&self, fb: &mut Framebuffer, x: i32, y: i32, s: &str, color: Color, bg: Option<Color>) {
        let mut cx = x;

        for c in s.chars() {
            if c == '\n' {
                // 改行は無視（必要に応じて対応）
                continue;
            }

            self.draw_char(fb, cx, y, c, color, bg);
            cx += self.width as i32;
        }
    }

    /// 文字幅を取得
    pub fn width(&self) -> u32 {
        self.width
    }

    /// 文字高さを取得
    pub fn height(&self) -> u32 {
        self.height
    }
}

// デフォルトの8x16フォントデータ（基本的なASCII文字）
static DEFAULT_FONT_8X16: [u8; 128 * 16] = {
    let mut font = [0u8; 128 * 16];

    // Space (32)
    // All zeros - already initialized

    // 数字 0-9 (48-57) の簡易定義
    // '0' (48)
    font[48 * 16 + 0] = 0b00111100;
    font[48 * 16 + 1] = 0b01100110;
    font[48 * 16 + 2] = 0b01100110;
    font[48 * 16 + 3] = 0b01101110;
    font[48 * 16 + 4] = 0b01110110;
    font[48 * 16 + 5] = 0b01100110;
    font[48 * 16 + 6] = 0b01100110;
    font[48 * 16 + 7] = 0b00111100;

    // '1' (49)
    font[49 * 16 + 0] = 0b00011000;
    font[49 * 16 + 1] = 0b00111000;
    font[49 * 16 + 2] = 0b00011000;
    font[49 * 16 + 3] = 0b00011000;
    font[49 * 16 + 4] = 0b00011000;
    font[49 * 16 + 5] = 0b00011000;
    font[49 * 16 + 6] = 0b00011000;
    font[49 * 16 + 7] = 0b01111110;

    // '2' (50)
    font[50 * 16 + 0] = 0b00111100;
    font[50 * 16 + 1] = 0b01100110;
    font[50 * 16 + 2] = 0b00000110;
    font[50 * 16 + 3] = 0b00001100;
    font[50 * 16 + 4] = 0b00011000;
    font[50 * 16 + 5] = 0b00110000;
    font[50 * 16 + 6] = 0b01100000;
    font[50 * 16 + 7] = 0b01111110;

    // '3' (51)
    font[51 * 16 + 0] = 0b00111100;
    font[51 * 16 + 1] = 0b01100110;
    font[51 * 16 + 2] = 0b00000110;
    font[51 * 16 + 3] = 0b00011100;
    font[51 * 16 + 4] = 0b00000110;
    font[51 * 16 + 5] = 0b00000110;
    font[51 * 16 + 6] = 0b01100110;
    font[51 * 16 + 7] = 0b00111100;

    // 'A' (65)
    font[65 * 16 + 0] = 0b00011000;
    font[65 * 16 + 1] = 0b00111100;
    font[65 * 16 + 2] = 0b01100110;
    font[65 * 16 + 3] = 0b01100110;
    font[65 * 16 + 4] = 0b01111110;
    font[65 * 16 + 5] = 0b01100110;
    font[65 * 16 + 6] = 0b01100110;
    font[65 * 16 + 7] = 0b01100110;

    // 'B' (66)
    font[66 * 16 + 0] = 0b01111100;
    font[66 * 16 + 1] = 0b01100110;
    font[66 * 16 + 2] = 0b01100110;
    font[66 * 16 + 3] = 0b01111100;
    font[66 * 16 + 4] = 0b01100110;
    font[66 * 16 + 5] = 0b01100110;
    font[66 * 16 + 6] = 0b01100110;
    font[66 * 16 + 7] = 0b01111100;

    // 'C' (67)
    font[67 * 16 + 0] = 0b00111100;
    font[67 * 16 + 1] = 0b01100110;
    font[67 * 16 + 2] = 0b01100000;
    font[67 * 16 + 3] = 0b01100000;
    font[67 * 16 + 4] = 0b01100000;
    font[67 * 16 + 5] = 0b01100000;
    font[67 * 16 + 6] = 0b01100110;
    font[67 * 16 + 7] = 0b00111100;

    // 'D' (68)
    font[68 * 16 + 0] = 0b01111000;
    font[68 * 16 + 1] = 0b01101100;
    font[68 * 16 + 2] = 0b01100110;
    font[68 * 16 + 3] = 0b01100110;
    font[68 * 16 + 4] = 0b01100110;
    font[68 * 16 + 5] = 0b01100110;
    font[68 * 16 + 6] = 0b01101100;
    font[68 * 16 + 7] = 0b01111000;

    // 'E' (69)
    font[69 * 16 + 0] = 0b01111110;
    font[69 * 16 + 1] = 0b01100000;
    font[69 * 16 + 2] = 0b01100000;
    font[69 * 16 + 3] = 0b01111100;
    font[69 * 16 + 4] = 0b01100000;
    font[69 * 16 + 5] = 0b01100000;
    font[69 * 16 + 6] = 0b01100000;
    font[69 * 16 + 7] = 0b01111110;

    // 'R' (82) - for RanyOS
    font[82 * 16 + 0] = 0b01111100;
    font[82 * 16 + 1] = 0b01100110;
    font[82 * 16 + 2] = 0b01100110;
    font[82 * 16 + 3] = 0b01111100;
    font[82 * 16 + 4] = 0b01101100;
    font[82 * 16 + 5] = 0b01100110;
    font[82 * 16 + 6] = 0b01100110;
    font[82 * 16 + 7] = 0b01100110;

    // 'a' (97)
    font[97 * 16 + 2] = 0b00111100;
    font[97 * 16 + 3] = 0b00000110;
    font[97 * 16 + 4] = 0b00111110;
    font[97 * 16 + 5] = 0b01100110;
    font[97 * 16 + 6] = 0b01100110;
    font[97 * 16 + 7] = 0b00111110;

    // 'n' (110)
    font[110 * 16 + 2] = 0b01111100;
    font[110 * 16 + 3] = 0b01100110;
    font[110 * 16 + 4] = 0b01100110;
    font[110 * 16 + 5] = 0b01100110;
    font[110 * 16 + 6] = 0b01100110;
    font[110 * 16 + 7] = 0b01100110;

    // 'y' (121)
    font[121 * 16 + 2] = 0b01100110;
    font[121 * 16 + 3] = 0b01100110;
    font[121 * 16 + 4] = 0b01100110;
    font[121 * 16 + 5] = 0b00111110;
    font[121 * 16 + 6] = 0b00000110;
    font[121 * 16 + 7] = 0b00111100;

    // 'O' (79)
    font[79 * 16 + 0] = 0b00111100;
    font[79 * 16 + 1] = 0b01100110;
    font[79 * 16 + 2] = 0b01100110;
    font[79 * 16 + 3] = 0b01100110;
    font[79 * 16 + 4] = 0b01100110;
    font[79 * 16 + 5] = 0b01100110;
    font[79 * 16 + 6] = 0b01100110;
    font[79 * 16 + 7] = 0b00111100;

    // 'S' (83)
    font[83 * 16 + 0] = 0b00111100;
    font[83 * 16 + 1] = 0b01100110;
    font[83 * 16 + 2] = 0b01100000;
    font[83 * 16 + 3] = 0b00111100;
    font[83 * 16 + 4] = 0b00000110;
    font[83 * 16 + 5] = 0b00000110;
    font[83 * 16 + 6] = 0b01100110;
    font[83 * 16 + 7] = 0b00111100;

    // ':' (58)
    font[58 * 16 + 2] = 0b00011000;
    font[58 * 16 + 3] = 0b00011000;
    font[58 * 16 + 5] = 0b00011000;
    font[58 * 16 + 6] = 0b00011000;

    // '>' (62)
    font[62 * 16 + 1] = 0b01100000;
    font[62 * 16 + 2] = 0b00011000;
    font[62 * 16 + 3] = 0b00000110;
    font[62 * 16 + 4] = 0b00011000;
    font[62 * 16 + 5] = 0b01100000;

    // '$' (36)
    font[36 * 16 + 0] = 0b00011000;
    font[36 * 16 + 1] = 0b00111110;
    font[36 * 16 + 2] = 0b01100000;
    font[36 * 16 + 3] = 0b00111100;
    font[36 * 16 + 4] = 0b00000110;
    font[36 * 16 + 5] = 0b01111100;
    font[36 * 16 + 6] = 0b00011000;
    font[36 * 16 + 7] = 0b00011000;

    // ' ' (32) space - all zeros, already done

    // '-' (45)
    font[45 * 16 + 4] = 0b01111110;

    // '/' (47)
    font[47 * 16 + 1] = 0b00000110;
    font[47 * 16 + 2] = 0b00001100;
    font[47 * 16 + 3] = 0b00011000;
    font[47 * 16 + 4] = 0b00110000;
    font[47 * 16 + 5] = 0b01100000;

    font
};

// ============================================================================
// Text Console
// ============================================================================

/// テキストコンソール
pub struct TextConsole {
    /// フレームバッファへの参照
    fb: *mut Framebuffer,
    /// フォント
    font: BitmapFont,
    /// 現在のカーソル位置（文字単位）
    cursor_x: u32,
    cursor_y: u32,
    /// コンソールサイズ（文字単位）
    cols: u32,
    rows: u32,
    /// 文字色
    fg_color: Color,
    /// 背景色
    bg_color: Color,
    /// テキストバッファ
    buffer: Vec<char>,
}

unsafe impl Send for TextConsole {}
unsafe impl Sync for TextConsole {}

impl TextConsole {
    /// 新しいコンソールを作成
    pub fn new(fb: &mut Framebuffer) -> Self {
        let font = BitmapFont::default_8x16();
        let cols = fb.width() / font.width();
        let rows = fb.height() / font.height();

        let buffer_size = (cols * rows) as usize;
        let buffer = vec![' '; buffer_size];

        Self {
            fb,
            font,
            cursor_x: 0,
            cursor_y: 0,
            cols,
            rows,
            fg_color: Color::WHITE,
            bg_color: Color::BLACK,
            buffer,
        }
    }

    /// 画面をクリア
    pub fn clear(&mut self) {
        unsafe {
            (*self.fb).clear(self.bg_color);
        }
        self.cursor_x = 0;
        self.cursor_y = 0;
        self.buffer.fill(' ');
    }

    /// 色を設定
    pub fn set_colors(&mut self, fg: Color, bg: Color) {
        self.fg_color = fg;
        self.bg_color = bg;
    }

    /// 文字を出力
    pub fn put_char(&mut self, c: char) {
        match c {
            '\n' => {
                self.cursor_x = 0;
                self.cursor_y += 1;
            }
            '\r' => {
                self.cursor_x = 0;
            }
            '\t' => {
                let spaces = 4 - (self.cursor_x % 4);
                for _ in 0..spaces {
                    self.put_char(' ');
                }
            }
            '\x08' => {
                // バックスペース
                if self.cursor_x > 0 {
                    self.cursor_x -= 1;
                    self.draw_char_at(self.cursor_x, self.cursor_y, ' ');
                }
            }
            _ => {
                if self.cursor_x >= self.cols {
                    self.cursor_x = 0;
                    self.cursor_y += 1;
                }

                self.draw_char_at(self.cursor_x, self.cursor_y, c);
                self.cursor_x += 1;
            }
        }

        // スクロールが必要な場合
        if self.cursor_y >= self.rows {
            self.scroll_up();
            self.cursor_y = self.rows - 1;
        }
    }

    /// 指定位置に文字を描画
    fn draw_char_at(&mut self, col: u32, row: u32, c: char) {
        let x = (col * self.font.width()) as i32;
        let y = (row * self.font.height()) as i32;

        // バッファを更新
        let idx = (row * self.cols + col) as usize;
        if idx < self.buffer.len() {
            self.buffer[idx] = c;
        }

        unsafe {
            self.font.draw_char(
                &mut *self.fb,
                x,
                y,
                c,
                self.fg_color,
                Some(self.bg_color),
            );
        }
    }

    /// 画面を1行スクロールアップ
    fn scroll_up(&mut self) {
        // バッファをシフト
        for row in 1..self.rows {
            for col in 0..self.cols {
                let src_idx = (row * self.cols + col) as usize;
                let dst_idx = ((row - 1) * self.cols + col) as usize;
                if src_idx < self.buffer.len() && dst_idx < self.buffer.len() {
                    self.buffer[dst_idx] = self.buffer[src_idx];
                }
            }
        }

        // 最後の行をクリア
        let last_row_start = ((self.rows - 1) * self.cols) as usize;
        for i in 0..self.cols as usize {
            if last_row_start + i < self.buffer.len() {
                self.buffer[last_row_start + i] = ' ';
            }
        }

        // 画面を再描画
        self.redraw();
    }

    /// 画面全体を再描画
    fn redraw(&mut self) {
        unsafe {
            (*self.fb).clear(self.bg_color);
        }

        for row in 0..self.rows {
            for col in 0..self.cols {
                let idx = (row * self.cols + col) as usize;
                if idx < self.buffer.len() {
                    let c = self.buffer[idx];
                    if c != ' ' {
                        let x = (col * self.font.width()) as i32;
                        let y = (row * self.font.height()) as i32;
                        unsafe {
                            self.font.draw_char(
                                &mut *self.fb,
                                x,
                                y,
                                c,
                                self.fg_color,
                                None,
                            );
                        }
                    }
                }
            }
        }
    }

    /// 文字列を出力
    pub fn write_str(&mut self, s: &str) {
        for c in s.chars() {
            self.put_char(c);
        }
    }

    /// カーソル位置を設定
    pub fn set_cursor(&mut self, col: u32, row: u32) {
        self.cursor_x = col.min(self.cols - 1);
        self.cursor_y = row.min(self.rows - 1);
    }

    /// カーソル位置を取得
    pub fn cursor(&self) -> (u32, u32) {
        (self.cursor_x, self.cursor_y)
    }
}

impl core::fmt::Write for TextConsole {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.write_str(s);
        Ok(())
    }
}

// ============================================================================
// Global State
// ============================================================================

/// グローバルフレームバッファ
static FRAMEBUFFER: Mutex<Option<Framebuffer>> = Mutex::new(None);

/// グローバルコンソール
static CONSOLE: Mutex<Option<TextConsole>> = Mutex::new(None);

/// フレームバッファを初期化
pub fn init(info: FramebufferInfo) {
    let mut fb = unsafe { Framebuffer::new(info) };
    fb.clear(Color::BLACK);

    *FRAMEBUFFER.lock() = Some(fb);

    crate::log!("[GRAPHICS] Framebuffer initialized: {}x{}\n",
        FRAMEBUFFER.lock().as_ref().unwrap().width(),
        FRAMEBUFFER.lock().as_ref().unwrap().height()
    );
}

/// グラフィカルコンソールを初期化
pub fn init_console() {
    let mut fb_guard = FRAMEBUFFER.lock();
    if let Some(ref mut fb) = *fb_guard {
        let console = TextConsole::new(fb);
        drop(fb_guard);
        *CONSOLE.lock() = Some(console);
        crate::log!("[GRAPHICS] Text console initialized\n");
    }
}

/// フレームバッファにアクセス
pub fn with_framebuffer<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Framebuffer) -> R,
{
    let mut guard = FRAMEBUFFER.lock();
    guard.as_mut().map(f)
}

/// コンソールにアクセス
pub fn with_console<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut TextConsole) -> R,
{
    let mut guard = CONSOLE.lock();
    guard.as_mut().map(f)
}

/// コンソールに出力
pub fn console_print(s: &str) {
    with_console(|console| {
        console.write_str(s);
    });
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color() {
        let c = Color::new(255, 128, 64);
        assert_eq!(c.red, 255);
        assert_eq!(c.green, 128);
        assert_eq!(c.blue, 64);
    }

    #[test]
    fn test_rect() {
        let r1 = Rect::new(0, 0, 100, 100);
        let r2 = Rect::new(50, 50, 100, 100);

        assert!(r1.intersects(&r2));

        let intersection = r1.intersection(&r2).unwrap();
        assert_eq!(intersection.x, 50);
        assert_eq!(intersection.y, 50);
        assert_eq!(intersection.width, 50);
        assert_eq!(intersection.height, 50);
    }
}
