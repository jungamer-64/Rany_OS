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
//! - Limineブートローダー統合
//! - ウィンドウコンポジタ

#![allow(dead_code)]

// サブモジュール
pub mod bsod;
pub mod compositor;
pub mod image;
pub mod qrcode;
pub mod window;

use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use spin::Mutex;
use limine::response::FramebufferResponse;

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
        Self {
            x,
            y,
            width,
            height,
        }
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
        point.x >= self.x && point.x < self.right() && point.y >= self.y && point.y < self.bottom()
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

        Some(Rect::new(x, y, (right - x) as u32, (bottom - y) as u32))
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

    /// ダブルバッファリングが有効かどうかを取得
    pub fn is_double_buffered(&self) -> bool {
        self.back_buffer.is_some()
    }

    /// バックバッファをフロントにコピー
    pub fn swap_buffers(&mut self) {
        if let Some(ref back) = self.back_buffer {
            unsafe {
                ptr::copy_nonoverlapping(back.as_ptr(), self.buffer, self.info.size());
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

        let offset =
            (y * self.info.stride) as usize + (x as usize * self.info.format.bytes_per_pixel());

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

        let offset =
            (y * self.info.stride) as usize + (x as usize * self.info.format.bytes_per_pixel());

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

    /// テキストを描画（組み込み8x16フォントを使用）
    /// 
    /// # Arguments
    /// * `x` - 開始X座標
    /// * `y` - 開始Y座標
    /// * `text` - 描画するテキスト
    /// * `color` - 文字色
    /// * `bg_color` - 背景色
    pub fn draw_text(&mut self, x: i32, y: i32, text: &str, color: Color, bg_color: Color) {
        let font = BitmapFont::default_8x16();
        let mut cx = x;

        for c in text.chars() {
            if c == '\n' {
                continue;
            }

            // 文字を描画
            let c_index = c as usize;
            if c_index < 128 {
                let glyph_start = c_index * font.height as usize;
                
                for row in 0..font.height {
                    let glyph_row = glyph_start + row as usize;
                    if glyph_row < font.data.len() {
                        let byte = font.data[glyph_row];
                        for col in 0..font.width {
                            let pixel_on = (byte >> (7 - col)) & 1 != 0;
                            let px = cx + col as i32;
                            let py = y + row as i32;
                            
                            if pixel_on {
                                self.set_pixel(px, py, color);
                            } else {
                                self.set_pixel(px, py, bg_color);
                            }
                        }
                    }
                }
            }
            
            cx += font.width as i32;
        }
    }
}

/// 8x16フォントの幅定数
pub const FONT_WIDTH: u32 = 8;
/// 8x16フォントの高さ定数
pub const FONT_HEIGHT: u32 = 16;

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
    pub fn draw_char(
        &self,
        fb: &mut Framebuffer,
        x: i32,
        y: i32,
        c: char,
        color: Color,
        bg: Option<Color>,
    ) {
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
    pub fn draw_string(
        &self,
        fb: &mut Framebuffer,
        x: i32,
        y: i32,
        s: &str,
        color: Color,
        bg: Option<Color>,
    ) {
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

// ============================================================================
// Complete 8x16 VGA-style Bitmap Font
// ============================================================================
// 完全なASCIIビットマップフォント（32-126）
// 標準VGAフォントに基づく8x16ピクセル

/// 完全な8x16 ASCIIフォントデータ
/// 128文字 × 16行 = 2048バイト
#[rustfmt::skip]
static DEFAULT_FONT_8X16: [u8; 128 * 16] = [
    // 0x00-0x1F: 制御文字（空白）
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x00
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x01
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x02
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x03
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x04
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x05
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x06
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x07
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x08
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x09
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x0A
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x0B
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x0C
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x0D
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x0E
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x0F
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x10
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x11
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x12
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x13
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x14
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x15
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x16
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x17
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x18
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x19
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x1A
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x1B
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x1C
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x1D
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x1E
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, // 0x1F
    
    // 0x20: Space ' '
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x21: '!'
    0x00,0x00,0x18,0x3C,0x3C,0x3C,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00,
    // 0x22: '"'
    0x00,0x66,0x66,0x66,0x24,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x23: '#'
    0x00,0x00,0x00,0x6C,0x6C,0xFE,0x6C,0x6C,0x6C,0xFE,0x6C,0x6C,0x00,0x00,0x00,0x00,
    // 0x24: '$'
    0x18,0x18,0x7C,0xC6,0xC2,0xC0,0x7C,0x06,0x06,0x86,0xC6,0x7C,0x18,0x18,0x00,0x00,
    // 0x25: '%'
    0x00,0x00,0x00,0x00,0xC2,0xC6,0x0C,0x18,0x30,0x60,0xC6,0x86,0x00,0x00,0x00,0x00,
    // 0x26: '&'
    0x00,0x00,0x38,0x6C,0x6C,0x38,0x76,0xDC,0xCC,0xCC,0xCC,0x76,0x00,0x00,0x00,0x00,
    // 0x27: '''
    0x00,0x30,0x30,0x30,0x60,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x28: '('
    0x00,0x00,0x0C,0x18,0x30,0x30,0x30,0x30,0x30,0x30,0x18,0x0C,0x00,0x00,0x00,0x00,
    // 0x29: ')'
    0x00,0x00,0x30,0x18,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x18,0x30,0x00,0x00,0x00,0x00,
    // 0x2A: '*'
    0x00,0x00,0x00,0x00,0x00,0x66,0x3C,0xFF,0x3C,0x66,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x2B: '+'
    0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x7E,0x18,0x18,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x2C: ','
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x18,0x30,0x00,0x00,0x00,
    // 0x2D: '-'
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFE,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x2E: '.'
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,
    // 0x2F: '/'
    0x00,0x00,0x00,0x00,0x02,0x06,0x0C,0x18,0x30,0x60,0xC0,0x80,0x00,0x00,0x00,0x00,
    // 0x30: '0'
    0x00,0x00,0x3C,0x66,0xC3,0xC3,0xDB,0xDB,0xC3,0xC3,0x66,0x3C,0x00,0x00,0x00,0x00,
    // 0x31: '1'
    0x00,0x00,0x18,0x38,0x78,0x18,0x18,0x18,0x18,0x18,0x18,0x7E,0x00,0x00,0x00,0x00,
    // 0x32: '2'
    0x00,0x00,0x7C,0xC6,0x06,0x0C,0x18,0x30,0x60,0xC0,0xC6,0xFE,0x00,0x00,0x00,0x00,
    // 0x33: '3'
    0x00,0x00,0x7C,0xC6,0x06,0x06,0x3C,0x06,0x06,0x06,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x34: '4'
    0x00,0x00,0x0C,0x1C,0x3C,0x6C,0xCC,0xFE,0x0C,0x0C,0x0C,0x1E,0x00,0x00,0x00,0x00,
    // 0x35: '5'
    0x00,0x00,0xFE,0xC0,0xC0,0xC0,0xFC,0x06,0x06,0x06,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x36: '6'
    0x00,0x00,0x38,0x60,0xC0,0xC0,0xFC,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x37: '7'
    0x00,0x00,0xFE,0xC6,0x06,0x06,0x0C,0x18,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00,
    // 0x38: '8'
    0x00,0x00,0x7C,0xC6,0xC6,0xC6,0x7C,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x39: '9'
    0x00,0x00,0x7C,0xC6,0xC6,0xC6,0x7E,0x06,0x06,0x06,0x0C,0x78,0x00,0x00,0x00,0x00,
    // 0x3A: ':'
    0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x00,0x00,
    // 0x3B: ';'
    0x00,0x00,0x00,0x00,0x18,0x18,0x00,0x00,0x00,0x18,0x18,0x30,0x00,0x00,0x00,0x00,
    // 0x3C: '<'
    0x00,0x00,0x00,0x06,0x0C,0x18,0x30,0x60,0x30,0x18,0x0C,0x06,0x00,0x00,0x00,0x00,
    // 0x3D: '='
    0x00,0x00,0x00,0x00,0x00,0x7E,0x00,0x00,0x7E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x3E: '>'
    0x00,0x00,0x00,0x60,0x30,0x18,0x0C,0x06,0x0C,0x18,0x30,0x60,0x00,0x00,0x00,0x00,
    // 0x3F: '?'
    0x00,0x00,0x7C,0xC6,0xC6,0x0C,0x18,0x18,0x18,0x00,0x18,0x18,0x00,0x00,0x00,0x00,
    // 0x40: '@'
    0x00,0x00,0x00,0x7C,0xC6,0xC6,0xDE,0xDE,0xDE,0xDC,0xC0,0x7C,0x00,0x00,0x00,0x00,
    // 0x41: 'A'
    0x00,0x00,0x10,0x38,0x6C,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0xC6,0x00,0x00,0x00,0x00,
    // 0x42: 'B'
    0x00,0x00,0xFC,0x66,0x66,0x66,0x7C,0x66,0x66,0x66,0x66,0xFC,0x00,0x00,0x00,0x00,
    // 0x43: 'C'
    0x00,0x00,0x3C,0x66,0xC2,0xC0,0xC0,0xC0,0xC0,0xC2,0x66,0x3C,0x00,0x00,0x00,0x00,
    // 0x44: 'D'
    0x00,0x00,0xF8,0x6C,0x66,0x66,0x66,0x66,0x66,0x66,0x6C,0xF8,0x00,0x00,0x00,0x00,
    // 0x45: 'E'
    0x00,0x00,0xFE,0x66,0x62,0x68,0x78,0x68,0x60,0x62,0x66,0xFE,0x00,0x00,0x00,0x00,
    // 0x46: 'F'
    0x00,0x00,0xFE,0x66,0x62,0x68,0x78,0x68,0x60,0x60,0x60,0xF0,0x00,0x00,0x00,0x00,
    // 0x47: 'G'
    0x00,0x00,0x3C,0x66,0xC2,0xC0,0xC0,0xDE,0xC6,0xC6,0x66,0x3A,0x00,0x00,0x00,0x00,
    // 0x48: 'H'
    0x00,0x00,0xC6,0xC6,0xC6,0xC6,0xFE,0xC6,0xC6,0xC6,0xC6,0xC6,0x00,0x00,0x00,0x00,
    // 0x49: 'I'
    0x00,0x00,0x3C,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,
    // 0x4A: 'J'
    0x00,0x00,0x1E,0x0C,0x0C,0x0C,0x0C,0x0C,0xCC,0xCC,0xCC,0x78,0x00,0x00,0x00,0x00,
    // 0x4B: 'K'
    0x00,0x00,0xE6,0x66,0x66,0x6C,0x78,0x78,0x6C,0x66,0x66,0xE6,0x00,0x00,0x00,0x00,
    // 0x4C: 'L'
    0x00,0x00,0xF0,0x60,0x60,0x60,0x60,0x60,0x60,0x62,0x66,0xFE,0x00,0x00,0x00,0x00,
    // 0x4D: 'M'
    0x00,0x00,0xC3,0xE7,0xFF,0xFF,0xDB,0xC3,0xC3,0xC3,0xC3,0xC3,0x00,0x00,0x00,0x00,
    // 0x4E: 'N'
    0x00,0x00,0xC6,0xE6,0xF6,0xFE,0xDE,0xCE,0xC6,0xC6,0xC6,0xC6,0x00,0x00,0x00,0x00,
    // 0x4F: 'O'
    0x00,0x00,0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x50: 'P'
    0x00,0x00,0xFC,0x66,0x66,0x66,0x7C,0x60,0x60,0x60,0x60,0xF0,0x00,0x00,0x00,0x00,
    // 0x51: 'Q'
    0x00,0x00,0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xD6,0xDE,0x7C,0x0C,0x0E,0x00,0x00,
    // 0x52: 'R'
    0x00,0x00,0xFC,0x66,0x66,0x66,0x7C,0x6C,0x66,0x66,0x66,0xE6,0x00,0x00,0x00,0x00,
    // 0x53: 'S'
    0x00,0x00,0x7C,0xC6,0xC6,0x60,0x38,0x0C,0x06,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x54: 'T'
    0x00,0x00,0xFF,0xDB,0x99,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,
    // 0x55: 'U'
    0x00,0x00,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x56: 'V'
    0x00,0x00,0xC3,0xC3,0xC3,0xC3,0xC3,0xC3,0xC3,0x66,0x3C,0x18,0x00,0x00,0x00,0x00,
    // 0x57: 'W'
    0x00,0x00,0xC3,0xC3,0xC3,0xC3,0xC3,0xDB,0xDB,0xFF,0x66,0x66,0x00,0x00,0x00,0x00,
    // 0x58: 'X'
    0x00,0x00,0xC3,0xC3,0x66,0x3C,0x18,0x18,0x3C,0x66,0xC3,0xC3,0x00,0x00,0x00,0x00,
    // 0x59: 'Y'
    0x00,0x00,0xC3,0xC3,0xC3,0x66,0x3C,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,
    // 0x5A: 'Z'
    0x00,0x00,0xFE,0xC6,0x86,0x0C,0x18,0x30,0x60,0xC2,0xC6,0xFE,0x00,0x00,0x00,0x00,
    // 0x5B: '['
    0x00,0x00,0x3C,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x3C,0x00,0x00,0x00,0x00,
    // 0x5C: '\'
    0x00,0x00,0x00,0x80,0xC0,0x60,0x30,0x18,0x0C,0x06,0x02,0x00,0x00,0x00,0x00,0x00,
    // 0x5D: ']'
    0x00,0x00,0x3C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x0C,0x3C,0x00,0x00,0x00,0x00,
    // 0x5E: '^'
    0x10,0x38,0x6C,0xC6,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x5F: '_'
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x00,0x00,
    // 0x60: '`'
    0x30,0x30,0x18,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x61: 'a'
    0x00,0x00,0x00,0x00,0x00,0x78,0x0C,0x7C,0xCC,0xCC,0xCC,0x76,0x00,0x00,0x00,0x00,
    // 0x62: 'b'
    0x00,0x00,0xE0,0x60,0x60,0x78,0x6C,0x66,0x66,0x66,0x66,0x7C,0x00,0x00,0x00,0x00,
    // 0x63: 'c'
    0x00,0x00,0x00,0x00,0x00,0x7C,0xC6,0xC0,0xC0,0xC0,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x64: 'd'
    0x00,0x00,0x1C,0x0C,0x0C,0x3C,0x6C,0xCC,0xCC,0xCC,0xCC,0x76,0x00,0x00,0x00,0x00,
    // 0x65: 'e'
    0x00,0x00,0x00,0x00,0x00,0x7C,0xC6,0xFE,0xC0,0xC0,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x66: 'f'
    0x00,0x00,0x38,0x6C,0x64,0x60,0xF0,0x60,0x60,0x60,0x60,0xF0,0x00,0x00,0x00,0x00,
    // 0x67: 'g'
    0x00,0x00,0x00,0x00,0x00,0x76,0xCC,0xCC,0xCC,0xCC,0xCC,0x7C,0x0C,0xCC,0x78,0x00,
    // 0x68: 'h'
    0x00,0x00,0xE0,0x60,0x60,0x6C,0x76,0x66,0x66,0x66,0x66,0xE6,0x00,0x00,0x00,0x00,
    // 0x69: 'i'
    0x00,0x00,0x18,0x18,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,
    // 0x6A: 'j'
    0x00,0x00,0x06,0x06,0x00,0x0E,0x06,0x06,0x06,0x06,0x06,0x06,0x66,0x66,0x3C,0x00,
    // 0x6B: 'k'
    0x00,0x00,0xE0,0x60,0x60,0x66,0x6C,0x78,0x78,0x6C,0x66,0xE6,0x00,0x00,0x00,0x00,
    // 0x6C: 'l'
    0x00,0x00,0x38,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x18,0x3C,0x00,0x00,0x00,0x00,
    // 0x6D: 'm'
    0x00,0x00,0x00,0x00,0x00,0xE6,0xFF,0xDB,0xDB,0xDB,0xDB,0xDB,0x00,0x00,0x00,0x00,
    // 0x6E: 'n'
    0x00,0x00,0x00,0x00,0x00,0xDC,0x66,0x66,0x66,0x66,0x66,0x66,0x00,0x00,0x00,0x00,
    // 0x6F: 'o'
    0x00,0x00,0x00,0x00,0x00,0x7C,0xC6,0xC6,0xC6,0xC6,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x70: 'p'
    0x00,0x00,0x00,0x00,0x00,0xDC,0x66,0x66,0x66,0x66,0x66,0x7C,0x60,0x60,0xF0,0x00,
    // 0x71: 'q'
    0x00,0x00,0x00,0x00,0x00,0x76,0xCC,0xCC,0xCC,0xCC,0xCC,0x7C,0x0C,0x0C,0x1E,0x00,
    // 0x72: 'r'
    0x00,0x00,0x00,0x00,0x00,0xDC,0x76,0x66,0x60,0x60,0x60,0xF0,0x00,0x00,0x00,0x00,
    // 0x73: 's'
    0x00,0x00,0x00,0x00,0x00,0x7C,0xC6,0x60,0x38,0x0C,0xC6,0x7C,0x00,0x00,0x00,0x00,
    // 0x74: 't'
    0x00,0x00,0x10,0x30,0x30,0xFC,0x30,0x30,0x30,0x30,0x36,0x1C,0x00,0x00,0x00,0x00,
    // 0x75: 'u'
    0x00,0x00,0x00,0x00,0x00,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0x76,0x00,0x00,0x00,0x00,
    // 0x76: 'v'
    0x00,0x00,0x00,0x00,0x00,0xC3,0xC3,0xC3,0xC3,0x66,0x3C,0x18,0x00,0x00,0x00,0x00,
    // 0x77: 'w'
    0x00,0x00,0x00,0x00,0x00,0xC3,0xC3,0xC3,0xDB,0xDB,0xFF,0x66,0x00,0x00,0x00,0x00,
    // 0x78: 'x'
    0x00,0x00,0x00,0x00,0x00,0xC3,0x66,0x3C,0x18,0x3C,0x66,0xC3,0x00,0x00,0x00,0x00,
    // 0x79: 'y'
    0x00,0x00,0x00,0x00,0x00,0xC6,0xC6,0xC6,0xC6,0xC6,0xC6,0x7E,0x06,0x0C,0xF8,0x00,
    // 0x7A: 'z'
    0x00,0x00,0x00,0x00,0x00,0xFE,0xCC,0x18,0x30,0x60,0xC6,0xFE,0x00,0x00,0x00,0x00,
    // 0x7B: '{'
    0x00,0x00,0x0E,0x18,0x18,0x18,0x70,0x18,0x18,0x18,0x18,0x0E,0x00,0x00,0x00,0x00,
    // 0x7C: '|'
    0x00,0x00,0x18,0x18,0x18,0x18,0x00,0x18,0x18,0x18,0x18,0x18,0x00,0x00,0x00,0x00,
    // 0x7D: '}'
    0x00,0x00,0x70,0x18,0x18,0x18,0x0E,0x18,0x18,0x18,0x18,0x70,0x00,0x00,0x00,0x00,
    // 0x7E: '~'
    0x00,0x00,0x76,0xDC,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    // 0x7F: DEL (空白)
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
];

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
            self.font
                .draw_char(&mut *self.fb, x, y, c, self.fg_color, Some(self.bg_color));
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
                            self.font
                                .draw_char(&mut *self.fb, x, y, c, self.fg_color, None);
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

    // ロックを1回だけ取得して情報を取り出す（2回のlock+unwrap → 1回のlockで変数コピー）
    // アセンブリ: 2x (lock acquire + memory fence + unwrap check) → 1x lock + 2x mov
    let (w, h) = {
        let guard = FRAMEBUFFER.lock();
        let fb = guard.as_ref().expect("framebuffer must be initialized");
        (fb.width(), fb.height())
    };
    crate::log!("[GRAPHICS] Framebuffer initialized: {}x{}\n", w, h);
}

/// Limineフレームバッファレスポンスからグラフィックスを初期化
/// 
/// ブートローダーから提供されたフレームバッファ情報を使用して
/// グラフィックスサブシステムを初期化します。
pub fn init_from_limine(response: &FramebufferResponse) -> bool {
    // 最初のフレームバッファを使用
    let mut iter = response.framebuffers();
    let Some(fb) = iter.next() else {
        crate::log!("[GRAPHICS] No framebuffer available from bootloader\n");
        return false;
    };

    // ピクセルフォーマットを判定
    // Limineは通常BGRA8888フォーマットを使用
    let format = detect_pixel_format(
        fb.red_mask_size(),
        fb.red_mask_shift(),
        fb.green_mask_size(),
        fb.green_mask_shift(),
        fb.blue_mask_size(),
        fb.blue_mask_shift(),
        fb.bpp(),
    );

    let info = FramebufferInfo {
        address: fb.addr() as u64,
        width: fb.width() as u32,
        height: fb.height() as u32,
        stride: fb.pitch() as u32,
        format,
        bpp: fb.bpp() as u8,
    };

    crate::log!(
        "[GRAPHICS] Limine framebuffer: {}x{}@{}bpp pitch={} format={:?}\n",
        info.width,
        info.height,
        info.bpp,
        info.stride,
        info.format
    );

    init(info);
    true
}

/// マスク情報からピクセルフォーマットを判定
fn detect_pixel_format(
    red_size: u8,
    red_shift: u8,
    green_size: u8,
    green_shift: u8,
    blue_size: u8,
    blue_shift: u8,
    bpp: u16,
) -> PixelFormat {
    match bpp {
        32 => {
            // 32bpp: BGRA or RGBA
            if red_shift == 16 && green_shift == 8 && blue_shift == 0 {
                PixelFormat::Bgra8888
            } else if red_shift == 0 && green_shift == 8 && blue_shift == 16 {
                PixelFormat::Rgba8888
            } else {
                // デフォルトはBGRA（最も一般的）
                PixelFormat::Bgra8888
            }
        }
        24 => {
            // 24bpp: BGR or RGB
            if red_shift == 16 && green_shift == 8 && blue_shift == 0 {
                PixelFormat::Bgr888
            } else {
                PixelFormat::Rgb888
            }
        }
        16 => {
            // 16bpp: RGB565
            if red_size == 5 && green_size == 6 && blue_size == 5 {
                PixelFormat::Rgb565
            } else {
                PixelFormat::Rgb565 // デフォルト
            }
        }
        _ => PixelFormat::Bgra8888, // 未知のフォーマットはBGRA8888を仮定
    }
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

/// フレームバッファが初期化されているか確認
pub fn framebuffer() -> Option<()> {
    if FRAMEBUFFER.lock().is_some() {
        Some(())
    } else {
        None
    }
}

/// コンソールに出力
pub fn console_print(s: &str) {
    with_console(|console| {
        console.write_str(s);
    });
}

// ============================================================================
// Boot Splash Screen
// ============================================================================

/// ブートスプラッシュ用の定数
mod boot_splash {
    use super::Color;
    
    /// ロゴのカラーパレット
    pub const LOGO_PRIMARY: Color = Color::new(0x3A, 0xA6, 0xB9);   // シアン
    pub const LOGO_SECONDARY: Color = Color::new(0xF5, 0xA6, 0x23); // オレンジ
    pub const LOGO_ACCENT: Color = Color::new(0xFF, 0xFF, 0xFF);    // 白
    pub const BG_COLOR: Color = Color::new(0x1A, 0x1A, 0x2E);       // ダークブルー
    pub const TEXT_COLOR: Color = Color::new(0xE0, 0xE0, 0xE0);     // ライトグレー
    
    /// ロゴビットマップ（簡易版 - E, X, O の文字）
    /// 16x16ピクセルの簡易フォント
    #[rustfmt::skip]
    pub const LOGO_E: [[u8; 12]; 16] = [
        [1,1,1,1,1,1,1,1,1,1,1,1],
        [1,1,1,1,1,1,1,1,1,1,1,1],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,1,1,1,1,1,1,0,0,0,0],
        [1,1,1,1,1,1,1,1,0,0,0,0],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,0,0,0,0,0,0,0,0,0,0],
        [1,1,1,1,1,1,1,1,1,1,1,1],
        [1,1,1,1,1,1,1,1,1,1,1,1],
    ];
    
    #[rustfmt::skip]
    pub const LOGO_X: [[u8; 12]; 16] = [
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [0,1,1,0,0,0,0,0,0,1,1,0],
        [0,1,1,0,0,0,0,0,0,1,1,0],
        [0,0,1,1,0,0,0,0,1,1,0,0],
        [0,0,1,1,0,0,0,0,1,1,0,0],
        [0,0,0,1,1,0,0,1,1,0,0,0],
        [0,0,0,1,1,0,0,1,1,0,0,0],
        [0,0,0,1,1,0,0,1,1,0,0,0],
        [0,0,0,1,1,0,0,1,1,0,0,0],
        [0,0,1,1,0,0,0,0,1,1,0,0],
        [0,0,1,1,0,0,0,0,1,1,0,0],
        [0,1,1,0,0,0,0,0,0,1,1,0],
        [0,1,1,0,0,0,0,0,0,1,1,0],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [1,1,0,0,0,0,0,0,0,0,1,1],
    ];
    
    #[rustfmt::skip]
    pub const LOGO_O: [[u8; 12]; 16] = [
        [0,0,0,1,1,1,1,1,1,0,0,0],
        [0,0,1,1,1,1,1,1,1,1,0,0],
        [0,1,1,0,0,0,0,0,0,1,1,0],
        [0,1,1,0,0,0,0,0,0,1,1,0],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [1,1,0,0,0,0,0,0,0,0,1,1],
        [0,1,1,0,0,0,0,0,0,1,1,0],
        [0,1,1,0,0,0,0,0,0,1,1,0],
        [0,0,1,1,1,1,1,1,1,1,0,0],
        [0,0,0,1,1,1,1,1,1,0,0,0],
    ];
}

/// ブートスプラッシュを表示
/// 
/// カーネル起動時にグラフィカルなスプラッシュ画面を表示します。
/// フレームバッファが初期化されていない場合は何もしません。
pub fn show_boot_splash() {
    with_framebuffer(|fb| {
        let width = fb.width();
        let height = fb.height();
        
        // 背景を塗りつぶす
        fb.clear(boot_splash::BG_COLOR);
        
        // ロゴを中央に描画（スケーリング係数）
        let scale = 4u32;
        let char_width = 12 * scale;
        let char_height = 16 * scale;
        let spacing = 4 * scale;
        let total_width = char_width * 3 + spacing * 2; // E, X, O + スペース
        
        let start_x = (width - total_width) / 2;
        let start_y = height / 3;
        
        // "E" を描画
        draw_logo_char(fb, &boot_splash::LOGO_E, start_x as i32, start_y as i32, scale, boot_splash::LOGO_PRIMARY);
        
        // "X" を描画
        let x_offset = start_x + char_width + spacing;
        draw_logo_char(fb, &boot_splash::LOGO_X, x_offset as i32, start_y as i32, scale, boot_splash::LOGO_SECONDARY);
        
        // "O" を描画
        let o_offset = x_offset + char_width + spacing;
        draw_logo_char(fb, &boot_splash::LOGO_O, o_offset as i32, start_y as i32, scale, boot_splash::LOGO_PRIMARY);
        
        // テキスト: "RanyOS" - ロゴの下
        let text_y = (start_y + char_height + 20) as i32;
        draw_centered_text(fb, "RanyOS", text_y, boot_splash::LOGO_ACCENT);
        
        // テキスト: バージョン情報
        let version_y = text_y + (FONT_HEIGHT as i32) + 8;
        draw_centered_text(fb, "Exokernel v0.3.0-alpha", version_y, boot_splash::TEXT_COLOR);
        
        // テキスト: ステータスメッセージ
        let status_y = (height * 2 / 3 + 24) as i32;
        draw_centered_text(fb, "Initializing...", status_y, boot_splash::TEXT_COLOR);
        
        // 進捗バー
        let bar_y = height * 2 / 3;
        let bar_width = width / 3;
        let bar_height = 8u32;
        let bar_x = (width - bar_width) / 2;
        
        // 進捗バーの背景
        fb.fill_rect(
            Rect::new(bar_x as i32, bar_y as i32, bar_width, bar_height),
            Color::new(0x40, 0x40, 0x50),
        );
        
        // 進捗バー（初期状態：10%）
        fb.fill_rect(
            Rect::new(bar_x as i32, bar_y as i32, bar_width / 10, bar_height),
            boot_splash::LOGO_PRIMARY,
        );
    });
}

/// ブートスプラッシュの進捗を更新
/// 
/// # Arguments
/// * `progress` - 進捗率（0-100）
pub fn update_boot_progress(progress: u32) {
    with_framebuffer(|fb| {
        let width = fb.width();
        let height = fb.height();
        
        let bar_y = height * 2 / 3;
        let bar_width = width / 3;
        let bar_height = 8u32;
        let bar_x = (width - bar_width) / 2;
        
        // 進捗に応じてバーを更新
        let filled_width = (bar_width * progress.min(100)) / 100;
        
        // バー全体を再描画
        fb.fill_rect(
            Rect::new(bar_x as i32, bar_y as i32, bar_width, bar_height),
            Color::new(0x40, 0x40, 0x50),
        );
        
        fb.fill_rect(
            Rect::new(bar_x as i32, bar_y as i32, filled_width, bar_height),
            boot_splash::LOGO_PRIMARY,
        );
        
        if fb.is_double_buffered() {
            fb.swap_buffers();
        }
    });
}

/// ロゴ文字を描画（ビットマップからスケーリング）
fn draw_logo_char(fb: &mut Framebuffer, bitmap: &[[u8; 12]; 16], x: i32, y: i32, scale: u32, color: Color) {
    for (row, line) in bitmap.iter().enumerate() {
        for (col, &pixel) in line.iter().enumerate() {
            if pixel != 0 {
                // スケーリング
                for sy in 0..scale {
                    for sx in 0..scale {
                        let px = x + (col as i32) * scale as i32 + sx as i32;
                        let py = y + (row as i32) * scale as i32 + sy as i32;
                        fb.set_pixel(px, py, color);
                    }
                }
            }
        }
    }
}

/// 中央揃えテキストを描画
fn draw_centered_text(fb: &mut Framebuffer, text: &str, y: i32, color: Color) {
    let width = fb.width();
    let text_width = text.len() as u32 * FONT_WIDTH;
    let x = ((width - text_width) / 2) as i32;
    fb.draw_text(x, y, text, color, boot_splash::BG_COLOR);
}

/// ブートスプラッシュの進捗とメッセージを更新
/// 
/// # Arguments
/// * `progress` - 進捗率（0-100）
/// * `message` - 表示するステータスメッセージ
pub fn update_boot_progress_with_message(progress: u32, message: &str) {
    with_framebuffer(|fb| {
        let width = fb.width();
        let height = fb.height();
        
        let bar_y = height * 2 / 3;
        let bar_width = width / 3;
        let bar_height = 8u32;
        let bar_x = (width - bar_width) / 2;
        
        // 進捗に応じてバーを更新
        let filled_width = (bar_width * progress.min(100)) / 100;
        
        // バー全体を再描画
        fb.fill_rect(
            Rect::new(bar_x as i32, bar_y as i32, bar_width, bar_height),
            Color::new(0x40, 0x40, 0x50),
        );
        
        fb.fill_rect(
            Rect::new(bar_x as i32, bar_y as i32, filled_width, bar_height),
            boot_splash::LOGO_PRIMARY,
        );
        
        // ステータスメッセージをクリアして再描画
        let status_y = (bar_y + 24) as i32;
        let clear_width = width / 2;
        let clear_x = (width - clear_width) / 2;
        fb.fill_rect(
            Rect::new(clear_x as i32, status_y, clear_width, FONT_HEIGHT + 4),
            boot_splash::BG_COLOR,
        );
        draw_centered_text(fb, message, status_y, boot_splash::TEXT_COLOR);
        
        if fb.is_double_buffered() {
            fb.swap_buffers();
        }
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
    fn test_color_to_u32() {
        let c = Color::new(255, 128, 64);
        let val = c.to_u32();
        let restored = Color::from_u32(val);
        assert_eq!(c.red, restored.red);
        assert_eq!(c.green, restored.green);
        assert_eq!(c.blue, restored.blue);
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

    #[test]
    fn test_rect_contains() {
        let r = Rect::new(10, 10, 100, 100);
        assert!(r.contains(Point::new(50, 50)));
        assert!(!r.contains(Point::new(5, 5)));
        assert!(!r.contains(Point::new(150, 150)));
    }

    #[test]
    fn test_pixel_format_bytes() {
        assert_eq!(PixelFormat::Rgb888.bytes_per_pixel(), 3);
        assert_eq!(PixelFormat::Bgra8888.bytes_per_pixel(), 4);
        assert_eq!(PixelFormat::Rgb565.bytes_per_pixel(), 2);
    }
}