// ============================================================================
// src/graphics/types.rs - Graphics Types
// ============================================================================
//!
//! グラフィックス基本型定義
//!
//! Color, PixelFormat, Point, Rect など基本的な型を定義

#![allow(dead_code)]

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
