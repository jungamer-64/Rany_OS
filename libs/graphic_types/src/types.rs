// ============================================================================
// src/graphics/types.rs - Graphics Types
// ============================================================================
//!
//! グラフィックス基本型定義
//!
//! `Color`, `PixelFormat`, `Point`, `Rect` など基本的な型を定義

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
    #[must_use]
    pub const fn new(red: u8, green: u8, blue: u8) -> Self {
        Self {
            blue,
            green,
            red,
            alpha: 255,
        }
    }

    /// アルファ付きカラーを作成
    #[must_use]
    pub const fn with_alpha(red: u8, green: u8, blue: u8, alpha: u8) -> Self {
        Self {
            blue,
            green,
            red,
            alpha,
        }
    }

    /// アルファブレンド計算 (src over dst)
    /// 近似計算: (src * a + dst * (255 - a)) / 255
    #[inline]
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub const fn blend(self, bg: Self) -> Self {
        if self.alpha == 255 {
            return self;
        }
        if self.alpha == 0 {
            return bg;
        }

        let a = self.alpha as u32;
        let inv_a = 255 - a;

        // Note: Division by 255 is approximated by >> 8 for speed in some contexts,
        // but exact calculation is (x * 257 + 128) >> 16 or just standard division.
        // For OS UI, `x >> 8` is often acceptable but `(x + y) / 255` is more correct.
        // We use standard division here for correctness in `const fn`.
        let r = (self.red as u32 * a + bg.red as u32 * inv_a) / 255;
        let g = (self.green as u32 * a + bg.green as u32 * inv_a) / 255;
        let b = (self.blue as u32 * a + bg.blue as u32 * inv_a) / 255;

        Self {
            red: r as u8,
            green: g as u8,
            blue: b as u8,
            alpha: 255, // Result is opaque if background is treated as opaque
        }
    }

    /// 32ビット値に変換（BGRA）
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        ((self.alpha as u32) << 24)
            | ((self.red as u32) << 16)
            | ((self.green as u32) << 8)
            | (self.blue as u32)
    }

    /// 32ビット値から変換
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self {
            blue: (value & 0xFF) as u8,
            green: ((value >> 8) & 0xFF) as u8,
            red: ((value >> 16) & 0xFF) as u8,
            alpha: ((value >> 24) & 0xFF) as u8,
        }
    }

    // 基本色定義
    // 基本色定義
    pub const BLACK: Self = Self::new(0, 0, 0);
    pub const WHITE: Self = Self::new(255, 255, 255);
    pub const RED: Self = Self::new(255, 0, 0);
    pub const GREEN: Self = Self::new(0, 255, 0);
    pub const BLUE: Self = Self::new(0, 0, 255);
    pub const YELLOW: Self = Self::new(255, 255, 0);
    pub const CYAN: Self = Self::new(0, 255, 255);
    pub const MAGENTA: Self = Self::new(255, 0, 255);
    pub const GRAY: Self = Self::new(128, 128, 128);
    pub const DARK_GRAY: Self = Self::new(64, 64, 64);
    pub const LIGHT_GRAY: Self = Self::new(192, 192, 192);
    pub const ORANGE: Self = Self::new(255, 165, 0);
    pub const PURPLE: Self = Self::new(128, 0, 128);
    pub const TRANSPARENT: Self = Self::with_alpha(0, 0, 0, 0);
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
#[repr(C)]
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
    #[must_use]
    pub const fn bytes_per_pixel(&self) -> usize {
        match self {
            Self::Rgb888 | Self::Bgr888 => 3,
            Self::Rgba8888 | Self::Bgra8888 => 4,
            Self::Rgb565 => 2,
        }
    }

    /// 指定フォーマットでカラーをバイト列へエンコードする
    /// `out` の長さは必ず `self.bytes_per_pixel()` 以上であること
    pub fn encode_color_bytes(&self, color: Color, out: &mut [u8]) {
        match self {
            Self::Bgra8888 => {
                out[0] = color.blue;
                out[1] = color.green;
                out[2] = color.red;
                out[3] = color.alpha;
            }
            Self::Rgba8888 => {
                out[0] = color.red;
                out[1] = color.green;
                out[2] = color.blue;
                out[3] = color.alpha;
            }
            Self::Bgr888 => {
                out[0] = color.blue;
                out[1] = color.green;
                out[2] = color.red;
            }
            Self::Rgb888 => {
                out[0] = color.red;
                out[1] = color.green;
                out[2] = color.blue;
            }
            Self::Rgb565 => {
                let r = (u16::from(color.red) >> 3) & 0x1F;
                let g = (u16::from(color.green) >> 2) & 0x3F;
                let b = (u16::from(color.blue) >> 3) & 0x1F;
                let val = (r << 11) | (g << 5) | b;
                let bytes = val.to_le_bytes();
                out[0] = bytes[0];
                out[1] = bytes[1];
            }
        }
    }

    /// バイト列から `Color` を復元する
    /// `bytes` は `self.bytes_per_pixel()` 以上の長さが必要
    #[must_use]
    pub fn decode_color_bytes(&self, bytes: &[u8]) -> Color {
        match self {
            Self::Bgra8888 => Color::with_alpha(bytes[2], bytes[1], bytes[0], bytes[3]),
            Self::Rgba8888 => Color::with_alpha(bytes[0], bytes[1], bytes[2], bytes[3]),
            Self::Bgr888 => Color::new(bytes[2], bytes[1], bytes[0]),
            Self::Rgb888 => Color::new(bytes[0], bytes[1], bytes[2]),
            Self::Rgb565 => {
                let val = u16::from_le_bytes([bytes[0], bytes[1]]);
                let r = ((val >> 11) & 0x1F) as u8 * 8;
                let g = ((val >> 5) & 0x3F) as u8 * 4;
                let b = (val & 0x1F) as u8 * 8;
                Color::new(r, g, b)
            }
        }
    }

    /// 32bitとしてエンコード可能なら u32 を返す（メモリ上のバイト順を想定したLE表現）
    #[must_use]
    pub const fn encode_u32(&self, color: Color) -> Option<u32> {
        match self {
            Self::Bgra8888 => Some(color.to_u32()),
            Self::Rgba8888 => {
                let b = [color.red, color.green, color.blue, color.alpha];
                Some(u32::from_le_bytes(b))
            }
            _ => None,
        }
    }

    /// 16bitとしてエンコード可能なら u16 を返す（LE）
    #[must_use]
    pub const fn encode_u16(&self, color: Color) -> Option<u16> {
        match self {
            Self::Rgb565 => {
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                Some((r << 11) | (g << 5) | b)
            }
            _ => None,
        }
    }
}

// ============================================================================
// Framebuffer Info
// ============================================================================

/// フレームバッファ情報
#[derive(Clone, Debug)]
#[repr(C)]
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
    #[must_use]
    pub const fn size(&self) -> usize {
        self.stride as usize * self.height as usize
    }
}

// ============================================================================
// Point and Rectangle
// ============================================================================

/// 2D座標
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    #[must_use]
    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}

/// 矩形
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    #[must_use]
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// 右端のX座標
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn right(&self) -> i32 {
        self.x + self.width as i32
    }

    /// 下端のY座標
    #[must_use]
    #[allow(clippy::cast_possible_wrap)]
    pub const fn bottom(&self) -> i32 {
        self.y + self.height as i32
    }

    /// 点が矩形内にあるか
    #[must_use]
    pub const fn contains(&self, point: Point) -> bool {
        point.x >= self.x && point.x < self.right() && point.y >= self.y && point.y < self.bottom()
    }

    /// 矩形が交差するか
    #[must_use]
    pub const fn intersects(&self, other: &Self) -> bool {
        self.x < other.right()
            && self.right() > other.x
            && self.y < other.bottom()
            && self.bottom() > other.y
    }

    /// 交差領域を取得
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn intersection(&self, other: &Self) -> Option<Self> {
        if !self.intersects(other) {
            return None;
        }

        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let right = self.right().min(other.right());
        let bottom = self.bottom().min(other.bottom());

        Some(Self::new(x, y, (right - x) as u32, (bottom - y) as u32))
    }

    /// 他の矩形を完全に含むか
    #[must_use]
    pub const fn contains_rect(&self, other: &Self) -> bool {
        other.x >= self.x
            && other.y >= self.y
            && other.right() <= self.right()
            && other.bottom() <= self.bottom()
    }

    /// 2つの矩形を含む最小の矩形を返す
    #[must_use]
    #[allow(clippy::cast_sign_loss)]
    pub fn union(&self, other: &Self) -> Self {
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = self.right().max(other.right());
        let bottom = self.bottom().max(other.bottom());
        Self::new(x, y, (right - x) as u32, (bottom - y) as u32)
    }

    /// Returns true if this rectangle has non-zero area.
    ///
    /// A valid rectangle has positive width AND height.
    /// Zero-size rectangles (width=0 or height=0) are considered invalid
    /// and are typically filtered out during rendering.
    #[inline]
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.width > 0 && self.height > 0
    }

    /// Returns true if this rectangle has zero area.
    ///
    /// Convenience method, equivalent to `!self.is_valid()`.
    #[inline]
    #[must_use]
    pub const fn is_zero_size(&self) -> bool {
        self.width == 0 || self.height == 0
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

    #[test]
    fn test_encode_decode_roundtrip() {
        let c = Color::with_alpha(0x12, 0x34, 0x56, 0xAA);

        // BGRA 32-bit
        let mut buf = [0u8; 4];
        PixelFormat::Bgra8888.encode_color_bytes(c, &mut buf);
        assert_eq!(buf, [c.blue, c.green, c.red, c.alpha]);
        let out = PixelFormat::Bgra8888.decode_color_bytes(&buf);
        assert_eq!(out.alpha, c.alpha);

        // RGBA 32-bit
        PixelFormat::Rgba8888.encode_color_bytes(c, &mut buf);
        assert_eq!(buf, [c.red, c.green, c.blue, c.alpha]);
        let out2 = PixelFormat::Rgba8888.decode_color_bytes(&buf);
        assert_eq!(out2.alpha, c.alpha);

        // 24-bit BGR
        let mut buf3 = [0u8; 3];
        let c2 = Color::new(0x12, 0x34, 0x56);
        PixelFormat::Bgr888.encode_color_bytes(c2, &mut buf3);
        assert_eq!(buf3, [c2.blue, c2.green, c2.red]);
        let out3 = PixelFormat::Bgr888.decode_color_bytes(&buf3);
        assert_eq!(out3, c2);

        // RGB565 - lossy roundtrip
        let mut buf2 = [0u8; 2];
        PixelFormat::Rgb565.encode_color_bytes(c2, &mut buf2);
        let out4 = PixelFormat::Rgb565.decode_color_bytes(&buf2);
        // RGB565 is lossy; ensure values are in expected reduced range
        assert!(out4.red <= c2.red);
        assert!(out4.green <= c2.green);
        assert!(out4.blue <= c2.blue);
    }

    #[test]
    fn test_point_repr_c_layout() {
        use core::mem::{align_of, size_of};
        // Point should be 8 bytes (2 x i32)
        assert_eq!(size_of::<Point>(), 8);
        assert_eq!(align_of::<Point>(), 4);
    }

    #[test]
    fn test_rect_repr_c_layout() {
        use core::mem::{align_of, size_of};
        // Rect should be 16 bytes (2 x i32 + 2 x u32)
        assert_eq!(size_of::<Rect>(), 16);
        assert_eq!(align_of::<Rect>(), 4);
    }

    #[test]
    fn test_color_repr_c_layout() {
        use core::mem::{align_of, size_of};
        // Color should be 4 bytes (4 x u8)
        assert_eq!(size_of::<Color>(), 4);
        assert_eq!(align_of::<Color>(), 1);
    }

    #[test]
    fn test_pixel_format_repr_c() {
        use core::mem::size_of;
        // PixelFormat enum with #[repr(C)] should have fixed size
        // (platform-dependent, but typically 4 bytes on most systems)
        let size = size_of::<PixelFormat>();
        assert!(size >= 1 && size <= 8);
    }
}
