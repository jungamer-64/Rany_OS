// ============================================================================
// src/graphics/font.rs - Bitmap Font Implementation
// ============================================================================
//!
//! ビットマップフォント実装
//!
//! 8x16 VGAスタイルフォントによるテキスト描画

#![allow(dead_code)]

use super::framebuffer::Framebuffer;
use super::{Color, Rect};

/// 8x16フォントの幅定数
pub const FONT_WIDTH: u32 = 8;
/// 8x16フォントの高さ定数
pub const FONT_HEIGHT: u32 = 16;
// ============================================================================
// Font Trait
// ============================================================================

/// フォントトレイト: 異なるフォント形式（Bitmap, PSF, TrueTypeなど）を抽象化
pub trait Font {
    /// 文字を描画
    fn draw_char(
        &self,
        fb: &mut Framebuffer,
        x: i32,
        y: i32,
        c: char,
        color: Color,
        bg: Option<Color>,
    );

    /// 文字幅を取得
    fn char_width(&self, c: char) -> u32;

    /// 文字幅（固定幅フォント用の利便性メソッド）
    /// デフォルト実装は代表文字 'M' の幅を返します。
    fn width(&self) -> u32 {
        self.char_width('M')
    }

    /// フォントの高さを取得
    fn height(&self) -> u32;

    /// ベースライン位置を取得（上端からのピクセル数）
    /// デフォルトは高さと同じ（下端揃え）
    fn baseline(&self) -> u32 {
        self.height()
    }

    /// 文字列を描画し、描画終了位置（次の文字の開始X座標）を返す
    fn draw_string(
        &self,
        fb: &mut Framebuffer,
        x: i32,
        y: i32,
        s: &str,
        color: Color,
        bg: Option<Color>,
    ) -> i32 {
        let mut cx = x;
        for c in s.chars() {
            if c == '\n' {
                continue;
            }
            self.draw_char(fb, cx, y, c, color, bg);
            cx += self.char_width(c) as i32;
        }
        cx
    }

    /// 文字列全体の描画幅（ピクセル）を計算
    fn text_width(&self, text: &str) -> u32 {
        text.chars().map(|c| self.char_width(c)).sum()
    }

    /// 文字のグリフデータを取得（生ビットマップデータへの参照）
    /// 戻り値はフォント形式に依存（例：8x16なら16バイトの配列）
    fn glyph(&self, c: char) -> Option<&[u8]>;
}

/// フォントトレイトの拡張メソッド
pub trait FontExt: Font {
    /// イテレータから描画幅を計算
    fn iter_width<I>(&self, chars: I) -> u32
    where
        I: Iterator<Item = char>,
    {
        chars.map(|c| self.char_width(c)).sum()
    }
}

impl<T: Font + ?Sized> FontExt for T {}

/// 8x16ビットマップフォント（基本ASCII）
#[derive(Copy, Clone)]
pub struct BitmapFont {
    /// フォントデータ（Code Page 437など、256文字 * 16バイト = 4096バイトを想定）
    data: &'static [u8],
    /// 文字幅
    width: u32,
    /// 文字高さ (unscaled, in bytes per glyph)
    height: u32,
    /// 表示スケール (1x, 2x, 3x...)
    scale: u8,
}

// 標準VGAフォントバイナリ
static FONT_RAW: &[u8] = include_bytes!("../../../assets/fonts/vga_8x16.bin");

// ============================================================================
// Bitmap Font
// ============================================================================

impl Font for BitmapFont {
    fn draw_char(
        &self,
        fb: &mut Framebuffer,
        x: i32,
        y: i32,
        c: char,
        color: Color,
        bg: Option<Color>,
    ) {
        self.draw_char_internal(fb, x, y, c, color, bg);
    }

    fn char_width(&self, c: char) -> u32 {
        if c == '\n' { 0 } else { self.width() }
    }

    fn height(&self) -> u32 {
        self.height * self.scale as u32
    }

    fn glyph(&self, c: char) -> Option<&[u8]> {
        let idx = c as usize;
        let glyph_h = self.height as usize;
        let start = idx.checked_mul(glyph_h)?;
        let end = start + glyph_h;
        if end <= self.data.len() {
            Some(&self.data[start..end])
        } else {
            None
        }
    }
}

impl BitmapFont {
    /// 組み込みの8x16フォントを取得
    pub fn default_8x16() -> Self {
        Self {
            data: FONT_RAW,
            width: 8,
            height: 16,
            scale: 1,
        }
    }

    /// スケールを設定
    pub fn set_scale(&mut self, scale: u8) {
        self.scale = if scale == 0 { 1 } else { scale };
    }

    /// 文字を描画 (Internal implementation)
    fn draw_char_internal(
        &self,
        fb: &mut Framebuffer,
        x: i32,
        y: i32,
        c: char,
        color: Color,
        bg: Option<Color>,
    ) {
        if self.scale == 1 {
            // 高速パス: Framebufferの最適化実装を使用
            fb.draw_char_8x16(x, y, c, color, bg);
            return;
        }

        // スケーリング描画
        let idx = c as usize;
        let glyph_h = self.height as usize;
        // フォントデータ範囲外の文字は無視 (または置換文字)
        if idx.checked_mul(glyph_h).is_none() {
            return;
        }

        let start = idx * glyph_h;
        if start + glyph_h > self.data.len() {
            return;
        }

        // グリフデータの取得
        let glyph = &self.data[start..start + glyph_h];
        let scale = self.scale as i32;

        // 背景描画
        if let Some(bg_color) = bg {
            fb.fill_rect(
                Rect::new(
                    x,
                    y,
                    self.width * self.scale as u32,
                    self.height * self.scale as u32,
                ),
                bg_color,
            );
        }

        // グリフ描画
        for (row_i, &row_byte) in glyph.iter().enumerate() {
            for bit_i in 0..8 {
                if (row_byte >> (7 - bit_i)) & 1 == 1 {
                    let px = x + (bit_i as i32 * scale);
                    let py = y + (row_i as i32 * scale);

                    // スケールサイズで矩形塗りつぶし
                    fb.fill_rect(
                        Rect::new(px, py, self.scale as u32, self.scale as u32),
                        color,
                    );
                }
            }
        }
    }

    /// 文字幅を取得 (スケール考慮)
    pub fn width(&self) -> u32 {
        self.width * self.scale as u32
    }

    /// 文字高さを取得 (スケール考慮)
    pub fn height(&self) -> u32 {
        self.height * self.scale as u32
    }

    /// フォントデータ長を取得
    pub fn data_len(&self) -> usize {
        self.data.len()
    }

    /// フォントデータを取得
    pub fn get_data(&self, index: usize) -> u8 {
        self.data[index]
    }

    /// 指定文字のグリフデータを返す（アンスケール、行バイト配列）
    pub fn glyph(&self, c: char) -> Option<&[u8]> {
        let idx = c as usize;
        let glyph_h = self.height as usize;
        let start = idx.checked_mul(glyph_h)?;
        let end = start + glyph_h;
        if end <= self.data.len() {
            Some(&self.data[start..end])
        } else {
            None
        }
    }

    /// 登録されているグリフの数
    pub fn glyph_count(&self) -> usize {
        let glyph_h = self.height as usize;
        if glyph_h == 0 {
            0
        } else {
            self.data.len() / glyph_h
        }
    }
}

// Unit tests for font helpers
#[cfg(test)]
mod tests {
    use super::*;

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn default_font_properties() {
        let f = BitmapFont::default_8x16();
        assert_eq!(f.width(), 8);
        assert_eq!(f.height(), 16);
        assert!(f.data_len() >= 2048);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn glyph_accessors() {
        let f = BitmapFont::default_8x16();
        // Printable ASCII should exist
        let g = f.glyph('A');
        assert!(g.is_some());
        let g = g.unwrap();
        assert_eq!(g.len(), f.height as usize);

        // High codepoint likely out of range for ASCII-only fonts
        let maybe = f.glyph('\u{80}');
        if f.data_len() < (128 * f.height as usize) {
            assert!(maybe.is_none());
        }
    }
}
