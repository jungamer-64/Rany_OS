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
// Bitmap Font
// ============================================================================

/// 8x16ビットマップフォント（基本ASCII）
pub struct BitmapFont {
    /// フォントデータ（Code Page 437など、256文字 * 16バイト = 4096バイトを想定）
    data: &'static [u8],
    /// 文字幅
    width: u32,
    /// 文字高さ
    height: u32,
    /// 表示スケール (1x, 2x, 3x...)
    scale: u8,
}

// 標準VGAフォントバイナリ
static FONT_RAW: &[u8] = include_bytes!("../../../assets/fonts/vga_8x16.bin");

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
        if self.scale == 1 {
            // 高速パス: Framebufferの最適化実装を使用
            fb.draw_char_8x16(x, y, c, color, bg);
            return;
        }

        // スケーリング描画
        let idx = c as usize;
        // フォントデータ範囲外の文字は無視 (または置換文字)
        if idx * 16 >= self.data.len() {
            return;
        }

        // グリフデータの取得
        let glyph = &self.data[idx * 16..(idx + 1) * 16];
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

    /// 文字列を描画し、描画終了位置（次の文字の開始X座標）を返す
    pub fn draw_string(
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
                // 改行は無視（必要に応じて対応）
                continue;
            }

            self.draw_char(fb, cx, y, c, color, bg);
            cx += self.width as i32;
        }

        cx // 描画終了X座標を返す
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

    /// 単一文字の描画幅（ピクセル）を取得
    /// draw_string での進行量と一致させる
    pub fn char_width(&self, c: char) -> u32 {
        if c == '\n' { 0 } else { self.width() }
    }

    /// 文字列全体の描画幅（ピクセル）を計算
    pub fn text_width(&self, text: &str) -> u32 {
        text.chars().map(|c| self.char_width(c)).sum()
    }

    /// イテレータから描画幅を計算（ゼロアロケーション）
    pub fn iter_width<I>(&self, chars: I) -> u32
    where
        I: Iterator<Item = char>,
    {
        chars.map(|c| self.char_width(c)).sum()
    }
}
