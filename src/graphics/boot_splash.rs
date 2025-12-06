// ============================================================================
// src/graphics/boot_splash.rs - Boot Splash Screen
// ============================================================================
//!
//! ブートスプラッシュスクリーン
//!
//! カーネル起動時のグラフィカルなスプラッシュ表示

#![allow(dead_code)]

use super::types::{Color, Rect};
use super::framebuffer::Framebuffer;
use super::font::FONT_HEIGHT;
use super::global::with_framebuffer;

// ============================================================================
// Boot Splash Constants
// ============================================================================

/// ブートスプラッシュ用の定数
mod splash_colors {
    use super::Color;
    
    /// ロゴのカラーパレット
    pub const LOGO_PRIMARY: Color = Color::new(0x3A, 0xA6, 0xB9);   // シアン
    pub const LOGO_SECONDARY: Color = Color::new(0xF5, 0xA6, 0x23); // オレンジ
    pub const LOGO_ACCENT: Color = Color::new(0xFF, 0xFF, 0xFF);    // 白
    pub const BG_COLOR: Color = Color::new(0x1A, 0x1A, 0x2E);       // ダークブルー
    pub const TEXT_COLOR: Color = Color::new(0xE0, 0xE0, 0xE0);     // ライトグレー
}

// ============================================================================
// Logo Bitmaps
// ============================================================================

/// ロゴビットマップ（簡易版 - E, X, O の文字）
/// 16x16ピクセルの簡易フォント
#[rustfmt::skip]
const LOGO_E: [[u8; 12]; 16] = [
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
const LOGO_X: [[u8; 12]; 16] = [
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
const LOGO_O: [[u8; 12]; 16] = [
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

// ============================================================================
// Boot Splash Functions
// ============================================================================

/// ブートスプラッシュを表示
/// 
/// カーネル起動時にグラフィカルなスプラッシュ画面を表示します。
/// フレームバッファが初期化されていない場合は何もしません。
pub fn show_boot_splash() {
    with_framebuffer(|fb| {
        let width = fb.width();
        let height = fb.height();
        
        // 背景を塗りつぶす
        fb.clear(splash_colors::BG_COLOR);
        
        // ロゴを中央に描画（スケーリング係数）
        let scale = 4u32;
        let char_width = 12 * scale;
        let char_height = 16 * scale;
        let spacing = 4 * scale;
        let total_width = char_width * 3 + spacing * 2; // E, X, O + スペース
        
        let start_x = (width - total_width) / 2;
        let start_y = height / 3;
        
        // "E" を描画
        draw_logo_char(fb, &LOGO_E, start_x as i32, start_y as i32, scale, splash_colors::LOGO_PRIMARY);
        
        // "X" を描画
        let x_offset = start_x + char_width + spacing;
        draw_logo_char(fb, &LOGO_X, x_offset as i32, start_y as i32, scale, splash_colors::LOGO_SECONDARY);
        
        // "O" を描画
        let o_offset = x_offset + char_width + spacing;
        draw_logo_char(fb, &LOGO_O, o_offset as i32, start_y as i32, scale, splash_colors::LOGO_PRIMARY);
        
        // テキスト: "RanyOS" - ロゴの下
        let text_y = (start_y + char_height + 20) as i32;
        draw_centered_text(fb, "RanyOS", text_y, splash_colors::LOGO_ACCENT);
        
        // テキスト: バージョン情報
        let version_y = text_y + (FONT_HEIGHT as i32) + 8;
        draw_centered_text(fb, "Exokernel v0.3.0-alpha", version_y, splash_colors::TEXT_COLOR);
        
        // テキスト: ステータスメッセージ
        let status_y = (height * 2 / 3 + 24) as i32;
        draw_centered_text(fb, "Initializing...", status_y, splash_colors::TEXT_COLOR);
        
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
            splash_colors::LOGO_PRIMARY,
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
            splash_colors::LOGO_PRIMARY,
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
    let font_width = 8u32; // FONT_WIDTH
    let text_width = text.len() as u32 * font_width;
    let x = ((width - text_width) / 2) as i32;
    fb.draw_text(x, y, text, color, splash_colors::BG_COLOR);
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
            splash_colors::LOGO_PRIMARY,
        );
        
        // ステータスメッセージをクリアして再描画
        let status_y = (bar_y + 24) as i32;
        let clear_width = width / 2;
        let clear_x = (width - clear_width) / 2;
        fb.fill_rect(
            Rect::new(clear_x as i32, status_y, clear_width, FONT_HEIGHT + 4),
            splash_colors::BG_COLOR,
        );
        draw_centered_text(fb, message, status_y, splash_colors::TEXT_COLOR);
        
        if fb.is_double_buffered() {
            fb.swap_buffers();
        }
    });
}
