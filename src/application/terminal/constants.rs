// ============================================================================
// src/application/terminal/constants.rs - Terminal Constants and Colors
// ============================================================================
//!
//! ターミナル定数とカラー定義

use crate::graphics::Color;

// ============================================================================
// Dimensions
// ============================================================================

/// ウィンドウの幅
pub const TERMINAL_WIDTH: u32 = 800;
/// ウィンドウの高さ
pub const TERMINAL_HEIGHT: u32 = 600;

/// 文字幅 (ピクセル)
pub const CHAR_WIDTH: u32 = 8;
/// 文字高さ (ピクセル)
pub const CHAR_HEIGHT: u32 = 16;

/// ターミナルのカラム数
pub const TERM_COLS: usize = (TERMINAL_WIDTH / CHAR_WIDTH) as usize;
/// ターミナルの行数
pub const TERM_ROWS: usize = (TERMINAL_HEIGHT / CHAR_HEIGHT) as usize;

/// スクロールバック行数
pub const SCROLLBACK_LINES: usize = 1000;

/// カーソル点滅間隔 (ミリ秒)
pub const CURSOR_BLINK_INTERVAL_MS: u64 = 500;

/// デフォルトのプロンプト
pub const DEFAULT_PROMPT: &str = "\x1b[1;32mrany\x1b[0m:\x1b[1;34m~\x1b[0m$ ";

/// コマンド履歴の最大サイズ
pub const HISTORY_MAX_SIZE: usize = 100;

// ============================================================================
// ANSI Colors
// ============================================================================

/// 標準ANSIカラー (0-7)
pub const ANSI_COLORS: [Color; 8] = [
    Color::new(0, 0, 0),       // 0: Black
    Color::new(205, 49, 49),   // 1: Red
    Color::new(13, 188, 121),  // 2: Green
    Color::new(229, 229, 16),  // 3: Yellow
    Color::new(36, 114, 200),  // 4: Blue
    Color::new(188, 63, 188),  // 5: Magenta
    Color::new(17, 168, 205),  // 6: Cyan
    Color::new(229, 229, 229), // 7: White
];

/// 高輝度ANSIカラー (8-15)
pub const ANSI_BRIGHT_COLORS: [Color; 8] = [
    Color::new(102, 102, 102), // 8: Bright Black (Gray)
    Color::new(241, 76, 76),   // 9: Bright Red
    Color::new(35, 209, 139),  // 10: Bright Green
    Color::new(245, 245, 67),  // 11: Bright Yellow
    Color::new(59, 142, 234),  // 12: Bright Blue
    Color::new(214, 112, 214), // 13: Bright Magenta
    Color::new(41, 184, 219),  // 14: Bright Cyan
    Color::new(255, 255, 255), // 15: Bright White
];

/// デフォルト前景色
pub const DEFAULT_FG: Color = Color::new(229, 229, 229);
/// デフォルト背景色
pub const DEFAULT_BG: Color = Color::new(30, 30, 30);
/// カーソル色
pub const CURSOR_COLOR: Color = Color::new(255, 255, 255);

// ============================================================================
// Color Utilities
// ============================================================================

/// 256色パレットから色を取得
pub fn color_from_256(n: usize) -> Color {
    match n {
        0..=7 => ANSI_COLORS[n],
        8..=15 => ANSI_BRIGHT_COLORS[n - 8],
        16..=231 => {
            // 216色キューブ (6x6x6)
            let n = n - 16;
            let r = ((n / 36) % 6) * 51;
            let g = ((n / 6) % 6) * 51;
            let b = (n % 6) * 51;
            Color::new(r as u8, g as u8, b as u8)
        }
        232..=255 => {
            // グレースケール (24段階)
            let gray = ((n - 232) * 10 + 8) as u8;
            Color::new(gray, gray, gray)
        }
        _ => DEFAULT_FG,
    }
}
