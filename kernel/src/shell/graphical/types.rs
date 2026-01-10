// ============================================================================
// src/shell/graphical/types.rs - Graphical Shell Types
// ============================================================================
//!
//! # グラフィカルシェル型定義

#![allow(dead_code)]

use crate::graphics::{Color, Font, Rect};
use alloc::boxed::Box;
use alloc::string::{String, ToString};

// ============================================================================

/// 入力行の描画状態（キャッシュ済みデータ）
pub struct RenderInputState<'a> {
    /// プロンプト文字列
    pub prompt: &'a str,
    /// 入力テキスト
    pub input_text: &'a str,
    /// カーソルのピクセルX座標（キャッシュ済み）
    pub cursor_pixel_x: i32,
    /// カーソル位置の文字（反転表示用）
    pub cursor_char: Option<char>,
    /// カーソル表示フラグ
    pub cursor_visible: bool,
    /// プロンプト終了X座標（キャッシュ済み）
    pub prompt_end_x: i32,
}

pub use crate::shell::line_buffer::{LineBuffer, MAX_LINE_LENGTH};

/// マウスカーソルの描画状態
#[cfg(feature = "mouse")]
pub struct RenderMouseState {
    /// 表示するか
    pub visible: bool,
    /// X座標
    pub x: i32,
    /// Y座標
    pub y: i32,
}

// ============================================================================
// Split Borrows Pattern (ゼロアロケーション描画のため)
// ============================================================================

/// シェル状態（可変データ）
/// 描画中に変更される可能性のあるデータ
pub struct ShellState {
    /// 出力行
    pub output_lines: alloc::collections::VecDeque<ConsoleLine>,
    /// 入力バッファ
    pub input_buffer: LineBuffer,
    /// 履歴ナビゲータ（共有ロジック）
    pub history_navigator: crate::shell::exoshell::history::HistoryNavigator,
    /// スクロールオフセット
    pub scroll_offset: usize,
    /// カーソル表示フラグ
    pub cursor_visible: bool,
    /// 最終カーソル切り替え時刻
    pub last_cursor_toggle: u64,
    /// プロンプト文字列
    pub prompt: String,
    /// 補完候補
    pub completions: alloc::vec::Vec<String>,
    /// 補完インデックス
    pub completion_index: usize,
    /// コマンド実行中フラグ
    pub is_executing: bool,
    /// マウス状態
    #[cfg(feature = "mouse")]
    pub mouse: MouseState,
    /// マウスカーソル表示
    #[cfg(feature = "mouse")]
    pub show_mouse_cursor: bool,
    /// 一時フォーマットバッファ
    pub temp_fmt_buffer: String,

    // ========== 描画キャッシュ ==========
    /// プロンプト終了X座標
    pub cached_prompt_end_x: i32,
    /// カーソルのピクセルX座標
    pub cached_cursor_pixel_x: i32,
    /// カーソル位置の文字
    pub cached_cursor_char: Option<char>,

    /// 前回の補完描画領域（部分更新の消去用）
    pub last_completion_rect: Rect,
}

/// シェルリソース（不変データ）
/// 描画中に変更されないリソース
pub struct ShellResources {
    /// フォント
    pub font: Box<dyn Font + Send + Sync>,
    /// テーマ
    pub theme: ShellTheme,
    /// フレームバッファ幅
    pub fb_width: u32,
    /// フレームバッファ高さ
    pub fb_height: u32,
    /// 列数
    pub cols: u32,
    /// 行数
    pub rows: u32,
}

impl ShellResources {
    /// 入力行のY座標
    #[inline]
    pub fn input_line_y(&self) -> i32 {
        (self.rows - 2) as i32 * self.font.height() as i32
    }

    /// フォント高さ
    #[inline]
    pub fn font_height(&self) -> i32 {
        self.font.height() as i32
    }
}

impl ShellState {
    /// カーソルのX座標
    #[inline]
    pub fn cursor_x(&self) -> i32 {
        self.cached_prompt_end_x + self.cached_cursor_pixel_x
    }

    /// マウスカーソルのRect
    #[inline]
    #[cfg(feature = "mouse")]
    pub fn mouse_rect(&self) -> crate::graphics::Rect {
        crate::graphics::Rect::new(self.mouse.x - 2, self.mouse.y - 2, 5, 5)
    }
}

// ============================================================================
// Configuration Constants
// ============================================================================





/// スクロールバック行数
pub const SCROLLBACK_LINES: usize = 500;

/// カーソル点滅間隔（ミリ秒）
pub const CURSOR_BLINK_MS: u64 = 500;

// フォントサイズは `graphics::font` 側の定義を使う（型を usize に合わせて再定義）
pub const FONT_WIDTH: usize = crate::graphics::FONT_WIDTH as usize;
pub const FONT_HEIGHT: usize = crate::graphics::FONT_HEIGHT as usize;

// ============================================================================
// Theme Colors
// ============================================================================

/// シェルのカラーテーマ
#[derive(Clone, Copy)]
pub struct ShellTheme {
    /// 背景色
    pub background: Color,
    /// 通常テキスト色
    pub foreground: Color,
    /// プロンプト色
    pub prompt: Color,
    /// 入力テキスト色
    pub input: Color,
    /// エラー色
    pub error: Color,
    /// 成功色
    pub success: Color,
    /// 情報色
    pub info: Color,
    /// 警告色
    pub warning: Color,
    /// カーソル色
    pub cursor: Color,
    /// 選択色
    pub selection: Color,
}

impl Default for ShellTheme {
    fn default() -> Self {
        Self {
            background: Color::new(24, 24, 32),    // ダークブルーグレー
            foreground: Color::new(220, 220, 220), // ライトグレー
            prompt: Color::new(80, 200, 255),      // シアン
            input: Color::WHITE,                   // 白
            error: Color::new(255, 80, 80),        // 赤
            success: Color::new(80, 255, 80),      // 緑
            info: Color::new(100, 180, 255),       // 青
            warning: Color::new(255, 200, 80),     // オレンジ
            cursor: Color::new(255, 255, 255),     // 白
            selection: Color::new(60, 80, 120),    // 選択背景
        }
    }
}



// ============================================================================
// Console Line
// ============================================================================

/// コンソール行（表示用）
#[derive(Clone)]
pub struct ConsoleLine {
    /// テキスト内容
    pub text: String,
    /// 色
    pub color: Color,
}

impl ConsoleLine {
    pub fn new(text: String, color: Color) -> Self {
        Self { text, color }
    }
}

// ============================================================================
// Mouse State
// ============================================================================

/// マウスカーソルの状態
#[cfg(feature = "mouse")]
#[derive(Clone, Copy)]
pub struct MouseState {
    /// X座標（ピクセル）
    pub x: i32,
    /// Y座標（ピクセル）
    pub y: i32,
    /// 左ボタンが押されているか
    pub left_down: bool,
    /// 右ボタンが押されているか
    pub right_down: bool,
    /// 中ボタンが押されているか
    pub middle_down: bool,
}

#[cfg(feature = "mouse")]
impl MouseState {
    pub fn new() -> Self {
        Self {
            x: 400, // 画面中央付近で開始
            y: 300,
            left_down: false,
            right_down: false,
            middle_down: false,
        }
    }

    /// イベントから状態を更新し、新しい位置を返す
    pub fn update(&mut self, event: &MouseEvent, max_x: i32, max_y: i32) {
        // 位置の更新（境界チェック付き）
        self.x = (self.x + event.dx).clamp(0, max_x - 1);
        self.y = (self.y + event.dy).clamp(0, max_y - 1);

        // ボタン状態の更新
        self.left_down = event.left_down;
        self.right_down = event.right_down;
        self.middle_down = event.middle_down;
    }
}

// MouseState itself needs to be guarded if it is not used elsewhere.
// However, the plan said "Guard RenderMouseState struct/impls".
// Let's guard the impl block for MouseState as well just to be safe/clean?
// Actually checking the plan... "Guard `mouse: MouseState` field in `ShellState`".
// If MouseState structure is used in `ShellState`, and `ShellState`'s field is guarded, `MouseState` struct definition technically can stay
// or be guarded. If I guard the struct definition, I must be sure no one else uses it.
// The file is `shell/graphical/types.rs`, specific to graphical shell.
// So safe to guard `MouseState` struct and impl too?
// Let's modify the struct definition too in a separate chunk.

#[cfg(feature = "mouse")]
impl Default for MouseState {
    fn default() -> Self {
        Self::new()
    }
}
