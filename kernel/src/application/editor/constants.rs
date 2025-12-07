// ============================================================================
// src/application/editor/constants.rs - Editor Constants
// ============================================================================

use crate::graphics::Color;

/// エディタウィンドウの幅
pub const EDITOR_WIDTH: u32 = 900;
/// エディタウィンドウの高さ
pub const EDITOR_HEIGHT: u32 = 700;

/// 文字幅 (ピクセル)
pub const CHAR_WIDTH: u32 = 8;
/// 文字高さ (ピクセル)
pub const CHAR_HEIGHT: u32 = 16;

/// ツールバーの高さ
pub const TOOLBAR_HEIGHT: u32 = 28;
/// 行番号の幅（文字数）
pub const LINE_NUMBER_WIDTH: usize = 5;
/// 行番号表示に使うピクセル幅
pub const LINE_NUMBER_PIXEL_WIDTH: u32 = (LINE_NUMBER_WIDTH as u32 + 1) * CHAR_WIDTH;

/// 編集エリアの開始X座標
pub const EDIT_AREA_X: u32 = LINE_NUMBER_PIXEL_WIDTH;
/// 編集エリアの開始Y座標
pub const EDIT_AREA_Y: u32 = TOOLBAR_HEIGHT;

/// 編集エリアの幅
pub const EDIT_AREA_WIDTH: u32 = EDITOR_WIDTH - EDIT_AREA_X;
/// 編集エリアの高さ
pub const EDIT_AREA_HEIGHT: u32 = EDITOR_HEIGHT - EDIT_AREA_Y;

/// 表示可能な行数
pub const VISIBLE_LINES: usize = (EDIT_AREA_HEIGHT / CHAR_HEIGHT) as usize;
/// 表示可能なカラム数
pub const VISIBLE_COLS: usize = (EDIT_AREA_WIDTH / CHAR_WIDTH) as usize;

/// タブ幅
pub const TAB_WIDTH: usize = 4;

// ============================================================================
// Colors
// ============================================================================

/// 背景色
pub const BG_COLOR: Color = Color { red: 30, green: 30, blue: 30, alpha: 255 };
/// テキスト色
pub const TEXT_COLOR: Color = Color { red: 220, green: 220, blue: 220, alpha: 255 };
/// 行番号の色
pub const LINE_NUMBER_COLOR: Color = Color { red: 100, green: 100, blue: 100, alpha: 255 };
/// 行番号背景色
pub const LINE_NUMBER_BG: Color = Color { red: 40, green: 40, blue: 40, alpha: 255 };
/// 現在行のハイライト色
pub const CURRENT_LINE_BG: Color = Color { red: 45, green: 45, blue: 45, alpha: 255 };
/// カーソル色
pub const CURSOR_COLOR: Color = Color { red: 255, green: 255, blue: 255, alpha: 255 };
/// 選択範囲の色
pub const SELECTION_COLOR: Color = Color { red: 70, green: 100, blue: 150, alpha: 255 };
/// ツールバー背景色
pub const TOOLBAR_BG: Color = Color { red: 50, green: 50, blue: 50, alpha: 255 };
/// ボタン色
pub const BUTTON_COLOR: Color = Color { red: 70, green: 70, blue: 70, alpha: 255 };
/// ボタンホバー色
pub const BUTTON_HOVER_COLOR: Color = Color { red: 90, green: 90, blue: 90, alpha: 255 };

// シンタックスハイライト色
/// キーワード色 (fn, let, mut, etc.)
pub const KEYWORD_COLOR: Color = Color { red: 198, green: 120, blue: 221, alpha: 255 };
/// 型の色
pub const TYPE_COLOR: Color = Color { red: 86, green: 182, blue: 194, alpha: 255 };
/// 文字列の色
pub const STRING_COLOR: Color = Color { red: 152, green: 195, blue: 121, alpha: 255 };
/// コメントの色
pub const COMMENT_COLOR: Color = Color { red: 92, green: 99, blue: 112, alpha: 255 };
/// 数値の色
pub const NUMBER_COLOR: Color = Color { red: 209, green: 154, blue: 102, alpha: 255 };
/// マクロの色
pub const MACRO_COLOR: Color = Color { red: 97, green: 175, blue: 239, alpha: 255 };
