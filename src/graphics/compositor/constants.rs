// ============================================================================
// src/graphics/compositor/constants.rs - Compositor Constants
// ============================================================================

//! コンポジタで使用する定数

/// 最大ダーティ矩形数（これを超えると全画面再描画）
pub const MAX_DIRTY_RECTS: usize = 32;

/// タイトルバーの高さ
pub const TITLE_BAR_HEIGHT: u32 = 28;

/// ウィンドウ境界線の幅
pub const BORDER_WIDTH: u32 = 1;

/// リサイズハンドルのサイズ
pub const RESIZE_HANDLE_SIZE: u32 = 8;

/// シャドウサイズ
pub const SHADOW_SIZE: u32 = 8;

/// ブラー半径（アクリル効果用）
pub const BLUR_RADIUS: usize = 15;
