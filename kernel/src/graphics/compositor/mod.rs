// ============================================================================
// src/graphics/compositor/mod.rs - Window Compositor Module
// ============================================================================

//! # ウィンドウコンポジタ
//!
//! 本格的なウィンドウ合成エンジン
//!
//! ## 機能
//! - ダーティ矩形による部分再描画
//! - マウスカーソルオーバーレイ合成
//! - ウィンドウのドラッグ・リサイズ
//! - アクリル効果（ガウシアンブラー + SIMD）
//! - Z-order管理
//!
//! ## アーキテクチャ
//! ```
//! +-------------------+
//! |   Compositor      |
//! +-------------------+
//! | - windows[]       |
//! | - dirty_regions[] |
//! | - cursor          |
//! | - back_buffer     |
//! +-------------------+
//!         |
//!         v
//! +-------------------+
//! |   Framebuffer     |
//! +-------------------+
//! ```

#![allow(dead_code)]

mod constants;
mod dirty_rect;
mod types;
mod cursor;
mod window;
mod compositor;

// Re-exports
pub use constants::*;
pub use dirty_rect::{DirtyRect, DirtyRegionManager};
pub use types::{
    CompositorWindowId, CompositorWindowState, CompositorWindowStyle,
    DragState, ResizeEdge, ZOrder,
};
pub use cursor::{CursorType, MouseCursor};
pub use window::CompositorWindow;
pub use compositor::Compositor;

// ============================================================================
// Global State
// ============================================================================

use spin::Mutex;
use crate::graphics::Framebuffer;

/// グローバルコンポジタ
static COMPOSITOR: Mutex<Option<Compositor>> = Mutex::new(None);

/// コンポジタを初期化
pub fn init(screen_width: u32, screen_height: u32) {
    *COMPOSITOR.lock() = Some(Compositor::new(screen_width, screen_height));
}

/// コンポジタにアクセス
pub fn with_compositor<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&Compositor) -> R,
{
    COMPOSITOR.lock().as_ref().map(f)
}

/// コンポジタにミュータブルアクセス
pub fn with_compositor_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Compositor) -> R,
{
    COMPOSITOR.lock().as_mut().map(f)
}

/// ウィンドウを作成
pub fn create_window(
    title: &str,
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    style: CompositorWindowStyle,
) -> Option<CompositorWindowId> {
    with_compositor_mut(|c| c.create_window(title, x, y, width, height, style))
}

/// ウィンドウを破棄
pub fn destroy_window(id: CompositorWindowId) {
    with_compositor_mut(|c| c.destroy_window(id));
}

/// フレームバッファに合成
pub fn compose(fb: &mut Framebuffer) {
    with_compositor_mut(|c| c.compose(fb));
}

/// マウス移動を処理
pub fn handle_mouse_move(x: i32, y: i32) {
    with_compositor_mut(|c| c.handle_mouse_move(x, y));
}

/// マウスボタン押下を処理
pub fn handle_mouse_down(x: i32, y: i32, button: u8) {
    with_compositor_mut(|c| c.handle_mouse_down(x, y, button));
}

/// マウスボタン解放を処理
pub fn handle_mouse_up(x: i32, y: i32, button: u8) {
    with_compositor_mut(|c| c.handle_mouse_up(x, y, button));
}
