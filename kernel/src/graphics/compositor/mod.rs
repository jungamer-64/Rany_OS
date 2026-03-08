// ============================================================================
// src/graphics/compositor/mod.rs - Window Compositor Module
// ============================================================================

//! # ウィンドウコンポジタ
//!
//! 本格的なウィンドウ合成エンジン
//!
//! ## 機能
//! - ダーティ矩形による部分再描画
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
//! | - back_buffer     |
//! +-------------------+
//!         |
//!         v
//! +-------------------+
//! |   Framebuffer     |
//! +-------------------+
//! ```

#![allow(dead_code)]

mod compositor;
mod constants;

mod dirty_rect;
mod types;
mod window;

// Re-exports
pub use compositor::Compositor;
pub use constants::*;
pub use dirty_rect::{DirtyRect, DirtyRegionManager};
pub use types::{CompositorWindowId, CompositorWindowState, CompositorWindowStyle, ZOrder};
pub use window::CompositorWindow;

// ============================================================================
// Global State
// ============================================================================

use crate::graphics::Framebuffer;
use crate::sync::PoisonLock;

/// グローバルコンポジタ
static COMPOSITOR: PoisonLock<Option<Compositor>> = PoisonLock::new(None);

/// コンポジタを初期化
pub fn init(screen_width: u32, screen_height: u32) {
    *COMPOSITOR.lock().unwrap_or_else(|e| e.into_inner()) =
        Some(Compositor::new(screen_width, screen_height));
}

/// コンポジタにアクセス
pub fn with_compositor<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&Compositor) -> R,
{
    COMPOSITOR.lock().unwrap_or_else(|e| e.into_inner()).as_ref().map(f)
}

/// コンポジタにミュータブルアクセス
pub fn with_compositor_mut<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut Compositor) -> R,
{
    COMPOSITOR.lock().unwrap_or_else(|e| e.into_inner()).as_mut().map(f)
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
