// ============================================================================
// src/graphics/mod.rs - Graphics and Framebuffer Driver
// ============================================================================
//!
//! # グラフィックスサブシステム
//!
//! フレームバッファベースのグラフィックス出力を提供。
//! VESAモード、GOP（UEFI）、VBEをサポート。
//!
//! ## 機能
//! - フレームバッファ直接描画
//! - 基本図形（線、矩形、円）
//! - ビットマップフォントによるテキスト描画
//! - ダブルバッファリング
//! - 画像描画（BMP）
//! - Limineブートローダー統合
//! - ウィンドウコンポジタ
//!
//! ## モジュール構造
//! - `types` - 基本型定義（Color, Point, Rect, PixelFormat）
//! - `framebuffer` - フレームバッファ描画
//! - `font` - ビットマップフォント
//! - `console` - テキストコンソール
//! - `global` - グローバル状態管理
//! - `boot_splash` - ブートスプラッシュ画面
#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub mod console;
pub mod font;
pub mod framebuffer;
#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub mod global;
pub mod mmio;
pub mod packer;
pub mod psf;
/// VGAテキストモード出力（レガシーVGAバッファ 0xB8000）
#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub mod vga;

// 既存のサブモジュール
#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub mod bsod;
#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub mod compositor;
pub mod qrcode;
#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub mod window;

// Re-exports from graphic_types
pub use graphic_types::image;
pub use graphic_types::{Color, FramebufferInfo, PixelFormat, Point, Rect};

// 型の再エクスポート
#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub use console::TextConsole;
pub use font::FontExt;
pub use font::{BitmapFont, FONT_HEIGHT, FONT_WIDTH, Font};
pub use framebuffer::Framebuffer;

// グローバル関数の再エクスポート
#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub use global::{
    console_print, force_unlock_framebuffer, framebuffer, init, init_console, init_from_boot_info,
    with_framebuffer,
};
