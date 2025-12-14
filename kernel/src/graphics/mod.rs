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

#![allow(dead_code)]

// コア機能モジュール
#[cfg(not(any(test, feature = "bench")))]
pub mod boot_splash;
#[cfg(not(any(test, feature = "bench")))]
pub mod console;
pub mod font;
pub mod framebuffer;
#[cfg(not(any(test, feature = "bench")))]
pub mod global;

// 既存のサブモジュール
#[cfg(not(any(test, feature = "bench")))]
pub mod bsod;
#[cfg(not(any(test, feature = "bench")))]
pub mod compositor;
#[cfg(not(any(test, feature = "bench")))]
pub mod qrcode;
#[cfg(not(any(test, feature = "bench")))]
pub mod window;

// Re-exports from graphic_types
pub use graphic_types::image;
pub use graphic_types::{Color, FramebufferInfo, PixelFormat, Point, Rect};

// Re-exports from gpu_driver
pub use gpu_driver::{DamagedRegion, DisplayMode, GpuError, GpuResult, colors};

// 型の再エクスポート
#[cfg(not(any(test, feature = "bench")))]
pub use console::TextConsole;
pub use font::{BitmapFont, FONT_HEIGHT, FONT_WIDTH};
pub use framebuffer::Framebuffer;

// グローバル関数の再エクスポート
#[cfg(not(any(test, feature = "bench")))]
pub use global::{
    console_print, framebuffer, init, init_console, init_from_limine, with_console,
    with_framebuffer,
};

// ブートスプラッシュ関数の再エクスポート
#[cfg(not(any(test, feature = "bench")))]
pub use boot_splash::{show_boot_splash, update_boot_progress, update_boot_progress_with_message};
