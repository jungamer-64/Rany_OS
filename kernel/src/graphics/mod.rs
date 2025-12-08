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
pub mod framebuffer;
pub mod font;
pub mod console;
pub mod global;
pub mod boot_splash;

// 既存のサブモジュール
pub mod bsod;
pub mod compositor;
pub mod qrcode;
pub mod window;

// Re-exports from graphic_types
pub use graphic_types::{Color, PixelFormat, FramebufferInfo, Point, Rect};
pub use graphic_types::image;

// Re-exports from gpu_driver
pub use gpu_driver::{DisplayMode, DamagedRegion, GpuError, GpuResult, colors};

// 型の再エクスポート
pub use framebuffer::Framebuffer;
pub use font::{BitmapFont, FONT_WIDTH, FONT_HEIGHT};
pub use console::TextConsole;

// グローバル関数の再エクスポート
pub use global::{
    init,
    init_from_limine,
    init_console,
    with_framebuffer,
    with_console,
    framebuffer,
    console_print,
};

// ブートスプラッシュ関数の再エクスポート
pub use boot_splash::{
    show_boot_splash,
    update_boot_progress,
    update_boot_progress_with_message,
};
