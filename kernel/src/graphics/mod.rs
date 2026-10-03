// ============================================================================
// src/graphics/mod.rs - Graphics and Framebuffer Driver
// ============================================================================
//!
//! Drawing owns either an ordinary RAM plane or a retained scanout mapping.
//! The boot handoff is admitted by the resource registry before AP startup;
//! geometry alone never authorizes memory access. Synchronous GUI batches borrow
//! that same mapping while the framebuffer lock excludes concurrent rendering.
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

#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub(crate) use global::init_from_boot_info;

// グローバル関数の再エクスポート
#[cfg(any(not(any(test, feature = "bench")), feature = "full_mm_tests"))]
pub use global::{
    console_print, force_unlock_framebuffer, framebuffer, init_console, with_framebuffer,
};

#[cfg(all(test, feature = "std"))]
mod scanout_tests;
