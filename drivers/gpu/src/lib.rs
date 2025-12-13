// ============================================================================
// drivers/gpu/src/lib.rs - GPU/Graphics Driver
// ============================================================================
//!
//! # GPU Driver
//!
//! Graphics and display support.
//!
//! ## Architecture
//! - Framebuffer management
//! - Window compositing
//! - Image rendering
//!
//! Note: Full implementation in kernel due to framebuffer access.
//! This crate provides type definitions and interfaces.
//! Core graphics types are in libs/graphic_types.

#![no_std]
#![allow(dead_code)]

extern crate alloc;

pub mod ffi;

pub use graphic_types::{Color, FramebufferInfo, PixelFormat, Point, Rect};

// ============================================================================
// Display Types
// ============================================================================

/// 画面モード
#[derive(Debug, Clone, Copy)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    pub format: PixelFormat,
}

/// 表示領域(dirty rectangle)
#[derive(Debug, Clone, Copy)]
pub struct DamagedRegion {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

// ============================================================================
// GPU Error
// ============================================================================

#[derive(Debug, Clone)]
pub enum GpuError {
    NotInitialized,
    InvalidMode,
    OutOfBounds,
    UnsupportedFormat,
}

pub type GpuResult<T> = Result<T, GpuError>;

// ============================================================================
// Re-export graphic_types
// ============================================================================

/// 色定数
pub mod colors {
    use super::Color;

    pub const BLACK: Color = Color::new(0, 0, 0);
    pub const WHITE: Color = Color::new(255, 255, 255);
    pub const RED: Color = Color::new(255, 0, 0);
    pub const GREEN: Color = Color::new(0, 255, 0);
    pub const BLUE: Color = Color::new(0, 0, 255);
}
