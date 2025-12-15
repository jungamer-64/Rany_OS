// ============================================================================
// graphic_types/src/lib.rs - Graphics Type Definitions
// ============================================================================
//!
//! # Graphics Types
//!
//! Pure data types for graphics: `Color`, `PixelFormat`, `Point`, `Rect`.
//! No kernel dependencies - can be used by kernel, drivers, and apps.

#![no_std]
#![allow(dead_code)]

// `alloc` usage is optional and gated behind the `alloc` feature so this
// no_std crate can be used in both kernel and userland contexts.
#[cfg(feature = "alloc")]
extern crate alloc;

mod types;

// Re-export all types
pub use types::{Color, FramebufferInfo, PixelFormat, Point, Rect};

// Image module depends on allocation support; enable it only when the
// `alloc` feature is enabled.
#[cfg(feature = "alloc")]
pub mod image;

#[cfg(feature = "alloc")]
pub use image::{
    IconGenerator, Image, ImageError, ImageResult, ImageView, ImageViewMut, MAX_IMAGE_SIZE,
    decode_bmp, decode_bmp_into, decode_ico, decode_tga,
};
