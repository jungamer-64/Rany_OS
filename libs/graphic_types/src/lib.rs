// ============================================================================
// graphic_types/src/lib.rs - Graphics Type Definitions
// ============================================================================
//!
//! # Graphics Types
//!
//! Pure data types for graphics: `Color`, `PixelFormat`, `Point`, `Rect`.
//! No kernel dependencies - can be used by kernel, drivers, and apps.

#![allow(clippy::cargo_common_metadata)]
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
    Image, ImageError, ImageResult, ImageView, ImageViewMut, MAX_IMAGE_SIZE, decode_bmp,
    decode_bmp_into,
};

#[cfg(feature = "qemu-test-export")]
#[allow(clippy::must_use_candidate)]
pub mod qemu_tests {
    pub fn color_ctor_smoke() -> bool {
        crate::types::qemu_tests::color_ctor_smoke()
    }

    pub fn color_roundtrip_smoke() -> bool {
        crate::types::qemu_tests::color_roundtrip_smoke()
    }

    pub fn rect_intersection_smoke() -> bool {
        crate::types::qemu_tests::rect_intersection_smoke()
    }

    pub fn rect_contains_smoke() -> bool {
        crate::types::qemu_tests::rect_contains_smoke()
    }

    pub fn pixel_format_bytes_smoke() -> bool {
        crate::types::qemu_tests::pixel_format_bytes_smoke()
    }

    pub fn encode_decode_roundtrip_smoke() -> bool {
        crate::types::qemu_tests::encode_decode_roundtrip_smoke()
    }

    pub fn point_layout_smoke() -> bool {
        crate::types::qemu_tests::point_layout_smoke()
    }

    pub fn rect_layout_smoke() -> bool {
        crate::types::qemu_tests::rect_layout_smoke()
    }

    pub fn color_layout_smoke() -> bool {
        crate::types::qemu_tests::color_layout_smoke()
    }

    pub fn pixel_format_layout_smoke() -> bool {
        crate::types::qemu_tests::pixel_format_layout_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_try_new_overflow_smoke() -> bool {
        crate::image::qemu_tests::try_new_overflow_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_try_new_max_size_smoke() -> bool {
        crate::image::qemu_tests::try_new_max_size_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_try_new_valid_smoke() -> bool {
        crate::image::qemu_tests::try_new_valid_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_try_filled_overflow_smoke() -> bool {
        crate::image::qemu_tests::try_filled_overflow_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_view_basic_smoke() -> bool {
        crate::image::qemu_tests::image_view_basic_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_view_mut_set_pixel_smoke() -> bool {
        crate::image::qemu_tests::image_view_mut_set_pixel_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_view_mut_fill_rect_smoke() -> bool {
        crate::image::qemu_tests::image_view_mut_fill_rect_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_view_out_of_bounds_smoke() -> bool {
        crate::image::qemu_tests::image_view_out_of_bounds_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_view_external_buffer_smoke() -> bool {
        crate::image::qemu_tests::image_view_external_buffer_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn image_view_stride_smoke() -> bool {
        crate::image::qemu_tests::image_view_stride_smoke()
    }

    #[cfg(feature = "alloc")]
    pub fn max_image_size_constant_smoke() -> bool {
        crate::image::qemu_tests::max_image_size_constant_smoke()
    }
}
