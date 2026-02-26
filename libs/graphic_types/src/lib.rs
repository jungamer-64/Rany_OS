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

#[cfg(test)]
mod qemu_smoke_tests {
    #[test]
    fn qemu_smoke_types() {
        assert!(crate::types::qemu_tests::color_ctor_smoke());
        assert!(crate::types::qemu_tests::color_roundtrip_smoke());
        assert!(crate::types::qemu_tests::rect_intersection_smoke());
        assert!(crate::types::qemu_tests::rect_contains_smoke());
        assert!(crate::types::qemu_tests::pixel_format_bytes_smoke());
        assert!(crate::types::qemu_tests::encode_decode_roundtrip_smoke());
        assert!(crate::types::qemu_tests::point_layout_smoke());
        assert!(crate::types::qemu_tests::rect_layout_smoke());
        assert!(crate::types::qemu_tests::color_layout_smoke());
        assert!(crate::types::qemu_tests::pixel_format_layout_smoke());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn qemu_smoke_images_alloc() {
        assert!(crate::image::qemu_tests::try_new_overflow_smoke());
        assert!(crate::image::qemu_tests::try_new_max_size_smoke());
        assert!(crate::image::qemu_tests::try_new_valid_smoke());
        assert!(crate::image::qemu_tests::try_filled_overflow_smoke());
        assert!(crate::image::qemu_tests::image_view_basic_smoke());
        assert!(crate::image::qemu_tests::image_view_mut_set_pixel_smoke());
        assert!(crate::image::qemu_tests::image_view_mut_fill_rect_smoke());
        assert!(crate::image::qemu_tests::image_view_out_of_bounds_smoke());
        assert!(crate::image::qemu_tests::image_view_external_buffer_smoke());
        assert!(crate::image::qemu_tests::image_view_stride_smoke());
        assert!(crate::image::qemu_tests::max_image_size_constant_smoke());
    }
}
