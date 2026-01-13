// ============================================================================
// kernel/src/graphics/framebuffer.rs - Framebuffer Implementation
// ============================================================================
//!
//! フレームバッファ描画実装
//!
//! ピクセル描画、図形描画、テキスト描画などのフレームバッファ操作

#![allow(dead_code)]

extern crate alloc;

use super::{BitmapFont, Color, FramebufferInfo, PixelFormat, Point, Rect};
use alloc::vec;
use alloc::vec::Vec;
use core::ptr;
use hal::mmio;

// NOTE: Packer static variables (PACKER_MODE, AVX2_AVAILABLE) have been moved
// to graphics/packer.rs module. Bench functions delegate to that module.

// Bench-time helpers to force or query the packer mode deterministically.
// Guarded by `bench` feature to avoid exposing this API in production builds.
#[cfg(feature = "bench")]
pub fn force_packer_mode(mode: u8) {
    super::packer::force_packer_mode(mode);
}

#[cfg(feature = "bench")]
pub fn current_packer_mode() -> u8 {
    super::packer::current_packer_mode()
}

// ============================================================================
// BENCHMARK-ONLY FUNCTIONS
// ============================================================================
// The following impl block contains functions compiled only with `feature = "bench"`:
// - counted_sfence: sfence with counter for measuring fence overhead
// - bench_pack_rgba_to_bgr24_*: packer benchmarks
// - bench_fill_rect_per_row_fenced: per-row fenced fill for comparison
// - bench_draw_text_per_glyph_fenced: per-glyph fenced text for comparison
// - bench_get/reset_sfence_count: fence counter access
// - bench_write_bgr_run_pixels, bench_write_bytes_mmio: low-level write benchmarks
// ============================================================================

#[cfg(feature = "bench")]
static SFENCE_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

#[cfg(feature = "bench")]
impl Framebuffer {
    #[inline]
    fn counted_sfence(&self) {
        use core::sync::atomic::Ordering;
        SFENCE_COUNT.fetch_add(1, Ordering::SeqCst);
        mmio::sfence();
    }
    /// Call scalar packer directly for micro-benchmarks
    pub fn bench_pack_rgba_to_bgr24_scalar(src: &[u8], dst: &mut [u8]) {
        Self::pack_rgba_to_bgr24_scalar(src, dst, true); // Default to BGR for backward compat
    }


    /// Bench-only: get the current sfence call count recorded by hal::mmio
    #[cfg(feature = "bench")]
    pub fn bench_get_sfence_count(&self) -> usize {
        use core::sync::atomic::Ordering;
        SFENCE_COUNT.load(Ordering::SeqCst)
    }

    /// Bench-only: reset the sfence call count recorded by hal::mmio
    #[cfg(feature = "bench")]
    pub fn bench_reset_sfence_count(&self) {
        use core::sync::atomic::Ordering;
        SFENCE_COUNT.store(0, Ordering::SeqCst);
    }

    /// Bench-only helper that fills a rect but performs a per-row sfence
    /// on each MMIO write (simulates the older, less efficient behavior).
    #[cfg(feature = "bench")]
    pub fn bench_fill_rect_per_row_fenced(&mut self, rect: Rect, color: Color) {
        // Clip
        let mut r = rect;
        r.x = r.x.max(self.clip.x);
        r.y = r.y.max(self.clip.y);
        let right = r.right().min(self.clip.right());
        let bottom = r.bottom().min(self.clip.bottom());
        r.width = (right - r.x).max(0) as u32;
        r.height = (bottom - r.y).max(0) as u32;
        if r.width == 0 || r.height == 0 {
            return;
        }

        self.stats.rectangles_drawn += 1;
        self.stats.pixels_drawn += (r.width * r.height) as usize;
        self.mark_dirty(r);

        let stride = self.info.stride as usize;

        // Only implement for 32-bit formats for bench
        if self.info.format.bytes_per_pixel() == 4 {
            let color_u32 = color.to_u32();
            // Simulate per-row fenced writes
            for y in r.y..r.bottom() {
                let offset = (y as usize * stride as usize) + (r.x as usize * 4);
                let addr = self.buffer as usize + offset;
                // This helper issues an sfence per call
                self.write_u32_run_streaming(addr, r.width as usize, color_u32);
            }
        } else {
            // Fallback to existing fill_rect behavior for other formats
            self.fill_rect(r, color);
        }
    }

    // Bench-only helper: simulate the old per-glyph fenced behavior for
    // 32-bit formats. This is compiled only with `--features bench` and
    // is used by the benchmarking harness to measure the difference
    // between issuing an sfence per glyph row vs batching a single
    // sfence after many writes.
    #[cfg(feature = "bench")]
    pub fn bench_draw_text_per_glyph_fenced(
        &mut self,
        x: i32,
        y: i32,
        text: &str,
        color: Color,
        bg_color: Color,
    ) {
        let font = BitmapFont::default_8x16();
        let char_count = text.chars().filter(|&c| c != '\n').count() as u32;
        if char_count == 0 {
            return;
        }

        let text_w = char_count * font.width() as u32;
        let text_h = font.height() as u32;

        self.mark_dirty(Rect::new(x, y, text_w, text_h));
        self.fill_rect(Rect::new(x, y, text_w, text_h), bg_color);

        let stride = self.info.stride as usize;

        // Only implement the 32-bit fast path for the bench helper
        if self.info.format.bytes_per_pixel() == 4 {
            let fg_u32 = color.to_u32();
            let bg_u32 = bg_color.to_u32();
            let mut cx = x;

            for c in text.chars() {
                if c == '\n' {
                    continue;
                }

                let char_x = cx;

                let glyph = match font.glyph(c) {
                    Some(g) => g,
                    None => {
                        cx += font.width() as i32;
                        continue;
                    }
                };

                if char_x >= self.clip.x && (char_x + font.width() as i32) <= self.clip.right() {
                    for (row, &byte) in glyph.iter().enumerate() {
                        let dst_y = y + row as i32;
                        if dst_y < self.clip.y || dst_y >= self.clip.bottom() {
                            continue;
                        }
                        let dst_offset = (dst_y as usize * stride) + (char_x as usize * 4);
                        // This will perform MMIO writes and issue an sfence
                        // per glyph row (old behavior).
                        self.write_glyph_row_32bit(byte, dst_offset, fg_u32, bg_u32);
                    }
                } else {
                    for (row, &byte) in glyph.iter().enumerate() {
                        let dst_y = y + row as i32;
                        if dst_y < self.clip.y || dst_y >= self.clip.bottom() {
                            continue;
                        }

                        for col in 0..8 {
                            let px = char_x + col as i32;
                            if px < self.clip.x || px >= self.clip.right() {
                                continue;
                            }

                            let is_on = (byte >> (7 - col)) & 1 != 0;
                            let c_val = if is_on { color } else { bg_color };
                            self.set_pixel_raw(px, dst_y, c_val);
                        }
                    }
                }

                cx += font.width() as i32;
            }
        }
    }

    /// Call dispatcher (runtime-selected) packer for micro-benchmarks
    pub fn bench_pack_rgba_to_bgr24_dispatch(src: &[u8], dst: &mut [u8], is_bgr: bool) {
        Self::pack_rgba_to_bgr24(src, dst, is_bgr);
    }

    // NOTE: Bench functions for direct SIMD paths (AVX2, SSSE3, NEON) have been
    // removed. Use the packer module directly for benchmarking:
    //   super::packer::pack_rgba_to_bgr24(src, dst, is_bgr)
    //   super::packer::pack_rgba_to_bgra(src, dst)
}

// Non-bench version of counted_sfence - just calls sfence without counting
#[cfg(not(feature = "bench"))]
impl Framebuffer {
    #[inline]
    fn counted_sfence(&self) {
        mmio::sfence();
    }
}

// NOTE: SIMD dispatch logic has been moved to graphics/packer.rs module.
/// Performance statistics for the framebuffer
#[derive(Debug, Clone, Copy, Default)]
pub struct PerfStats {
    pub flushes: usize,
    pub pixels_drawn: usize,
    pub rectangles_drawn: usize,
}

/// フレームバッファの内部状態
pub struct Framebuffer {
    buffer: *mut u8,
    info: FramebufferInfo,
    back_buffer: Option<Vec<u32>>,
    clip: Rect,
    scratch_u8: Vec<u8>,
    scratch_u32: Vec<u32>,
    /// Dirty rectangle tracking for optimized partial updates.
    /// Up to 4 disjoint rectangles are tracked; when full, two closest are merged.
    dirty_rects: [Option<Rect>; 4],
    /// Performance statistics
    pub stats: PerfStats,
}

#[cfg(test)]
mod tests;

unsafe impl Send for Framebuffer {}
unsafe impl Sync for Framebuffer {}

impl Framebuffer {
    /// 新しいフレームバッファを作成
    pub unsafe fn new(info: FramebufferInfo) -> Self {
        let clip = Rect::new(0, 0, info.width, info.height);
        // Compute sizes before moving `info` into the struct
        let width_usize = info.width as usize;
        Self {
            buffer: info.address as *mut u8,
            info,
            back_buffer: None,
            clip,
            scratch_u8: Vec::with_capacity(width_usize * 4),
            scratch_u32: Vec::with_capacity(width_usize),
            dirty_rects: [None, None, None, None],
            stats: PerfStats::default(),
        }
    }

    /// Access raw buffer pointer (unsafe)
    pub fn raw_buffer_ptr(&self) -> *mut u8 {
        self.buffer
    }

    /// Get stride (bytes per line)
    pub fn stride(&self) -> u32 {
        self.info.stride
    }

    /// Create a framebuffer from kernel_api::gui::FramebufferInfo
    ///
    /// # Safety
    /// The vaddr in kapi_info must be a valid readable/writable framebuffer address
    pub unsafe fn from_kapi_info(kapi_info: &kernel_api::gui::FramebufferInfo) -> Self {
        use kernel_api::gui::PixelFormat as KapiPixelFormat;

        // Convert pixel format
        let format = match kapi_info.format {
            KapiPixelFormat::Rgb32 => PixelFormat::Rgba8888,
            KapiPixelFormat::Bgr32 => PixelFormat::Bgra8888,
            KapiPixelFormat::Rgb24 => PixelFormat::Rgb888,
            KapiPixelFormat::Bgr24 => PixelFormat::Bgr888,
            KapiPixelFormat::Unknown => PixelFormat::Bgra8888, // Default fallback
        };

        let bpp = match format.bytes_per_pixel() {
            4 => 32,
            3 => 24,
            2 => 16,
            _ => 32,
        };

        let info = FramebufferInfo {
            address: kapi_info.vaddr as u64,
            width: kapi_info.width as u32,
            height: kapi_info.height as u32,
            stride: kapi_info.stride as u32,
            format,
            bpp,
        };

        unsafe { Self::new(info) }
    }

    /// Ensure scratch_u32 has at least `capacity` elements
    fn ensure_scratch_u32(&mut self, capacity: usize) {
        if self.scratch_u32.capacity() < capacity {
            // Correctly reserve from current length
            self.scratch_u32.reserve(capacity - self.scratch_u32.len());
        }
        // Safety: We have ensured capacity >= capacity. The caller MUST overwrite
        // all elements up to `capacity` before reading.
        unsafe { self.scratch_u32.set_len(capacity); }
    }

    /// Ensure scratch_u8 has at least `capacity` bytes
    fn ensure_scratch_u8(&mut self, capacity: usize) {
        if self.scratch_u8.capacity() < capacity {
            // Correctly reserve from current length
            self.scratch_u8.reserve(capacity - self.scratch_u8.len());
        }
        // Safety: We have ensured capacity >= capacity. The caller MUST overwrite
        // all bytes up to `capacity` before reading.
        unsafe { self.scratch_u8.set_len(capacity); }
    }

    /// Write a slice of bytes to MMIO region efficiently.
    ///
    /// This will attempt to perform aligned 32-bit writes when possible to
    /// reduce the number of volatile writes. It never performs unaligned
    /// u32 writes: any leading bytes to reach 4-byte alignment are emitted
    /// as u8 writes.
    fn write_bytes_mmio(&self, addr: usize, data: &[u8]) {
        let mut ptr = addr;
        let mut i = 0usize;
        let len = data.len();

        // Align to 8-bytes boundary. If pointer is 4 mod 8 and at least
        // 4 bytes remain, write a single u32 to reach 8-byte alignment
        // (faster than 4 u8 volatile writes). Otherwise emit up to 7 u8
        // writes to reach the 8-byte boundary.
        let align8 = ptr & 7;
        if align8 != 0 {
            if align8 == 4 && i + 4 <= len {
                #[cfg(target_endian = "little")]
                {
                    let v =
                        unsafe { core::ptr::read_unaligned(data.as_ptr().add(i) as *const u32) };
                    mmio::mmio_write_u32(ptr, v);
                }
                #[cfg(not(target_endian = "little"))]
                {
                    let v = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                    mmio::mmio_write_u32(ptr, v);
                }
                ptr += 4;
                i += 4;
            } else {
                let to_align = core::cmp::min(8 - align8, len - i);
                for _ in 0..to_align {
                    mmio::volatile_write::<u8>(ptr, data[i]);
                    ptr += 1;
                    i += 1;
                }
            }
        }

        // Bulk write u64 when possible. Unroll 4 u64 writes per iteration.
        while i + 32 <= len {
            #[cfg(target_endian = "little")]
            {
                let v0 = unsafe { core::ptr::read_unaligned(data.as_ptr().add(i) as *const u64) };
                let v1 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 8) as *const u64) };
                let v2 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 16) as *const u64) };
                let v3 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 24) as *const u64) };
                mmio::mmio_write_u64(ptr, v0);
                mmio::mmio_write_u64(ptr + 8, v1);
                mmio::mmio_write_u64(ptr + 16, v2);
                mmio::mmio_write_u64(ptr + 24, v3);
            }
            #[cfg(not(target_endian = "little"))]
            {
                let v0 = u64::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                let v1 = u64::from_le_bytes([
                    data[i + 8],
                    data[i + 9],
                    data[i + 10],
                    data[i + 11],
                    data[i + 12],
                    data[i + 13],
                    data[i + 14],
                    data[i + 15],
                ]);
                let v2 = u64::from_le_bytes([
                    data[i + 16],
                    data[i + 17],
                    data[i + 18],
                    data[i + 19],
                    data[i + 20],
                    data[i + 21],
                    data[i + 22],
                    data[i + 23],
                ]);
                let v3 = u64::from_le_bytes([
                    data[i + 24],
                    data[i + 25],
                    data[i + 26],
                    data[i + 27],
                    data[i + 28],
                    data[i + 29],
                    data[i + 30],
                    data[i + 31],
                ]);
                mmio::mmio_write_u64(ptr, v0);
                mmio::mmio_write_u64(ptr + 8, v1);
                mmio::mmio_write_u64(ptr + 16, v2);
                mmio::mmio_write_u64(ptr + 24, v3);
            }
            ptr += 32;
            i += 32;
        }

        while i + 8 <= len {
            #[cfg(target_endian = "little")]
            {
                let v = unsafe { core::ptr::read_unaligned(data.as_ptr().add(i) as *const u64) };
                mmio::mmio_write_u64(ptr, v);
            }
            #[cfg(not(target_endian = "little"))]
            {
                let v = u64::from_le_bytes([
                    data[i],
                    data[i + 1],
                    data[i + 2],
                    data[i + 3],
                    data[i + 4],
                    data[i + 5],
                    data[i + 6],
                    data[i + 7],
                ]);
                mmio::mmio_write_u64(ptr, v);
            }
            ptr += 8;
            i += 8;
        }

        // Remaining u32-aligned writes; unroll 4 at a time
        while i + 16 <= len {
            #[cfg(target_endian = "little")]
            {
                let v0 = unsafe { core::ptr::read_unaligned(data.as_ptr().add(i) as *const u32) };
                let v1 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 4) as *const u32) };
                let v2 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 8) as *const u32) };
                let v3 =
                    unsafe { core::ptr::read_unaligned(data.as_ptr().add(i + 12) as *const u32) };
                mmio::mmio_write_u32(ptr, v0);
                mmio::mmio_write_u32(ptr + 4, v1);
                mmio::mmio_write_u32(ptr + 8, v2);
                mmio::mmio_write_u32(ptr + 12, v3);
            }
            #[cfg(not(target_endian = "little"))]
            {
                let v0 = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                let v1 = u32::from_le_bytes([data[i + 4], data[i + 5], data[i + 6], data[i + 7]]);
                let v2 = u32::from_le_bytes([data[i + 8], data[i + 9], data[i + 10], data[i + 11]]);
                let v3 =
                    u32::from_le_bytes([data[i + 12], data[i + 13], data[i + 14], data[i + 15]]);
                mmio::mmio_write_u32(ptr, v0);
                mmio::mmio_write_u32(ptr + 4, v1);
                mmio::mmio_write_u32(ptr + 8, v2);
                mmio::mmio_write_u32(ptr + 12, v3);
            }
            ptr += 16;
            i += 16;
        }

        while i + 4 <= len {
            #[cfg(target_endian = "little")]
            {
                let v = unsafe { core::ptr::read_unaligned(data.as_ptr().add(i) as *const u32) };
                mmio::mmio_write_u32(ptr, v);
            }
            #[cfg(not(target_endian = "little"))]
            {
                let v = u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
                mmio::mmio_write_u32(ptr, v);
            }
            ptr += 4;
            i += 4;
        }

        // Remaining tail bytes
        while i < len {
            mmio::volatile_write::<u8>(ptr, data[i]);
            ptr += 1;
            i += 1;
        }
    }

    /// Write a slice of u32 pixels to an MMIO destination, using u64 pair writes
    /// when possible for improved throughput.
    fn write_u32_slice_mmio(&self, addr: usize, data: &[u32]) {
        let mut ptr = addr;
        let mut i = 0usize;
        let len = data.len();

        // If ptr is 4 mod 8, write a single u32 to reach 8-byte alignment
        if (ptr & 7) == 4 && i < len {
            mmio::mmio_write_u32(ptr, data[i]);
            ptr += 4;
            i += 1;
        }

        // Write u64 pairs; unroll 4 pairs at a time for throughput.
        while i + 7 < len {
            let p0 = (data[i] as u64) | ((data[i + 1] as u64) << 32);
            let p1 = (data[i + 2] as u64) | ((data[i + 3] as u64) << 32);
            let p2 = (data[i + 4] as u64) | ((data[i + 5] as u64) << 32);
            let p3 = (data[i + 6] as u64) | ((data[i + 7] as u64) << 32);
            mmio::mmio_write_u64(ptr, p0);
            mmio::mmio_write_u64(ptr + 8, p1);
            mmio::mmio_write_u64(ptr + 16, p2);
            mmio::mmio_write_u64(ptr + 24, p3);
            ptr += 32;
            i += 8;
        }

        while i + 1 < len {
            let pair = (data[i] as u64) | ((data[i + 1] as u64) << 32);
            mmio::mmio_write_u64(ptr, pair);
            ptr += 8;
            i += 2;
        }

        if i < len {
            mmio::mmio_write_u32(ptr, data[i]);
        }
    }

    /// Write a slice of bytes to MMIO using non-temporal (streaming) stores.
    ///
    /// This bypasses the CPU cache and writes directly to VRAM, which is
    /// optimal for framebuffer writes where the data won't be read back.
    /// After calling this, you should call `mmio::sfence()` to ensure stores
    /// are globally visible.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn write_bytes_mmio_streaming(&self, addr: usize, data: &[u8]) {
        unsafe {
            mmio::stream_write_bytes(addr, data);
        }
    }

    /// Fallback for non-x86: use regular volatile writes
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn write_bytes_mmio_streaming(&self, addr: usize, data: &[u8]) {
        self.write_bytes_mmio(addr, data);
    }

    /// Write a slice of u32 pixels using non-temporal (streaming) stores.
    ///
    /// This bypasses the CPU cache for better VRAM write throughput.
    /// After calling this, you should call `mmio::sfence()` to ensure stores
    /// are globally visible.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn write_u32_slice_mmio_streaming(&self, addr: usize, data: &[u32]) {
        let mut ptr = addr;
        let mut i = 0usize;
        let len = data.len();

        // If ptr is 4 mod 8, write a single u32 to reach 8-byte alignment
        if (ptr & 7) == 4 && i < len {
            mmio::stream_write_u32(ptr, data[i]);
            ptr += 4;
            i += 1;
        }

        // Write u64 pairs using streaming stores
        while i + 1 < len {
            let pair = (data[i] as u64) | ((data[i + 1] as u64) << 32);
            mmio::stream_write_u64(ptr, pair);
            ptr += 8;
            i += 2;
        }

        // Handle trailing u32
        if i < len {
            mmio::stream_write_u32(ptr, data[i]);
        }
    }

    /// Fallback for non-x86: use regular volatile writes
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn write_u32_slice_mmio_streaming(&self, addr: usize, data: &[u32]) {
        self.write_u32_slice_mmio(addr, data);
    }

    /// Write a repeating u32 value to MMIO using non-temporal (streaming) stores.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn write_u32_run_streaming(&self, addr: usize, count: usize, value: u32) {
        let mut ptr = addr;
        let mut i = 0usize;

        #[cfg(all(feature = "std", feature = "bench"))]
        let bench_debug_env = std::env::var("RANY_DEBUG_DRAW").ok().as_deref() == Some("1");

        #[cfg(all(feature = "std", feature = "bench"))]
        if bench_debug_env && crate::graphics::mmio::bench_debug_print_allowed() {
            eprintln!(
                "write_u32_run_streaming: addr=0x{:x} count={} value=0x{:x}",
                addr, count, value
            );
        }

        // Align to 8-bytes boundary
        if (ptr & 7) == 4 && i < count {
            #[cfg(all(feature = "std", feature = "bench"))]
            if bench_debug_env && crate::graphics::mmio::bench_debug_print_allowed() {
                eprintln!("  stream_write_u32 at 0x{:x} val=0x{:x}", ptr, value);
            }
            mmio::stream_write_u32(ptr, value);
            ptr += 4;
            i += 1;
        }

        // Write u64 pairs (repeating value)
        let val64 = (value as u64) | ((value as u64) << 32);
        while i + 1 < count {
            #[cfg(all(feature = "std", feature = "bench"))]
            if bench_debug_env && crate::graphics::mmio::bench_debug_print_allowed() {
                eprintln!("  stream_write_u64 at 0x{:x} val=0x{:x}", ptr, val64);
            }
            mmio::stream_write_u64(ptr, val64);
            ptr += 8;
            i += 2;
        }

        // Trailing u32
        if i < count {
            #[cfg(all(feature = "std", feature = "bench"))]
            if bench_debug_env && crate::graphics::mmio::bench_debug_print_allowed() {
                eprintln!("  stream_write_u32 at 0x{:x} val=0x{:x}", ptr, value);
            }
            mmio::stream_write_u32(ptr, value);
        }
        // Ensure streaming stores are visible to device
        self.counted_sfence();
        // Note: callers that want to batch many rows together can use
        // `write_u32_run_streaming_nofence` and call `mmio::sfence()` once
        // after the batch for better throughput.
    }

    /// Like `write_u32_run_streaming` but does not issue an sfence at the end.
    /// Useful when batching multiple row writes and issuing a single sfence
    /// after the entire batch for improved throughput.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn write_u32_run_streaming_nofence(&self, addr: usize, count: usize, value: u32) {
        let mut ptr = addr;
        let mut i = 0usize;

        // Align to 8-bytes boundary
        if (ptr & 7) == 4 && i < count {
            mmio::stream_write_u32(ptr, value);
            ptr += 4;
            i += 1;
        }

        // Write u64 pairs (repeating value)
        let val64 = (value as u64) | ((value as u64) << 32);
        while i + 1 < count {
            mmio::stream_write_u64(ptr, val64);
            ptr += 8;
            i += 2;
        }

        // Trailing u32
        if i < count {
            mmio::stream_write_u32(ptr, value);
        }
    }

    /// Non-x86 fallback: use regular u32 writes (no special streaming stores).
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn write_u32_run_streaming_nofence(&self, addr: usize, count: usize, value: u32) {
        self.write_u32_run(addr, count, value);
    }

    /// Fallback for non-x86
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn write_u32_run_streaming(&self, addr: usize, count: usize, value: u32) {
        self.write_u32_run(addr, count, value);
    }

    /// Stream-pack RGBA bytes into BGRA bytes and write them to MMIO in
    /// moderate-size chunks. This avoids allocating a large `scratch_u32`
    /// buffer for very long runs and allows SIMD packers to operate on
    /// small temporaries which are then emitted via `write_bytes_mmio`.
    fn write_rgba_packed_to_mmio_stream(&mut self, addr: usize, src: &[u8]) {
        // Process in pixel-based chunks to allow direct u32 writes. Default
        // chunk size is 512 pixels (2048 bytes); bench runs may override this
        // via the `RANY_CHUNK_PIXELS` environment variable for tuning.
        #[cfg(all(feature = "std", feature = "bench"))]
        let chunk_pixels: usize = std::env::var("RANY_CHUNK_PIXELS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(512);
        #[cfg(not(all(feature = "std", feature = "bench")))]
        let chunk_pixels: usize = 512;

        if src.is_empty() {
            return;
        }

        let total_pixels = src.len() / 4;
        let mut processed_pixels = 0usize;

        while processed_pixels < total_pixels {
            let remaining_pixels = total_pixels - processed_pixels;
            let chunk_pixels = core::cmp::min(chunk_pixels, remaining_pixels);

            // Ensure a u32-backed scratch buffer for this chunk
            self.ensure_scratch_u32(chunk_pixels);
            let src_offset = processed_pixels * 4;

            {
                // Mutable borrow scope for packer
                let src_chunk = &src[src_offset..src_offset + chunk_pixels * 4];
                let dst_bytes = unsafe {
                    core::slice::from_raw_parts_mut(
                        self.scratch_u32.as_mut_ptr() as *mut u8,
                        chunk_pixels * 4,
                    )
                };
                Self::pack_rgba_to_bgra(src_chunk, dst_bytes);
            }

            // Emit packed u32 words using streaming stores
            let addr_chunk = addr + processed_pixels * 4;
            self.write_u32_slice_mmio_streaming(addr_chunk, &self.scratch_u32[..chunk_pixels]);

            processed_pixels += chunk_pixels;
        }
        // Ensure global visibility once after the full stream
        self.counted_sfence();
    }

    /// Pack RGBA byte buffer into BGRA byte buffer.
    /// Delegates to the packer module which handles SIMD dispatch.
    #[inline]
    pub fn pack_rgba_to_bgra(src: &[u8], dst: &mut [u8]) {
        super::packer::pack_rgba_to_bgra(src, dst)
    }

    /// Public dispatcher for 24-bit packing (uses SIMD if available)
    #[inline]
    pub fn pack_rgba_to_bgr24(src: &[u8], dst: &mut [u8], is_bgr: bool) {
        super::packer::pack_rgba_to_bgr24(src, dst, is_bgr)
    }
    /// Scalar packer (public for bench tests)
    #[inline]
    pub fn pack_rgba_to_bgra_scalar(src: &[u8], dst: &mut [u8]) {
        super::packer::pack_rgba_to_bgra_scalar(src, dst)
    }

    /// 24-bit scalar packer (public for bench tests)
    #[inline]
    pub fn pack_rgba_to_bgr24_scalar(src: &[u8], dst: &mut [u8], is_bgr: bool) {
        super::packer::pack_rgba_to_bgr24_scalar(src, dst, is_bgr)
    }

    // ------------------------------------------------------------------------
    // SIMD entry points (exposed for tests/benching)
    // ------------------------------------------------------------------------
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2"))]
    pub unsafe fn pack_rgba_to_bgra_avx2(src: *const u8, dst: *mut u8, bytes: usize) {
        // SAFETY: `src` and `dst` must be valid for `bytes` bytes and non-overlapping as required by the
        // underlying SIMD implementation. The caller of this `unsafe` function is responsible for ensuring that.
        unsafe { crate::graphics::packer::pack_rgba_to_bgra_avx2(src, dst, bytes); }
    }

    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "ssse3"))]
    pub unsafe fn pack_rgba_to_bgra_ssse3(src: *const u8, dst: *mut u8, bytes: usize) {
        // SAFETY: Same invariants as `pack_rgba_to_bgra_avx2`.
        unsafe { crate::graphics::packer::pack_rgba_to_bgra_ssse3(src, dst, bytes); }
    }

    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "avx2"))]
    pub unsafe fn pack_rgba_to_bgr24_avx2_8pixels(src: *const u8, dst: *mut u8, is_bgr: bool) {
        // SAFETY: `src` and `dst` must point to at least 8 pixels' worth of data.
        unsafe { crate::graphics::packer::pack_rgba_to_bgr24_avx2_8pixels(src, dst, is_bgr); }
    }

    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), target_feature = "ssse3"))]
    pub unsafe fn pack_rgba_to_bgr24_ssse3_8pixels(src: *const u8, dst: *mut u8, is_bgr: bool) {
        // SAFETY: `src` and `dst` must point to at least 8 pixels' worth of data.
        unsafe { crate::graphics::packer::pack_rgba_to_bgr24_ssse3_8pixels(src, dst, is_bgr); }
    }

    #[cfg(target_arch = "aarch64")]
    pub unsafe fn pack_rgba_to_bgra_neon(src: *const u8, dst: *mut u8, bytes: usize) {
        // SAFETY: same invariants as other SIMD entry points.
        unsafe { crate::graphics::packer::pack_rgba_to_bgra_neon(src, dst, bytes); }
    }

    // ------------------------------------------------------------------------
    /// Write a run of u32 pixels (color already packed) to destination offset

    // NOTE: All SIMD pack implementations (AVX2, SSSE3, NEON) have been moved to
    // graphics/packer.rs module. The public pack_rgba_to_bgra() and pack_rgba_to_bgr24()
    // functions delegate to that module.

    /// Write a run of u32 pixels (color already packed) to destination offset
    fn write_u32_run(&mut self, dst_offset_bytes: usize, run_len_pixels: usize, color_u32: u32) {
        if let Some(ref mut back) = self.back_buffer {
            // OOB check: prevent silent heap corruption
            let back_size_bytes = back.len() * 4;
            debug_assert!(
                dst_offset_bytes + run_len_pixels * 4 <= back_size_bytes,
                "write_u32_run: OOB write ({} + {} > {})",
                dst_offset_bytes,
                run_len_pixels * 4,
                back_size_bytes
            );
            // Backed by a Vec -> write via slice with alignment safety
            let row_ptr = unsafe { (back.as_mut_ptr() as *mut u8).add(dst_offset_bytes) };
            
            // Check alignment before creating u32 slice
            if row_ptr as usize % 4 == 0 {
                // Fast path: pointer is properly aligned for u32
                let row_slice = unsafe {
                    core::slice::from_raw_parts_mut(row_ptr as *mut u32, run_len_pixels)
                };
                row_slice.fill(color_u32);
            } else {
                // Safe path: use unaligned writes to avoid UB
                for i in 0..run_len_pixels {
                    unsafe {
                        ptr::write_unaligned(row_ptr.add(i * 4) as *mut u32, color_u32);
                    }
                }
            }
        } else {
            // MMIO path: use streaming stores for better VRAM throughput
            if self.buffer.is_null() {
                return;
            }
            let mut addr = self.buffer as usize + dst_offset_bytes;
            let mut remaining = run_len_pixels;

            // If addr is 4 mod 8, write a single u32 first to reach 8-byte alignment
            if (addr & 7) == 4 && remaining >= 1 {
                mmio::stream_write_u32(addr, color_u32);
                addr += 4;
                remaining -= 1;
            }

            if remaining >= 2 {
                let mut pair_count = remaining / 2;
                let pair_val = (color_u32 as u64) | ((color_u32 as u64) << 32);

                // Unroll 4 writes at a time to reduce loop overhead
                while pair_count >= 4 {
                    mmio::stream_write_u64(addr, pair_val);
                    mmio::stream_write_u64(addr + 8, pair_val);
                    mmio::stream_write_u64(addr + 16, pair_val);
                    mmio::stream_write_u64(addr + 24, pair_val);
                    addr += 32;
                    pair_count -= 4;
                }

                while pair_count > 0 {
                    mmio::stream_write_u64(addr, pair_val);
                    addr += 8;
                    pair_count -= 1;
                }

                remaining -= (remaining / 2) * 2;
            }

            if remaining == 1 {
                mmio::stream_write_u32(addr, color_u32);
            }

            // Ensure streaming stores are globally visible
            self.counted_sfence();
        }
    }

    /// Write a run of 24-bit (3-byte) pixels with format-aware byte ordering.
    /// For Bgr888: [B,G,R], for Rgb888: [R,G,B]
    fn write_bgr_run(&mut self, dst_offset_bytes: usize, run_len_pixels: usize, color: Color) {
        // Determine byte order based on format: BGR = [B,G,R], RGB = [R,G,B]
        let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);
        let (c0, c1, c2) = if is_bgr {
            (color.blue, color.green, color.red)
        } else {
            (color.red, color.green, color.blue)
        };

        if self.back_buffer.is_none() && self.buffer.is_null() {
            return;
        }

        let total = run_len_pixels * 3;
        // Prepare scratch buffer first to avoid holding a mutable borrow to self
        self.ensure_scratch_u8(total);
        // Small-run fast-path for MMIO: avoid preparing a large scratch buffer
        // when the run is short (reduces overhead for short lines). The
        // threshold is tunable via `RANY_SMALL_BGR_DIRECT_MMIO` in bench runs.
        #[inline]
        fn small_bgr_direct_threshold() -> usize {
            #[cfg(all(feature = "std", feature = "bench"))]
            {
                std::env::var("RANY_SMALL_BGR_DIRECT_MMIO")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(16)
            }
            #[cfg(not(all(feature = "std", feature = "bench")))]
            {
                16
            }
        }

        if self.back_buffer.is_none() && run_len_pixels <= small_bgr_direct_threshold() {
            let addr = self.buffer as usize + dst_offset_bytes;
            if addr != 0 {
                // 4-pixel (12-byte) optimization: write as u32 × 3
                // Pack 4 pixels into 3 u32 words for aligned writes:
                // p0(c0,c1,c2), p1(c0,c1,c2), p2(c0,c1,c2), p3(c0,c1,c2) = 12 bytes
                // u32_0 = [c0, c1, c2, c0]  (p0 + p1.c0)
                // u32_1 = [c1, c2, c0, c1]  (p1.c1c2 + p2.c0c1)
                // u32_2 = [c2, c0, c1, c2]  (p2.c2 + p3)
                let u32_0 = (c0 as u32) | ((c1 as u32) << 8) | ((c2 as u32) << 16) | ((c0 as u32) << 24);
                let u32_1 = (c1 as u32) | ((c2 as u32) << 8) | ((c0 as u32) << 16) | ((c1 as u32) << 24);
                let u32_2 = (c2 as u32) | ((c0 as u32) << 8) | ((c1 as u32) << 16) | ((c2 as u32) << 24);

                let mut off = addr;
                let mut remaining = run_len_pixels;

                // Align to 4-byte boundary first (write individual bytes)
                // Align to 4-byte boundary first (write individual bytes)
                let misalign = off & 3;
                if misalign != 0 && remaining > 0 {
                    // 3 bytes/pixel. misalign(1..3) pixels writes (3*misalign) bytes.
                    // (off + 3*mis) % 4 == (mis + 3*mis) % 4 == (4*mis) % 4 == 0. Correct.
                    let k = core::cmp::min(misalign, remaining);
                    for _ in 0..k {
                        mmio::volatile_write::<u8>(off, c0);
                        mmio::volatile_write::<u8>(off + 1, c1);
                        mmio::volatile_write::<u8>(off + 2, c2);
                        off += 3;
                        remaining -= 1;
                    }
                    debug_assert!(remaining == 0 || (off & 3) == 0, "Alignment logic failed: off={}", off);
                }

                // Now write 4-pixel groups using u32 × 3 (12 bytes = 4 pixels)
                while remaining >= 4 {
                    mmio::volatile_write::<u32>(off, u32_0);
                    mmio::volatile_write::<u32>(off + 4, u32_1);
                    mmio::volatile_write::<u32>(off + 8, u32_2);
                    off += 12;
                    remaining -= 4;
                }

                // Handle remaining 1-3 pixels with byte writes
                for _ in 0..remaining {
                    mmio::volatile_write::<u8>(off, c0);
                    mmio::volatile_write::<u8>(off + 1, c1);
                    mmio::volatile_write::<u8>(off + 2, c2);
                    off += 3;
                }
                return;
            }
        }

        // Large-run direct MMIO path: write repeated byte patterns directly
        // to MMIO using u64 writes when the run is long. The threshold is
        // tunable via `RANY_LARGE_BGR_DIRECT_MMIO` in bench builds.
        #[inline]
        fn large_bgr_direct_threshold() -> usize {
            #[cfg(all(feature = "std", feature = "bench"))]
            {
                // Increase default threshold: empirical benches showed
                // regressions for moderate-large runs (1k..8k). Use a
                // conservative default so most workloads use the
                // scratch+write_bytes_mmio path which is more stable.
                std::env::var("RANY_LARGE_BGR_DIRECT_MMIO")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(4096)
            }
            #[cfg(not(all(feature = "std", feature = "bench")))]
            {
                128
            }
        }

        if self.back_buffer.is_none() && run_len_pixels >= large_bgr_direct_threshold() {
            let mut addr = self.buffer as usize + dst_offset_bytes;
            if addr != 0 {
                let mut remaining = run_len_pixels * 3;

                // Component array for indexed access
                let comps = [c0, c1, c2];

                // Align to 8-byte boundary by writing up to 7 initial bytes
                let align8 = addr & 7;
                let mut to_align_total = 0usize;
                if align8 != 0 {
                    let to_align = core::cmp::min(8 - align8, remaining);
                    to_align_total = to_align;
                    for i in 0..to_align {
                        mmio::volatile_write::<u8>(addr + i, comps[i % 3]);
                    }
                    addr += to_align;
                    remaining -= to_align;
                }
                let mut comp_idx = to_align_total % 3;

                // Precompute 8-byte patterns for each possible component
                // starting index (0..2). This allows us to emit correctly
                // rotated 8-byte patterns for the repeating stream
                // without rebuilding the pattern on every iteration.
                let mut patterns = [0u64; 3];
                for k in 0..3 {
                    let mut patt = 0u64;
                    for j in 0..8 {
                        let byte = comps[(k + j) % 3] as u64;
                        patt |= byte << (8 * j);
                    }
                    patterns[k] = patt;
                }

                // Write groups of 24 bytes (three 8-byte patterns) when
                // possible. Writing three patterns per loop keeps the
                // component rotation aligned (24 % 3 == 0).
                while remaining >= 24 {
                    mmio::stream_write_u64(addr, patterns[comp_idx % 3]);
                    mmio::stream_write_u64(addr + 8, patterns[(comp_idx + 8) % 3]);
                    mmio::stream_write_u64(addr + 16, patterns[(comp_idx + 16) % 3]);
                    addr += 24;
                    remaining -= 24;
                    // comp_idx cycles back to same value after +24
                }

                // Handle remaining full 8-byte blocks
                while remaining >= 8 {
                    mmio::stream_write_u64(addr, patterns[comp_idx % 3]);
                    addr += 8;
                    remaining -= 8;
                    comp_idx = (comp_idx + 8) % 3;
                }

                // Handle remaining bytes
                while remaining > 0 {
                    mmio::volatile_write::<u8>(addr, comps[comp_idx % 3]);
                    addr += 1;
                    remaining -= 1;
                    comp_idx = (comp_idx + 1) % 3;
                }

                mmio::sfence();
                return;
            }
        }
        if run_len_pixels > 0 {
            // Exponential fill: write first pixel then copy already-filled region
            // repeatedly to build the rest of the buffer. This reduces per-pixel
            // overhead for large fills of a single color.
            self.scratch_u8[0] = c0;
            self.scratch_u8[1] = c1;
            self.scratch_u8[2] = c2;

            let mut filled = 1usize;
            while filled < run_len_pixels {
                let copy_pixels = core::cmp::min(filled, run_len_pixels - filled);
                let copy_bytes = copy_pixels * 3;
                let dst_offset = filled * 3;
                unsafe {
                    // Use ptr::copy for overlapping-safe copy
                    ptr::copy(
                        self.scratch_u8.as_ptr(),
                        self.scratch_u8.as_mut_ptr().add(dst_offset),
                        copy_bytes,
                    );
                }
                filled += copy_pixels;
            }
        }

        if let Some(ref mut _back) = self.back_buffer {
            // write_bgr_run on 32bpp backbuffer is not supported/needed (draw_text avoids it).
            // dead code or panic.
            debug_assert!(false, "write_bgr_run called on 32bpp backbuffer");
        } else {
            // MMIO path: write bytes using bulk u32 when possible
            let addr = self.buffer as usize + dst_offset_bytes;
            self.write_bytes_mmio(addr, &self.scratch_u8[..total]);
        }
    }


    /// Bench helper: expose targeted BGR run write for micro-bench timing.
    /// Only compiled when the `bench` feature is enabled.
    #[cfg(feature = "bench")]
    pub fn bench_write_bgr_run_pixels(
        &mut self,
        x: usize,
        y: usize,
        run_len_pixels: usize,
        color: Color,
    ) {
        let dst_offset = y * self.info.stride as usize + x * 3;
        self.write_bgr_run(dst_offset, run_len_pixels, color);
    }

    /// Bench helper: call internal write_bytes_mmio path directly.
    #[cfg(feature = "bench")]
    pub fn bench_write_bytes_mmio(&mut self, x: usize, y: usize, data: &[u8]) {
        let dst_offset = y * self.info.stride as usize + x * self.info.format.bytes_per_pixel();
        let addr = self.buffer as usize + dst_offset;
        // Call private method directly
        self.write_bytes_mmio(addr, data);
    }

    /// Bench helper: draw a single 8x16 glyph without marking dirty or
    /// performing per-char background fills. This allows bench code to
    /// emulate `draw_text` behavior (prefill background once) and then
    /// draw glyphs individually without per-char dirty updates.
    #[cfg(feature = "bench")]
    pub fn bench_draw_char_no_dirty(
        &mut self,
        x: i32,
        y: i32,
        c: char,
        color: Color,
        bg: Option<Color>,
    ) {
        let font = BitmapFont::default_8x16();
        let stride = self.info.stride as usize;
        let bpp = self.info.format.bytes_per_pixel();

        // Get glyph bytes (unscaled). If missing, don't draw.
        let glyph = match font.glyph(c) {
            Some(g) => g,
            None => return,
        };
        let char_w = font.width() as u32;

        for (row, &byte) in glyph.iter().enumerate() {
            let dst_y = y + row as i32;
            if dst_y < self.clip.y || dst_y >= self.clip.bottom() {
                continue;
            }

            match bpp {
                4 => {
                    let fg_u32 = self.info.format.encode_u32(color).unwrap_or(color.to_u32());

                    if bg.is_some() {
                        let dst_x = x;
                        if dst_x >= self.clip.x && (dst_x + char_w as i32) <= self.clip.right() {
                            let dst_offset = (dst_y as usize * stride) + (dst_x as usize * 4);
                            let bg_color = bg.unwrap();
                            let bg_u32 = self
                                .info
                                .format
                                .encode_u32(bg_color)
                                .unwrap_or(bg_color.to_u32());
                            self.write_glyph_row_32bit(byte, dst_offset, fg_u32, bg_u32);
                            continue;
                        }
                    }

                    for col in 0..8 {
                        let px = x + col as i32;
                        if px < self.clip.x || px >= self.clip.right() {
                            continue;
                        }
                        let is_on = (byte >> (7 - col)) & 1 != 0;
                        if is_on {
                            self.set_pixel_raw(px, dst_y, color);
                        }
                    }
                }
                3 => {
                    let mut col = 0usize;
                    while col < 8 {
                        while col < 8 {
                            let pixel_on = (byte >> (7 - col)) & 1 != 0;
                            if pixel_on {
                                break;
                            }
                            col += 1;
                        }

                        let run_start = col;
                        while col < 8 {
                            let pixel_on = (byte >> (7 - col)) & 1 != 0;
                            if !pixel_on {
                                break;
                            }
                            col += 1;
                        }

                        let run_len = col.saturating_sub(run_start);
                        if run_len == 0 {
                            continue;
                        }

                        let dst_x = x + run_start as i32;
                        if dst_x < self.clip.x || dst_x >= self.clip.right() {
                            continue;
                        }

                        let clipped_end = (dst_x + run_len as i32 - 1).min(self.clip.right() - 1);
                        let clipped_len = (clipped_end - dst_x + 1) as usize;
                        let start_offset = (dst_y as usize * stride) + (dst_x as usize * 3);
                        self.write_bgr_run(start_offset, clipped_len, color);
                    }
                }
                _ => {
                    for col in 0..8 {
                        let px = x + col as i32;
                        if px < self.clip.x || px >= self.clip.right() {
                            continue;
                        }
                        let is_on = (byte >> (7 - col)) & 1 != 0;
                        if is_on {
                            self.set_pixel_raw(px, dst_y, color);
                        }
                    }
                }
            }
        }
    }

    /// Bench helper: write a slice of u32 pixels using streaming stores
    /// (when available). This exposes the internal streaming path to benches
    /// for micro-benchmarking MMIO u32 writes.
    #[cfg(feature = "bench")]
    pub fn bench_write_u32_slice_streaming(&mut self, x: usize, y: usize, data: &[u32]) {
        let dst_offset = y * self.info.stride as usize + x * self.info.format.bytes_per_pixel();
        let addr = self.buffer as usize + dst_offset;
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            // If the framebuffer base address is 0 (bench harness common case),
            // allocate a temporary buffer and exercise the streaming path
            // against a valid heap buffer to avoid access violations on hosts
            // where address 0 isn't writable.
            if addr == 0 {
                let mut tmp = vec![0u8; data.len() * 4];
                let tmp_addr = tmp.as_mut_ptr() as usize;
                self.write_u32_slice_mmio_streaming(tmp_addr, data);
                mmio::sfence();
                // tmp dropped here
            } else {
                self.write_u32_slice_mmio_streaming(addr, data);
                mmio::sfence();
            }
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            // For non-x86, avoid writing to address 0 (unmapped) by using a
            // temporary buffer when addr == 0.
            if addr == 0 {
                let mut tmp = vec![0u8; data.len() * 4];
                let tmp_addr = tmp.as_mut_ptr() as usize;
                self.write_u32_slice_mmio(tmp_addr, data);
            } else {
                self.write_u32_slice_mmio(addr, data);
            }
        }
    }

    /// bitマスクを32bitカラーアレイに展開して書き込む（テキスト描画用）
    /// AVX2最適化のための構造を備えるが、現在はスカラ実装（unrolled loop & u64 writes）を使用。
    #[inline(always)]
    fn write_glyph_row_32bit(
        &mut self,
        bits: u8,
        dst_offset_bytes: usize,
        fg_u32: u32,
        bg_u32: u32,
    ) {
        // Delegate to no-fence variant and fence if it performed MMIO writes
        if self.write_glyph_row_32bit_nofence(bits, dst_offset_bytes, fg_u32, bg_u32) {
            mmio::sfence();
        }
    }

    /// Like `write_glyph_row_32bit` but does not issue an sfence. Returns
    /// true if MMIO streaming writes were performed (i.e., when not
    /// double-buffered). This allows callers to batch many glyph row writes
    /// and issue a single fence for better throughput.
    #[inline(always)]
    fn write_glyph_row_32bit_nofence(
        &mut self,
        bits: u8,
        dst_offset_bytes: usize,
        fg_u32: u32,
        bg_u32: u32,
    ) -> bool {
        let addr = self.buffer as usize + dst_offset_bytes;

        // Helper for branchless selection
        #[inline(always)]
        fn sel(mask: u32, fg: u32, bg: u32) -> u32 {
            bg ^ ((bg ^ fg) & mask)
        }

        // Generate masks using arithmetic shift to propagate the bit to all positions
        let b = bits as i32;
        let m0 = ((b << 24) >> 31) as u32;
        let m1 = ((b << 25) >> 31) as u32;
        let m2 = ((b << 26) >> 31) as u32;
        let m3 = ((b << 27) >> 31) as u32;
        let m4 = ((b << 28) >> 31) as u32;
        let m5 = ((b << 29) >> 31) as u32;
        let m6 = ((b << 30) >> 31) as u32;
        let m7 = ((b << 31) >> 31) as u32;

        if let Some(ref mut back) = self.back_buffer {
            // Write to back buffer: pack into u64 writes to reduce the
            // number of memory operations compared to eight separate u32 writes.
            // Sanity-check bounds to convert potential silent OOB writes into
            // an actionable panic with diagnostics during bench runs.
            let back_len = back.len();
            let back_size_bytes = back_len * 4;
            let required = 32usize; // 4 * u64
            if dst_offset_bytes + required > back_size_bytes {
                panic!(
                    "OOB glyph write to back buffer: dst_offset={} required={} back_size={} stride={}",
                    dst_offset_bytes, required, back_size_bytes, self.info.stride
                );
            }

            // Cast u32 pointer to u8 pointer for byte-offset arithmetic
            let base = unsafe { (back.as_mut_ptr() as *mut u8).add(dst_offset_bytes) };
            unsafe {
                let s0 = sel(m0, fg_u32, bg_u32);
                let s1 = sel(m1, fg_u32, bg_u32);
                let s2 = sel(m2, fg_u32, bg_u32);
                let s3 = sel(m3, fg_u32, bg_u32);
                let s4 = sel(m4, fg_u32, bg_u32);
                let s5 = sel(m5, fg_u32, bg_u32);
                let s6 = sel(m6, fg_u32, bg_u32);
                let s7 = sel(m7, fg_u32, bg_u32);

                let v0 = (s0 as u64) | ((s1 as u64) << 32);
                let v1 = (s2 as u64) | ((s3 as u64) << 32);
                let v2 = (s4 as u64) | ((s5 as u64) << 32);
                let v3 = (s6 as u64) | ((s7 as u64) << 32);

                core::ptr::write_unaligned(base as *mut u64, v0);
                core::ptr::write_unaligned(base.add(8) as *mut u64, v1);
                core::ptr::write_unaligned(base.add(16) as *mut u64, v2);
                core::ptr::write_unaligned(base.add(24) as *mut u64, v3);
            }

            // Back buffer writes are not MMIO
            return false;
        }

        if self.buffer.is_null() {
            return false;
        }

        // Sanity-check: when writing to a heap-backed framebuffer (not
        // double-buffered), ensure the destination range is within the
        // allocated framebuffer to avoid silent OOB writes that cause
        // hard crashes on the host.
        let required = 32usize; // we will write 4 u64 values (32 bytes)
        if self.buffer != ptr::null_mut() as *mut u8 {
            let buf_start = self.buffer as usize;
            let buf_end = buf_start + self.info.size();
            if addr + required > buf_end {
                panic!(
                    "OOB glyph write: addr=0x{:x} needed={} buf_end=0x{:x} stride={} dst_offset={}",
                    addr, required, buf_end, self.info.stride, dst_offset_bytes
                );
            }
        }

        // Write to MMIO using 64-bit streaming writes where possible
        // 0x80 -> pixel 0, 0x40 -> pixel 1
        let p0 = sel(m0, fg_u32, bg_u32);
        let p1 = sel(m1, fg_u32, bg_u32);
        let v0 = (p0 as u64) | ((p1 as u64) << 32);
        mmio::stream_write_u64(addr, v0);

        // 0x20 -> pixel 2, 0x10 -> pixel 3
        let p2 = sel(m2, fg_u32, bg_u32);
        let p3 = sel(m3, fg_u32, bg_u32);
        let v1 = (p2 as u64) | ((p3 as u64) << 32);
        mmio::stream_write_u64(addr + 8, v1);

        // 0x08 -> pixel 4, 0x04 -> pixel 5
        let p4 = sel(m4, fg_u32, bg_u32);
        let p5 = sel(m5, fg_u32, bg_u32);
        let v2 = (p4 as u64) | ((p5 as u64) << 32);
        mmio::stream_write_u64(addr + 16, v2);

        // 0x02 -> pixel 6, 0x01 -> pixel 7
        let p6 = sel(m6, fg_u32, bg_u32);
        let p7 = sel(m7, fg_u32, bg_u32);
        let v3 = (p6 as u64) | ((p7 as u64) << 32);
        mmio::stream_write_u64(addr + 24, v3);

        // Caller will issue sfence once per-batch
        true
    }

    /// ダブルバッファリングを有効化
    pub fn enable_double_buffering(&mut self) {
        let count = (self.info.width * self.info.height) as usize;
        self.back_buffer = Some(vec![0u32; count]);
    }

    /// ダブルバッファリングを外部バッファで有効化（デッドロック回避用）
    pub fn enable_double_buffering_from_vec(&mut self, buffer: Vec<u32>) {
        let count = (self.info.width * self.info.height) as usize;
        if buffer.len() == count {
            self.back_buffer = Some(buffer);
        } else {
             // Size mismatch
        }
    }

    /// ダブルバッファリングが有効かどうかを取得
    pub fn is_double_buffered(&self) -> bool {
        self.back_buffer.is_some()
    }

    /// Compatibility accessor for previous `dirty_rect` field.
    pub fn dirty_rect(&self) -> Option<Rect> {
        let mut out: Option<Rect> = None;
        for slot in self.dirty_rects.iter() {
            if let Some(r) = slot {
                out = Some(match out {
                    None => *r,
                    Some(prev) => prev.union(r),
                });
            }
        }
        out
    }

    /// 描画領域を「汚れ」としてマーク
    /// Uses up to 4 disjoint rects; merges when full to avoid over-expanding.
    fn mark_dirty(&mut self, rect: Rect) {
        // クリップ領域との共通部分をとる
        let draw_rect = match rect.intersection(&self.clip) {
            Some(r) => r,
            None => return,
        };

        if !draw_rect.is_valid() {
            return;
        }

        // Try to merge with an overlapping or adjacent existing rect
        for slot in self.dirty_rects.iter_mut() {
            if let Some(existing) = slot {
                // Check if rects overlap or are adjacent (touching)
                let merged = existing.union(&draw_rect);
                let existing_area = existing.width as u64 * existing.height as u64;
                let draw_area = draw_rect.width as u64 * draw_rect.height as u64;
                let merged_area = merged.width as u64 * merged.height as u64;
                
                // Merge if union doesn't expand area too much (< 1.5x sum of individual areas)
                if merged_area <= (existing_area + draw_area) * 3 / 2 {
                    *slot = Some(merged);
                    return;
                }
            }
        }

        // Try to find an empty slot
        for slot in self.dirty_rects.iter_mut() {
            if slot.is_none() {
                *slot = Some(draw_rect);
                return;
            }
        }

        // All slots full: force merge the two rects with smallest area INCREASE
        // This prevents merging distant rects that would create huge bounding boxes
        let mut min_added_area = u64::MAX;
        let mut merge_pair = (0, 1);
        for i in 0..4 {
            for j in (i + 1)..4 {
                if let (Some(a), Some(b)) = (&self.dirty_rects[i], &self.dirty_rects[j]) {
                    let area_a = a.width as u64 * a.height as u64;
                    let area_b = b.width as u64 * b.height as u64;
                    let combined = a.union(b);
                    let combined_area = combined.width as u64 * combined.height as u64;
                    // Area increase = how much "wasted" space the merge creates
                    let added_area = combined_area.saturating_sub(area_a + area_b);
                    if added_area < min_added_area {
                        min_added_area = added_area;
                        merge_pair = (i, j);
                    }
                }
            }
        }

        // Merge the pair and put the new rect in one of the freed slots
        let (i, j) = merge_pair;
        if let (Some(a), Some(b)) = (&self.dirty_rects[i], &self.dirty_rects[j]) {
            let merged = a.union(b);
            self.dirty_rects[i] = Some(merged);
            self.dirty_rects[j] = Some(draw_rect);
        }
    }

    /// 最適化されたバッファ転送 - transfers all dirty rects
    pub fn flush_dirty_area(&mut self) {
        // Extract rects to stack to avoid borrowing self.dirty_rects while calling self.blit_rect
        let mut rects = [None; 4];
        for (i, slot) in self.dirty_rects.iter_mut().enumerate() {
            rects[i] = slot.take();
        }

        for rect_opt in rects.iter() {
            if let Some(rect) = rect_opt {
                self.stats.flushes += 1;
                self.blit_rect(*rect);
            }
        }
    }

    /// バックバッファをフロントにコピー（全画面または汚れた部分）
    pub fn swap_buffers(&mut self) {
        if self.back_buffer.is_some() {
            self.flush_dirty_area();
        }
    }

    /// 指定領域のみバックバッファからVRAMへコピー（部分Blit）
    /// 全画面コピーより効率的
    /// 注: "Swap"ではなく"Blit"（一方向コピー）
    pub fn blit_rect(&mut self, rect: Rect) {
        if let Some(ref back) = self.back_buffer {
            let stride_mmio = self.info.stride as usize;
            let bytes_per_pixel = (self.info.bpp / 8) as usize;

            // 境界チェック
            let x = (rect.x.max(0) as u32).min(self.info.width) as usize;
            let y = (rect.y.max(0) as u32).min(self.info.height) as usize;
            let w = (rect.width as usize).min(self.info.width as usize - x);
            let h = (rect.height as usize).min(self.info.height as usize - y);

            if w == 0 || h == 0 {
                return;
            }

            // Iterate rows
            for row in 0..h {
                let src_y = y + row;
                let src_idx = src_y * self.info.width as usize + x;
                let src_slice = &back[src_idx .. src_idx + w];

                let dst_offset = (y + row) * stride_mmio + x * bytes_per_pixel;
                let dst_addr = self.buffer as usize + dst_offset;

                match bytes_per_pixel {
                    4 => {
                        // 32-bit to 32-bit: Direct copy (MMIO optimized)
                        // Cast src_slice (u32) to u8 bytes
                        let src_bytes = unsafe {
                            core::slice::from_raw_parts(src_slice.as_ptr() as *const u8, w * 4)
                        };
                        self.write_bytes_mmio_streaming(dst_addr, src_bytes);
                    }
                    3 => {
                        // 32-bit BGRA to 24-bit BGR: Pack and write
                        // We iterate pixels and write 3 bytes.
                        // Can use volatile writes manually for best perf without intermediate buf
                        let mut curr_addr = dst_addr;
                        for &pixel in src_slice {
                            // Little Endian: pixel = BB GG RR AA
                            // We want BB GG RR
                            let b = (pixel & 0xFF) as u8;
                            let g = ((pixel >> 8) & 0xFF) as u8;
                            let r = ((pixel >> 16) & 0xFF) as u8;
                            mmio::volatile_write::<u8>(curr_addr, b);
                            mmio::volatile_write::<u8>(curr_addr + 1, g);
                            mmio::volatile_write::<u8>(curr_addr + 2, r);
                            curr_addr += 3;
                        }
                    }
                    2 => {
                         // 16-bit
                         let mut curr_addr = dst_addr;
                         for &pixel in src_slice {
                             // Convert 8888 -> 565
                             let b = (pixel & 0xFF) as u8;
                             let g = ((pixel >> 8) & 0xFF) as u8;
                             let r = ((pixel >> 16) & 0xFF) as u8;
                             let rgb565 = ((r as u16 & 0xF8) << 8) | ((g as u16 & 0xFC) << 3) | (b as u16 >> 3);
                             mmio::mmio_write_u16(curr_addr, rgb565);
                             curr_addr += 2;
                         }
                    }
                    _ => {}
                }
            }
            mmio::sfence();
        }
    }

    /// 描画先バッファを取得
    fn draw_buffer(&mut self) -> *mut u8 {
        if let Some(ref mut back) = self.back_buffer {
            back.as_mut_ptr() as *mut u8
        } else {
            self.buffer
        }
    }

    /// フレームバッファ情報を取得
    pub fn info(&self) -> &FramebufferInfo {
        &self.info
    }

    /// 幅を取得
    pub fn width(&self) -> u32 {
        self.info.width
    }

    /// 高さを取得
    pub fn height(&self) -> u32 {
        self.info.height
    }

    /// クリップ領域を設定
    pub fn set_clip(&mut self, rect: Rect) {
        self.clip = rect;
    }

    /// クリップ領域をリセット
    pub fn reset_clip(&mut self) {
        self.clip = Rect::new(0, 0, self.info.width, self.info.height);
    }

    /// 現在のクリップ領域を取得
    pub fn clip_rect(&self) -> Rect {
        self.clip
    }

    /// ピクセルをセット
    pub fn set_pixel(&mut self, x: i32, y: i32, color: Color) {
        if x < 0 || y < 0 {
            return;
        }
        let x = x as u32;
        let y = y as u32;

        if x >= self.info.width || y >= self.info.height {
            return;
        }

        if !self.clip.contains(Point::new(x as i32, y as i32)) {
            return;
        }

        // Mark the single-pixel area as dirty first
        self.mark_dirty(Rect::new(x as i32, y as i32, 1, 1));

        self.set_pixel_raw(x as i32, y as i32, color);
    }

    /// Dirty Rectangle更新を行わない内部用メソッド
    ///
    /// # Safety Note
    /// This function now performs bounds validation to prevent page faults
    /// from invalid coordinates (negative values or out of framebuffer range).
    fn set_pixel_raw(&mut self, x: i32, y: i32, color: Color) {
        // CRITICAL: Bounds check to prevent page faults from invalid coordinates
        // Without this check, negative x/y would wrap around when cast to usize,
        // causing access to invalid MMIO addresses (e.g., 0xFFFFFFFFFFFFFFF8)
        if x < 0 || y < 0 {
            return;
        }
        let x_u = x as u32;
        let y_u = y as u32;
        if x_u >= self.info.width || y_u >= self.info.height {
            return;
        }

        if let Some(ref mut back) = self.back_buffer {
            // Write to back buffer (u32/BGRA)
            // Stride for backbuffer is always width (pixels)
            let idx = (y_u as usize * self.info.width as usize) + x_u as usize;
            back[idx] = color.to_u32(); // Stores BGRA on LE
        } else {
            // Write to MMIO: use volatile writes via mmio module
            let buffer = self.buffer;

            // Safety check for tests or unmapped framebuffer
            if buffer.is_null() {
                return;
            }
            
            // Recalculate byte offset for MMIO (uses stride)
            let offset = (y_u as usize * self.info.stride as usize)
                + (x_u as usize * self.info.format.bytes_per_pixel());

            match self.info.format {
                PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                    let pixel_addr = buffer.add(offset) as usize;
                    mmio::mmio_write_u32(pixel_addr, color.to_u32());
                },
                PixelFormat::Bgr888 => unsafe {
                    let addr = buffer.add(offset) as usize;
                    mmio::volatile_write::<u8>(addr, color.blue);
                    mmio::volatile_write::<u8>(addr + 1, color.green);
                    mmio::volatile_write::<u8>(addr + 2, color.red);
                },
                PixelFormat::Rgb888 => unsafe {
                    let addr = buffer.add(offset) as usize;
                    mmio::volatile_write::<u8>(addr, color.red);
                    mmio::volatile_write::<u8>(addr + 1, color.green);
                    mmio::volatile_write::<u8>(addr + 2, color.blue);
                },
                PixelFormat::Rgb565 => unsafe {
                    let r = (color.red as u16 >> 3) & 0x1F;
                    let g = (color.green as u16 >> 2) & 0x3F;
                    let b = (color.blue as u16 >> 3) & 0x1F;
                    let pixel = (r << 11) | (g << 5) | b;
                    let ptr_addr = buffer.add(offset) as usize;
                    mmio::mmio_write_u16(ptr_addr, pixel);
                },
            }
        }
    }

    /// ピクセルを取得
    ///
    /// # Performance Warning
    /// When no back_buffer is present, this reads directly from VRAM which is
    /// **extremely slow** (100-1000x slower than RAM reads due to PCIe latency).
    /// For blend operations or repeated pixel reads, ensure double buffering is enabled.
    pub fn get_pixel(&self, x: u32, y: u32) -> Color {
        if x >= self.info.width || y >= self.info.height {
            return Color::BLACK;
        }

        // Read from back_buffer if available (fast RAM access) instead of VRAM
        if let Some(ref back) = self.back_buffer {
            let idx = (y as usize * self.info.width as usize) + x as usize;
            if idx < back.len() {
                return Color::from_u32(back[idx]);
            }
        }

        // Fallback: read directly from VRAM (SLOW!)
        let offset =
            (y * self.info.stride) as usize + (x as usize * self.info.format.bytes_per_pixel());

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => unsafe {
                let pixel = mmio::mmio_read_u32(self.buffer.add(offset) as usize);
                Color::from_u32(pixel)
            },
            PixelFormat::Bgr888 => unsafe {
                let b = mmio::volatile_read::<u8>(self.buffer.add(offset) as usize);
                let g = mmio::volatile_read::<u8>(self.buffer.add(offset + 1) as usize);
                let r = mmio::volatile_read::<u8>(self.buffer.add(offset + 2) as usize);
                Color::new(r, g, b)
            },
            PixelFormat::Rgb888 => unsafe {
                let r = mmio::volatile_read::<u8>(self.buffer.add(offset) as usize);
                let g = mmio::volatile_read::<u8>(self.buffer.add(offset + 1) as usize);
                let b = mmio::volatile_read::<u8>(self.buffer.add(offset + 2) as usize);
                Color::new(r, g, b)
            },
            PixelFormat::Rgb565 => unsafe {
                let pixel = mmio::mmio_read_u16(self.buffer.add(offset) as usize);
                let r = ((pixel >> 11) & 0x1F) as u8 * 8;
                let g = ((pixel >> 5) & 0x3F) as u8 * 4;
                let b = (pixel & 0x1F) as u8 * 8;
                Color::new(r, g, b)
            },
        }
    }

    /// 画面をクリア
    pub fn clear(&mut self, color: Color) {
        if let Some(ref mut back) = self.back_buffer {
             // Fast u32 fill
             back.fill(color.to_u32());
             // Mark dirty if needed? We assume clear invalidates everything usually,
             // or caller handles referencing dirty logic.
             // If we must mark dirty:
             let rect = Rect::new(0, 0, self.info.width, self.info.height);
             self.mark_dirty(rect);
             return;
        }
        // Mark entire screen as dirty
        self.mark_dirty(Rect::new(0, 0, self.info.width, self.info.height));
        let buffer = self.draw_buffer();
        let _bytes_per_pixel = self.info.format.bytes_per_pixel();
        let width = self.info.width as usize;
        let stride = self.info.stride as usize;

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => {
                let color_u32 = color.to_u32();
                if self.back_buffer.is_some() {
                    for y in 0..self.info.height as usize {
                        let offset = y * stride;
                        let row_ptr = unsafe { buffer.add(offset) as *mut u32 };
                        let row_slice = unsafe { core::slice::from_raw_parts_mut(row_ptr, width) };
                        row_slice.fill(color_u32);
                    }
                } else {
                    for y in 0..self.info.height as usize {
                        let offset = y * stride;
                        let addr = self.buffer as usize + offset;
                        // Use a no-fence variant to batch sfence after full clear
                        self.write_u32_run_streaming_nofence(addr, width, color_u32);
                    }
                    mmio::sfence();
                }
            }
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => {
                let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);
                let row_bytes = width * 3;
                // Prepare one scratch row and reuse for every row
                self.ensure_scratch_u8(row_bytes);
                // Fill first pixel with correct byte order
                if is_bgr {
                    self.scratch_u8[0] = color.blue;
                    if row_bytes > 1 {
                        self.scratch_u8[1] = color.green;
                    }
                    if row_bytes > 2 {
                        self.scratch_u8[2] = color.red;
                    }
                } else {
                    self.scratch_u8[0] = color.red;
                    if row_bytes > 1 {
                        self.scratch_u8[1] = color.green;
                    }
                    if row_bytes > 2 {
                        self.scratch_u8[2] = color.blue;
                    }
                }

                let mut filled = 1usize; // number of pixels filled
                while filled < width {
                    let copy_pixels = core::cmp::min(filled, width - filled);
                    let copy_bytes = copy_pixels * 3;
                    let dst_offset = filled * 3;
                    unsafe {
                        ptr::copy(
                            self.scratch_u8.as_ptr(),
                            self.scratch_u8.as_mut_ptr().add(dst_offset),
                            copy_bytes,
                        );
                    }
                    filled += copy_pixels;
                }

                if let Some(ref mut _back) = self.back_buffer {
                    debug_assert!(false, "legacy clear logic called on u32 backbuffer");
                } else {
                    for y in 0..self.info.height as usize {
                        let offset = y * stride;
                        let addr = self.buffer as usize + offset;
                        self.write_bytes_mmio_streaming(addr, &self.scratch_u8[..row_bytes]);
                    }
                    mmio::sfence();
                }
            }
            PixelFormat::Rgb565 => {
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                let pixel = (r << 11) | (g << 5) | b;
                let row_bytes = width * 2;
                // Build scratch row as little-endian u16 bytes
                self.ensure_scratch_u8(row_bytes);
                for i in 0..width {
                    let off = i * 2;
                    self.scratch_u8[off] = (pixel & 0xFF) as u8;
                    self.scratch_u8[off + 1] = (pixel >> 8) as u8;
                }

                if let Some(ref mut back) = self.back_buffer {
                    for y in 0..self.info.height as usize {
                        let offset = y * stride;
                        unsafe {
                            ptr::copy_nonoverlapping(
                                self.scratch_u8.as_ptr(),
                                (back.as_mut_ptr() as *mut u8).add(offset),
                                row_bytes,
                            );
                        }
                    }
                } else {
                    for y in 0..self.info.height as usize {
                        let offset = y * stride;
                        let addr = self.buffer as usize + offset;
                        self.write_bytes_mmio_streaming(addr, &self.scratch_u8[..row_bytes]);
                    }
                    mmio::sfence();
                }
            }
        }
    }

    /// 水平線を描画
    pub fn draw_hline(&mut self, x1: i32, x2: i32, y: i32, color: Color) {
        if y < self.clip.y || y >= self.clip.bottom() {
            return;
        }

        let start_x = x1.min(x2).max(self.clip.x);
        let end_x = x1.max(x2).min(self.clip.right() - 1);

        if start_x > end_x {
            return;
        }

        // Mark dirty
        self.mark_dirty(Rect::new(start_x, y, (end_x - start_x + 1) as u32, 1));
        self.draw_hline_raw(start_x, end_x, y, color);
    }

    /// Dirty Rectangle更新を行わない水平線描画（クリッピング済み前提）
    fn draw_hline_raw(&mut self, start_x: i32, end_x: i32, y: i32, color: Color) {
        let (bytes_per_pixel, stride) = if self.back_buffer.is_some() {
            (4, (self.info.width * 4) as usize)
        } else {
            (self.info.format.bytes_per_pixel(), self.info.stride as usize)
        };
        let x_start = start_x as usize;
        let run_len = (end_x - start_x + 1) as usize;
        let offset = (y as usize * stride) + x_start * bytes_per_pixel;

        match bytes_per_pixel {
            4 => {
                let color_u32 = color.to_u32();
                // Delegate to write_u32_run which already handles backbuffer/MMIO paths efficiently
                self.write_u32_run(offset, run_len, color_u32);
            }
            3 => {
                self.write_bgr_run(offset, run_len, color);
            }
            2 => {
                // rgb565 per-pixel write. Branch once on presence of back buffer
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                let pixel = (r << 11) | (g << 5) | b;
                if let Some(_) = self.back_buffer {
                    debug_assert!(false, "16bpp hline called on u32 backbuffer");
                } else {
                    let base_addr = self.draw_buffer() as usize;
                    for i in 0..run_len {
                        let off = base_addr + offset + i * 2;
                        mmio::mmio_write_u16(off, pixel);
                    }
                }
            }
            _ => {
                // Fallback (use set_pixel_raw)
                for x in start_x..=end_x {
                    self.set_pixel_raw(x, y, color);
                }
            }
        }
    }

    /// 垂直線を描画
    pub fn draw_vline(&mut self, x: i32, y1: i32, y2: i32, color: Color) {
        if x < self.clip.x || x >= self.clip.right() {
            return;
        }

        let start_y = y1.min(y2).max(self.clip.y);
        let end_y = y1.max(y2).min(self.clip.bottom() - 1);

        if start_y > end_y {
            return;
        }

        // Mark dirty
        self.mark_dirty(Rect::new(x, start_y, 1, (end_y - start_y + 1) as u32));
        self.draw_vline_raw(x, start_y, end_y, color);
    }

    /// Dirty Rectangle更新を行わない垂直線描画（クリッピング済み前提）
    fn draw_vline_raw(&mut self, x: i32, start_y: i32, end_y: i32, color: Color) {
        let (bytes_per_pixel, stride) = if self.back_buffer.is_some() {
            (4, (self.info.width * 4) as usize)
        } else {
            (self.info.format.bytes_per_pixel(), self.info.stride as usize)
        };
        let x_off = x as usize;
        let run_len = (end_y - start_y + 1) as usize;

        match bytes_per_pixel {
            4 => {
                let color_u32 = color.to_u32();
                // Branch once: either write to back buffer (fast pointer writes)
                // or write via MMIO helper.
                if let Some(_) = self.back_buffer {
                    let base = self.draw_buffer();
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = y * stride + x_off * 4;
                        unsafe {
                            ptr::write_unaligned(base.add(off) as *mut u32, color_u32);
                        }
                    }
                } else {
                    let base_addr = self.draw_buffer() as usize;
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = base_addr + y * stride + x_off * 4;
                        mmio::mmio_write_u32(off, color_u32);
                    }
                }
            }
            3 => {
                let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);
                let (c0, c1, c2) = if is_bgr {
                    (color.blue, color.green, color.red)
                } else {
                    (color.red, color.green, color.blue)
                };

                if let Some(ref mut _back) = self.back_buffer {
                    debug_assert!(false, "24bpp vline called on u32 backbuffer");
                } else {
                    let base_addr = self.draw_buffer() as usize;
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = base_addr + y * stride + x_off * 3;
                        mmio::volatile_write(off, c0);
                        mmio::volatile_write(off + 1, c1);
                        mmio::volatile_write(off + 2, c2);
                    }
                }
            }

            2 => {
                let r = (color.red as u16 >> 3) & 0x1F;
                let g = (color.green as u16 >> 2) & 0x3F;
                let b = (color.blue as u16 >> 3) & 0x1F;
                let pixel = (r << 11) | (g << 5) | b;
                if let Some(ref mut _back) = self.back_buffer {
                    debug_assert!(false, "16bpp vline called on u32 backbuffer");
                } else {
                    let base_addr = self.draw_buffer() as usize;
                    for i in 0..run_len {
                        let y = (start_y as usize) + i;
                        let off = base_addr + y * stride + x_off * 2;
                        mmio::mmio_write_u16(off, pixel);
                    }
                }
            }
            _ => {
                for y in start_y..=end_y {
                    self.set_pixel_raw(x, y, color);
                }
            }
        }
    }

    /// 線を描画（Bresenhamアルゴリズム） - Optimized
    pub fn draw_line(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        // Fast-path horizontal/vertical lines to use bulk writers (already optimized internally)
        if y1 == y2 {
            self.draw_hline(x1, x2, y1, color);
            return;
        }
        if x1 == x2 {
            self.draw_vline(x1, y1, y2, color);
            return;
        }

        // Calculate bounding box and mark dirty once
        let min_x = x1.min(x2);
        let min_y = y1.min(y2);
        let max_x = x1.max(x2);
        let max_y = y1.max(y2);
        let width = (max_x - min_x + 1) as u32;
        let height = (max_y - min_y + 1) as u32;

        self.mark_dirty(Rect::new(min_x, min_y, width, height));

        // We'll use Bresenham's algorithm but coalesce consecutive horizontal
        // runs into fast `draw_hline_raw` calls when possible to leverage bulk writers.
        let abs_dx = (x2 - x1).abs();
        let abs_dy = (y2 - y1).abs();

        // Heuristic: coalesce horizontal runs only for primarily-horizontal lines.
        if abs_dx < abs_dy {
            // Steep line: fallback to naive per-pixel algorithm to avoid extra
            // branching overhead when horizontal runs are uncommon.
            // Steep line: fallback to naive per-pixel algorithm to avoid extra
            // branching overhead when horizontal runs are uncommon.
            {
                // If bench feature not enabled, perform the naive walk inline.
                let dx = (x2 - x1).abs();
                let dy = -(y2 - y1).abs();
                let sx = if x1 < x2 { 1 } else { -1 };
                let sy = if y1 < y2 { 1 } else { -1 };
                let mut err = dx + dy;
                let mut x = x1;
                let mut y = y1;

                loop {
                    // Ensure we only call raw write for pixels inside clip
                    if x >= self.clip.x
                        && x < self.clip.right()
                        && y >= self.clip.y
                        && y < self.clip.bottom()
                    {
                        self.set_pixel_raw(x, y, color);
                    }
                    if x == x2 && y == y2 {
                        return;
                    }
                    let e2 = 2 * err;
                    if e2 >= dy {
                        err += dy;
                        x += sx;
                    }
                    if e2 <= dx {
                        err += dx;
                        y += sy;
                    }
                }
            }
        } else {
            // Primarily horizontal
            let dx = abs_dx;
            let dy = -(abs_dy);
            let sx = if x1 < x2 { 1 } else { -1 };
            let sy = if y1 < y2 { 1 } else { -1 };
            let mut err = dx + dy;

            let mut x = x1;
            let mut y = y1;

            // Track a current horizontal run starting at `run_start` on row `run_y`.
            let mut run_start = x;
            let mut run_y = y;
            let mut run_len = 1usize;

            loop {
                // If we've reached the destination, flush the pending run and exit.
                if x == x2 && y == y2 {
                    if run_len == 1 {
                        // Single-pixel run: ensure it's inside clip before raw write
                        if x >= self.clip.x
                            && x < self.clip.right()
                            && y >= self.clip.y
                            && y < self.clip.bottom()
                        {
                            self.set_pixel_raw(x, y, color);
                        }
                    } else {
                        // Normalize coordinates
                        let (s, e) = if sx > 0 {
                            (run_start, run_start + (run_len as i32 - 1))
                        } else {
                            (run_start - (run_len as i32 - 1), run_start)
                        };
                        // Clip horizontally to avoid writing out of bounds
                        if run_y >= self.clip.y && run_y < self.clip.bottom() {
                            let clip_left = self.clip.x;
                            let clip_right_incl = self.clip.right() - 1;
                            let s_clamped = s.max(clip_left).min(clip_right_incl);
                            let e_clamped = e.max(clip_left).min(clip_right_incl);
                            if s_clamped <= e_clamped {
                                self.draw_hline_raw(s_clamped, e_clamped, run_y, color);
                            }
                        }
                    }
                    break;
                }

                let e2 = 2 * err;
                if e2 >= dy {
                    err += dy;
                    x += sx;
                    // X changed.
                    // If Y also changes (diagonal step) or just X changes?
                    // Bresenham logic:
                    // if e2 >= dy { err += dy; x += sx; }
                    // if e2 <= dx { err += dx; y += sy; }
                    // If ONLY x changes, we extend run.
                    // If y changes, we flush run.
                }

                let y_changed = if e2 <= dx {
                    err += dx;
                    y += sy;
                    true
                } else {
                    false
                };

                if y_changed {
                    // Flush current run
                    if run_len == 1 {
                        // Ensure single-pixel run is within clip before raw write
                        if run_start >= self.clip.x
                            && run_start < self.clip.right()
                            && run_y >= self.clip.y
                            && run_y < self.clip.bottom()
                        {
                            self.set_pixel_raw(run_start, run_y, color);
                        }
                    } else {
                        let (s, e) = if sx > 0 {
                            (run_start, run_start + (run_len as i32 - 1))
                        } else {
                            (run_start - (run_len as i32 - 1), run_start)
                        };
                        // Clip run to prevent out-of-bounds writes
                        if run_y >= self.clip.y && run_y < self.clip.bottom() {
                            let clip_left = self.clip.x;
                            let clip_right_incl = self.clip.right() - 1;
                            let s_clamped = s.max(clip_left).min(clip_right_incl);
                            let e_clamped = e.max(clip_left).min(clip_right_incl);
                            if s_clamped <= e_clamped {
                                self.draw_hline_raw(s_clamped, e_clamped, run_y, color);
                            }
                        }
                    }
                    // Start new run
                    run_start = x;
                    run_y = y;
                    run_len = 1;
                } else {
                    // Only X changed, extend run
                    run_len += 1;
                }
            }
        }
    }

    /// Naive per-pixel Bresenham implementation useful for benchmarking and
    /// correctness comparisons. Enabled when `bench` feature is active.
    #[cfg(feature = "bench")]
    pub fn draw_line_naive(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        if y1 == y2 {
            self.draw_hline(x1, x2, y1, color);
            return;
        }
        if x1 == x2 {
            self.draw_vline(x1, y1, y2, color);
            return;
        }

        let dx = (x2 - x1).abs();
        let dy = -(y2 - y1).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;

        let mut x = x1;
        let mut y = y1;

        loop {
            self.set_pixel(x, y, color);
            if x == x2 && y == y2 {
                break;
            }
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                x += sx;
            }
            if e2 <= dx {
                err += dx;
                y += sy;
            }
        }
    }

    /// 矩形を描画（枠のみ）
    pub fn draw_rect(&mut self, rect: Rect, color: Color) {
        self.draw_hline(rect.x, rect.right() - 1, rect.y, color);
        self.draw_hline(rect.x, rect.right() - 1, rect.bottom() - 1, color);
        self.draw_vline(rect.x, rect.y, rect.bottom() - 1, color);
        self.draw_vline(rect.right() - 1, rect.y, rect.bottom() - 1, color);
    }

    /// 矩形領域をコピー（スクロール等に使用）
    pub fn copy_rect(&mut self, src: Rect, dst_x: i32, dst_y: i32) {
        // クリップ処理
        let mut s = src;
        // srcのクリップ
        s.x = s.x.max(self.clip.x);
        s.y = s.y.max(self.clip.y);
        let s_right = s.right().min(self.clip.right());
        let s_bottom = s.bottom().min(self.clip.bottom());
        s.width = (s_right - s.x).max(0) as u32;
        s.height = (s_bottom - s.y).max(0) as u32;

        // dstのクリップ（srcと連動）
        let mut d_x = dst_x + (s.x - src.x);
        let mut d_y = dst_y + (s.y - src.y);

        // dstが画面外にはみ出す場合の調整
        let clip_left = self.clip.x;
        let clip_top = self.clip.y;
        let clip_right = self.clip.right();
        let clip_bottom = self.clip.bottom();

        if d_x < clip_left {
            let diff = clip_left - d_x;
            s.x += diff;
            s.width = s.width.saturating_sub(diff as u32);
            d_x = clip_left;
        }
        if d_y < clip_top {
            let diff = clip_top - d_y;
            s.y += diff;
            s.height = s.height.saturating_sub(diff as u32);
            d_y = clip_top;
        }

        // 右/下のはみ出し
        let d_right = d_x + s.width as i32;
        if d_right > clip_right {
            let diff = d_right - clip_right;
            s.width = s.width.saturating_sub(diff as u32);
        }
        let d_bottom = d_y + s.height as i32;
        if d_bottom > clip_bottom {
            let diff = d_bottom - clip_bottom;
            s.height = s.height.saturating_sub(diff as u32);
        }

        if s.width == 0 || s.height == 0 {
            return;
        }

        // Mark destination dirty
        self.mark_dirty(Rect::new(d_x, d_y, s.width, s.height));

        let buffer = self.draw_buffer();
        let (stride, bpp) = if self.back_buffer.is_some() {
            (self.info.width as usize * 4, 4)
        } else {
            (self.info.stride as usize, self.info.format.bytes_per_pixel())
        };
        let copy_bytes = s.width as usize * bpp;

        unsafe {
            if d_y > s.y {
                // 下方向へのコピー（後ろから）
                for i in (0..s.height).rev() {
                    let src_row_y = s.y + i as i32;
                    let dst_row_y = d_y + i as i32;

                    let src_offset = (src_row_y as usize * stride) + (s.x as usize * bpp);
                    let dst_offset = (dst_row_y as usize * stride) + (d_x as usize * bpp);

                    ptr::copy(buffer.add(src_offset), buffer.add(dst_offset), copy_bytes);
                }
            } else {
                // 上方向へのコピー（前から）
                for i in 0..s.height {
                    let src_row_y = s.y + i as i32;
                    let dst_row_y = d_y + i as i32;

                    let src_offset = (src_row_y as usize * stride) + (s.x as usize * bpp);
                    let dst_offset = (dst_row_y as usize * stride) + (d_x as usize * bpp);

                    ptr::copy(buffer.add(src_offset), buffer.add(dst_offset), copy_bytes);
                }
            }
        }
    }

    /// Draw entire image at (dst_x, dst_y)
    pub fn draw_image(&mut self, image: &crate::graphics::image::Image, dst_x: i32, dst_y: i32) {
        self.draw_image_part(image, Rect::new(0, 0, image.width(), image.height()), dst_x, dst_y);
    }

    /// Draw a part of an image
    pub fn draw_image_part(
        &mut self,
        image: &crate::graphics::image::Image,
        src_rect: Rect,
        dst_x: i32,
        dst_y: i32,
    ) {
        // Clip source rect to image bounds
        let s_x = src_rect.x.max(0);
        let s_y = src_rect.y.max(0);
        let s_w = (src_rect.width as i32).min(image.width() as i32 - s_x).max(0) as u32;
        let s_h = (src_rect.height as i32).min(image.height() as i32 - s_y).max(0) as u32;

        if s_w == 0 || s_h == 0 {
            return;
        }

        // Clip destination rect to screen bounds
        let mut d_x = dst_x;
        let mut d_y = dst_y;
        let mut r_x = s_x;
        let mut r_y = s_y;
        let mut r_w = s_w;
        let mut r_h = s_h;

        // Left clip
        if d_x < self.clip.x {
            let diff = self.clip.x - d_x;
            if diff >= r_w as i32 { return; }
            d_x += diff;
            r_x += diff;
            r_w -= diff as u32;
        }
        // Top clip
        if d_y < self.clip.y {
            let diff = self.clip.y - d_y;
            if diff >= r_h as i32 { return; }
            d_y += diff;
            r_y += diff;
            r_h -= diff as u32;
        }
        // Right clip
        let over_x = (d_x + r_w as i32) - self.clip.right();
        if over_x > 0 {
            if over_x >= r_w as i32 { return; }
            r_w -= over_x as u32;
        }
        // Bottom clip
        let over_y = (d_y + r_h as i32) - self.clip.bottom();
        if over_y > 0 {
            if over_y >= r_h as i32 { return; }
            r_h -= over_y as u32;
        }

        if r_w == 0 || r_h == 0 {
            return;
        }

        // Mark dirty
        self.mark_dirty(Rect::new(d_x, d_y, r_w, r_h));

        // Perform blit
        let src_stride = image.width() * 4; // Image is always RGBA8888 packed
        let src_data = image.data();
        let dst_stride = if self.back_buffer.is_some() { self.info.width * 4 } else { self.info.stride } as usize;
        let dst_bpp = if self.back_buffer.is_some() { 4 } else { self.info.format.bytes_per_pixel() } as usize;

        let buf_ptr = self.draw_buffer();

        // Check if formats match (Image is RGBA, we need to know FB format)
        // If backbuffer is active, it is BGRA (u32). Image is RGBA (u8 bytes).
        // Wait, backbuffer is Vec<u32>. `set_pixel` converts Color (RGBA internal?) to u32 (BGRA).
        // Color struct is R,G,B,A. `to_u32` -> A R G B? No, usually 0xAARRGGBB.
        // If LE, 0xAARRGGBB is B G R A in memory.
        // Image data is R G B A in memory.
        // So we need R<->B swap (swizzle).
        // Except if format is Rgba8888.
        let needs_swizzle = match (self.back_buffer.is_some(), self.info.format) {
             (true, _) => true, // Backbuffer is BGRA (u32)
             (false, PixelFormat::Bgra8888 | PixelFormat::Bgr888) => true,
             _ => false,
        };

        for i in 0..r_h {
            let src_row_offset = ((r_y as u32 + i as u32) * src_stride + (r_x as u32 * 4)) as usize;
            // Ensure all operands are usize for offset calculation
            let dst_row_offset = (d_y as usize + i as usize) * dst_stride + (d_x as usize * dst_bpp as usize);
            
            let src_row = &src_data[src_row_offset .. src_row_offset + (r_w as usize * 4)];
            
            unsafe {
                let dst_ptr = buf_ptr.add(dst_row_offset);
                
                if self.back_buffer.is_some() {
                   // Writing to Vec<u32> (backbuffer)
                   let dst_slice = core::slice::from_raw_parts_mut(dst_ptr, r_w as usize * 4);
                   crate::graphics::packer::pack_rgba_to_bgra(src_row, dst_slice);
                } else {
                   // MMIO
                   match dst_bpp {
                       4 => {
                           if needs_swizzle {
                               let dst_slice = core::slice::from_raw_parts_mut(dst_ptr, r_w as usize * 4);
                               crate::graphics::packer::pack_rgba_to_bgra(src_row, dst_slice);
                           } else {
                               self.write_bytes_mmio_streaming(dst_ptr as usize, src_row);
                           }
                       }
                       3 => {
                           let dst_slice = core::slice::from_raw_parts_mut(dst_ptr, r_w as usize * 3);
                           crate::graphics::packer::pack_rgba_to_bgr24(src_row, dst_slice, needs_swizzle);
                       }
                       _ => {}
                   }
                   if i == r_h - 1 {
                       mmio::sfence();
                   }
                }
            }
        }
    }
    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        // クリップ処理
        let mut r = rect;
        r.x = r.x.max(self.clip.x);
        r.y = r.y.max(self.clip.y);
        let right = r.right().min(self.clip.right());
        let bottom = r.bottom().min(self.clip.bottom());
        r.width = (right - r.x).max(0) as u32;
        r.height = (bottom - r.y).max(0) as u32;

        if r.width == 0 || r.height == 0 {
            return;
        }

        if self.back_buffer.is_none() && self.buffer.is_null() {
            return;
        }

        self.stats.rectangles_drawn += 1;
        self.stats.pixels_drawn += (r.width * r.height) as usize;

        // Mark dirty
        self.mark_dirty(r);

        let _buffer = self.draw_buffer();
        let bpp = self.info.format.bytes_per_pixel();
        let stride = self.info.stride;

        #[cfg(feature = "std")]
        if std::env::var("RANY_DEBUG_DRAW").ok().as_deref() == Some("1") {
            eprintln!(
                "fill_rect start: back_present={} buffer_ptr=0x{:x} info_size={} stride={} rect={:?}",
                self.back_buffer.is_some(),
                self.buffer as usize,
                self.info.size(),
                stride,
                r
            );
        }

        if let Some(ref mut back) = self.back_buffer {
             let w = r.width as usize;
             let val = color.to_u32();
             for y in r.y..r.bottom() {
                 let idx = (y as usize * self.info.width as usize) + r.x as usize;
                 back[idx..idx+w].fill(val);
             }
             return;
        }

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => {
                let color_u32 = color.to_u32();

                if bpp == 4 {
                    // MMIO path: use aligned streaming write helper
                    for y in r.y..r.bottom() {
                        let offset = (y as usize * stride as usize) + (r.x as usize * 4);
                        let addr = self.buffer as usize + offset;
                        // Use the no-fence variant per-row and issue a single
                        // sfence after the loop for better throughput.
                        self.write_u32_run_streaming_nofence(addr, r.width as usize, color_u32);
                    }
                    mmio::sfence();
                } else {
                     // Should not happen for 32bpp path if backbuffer logic logic was hit?
                     // Ah, this block is if back_buffer is None.
                }
            }
            _ => {
                // 24bpp (and other) formats: use safe 1-row pattern approach
                // Create one row of the pattern, then copy it to subsequent rows.
                match self.info.format {
                    PixelFormat::Bgr888 | PixelFormat::Rgb888 => {
                        let width = r.width as usize;
                        let row_bytes = width * 3;
                        
                        if row_bytes == 0 {
                            return;
                        }
                        
                        // Get color bytes in correct order
                        let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);
                        let (c0, c1, c2) = if is_bgr {
                            (color.blue, color.green, color.red)
                        } else {
                            (color.red, color.green, color.blue)
                        };
                        
                        // Ensure scratch buffer has enough space for one row
                        self.ensure_scratch_u8(row_bytes);
                        
                        // Build one row pattern in scratch buffer
                        for i in 0..width {
                            self.scratch_u8[i * 3] = c0;
                            self.scratch_u8[i * 3 + 1] = c1;
                            self.scratch_u8[i * 3 + 2] = c2;
                        }
                        
                        let stride = stride as usize;
                        
                        if let Some(ref mut _back) = self.back_buffer {
                             // 24bpp fill_rect fallback.
                             // Backbuffer should use top-level 32bpp path.
                             debug_assert!(false, "24bpp fill_rect fallback called on u32 backbuffer");
                        } else {
                            // MMIO path: use streaming writes for each row
                            for y in r.y..r.bottom() {
                                let offset = y as usize * stride + r.x as usize * 3;
                                let addr = self.buffer as usize + offset;
                                self.write_bytes_mmio_streaming(addr, &self.scratch_u8[..row_bytes]);
                            }
                            mmio::sfence();
                        }
                    }
                    _ => {
                        // Other formats: per-pixel fallback (16-bit etc)
                        for y in r.y..r.bottom() {
                            for x in r.x..r.right() {
                                self.set_pixel_raw(x, y, color);
                            }
                        }
                    }
                }
            }
        }
    }

    /// 円を描画（Midpointアルゴリズム）
    pub fn draw_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        let mut x = radius;
        let mut y = 0;
        let mut err = 0;

        while x >= y {
            self.set_pixel(cx + x, cy + y, color);
            self.set_pixel(cx + y, cy + x, color);
            self.set_pixel(cx - y, cy + x, color);
            self.set_pixel(cx - x, cy + y, color);
            self.set_pixel(cx - x, cy - y, color);
            self.set_pixel(cx - y, cy - x, color);
            self.set_pixel(cx + y, cy - x, color);
            self.set_pixel(cx + x, cy - y, color);

            y += 1;
            if err <= 0 {
                err += 2 * y + 1;
            }
            if err > 0 {
                x -= 1;
                err -= 2 * x + 1;
            }
        }
    }

    /// 塗りつぶし円を描画
    pub fn fill_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        let mut x = radius;
        let mut y = 0;
        let mut err = 0;

        while x >= y {
            self.draw_hline(cx - x, cx + x, cy + y, color);
            self.draw_hline(cx - y, cx + y, cy + x, color);
            self.draw_hline(cx - x, cx + x, cy - y, color);
            self.draw_hline(cx - y, cx + y, cy - x, color);

            y += 1;
            if err <= 0 {
                err += 2 * y + 1;
            }
            if err > 0 {
                x -= 1;
                err -= 2 * x + 1;
            }
        }
    }

    /// テキストを描画（組み込み8x16フォントを使用）
    ///
    /// # Arguments
    /// * `x` - 開始X座標
    /// * `y` - 開始Y座標
    /// * `text` - 描画するテキスト
    /// * `color` - 文字色
    /// * `bg_color` - 背景色
    pub fn draw_text(&mut self, x: i32, y: i32, text: &str, color: Color, bg_color: Color) {
        let font = BitmapFont::default_8x16();
        
        // Calculate stride: if using backbuffer (Vec<u32>), stride is width * 4.
        // Otherwise use MMIO stride.
        let stride = if self.back_buffer.is_some() {
            (self.info.width * 4) as usize
        } else {
            self.info.stride as usize
        };
        
        // --- Single-Pass Background Fill Optimization ---
        // Calculate the total width of the text to limit the number of fill_rect calls.
        // Currently draw_text only handles single line (strips newlines).
        let char_count = text.chars().filter(|&c| c != '\n').count() as i32;
        let total_w = char_count * font.width() as i32;
        let char_h = font.height() as u32;

        if total_w > 0 {
            // Fill the entire background once
            self.fill_rect(Rect::new(x, y, total_w as u32, char_h), bg_color);
        }

        let format = if self.back_buffer.is_some() {
            PixelFormat::Bgra8888
        } else {
            self.info.format
        };

        let bpp = format.bytes_per_pixel() as usize;
        let mut cx = x;
        let mut need_fence = false; // Track if any MMIO streaming writes occurred
        for c in text.chars() {
            if c == '\n' {
                continue;
            }

            // 32-bit Fast Path: fully clipped & opaque
            // If the character is completely contained within the clip rect, we can
            // write full rows efficiently without per-pixel checks or separate background fill.
            let char_w = font.width() as i32;
            let char_h = font.height() as i32;
            if bpp == 4 
                && cx >= self.clip.x && (cx + char_w) <= self.clip.right()
                && y >= self.clip.y && (y + char_h) <= self.clip.bottom()
            {
                // Mark dirty for double-buffering support
                self.mark_dirty(Rect::new(cx, y, char_w as u32, char_h as u32));
                
                let fg_u32 = format.encode_u32(color).unwrap_or(color.to_u32());
                let bg_u32 = format.encode_u32(bg_color).unwrap_or(bg_color.to_u32());
                
                let data = font.glyph(c).unwrap_or(&[0u8; 16]);
                
                for (row, &byte) in data.iter().enumerate() {
                    let offset = ((y + row as i32) as usize * stride) + (cx as usize * 4);
                    need_fence |= self.write_glyph_row_32bit_nofence(byte, offset, fg_u32, bg_u32);
                }
                
                cx += char_w;
                continue;
            }

            let glyph_opt = font.glyph(c);

            // For either a missing glyph or regular glyph, we should
            // We skip filling the character box (fill_rect) because we pre-filled
            // the entire string background at the start of the function.
            // This massively reduces MMIO/fill overhead for 24bpp and clipped text.
            // let char_w = font.width() as u32;
            // let _char_h = font.height() as u32;
            // self.fill_rect(Rect::new(cx, y, char_w, char_h), bg_color);

            let glyph = match glyph_opt {
                Some(g) => g,
                None => {
                    cx += font.width() as i32;
                    continue;
                }
            };

            for (row, &byte) in glyph.iter().enumerate() {
                let mut col = 0usize;
                while col < font.width() as usize {
                    // Skip off pixels
                    while col < font.width() as usize {
                        let pixel_on = (byte >> (7 - col)) & 1 != 0;
                        if pixel_on {
                            break;
                        }
                        col += 1;
                    }

                    let run_start = col;
                    while col < font.width() as usize {
                        let pixel_on = (byte >> (7 - col)) & 1 != 0;
                        if !pixel_on {
                            break;
                        }
                        col += 1;
                    }

                    let run_len = col.saturating_sub(run_start);
                    if run_len == 0 {
                        continue;
                    }

                    // Compute absolute destination and apply clipping
                    let dst_x = cx + run_start as i32;
                    let dst_y = y + row as i32;
                    if dst_y < self.clip.y || dst_y >= self.clip.bottom() {
                        continue;
                    }

                    let dst_run_end_x = dst_x + run_len as i32 - 1;
                    if dst_run_end_x < self.clip.x || dst_x >= self.clip.right() {
                        continue;
                    }

                    let clipped_start = dst_x.max(self.clip.x);
                    let clipped_end = dst_run_end_x.min(self.clip.right() - 1);
                    let clipped_len = (clipped_end - clipped_start + 1) as usize;
                    let start_offset = (dst_y as usize * stride) + (clipped_start as usize * bpp);

                    match bpp {
                        3 => {
                            // 24bpp Optimized: Use write_bgr_run instead of per-pixel loops
                            // Background is already filled; only write the FG runs.
                            // write_bgr_run handles MMIO streaming internally.
                            // Note: We need to mark need_fence because write_bgr_run typically uses non-temporal stores
                            self.write_bgr_run(start_offset, clipped_len, color);
                            need_fence = true;
                        }
                        2 => {
                            for i in 0..clipped_len {
                                let off = start_offset + i * 2;
                                let r = (color.red as u16 >> 3) & 0x1F;
                                let g = (color.green as u16 >> 2) & 0x3F;
                                let b = (color.blue as u16 >> 3) & 0x1F;
                                let pixel = (r << 11) | (g << 5) | b;
                                if self.back_buffer.is_some() {
                                    unsafe {
                                        ptr::write(self.draw_buffer().add(off) as *mut u16, pixel);
                                    }
                                } else {
                                    unsafe {
                                        mmio::mmio_write_u16(
                                            self.draw_buffer().add(off) as usize,
                                            pixel,
                                        );
                                    }
                                }
                            }
                        }
                        _ => {
                            // Fallback
                            for i in 0..clipped_len {
                                // We have already marked the text region dirty above;
                                // use raw pixel write to avoid redundant dirty updates.
                                self.set_pixel_raw(clipped_start + i as i32, dst_y, color);
                            }
                        }
                    }
                }
            }

            cx += font.width() as i32;
        }

        // Ensure batched 32-bit writes are visible (once per string, not per char)
        if need_fence {
            self.counted_sfence();
        }
    }

    /// Draw a generic bitmap glyph.
    ///
    /// Optimized for 32bpp and 24bpp formats using bulk writes/runs where possible.
    /// `glyph` is expected to be row-major, byte-aligned (stride = (width + 7) / 8).
    pub fn draw_glyph_bitmap(
        &mut self,
        x: i32,
        y: i32,
        glyph: &[u8],
        width: u32,
        height: u32,
        color: Color,
        bg: Option<Color>,
    ) {
        let (stride, bpp) = if self.back_buffer.is_some() {
            ((self.info.width * 4) as usize, 4)
        } else {
            (self.info.stride as usize, self.info.format.bytes_per_pixel())
        };

        // Mark dirty
        self.mark_dirty(Rect::new(x, y, width, height));

        // Fill background if specified
        if let Some(bg_color) = bg {
            self.fill_rect(Rect::new(x, y, width, height), bg_color);
        }

        let bytes_per_row = ((width + 7) / 8) as usize;

        // Pre-encode colors for 32-bit optimization
        let (fg_u32, bg_u32) = if bpp == 4 {
            if self.back_buffer.is_some() {
                (color.to_u32(), bg.map(|c| c.to_u32()).unwrap_or(0))
            } else {
                (
                    self.info.format.encode_u32(color).unwrap_or(color.to_u32()),
                    bg.map(|c| self.info.format.encode_u32(c).unwrap_or(c.to_u32())).unwrap_or(0),
                )
            }
        } else {
            (0, 0)
        };

        let mut mmio_wrote = false;
        for row in 0..height {
            let dst_y = y + row as i32;
            if dst_y < self.clip.y || dst_y >= self.clip.bottom() {
                continue;
            }

            let row_offset = row as usize * bytes_per_row;
            if row_offset >= glyph.len() {
                break;
            }
            let row_data =
                &glyph[row_offset..core::cmp::min(row_offset + bytes_per_row, glyph.len())];

            for (byte_idx, &byte) in row_data.iter().enumerate() {
                let px_start = x + (byte_idx * 8) as i32;

                // 32-bit Optimization: Write 8 pixels at once if fully visible and fits in width
                if bpp == 4 {
                    // Check bounds: visible horizontally AND within glyph width
                    // (Ensure we don't write extra pixels if width % 8 != 0)
                    if bg.is_some()
                        && px_start >= self.clip.x
                        && (px_start + 8) <= self.clip.right()
                        && (px_start + 8) <= (x + width as i32)
                    {
                        let dst_offset = (dst_y as usize * stride) + (px_start as usize * 4);
                        if self.write_glyph_row_32bit_nofence(byte, dst_offset, fg_u32, bg_u32) {
                            mmio_wrote = true;
                        }
                        continue;
                    }
                } else if bpp == 3 {
                    // 24-bit Optimization: Find runs of ON bits
                    let mut col = 0usize;
                    while col < 8 {
                        // Check bound against glyph width
                        if (byte_idx * 8 + col) >= width as usize {
                            break;
                        }

                        // Skip OFF pixels
                        while col < 8 {
                            if (byte_idx * 8 + col) >= width as usize {
                                break;
                            }
                            let is_on = (byte >> (7 - col)) & 1 != 0;
                            if is_on {
                                break;
                            }
                            col += 1;
                        }

                        let run_start = col;
                        while col < 8 {
                            if (byte_idx * 8 + col) >= width as usize {
                                break;
                            }
                            let is_on = (byte >> (7 - col)) & 1 != 0;
                            if !is_on {
                                break;
                            }
                            col += 1;
                        }

                        let run_len = col - run_start;
                        if run_len == 0 {
                            continue;
                        }

                        let dst_x = px_start + run_start as i32;

                        // Clipping
                        let dst_start_x = dst_x.max(self.clip.x);
                        let dst_end_x = (dst_x + run_len as i32 - 1).min(self.clip.right() - 1);

                        if dst_end_x >= dst_start_x {
                            let clipped_len = (dst_end_x - dst_start_x + 1) as usize;
                            let start_offset =
                                (dst_y as usize * stride) + (dst_start_x as usize * 3);
                            self.write_bgr_run(start_offset, clipped_len, color);
                        }
                    }
                    continue;
                } else if bpp == 2 {
                    // 16-bit Optimization (e.g. RGB565)
                    let mut col = 0usize;
                    while col < 8 {
                        if (byte_idx * 8 + col) >= width as usize {
                            break;
                        }

                        while col < 8 {
                            if (byte_idx * 8 + col) >= width as usize {
                                break;
                            }
                            let is_on = (byte >> (7 - col)) & 1 != 0;
                            if is_on {
                                break;
                            }
                            col += 1;
                        }

                        let run_start = col;
                        while col < 8 {
                            if (byte_idx * 8 + col) >= width as usize {
                                break;
                            }
                            let is_on = (byte >> (7 - col)) & 1 != 0;
                            if !is_on {
                                break;
                            }
                            col += 1;
                        }

                        let run_len = col - run_start;
                        if run_len == 0 {
                            continue;
                        }

                        let dst_x = px_start + run_start as i32;

                        let dst_start_x = dst_x.max(self.clip.x);
                        let dst_end_x = (dst_x + run_len as i32 - 1).min(self.clip.right() - 1);

                        if dst_end_x >= dst_start_x {
                            let clipped_len = (dst_end_x - dst_start_x + 1) as usize;
                            let start_offset =
                                (dst_y as usize * stride) + (dst_start_x as usize * 2);

                            // Encode 16-bit pixel
                            let r16 = (color.red as u16 >> 3) & 0x1F;
                            let g16 = (color.green as u16 >> 2) & 0x3F;
                            let b16 = (color.blue as u16 >> 3) & 0x1F;
                            let pixel = (r16 << 11) | (g16 << 5) | b16;

                            self.ensure_scratch_u8(clipped_len * 2);
                            for i in 0..clipped_len {
                                self.scratch_u8[i * 2] = (pixel & 0xFF) as u8;
                                self.scratch_u8[i * 2 + 1] = (pixel >> 8) as u8;
                            }

                            if let Some(ref mut _back) = self.back_buffer {
                                // 16bpp optimization invalid for 32bpp backbuffer
                                debug_assert!(false, "16bpp draw_line called on u32 backbuffer");
                            } else {
                                let addr = self.buffer as usize + start_offset;
                                self.write_bytes_mmio_streaming(
                                    addr,
                                    &self.scratch_u8[..clipped_len * 2],
                                );
                                mmio::sfence();
                            }
                        }
                    }
                    continue;
                }

                // Fallback / Partial / 16-bit path
                for bit in 0..8 {
                    let px = px_start + bit;
                    // Check bounds against clip AND glyph width
                    if px < self.clip.x || px >= self.clip.right() || px >= x + width as i32 {
                        continue;
                    }

                    let is_on = (byte >> (7 - bit)) & 1 != 0;
                    if is_on {
                        self.set_pixel_raw(px, dst_y, color);
                    }
                }
            }
        }

        if mmio_wrote {
            mmio::sfence();
        }
    }

    /// Draw a single 8x16 bitmap glyph (convenience optimized path).
    ///
    /// This method exposes a compact and faster path for single-character
    /// drawing used by `BitmapFont::draw_char`. It attempts to use
    /// 64-bit writes on 32-bit framebuffers and `write_bgr_run` on 24-bit
    /// framebuffers to minimize per-pixel overhead.
    pub fn draw_char_8x16(&mut self, x: i32, y: i32, c: char, color: Color, bg: Option<Color>) {
        let font = BitmapFont::default_8x16();
        let glyph = match font.glyph(c) {
            Some(g) => g,
            None => return,
        };
        let stride = self.info.stride as usize;
        let bpp = self.info.format.bytes_per_pixel();

        // Mark entire character area dirty to avoid per-pixel dirty updates
        let char_w_i32 = font.width() as i32;
        let char_w = font.width() as u32;
        let char_h = font.height() as u32;
        self.mark_dirty(Rect::new(x, y, char_w, char_h));

        // CHECK FAST PATH CONDITIONS
        // We can skip fill_rect if we are going to overwrite everything with write_glyph_row_32bit_nofence
        let is_fully_visible = x >= self.clip.x && (x + char_w_i32) <= self.clip.right();
        let use_fast_path_32 = bpp == 4 && bg.is_some() && is_fully_visible;

        // If background specified AND we won't use the fast path (which handles bg), fill it now.
        if let Some(bg_color) = bg {
            if !use_fast_path_32 {
                self.fill_rect(Rect::new(x, y, char_w, char_h), bg_color);
            }
        }

        let mut mmio_written = false;
        for (row, &byte) in glyph.iter().enumerate() {
            let dst_y = y + row as i32;
            if dst_y < self.clip.y || dst_y >= self.clip.bottom() {
                continue;
            }

            match bpp {
                4 => {
                    // 32-bit formats
                    let fg_u32 = self.info.format.encode_u32(color).unwrap_or(color.to_u32());

                    if bg.is_some() {
                        // If fully visible horizontally, write whole 8-pixel row
                        if is_fully_visible {
                            let dst_offset = (dst_y as usize * stride) + (x as usize * 4);
                            let bg_color = bg.unwrap();
                            let bg_u32 = self
                                .info
                                .format
                                .encode_u32(bg_color)
                                .unwrap_or(bg_color.to_u32());
                            // This writes both FG and BG pixels
                            mmio_written |= self.write_glyph_row_32bit_nofence(byte, dst_offset, fg_u32, bg_u32);
                            continue;
                        }
                    }

                    // Partially clipped or no-background case: set pixels individually
                    for col in 0..8 {
                        let px = x + col as i32;
                        if px < self.clip.x || px >= self.clip.right() {
                            continue;
                        }
                        let is_on = (byte >> (7 - col)) & 1 != 0;
                        if is_on {
                            self.set_pixel_raw(px, dst_y, color);
                        }
                    }
                }
                3 => {
                    // 24-bit formats: write runs of on-bits with write_bgr_run
                    let mut col = 0usize;
                    while col < 8 {
                        // Skip off pixels
                        while col < 8 {
                            let pixel_on = (byte >> (7 - col)) & 1 != 0;
                            if pixel_on {
                                break;
                            }
                            col += 1;
                        }
                        let run_start = col;
                        while col < 8 {
                            let pixel_on = (byte >> (7 - col)) & 1 != 0;
                            if !pixel_on {
                                break;
                            }
                            col += 1;
                        }
                        let run_len = col.saturating_sub(run_start);
                        if run_len == 0 {
                            continue;
                        }
                        let dst_x = x + run_start as i32;
                        if dst_x < self.clip.x || dst_x >= self.clip.right() {
                            continue;
                        }
                        let clipped_end = (dst_x + run_len as i32 - 1).min(self.clip.right() - 1);
                        let clipped_len = (clipped_end - dst_x + 1) as usize;
                        let start_offset = (dst_y as usize * stride) + (dst_x as usize * 3);
                        self.write_bgr_run(start_offset, clipped_len, color);
                    }
                }
                _ => {
                    // Fallback: per-pixel writes (e.g., RGB565)
                    for col in 0..8 {
                        let px = x + col as i32;
                        if px < self.clip.x || px >= self.clip.right() {
                            continue;
                        }
                        let is_on = (byte >> (7 - col)) & 1 != 0;
                        if is_on {
                            self.set_pixel_raw(px, dst_y, color);
                        }
                    }
                }
            }
        }

        if mmio_written {
            self.counted_sfence();
        }
    }

    /// 画像描画用のクリッピング計算 helper
    fn calculate_image_clip(
        &self,
        image: &super::image::Image,
        x: i32,
        y: i32,
    ) -> Option<(Rect, u32, u32)> {
        // Compute intersection between image destination rect and clip/bounds
        let dst_x0 = x.max(self.clip.x).max(0);
        let dst_y0 = y.max(self.clip.y).max(0);
        let dst_x1 = (x + image.width() as i32)
            .min(self.clip.right())
            .min(self.info.width as i32);
        let dst_y1 = (y + image.height() as i32)
            .min(self.clip.bottom())
            .min(self.info.height as i32);

        if dst_x1 <= dst_x0 || dst_y1 <= dst_y0 {
            return None;
        }

        let width = (dst_x1 - dst_x0) as u32;
        let height = (dst_y1 - dst_y0) as u32;
        let draw_rect = Rect::new(dst_x0, dst_y0, width, height);

        // Source offsets
        let src_off_x = (dst_x0 - x) as u32;
        let src_off_y = (dst_y0 - y) as u32;

        Some((draw_rect, src_off_x, src_off_y))
    }



    /// 32-bit不透明ランの描画
    fn write_opaque_run_32bit(
        &mut self,
        image: &super::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        avx2_available: bool,
    ) -> bool {
        let src_base = (src_row * image.width() + run_start) as usize;
        let imgdata = image.data();
        let mut mmio_written = false;

        // If backbuffer (fixed u32/BGRA) is active, write to it directly performing RGBA->BGRA swizzle
        if let Some(ref mut back) = self.back_buffer {
             let src_offset = src_base * 4;
             // Ensure bounds
             if src_offset + run_len * 4 <= imgdata.len() {
                 let dst_ptr = unsafe { (back.as_mut_ptr() as *mut u8).add(dst_byte_offset) };
                 // Image is RGBA [R, G, B, A]. Backbuffer is u32/BGRA (on LE) [B, G, R, A].
                 // Perform R/B swap swizzle.
                 for i in 0..run_len {
                     let off = i * 4;
                     let r = imgdata[src_offset + off];
                     let g = imgdata[src_offset + off + 1];
                     let b = imgdata[src_offset + off + 2];
                     let a = imgdata[src_offset + off + 3];
                     unsafe {
                         *dst_ptr.add(off) = b;
                         *dst_ptr.add(off + 1) = g;
                         *dst_ptr.add(off + 2) = r;
                         *dst_ptr.add(off + 3) = a;
                     }
                 }
             }
             return false;
        }
        
        // Allow tuning... (omitted for brevity, keep existing logic if possible, or just copy-paste)
        /* ... keeping variable declarations ... */
        #[cfg(feature = "std")]
        let stream_threshold_pixels: usize = std::env::var("RANY_STREAM_THRESHOLD_PIXELS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(2048);
        #[cfg(not(feature = "std"))]
        let stream_threshold_pixels: usize = 2048;

        if self.info.format == PixelFormat::Rgba8888 {
            let byte_len = run_len * 4;
            let src_slice = &imgdata[src_base * 4..src_base * 4 + byte_len];

                let addr = self.buffer as usize + dst_byte_offset;
                self.write_bytes_mmio_streaming(addr, src_slice);
                // mmio::sfence(); // DEFERRED
                mmio_written = true;
        } else if self.info.format == PixelFormat::Bgra8888 {
            let src_slice = &imgdata[src_base * 4..src_base * 4 + run_len * 4];

                if avx2_available && run_len >= stream_threshold_pixels {
                    let addr = self.buffer as usize + dst_byte_offset;
                    self.write_rgba_packed_to_mmio_stream(addr, src_slice);
                    // return; // DEFERRED
                    return true;
                }

                self.ensure_scratch_u32(run_len);
                let dst_bytes = unsafe {
                    core::slice::from_raw_parts_mut(
                        self.scratch_u32.as_mut_ptr() as *mut u8,
                        run_len * 4,
                    )
                };
                Self::pack_rgba_to_bgra(src_slice, dst_bytes);
                let addr = self.buffer as usize + dst_byte_offset;
                self.write_u32_slice_mmio(addr, &self.scratch_u32[..run_len]);
                mmio_written = true; // Volatile writes technically don't need sfence but we signal activity
        }
        mmio_written
    }

    /// 24-bit不透明ランの描画
    fn write_opaque_run_24bit(
        &mut self,
        image: &super::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        x: i32,
        dst_row: i32,
        _avx2_available: bool,
    ) -> bool {
        let total_bytes = run_len * 3;
        self.ensure_scratch_u8(total_bytes);
        let src_base = (src_row * image.width() + run_start) as usize;
        let imgdata = image.data();
        let mut handled_in_scratch = false;

        // let mut i = 0usize;
        // let mut src_idx = src_base * 4;
        // let mut dst_off = 0usize;

        match self.info.format {
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => {
                handled_in_scratch = true;
                let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);

                // Pack directly into scratch buffer using optimized dispatcher
                let src_slice = unsafe {
                    core::slice::from_raw_parts(imgdata.as_ptr().add(src_base * 4), run_len * 4)
                };
                let dst_slice = unsafe {
                    core::slice::from_raw_parts_mut(self.scratch_u8.as_mut_ptr(), run_len * 3)
                };

                Self::pack_rgba_to_bgr24(src_slice, dst_slice, is_bgr);
            }
            _ => {
                // Fallback — use raw writes since caller has already marked dirty
                for j in 0..run_len {
                    let idx2 = (src_base + j) * 4;
                    let c = Color::with_alpha(
                        imgdata[idx2],
                        imgdata[idx2 + 1],
                        imgdata[idx2 + 2],
                        imgdata[idx2 + 3],
                    );
                    self.set_pixel_raw(x + (run_start as i32 + j as i32), dst_row, c);
                }
            }
        }

        if handled_in_scratch {
            // Tunable chunk size for 24-bit writes; use `RANY_CHUNK_24_PIXELS`
            // to experiment with different chunk sizes when benching.
            #[cfg(feature = "std")]
            let chunk_24_pixels: usize = std::env::var("RANY_CHUNK_24_PIXELS")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or_else(|| {
                    if run_len >= 8192 {
                        4096
                    } else if run_len >= 2048 {
                        1024
                    } else {
                        512
                    }
                });
            #[cfg(not(feature = "std"))]
            let chunk_24_pixels: usize = if run_len >= 8192 {
                4096
            } else if run_len >= 2048 {
                1024
            } else {
                512
            };

            let mut processed = 0usize;
            while processed < run_len {
                let chunk = core::cmp::min(chunk_24_pixels, run_len - processed);
                let chunk_bytes = chunk * 3;
                let start = processed * 3;
                let end = start + chunk_bytes;
                if let Some(ref mut back) = self.back_buffer {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            self.scratch_u8.as_ptr().add(start),
                            (back.as_mut_ptr() as *mut u8).add(dst_byte_offset + start),
                            chunk_bytes,
                        );
                    }
                } else {
                    let addr = self.buffer as usize + dst_byte_offset + start;
                    self.write_bytes_mmio_streaming(addr, &self.scratch_u8[start..end]);
                }
                processed += chunk;
            }
            // Ensure streaming stores are globally visible after the full run
            if self.back_buffer.is_none() {
                // mmio::sfence(); // DEFERRED
                return true;
            }
        }
        false
    }

    /// ピクセルをブレンドして描画
    pub fn blend_pixel(&mut self, x: i32, y: i32, color: Color) {
        if color.alpha == 255 {
            self.set_pixel(x, y, color);
            return;
        }
        if color.alpha == 0 {
            return;
        }

        if let Some(ref _back) = self.back_buffer {
            if !self.clip.contains(Point::new(x, y)) {
                return;
            }
            // Use get_pixel to retrieve background color seamlessly from backbuffer (asserts checks etc)
            let bg = self.get_pixel(x as u32, y as u32);
            let result = color.blend(bg);
            self.set_pixel(x, y, result);
        } else {
            // Fallback for MMIO: just overwrite (no readback)
            self.set_pixel(x, y, color);
        }
    }

    /// 画像描画用のスキャンライン処理
    fn draw_image_scanline(
        &mut self,
        image: &super::image::Image,
        src_row: u32,
        dst_row: i32,
        row_start: u32,
        row_end: u32,
        x: i32,
        avx2_available: bool,
    ) -> bool {
        let mut mmio_written = false;
        // If backbuffer (u32) is active, we treat the destination as 32bpp (BGRA/RGBA)
        // regardless of the actual hardware format. Flush will handle conversion.
        let (bytes_per_pixel, stride) = if self.back_buffer.is_some() {
             (4, (self.info.width * 4) as u32)
        } else {
             (self.info.format.bytes_per_pixel(), self.info.stride)
        };
        
        let dst_row_offset = (dst_row as u32 * stride) as usize;
        let mut col = row_start;
        let img_ptr = image.data().as_ptr();

        while col < row_end {
            // Skip non-opaque pixels (alpha != 255) by falling back to per-pixel set_pixel
            while col < row_end {
                let idx = ((src_row * image.width() + col) * 4) as usize;
                let alpha = unsafe { *img_ptr.add(idx + 3) };
                if alpha == 255 {
                    break;
                }
                // fallback: preserve original semantic (write if alpha > 0)
                if alpha > 0 {
                    let c = image.get_pixel(col, src_row);
                    self.blend_pixel(x + col as i32, dst_row, c);
                }
                col += 1;
            }

            // Now col is at start of an opaque run (or at row_end)
            let run_start = col;
            while col < row_end {
                let idx = ((src_row * image.width() + col) * 4) as usize;
                let alpha = unsafe { *img_ptr.add(idx + 3) };
                if alpha != 255 {
                    break;
                }
                col += 1;
            }

            let run_len = (col - run_start) as usize;
            if run_len == 0 {
                continue;
            }

            // The absolute x-coordinate on the framebuffer for the start of this run.
            // `x` is the image's top-left x. `run_start` is the column relative to the image's x.
            let abs_x = (x + run_start as i32) as usize;
            let dst_byte_offset = dst_row_offset + abs_x * bytes_per_pixel;

            match bytes_per_pixel {
                4 => {
                     if self.write_opaque_run_32bit(
                        image,
                        src_row,
                        run_start,
                        run_len,
                        dst_byte_offset,
                        avx2_available,
                    ) {
                        mmio_written = true;
                    }
                }
                3 => {
                    if self.write_opaque_run_24bit(
                        image,
                        src_row,
                        run_start,
                        run_len,
                        dst_byte_offset,
                        x,
                        dst_row,
                        avx2_available,
                    ) {
                        mmio_written = true;
                    }
                }
                _ => {
                    // Fallback
                    for i in 0..run_len {
                        let c = image.get_pixel(run_start + i as u32, src_row);
                        self.set_pixel(x + (run_start as i32 + i as i32), dst_row, c);
                    }
                    if self.back_buffer.is_none() {
                        mmio_written = true;
                    }
                }
            }
        }
        mmio_written
    }

    /// helper: detect AVX2 availability (used by draw_image)
    fn get_avx2_available() -> bool {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        {
            #[cfg(feature = "std")]
            {
                std::is_x86_feature_detected!("avx2")
            }
            #[cfg(not(feature = "std"))]
            {
                hal::mmio::get_simd_level() >= hal::mmio::simd_level::AVX2
            }
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        {
            false
        }
    }

}
