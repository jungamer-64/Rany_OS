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

#[cfg(feature = "qemu-test-export")]
pub mod qemu_tests;

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
    fn write_bytes_align_to_8(ptr: &mut usize, data: &[u8], i: &mut usize, len: usize) {
        let align8 = *ptr & 7;
        if align8 != 0 {
            if align8 == 4 && *i + 4 <= len {
                #[cfg(target_endian = "little")]
                {
                    let v =
                        unsafe { core::ptr::read_unaligned(data.as_ptr().add(*i) as *const u32) };
                    mmio::mmio_write_u32(*ptr, v);
                }
                #[cfg(not(target_endian = "little"))]
                {
                    let v = u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
                    mmio::mmio_write_u32(*ptr, v);
                }
                *ptr += 4;
                *i += 4;
            } else {
                let to_align = core::cmp::min(8 - align8, len - *i);
                for _ in 0..to_align {
                    mmio::volatile_write::<u8>(*ptr, data[*i]);
                    *ptr += 1;
                    *i += 1;
                }
            }
        }
    }

    fn write_bytes_mmio(&self, addr: usize, data: &[u8]) {
        let mut ptr = addr;
        let mut i = 0usize;
        let len = data.len();

        Self::write_bytes_align_to_8(&mut ptr, data, &mut i, len);

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

    /// Emit a bench-debug log line for a streaming framebuffer write.
    #[cfg(all(feature = "std", feature = "bench"))]
    #[inline(always)]
    fn bench_debug_fb_stream_write(enabled: bool, ptr: usize, val: u64, is_u64: bool) {
        if enabled && crate::graphics::mmio::bench_debug_print_allowed() {
            if is_u64 {
                eprintln!("  stream_write_u64 at 0x{:x} val=0x{:x}", ptr, val);
            } else {
                eprintln!("  stream_write_u32 at 0x{:x} val=0x{:x}", ptr, val);
            }
        }
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
            Self::bench_debug_fb_stream_write(bench_debug_env, ptr, value as u64, false);
            mmio::stream_write_u32(ptr, value);
            ptr += 4;
            i += 1;
        }

        // Write u64 pairs (repeating value)
        let val64 = (value as u64) | ((value as u64) << 32);
        while i + 1 < count {
            #[cfg(all(feature = "std", feature = "bench"))]
            Self::bench_debug_fb_stream_write(bench_debug_env, ptr, val64, true);
            mmio::stream_write_u64(ptr, val64);
            ptr += 8;
            i += 2;
        }

        // Trailing u32
        if i < count {
            #[cfg(all(feature = "std", feature = "bench"))]
            Self::bench_debug_fb_stream_write(bench_debug_env, ptr, value as u64, false);
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

    #[inline(always)]
    fn color_to_rgb565(color: Color) -> u16 {
        let r = (color.red as u16 >> 3) & 0x1F;
        let g = (color.green as u16 >> 2) & 0x3F;
        let b = (color.blue as u16 >> 3) & 0x1F;
        (r << 11) | (g << 5) | b
    }

    /// Write a run of u16 pixels (RGB565) to MMIO using streaming u32 pairs when possible.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    fn write_u16_run_streaming_nofence(&self, addr: usize, count: usize, value: u16) {
        let mut ptr = addr;
        let mut remaining = count;

        // Align to 4-byte boundary.
        if (ptr & 3) == 2 && remaining > 0 {
            mmio::mmio_write_u16(ptr, value);
            ptr += 2;
            remaining -= 1;
        }

        let pair = (value as u32) | ((value as u32) << 16);
        while remaining >= 2 {
            mmio::stream_write_u32(ptr, pair);
            ptr += 4;
            remaining -= 2;
        }

        if remaining == 1 {
            mmio::mmio_write_u16(ptr, value);
        }
    }

    /// Non-x86 fallback for u16 run writer.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn write_u16_run_streaming_nofence(&self, addr: usize, count: usize, value: u16) {
        let mut ptr = addr;
        for _ in 0..count {
            mmio::mmio_write_u16(ptr, value);
            ptr += 2;
        }
    }

    /// u16 run writer with fence.
    fn write_u16_run_streaming(&self, addr: usize, count: usize, value: u16) {
        self.write_u16_run_streaming_nofence(addr, count, value);
        self.counted_sfence();
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
            self.write_u32_run_mmio(dst_offset_bytes, run_len_pixels, color_u32);
        }
    }

    /// MMIO path for write_u32_run: streaming stores for VRAM throughput
    fn write_u32_run_mmio(&mut self, dst_offset_bytes: usize, run_len_pixels: usize, color_u32: u32) {
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

    /// Determine the byte ordering for 24-bit pixel writes.
    fn bgr_color_order(&self, color: Color) -> (u8, u8, u8) {
        if matches!(self.info.format, PixelFormat::Bgr888) {
            (color.blue, color.green, color.red)
        } else {
            (color.red, color.green, color.blue)
        }
    }

    /// MMIO dispatch for write_bgr_run: handles small-direct, large-direct, and scratch paths.
    fn write_bgr_run_mmio(
        &mut self,
        dst_offset_bytes: usize,
        run_len_pixels: usize,
        total: usize,
        c0: u8,
        c1: u8,
        c2: u8,
    ) {
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

        #[inline]
        fn large_bgr_direct_threshold() -> usize {
            #[cfg(all(feature = "std", feature = "bench"))]
            {
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

        let addr = self.buffer as usize + dst_offset_bytes;

        if run_len_pixels <= small_bgr_direct_threshold() && addr != 0 {
            Self::write_bgr_small_direct_mmio(addr, run_len_pixels, c0, c1, c2);
            return;
        }

        if run_len_pixels >= large_bgr_direct_threshold() && addr != 0 {
            Self::write_bgr_large_direct_mmio(addr, run_len_pixels, c0, c1, c2);
            return;
        }

        if run_len_pixels > 0 {
            Self::fill_scratch_bgr_exponential(&mut self.scratch_u8, run_len_pixels, c0, c1, c2);
        }
        self.write_bytes_mmio(addr, &self.scratch_u8[..total]);
    }

    /// Write a run of 24-bit (3-byte) pixels with format-aware byte ordering.
    /// For Bgr888: [B,G,R], for Rgb888: [R,G,B]
    fn write_bgr_run(&mut self, dst_offset_bytes: usize, run_len_pixels: usize, color: Color) {
        let (c0, c1, c2) = self.bgr_color_order(color);

        if self.back_buffer.is_none() && self.buffer.is_null() {
            return;
        }

        let total = run_len_pixels * 3;
        self.ensure_scratch_u8(total);

        if self.back_buffer.is_some() {
            debug_assert!(false, "write_bgr_run called on 32bpp backbuffer");
            return;
        }

        self.write_bgr_run_mmio(dst_offset_bytes, run_len_pixels, total, c0, c1, c2);
    }

    /// Small-run fast-path: write BGR pixels directly via byte/u32 MMIO writes.
    /// Handles alignment and packs 4 pixels into 3 u32 words.
    fn write_bgr_small_direct_mmio(
        addr: usize,
        run_len_pixels: usize,
        c0: u8,
        c1: u8,
        c2: u8,
    ) {
        let u32_0 =
            (c0 as u32) | ((c1 as u32) << 8) | ((c2 as u32) << 16) | ((c0 as u32) << 24);
        let u32_1 =
            (c1 as u32) | ((c2 as u32) << 8) | ((c0 as u32) << 16) | ((c1 as u32) << 24);
        let u32_2 =
            (c2 as u32) | ((c0 as u32) << 8) | ((c1 as u32) << 16) | ((c2 as u32) << 24);

        let mut off = addr;
        let mut remaining = run_len_pixels;

        // Align to 4-byte boundary first (write individual bytes)
        let misalign = off & 3;
        if misalign != 0 && remaining > 0 {
            let k = core::cmp::min(misalign, remaining);
            for _ in 0..k {
                mmio::volatile_write::<u8>(off, c0);
                mmio::volatile_write::<u8>(off + 1, c1);
                mmio::volatile_write::<u8>(off + 2, c2);
                off += 3;
                remaining -= 1;
            }
            debug_assert!(
                remaining == 0 || (off & 3) == 0,
                "Alignment logic failed: off={}",
                off
            );
        }

        // Write 4-pixel groups using u32 × 3 (12 bytes = 4 pixels)
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
    }

    /// Large-run direct MMIO path: write BGR pixels using u64 streaming writes.
    /// Handles alignment, precomputes 8-byte patterns, and writes in 24-byte groups.
    fn write_bgr_large_direct_mmio(
        addr: usize,
        run_len_pixels: usize,
        c0: u8,
        c1: u8,
        c2: u8,
    ) {
        let mut addr = addr;
        let mut remaining = run_len_pixels * 3;
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

        // Precompute 8-byte patterns for each possible component starting index
        let mut patterns = [0u64; 3];
        for k in 0..3 {
            let mut patt = 0u64;
            for j in 0..8 {
                let byte = comps[(k + j) % 3] as u64;
                patt |= byte << (8 * j);
            }
            patterns[k] = patt;
        }

        // Write groups of 24 bytes (three 8-byte patterns)
        while remaining >= 24 {
            mmio::stream_write_u64(addr, patterns[comp_idx % 3]);
            mmio::stream_write_u64(addr + 8, patterns[(comp_idx + 8) % 3]);
            mmio::stream_write_u64(addr + 16, patterns[(comp_idx + 16) % 3]);
            addr += 24;
            remaining -= 24;
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
    }

    /// Exponential fill: write repeated BGR pixels into a scratch buffer.
    /// First pixel is written, then the filled region is doubled repeatedly.
    fn fill_scratch_bgr_exponential(
        scratch: &mut [u8],
        run_len_pixels: usize,
        c0: u8,
        c1: u8,
        c2: u8,
    ) {
        scratch[0] = c0;
        scratch[1] = c1;
        scratch[2] = c2;

        let mut filled = 1usize;
        while filled < run_len_pixels {
            let copy_pixels = core::cmp::min(filled, run_len_pixels - filled);
            let copy_bytes = copy_pixels * 3;
            let dst_offset = filled * 3;
            unsafe {
                ptr::copy(
                    scratch.as_ptr(),
                    scratch.as_mut_ptr().add(dst_offset),
                    copy_bytes,
                );
            }
            filled += copy_pixels;
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
    /// All slots full: find the pair of dirty rects whose merge adds the least area.
    fn find_best_merge_pair(rects: &[Option<Rect>; 4]) -> (usize, usize) {
        let mut min_added_area = u64::MAX;
        let mut merge_pair = (0, 1);
        for i in 0..4 {
            for j in (i + 1)..4 {
                if let (Some(a), Some(b)) = (&rects[i], &rects[j]) {
                    let area_a = a.width as u64 * a.height as u64;
                    let area_b = b.width as u64 * b.height as u64;
                    let combined = a.union(b);
                    let combined_area = combined.width as u64 * combined.height as u64;
                    let added_area = combined_area.saturating_sub(area_a + area_b);
                    if added_area < min_added_area {
                        min_added_area = added_area;
                        merge_pair = (i, j);
                    }
                }
            }
        }
        merge_pair
    }

    /// Try to merge rect with an existing dirty rect, or insert into an empty slot.
    /// Returns true if successfully placed.
    fn try_merge_or_insert_dirty(&mut self, draw_rect: Rect) -> bool {
        for slot in self.dirty_rects.iter_mut() {
            if let Some(existing) = slot {
                let merged = existing.union(&draw_rect);
                let existing_area = existing.width as u64 * existing.height as u64;
                let draw_area = draw_rect.width as u64 * draw_rect.height as u64;
                let merged_area = merged.width as u64 * merged.height as u64;

                if merged_area <= (existing_area + draw_area) * 3 / 2 {
                    *slot = Some(merged);
                    return true;
                }
            }
        }

        for slot in self.dirty_rects.iter_mut() {
            if slot.is_none() {
                *slot = Some(draw_rect);
                return true;
            }
        }

        false
    }

    fn mark_dirty(&mut self, rect: Rect) {
        // クリップ領域との共通部分をとる
        let draw_rect = match rect.intersection(&self.clip) {
            Some(r) => r,
            None => return,
        };

        if !draw_rect.is_valid() {
            return;
        }

        if self.try_merge_or_insert_dirty(draw_rect) {
            return;
        }

        // All slots full: force merge the two rects with smallest area INCREASE
        let (i, j) = Self::find_best_merge_pair(&self.dirty_rects);
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
    fn pack_bgra_u32_to_bgr24_row(src: &[u32], dst: &mut [u8]) {
        debug_assert!(dst.len() >= src.len() * 3);

        let mut si = 0usize;
        let mut di = 0usize;

        while si + 4 <= src.len() {
            let p0 = src[si];
            let p1 = src[si + 1];
            let p2 = src[si + 2];
            let p3 = src[si + 3];

            dst[di] = (p0 & 0xFF) as u8;
            dst[di + 1] = ((p0 >> 8) & 0xFF) as u8;
            dst[di + 2] = ((p0 >> 16) & 0xFF) as u8;

            dst[di + 3] = (p1 & 0xFF) as u8;
            dst[di + 4] = ((p1 >> 8) & 0xFF) as u8;
            dst[di + 5] = ((p1 >> 16) & 0xFF) as u8;

            dst[di + 6] = (p2 & 0xFF) as u8;
            dst[di + 7] = ((p2 >> 8) & 0xFF) as u8;
            dst[di + 8] = ((p2 >> 16) & 0xFF) as u8;

            dst[di + 9] = (p3 & 0xFF) as u8;
            dst[di + 10] = ((p3 >> 8) & 0xFF) as u8;
            dst[di + 11] = ((p3 >> 16) & 0xFF) as u8;

            si += 4;
            di += 12;
        }

        while si < src.len() {
            let p = src[si];
            dst[di] = (p & 0xFF) as u8;
            dst[di + 1] = ((p >> 8) & 0xFF) as u8;
            dst[di + 2] = ((p >> 16) & 0xFF) as u8;
            si += 1;
            di += 3;
        }
    }

    fn pack_bgra_u32_to_rgb24_row(src: &[u32], dst: &mut [u8]) {
        debug_assert!(dst.len() >= src.len() * 3);

        let mut si = 0usize;
        let mut di = 0usize;

        while si + 4 <= src.len() {
            let p0 = src[si];
            let p1 = src[si + 1];
            let p2 = src[si + 2];
            let p3 = src[si + 3];

            dst[di] = ((p0 >> 16) & 0xFF) as u8;
            dst[di + 1] = ((p0 >> 8) & 0xFF) as u8;
            dst[di + 2] = (p0 & 0xFF) as u8;

            dst[di + 3] = ((p1 >> 16) & 0xFF) as u8;
            dst[di + 4] = ((p1 >> 8) & 0xFF) as u8;
            dst[di + 5] = (p1 & 0xFF) as u8;

            dst[di + 6] = ((p2 >> 16) & 0xFF) as u8;
            dst[di + 7] = ((p2 >> 8) & 0xFF) as u8;
            dst[di + 8] = (p2 & 0xFF) as u8;

            dst[di + 9] = ((p3 >> 16) & 0xFF) as u8;
            dst[di + 10] = ((p3 >> 8) & 0xFF) as u8;
            dst[di + 11] = (p3 & 0xFF) as u8;

            si += 4;
            di += 12;
        }

        while si < src.len() {
            let p = src[si];
            dst[di] = ((p >> 16) & 0xFF) as u8;
            dst[di + 1] = ((p >> 8) & 0xFF) as u8;
            dst[di + 2] = (p & 0xFF) as u8;
            si += 1;
            di += 3;
        }
    }

    #[inline(always)]
    fn bgra_u32_to_rgb565(pixel: u32) -> u16 {
        let b = (pixel & 0xFF) as u16;
        let g = ((pixel >> 8) & 0xFF) as u16;
        let r = ((pixel >> 16) & 0xFF) as u16;
        ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
    }

    fn pack_bgra_u32_to_rgb565le_row(src: &[u32], dst: &mut [u8]) {
        debug_assert!(dst.len() >= src.len() * 2);

        let mut out_off = 0usize;
        let mut pairs = src.chunks_exact(2);
        for pair in &mut pairs {
            let p0 = Self::bgra_u32_to_rgb565(pair[0]) as u32;
            let p1 = Self::bgra_u32_to_rgb565(pair[1]) as u32;
            let packed = (p0 | (p1 << 16)).to_le();
            unsafe {
                ptr::write_unaligned(dst.as_mut_ptr().add(out_off) as *mut u32, packed);
            }
            out_off += 4;
        }

        if let Some(&last) = pairs.remainder().first() {
            let rgb565 = Self::bgra_u32_to_rgb565(last);
            dst[out_off] = (rgb565 & 0xFF) as u8;
            dst[out_off + 1] = (rgb565 >> 8) as u8;
        }
    }

    fn blit_rect_32bpp(&mut self, back_ptr: *const u32, x: usize, y: usize, w: usize, h: usize, stride_mmio: usize) {
        for row in 0..h {
            let src_y = y + row;
            let src_idx = src_y * self.info.width as usize + x;
            let src_slice = unsafe { core::slice::from_raw_parts(back_ptr.add(src_idx), w) };
            let dst_offset = (y + row) * stride_mmio + x * 4;
            let dst_addr = self.buffer as usize + dst_offset;
            self.write_u32_slice_mmio_streaming(dst_addr, src_slice);
        }
    }

    fn blit_rect_24bpp(&mut self, back_ptr: *const u32, x: usize, y: usize, w: usize, h: usize, stride_mmio: usize) {
        let row_bytes = w * 3;
        self.ensure_scratch_u8(row_bytes);
        let is_bgr_24 = matches!(self.info.format, PixelFormat::Bgr888);
        for row in 0..h {
            let src_y = y + row;
            let src_idx = src_y * self.info.width as usize + x;
            let src_slice = unsafe { core::slice::from_raw_parts(back_ptr.add(src_idx), w) };
            let dst_offset = (y + row) * stride_mmio + x * 3;
            let dst_addr = self.buffer as usize + dst_offset;
            if is_bgr_24 {
                Self::pack_bgra_u32_to_bgr24_row(src_slice, &mut self.scratch_u8[..row_bytes]);
            } else {
                Self::pack_bgra_u32_to_rgb24_row(src_slice, &mut self.scratch_u8[..row_bytes]);
            }
            self.write_bytes_mmio_streaming(dst_addr, &self.scratch_u8[..row_bytes]);
        }
    }

    fn blit_rect_16bpp(&mut self, back_ptr: *const u32, x: usize, y: usize, w: usize, h: usize, stride_mmio: usize) {
        let row_bytes = w * 2;
        self.ensure_scratch_u8(row_bytes);
        for row in 0..h {
            let src_y = y + row;
            let src_idx = src_y * self.info.width as usize + x;
            let src_slice = unsafe { core::slice::from_raw_parts(back_ptr.add(src_idx), w) };
            let dst_offset = (y + row) * stride_mmio + x * 2;
            let dst_addr = self.buffer as usize + dst_offset;
            Self::pack_bgra_u32_to_rgb565le_row(src_slice, &mut self.scratch_u8[..row_bytes]);
            self.write_bytes_mmio_streaming(dst_addr, &self.scratch_u8[..row_bytes]);
        }
    }

    pub fn blit_rect(&mut self, rect: Rect) {
        let back_ptr = match self.back_buffer.as_ref() {
            Some(back) => back.as_ptr(),
            None => return,
        };

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

        match bytes_per_pixel {
            4 => self.blit_rect_32bpp(back_ptr, x, y, w, h, stride_mmio),
            3 => self.blit_rect_24bpp(back_ptr, x, y, w, h, stride_mmio),
            2 => self.blit_rect_16bpp(back_ptr, x, y, w, h, stride_mmio),
            _ => return,
        }
        mmio::sfence();
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
             back.fill(color.to_u32());
             let rect = Rect::new(0, 0, self.info.width, self.info.height);
             self.mark_dirty(rect);
             return;
        }
        self.mark_dirty(Rect::new(0, 0, self.info.width, self.info.height));
        let draw_buf = self.draw_buffer();
        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => self.clear_32bpp(draw_buf, color),
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => self.clear_24bpp(color),
            PixelFormat::Rgb565 => self.clear_rgb565(color),
        }
    }

    /// Clear screen with 32-bit pixel format (Bgra8888 / Rgba8888).
    fn clear_32bpp(&mut self, _draw_buf: *mut u8, color: Color) {
        // Note: backbuffer case is handled by clear() early-return, this is MMIO-only.
        let width = self.info.width as usize;
        let stride = self.info.stride as usize;
        let color_u32 = color.to_u32();
        for y in 0..self.info.height as usize {
            let offset = y * stride;
            let addr = self.buffer as usize + offset;
            self.write_u32_run_streaming_nofence(addr, width, color_u32);
        }
        mmio::sfence();
    }

    /// Fill the scratch buffer with one 24bpp row of the given colour.
    fn fill_scratch_row_24bpp(&mut self, color: Color, width: usize) {
        let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);
        let row_bytes = width * 3;
        self.ensure_scratch_u8(row_bytes);
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
        let mut filled = 1usize;
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
    }

    /// Clear screen with 24-bit pixel format (Bgr888 / Rgb888).
    fn clear_24bpp(&mut self, color: Color) {
        let width = self.info.width as usize;
        let stride = self.info.stride as usize;
        let row_bytes = width * 3;
        self.fill_scratch_row_24bpp(color, width);
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

    /// Clear screen with 16-bit pixel format (Rgb565).
    fn clear_rgb565(&mut self, color: Color) {
        let width = self.info.width as usize;
        let stride = self.info.stride as usize;
        let pixel = Self::color_to_rgb565(color);

        if let Some(ref mut _back) = self.back_buffer {
            // Backbuffer is always u32/BGRA in this implementation.
            debug_assert!(false, "clear_rgb565 called with u32 backbuffer");
        } else {
            for y in 0..self.info.height as usize {
                let offset = y * stride;
                let addr = self.buffer as usize + offset;
                self.write_u16_run_streaming_nofence(addr, width, pixel);
            }
            mmio::sfence();
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
                let pixel = Self::color_to_rgb565(color);
                if let Some(_) = self.back_buffer {
                    debug_assert!(false, "16bpp hline called on u32 backbuffer");
                } else {
                    let addr = self.draw_buffer() as usize + offset;
                    self.write_u16_run_streaming(addr, run_len, pixel);
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

    /// 4bpp垂直線描画ヘルパー
    fn draw_vline_4bpp(&mut self, x_off: usize, start_y: usize, run_len: usize, stride: usize, color: Color) {
        let color_u32 = color.to_u32();
        let mut off = start_y * stride + x_off * 4;
        if self.back_buffer.is_some() {
            let base = self.draw_buffer();
            for i in 0..run_len {
                unsafe {
                    ptr::write(base.add(off) as *mut u32, color_u32);
                }
                if i + 1 < run_len {
                    off += stride;
                }
            }
        } else {
            let base_addr = self.draw_buffer() as usize;
            for i in 0..run_len {
                mmio::mmio_write_u32(base_addr + off, color_u32);
                if i + 1 < run_len {
                    off += stride;
                }
            }
            if run_len > 0 {
                mmio::sfence();
            }
        }
    }

    /// 3bpp垂直線描画ヘルパー
    fn draw_vline_3bpp(&mut self, x_off: usize, start_y: usize, run_len: usize, stride: usize, color: Color) {
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
            let mut off = base_addr + start_y * stride + x_off * 3;
            for i in 0..run_len {
                mmio::volatile_write(off, c0);
                mmio::volatile_write(off + 1, c1);
                mmio::volatile_write(off + 2, c2);
                if i + 1 < run_len {
                    off += stride;
                }
            }
            if run_len > 0 {
                mmio::sfence();
            }
        }
    }

    /// 2bpp垂直線描画ヘルパー
    fn draw_vline_2bpp(&mut self, x_off: usize, start_y: usize, run_len: usize, stride: usize, color: Color) {
        let pixel = Self::color_to_rgb565(color);
        if let Some(ref mut _back) = self.back_buffer {
            debug_assert!(false, "16bpp vline called on u32 backbuffer");
        } else {
            let base_addr = self.draw_buffer() as usize;
            let mut off = base_addr + start_y * stride + x_off * 2;
            for i in 0..run_len {
                mmio::mmio_write_u16(off, pixel);
                if i + 1 < run_len {
                    off += stride;
                }
            }
            if run_len > 0 {
                mmio::sfence();
            }
        }
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
            4 => self.draw_vline_4bpp(x_off, start_y as usize, run_len, stride, color),
            3 => self.draw_vline_3bpp(x_off, start_y as usize, run_len, stride, color),
            2 => self.draw_vline_2bpp(x_off, start_y as usize, run_len, stride, color),
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
        self.mark_dirty(Rect::new(min_x, min_y, (max_x - min_x + 1) as u32, (max_y - min_y + 1) as u32));

        let abs_dx = (x2 - x1).abs();
        let abs_dy = (y2 - y1).abs();

        if abs_dx < abs_dy {
            self.draw_line_steep(x1, y1, x2, y2, color);
        } else {
            self.draw_line_shallow(x1, y1, x2, y2, color);
        }
    }

    /// Steep Bresenham: coalesce vertical runs (|dy| > |dx|).
    fn draw_line_steep(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        let dx = (x2 - x1).abs();
        let dy = -(y2 - y1).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;
        let mut x = x1;
        let mut y = y1;

        // Track current vertical run for coalescing
        let mut run_x = x;
        let mut run_start = y;
        let mut run_end = y;

        loop {
            if x == x2 && y == y2 {
                self.flush_steep_run(run_x, run_start, run_end, color);
                return;
            }

            let mut next_x = x;
            let mut next_y = y;
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                next_x += sx;
            }
            if e2 <= dx {
                err += dx;
                next_y += sy;
            }

            if next_x == run_x {
                // Same column — extend current vertical run
                run_end = next_y;
            } else {
                // Column changed — flush current run and start new one
                self.flush_steep_run(run_x, run_start, run_end, color);
                run_x = next_x;
                run_start = next_y;
                run_end = next_y;
            }
            x = next_x;
            y = next_y;
        }
    }

    /// Flush one vertical run collected by steep Bresenham.
    #[inline]
    fn flush_steep_run(&mut self, run_x: i32, run_start: i32, run_end: i32, color: Color) {
        if run_x < self.clip.x || run_x >= self.clip.right() {
            return;
        }

        let mut start = run_start.min(run_end);
        let mut end = run_start.max(run_end);
        start = start.max(self.clip.y);
        end = end.min(self.clip.bottom() - 1);

        if start <= end {
            self.draw_vline_raw(run_x, start, end, color);
        }
    }

    /// Flush one horizontal run collected by shallow Bresenham.
    #[inline]
    fn flush_shallow_run(&mut self, run_y: i32, run_start: i32, run_end: i32, color: Color) {
        if run_y < self.clip.y || run_y >= self.clip.bottom() {
            return;
        }

        let mut start = run_start.min(run_end);
        let mut end = run_start.max(run_end);
        start = start.max(self.clip.x);
        end = end.min(self.clip.right() - 1);

        if start <= end {
            self.draw_hline_raw(start, end, run_y, color);
        }
    }

    /// Shallow Bresenham: coalesce horizontal runs (|dx| >= |dy|).
    fn draw_line_shallow(&mut self, x1: i32, y1: i32, x2: i32, y2: i32, color: Color) {
        let dx = (x2 - x1).abs();
        let dy = -(y2 - y1).abs();
        let sx = if x1 < x2 { 1 } else { -1 };
        let sy = if y1 < y2 { 1 } else { -1 };
        let mut err = dx + dy;
        let mut x = x1;
        let mut y = y1;

        let mut run_y = y;
        let mut run_start = x;
        let mut run_end = x;

        loop {
            if x == x2 && y == y2 {
                self.flush_shallow_run(run_y, run_start, run_end, color);
                return;
            }

            // Compute next Bresenham point first, then decide whether it
            // belongs to the current horizontal run or starts a new row run.
            let mut next_x = x;
            let mut next_y = y;
            let e2 = 2 * err;
            if e2 >= dy {
                err += dy;
                next_x += sx;
            }
            if e2 <= dx {
                err += dx;
                next_y += sy;
            }

            if next_y == run_y {
                run_end = next_x;
            } else {
                self.flush_shallow_run(run_y, run_start, run_end, color);
                run_y = next_y;
                run_start = next_x;
                run_end = next_x;
            }

            x = next_x;
            y = next_y;
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
        if rect.width == 0 || rect.height == 0 {
            return;
        }
        // Pre-mark entire bounding box dirty once instead of 4 separate mark_dirty calls
        self.mark_dirty(rect);

        let x0 = rect.x;
        let x1 = rect.right() - 1;
        let y0 = rect.y;
        let y1 = rect.bottom() - 1;

        // Clip and use raw variants (skip per-call mark_dirty)
        // Top hline
        if y0 >= self.clip.y && y0 < self.clip.bottom() {
            let s = x0.max(self.clip.x);
            let e = x1.min(self.clip.right() - 1);
            if s <= e { self.draw_hline_raw(s, e, y0, color); }
        }
        // Bottom hline
        if y1 >= self.clip.y && y1 < self.clip.bottom() && y1 != y0 {
            let s = x0.max(self.clip.x);
            let e = x1.min(self.clip.right() - 1);
            if s <= e { self.draw_hline_raw(s, e, y1, color); }
        }
        // Left vline (exclude corners already drawn by hlines)
        if x0 >= self.clip.x && x0 < self.clip.right() {
            let vs = (y0 + 1).max(self.clip.y);
            let ve = (y1 - 1).min(self.clip.bottom() - 1);
            if vs <= ve { self.draw_vline_raw(x0, vs, ve, color); }
        }
        // Right vline (exclude corners)
        if x1 >= self.clip.x && x1 < self.clip.right() && x1 != x0 {
            let vs = (y0 + 1).max(self.clip.y);
            let ve = (y1 - 1).min(self.clip.bottom() - 1);
            if vs <= ve { self.draw_vline_raw(x1, vs, ve, color); }
        }
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

        // Fast path: backbuffer is tightly packed u32 pixels.
        // Use slice-level copy_within (memmove semantics) per row.
        if let Some(ref mut back) = self.back_buffer {
            let row_pixels = self.info.width as usize;
            let copy_pixels = s.width as usize;
            if d_y > s.y {
                for i in (0..s.height as usize).rev() {
                    let src_row_y = s.y as usize + i;
                    let dst_row_y = d_y as usize + i;
                    let src_start = src_row_y * row_pixels + s.x as usize;
                    let dst_start = dst_row_y * row_pixels + d_x as usize;
                    back.copy_within(src_start..src_start + copy_pixels, dst_start);
                }
            } else {
                for i in 0..s.height as usize {
                    let src_row_y = s.y as usize + i;
                    let dst_row_y = d_y as usize + i;
                    let src_start = src_row_y * row_pixels + s.x as usize;
                    let dst_start = dst_row_y * row_pixels + d_x as usize;
                    back.copy_within(src_start..src_start + copy_pixels, dst_start);
                }
            }
            return;
        }

        let buffer = self.draw_buffer();
        let (stride, bpp) = (self.info.stride as usize, self.info.format.bytes_per_pixel());
        let copy_bytes = s.width as usize * bpp;
        // When source and destination rows are different, row slices do not overlap
        // in the normal framebuffer layout (stride >= row bytes). In that case we
        // can use copy_nonoverlapping for a slightly faster path.
        let use_nonoverlap_rows = d_y != s.y && copy_bytes <= stride;

        unsafe {
            if d_y > s.y {
                // 下方向へのコピー（後ろから）
                for i in (0..s.height).rev() {
                    let src_row_y = s.y + i as i32;
                    let dst_row_y = d_y + i as i32;

                    let src_offset = (src_row_y as usize * stride) + (s.x as usize * bpp);
                    let dst_offset = (dst_row_y as usize * stride) + (d_x as usize * bpp);

                    let src_ptr = buffer.add(src_offset);
                    let dst_ptr = buffer.add(dst_offset);
                    if use_nonoverlap_rows {
                        ptr::copy_nonoverlapping(src_ptr, dst_ptr, copy_bytes);
                    } else {
                        ptr::copy(src_ptr, dst_ptr, copy_bytes);
                    }
                }
            } else {
                // 上方向へのコピー（前から）
                for i in 0..s.height {
                    let src_row_y = s.y + i as i32;
                    let dst_row_y = d_y + i as i32;

                    let src_offset = (src_row_y as usize * stride) + (s.x as usize * bpp);
                    let dst_offset = (dst_row_y as usize * stride) + (d_x as usize * bpp);

                    let src_ptr = buffer.add(src_offset);
                    let dst_ptr = buffer.add(dst_offset);
                    if use_nonoverlap_rows {
                        ptr::copy_nonoverlapping(src_ptr, dst_ptr, copy_bytes);
                    } else {
                        ptr::copy(src_ptr, dst_ptr, copy_bytes);
                    }
                }
            }
            // Ensure writes to WC-mapped VRAM are globally visible
            mmio::sfence();
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
        let (s_x, s_y, s_w, s_h) = Self::clip_src_to_image(&src_rect, image);
        if s_w == 0 || s_h == 0 {
            return;
        }

        let clip_result = self.clip_dst_to_screen(s_x, s_y, s_w, s_h, dst_x, dst_y);
        let (d_x, d_y, r_x, r_y, r_w, r_h) = match clip_result {
            Some(v) => v,
            None => return,
        };

        if r_w == 0 || r_h == 0 {
            return;
        }

        // Mark dirty
        self.mark_dirty(Rect::new(d_x, d_y, r_w, r_h));

        // Perform blit
        self.blit_image_rows(image, d_x, d_y, r_x, r_y, r_w, r_h);
    }

    fn clip_src_to_image(src_rect: &Rect, image: &crate::graphics::image::Image) -> (i32, i32, u32, u32) {
        let s_x = src_rect.x.max(0);
        let s_y = src_rect.y.max(0);
        let s_w = (src_rect.width as i32).min(image.width() as i32 - s_x).max(0) as u32;
        let s_h = (src_rect.height as i32).min(image.height() as i32 - s_y).max(0) as u32;
        (s_x, s_y, s_w, s_h)
    }

    fn clip_dst_to_screen(
        &self, s_x: i32, s_y: i32, s_w: u32, s_h: u32, dst_x: i32, dst_y: i32,
    ) -> Option<(i32, i32, i32, i32, u32, u32)> {
        let mut d_x = dst_x;
        let mut d_y = dst_y;
        let mut r_x = s_x;
        let mut r_y = s_y;
        let mut r_w = s_w;
        let mut r_h = s_h;

        // Left clip
        if d_x < self.clip.x {
            let diff = self.clip.x - d_x;
            if diff >= r_w as i32 { return None; }
            d_x += diff;
            r_x += diff;
            r_w -= diff as u32;
        }
        // Top clip
        if d_y < self.clip.y {
            let diff = self.clip.y - d_y;
            if diff >= r_h as i32 { return None; }
            d_y += diff;
            r_y += diff;
            r_h -= diff as u32;
        }
        // Right clip
        let over_x = (d_x + r_w as i32) - self.clip.right();
        if over_x > 0 {
            if over_x >= r_w as i32 { return None; }
            r_w -= over_x as u32;
        }
        // Bottom clip
        let over_y = (d_y + r_h as i32) - self.clip.bottom();
        if over_y > 0 {
            if over_y >= r_h as i32 { return None; }
            r_h -= over_y as u32;
        }

        Some((d_x, d_y, r_x, r_y, r_w, r_h))
    }

    fn blit_image_rows(
        &mut self,
        image: &crate::graphics::image::Image,
        d_x: i32, d_y: i32,
        r_x: i32, r_y: i32,
        r_w: u32, r_h: u32,
    ) {
        let src_stride = image.width() * 4;
        let src_data = image.data();
        let dst_stride = if self.back_buffer.is_some() { self.info.width * 4 } else { self.info.stride } as usize;
        let dst_bpp = if self.back_buffer.is_some() { 4 } else { self.info.format.bytes_per_pixel() } as usize;

        let buf_ptr = self.draw_buffer();

        let needs_swizzle = match (self.back_buffer.is_some(), self.info.format) {
             (true, _) => true,
             (false, PixelFormat::Bgra8888 | PixelFormat::Bgr888) => true,
             _ => false,
        };

        for i in 0..r_h {
            let src_row_offset = ((r_y as u32 + i as u32) * src_stride + (r_x as u32 * 4)) as usize;
            let dst_row_offset = (d_y as usize + i as usize) * dst_stride + (d_x as usize * dst_bpp as usize);
            
            let src_row = &src_data[src_row_offset .. src_row_offset + (r_w as usize * 4)];
            
            unsafe {
                let dst_ptr = buf_ptr.add(dst_row_offset);
                
                if self.back_buffer.is_some() {
                   let dst_slice = core::slice::from_raw_parts_mut(dst_ptr, r_w as usize * 4);
                   crate::graphics::packer::pack_rgba_to_bgra(src_row, dst_slice);
                } else {
                   self.blit_mmio_row(dst_ptr, src_row, r_w, dst_bpp, needs_swizzle, i == r_h - 1);
                }
            }
        }
    }

    unsafe fn blit_mmio_row(
        &mut self,
        dst_ptr: *mut u8,
        src_row: &[u8],
        r_w: u32,
        dst_bpp: usize,
        needs_swizzle: bool,
        is_last_row: bool,
    ) {
        match dst_bpp {
            4 => {
                if needs_swizzle {
                    let dst_slice = unsafe {
                        core::slice::from_raw_parts_mut(dst_ptr, r_w as usize * 4)
                    };
                    crate::graphics::packer::pack_rgba_to_bgra(src_row, dst_slice);
                } else {
                    self.write_bytes_mmio_streaming(dst_ptr as usize, src_row);
                }
            }
            3 => {
                let dst_slice = unsafe {
                    core::slice::from_raw_parts_mut(dst_ptr, r_w as usize * 3)
                };
                crate::graphics::packer::pack_rgba_to_bgr24(src_row, dst_slice, needs_swizzle);
            }
            2 => {
                // RGB565 direct path: convert RGBA pixels to RGB565 and stream-write
                let pixel_count = r_w as usize;
                self.ensure_scratch_u8(pixel_count * 2);
                let src_pixels = unsafe {
                    core::slice::from_raw_parts(src_row.as_ptr() as *const u32, pixel_count)
                };
                // Convert RGBA u32 -> RGB565 u16 into scratch buffer
                {
                    let dst_u16 = unsafe {
                        core::slice::from_raw_parts_mut(
                            self.scratch_u8.as_mut_ptr() as *mut u16,
                            pixel_count,
                        )
                    };
                    for (i, &rgba) in src_pixels.iter().enumerate() {
                        let r = (rgba & 0xFF) as u16;
                        let g = ((rgba >> 8) & 0xFF) as u16;
                        let b = ((rgba >> 16) & 0xFF) as u16;
                        dst_u16[i] = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
                    }
                }
                let addr = dst_ptr as usize;
                self.write_bytes_mmio_streaming(addr, &self.scratch_u8[..pixel_count * 2]);
            }
            _ => {}
        }
        if is_last_row {
            mmio::sfence();
        }
    }
    /// Clip a rectangle to the framebuffer clip region.
    /// Returns `None` if the rectangle is fully clipped away.
    fn clip_intersection(&self, rect: Rect) -> Option<Rect> {
        let mut r = rect;
        r.x = r.x.max(self.clip.x);
        r.y = r.y.max(self.clip.y);
        let right = r.right().min(self.clip.right());
        let bottom = r.bottom().min(self.clip.bottom());
        r.width = (right - r.x).max(0) as u32;
        r.height = (bottom - r.y).max(0) as u32;
        if r.width == 0 || r.height == 0 { None } else { Some(r) }
    }

    /// Fill a clipped rectangle into the u32 backbuffer.
    fn fill_rect_backbuffer(&mut self, r: Rect, color: Color) {
        if let Some(ref mut back) = self.back_buffer {
            let val = color.to_u32();
            let fb_width = self.info.width as usize;

            // Fast path: full-width span is contiguous in backbuffer.
            if r.x == 0 && r.width as usize == fb_width {
                let start = r.y as usize * fb_width;
                let len = r.height as usize * fb_width;
                back[start..start + len].fill(val);
                return;
            }

            let w = r.width as usize;
            for y in r.y..r.bottom() {
                let idx = (y as usize * fb_width) + r.x as usize;
                back[idx..idx + w].fill(val);
            }
        }
    }

    /// 32bpp MMIO streaming fill (Bgra8888 / Rgba8888).
    fn fill_rect_32bpp_mmio(&mut self, r: Rect, color_u32: u32) {
        let stride = self.info.stride as usize;
        for y in r.y..r.bottom() {
            let offset = (y as usize * stride) + (r.x as usize * 4);
            let addr = self.buffer as usize + offset;
            self.write_u32_run_streaming_nofence(addr, r.width as usize, color_u32);
        }
        mmio::sfence();
    }

    /// 24bpp MMIO streaming fill (Bgr888 / Rgb888).
    fn fill_rect_24bpp_mmio(&mut self, r: Rect, color: Color) {
        let width = r.width as usize;
        let row_bytes = width * 3;
        if row_bytes == 0 {
            return;
        }

        let is_bgr = matches!(self.info.format, PixelFormat::Bgr888);
        let (c0, c1, c2) = if is_bgr {
            (color.blue, color.green, color.red)
        } else {
            (color.red, color.green, color.blue)
        };

        self.ensure_scratch_u8(row_bytes);
        if width > 0 {
            Self::fill_scratch_bgr_exponential(&mut self.scratch_u8, width, c0, c1, c2);
        }

        let stride = self.info.stride as usize;
        for y in r.y..r.bottom() {
            let offset = y as usize * stride + r.x as usize * 3;
            let addr = self.buffer as usize + offset;
            self.write_bytes_mmio_streaming(addr, &self.scratch_u8[..row_bytes]);
        }
        mmio::sfence();
    }

    /// 16bpp MMIO streaming fill (Rgb565).
    fn fill_rect_16bpp_mmio(&mut self, r: Rect, color: Color) {
        let stride = self.info.stride as usize;
        let pixel = Self::color_to_rgb565(color);
        let width = r.width as usize;

        for y in r.y..r.bottom() {
            let offset = y as usize * stride + r.x as usize * 2;
            let addr = self.buffer as usize + offset;
            self.write_u16_run_streaming_nofence(addr, width, pixel);
        }
        mmio::sfence();
    }

    /// Per-pixel fallback fill for other pixel formats.
    fn fill_rect_pixel_fallback(&mut self, r: Rect, color: Color) {
        for y in r.y..r.bottom() {
            for x in r.x..r.right() {
                self.set_pixel_raw(x, y, color);
            }
        }
    }

    pub fn fill_rect(&mut self, rect: Rect, color: Color) {
        let r = match self.clip_intersection(rect) {
            Some(r) => r,
            None => return,
        };

        if self.back_buffer.is_none() && self.buffer.is_null() {
            return;
        }

        self.stats.rectangles_drawn += 1;
        self.stats.pixels_drawn += (r.width * r.height) as usize;

        // Mark dirty
        self.mark_dirty(r);

        let _buffer = self.draw_buffer();

        #[cfg(feature = "std")]
        if std::env::var("RANY_DEBUG_DRAW").ok().as_deref() == Some("1") {
            eprintln!(
                "fill_rect start: back_present={} buffer_ptr=0x{:x} info_size={} stride={} rect={:?}",
                self.back_buffer.is_some(),
                self.buffer as usize,
                self.info.size(),
                self.info.stride,
                r
            );
        }

        if self.back_buffer.is_some() {
            self.fill_rect_backbuffer(r, color);
            return;
        }

        match self.info.format {
            PixelFormat::Bgra8888 | PixelFormat::Rgba8888 => {
                self.fill_rect_32bpp_mmio(r, color.to_u32());
            }
            PixelFormat::Bgr888 | PixelFormat::Rgb888 => {
                self.fill_rect_24bpp_mmio(r, color);
            }
            PixelFormat::Rgb565 => {
                self.fill_rect_16bpp_mmio(r, color);
            }
            _ => {
                self.fill_rect_pixel_fallback(r, color);
            }
        }
    }

    /// 円を描画（Midpointアルゴリズム）
    pub fn draw_circle(&mut self, cx: i32, cy: i32, radius: i32, color: Color) {
        if radius <= 0 {
            self.set_pixel(cx, cy, color);
            return;
        }
        // Pre-mark bounding box dirty once instead of per-pixel
        self.mark_dirty(Rect::new(
            cx - radius, cy - radius,
            (radius * 2 + 1) as u32, (radius * 2 + 1) as u32,
        ));
        let mut x = radius;
        let mut y = 0;
        let mut err = 0;

        while x >= y {
            // Use set_pixel_raw (skip per-pixel dirty mark + clip re-check)
            // Only draw if within clip bounds
            let pts = [
                (cx + x, cy + y), (cx + y, cy + x),
                (cx - y, cy + x), (cx - x, cy + y),
                (cx - x, cy - y), (cx - y, cy - x),
                (cx + y, cy - x), (cx + x, cy - y),
            ];
            for &(px, py) in &pts {
                if self.clip_contains_point(px, py) {
                    self.set_pixel_raw(px, py, color);
                }
            }

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
        if radius <= 0 {
            self.set_pixel(cx, cy, color);
            return;
        }
        // Pre-mark bounding box dirty once
        self.mark_dirty(Rect::new(
            cx - radius, cy - radius,
            (radius * 2 + 1) as u32, (radius * 2 + 1) as u32,
        ));

        let mut x = radius;
        let mut y = 0;
        let mut err = 0;
        // Track last drawn y-coordinates to eliminate duplicate hlines
        let mut last_y1: i32 = i32::MIN;
        let mut last_y2: i32 = i32::MIN;
        let mut last_y3: i32 = i32::MIN;
        let mut last_y4: i32 = i32::MIN;

        while x >= y {
            // Use draw_hline_raw (skip per-hline dirty mark — already pre-marked)
            let rows = [
                (cx - x, cx + x, cy + y),
                (cx - y, cx + y, cy + x),
                (cx - x, cx + x, cy - y),
                (cx - y, cx + y, cy - x),
            ];
            let last = [&mut last_y1, &mut last_y2, &mut last_y3, &mut last_y4];
            for (i, &(x0, x1, ry)) in rows.iter().enumerate() {
                if ry != *last[i] {
                    *last[i] = ry;
                    // Clip and draw raw
                    let sy = ry;
                    if sy >= self.clip.y && sy < self.clip.bottom() {
                        let start = x0.max(self.clip.x);
                        let end = x1.min(self.clip.right() - 1);
                        if start <= end {
                            self.draw_hline_raw(start, end, sy, color);
                        }
                    }
                }
            }

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

    // ─── Shared pixel-run helpers ───────────────────────────────────────────

    /// Check if a point is inside the clip rectangle.
    #[inline]
    fn clip_contains_point(&self, x: i32, y: i32) -> bool {
        x >= self.clip.x && x < self.clip.right() && y >= self.clip.y && y < self.clip.bottom()
    }

    /// Check if a rectangle is fully contained in the clip rectangle.
    #[inline]
    fn clip_contains_rect(&self, x: i32, y: i32, w: i32, h: i32) -> bool {
        x >= self.clip.x && (x + w) <= self.clip.right() && y >= self.clip.y && (y + h) <= self.clip.bottom()
    }

    /// Check if a Y coordinate is within the clip vertical range.
    #[inline]
    fn clip_y_visible(&self, y: i32) -> bool {
        y >= self.clip.y && y < self.clip.bottom()
    }

    /// Find a run of ON bits in `byte` starting from `col`, bounded by `max_bits`.
    /// Returns `(run_start, run_len, new_col)`.
    #[inline]
    fn next_on_run(byte: u8, mut col: usize, max_bits: usize) -> (usize, usize, usize) {
        // Skip OFF pixels
        while col < max_bits {
            if (byte >> (7 - col)) & 1 != 0 {
                break;
            }
            col += 1;
        }
        let run_start = col;
        // Count ON pixels
        while col < max_bits {
            if (byte >> (7 - col)) & 1 == 0 {
                break;
            }
            col += 1;
        }
        (run_start, col - run_start, col)
    }

    /// Find a run of ON bits with extra width bound: `(byte_idx * 8 + col) < width`.
    #[inline]
    fn next_on_run_bounded(byte: u8, mut col: usize, byte_idx: usize, width: usize) -> (usize, usize, usize) {
        while col < 8 && (byte_idx * 8 + col) < width {
            if (byte >> (7 - col)) & 1 != 0 {
                break;
            }
            col += 1;
        }
        let run_start = col;
        while col < 8 && (byte_idx * 8 + col) < width {
            if (byte >> (7 - col)) & 1 == 0 {
                break;
            }
            col += 1;
        }
        (run_start, col - run_start, col)
    }

    /// Write a clipped run of foreground pixels at 24bpp using `write_bgr_run`.
    fn write_clipped_bgr_run(
        &mut self,
        dst_x: i32,
        run_len: usize,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) {
        let dst_start_x = dst_x.max(self.clip.x);
        let dst_end_x = (dst_x + run_len as i32 - 1).min(self.clip.right() - 1);
        if dst_end_x >= dst_start_x {
            let clipped_len = (dst_end_x - dst_start_x + 1) as usize;
            let start_offset = (dst_y as usize * stride) + (dst_start_x as usize * 3);
            self.write_bgr_run(start_offset, clipped_len, color);
        }
    }

    /// Write a clipped run of foreground pixels at 16bpp (RGB565) using MMIO streaming.
    fn write_clipped_rgb565_run_nofence(
        &mut self,
        dst_x: i32,
        run_len: usize,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) -> bool {
        let dst_start_x = dst_x.max(self.clip.x);
        let dst_end_x = (dst_x + run_len as i32 - 1).min(self.clip.right() - 1);
        if dst_end_x < dst_start_x {
            return false;
        }

        let clipped_len = (dst_end_x - dst_start_x + 1) as usize;
        let start_offset = (dst_y as usize * stride) + (dst_start_x as usize * 2);
        let pixel = Self::color_to_rgb565(color);

        if self.back_buffer.is_some() {
            debug_assert!(false, "16bpp draw called on u32 backbuffer");
            false
        } else {
            let addr = self.buffer as usize + start_offset;
            self.write_u16_run_streaming_nofence(addr, clipped_len, pixel);
            true
        }
    }

    fn write_clipped_rgb565_run(
        &mut self,
        dst_x: i32,
        run_len: usize,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) {
        if self.write_clipped_rgb565_run_nofence(dst_x, run_len, dst_y, stride, color) {
            self.counted_sfence();
        }
    }

    /// Process one byte of glyph data at 24bpp, writing clipped runs.
    fn glyph_byte_runs_24bpp(
        &mut self,
        byte: u8,
        byte_idx: usize,
        width: u32,
        px_start: i32,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) {
        let mut col = 0usize;
        while col < 8 && (byte_idx * 8 + col) < width as usize {
            let (run_start, run_len, new_col) =
                Self::next_on_run_bounded(byte, col, byte_idx, width as usize);
            col = new_col;
            if run_len == 0 {
                continue;
            }
            let dst_x = px_start + run_start as i32;
            self.write_clipped_bgr_run(dst_x, run_len, dst_y, stride, color);
        }
    }

    /// Process one byte of glyph data at 16bpp, writing clipped runs.
    fn glyph_byte_runs_16bpp(
        &mut self,
        byte: u8,
        byte_idx: usize,
        width: u32,
        px_start: i32,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) -> bool {
        let mut wrote_mmio = false;
        let mut col = 0usize;
        while col < 8 && (byte_idx * 8 + col) < width as usize {
            let (run_start, run_len, new_col) =
                Self::next_on_run_bounded(byte, col, byte_idx, width as usize);
            col = new_col;
            if run_len == 0 {
                continue;
            }
            let dst_x = px_start + run_start as i32;
            wrote_mmio |= self.write_clipped_rgb565_run_nofence(dst_x, run_len, dst_y, stride, color);
        }
        wrote_mmio
    }

    /// Flush a horizontal run during Bresenham line drawing.
    fn flush_hrun(
        &mut self,
        run_start: i32,
        run_len: usize,
        run_y: i32,
        sx: i32,
        color: Color,
    ) {
        if run_y < self.clip.y || run_y >= self.clip.bottom() {
            return;
        }
        let (s, e) = if run_len <= 1 {
            (run_start, run_start)
        } else if sx > 0 {
            (run_start, run_start + (run_len as i32 - 1))
        } else {
            (run_start - (run_len as i32 - 1), run_start)
        };
        let s_clamped = s.max(self.clip.x).min(self.clip.right() - 1);
        let e_clamped = e.max(self.clip.x).min(self.clip.right() - 1);
        if s_clamped <= e_clamped {
            self.draw_hline_raw(s_clamped, e_clamped, run_y, color);
        }
    }

    // ─── End shared helpers ────────────────────────────────────────────────

    /// Process a single byte of glyph bitmap data, dispatching by bpp.
    /// Returns `true` if MMIO writes occurred (needs fence).
    #[allow(clippy::too_many_arguments)]
    fn glyph_process_byte(
        &mut self,
        byte: u8,
        byte_idx: usize,
        bpp: usize,
        stride: usize,
        px_start: i32,
        dst_y: i32,
        glyph_x: i32,
        width: u32,
        color: Color,
        has_bg: bool,
        fg_u32: u32,
        bg_u32: u32,
    ) -> bool {
        match bpp {
            4 if has_bg
                && px_start >= self.clip.x
                && (px_start + 8) <= self.clip.right()
                && (px_start + 8) <= (glyph_x + width as i32) =>
            {
                let dst_offset = (dst_y as usize * stride) + (px_start as usize * 4);
                self.write_glyph_row_32bit_nofence(byte, dst_offset, fg_u32, bg_u32)
            }
            3 => {
                self.glyph_byte_runs_24bpp(byte, byte_idx, width, px_start, dst_y, stride, color);
                false
            }
            2 => {
                self.glyph_byte_runs_16bpp(byte, byte_idx, width, px_start, dst_y, stride, color)
            }
            _ => {
                self.glyph_byte_fallback(byte, px_start, dst_y, glyph_x, width, color);
                false
            }
        }
    }

    /// Fallback per-pixel write for a single byte of glyph data.
    fn glyph_byte_fallback(
        &mut self,
        byte: u8,
        px_start: i32,
        dst_y: i32,
        glyph_x: i32,
        width: u32,
        color: Color,
    ) {
        for bit in 0..8 {
            let px = px_start + bit;
            if px < self.clip.x || px >= self.clip.right() || px >= glyph_x + width as i32 {
                continue;
            }
            if (byte >> (7 - bit)) & 1 != 0 {
                self.set_pixel_raw(px, dst_y, color);
            }
        }
    }

    /// Draw a single character using the 32bpp fast path in draw_text.
    /// Returns `true` if MMIO writes occurred.
    fn draw_text_char_32bpp_fast(
        &mut self,
        cx: i32,
        y: i32,
        c: char,
        font: &BitmapFont,
        stride: usize,
        format: PixelFormat,
        color: Color,
        bg_color: Color,
    ) -> bool {
        let char_w = font.width() as i32;
        let char_h = font.height() as i32;
        self.mark_dirty(Rect::new(cx, y, char_w as u32, char_h as u32));

        let fg_u32 = format.encode_u32(color).unwrap_or(color.to_u32());
        let bg_u32 = format.encode_u32(bg_color).unwrap_or(bg_color.to_u32());

        let data = font.glyph(c).unwrap_or(&[0u8; 16]);
        let mut wrote = false;
        for (row, &byte) in data.iter().enumerate() {
            let offset = ((y + row as i32) as usize * stride) + (cx as usize * 4);
            wrote |= self.write_glyph_row_32bit_nofence(byte, offset, fg_u32, bg_u32);
        }
        wrote
    }

    /// Draw a single character using the 16bpp fg+bg single-pass fast path.
    /// Writes all 8 pixels per row using branchless selection — no prefill needed.
    fn draw_text_char_16bpp_fast(
        &mut self,
        cx: i32,
        y: i32,
        c: char,
        font: &BitmapFont,
        stride: usize,
        color: Color,
        bg_color: Color,
    ) -> bool {
        let char_w = font.width() as i32;
        let char_h = font.height() as i32;
        self.mark_dirty(Rect::new(cx, y, char_w as u32, char_h as u32));

        let fg_u16 = Self::color_to_rgb565(color);
        let bg_u16 = Self::color_to_rgb565(bg_color);

        let data = font.glyph(c).unwrap_or(&[0u8; 16]);
        let mut wrote = false;
        for (row, &byte) in data.iter().enumerate() {
            let offset = ((y + row as i32) as usize * stride) + (cx as usize * 2);
            wrote |= self.write_glyph_row_16bit_nofence(byte, offset, fg_u16, bg_u16);
        }
        wrote
    }

    /// Draw a single character using the 24bpp fg+bg single-pass fast path.
    fn draw_text_char_24bpp_fast(
        &mut self,
        cx: i32,
        y: i32,
        c: char,
        font: &BitmapFont,
        stride: usize,
        color: Color,
        bg_color: Color,
    ) -> bool {
        let char_w = font.width() as i32;
        let char_h = font.height() as i32;
        self.mark_dirty(Rect::new(cx, y, char_w as u32, char_h as u32));

        let fg_bytes = self.bgr_color_order(color);
        let bg_bytes = self.bgr_color_order(bg_color);

        let data = font.glyph(c).unwrap_or(&[0u8; 16]);
        let mut wrote = false;
        for (row, &byte) in data.iter().enumerate() {
            let offset = ((y + row as i32) as usize * stride) + (cx as usize * 3);
            wrote |= self.write_glyph_row_24bit_nofence(byte, offset, fg_bytes, bg_bytes);
        }
        wrote
    }

    /// Draw one glyph row (non-32bpp path) with run detection and bpp dispatch.
    fn draw_text_glyph_row(
        &mut self,
        byte: u8,
        font_width: usize,
        cx: i32,
        dst_y: i32,
        stride: usize,
        bpp: usize,
        color: Color,
    ) -> bool {
        let mut need_fence = false;
        let mut col = 0usize;
        while col < font_width {
            let (run_start, run_len, new_col) = Self::next_on_run(byte, col, font_width);
            col = new_col;
            if run_len == 0 {
                continue;
            }
            let dst_x = cx + run_start as i32;
            let dst_run_end_x = dst_x + run_len as i32 - 1;
            if dst_run_end_x < self.clip.x || dst_x >= self.clip.right() {
                continue;
            }
            need_fence |= self.draw_text_write_run(dst_x, dst_run_end_x, dst_y, stride, bpp, color);
        }
        need_fence
    }

    /// Write a single run of ON-pixels for draw_text, dispatching by bpp.
    fn draw_text_write_run(
        &mut self,
        dst_x: i32,
        dst_run_end_x: i32,
        dst_y: i32,
        stride: usize,
        bpp: usize,
        color: Color,
    ) -> bool {
        let clipped_start = dst_x.max(self.clip.x);
        let clipped_end = dst_run_end_x.min(self.clip.right() - 1);
        let clipped_len = (clipped_end - clipped_start + 1) as usize;
        let start_offset = (dst_y as usize * stride) + (clipped_start as usize * bpp);
        match bpp {
            3 => {
                self.write_bgr_run(start_offset, clipped_len, color);
                true
            }
            2 => {
                let pixel = Self::color_to_rgb565(color);

                if self.back_buffer.is_some() {
                    let base = unsafe { self.draw_buffer().add(start_offset) };
                    let pair = (pixel as u32) | ((pixel as u32) << 16);
                    let mut i = 0usize;

                    while i + 1 < clipped_len {
                        unsafe {
                            ptr::write_unaligned(base.add(i * 2) as *mut u32, pair);
                        }
                        i += 2;
                    }

                    if i < clipped_len {
                        unsafe {
                            ptr::write_unaligned(base.add(i * 2) as *mut u16, pixel);
                        }
                    }
                    false
                } else {
                    let addr = self.draw_buffer() as usize + start_offset;
                    self.write_u16_run_streaming_nofence(addr, clipped_len, pixel);
                    true
                }
            }
            _ => {
                for i in 0..clipped_len {
                    self.set_pixel_raw(clipped_start + i as i32, dst_y, color);
                }
                false
            }
        }
    }

    /// Compute stride, format and bpp for text drawing.
    fn draw_text_setup(&self) -> (usize, PixelFormat, usize) {
        let stride = if self.back_buffer.is_some() {
            (self.info.width * 4) as usize
        } else {
            self.info.stride as usize
        };
        let format = if self.back_buffer.is_some() {
            PixelFormat::Bgra8888
        } else {
            self.info.format
        };
        let bpp = format.bytes_per_pixel() as usize;
        (stride, format, bpp)
    }

    /// Draw a single non-32bpp character glyph, returning whether MMIO writes occurred.
    fn draw_text_char_generic(
        &mut self,
        cx: i32,
        y: i32,
        c: char,
        font: &BitmapFont,
        stride: usize,
        bpp: usize,
        color: Color,
    ) -> bool {
        let glyph = match font.glyph(c) {
            Some(g) => g,
            None => return false,
        };
        let mut need_fence = false;
        for (row, &byte) in glyph.iter().enumerate() {
            let dst_y = y + row as i32;
            if !self.clip_y_visible(dst_y) {
                continue;
            }
            need_fence |= self.draw_text_glyph_row(byte, font.width() as usize, cx, dst_y, stride, bpp, color);
        }
        need_fence
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
        let (stride, format, bpp) = self.draw_text_setup();
        
        let char_count = text.chars().filter(|&c| c != '\n').count() as i32;
        let total_w = char_count * font.width() as i32;
        let char_h = font.height() as u32;

        // Determine if we can use single-pass fg+bg rendering (no prefill needed)
        let use_single_pass = (bpp == 4 || bpp == 2 || bpp == 3) && self.back_buffer.is_none();

        // Only pre-fill background for paths that don't do single-pass fg+bg
        if total_w > 0 && !use_single_pass {
            self.fill_rect(Rect::new(x, y, total_w as u32, char_h), bg_color);
        }

        let mut cx = x;
        let mut need_fence = false;
        for c in text.chars() {
            if c == '\n' {
                continue;
            }

            let char_w = font.width() as i32;
            let char_h = font.height() as i32;
            let fully_visible = self.clip_contains_rect(cx, y, char_w, char_h);

            // Single-pass fast paths: write fg+bg together, no prefill needed
            if fully_visible && use_single_pass {
                match bpp {
                    4 => {
                        need_fence |= self.draw_text_char_32bpp_fast(cx, y, c, &font, stride, format, color, bg_color);
                        cx += char_w;
                        continue;
                    }
                    2 => {
                        need_fence |= self.draw_text_char_16bpp_fast(cx, y, c, &font, stride, color, bg_color);
                        cx += char_w;
                        continue;
                    }
                    3 => {
                        need_fence |= self.draw_text_char_24bpp_fast(cx, y, c, &font, stride, color, bg_color);
                        cx += char_w;
                        continue;
                    }
                    _ => {}
                }
            }

            // For 16/24bpp single-pass not fully visible: fill bg for this char, then draw fg only
            if use_single_pass && !fully_visible && (bpp == 2 || bpp == 3) {
                self.fill_rect(Rect::new(cx, y, char_w as u32, char_h as u32), bg_color);
            }

            need_fence |= self.draw_text_char_generic(cx, y, c, &font, stride, bpp, color);
            cx += font.width() as i32;
        }

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
        let (fg_u32, bg_u32) = self.preencode_glyph_fg_bg(bpp, color, bg);

        let mut mmio_wrote = false;
        for row in 0..height {
            let dst_y = y + row as i32;
            if !self.clip_y_visible(dst_y) {
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
                mmio_wrote |= self.glyph_process_byte(
                    byte, byte_idx, bpp, stride, px_start, dst_y, x, width, color, bg.is_some(), fg_u32, bg_u32,
                );
            }
        }

        if mmio_wrote {
            mmio::sfence();
        }
    }

    fn preencode_glyph_fg_bg(&self, bpp: usize, color: Color, bg: Option<Color>) -> (u32, u32) {
        if bpp == 4 {
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
        }
    }

    /// Pre-encode foreground/background colors for the 32bpp MMIO path.
    fn preencode_colors_32(&self, color: Color, bg_color: Color) -> (u32, u32) {
        let fg = self.info.format.encode_u32(color).unwrap_or(color.to_u32());
        let bg_v = self.info.format.encode_u32(bg_color).unwrap_or(bg_color.to_u32());
        (fg, bg_v)
    }

    /// Write one glyph row at 16bpp (RGB565) with branchless fg/bg selection.
    /// Writes all 8 pixels in one pass using streaming u64 writes (16 bytes total).
    /// Returns `true` if MMIO writes occurred.
    fn write_glyph_row_16bit_nofence(
        &self,
        bits: u8,
        dst_offset_bytes: usize,
        fg_u16: u16,
        bg_u16: u16,
    ) -> bool {
        if self.buffer.is_null() {
            return false;
        }
        let addr = self.buffer as usize + dst_offset_bytes;

        // Branchless pixel selection: for each bit, mask selects fg or bg
        #[inline(always)]
        fn sel16(mask: u16, fg: u16, bg: u16) -> u16 {
            bg ^ ((bg ^ fg) & mask)
        }

        let b = bits as i32;
        let m0 = ((b << 24) >> 31) as u16;
        let m1 = ((b << 25) >> 31) as u16;
        let m2 = ((b << 26) >> 31) as u16;
        let m3 = ((b << 27) >> 31) as u16;
        let m4 = ((b << 28) >> 31) as u16;
        let m5 = ((b << 29) >> 31) as u16;
        let m6 = ((b << 30) >> 31) as u16;
        let m7 = ((b << 31) >> 31) as u16;

        // Pack 4 pixels into one u64 (LE: pixel0 at low bits)
        let p0 = sel16(m0, fg_u16, bg_u16) as u64;
        let p1 = sel16(m1, fg_u16, bg_u16) as u64;
        let p2 = sel16(m2, fg_u16, bg_u16) as u64;
        let p3 = sel16(m3, fg_u16, bg_u16) as u64;
        let v0 = p0 | (p1 << 16) | (p2 << 32) | (p3 << 48);

        let p4 = sel16(m4, fg_u16, bg_u16) as u64;
        let p5 = sel16(m5, fg_u16, bg_u16) as u64;
        let p6 = sel16(m6, fg_u16, bg_u16) as u64;
        let p7 = sel16(m7, fg_u16, bg_u16) as u64;
        let v1 = p4 | (p5 << 16) | (p6 << 32) | (p7 << 48);

        mmio::stream_write_u64(addr, v0);
        mmio::stream_write_u64(addr + 8, v1);
        true
    }

    /// Write one glyph row at 24bpp (BGR888/RGB888) with branchless fg/bg selection.
    /// Writes all 8 pixels (24 bytes) via streaming store.
    /// Returns `true` if MMIO writes occurred.
    fn write_glyph_row_24bit_nofence(
        &mut self,
        bits: u8,
        dst_offset_bytes: usize,
        fg_bytes: (u8, u8, u8),
        bg_bytes: (u8, u8, u8),
    ) -> bool {
        if self.buffer.is_null() {
            return false;
        }
        let addr = self.buffer as usize + dst_offset_bytes;

        // Build 24 bytes in a stack buffer, then streaming write
        let mut buf = [0u8; 24];
        let b = bits as i32;
        for bit in 0..8u32 {
            let mask = ((b << (24 + bit)) >> 31) as u8;
            // mask is 0xFF for fg, 0x00 for bg
            let c0 = bg_bytes.0 ^ ((bg_bytes.0 ^ fg_bytes.0) & mask);
            let c1 = bg_bytes.1 ^ ((bg_bytes.1 ^ fg_bytes.1) & mask);
            let c2 = bg_bytes.2 ^ ((bg_bytes.2 ^ fg_bytes.2) & mask);
            let off = bit as usize * 3;
            buf[off] = c0;
            buf[off + 1] = c1;
            buf[off + 2] = c2;
        }

        // Stream 24 bytes: 3 u64 writes (covers 24 bytes exactly)
        let v0 = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
        let v1 = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
        let v2 = u64::from_le_bytes([buf[16], buf[17], buf[18], buf[19], buf[20], buf[21], buf[22], buf[23]]);
        mmio::stream_write_u64(addr, v0);
        mmio::stream_write_u64(addr + 8, v1);
        mmio::stream_write_u64(addr + 16, v2);
        true
    }

    /// Render glyph rows dispatching between fast-32bpp and generic paths.
    fn render_char_rows(
        &mut self,
        glyph: &[u8],
        x: i32,
        y: i32,
        use_fast_path_32: bool,
        fg_u32: u32,
        bg_u32: u32,
        bpp: usize,
        stride: usize,
        color: Color,
    ) -> bool {
        let mut mmio_written = false;
        for (row, &byte) in glyph.iter().enumerate() {
            let dst_y = y + row as i32;
            if !self.clip_y_visible(dst_y) {
                continue;
            }
            if use_fast_path_32 {
                let dst_offset = (dst_y as usize * stride) + (x as usize * 4);
                mmio_written |= self.write_glyph_row_32bit_nofence(byte, dst_offset, fg_u32, bg_u32);
            } else {
                mmio_written |= self.draw_char_8x16_row(byte, bpp, x, dst_y, stride, color);
            }
        }
        mmio_written
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

        let char_w_i32 = font.width() as i32;
        let char_w = font.width() as u32;
        let char_h = font.height() as u32;
        self.mark_dirty(Rect::new(x, y, char_w, char_h));

        let is_fully_visible = x >= self.clip.x && (x + char_w_i32) <= self.clip.right();
        let no_backbuf = self.back_buffer.is_none();

        // Determine fast path mode: 0 = none, 4 = 32bpp, 2 = 16bpp, 3 = 24bpp
        let fast_mode = if bg.is_some() && is_fully_visible && no_backbuf {
            match bpp {
                4 | 2 | 3 => bpp,
                _ => 0,
            }
        } else if bg.is_some() && is_fully_visible && bpp == 4 {
            4 // 32bpp works with or without backbuffer
        } else {
            0
        };

        // Pre-fill background only when not using single-pass fast path
        if let Some(bg_color) = bg {
            if fast_mode == 0 {
                self.fill_rect(Rect::new(x, y, char_w, char_h), bg_color);
            }
        }

        let mmio_written = match fast_mode {
            4 => {
                let (fg_u32, bg_u32) = self.preencode_colors_32(color, bg.unwrap());
                self.render_char_rows(glyph, x, y, true, fg_u32, bg_u32, bpp, stride, color)
            }
            2 => {
                let fg_u16 = Self::color_to_rgb565(color);
                let bg_u16 = Self::color_to_rgb565(bg.unwrap());
                let mut wrote = false;
                for (row, &byte) in glyph.iter().enumerate() {
                    let dst_y = y + row as i32;
                    if !self.clip_y_visible(dst_y) { continue; }
                    let offset = (dst_y as usize * stride) + (x as usize * 2);
                    wrote |= self.write_glyph_row_16bit_nofence(byte, offset, fg_u16, bg_u16);
                }
                wrote
            }
            3 => {
                let fg_bytes = self.bgr_color_order(color);
                let bg_bytes = self.bgr_color_order(bg.unwrap());
                let mut wrote = false;
                for (row, &byte) in glyph.iter().enumerate() {
                    let dst_y = y + row as i32;
                    if !self.clip_y_visible(dst_y) { continue; }
                    let offset = (dst_y as usize * stride) + (x as usize * 3);
                    wrote |= self.write_glyph_row_24bit_nofence(byte, offset, fg_bytes, bg_bytes);
                }
                wrote
            }
            _ => {
                self.render_char_rows(glyph, x, y, false, 0, 0, bpp, stride, color)
            }
        };

        if mmio_written {
            self.counted_sfence();
        }
    }

    /// Process one row of draw_char_8x16 for non-fast-path bpp values.
    fn draw_char_8x16_row(
        &mut self,
        byte: u8,
        bpp: usize,
        x: i32,
        dst_y: i32,
        stride: usize,
        color: Color,
    ) -> bool {
        match bpp {
            4 | 0 => {
                // 32bpp partial/no-bg: per-pixel fallback
                self.glyph_byte_fallback(byte, x, dst_y, x, 8, color);
                false
            }
            3 => {
                // 24bpp: run-coalesced writes
                let mut col = 0usize;
                while col < 8 {
                    let (run_start, run_len, new_col) = Self::next_on_run(byte, col, 8);
                    col = new_col;
                    if run_len == 0 {
                        continue;
                    }
                    let dst_x = x + run_start as i32;
                    if dst_x >= self.clip.right() {
                        continue;
                    }
                    self.write_clipped_bgr_run(dst_x, run_len, dst_y, stride, color);
                }
                false
            }
            2 => {
                let mut wrote_mmio = false;
                let mut col = 0usize;
                while col < 8 {
                    let (run_start, run_len, new_col) = Self::next_on_run(byte, col, 8);
                    col = new_col;
                    if run_len == 0 {
                        continue;
                    }
                    let dst_x = x + run_start as i32;
                    if dst_x >= self.clip.right() {
                        continue;
                    }
                    wrote_mmio |= self.write_clipped_rgb565_run_nofence(dst_x, run_len, dst_y, stride, color);
                }
                wrote_mmio
            }
            _ => {
                self.glyph_byte_fallback(byte, x, dst_y, x, 8, color);
                false
            }
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

        // If backbuffer (fixed u32/BGRA) is active, use SIMD packer for RGBA->BGRA swizzle
        if let Some(ref mut back) = self.back_buffer {
             let src_offset = src_base * 4;
             let byte_len = run_len * 4;
             // Ensure bounds
             if src_offset + byte_len <= imgdata.len() {
                 let src_slice = &imgdata[src_offset..src_offset + byte_len];
                 let dst_slice = unsafe {
                     core::slice::from_raw_parts_mut(
                         (back.as_mut_ptr() as *mut u8).add(dst_byte_offset),
                         byte_len,
                     )
                 };
                 // SIMD-accelerated RGBA→BGRA (AVX2/SSSE3/scalar auto-dispatch)
                 crate::graphics::packer::pack_rgba_to_bgra(src_slice, dst_slice);
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

    /// 24-bitチャンクサイズ選択
    fn choose_chunk_24_pixels(run_len: usize) -> usize {
        if run_len >= 8192 {
            4096
        } else if run_len >= 2048 {
            1024
        } else {
            512
        }
    }

    /// scratchバッファからバック/MMIOへチャンク書き込み
    fn flush_scratch_24bit(
        &mut self,
        run_len: usize,
        dst_byte_offset: usize,
    ) {
        // Tunable chunk size for 24-bit writes
        #[cfg(feature = "std")]
        let chunk_24_pixels: usize = std::env::var("RANY_CHUNK_24_PIXELS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or_else(|| Self::choose_chunk_24_pixels(run_len));
        #[cfg(not(feature = "std"))]
        let chunk_24_pixels: usize = Self::choose_chunk_24_pixels(run_len);

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
    }

    /// 16-bit (RGB565) 不透明ランの描画
    fn write_opaque_run_16bit(
        &mut self,
        image: &super::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        _x: i32,
        _dst_row: i32,
    ) -> bool {
        let src_base = (src_row * image.width() + run_start) as usize;
        let imgdata = image.data();

        // Backbuffer is always u32/BGRA — 16bpp write_run should not reach here
        // with backbuffer active; handled by the 4bpp (backbuffer) path.
        if self.back_buffer.is_some() {
            debug_assert!(false, "16bpp write_run called on u32 backbuffer");
            return false;
        }

        // Convert RGBA pixels to RGB565 and stream-write
        let addr = self.buffer as usize + dst_byte_offset;
        // Use scratch_u8 as u16 buffer to batch the conversion
        let byte_len = run_len * 2;
        self.ensure_scratch_u8(byte_len);
        {
            let dst_u16 = unsafe {
                core::slice::from_raw_parts_mut(
                    self.scratch_u8.as_mut_ptr() as *mut u16,
                    run_len,
                )
            };
            for i in 0..run_len {
                let idx = (src_base + i) * 4;
                let r = imgdata[idx] as u16;
                let g = imgdata[idx + 1] as u16;
                let b = imgdata[idx + 2] as u16;
                dst_u16[i] = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
            }
        }
        self.write_bytes_mmio_streaming(addr, &self.scratch_u8[..byte_len]);
        true
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
            self.flush_scratch_24bit(run_len, dst_byte_offset);
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

    /// 透明ピクセルをスキップし、アルファ>0のピクセルはブレンド描画する
    fn skip_transparent_pixels(
        &mut self,
        image: &super::image::Image,
        src_row: u32,
        col: &mut u32,
        row_end: u32,
        x: i32,
        dst_row: i32,
        img_ptr: *const u8,
    ) {
        while *col < row_end {
            let idx = ((src_row * image.width() + *col) * 4) as usize;
            let alpha = unsafe { *img_ptr.add(idx + 3) };
            if alpha == 255 {
                break;
            }
            if alpha > 0 {
                let c = image.get_pixel(*col, src_row);
                self.blend_pixel(x + *col as i32, dst_row, c);
            }
            *col += 1;
        }
    }

    /// 不透明ピクセルの連続走査長を検出
    fn find_opaque_run_len(
        image: &super::image::Image,
        src_row: u32,
        col: &mut u32,
        row_end: u32,
        img_ptr: *const u8,
    ) -> usize {
        let run_start = *col;
        while *col < row_end {
            let idx = ((src_row * image.width() + *col) * 4) as usize;
            let alpha = unsafe { *img_ptr.add(idx + 3) };
            if alpha != 255 {
                break;
            }
            *col += 1;
        }
        (*col - run_start) as usize
    }

    /// 不透明ランをフレームバッファに書き込む
    fn write_run(
        &mut self,
        image: &super::image::Image,
        src_row: u32,
        run_start: u32,
        run_len: usize,
        dst_byte_offset: usize,
        bytes_per_pixel: usize,
        x: i32,
        dst_row: i32,
        avx2_available: bool,
    ) -> bool {
        match bytes_per_pixel {
            4 => self.write_opaque_run_32bit(
                image, src_row, run_start, run_len, dst_byte_offset, avx2_available,
            ),
            3 => self.write_opaque_run_24bit(
                image, src_row, run_start, run_len, dst_byte_offset, x, dst_row, avx2_available,
            ),
            2 => self.write_opaque_run_16bit(
                image, src_row, run_start, run_len, dst_byte_offset, x, dst_row,
            ),
            _ => {
                for i in 0..run_len {
                    let c = image.get_pixel(run_start + i as u32, src_row);
                    self.set_pixel(x + (run_start as i32 + i as i32), dst_row, c);
                }
                self.back_buffer.is_none()
            }
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
        let (bytes_per_pixel, stride) = if self.back_buffer.is_some() {
             (4, (self.info.width * 4) as u32)
        } else {
             (self.info.format.bytes_per_pixel(), self.info.stride)
        };
        
        let dst_row_offset = (dst_row as u32 * stride) as usize;
        let mut col = row_start;
        let img_ptr = image.data().as_ptr();

        while col < row_end {
            self.skip_transparent_pixels(image, src_row, &mut col, row_end, x, dst_row, img_ptr);

            let run_start = col;
            let run_len = Self::find_opaque_run_len(image, src_row, &mut col, row_end, img_ptr);
            if run_len == 0 {
                continue;
            }

            let abs_x = (x + run_start as i32) as usize;
            let dst_byte_offset = dst_row_offset + abs_x * bytes_per_pixel;

            if self.write_run(
                image, src_row, run_start, run_len, dst_byte_offset,
                bytes_per_pixel, x, dst_row, avx2_available,
            ) {
                mmio_written = true;
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
