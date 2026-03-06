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
        unsafe {
            self.scratch_u32.set_len(capacity);
        }
    }

    /// Ensure scratch_u8 has at least `capacity` bytes
    fn ensure_scratch_u8(&mut self, capacity: usize) {
        if self.scratch_u8.capacity() < capacity {
            // Correctly reserve from current length
            self.scratch_u8.reserve(capacity - self.scratch_u8.len());
        }
        // Safety: We have ensured capacity >= capacity. The caller MUST overwrite
        // all bytes up to `capacity` before reading.
        unsafe {
            self.scratch_u8.set_len(capacity);
        }
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
                    let v =
                        u32::from_le_bytes([data[*i], data[*i + 1], data[*i + 2], data[*i + 3]]);
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
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2"
    ))]
    pub unsafe fn pack_rgba_to_bgra_avx2(src: *const u8, dst: *mut u8, bytes: usize) {
        // SAFETY: `src` and `dst` must be valid for `bytes` bytes and non-overlapping as required by the
        // underlying SIMD implementation. The caller of this `unsafe` function is responsible for ensuring that.
        unsafe {
            crate::graphics::packer::pack_rgba_to_bgra_avx2(src, dst, bytes);
        }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "ssse3"
    ))]
    pub unsafe fn pack_rgba_to_bgra_ssse3(src: *const u8, dst: *mut u8, bytes: usize) {
        // SAFETY: Same invariants as `pack_rgba_to_bgra_avx2`.
        unsafe {
            crate::graphics::packer::pack_rgba_to_bgra_ssse3(src, dst, bytes);
        }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2"
    ))]
    pub unsafe fn pack_rgba_to_bgr24_avx2_8pixels(src: *const u8, dst: *mut u8, is_bgr: bool) {
        // SAFETY: `src` and `dst` must point to at least 8 pixels' worth of data.
        unsafe {
            crate::graphics::packer::pack_rgba_to_bgr24_avx2_8pixels(src, dst, is_bgr);
        }
    }

    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "ssse3"
    ))]
    pub unsafe fn pack_rgba_to_bgr24_ssse3_8pixels(src: *const u8, dst: *mut u8, is_bgr: bool) {
        // SAFETY: `src` and `dst` must point to at least 8 pixels' worth of data.
        unsafe {
            crate::graphics::packer::pack_rgba_to_bgr24_ssse3_8pixels(src, dst, is_bgr);
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub unsafe fn pack_rgba_to_bgra_neon(src: *const u8, dst: *mut u8, bytes: usize) {
        // SAFETY: same invariants as other SIMD entry points.
        unsafe {
            crate::graphics::packer::pack_rgba_to_bgra_neon(src, dst, bytes);
        }
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
                let row_slice =
                    unsafe { core::slice::from_raw_parts_mut(row_ptr as *mut u32, run_len_pixels) };
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
    fn write_u32_run_mmio(
        &mut self,
        dst_offset_bytes: usize,
        run_len_pixels: usize,
        color_u32: u32,
    ) {
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
    fn write_bgr_small_direct_mmio(addr: usize, run_len_pixels: usize, c0: u8, c1: u8, c2: u8) {
        let u32_0 = (c0 as u32) | ((c1 as u32) << 8) | ((c2 as u32) << 16) | ((c0 as u32) << 24);
        let u32_1 = (c1 as u32) | ((c2 as u32) << 8) | ((c0 as u32) << 16) | ((c1 as u32) << 24);
        let u32_2 = (c2 as u32) | ((c0 as u32) << 8) | ((c1 as u32) << 16) | ((c2 as u32) << 24);

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
    fn write_bgr_large_direct_mmio(addr: usize, run_len_pixels: usize, c0: u8, c1: u8, c2: u8) {
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

    fn blit_rect_32bpp(
        &mut self,
        back_ptr: *const u32,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        stride_mmio: usize,
    ) {
        for row in 0..h {
            let src_y = y + row;
            let src_idx = src_y * self.info.width as usize + x;
            let src_slice = unsafe { core::slice::from_raw_parts(back_ptr.add(src_idx), w) };
            let dst_offset = (y + row) * stride_mmio + x * 4;
            let dst_addr = self.buffer as usize + dst_offset;
            self.write_u32_slice_mmio_streaming(dst_addr, src_slice);
        }
    }

    fn blit_rect_24bpp(
        &mut self,
        back_ptr: *const u32,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        stride_mmio: usize,
    ) {
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

    fn blit_rect_16bpp(
        &mut self,
        back_ptr: *const u32,
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        stride_mmio: usize,
    ) {
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
}

// ============================================================================
// Submodules (split from this file for clarity)
// ============================================================================
mod drawing;
mod image;
mod text;
