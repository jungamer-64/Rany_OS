// ============================================================================
// kernel/src/graphics/packer.rs - Pixel Format Packer Module
// ============================================================================
//!
//! SIMD-accelerated pixel format conversion functions.
//!
//! This module provides optimized pixel packing routines for:
//! - RGBA -> BGRA (32-bit swap)
//! - RGBA -> BGR24/RGB24 (32-bit to 24-bit compression)
//!
//! Implementations use AVX2, SSSE3, or NEON when available, with
//! scalar fallbacks for unsupported platforms.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU8, Ordering};

// Packer selection cache. 0 = unknown, 1 = scalar, 2 = ssse3, 3 = avx2, 4 = neon.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) static PACKER_MODE: AtomicU8 = AtomicU8::new(0);

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) static AVX2_AVAILABLE: AtomicU8 = AtomicU8::new(0);

#[cfg(target_arch = "aarch64")]
pub(crate) static PACKER_MODE: AtomicU8 = AtomicU8::new(0);

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) static PACKER_MODE: AtomicU8 = AtomicU8::new(1); // Default scalar

/// Force packer mode (bench only)
#[cfg(feature = "bench")]
pub fn force_packer_mode(mode: u8) {
    PACKER_MODE.store(mode, Ordering::Relaxed);
}

/// Get current packer mode (bench only)
#[cfg(feature = "bench")]
pub fn current_packer_mode() -> u8 {
    PACKER_MODE.load(Ordering::Relaxed)
}

// ============================================================================
// Runtime Detection & Dispatch
// ============================================================================

/// Detect and cache the best available SIMD level
fn detect_simd_mode() -> u8 {
    let mut mode = 1u8; // Default scalar
    
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        #[cfg(feature = "std")]
        {
            if std::is_x86_feature_detected!("avx2") { mode = 3; }
            else if std::is_x86_feature_detected!("ssse3") { mode = 2; }
        }
        #[cfg(not(feature = "std"))]
        {
            use hal::mmio;
            if mmio::get_simd_level() >= mmio::simd_level::AVX2 { mode = 3; }
            else if mmio::get_simd_level() >= mmio::simd_level::SSSE3 { mode = 2; }
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        if cfg!(target_feature = "neon") { mode = 4; }
    }
    
    // Environment override (std only) with clamp
    #[cfg(feature = "std")]
    if let Ok(val) = std::env::var("RANY_PACKER") {
        let low = val.to_ascii_lowercase();
        let forced: Option<u8> = match low.as_str() {
            "scalar" => Some(1u8),
            "ssse3" => Some(2u8),
            "avx2" => Some(3u8),
            "neon" => Some(4u8),
            s => s.parse::<u8>().ok(),
        };
        if let Some(f) = forced {
            mode = mode.min(f).max(1);
        }
    }
    
    mode
}

/// Get or detect the packer mode
#[inline]
pub fn get_packer_mode() -> u8 {
    let mode = PACKER_MODE.load(Ordering::Relaxed);
    if mode == 0 {
        let detected = detect_simd_mode();
        PACKER_MODE.store(detected, Ordering::Relaxed);
        detected
    } else {
        mode
    }
}

// ============================================================================
// RGBA -> BGRA (32-bit swap)
// ============================================================================

/// Pack RGBA byte buffer into BGRA byte buffer.
/// Uses AVX2, SSSE3, or scalar based on CPU capabilities.
pub fn pack_rgba_to_bgra(src: &[u8], dst: &mut [u8]) {
    let pixels = core::cmp::min(src.len(), dst.len()) / 4;
    let bytes = pixels * 4;
    
    if bytes == 0 {
        return;
    }
    
    // Small-run fast-path
    if bytes < 16 {
        pack_rgba_to_bgra_scalar(&src[..bytes], &mut dst[..bytes]);
        return;
    }
    
    let mode = get_packer_mode();
    
    match mode {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        3 => unsafe { pack_rgba_to_bgra_avx2(src.as_ptr(), dst.as_mut_ptr(), bytes) },
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        2 => unsafe { pack_rgba_to_bgra_ssse3(src.as_ptr(), dst.as_mut_ptr(), bytes) },
        #[cfg(target_arch = "aarch64")]
        4 => unsafe { pack_rgba_to_bgra_neon(src.as_ptr(), dst.as_mut_ptr(), bytes) },
        _ => pack_rgba_to_bgra_scalar(&src[..bytes], &mut dst[..bytes]),
    }
}

/// Scalar RGBA -> BGRA packer
#[inline(always)]
pub fn pack_rgba_to_bgra_scalar(src: &[u8], dst: &mut [u8]) {
    let pixels = core::cmp::min(src.len(), dst.len()) / 4;
    let bytes = pixels * 4;
    let mut i = 0usize;

    // Process 16-byte blocks
    while i + 16 <= bytes {
        let v0 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i) as *const u32) };
        let v1 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i + 4) as *const u32) };
        let v2 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i + 8) as *const u32) };
        let v3 = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i + 12) as *const u32) };

        let s0 = (v0 & 0xFF00FF00) | ((v0 & 0x000000FF) << 16) | ((v0 & 0x00FF0000) >> 16);
        let s1 = (v1 & 0xFF00FF00) | ((v1 & 0x000000FF) << 16) | ((v1 & 0x00FF0000) >> 16);
        let s2 = (v2 & 0xFF00FF00) | ((v2 & 0x000000FF) << 16) | ((v2 & 0x00FF0000) >> 16);
        let s3 = (v3 & 0xFF00FF00) | ((v3 & 0x000000FF) << 16) | ((v3 & 0x00FF0000) >> 16);

        let p0 = (s0 as u64) | ((s1 as u64) << 32);
        let p1 = (s2 as u64) | ((s3 as u64) << 32);

        unsafe {
            core::ptr::write_unaligned(dst.as_mut_ptr().add(i) as *mut u64, p0);
            core::ptr::write_unaligned(dst.as_mut_ptr().add(i + 8) as *mut u64, p1);
        }
        i += 16;
    }

    while i + 4 <= bytes {
        let v = unsafe { core::ptr::read_unaligned(src.as_ptr().add(i) as *const u32) };
        let swapped = (v & 0xFF00FF00) | ((v & 0x000000FF) << 16) | ((v & 0x00FF0000) >> 16);
        unsafe {
            core::ptr::write_unaligned(dst.as_mut_ptr().add(i) as *mut u32, swapped);
        }
        i += 4;
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
pub unsafe fn pack_rgba_to_bgra_avx2(src: *const u8, dst: *mut u8, bytes: usize) {
    use core::arch::x86_64::*;
    
    let mask = _mm256_setr_epi8(
        2, 1, 0, 3, 6, 5, 4, 7, 10, 9, 8, 11, 14, 13, 12, 15,
        18, 17, 16, 19, 22, 21, 20, 23, 26, 25, 24, 27, 30, 29, 28, 31,
    );

    let mut i = 0usize;

    while i + 64 <= bytes {
        let v0 = _mm256_loadu_si256(src.add(i) as *const __m256i);
        let v1 = _mm256_loadu_si256(src.add(i + 32) as *const __m256i);
        let r0 = _mm256_shuffle_epi8(v0, mask);
        let r1 = _mm256_shuffle_epi8(v1, mask);
        _mm256_storeu_si256(dst.add(i) as *mut __m256i, r0);
        _mm256_storeu_si256(dst.add(i + 32) as *mut __m256i, r1);
        i += 64;
    }

    while i + 32 <= bytes {
        let v = _mm256_loadu_si256(src.add(i) as *const __m256i);
        let r = _mm256_shuffle_epi8(v, mask);
        _mm256_storeu_si256(dst.add(i) as *mut __m256i, r);
        i += 32;
    }

    // SSSE3 tail
    while i + 16 <= bytes {
        let v = _mm_loadu_si128(src.add(i) as *const __m128i);
        let m = _mm_setr_epi8(2, 1, 0, 3, 6, 5, 4, 7, 10, 9, 8, 11, 14, 13, 12, 15);
        let r = _mm_shuffle_epi8(v, m);
        _mm_storeu_si128(dst.add(i) as *mut __m128i, r);
        i += 16;
    }

    // Scalar tail
    while i < bytes {
        let s = (i / 4) * 4;
        let r = *src.add(s);
        let g = *src.add(s + 1);
        let b = *src.add(s + 2);
        let a = *src.add(s + 3);
        *dst.add(s) = b;
        *dst.add(s + 1) = g;
        *dst.add(s + 2) = r;
        *dst.add(s + 3) = a;
        i += 4;
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "ssse3")]
pub unsafe fn pack_rgba_to_bgra_ssse3(src: *const u8, dst: *mut u8, bytes: usize) {
    use core::arch::x86_64::*;
    
    let mask = _mm_setr_epi8(2, 1, 0, 3, 6, 5, 4, 7, 10, 9, 8, 11, 14, 13, 12, 15);
    let mut i = 0usize;

    while i + 32 <= bytes {
        let v0 = _mm_loadu_si128(src.add(i) as *const __m128i);
        let v1 = _mm_loadu_si128(src.add(i + 16) as *const __m128i);
        let r0 = _mm_shuffle_epi8(v0, mask);
        let r1 = _mm_shuffle_epi8(v1, mask);
        _mm_storeu_si128(dst.add(i) as *mut __m128i, r0);
        _mm_storeu_si128(dst.add(i + 16) as *mut __m128i, r1);
        i += 32;
    }

    while i + 16 <= bytes {
        let v = _mm_loadu_si128(src.add(i) as *const __m128i);
        let r = _mm_shuffle_epi8(v, mask);
        _mm_storeu_si128(dst.add(i) as *mut __m128i, r);
        i += 16;
    }

    // Scalar tail
    while i < bytes {
        let s = (i / 4) * 4;
        let r = *src.add(s);
        let g = *src.add(s + 1);
        let b = *src.add(s + 2);
        let a = *src.add(s + 3);
        *dst.add(s) = b;
        *dst.add(s + 1) = g;
        *dst.add(s + 2) = r;
        *dst.add(s + 3) = a;
        i += 4;
    }
}

#[cfg(target_arch = "aarch64")]
pub unsafe fn pack_rgba_to_bgra_neon(src: *const u8, dst: *mut u8, bytes: usize) {
    // Scalar fallback for NEON (can be optimized with NEON intrinsics later)
    let mut i = 0usize;
    while i < bytes {
        let s = (i / 4) * 4;
        let r = *src.add(s);
        let g = *src.add(s + 1);
        let b = *src.add(s + 2);
        let a = *src.add(s + 3);
        *dst.add(s) = b;
        *dst.add(s + 1) = g;
        *dst.add(s + 2) = r;
        *dst.add(s + 3) = a;
        i += 4;
    }
}

// ============================================================================
// RGBA -> BGR24/RGB24 (32-bit to 24-bit)
// ============================================================================

/// Pack RGBA into BGR24 or RGB24.
pub fn pack_rgba_to_bgr24(src: &[u8], dst: &mut [u8], is_bgr: bool) {
    let pixels = core::cmp::min(src.len() / 4, dst.len() / 3);
    
    if pixels < 8 {
        pack_rgba_to_bgr24_scalar(src, dst, is_bgr);
        return;
    }
    
    let mode = get_packer_mode();
    
    match mode {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        3 => unsafe { pack_rgba_to_bgr24_avx2(src, dst, pixels, is_bgr) },
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        2 => unsafe { pack_rgba_to_bgr24_ssse3(src, dst, pixels, is_bgr) },
        #[cfg(target_arch = "aarch64")]
        4 => unsafe { pack_rgba_to_bgr24_neon(src, dst, pixels, is_bgr) },
        _ => pack_rgba_to_bgr24_scalar(src, dst, is_bgr),
    }
}

/// Scalar BGR24/RGB24 packer
#[inline(always)]
pub fn pack_rgba_to_bgr24_scalar(src: &[u8], dst: &mut [u8], is_bgr: bool) {
    let len = core::cmp::min(src.len() / 4, dst.len() / 3);
    let mut i = 0;
    let mut src_idx = 0;
    let mut dst_off = 0;

    if is_bgr {
        while i < len {
            dst[dst_off] = src[src_idx + 2];     // B
            dst[dst_off + 1] = src[src_idx + 1]; // G
            dst[dst_off + 2] = src[src_idx];     // R
            src_idx += 4;
            dst_off += 3;
            i += 1;
        }
    } else {
        while i < len {
            dst[dst_off] = src[src_idx];         // R
            dst[dst_off + 1] = src[src_idx + 1]; // G
            dst[dst_off + 2] = src[src_idx + 2]; // B
            src_idx += 4;
            dst_off += 3;
            i += 1;
        }
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
#[inline]
unsafe fn pack_rgba_to_bgr24_avx2(src: &[u8], dst: &mut [u8], pixels: usize, is_bgr: bool) {
    let mut processed = 0;
    let mut src_ptr = src.as_ptr();
    let mut dst_ptr = dst.as_mut_ptr();
    
    while processed + 8 <= pixels {
        pack_rgba_to_bgr24_avx2_8pixels(src_ptr, dst_ptr, is_bgr);
        src_ptr = src_ptr.add(32);
        dst_ptr = dst_ptr.add(24);
        processed += 8;
    }
    
    let end_src = pixels * 4;
    let end_dst = pixels * 3;
    pack_rgba_to_bgr24_scalar(&src[processed * 4..end_src], &mut dst[processed * 3..end_dst], is_bgr);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
#[inline]
pub unsafe fn pack_rgba_to_bgr24_avx2_8pixels(src: *const u8, dst: *mut u8, is_bgr: bool) {
    use core::arch::x86_64::*;
    
    let shuffle_mask = if is_bgr {
        _mm256_setr_epi8(
            2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
            2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1,
        )
    } else {
        _mm256_setr_epi8(
            0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, -1, -1, -1, -1,
            0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, -1, -1, -1, -1,
        )
    };

    let rgba = _mm256_loadu_si256(src as *const __m256i);
    let shuffled = _mm256_shuffle_epi8(rgba, shuffle_mask);
    
    // Extract and merge the two 12-byte results
    let lo = _mm256_extracti128_si256::<0>(shuffled);
    let hi = _mm256_extracti128_si256::<1>(shuffled);
    
    // Store first 12 bytes from each lane
    let lo_val = _mm_cvtsi128_si64(lo) as u64;
    core::ptr::copy_nonoverlapping(&lo_val as *const u64 as *const u8, dst, 8);
    
    let lo_shifted = _mm_srli_si128::<8>(lo);
    let lo_upper = _mm_cvtsi128_si64(lo_shifted) as u32;
    core::ptr::copy_nonoverlapping(&lo_upper as *const u32 as *const u8, dst.add(8), 4);
    
    let hi_val = _mm_cvtsi128_si64(hi) as u64;
    core::ptr::copy_nonoverlapping(&hi_val as *const u64 as *const u8, dst.add(12), 8);
    
    let hi_shifted = _mm_srli_si128::<8>(hi);
    let hi_upper = _mm_cvtsi128_si64(hi_shifted) as u32;
    core::ptr::copy_nonoverlapping(&hi_upper as *const u32 as *const u8, dst.add(20), 4);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "ssse3")]
#[inline]
pub unsafe fn pack_rgba_to_bgr24_ssse3(src: &[u8], dst: &mut [u8], pixels: usize, is_bgr: bool) {
    let mut processed = 0;
    let mut src_ptr = src.as_ptr();
    let mut dst_ptr = dst.as_mut_ptr();
    
    while processed + 8 <= pixels {
        pack_rgba_to_bgr24_ssse3_8pixels(src_ptr, dst_ptr, is_bgr);
        src_ptr = src_ptr.add(32);
        dst_ptr = dst_ptr.add(24);
        processed += 8;
    }
    
    let end_src = pixels * 4;
    let end_dst = pixels * 3;
    pack_rgba_to_bgr24_scalar(&src[processed * 4..end_src], &mut dst[processed * 3..end_dst], is_bgr);
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "ssse3")]
#[inline]
pub unsafe fn pack_rgba_to_bgr24_ssse3_8pixels(src: *const u8, dst: *mut u8, is_bgr: bool) {
    use core::arch::x86_64::*;
    
    let shuffle_mask = if is_bgr {
        _mm_setr_epi8(2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12, -1, -1, -1, -1)
    } else {
        _mm_setr_epi8(0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, -1, -1, -1, -1)
    };

    // Process first 4 pixels (16 bytes -> 12 bytes)
    let rgba_lo = _mm_loadu_si128(src as *const __m128i);
    let shuffled_lo = _mm_shuffle_epi8(rgba_lo, shuffle_mask);
    
    // Process second 4 pixels
    let rgba_hi = _mm_loadu_si128(src.add(16) as *const __m128i);
    let shuffled_hi = _mm_shuffle_epi8(rgba_hi, shuffle_mask);
    
    // Store 12 bytes from each
    let lo_val = _mm_cvtsi128_si64(shuffled_lo) as u64;
    core::ptr::copy_nonoverlapping(&lo_val as *const u64 as *const u8, dst, 8);
    
    let lo_shifted = _mm_srli_si128::<8>(shuffled_lo);
    let lo_upper = _mm_cvtsi128_si64(lo_shifted) as u32;
    core::ptr::copy_nonoverlapping(&lo_upper as *const u32 as *const u8, dst.add(8), 4);
    
    let hi_val = _mm_cvtsi128_si64(shuffled_hi) as u64;
    core::ptr::copy_nonoverlapping(&hi_val as *const u64 as *const u8, dst.add(12), 8);
    
    let hi_shifted = _mm_srli_si128::<8>(shuffled_hi);
    let hi_upper = _mm_cvtsi128_si64(hi_shifted) as u32;
    core::ptr::copy_nonoverlapping(&hi_upper as *const u32 as *const u8, dst.add(20), 4);
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn pack_rgba_to_bgr24_neon(src: &[u8], dst: &mut [u8], pixels: usize, is_bgr: bool) {
    // Scalar fallback for now
    pack_rgba_to_bgr24_scalar(src, dst, is_bgr);
}

// ============================================================================
// AVX2 Availability Check
// ============================================================================

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn get_avx2_available() -> bool {
    #[cfg(not(feature = "std"))]
    {
        hal::mmio::get_simd_level() >= hal::mmio::simd_level::AVX2
    }
    #[cfg(feature = "std")]
    {
        let v = AVX2_AVAILABLE.load(Ordering::Relaxed);
        if v == 0 {
            let avail = std::is_x86_feature_detected!("avx2");
            AVX2_AVAILABLE.store(if avail { 2 } else { 1 }, Ordering::Relaxed);
            avail
        } else {
            v == 2
        }
    }
}
