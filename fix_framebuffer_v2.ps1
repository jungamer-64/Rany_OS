$path = "d:\Rust\Rany_OS\kernel\src\graphics\framebuffer.rs"
$lines = Get-Content $path -Encoding UTF8

# Part 1: Imports
# Lines 0..16 are index based (Line 1 to 17)
# We want to replace headers.
# Line 17 (index 16) is `use hal::mmio;`.
# We output lines 0..16 (indexes 0..16 includes 17 lines!)
# Wait. `0..16` is 17 items.
# Logic: $head = $lines[0..15] (first 16 lines).
# New line = "use hal::mmio;\nuse super::mmio::MmioWriter;"
# Or just replace line 16.

$part1 = $lines[0..16]
$import_fix = "use super::mmio::MmioWriter;"

# Part 2: Macro Insertion
# We insert AFTER line 46 (index 45).
# So we need lines 17..46 (indices 17..46, corresponding to lines 18..47).
# Wait. Let's be precise.
# Original Line 47: `}` (closing brace of `current_packer_mode`).
# We want to insert AFTER this brace.
# So we include Up TO index 46.
$part2 = $lines[17..46]

# Using Literal Here-String (@' ... '@) avoids expansion of $
$macro_def = @'
// Macro to dispatch SIMD packing calls
macro_rules! simd_pack_dispatch {
    ($src:expr, $dst:expr, $len:expr,
     $simd_fn_avx2:ident, $simd_fn_ssse3:ident, $simd_fn_neon:ident, $scalar_fn:ident
     $(, $extra_args:expr)*) => {
        {
            use core::sync::atomic::Ordering;
            #[allow(unused_mut)]
            let mut mode = PACKER_MODE.load(Ordering::Relaxed);

            // Environment override logic
                #[cfg(feature = "std")]
                if let Ok(val) = std::env::var("RANY_PACKER") {
                    let forced = match val.to_ascii_lowercase().as_str() {
                        "scalar" => Some(1u8),
                        "ssse3" => Some(2u8),
                        "avx2" => Some(3u8),
                        "neon" => Some(4u8),
                        s => s.parse::<u8>().ok(),
                    };
                    if let Some(f) = forced {
                        PACKER_MODE.store(f, Ordering::Relaxed);
                        mode = f;
                    }

            }

            if mode == 0 {
                // Runtime detection logic
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                {
                    if cfg!(target_feature = "avx2") { mode = 3; }
                    else if cfg!(target_feature = "ssse3") { mode = 2; }
                    else { mode = 1; }
                }
                #[cfg(target_arch = "aarch64")]
                {
                    if cfg!(target_feature = "neon") { mode = 4; }
                    else { mode = 1; }
                }
                PACKER_MODE.store(mode, Ordering::Relaxed);
            }

            match mode {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                3 => unsafe {
                    // AVX2
                    Framebuffer::$simd_fn_avx2($src, $dst, $len $(, $extra_args)*)
                },
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                2 => unsafe {
                    // SSSE3
                    Framebuffer::$simd_fn_ssse3($src, $dst, $len $(, $extra_args)*)
                },
                 #[cfg(target_arch = "aarch64")]
                4 => unsafe {
                    // NEON
                    Framebuffer::$simd_fn_neon($src, $dst, $len $(, $extra_args)*)
                },
                _ => Framebuffer::$scalar_fn($src, $dst),
            }
        }
    };
}
'@

# Part 3: Between Macro and pack_rgba_to_bgra
# pack_rgba_to_bgra starts at line 1873 (Index 1872).
# We keep lines from 47 (Index 47) up to 1872 (Index 1871).
$part3 = $lines[47..1871]

# Part 4: Replacement for pack_rgba_to_bgra
# Starts at Index 1872.
# Ends at Line 2090 (Index 2089).
# So we DROP $lines[1872..2089].

$packers = @'
    /// Pack RGBA byte buffer into BGRA byte buffer. Prefer scalar fallback for now as SIMD is 24-bit focused.
    pub fn pack_rgba_to_bgra(src: &[u8], dst: &mut [u8]) {
        Self::pack_rgba_to_bgra_scalar(src, dst);
    }

    /// Public dispatcher for 24-bit packing (uses SIMD if available)
    pub fn pack_rgba_to_bgr24(src: &[u8], dst: &mut [u8], is_bgr: bool) {
        let pixels = core::cmp::min(src.len() / 4, dst.len() / 3);
        simd_pack_dispatch!(
            src,
            dst,
            pixels,
            pack_rgba_to_bgr24_avx2,
            pack_rgba_to_bgr24_ssse3,
            pack_rgba_to_bgr24_neon,
            pack_rgba_to_bgr24_scalar,
            is_bgr
        );
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "avx2")]
    unsafe fn pack_rgba_to_bgr24_avx2(src: &[u8], dst: &mut [u8], pixels: usize, is_bgr: bool) {
        let mut processed = 0;
        let mut src_ptr = src.as_ptr();
        let mut dst_ptr = dst.as_mut_ptr();
        while processed + 8 <= pixels {
            unsafe {
                Framebuffer::pack_rgba_to_bgr24_avx2_8pixels(src_ptr, dst_ptr, is_bgr);
                src_ptr = src_ptr.add(32);
                dst_ptr = dst_ptr.add(24);
                processed += 8;
            }
        }
        Framebuffer::pack_rgba_to_bgr24_scalar(&src[processed * 4..], &mut dst[processed * 3..]);
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    #[target_feature(enable = "ssse3")]
    unsafe fn pack_rgba_to_bgr24_ssse3(src: &[u8], dst: &mut [u8], pixels: usize, is_bgr: bool) {
        let mut processed = 0;
        let mut src_ptr = src.as_ptr();
        let mut dst_ptr = dst.as_mut_ptr();
        while processed + 8 <= pixels {
            unsafe {
                Framebuffer::pack_rgba_to_bgr24_ssse3_8pixels(src_ptr, dst_ptr, is_bgr);
                src_ptr = src_ptr.add(32);
                dst_ptr = dst_ptr.add(24);
                processed += 8;
            }
        }
        Framebuffer::pack_rgba_to_bgr24_scalar(&src[processed * 4..], &mut dst[processed * 3..]);
    }

    #[cfg(target_arch = "aarch64")]
    unsafe fn pack_rgba_to_bgr24_neon(src: &[u8], dst: &mut [u8], pixels: usize, is_bgr: bool) {
        let mut processed = 0;
        let mut src_ptr = src.as_ptr();
        let mut dst_ptr = dst.as_mut_ptr();
        while processed + 8 <= pixels {
            unsafe {
                Framebuffer::pack_rgba_to_bgr24_neon_8pixels(src_ptr, dst_ptr, is_bgr);
                src_ptr = src_ptr.add(32);
                dst_ptr = dst_ptr.add(24);
                processed += 8;
            }
        }
        Framebuffer::pack_rgba_to_bgr24_scalar(&src[processed * 4..], &mut dst[processed * 3..]);
    }

    fn pack_rgba_to_bgr24_scalar(src: &[u8], dst: &mut [u8]) {
        let len = src.len() / 4;
        let mut i = 0;
        let mut src_idx = 0;
        let mut dst_off = 0;

        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        unsafe {
            let src_ptr = src.as_ptr();
            let dst_ptr = dst.as_mut_ptr();
            while i + 3 < len {
                let p0 = core::ptr::read_unaligned(src_ptr.add(src_idx) as *const u32);
                let p1 = core::ptr::read_unaligned(src_ptr.add(src_idx + 4) as *const u32);
                let p2 = core::ptr::read_unaligned(src_ptr.add(src_idx + 8) as *const u32);
                let p3 = core::ptr::read_unaligned(src_ptr.add(src_idx + 12) as *const u32);
                
                let b0 = ((p0 >> 16) & 0xFF) as u32; let g0 = ((p0 >> 8) & 0xFF) as u32; let r0 = (p0 & 0xFF) as u32;
                let b1 = ((p1 >> 16) & 0xFF) as u32; let g1 = ((p1 >> 8) & 0xFF) as u32; let r1 = (p1 & 0xFF) as u32;
                let b2 = ((p2 >> 16) & 0xFF) as u32; let g2 = ((p2 >> 8) & 0xFF) as u32; let r2 = (p2 & 0xFF) as u32;
                let b3 = ((p3 >> 16) & 0xFF) as u32; let g3 = ((p3 >> 8) & 0xFF) as u32; let r3 = (p3 & 0xFF) as u32;
                
                let d0 = r0 | (g0 << 8) | (b0 << 16) | (r1 << 24);
                let d1 = g1 | (b1 << 8) | (r2 << 16) | (g2 << 24);
                let d2 = b2 | (r3 << 8) | (g3 << 16) | (b3 << 24);
                
                core::ptr::write_unaligned(dst_ptr.add(dst_off) as *mut u32, d0);
                core::ptr::write_unaligned(dst_ptr.add(dst_off + 4) as *mut u32, d1);
                core::ptr::write_unaligned(dst_ptr.add(dst_off + 8) as *mut u32, d2);
                
                src_idx += 16; dst_off += 12; i += 4;
            }
        }
        
        while i < len {
            dst[dst_off] = src[src_idx + 2];
            dst[dst_off + 1] = src[src_idx + 1];
            dst[dst_off + 2] = src[src_idx];
            src_idx += 4; dst_off += 3; i += 1;
        }
    }
'@

# Part 5: Rest of file
# Starts at Index 2090 (Line 2091).
$part5 = $lines[2090..($lines.Count - 1)]

# Combine
$part1 += $import_fix
Set-Content $path -Value ($part1 + $part2 + $macro_def + $part3 + $packers + $part5) -Encoding UTF8
