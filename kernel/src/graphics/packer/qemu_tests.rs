#[cfg(any(
    target_feature = "avx2",
    target_feature = "ssse3",
    target_arch = "aarch64"
))]
use alloc::vec;

pub fn wave6_pack_rgba_to_bgra_avx2_matches_scalar_smoke() -> bool {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2"
    ))]
    {
        if hal::mmio::get_simd_level() < hal::mmio::simd_level::AVX2 {
            return true;
        }
        for &len in &[4usize, 12, 16, 20, 48, 64, 100] {
            let mut src = vec![0u8; len * 4];
            for (i, slot) in src.iter_mut().enumerate() {
                *slot = (i * 97 % 251) as u8;
            }
            let mut dst_simd = vec![0u8; src.len()];
            let mut dst_scalar = vec![0u8; src.len()];
            // SAFETY: CPU admission above enables this instruction set; the disjoint
            // initialized source/destination allocations cover the complete pixel count.
            unsafe {
                crate::graphics::packer::pack_rgba_to_bgra_avx2(
                    src.as_ptr(),
                    dst_simd.as_mut_ptr(),
                    src.len(),
                );
            }
            crate::graphics::packer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);
            if dst_simd != dst_scalar {
                return false;
            }
        }
        return true;
    }
    #[cfg(not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2"
    )))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgr24_avx2_matches_scalar_smoke() -> bool {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2"
    ))]
    {
        if hal::mmio::get_simd_level() < hal::mmio::simd_level::AVX2 {
            return true;
        }
        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for (i, slot) in src.iter_mut().enumerate() {
            *slot = (i * 97 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        // SAFETY: CPU admission above enables this instruction set; the disjoint
        // initialized source/destination allocations cover the complete pixel count.
        unsafe {
            crate::graphics::packer::pack_rgba_to_bgr24_avx2_8pixels(
                src.as_ptr(),
                dst_simd.as_mut_ptr(),
                true,
            );
        }
        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s];
        }
        return dst_simd == dst_scalar;
    }
    #[cfg(not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "avx2"
    )))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgr24_ssse3_matches_scalar_smoke() -> bool {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "ssse3"
    ))]
    {
        if hal::mmio::get_simd_level() < hal::mmio::simd_level::SSSE3 {
            return true;
        }
        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for (i, slot) in src.iter_mut().enumerate() {
            *slot = (i * 61 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        // SAFETY: CPU admission above enables this instruction set; the disjoint
        // initialized source/destination allocations cover the complete pixel count.
        unsafe {
            crate::graphics::packer::pack_rgba_to_bgr24_ssse3_8pixels(
                src.as_ptr(),
                dst_simd.as_mut_ptr(),
                true,
            );
        }
        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s];
        }
        return dst_simd == dst_scalar;
    }
    #[cfg(not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "ssse3"
    )))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgra_neon_matches_scalar_smoke() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        for &len in &[4usize, 12, 16, 20, 48, 64, 100] {
            let mut src = vec![0u8; len * 4];
            for (i, slot) in src.iter_mut().enumerate() {
                *slot = (i * 61 % 251) as u8;
            }
            let mut dst_neon = vec![0u8; src.len()];
            let mut dst_scalar = vec![0u8; src.len()];
            // SAFETY: CPU admission above enables this instruction set; the disjoint
            // initialized source/destination allocations cover the complete pixel count.
            unsafe {
                crate::graphics::packer::pack_rgba_to_bgra_neon(
                    src.as_ptr(),
                    dst_neon.as_mut_ptr(),
                    src.len(),
                );
            }
            crate::graphics::packer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);
            if dst_neon != dst_scalar {
                return false;
            }
        }
        return true;
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgr24_neon_matches_scalar_smoke() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for (i, slot) in src.iter_mut().enumerate() {
            *slot = (i * 97 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        // SAFETY: CPU admission above enables this instruction set; the disjoint
        // initialized source/destination allocations cover the complete pixel count.
        unsafe {
            crate::graphics::packer::pack_rgba_to_bgr24_neon_8pixels(
                src.as_ptr(),
                dst_simd.as_mut_ptr(),
                true,
            );
        }
        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s];
        }
        return dst_simd == dst_scalar;
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgr24_neon_matches_scalar_rgb_smoke() -> bool {
    #[cfg(target_arch = "aarch64")]
    {
        let len = 8usize;
        let mut src = vec![0u8; len * 4];
        for (i, slot) in src.iter_mut().enumerate() {
            *slot = (i * 113 % 251) as u8;
        }
        let mut dst_simd = vec![0u8; len * 3];
        // SAFETY: CPU admission above enables this instruction set; the disjoint
        // initialized source/destination allocations cover the complete pixel count.
        unsafe {
            crate::graphics::packer::pack_rgba_to_bgr24_neon_8pixels(
                src.as_ptr(),
                dst_simd.as_mut_ptr(),
                false,
            );
        }
        let mut dst_scalar = vec![0u8; len * 3];
        for p in 0..len {
            let s = p * 4;
            dst_scalar[p * 3] = src[s];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s + 2];
        }
        return dst_simd == dst_scalar;
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        true
    }
}

pub fn wave6_pack_rgba_to_bgra_ssse3_matches_scalar_smoke() -> bool {
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "ssse3"
    ))]
    {
        if hal::mmio::get_simd_level() < hal::mmio::simd_level::SSSE3 {
            return true;
        }
        for &len in &[4usize, 12, 16, 20, 48, 64, 100] {
            let mut src = vec![0u8; len * 4];
            for (i, slot) in src.iter_mut().enumerate() {
                *slot = (i * 37 % 251) as u8;
            }
            let mut dst_simd = vec![0u8; src.len()];
            let mut dst_scalar = vec![0u8; src.len()];
            // SAFETY: CPU admission above enables this instruction set; the disjoint
            // initialized source/destination allocations cover the complete pixel count.
            unsafe {
                crate::graphics::packer::pack_rgba_to_bgra_ssse3(
                    src.as_ptr(),
                    dst_simd.as_mut_ptr(),
                    src.len(),
                );
            }
            crate::graphics::packer::pack_rgba_to_bgra_scalar(&src, &mut dst_scalar);
            if dst_simd != dst_scalar {
                return false;
            }
        }
        return true;
    }
    #[cfg(not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "ssse3"
    )))]
    {
        true
    }
}
