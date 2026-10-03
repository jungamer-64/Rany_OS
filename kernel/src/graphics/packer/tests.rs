#[cfg(any(
    target_feature = "avx2",
    target_feature = "ssse3",
    target_arch = "aarch64"
))]
use alloc::vec;
/// Compare SIMD pack function against scalar reference for multiple sizes.
/// `simd_fn` receives (src_ptr, dst_ptr, byte_len).
/// `scalar_fn` receives (&[u8], &mut [u8]).
#[cfg(any(
    all(
        target_arch = "x86_64",
        any(target_feature = "ssse3", target_feature = "avx2")
    ),
    target_arch = "aarch64"
))]
fn assert_simd_matches_scalar(
    sizes: &[usize],
    seed_mul: usize,
    simd_fn: unsafe fn(*const u8, *mut u8, usize),
    scalar_fn: fn(&[u8], &mut [u8]),
) {
    for &len in sizes {
        let mut src = vec![0u8; len * 4];
        for (i, b) in src.iter_mut().enumerate() {
            *b = (i * seed_mul % 251) as u8;
        }
        let mut dst_simd = vec![0u8; src.len()];
        let mut dst_scalar = vec![0u8; src.len()];
        // SAFETY: caller selects an enabled CPU instruction set; both disjoint allocations cover the complete byte count.
        unsafe {
            simd_fn(src.as_ptr(), dst_simd.as_mut_ptr(), src.len());
        }
        scalar_fn(&src, &mut dst_scalar);
        assert_eq!(dst_simd, dst_scalar, "mismatch at size {len}");
    }
}

/// Compare SIMD BGR24 8-pixel pack against scalar reference.
#[cfg(any(
    all(
        target_arch = "x86_64",
        any(target_feature = "ssse3", target_feature = "avx2")
    ),
    target_arch = "aarch64"
))]
fn assert_bgr24_8px_matches_scalar(
    seed_mul: usize,
    is_bgr: bool,
    simd_fn: unsafe fn(*const u8, *mut u8, bool),
) {
    let len = 8usize;
    let mut src = vec![0u8; len * 4];
    for (i, b) in src.iter_mut().enumerate() {
        *b = (i * seed_mul % 251) as u8;
    }
    let mut dst_simd = vec![0u8; len * 3];
    // SAFETY: caller selects an enabled instruction set; disjoint allocations cover 32 source and 24 destination bytes.
    unsafe {
        simd_fn(src.as_ptr(), dst_simd.as_mut_ptr(), is_bgr);
    }
    let mut dst_scalar = vec![0u8; len * 3];
    for p in 0..len {
        let s = p * 4;
        if is_bgr {
            dst_scalar[p * 3] = src[s + 2];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s];
        } else {
            dst_scalar[p * 3] = src[s];
            dst_scalar[p * 3 + 1] = src[s + 1];
            dst_scalar[p * 3 + 2] = src[s + 2];
        }
    }
    assert_eq!(dst_simd, dst_scalar);
}

#[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_pack_rgba_to_bgra_ssse3_matches_scalar() {
    #[cfg(feature = "std")]
    if !std::is_x86_feature_detected!("ssse3") {
        return;
    }
    #[cfg(not(feature = "std"))]
    if hal::mmio::get_simd_level() < hal::mmio::simd_level::SSSE3 {
        return;
    }

    assert_simd_matches_scalar(
        &[4, 12, 16, 20, 48, 64, 100],
        37,
        crate::graphics::packer::pack_rgba_to_bgra_ssse3,
        crate::graphics::packer::pack_rgba_to_bgra,
    );
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_pack_rgba_to_bgra_avx2_matches_scalar() {
    #[cfg(feature = "std")]
    if !std::is_x86_feature_detected!("avx2") {
        return;
    }
    #[cfg(not(feature = "std"))]
    if hal::mmio::get_simd_level() < hal::mmio::simd_level::AVX2 {
        return;
    }

    assert_simd_matches_scalar(
        &[4, 12, 16, 20, 48, 64, 100],
        97,
        crate::graphics::packer::pack_rgba_to_bgra_avx2,
        crate::graphics::packer::pack_rgba_to_bgra_scalar,
    );
}

#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_pack_rgba_to_bgr24_avx2_matches_scalar() {
    #[cfg(feature = "std")]
    if !std::is_x86_feature_detected!("avx2") {
        return;
    }
    #[cfg(not(feature = "std"))]
    if hal::mmio::get_simd_level() < hal::mmio::simd_level::AVX2 {
        return;
    }

    assert_bgr24_8px_matches_scalar(
        97,
        true,
        crate::graphics::packer::pack_rgba_to_bgr24_avx2_8pixels,
    );
}

#[cfg(all(target_arch = "x86_64", target_feature = "ssse3"))]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_pack_rgba_to_bgr24_ssse3_matches_scalar() {
    #[cfg(feature = "std")]
    if !std::is_x86_feature_detected!("ssse3") {
        return;
    }
    #[cfg(not(feature = "std"))]
    if hal::mmio::get_simd_level() < hal::mmio::simd_level::SSSE3 {
        return;
    }

    assert_bgr24_8px_matches_scalar(
        61,
        true,
        crate::graphics::packer::pack_rgba_to_bgr24_ssse3_8pixels,
    );
}

#[cfg(target_arch = "aarch64")]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_pack_rgba_to_bgra_neon_matches_scalar() {
    if !std::is_aarch64_feature_detected!("neon") {
        return;
    }

    assert_simd_matches_scalar(
        &[4, 12, 16, 20, 48, 64, 100],
        61,
        crate::graphics::packer::pack_rgba_to_bgra_neon,
        crate::graphics::packer::pack_rgba_to_bgra_scalar,
    );
}

#[cfg(target_arch = "aarch64")]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_pack_rgba_to_bgr24_neon_matches_scalar() {
    if !std::is_aarch64_feature_detected!("neon") {
        return;
    }
    assert_bgr24_8px_matches_scalar(
        97,
        true,
        crate::graphics::packer::pack_rgba_to_bgr24_neon_8pixels,
    );
}

#[cfg(target_arch = "aarch64")]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
pub(crate) fn test_pack_rgba_to_bgr24_neon_matches_scalar_rgb() {
    if !std::is_aarch64_feature_detected!("neon") {
        return;
    }
    assert_bgr24_8px_matches_scalar(
        113,
        false,
        crate::graphics::packer::pack_rgba_to_bgr24_neon_8pixels,
    );
}

#[cfg(feature = "std")]
#[test]
fn environment_policy_names_are_capped_by_detected_instruction_support() {
    use super::{clamp_forced_mode, parse_packer_mode_name};
    assert_eq!(parse_packer_mode_name("scalar"), Some(1));
    assert_eq!(parse_packer_mode_name("AVX2"), Some(3));
    assert_eq!(parse_packer_mode_name("absent"), None);
    assert_eq!(clamp_forced_mode(2, 3), 2);
    assert_eq!(clamp_forced_mode(3, 1), 1);
}

mod dispatch;
