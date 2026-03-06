use super::*;
use core::sync::atomic::Ordering as AOrdering;

fn fill_src(buf: &mut [u8], pixels: usize) {
    for i in 0..pixels {
        let r = ((i * 37) & 0xFF) as u8;
        let g = ((i * 73) & 0xFF) as u8;
        let b = ((i * 91) & 0xFF) as u8;
        let a = 0xFFu8;
        buf[4 * i] = r;
        buf[4 * i + 1] = g;
        buf[4 * i + 2] = b;
        buf[4 * i + 3] = a;
    }
}

#[test_case]
fn pack_rgba_to_bgra_matches_scalar_mode() {
    let pixels_list = [1usize, 2, 7, 8, 9, 15, 16, 17, 24, 32, 33, 64];
    for &pixels in pixels_list.iter() {
        let mut src = [0u8; 4 * 64];
        fill_src(&mut src, pixels);
        let mut out_dispatch = [0u8; 4 * 64];
        let mut out_scalar = [0u8; 4 * 64];
        let prev = PACKER_MODE.load(AOrdering::Relaxed);
        PACKER_MODE.store(1, AOrdering::Relaxed);
        pack_rgba_to_bgra(&src[..pixels * 4], &mut out_dispatch[..pixels * 4]);
        pack_rgba_to_bgra_scalar(&src[..pixels * 4], &mut out_scalar[..pixels * 4]);
        PACKER_MODE.store(prev, AOrdering::Relaxed);
        assert_eq!(
            &out_dispatch[..pixels * 4],
            &out_scalar[..pixels * 4],
            "pixels={}",
            pixels
        );
    }
}

#[test_case]
fn pack_rgba_to_bgra_matches_simd_if_available() {
    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    {
        let pixels_list = [8usize, 9, 15, 16, 17, 24, 32, 33];
        // SSSE3
        if std::is_x86_feature_detected!("ssse3") {
            let prev = PACKER_MODE.load(AOrdering::Relaxed);
            PACKER_MODE.store(2, AOrdering::Relaxed);
            for &pixels in pixels_list.iter() {
                let mut src = [0u8; 4 * 64];
                fill_src(&mut src, pixels);
                let mut out_dispatch = [0u8; 4 * 64];
                let mut out_scalar = [0u8; 4 * 64];
                pack_rgba_to_bgra(&src[..pixels * 4], &mut out_dispatch[..pixels * 4]);
                pack_rgba_to_bgra_scalar(&src[..pixels * 4], &mut out_scalar[..pixels * 4]);
                assert_eq!(
                    &out_dispatch[..pixels * 4],
                    &out_scalar[..pixels * 4],
                    "ssse3 pixels={}",
                    pixels
                );
            }
            PACKER_MODE.store(prev, AOrdering::Relaxed);
        }
        // AVX2
        if std::is_x86_feature_detected!("avx2") {
            let prev = PACKER_MODE.load(AOrdering::Relaxed);
            PACKER_MODE.store(3, AOrdering::Relaxed);
            for &pixels in pixels_list.iter() {
                let mut src = [0u8; 4 * 64];
                fill_src(&mut src, pixels);
                let mut out_dispatch = [0u8; 4 * 64];
                let mut out_scalar = [0u8; 4 * 64];
                pack_rgba_to_bgra(&src[..pixels * 4], &mut out_dispatch[..pixels * 4]);
                pack_rgba_to_bgra_scalar(&src[..pixels * 4], &mut out_scalar[..pixels * 4]);
                assert_eq!(
                    &out_dispatch[..pixels * 4],
                    &out_scalar[..pixels * 4],
                    "avx2 pixels={}",
                    pixels
                );
            }
            PACKER_MODE.store(prev, AOrdering::Relaxed);
        }
    }
}

#[test_case]
fn pack_rgba_to_bgr24_matches_scalar_mode() {
    let pixels_list = [1usize, 2, 7, 8, 9, 15, 16, 17, 24, 31, 32, 33, 64];
    for &pixels in pixels_list.iter() {
        let mut src = [0u8; 4 * 64];
        fill_src(&mut src, pixels);
        let mut out_dispatch = [0u8; 3 * 64];
        let mut out_scalar = [0u8; 3 * 64];
        let prev = PACKER_MODE.load(AOrdering::Relaxed);
        PACKER_MODE.store(1, AOrdering::Relaxed);
        pack_rgba_to_bgr24(&src[..pixels * 4], &mut out_dispatch[..pixels * 3], true);
        pack_rgba_to_bgr24_scalar(&src[..pixels * 4], &mut out_scalar[..pixels * 3], true);
        PACKER_MODE.store(prev, AOrdering::Relaxed);
        assert_eq!(
            &out_dispatch[..pixels * 3],
            &out_scalar[..pixels * 3],
            "pixels={}",
            pixels
        );
    }
}

#[test_case]
fn pack_rgba_to_bgr24_matches_simd_if_available() {
    #[cfg(all(feature = "std", any(target_arch = "x86", target_arch = "x86_64")))]
    {
        let pixels_list = [8usize, 9, 15, 16, 17, 24, 32, 33];
        if std::is_x86_feature_detected!("ssse3") {
            let prev = PACKER_MODE.load(AOrdering::Relaxed);
            PACKER_MODE.store(2, AOrdering::Relaxed);
            for &pixels in pixels_list.iter() {
                let mut src = [0u8; 4 * 64];
                fill_src(&mut src, pixels);
                let mut out_dispatch = [0u8; 3 * 64];
                let mut out_scalar = [0u8; 3 * 64];
                pack_rgba_to_bgr24(&src[..pixels * 4], &mut out_dispatch[..pixels * 3], true);
                pack_rgba_to_bgr24_scalar(&src[..pixels * 4], &mut out_scalar[..pixels * 3], true);
                assert_eq!(
                    &out_dispatch[..pixels * 3],
                    &out_scalar[..pixels * 3],
                    "ssse3 pixels={}",
                    pixels
                );
            }
            PACKER_MODE.store(prev, AOrdering::Relaxed);
        }
        if std::is_x86_feature_detected!("avx2") {
            let prev = PACKER_MODE.load(AOrdering::Relaxed);
            PACKER_MODE.store(3, AOrdering::Relaxed);
            for &pixels in pixels_list.iter() {
                let mut src = [0u8; 4 * 64];
                fill_src(&mut src, pixels);
                let mut out_dispatch = [0u8; 3 * 64];
                let mut out_scalar = [0u8; 3 * 64];
                pack_rgba_to_bgr24(&src[..pixels * 4], &mut out_dispatch[..pixels * 3], true);
                pack_rgba_to_bgr24_scalar(&src[..pixels * 4], &mut out_scalar[..pixels * 3], true);
                assert_eq!(
                    &out_dispatch[..pixels * 3],
                    &out_scalar[..pixels * 3],
                    "avx2 pixels={}",
                    pixels
                );
            }
            PACKER_MODE.store(prev, AOrdering::Relaxed);
        }
    }
}
