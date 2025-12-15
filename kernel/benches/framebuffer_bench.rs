//! Framebuffer benchmark suite
//!
//! Comprehensive benchmarks for framebuffer graphics operations including:
//! - Image drawing (opaque/various formats)
//! - SIMD packer performance (scalar/SSSE3/AVX2/NEON)

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use graphic_types::{Color, FramebufferInfo, PixelFormat};
use rany_os::graphics::framebuffer::Framebuffer;
use rany_os::graphics::image::Image;
use std::time::Duration;

// =============================================================================
// Configuration
// =============================================================================

/// Returns a custom Criterion configuration with longer measurement time
/// to reduce noise in CI environments.
fn criterion_config() -> Criterion {
    // Allow environment overrides for longer measurement / warmer warmups
    let measurement_secs: u64 = std::env::var("RANY_BENCH_MEAS_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let sample_size: usize = std::env::var("RANY_BENCH_SAMPLE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);
    let warm_up_secs: u64 = std::env::var("RANY_BENCH_WARMUP_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);

    eprintln!(
        "Criterion config: measurement={}s sample_size={} warmup={}s",
        measurement_secs, sample_size, warm_up_secs
    );

    Criterion::default()
        .measurement_time(Duration::from_secs(measurement_secs))
        .sample_size(sample_size)
        .warm_up_time(Duration::from_secs(warm_up_secs))
}

/// Heuristic to pick an inner-loop repeat count so per-iteration work is
/// reasonably large and thus less susceptible to timer noise. Controlled by
/// `RANY_BENCH_TARGET_PIXELS_PER_ITER` (default 1_000_000).
fn bench_repeat_for_pixels(pixels: usize) -> usize {
    const DEFAULT_TARGET_PIXELS: usize = 1_000_000;
    let target: usize = std::env::var("RANY_BENCH_TARGET_PIXELS_PER_ITER")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_TARGET_PIXELS);
    let repeats = core::cmp::max(1usize, target / core::cmp::max(1usize, pixels));
    eprintln!("bench_repeat_for_pixels: pixels={} -> repeats={}", pixels, repeats);
    repeats
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Standard test resolution
const BENCH_WIDTH: u32 = 800;
const BENCH_HEIGHT: u32 = 600;

/// Create a framebuffer with backing memory for benchmarking
fn setup_framebuffer(
    width: u32,
    height: u32,
    format: PixelFormat,
    bpp: u8,
    double_buffer: bool,
) -> (Vec<u8>, Framebuffer) {
    let bytes_per_pixel = bpp as u32 / 8;
    let stride = width * bytes_per_pixel;
    let info = FramebufferInfo {
        address: 0,
        width,
        height,
        stride,
        format,
        bpp,
    };

    let mut mem = vec![0u8; info.size()];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let mut fb = unsafe { Framebuffer::new(info2) };

    if double_buffer {
        let back = vec![0u8; info.size()];
        fb.enable_double_buffering_from_vec(back);
    }

    (mem, fb)
}

/// Generate pseudo-random test data for packer benchmarks
fn generate_test_data(size: usize, seed: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    for i in 0..size {
        data[i] = ((i * seed) % 251) as u8;
    }
    data
}

// =============================================================================
// Image Drawing Benchmarks
// =============================================================================

fn bench_draw_image_bgra(c: &mut Criterion) {
    let (_mem, mut fb) =
        setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Bgra8888, 32, true);
    let img = Image::filled(
        BENCH_WIDTH,
        BENCH_HEIGHT,
        Color::with_alpha(64, 128, 192, 255),
    );

    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("draw_image_bgra", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                fb.draw_image(black_box(&img), 0, 0)
            }
        })
    });
}

fn bench_draw_image_rgba(c: &mut Criterion) {
    let (_mem, mut fb) =
        setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Rgba8888, 32, true);
    let img = Image::filled(
        BENCH_WIDTH,
        BENCH_HEIGHT,
        Color::with_alpha(64, 128, 192, 255),
    );

    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("draw_image_rgba", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                fb.draw_image(black_box(&img), 0, 0)
            }
        })
    });
}

fn bench_draw_image_bgr24(c: &mut Criterion) {
    let (_mem, mut fb) =
        setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Bgr888, 24, true);
    let img = Image::filled(
        BENCH_WIDTH,
        BENCH_HEIGHT,
        Color::with_alpha(64, 128, 192, 255),
    );

    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("draw_image_bgr24", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                fb.draw_image(black_box(&img), 0, 0)
            }
        })
    });
}

fn bench_draw_image_rgb565(c: &mut Criterion) {
    let (_mem, mut fb) =
        setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Rgb565, 16, true);
    let img = Image::filled(
        BENCH_WIDTH,
        BENCH_HEIGHT,
        Color::with_alpha(64, 128, 192, 255),
    );

    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("draw_image_rgb565", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                fb.draw_image(black_box(&img), 0, 0)
            }
        })
    });
}

fn bench_draw_image_mmio(c: &mut Criterion) {
    // MMIO path (no double buffering)
    let (_mem, mut fb) =
        setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Bgra8888, 32, false);
    let img = Image::filled(
        BENCH_WIDTH,
        BENCH_HEIGHT,
        Color::with_alpha(64, 128, 192, 255),
    );

    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("draw_image_mmio", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                fb.draw_image(black_box(&img), 0, 0)
            }
        })
    });
}

// =============================================================================
// SIMD Packer Benchmarks
// =============================================================================

fn bench_pack_rgba_to_bgr24_dispatch(c: &mut Criterion) {
    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let src = generate_test_data(pixels * 4, 97);
    let mut dst = vec![0u8; pixels * 3];
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("pack_rgba_bgr24_dispatch", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                Framebuffer::bench_pack_rgba_to_bgr24_dispatch(
                    black_box(&src),
                    black_box(&mut dst),
                    true,
                )
            }
        })
    });
}

fn bench_pack_rgba_to_bgr24_scalar(c: &mut Criterion) {
    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let src = generate_test_data(pixels * 4, 61);
    let mut dst = vec![0u8; pixels * 3];
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("pack_rgba_bgr24_scalar", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                Framebuffer::bench_pack_rgba_to_bgr24_scalar(black_box(&src), black_box(&mut dst))
            }
        })
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn bench_pack_rgba_to_bgr24_avx2(c: &mut Criterion) {
    if !std::is_x86_feature_detected!("avx2") {
        return;
    }
    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let src = generate_test_data(pixels * 4, 101);
    let mut dst = vec![0u8; pixels * 3];
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("pack_rgba_bgr24_avx2", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                unsafe {
                    Framebuffer::bench_pack_rgba_to_bgr24_avx2(
                        black_box(&src),
                        black_box(&mut dst),
                        pixels,
                        true,
                    )
                }
            }
        })
    });
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn bench_pack_rgba_to_bgr24_avx2(_c: &mut Criterion) {
    // AVX2 not available on this architecture
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn bench_pack_rgba_to_bgr24_avx2_8pix_micro(_c: &mut Criterion) {}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn bench_pack_rgba_to_bgr24_ssse3(c: &mut Criterion) {
    if !std::is_x86_feature_detected!("ssse3") {
        return;
    }
    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let src = generate_test_data(pixels * 4, 53);
    let mut dst = vec![0u8; pixels * 3];
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("pack_rgba_bgr24_ssse3", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                unsafe {
                    Framebuffer::bench_pack_rgba_to_bgr24_ssse3(
                        black_box(&src),
                        black_box(&mut dst),
                        pixels,
                        true,
                    )
                }
            }
        })
    });
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn bench_pack_rgba_to_bgr24_ssse3(_c: &mut Criterion) {
    // SSSE3 not available on this architecture
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn bench_pack_rgba_to_bgr24_ssse3_8pix_micro(_c: &mut Criterion) {}

fn bench_pack_rgba_to_bgr24_neon(_c: &mut Criterion) {
    #[cfg(target_arch = "aarch64")]
    {
        if !std::arch::is_aarch64_feature_detected!("neon") {
            return;
        }
        let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
        let src = generate_test_data(pixels * 4, 79);
        let mut dst = vec![0u8; pixels * 3];

        let repeats = bench_repeat_for_pixels(pixels);
        _c.bench_function("pack_rgba_bgr24_neon", |b| {
            b.iter(|| {
                for _ in 0..repeats {
                    unsafe {
                        Framebuffer::bench_pack_rgba_to_bgr24_neon(
                            black_box(&src),
                            black_box(&mut dst),
                            pixels,
                            true,
                        )
                    }
                }
            })
        });
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn bench_pack_rgba_to_bgr24_neon_8pix_micro(_c: &mut Criterion) {}

// Micro-bench: measure raw helper throughput (8-pixel helper) to isolate
// per-call overhead from streaming bandwidth. Controlled by
// RANY_PACKER_INNER_REPEATS (default 1_000_000).
fn inner_repeats() -> usize {
    std::env::var("RANY_PACKER_INNER_REPEATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1_000_000)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn bench_pack_rgba_to_bgr24_avx2_8pix_micro(c: &mut Criterion) {
    if !std::is_x86_feature_detected!("avx2") {
        return;
    }
    let src = generate_test_data(32, 199);
    let mut dst = vec![0u8; 24];
    let reps = inner_repeats();
    eprintln!("avx2_8pix_micro reps={}", reps);
    c.bench_function("pack_rgba_bgr24_avx2_8pix_micro", |b| {
        b.iter(|| {
            for _ in 0..reps {
                unsafe { Framebuffer::bench_pack_rgba_to_bgr24_avx2_8pixels(src.as_ptr(), dst.as_mut_ptr(), true) }
            }
        })
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn bench_pack_rgba_to_bgr24_ssse3_8pix_micro(c: &mut Criterion) {
    if !std::is_x86_feature_detected!("ssse3") {
        return;
    }
    let src = generate_test_data(32, 211);
    let mut dst = vec![0u8; 24];
    let reps = inner_repeats();
    eprintln!("ssse3_8pix_micro reps={}", reps);
    c.bench_function("pack_rgba_bgr24_ssse3_8pix_micro", |b| {
        b.iter(|| {
            for _ in 0..reps {
                unsafe { Framebuffer::bench_pack_rgba_to_bgr24_ssse3_8pixels(src.as_ptr(), dst.as_mut_ptr(), true) }
            }
        })
    });
}

#[cfg(target_arch = "aarch64")]
fn bench_pack_rgba_to_bgr24_neon_8pix_micro(c: &mut Criterion) {
    if !std::arch::is_aarch64_feature_detected!("neon") {
        return;
    }
    let src = generate_test_data(32, 223);
    let mut dst = vec![0u8; 24];
    let reps = inner_repeats();
    eprintln!("neon_8pix_micro reps={}", reps);
    c.bench_function("pack_rgba_bgr24_neon_8pix_micro", |b| {
        b.iter(|| {
            for _ in 0..reps {
                unsafe { Framebuffer::pack_rgba_to_bgr24_neon_8pixels(src.as_ptr(), dst.as_mut_ptr(), true) }
            }
        })
    });
}

// Additional micro-benchmarks across multiple sizes to observe scaling
fn bench_pack_rgba_to_bgr24_scalar_sizes(c: &mut Criterion) {
    for &pixels in &[1024usize, 16384usize, 131072usize] {
        let mut src = generate_test_data(pixels * 4, 61);
        let mut dst = vec![0u8; pixels * 3];
        let id = format!("pack_rgba_bgr24_scalar_{}px", pixels);
        let repeats = bench_repeat_for_pixels(pixels);
        c.bench_function(&id, |b| {
            b.iter(|| {
                for _ in 0..repeats {
                    Framebuffer::bench_pack_rgba_to_bgr24_scalar(black_box(&src), black_box(&mut dst))
                }
            })
        });
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn bench_pack_rgba_to_bgr24_avx2_sizes(c: &mut Criterion) {
    if !std::is_x86_feature_detected!("avx2") {
        return;
    }
    for &pixels in &[1024usize, 16384usize, 131072usize] {
        let mut src = generate_test_data(pixels * 4, 101);
        let mut dst = vec![0u8; pixels * 3];
        let id = format!("pack_rgba_bgr24_avx2_{}px", pixels);
        let repeats = bench_repeat_for_pixels(pixels);
        c.bench_function(&id, |b| {
            b.iter(|| {
                for _ in 0..repeats {
                    unsafe {
                        Framebuffer::bench_pack_rgba_to_bgr24_avx2(black_box(&src), black_box(&mut dst), pixels, true)
                    }
                }
            })
        });
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn bench_pack_rgba_to_bgr24_avx2_sizes(_c: &mut Criterion) {}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn bench_pack_rgba_to_bgr24_ssse3_sizes(c: &mut Criterion) {
    if !std::is_x86_feature_detected!("ssse3") {
        return;
    }
    for &pixels in &[1024usize, 16384usize, 131072usize] {
        let mut src = generate_test_data(pixels * 4, 53);
        let mut dst = vec![0u8; pixels * 3];
        let id = format!("pack_rgba_bgr24_ssse3_{}px", pixels);
        let repeats = bench_repeat_for_pixels(pixels);
        c.bench_function(&id, |b| {
            b.iter(|| {
                for _ in 0..repeats {
                    unsafe {
                        Framebuffer::bench_pack_rgba_to_bgr24_ssse3(black_box(&src), black_box(&mut dst), pixels, true)
                    }
                }
            })
        });
    }
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn bench_pack_rgba_to_bgr24_ssse3_sizes(_c: &mut Criterion) {}

// =============================================================================
// Large Buffer Benchmark (Cache Pressure)
// =============================================================================

fn bench_large_buffer(c: &mut Criterion) {
    // 4K resolution: 3840x2160 (~33MB)
    const WIDTH_4K: u32 = 3840;
    const HEIGHT_4K: u32 = 2160;

    let (_mem, mut fb) = setup_framebuffer(WIDTH_4K, HEIGHT_4K, PixelFormat::Bgra8888, 32, true);
    let img = Image::filled(WIDTH_4K, HEIGHT_4K, Color::with_alpha(64, 128, 192, 255));

    c.bench_function("draw_image_4k", |b| {
        b.iter(|| fb.draw_image(black_box(&img), 0, 0))
    });
}

// =============================================================================
// Criterion Groups
// =============================================================================

criterion_group! {
    name = image_benches;
    config = criterion_config();
    targets =
        bench_draw_image_bgra,
        bench_draw_image_rgba,
        bench_draw_image_bgr24,
        bench_draw_image_rgb565,
        bench_draw_image_mmio,
        bench_large_buffer
}

criterion_group! {
    name = packer_benches;
    config = criterion_config();
    targets =
        bench_pack_rgba_to_bgr24_dispatch,
        bench_pack_rgba_to_bgr24_scalar,
        bench_pack_rgba_to_bgr24_avx2,
        bench_pack_rgba_to_bgr24_ssse3,
        bench_pack_rgba_to_bgr24_neon,
        // 8-pixel micro-bench helpers
        bench_pack_rgba_to_bgr24_avx2_8pix_micro,
        bench_pack_rgba_to_bgr24_ssse3_8pix_micro,
        bench_pack_rgba_to_bgr24_neon_8pix_micro,
        bench_pack_rgba_to_bgr24_scalar_sizes,
        bench_pack_rgba_to_bgr24_avx2_sizes,
        bench_pack_rgba_to_bgr24_ssse3_sizes
}

criterion_main!(image_benches, packer_benches);
