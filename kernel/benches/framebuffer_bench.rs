//! Framebuffer benchmark suite
//!
//! Comprehensive benchmarks for framebuffer graphics operations including:
//! - Image drawing (opaque/various formats)
//! - SIMD packer performance (scalar/SSSE3/AVX2/NEON)

use criterion::{Criterion, criterion_group, criterion_main};
use graphic_types::{Color, PixelFormat};
use rany_os::graphics::framebuffer::Framebuffer;
use rany_os::graphics::framebuffer::{FramebufferLayout, PixelBuffer};
use rany_os::graphics::image::Image;
use std::hint::black_box;
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
    eprintln!(
        "bench_repeat_for_pixels: pixels={} -> repeats={}",
        pixels, repeats
    );
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
    double_buffer: bool,
) -> Framebuffer {
    let layout = FramebufferLayout::new(
        width,
        height,
        width * format.bytes_per_pixel() as u32,
        format,
    )
    .expect("benchmark geometry");
    let mut fb = Framebuffer::new(layout, PixelBuffer::Memory(vec![0; layout.size()]))
        .expect("benchmark framebuffer workspace");
    if double_buffer {
        fb.enable_double_buffering().expect("benchmark back plane");
    }
    fb
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
    let mut fb = setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Bgra8888, true);
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
    let mut fb = setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Rgba8888, true);
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
    let mut fb = setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Bgr888, true);
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
    let mut fb = setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Rgb565, true);
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

fn bench_draw_image_ram_front(c: &mut Criterion) {
    // MMIO path (no double buffering)
    let mut fb = setup_framebuffer(BENCH_WIDTH, BENCH_HEIGHT, PixelFormat::Bgra8888, false);
    let img = Image::filled(
        BENCH_WIDTH,
        BENCH_HEIGHT,
        Color::with_alpha(64, 128, 192, 255),
    );

    let pixels = BENCH_WIDTH as usize * BENCH_HEIGHT as usize;
    let repeats = bench_repeat_for_pixels(pixels);

    c.bench_function("draw_image_ram_front", |b| {
        b.iter(|| {
            for _ in 0..repeats {
                fb.draw_image(black_box(&img), 0, 0)
            }
        })
    });
}

// =============================================================================
// SIMD packer throughput uses the same dispatcher and scalar routine as rendering.
// The instruction set is admitted by the production CPU detector.
fn bench_packers(c: &mut Criterion) {
    for pixels in [8, 64, 1024, BENCH_WIDTH as usize * BENCH_HEIGHT as usize] {
        let source = generate_test_data(pixels * 4, 97);
        let mut destination = vec![0; pixels * 3];
        c.bench_function(&format!("pack_rgba_bgr24_dispatch_{pixels}"), |b| {
            b.iter(|| {
                rany_os::graphics::packer::pack_rgba_to_bgr24(
                    black_box(&source),
                    black_box(&mut destination),
                    true,
                )
            });
        });
        c.bench_function(&format!("pack_rgba_bgr24_scalar_{pixels}"), |b| {
            b.iter(|| {
                rany_os::graphics::packer::pack_rgba_to_bgr24_scalar(
                    black_box(&source),
                    black_box(&mut destination),
                    true,
                )
            });
        });
    }
}

fn bench_large_buffer(c: &mut Criterion) {
    // 4K resolution: 3840x2160 (~33MB)
    const WIDTH_4K: u32 = 3840;
    const HEIGHT_4K: u32 = 2160;

    let mut fb = setup_framebuffer(WIDTH_4K, HEIGHT_4K, PixelFormat::Bgra8888, true);
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
        bench_draw_image_ram_front,
        bench_large_buffer
}

criterion_group! {
    name = packer_benches;
    config = criterion_config();
    targets = bench_packers
}

criterion_main!(image_benches, packer_benches);
