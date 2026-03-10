// framebuffer_bench/src/main.rs
use criterion::{Criterion, black_box};
use std::env;

use rany_os::graphics::framebuffer::Framebuffer;
use rany_os::graphics::framebuffer::{current_packer_mode, force_packer_mode};
use rany_os::graphics::image::Image;
use rany_os::graphics::{Color, FramebufferInfo, PixelFormat};

fn setup_fb(info: &FramebufferInfo) -> (Vec<u8>, Framebuffer, Image) {
    let mut mem = vec![0u8; info.size()];
    let addr = mem.as_mut_ptr() as u64;
    let mut info2 = info.clone();
    info2.address = addr;

    let fb = unsafe { Framebuffer::new(info2) };
    let img = Image::filled(
        info.width,
        info.height,
        Color::with_alpha(64, 128, 192, 255),
    );
    (mem, fb, img)
}

fn bench_draw_image_with_criterion(c: &mut Criterion) {
    let width = 800u32;
    let height = 600u32;

    let info_bgra = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };

    let info_bgr24 = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 3,
        format: PixelFormat::Bgr888,
        bpp: 24,
    };

    let info_rgba = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 4,
        format: PixelFormat::Rgba8888,
        bpp: 32,
    };

    let (_mem_bgra, mut fb_bgra, img_bgra) = setup_fb(&info_bgra);
    c.bench_function("draw_image_bgra", |b| {
        b.iter(|| fb_bgra.draw_image(black_box(&img_bgra), 0, 0))
    });

    let (_mem_bgr24, mut fb_bgr24, img_bgr24) = setup_fb(&info_bgr24);
    c.bench_function("draw_image_bgr24", |b| {
        b.iter(|| fb_bgr24.draw_image(black_box(&img_bgr24), 0, 0))
    });

    let (_mem_rgba, mut fb_rgba, img_rgba) = setup_fb(&info_rgba);
    c.bench_function("draw_image_rgba", |b| {
        b.iter(|| fb_rgba.draw_image(black_box(&img_rgba), 0, 0))
    });

    // Draw-line micro-benchmark: many short/long lines across the framebuffer
    let (_mem_lines, mut fb_lines, _img) = setup_fb(&info_bgra);
    // Precompute deterministic list of lines
    let mut lines = Vec::new();
    for i in 0..1000u32 {
        let x1 = (i % width) as i32;
        let y1 = ((i * 3) % height) as i32;
        let x2 = ((i * 7 + 13) % width) as i32;
        let y2 = ((i * 11 + 29) % height) as i32;
        lines.push((x1, y1, x2, y2));
    }
    c.bench_function("draw_line_many", |b| {
        b.iter(|| {
            for &(x1, y1, x2, y2) in &lines {
                fb_lines.draw_line(x1, y1, x2, y2, Color::with_alpha(10, 20, 30, 255));
            }
        })
    });

    // Also run the naive version when available (bench feature exposes it) to compare
    c.bench_function("draw_line_many_naive", |b| {
        b.iter(|| {
            for &(x1, y1, x2, y2) in &lines {
                fb_lines.draw_line_naive(x1, y1, x2, y2, Color::with_alpha(10, 20, 30, 255));
            }
        })
    });

    // Packer micro-bench: measure pure packer throughput
    let pack_width = 1280u32;
    let pack_height = 720u32;
    let buf_len = (pack_width * pack_height * 4) as usize;
    let mut src_pack = vec![0u8; buf_len];
    for i in 0..buf_len {
        src_pack[i] = (i * 73 % 251) as u8;
    }
    let mut dst_pack = vec![0u8; buf_len];
    let mut dst_pack2 = vec![0u8; buf_len];

    c.bench_function("pack_rgba_scalar", |b| {
        b.iter(|| {
            Framebuffer::pack_rgba_to_bgra_scalar(&src_pack, &mut dst_pack);
        })
    });

    c.bench_function("pack_rgba_dispatch", |b| {
        b.iter(|| {
            Framebuffer::pack_rgba_to_bgra(&src_pack, &mut dst_pack2);
        })
    });

    // If AVX2 present, benchmark it specifically
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if std::is_x86_feature_detected!("avx2") {
        // Measure dispatch path when AVX2 is available (will hit AVX2 implementation)
        let mut dst_dispatch = vec![0u8; buf_len];
        c.bench_function("pack_rgba_dispatch_avx2", |b| {
            b.iter(|| {
                Framebuffer::pack_rgba_to_bgra(&src_pack, &mut dst_dispatch);
            })
        });
    }

    // New Benchmarks for Logic Improvements

    // 1. Text Rendering (LUT vs Check)
    // We use long text to amortize setup costs
    let text = "The quick brown fox jumps over the lazy dog. 0123456789!@#$%^&*()";
    c.bench_function("draw_text_32bit", |b| {
        b.iter(|| {
            fb_bgra.draw_text(100, 100, text, Color::WHITE, Color::BLACK);
        })
    });

    // 2. Alpha Blending Integration
    let img_alpha = Image::filled(width, height, Color::with_alpha(64, 128, 192, 128));
    c.bench_function("draw_image_alpha", |b| {
        b.iter(|| {
            fb_bgra.draw_image(black_box(&img_alpha), 0, 0);
        })
    });

    // 3. Fill Rect (Dirty Rect overhead check)
    c.bench_function("fill_rect_full", |b| {
        b.iter(|| {
            fb_bgra.fill_rect(
                rany_os::graphics::Rect::new(0, 0, width, height),
                Color::BLUE,
            );
        })
    });

    // 4. Large Buffer Simulation (Bandwidth/Cache-Thrashing)
    // Use 8K resolution (7680x4320) ~132MB to force main memory access (exceed L3 cache)
    let width_8k = 7680u32;
    let height_8k = 4320u32;
    let info_8k = FramebufferInfo {
        address: 0, // setup_fb will patch this
        width: width_8k,
        height: height_8k,
        stride: width_8k * 4,
        format: PixelFormat::Bgra8888,
        bpp: 32,
    };
    // Note: Allocates ~132MB
    let (_mem_8k, mut fb_8k, _img) = setup_fb(&info_8k);
    let rect_8k = rany_os::graphics::Rect::new(0, 0, width_8k, height_8k);

    c.bench_function("large_buffer_fill_8k", |b| {
        b.iter(|| {
            // Fill entire 8K buffer
            fb_8k.fill_rect(black_box(rect_8k), Color::BLUE);
        })
    });

    // 5. Rgb565 Benchmark (16-bit Color)
    // Measures 16-bit specific performance (currently fallback path or bandwidth savings)
    let info_565 = FramebufferInfo {
        address: 0,
        width,
        height,
        stride: width * 2,
        format: PixelFormat::Rgb565,
        bpp: 16,
    };
    let (_mem_565, mut fb_565, img_565) = setup_fb(&info_565);
    c.bench_function("draw_image_rgb565", |b| {
        b.iter(|| {
            fb_565.draw_image(black_box(&img_565), 0, 0);
        })
    });

    // 6. BGR write path micro-bench (small and large runs)
    let (_mem_bgr24_mmio, mut fb_bgr24_mmio, _img_bgr24) = setup_fb(&info_bgr24);
    // small runs (exercise direct MMIO fast-path)
    for &sz in &[1usize, 2, 4, 8] {
        let name = format!("write_bgr_small_{}", sz);
        c.bench_function(&name, |b| {
            b.iter(|| {
                fb_bgr24_mmio.bench_write_bgr_run_pixels(0, 0, sz, Color::with_alpha(5, 6, 7, 255));
            })
        });
    }
    // large runs
    for &sz in &[128usize, 1024usize, 8192usize] {
        let name = format!("write_bgr_large_{}", sz);
        c.bench_function(&name, |b| {
            b.iter(|| {
                fb_bgr24_mmio.bench_write_bgr_run_pixels(0, 0, sz, Color::with_alpha(5, 6, 7, 255));
            })
        });
    }

    // Also measure the back-buffer path (memory copy)
    let mut fb_bgr24_back = unsafe { Framebuffer::new(info_bgr24.clone()) };
    fb_bgr24_back.enable_double_buffering();
    for &sz in &[1usize, 8usize, 1024usize] {
        let name = format!("write_bgr_backbuf_{}", sz);
        c.bench_function(&name, |b| {
            b.iter(|| {
                fb_bgr24_back.bench_write_bgr_run_pixels(0, 0, sz, Color::with_alpha(5, 6, 7, 255));
            })
        });
    }

    // 7. write_bytes_mmio micro-bench: small/large byte runs
    let data_small = vec![0u8; 16];
    let data_large = vec![0u8; 16384];
    c.bench_function("write_bytes_small_16", |b| {
        b.iter(|| {
            fb_bgr24_mmio.bench_write_bytes_mmio(0, 0, &data_small);
        })
    });
    c.bench_function("write_bytes_large_16k", |b| {
        b.iter(|| {
            fb_bgr24_mmio.bench_write_bytes_mmio(0, 0, &data_large);
        })
    });

    // 8. Forced packer benchmarks (deterministic selection via bench helper)
    // Ensure we can force packer modes for comparison
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // Scalar (baseline)
        force_packer_mode(1);
        c.bench_function("pack_rgba_forced_scalar", |b| {
            b.iter(|| {
                Framebuffer::pack_rgba_to_bgra(&src_pack, &mut dst_pack2);
            })
        });

        // If AVX2 available, force it and measure
        if std::is_x86_feature_detected!("avx2") {
            force_packer_mode(3);
            c.bench_function("pack_rgba_forced_avx2", |b| {
                b.iter(|| {
                    Framebuffer::pack_rgba_to_bgra(&src_pack, &mut dst_pack2);
                })
            });
        }
    }
}

fn main() {
    // If the user runs `cargo run`, accept optional argument "criterion" to run Criterion benches,
    // otherwise fall back to a small custom micro-benchmark for quick numbers.
    let args: Vec<String> = env::args().collect(); // nosemgrep: codacy.tools-configs.rust.lang.security.args.args
    if args.iter().any(|a| a == "criterion") {
        let mut c = Criterion::default();
        bench_draw_image_with_criterion(&mut c);
        c.final_summary();
    } else {
        // fallback: quick micro-bench using Criterion's simple bench to get a summary-like output
        println!(
            "Running quick Criterion benches (use `cargo run --release -- criterion` for full results)"
        );
        let mut c = Criterion::default();
        bench_draw_image_with_criterion(&mut c);
        c.final_summary();
    }
}
