FrameBuffer Bench Baseline
==========================

Recorded on: 2025-12-14
Host: Windows (local dev environment)

Command used:
```
cargo run --manifest-path tools/framebuffer_bench/Cargo.toml --release -- "criterion"
```

Results (99% CI ranges from Criterion):

- draw_image_bgra: time: [274.13 µs 280.51 µs 288.23 µs]
- draw_image_bgr24: time: [1.1955 ms 1.2250 ms 1.2597 ms]
- draw_image_rgba: time: [779.29 µs 803.49 µs 831.85 µs]
- draw_line_many: time: [944.46 µs 965.60 µs 990.13 µs]

Notes:
- BGRA and RGBA paths use u32/u64-aligned bulk writes when possible.
- 24-bit path uses an unrolled pack into a byte scratch buffer and bulk writes.
- write_bytes_mmio and write_u32_slice_mmio include loop unrolling for improved throughput on large writes.
