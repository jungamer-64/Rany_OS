# Framebuffer Bench

This small crate provides quick and reproducible micro/criterion benchmarks for the framebuffer draw paths.

Quick runs (no Criterion statistics):

```powershell
# quick run
cargo run --manifest-path tools/framebuffer_bench/Cargo.toml --release
```

Full Criterion run (produces target/criterion output and statistical summaries):

```powershell
# run full Criterion benches
cargo run --manifest-path tools/framebuffer_bench/Cargo.toml --release -- criterion
```

The runner exercises draw_image with three formats: BGRA8888, BGR888 (24-bit) and RGBA8888.
