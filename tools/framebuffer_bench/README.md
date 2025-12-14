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

A small helper script `compare_bench.py` is provided to compare current Criterion medians against a stored baseline (`BENCH_BASELINE.json`). The GitHub Action `perf.yml` runs the benches and invokes this comparison to detect regressions.

When the benchmark workflow runs on a Pull Request, it will automatically post a comment on the PR with the comparison results and upload Criterion artifacts (the `target/criterion` directory) as a workflow artifact. If any benchmark exceeds the configured regression threshold, the perf job will fail and block merging if the repository enforces status checks.
