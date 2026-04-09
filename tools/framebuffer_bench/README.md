# Framebuffer Bench

- Status: Component detail / benchmark guide
- Audience: framebuffer 描画パスの性能回帰を確認したい contributor
- Related: [ドキュメントハブ](../../docs/README.md), [性能目標](../../docs/reference/performance-targets.md), [baseline](bench-baseline.md)

## 概要

- 方針: workspace から切り離した専用 bench crate と baseline を使う

This small crate provides quick and reproducible micro/criterion benchmarks for the framebuffer draw paths.

Note: this crate has been intentionally left out of the workspace members and contains a local
`.cargo/config.toml` that clears `build-std` so it runs against the toolchain-provided `std`/`core`.
This prevents workspace `build-std` settings from causing duplicate-lang-item (E0152) errors
when running release/criterion benches.

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

## 関連文書

- [bench-baseline.md](bench-baseline.md)
- [../../docs/README.md](../../docs/README.md)
