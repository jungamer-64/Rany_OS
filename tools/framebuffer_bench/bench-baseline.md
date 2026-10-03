# Framebuffer Bench Baseline

## 概要

- 対象: 現行ベンチマークの比較基準を確認したい contributor
- 方針: 計測日、コマンド、結果、補足を短く保持する
- 関連: [README.md](README.md), [../../docs/README.md](../../docs/README.md)

Recorded on: 2025-12-15
Host: Windows (local dev environment)

Command used:

```text
cargo run --manifest-path tools/framebuffer_bench/Cargo.toml --release -- "criterion"
```

Results (99% CI ranges from Criterion):

- draw_image_bgra: time: [276.99 µs 281.63 µs 287.43 µs]
- draw_image_bgr24: time: [1.1322 ms 1.1512 ms 1.1722 ms]
- draw_image_rgba: time: [723.42 µs 729.59 µs 737.17 µs]
- draw_line_many: time: [862.75 µs 868.24 µs 874.10 µs]

## 関連文書

- [README.md](README.md)
- [../../docs/README.md](../../docs/README.md)
