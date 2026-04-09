# IOMMU Command Queue Bench

- Status: Component detail / benchmark guide
- Audience: IOMMU command queue / IOVA allocator の性能を追う contributor
- Related: [ドキュメントハブ](../../docs/README.md), [カーネルブートシーケンス](../../docs/kernel-boot-sequence.md), [性能目標](../../docs/reference/performance-targets.md)

## 概要

- 方針: host 側 microbench と full-boot QEMU 検証の入口をまとめる

Small Criterion-based microbench for `CommandQueue` throughput/latency.

Usage examples:

- Quick run (debug):
  cargo run --manifest-path tools/iommu_bench/Cargo.toml

- Full Criterion (release):
  cargo run --manifest-path tools/iommu_bench/Cargo.toml --release -- criterion

Benchmarks included:

- cq_submit_sync_single_thread
- cq_submit_sync_4_producers
- cq_submit_async_single_thread

## IOVA Bitmap Benchmarks

IOVA Bitmap performance tests are migrated into the QEMU full-boot flow.
Run through the official 2-layer entrypoints:

```bash
# Run host pure tier
cargo test

# Run full-boot required tier
cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture
```

These tests compare:

- **IovaBitmap (Legacy)**: Original implementation
- **IovaBitmapV2**: New implementation using HugePageBitmap from mm module
- **IovaAllocatorSimple**: Generic allocator with both backends

## 関連文書

- [../../docs/README.md](../../docs/README.md)
- [../../docs/kernel-boot-sequence.md](../../docs/kernel-boot-sequence.md)
