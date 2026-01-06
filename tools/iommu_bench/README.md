# IOMMU Command Queue Bench

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

IOVA Bitmap performance tests are implemented as kernel unit tests due to
complex module dependencies. Run them with:

```bash
# Run all IOVA bitmap comparison tests
cargo test --package rany_kernel --target x86_64-exorust.json \
  -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem \
  test_bitmap_throughput

# Specific tests:
# - test_bitmap_throughput_comparison     - IovaBitmap vs IovaBitmapV2
# - test_allocator_simple_backend_comparison - IovaAllocatorSimple backends
# - test_2mb_allocation_comparison        - 2MB allocation comparison
```

These tests compare:
- **IovaBitmap (Legacy)**: Original implementation
- **IovaBitmapV2**: New implementation using HugePageBitmap from mm module
- **IovaAllocatorSimple**: Generic allocator with both backends