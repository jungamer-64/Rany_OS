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

