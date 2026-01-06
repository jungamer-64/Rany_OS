// Minimal I/O module for bench builds: expose only selected I/O pieces so
// benches can exercise the desired paths without compiling the entire
// I/O subsystem which pulls in many heavy dependencies and platform code.

#[path = "log.rs"]
pub mod log;

// Note: IOVA bitmap benchmarks require full mm module dependencies.
// For IOVA benchmarks, use kernel unit tests instead:
//   cargo test --package rany_kernel test_bitmap_throughput_comparison