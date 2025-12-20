// Minimal I/O module for bench builds: expose only selected I/O pieces so
// benches can exercise the desired paths without compiling the entire
// I/O subsystem which pulls in many heavy dependencies and platform code.

#[path = "log.rs"]
pub mod log;

// Include the CommandQueue implementation for IOMMU microbenchmarks
#[path = "iommu_cmdqueue.rs"]
pub mod iommu_cmdqueue;