// Minimal I/O module for bench builds: expose only selected I/O pieces so
// benches can exercise the desired paths without compiling the entire
// I/O subsystem which pulls in many heavy dependencies and platform code.

#[path = "log/mod.rs"]
pub mod log;

pub mod iommu {
    #[path = "types/mod.rs"]
    pub mod types;
}

#[path = "iommu/runtime/command/queue.rs"]
pub mod iommu_cmdqueue;

// Note: IOVA bitmap benchmarks require full mm module dependencies.
// For runtime coverage on QEMU, use the full-boot required profile:
//   cargo test -p qemu-tests fullboot_pr_required -- --exact --nocapture
