// ============================================================================
// kernel/src/io/iommu/mod.rs
// ============================================================================

//!
//! IOMMU Support (Intel VT-d / AMD-Vi)
//!
pub mod api;
pub mod types;

// Layered module namespaces
pub(crate) mod common;
pub(crate) mod runtime;
pub(crate) mod vendors;

#[cfg(test)]
pub(crate) mod testkit;

#[cfg(feature = "qemu-test-export")]
pub(crate) mod qemu_tests {
    pub mod wave3 {
        pub fn cmdqueue_reclaim_completed_slot_smoke() -> bool {
            crate::io::iommu::runtime::command::queue::qemu_smoke_reclaim_completed_slot()
        }

        pub fn cmdqueue_cancel_queued_command_smoke() -> bool {
            crate::io::iommu::runtime::command::queue::qemu_smoke_cancel_queued_command()
        }

        pub fn cmdqueue_drop_triggers_cancel_smoke() -> bool {
            crate::io::iommu::runtime::command::queue::qemu_smoke_drop_triggers_cancel()
        }

        pub fn cmdqueue_process_up_to_respects_fuel_smoke() -> bool {
            crate::io::iommu::runtime::command::queue::qemu_smoke_process_up_to_respects_fuel()
        }

        pub fn cmdqueue_fuel_shim_basic_smoke() -> bool {
            crate::io::iommu::runtime::command::queue::qemu_smoke_fuel_shim_basic()
        }

        pub fn cmdqueue_metrics_counts_smoke() -> bool {
            crate::io::iommu::runtime::command::queue::qemu_smoke_metrics_counts()
        }
    }
}

// End of file
