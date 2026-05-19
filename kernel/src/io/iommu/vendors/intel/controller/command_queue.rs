// ============================================================================
// kernel/src/io/iommu/vendors/intel/controller/command_queue.rs
// ============================================================================

//! Support routines for the IOMMU controller command queue.
//!
//! The IOMMU controller optionally maintains a `CommandQueue` instance to
//! offload certain operations (map/unmap, invalidation) to the device.  The
//! helper methods here encapsulate the boilerplate used by both the controller
//! implementation and driver code.

use super::IommuController;

impl IommuController {
    /// Process one entry from the command queue (used during initialization)
    pub(crate) fn process_command_queue_once(&self) {
        if let Some(cq) = self.command_queue_ref() {
            let _ = cq.process_once(|_k| Ok(0));
        }
    }
}
