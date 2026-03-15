// ============================================================================
// kernel/src/io/iommu/api/dispatcher.rs
// ============================================================================

use crate::io::iommu::runtime::backend::IommuBackend;
use crate::io::iommu::runtime::command::queue::IommuCommandKind;
use crate::io::iommu::runtime::registry::get_iommu_driver;
use crate::io::iommu::vendors::intel::controller::dma::DomainManager;

#[inline]
fn dispatch_iommu_command(
    ctrl: &crate::io::iommu::vendors::intel::controller::IommuController,
    kind: &IommuCommandKind,
) -> Result<i32, ()> {
    ctrl.handle_command_queue_entry(kind).map_err(|_| ())
}

/// Process pending IOMMU command queues for Intel/AMD backends.
///
/// This is used by the task executor and can be called by other runtime
/// dispatchers that need to make progress on queued IOMMU operations.
pub fn process_pending_command_queues() {
    // 1. Process Intel-specific controllers if registry is present
    if let Some(reg) = crate::io::iommu::vendors::intel::registry::get_iommu_registry() {
        for ctrl in &reg.controllers {
            if let Some(cq) = ctrl.command_queue_ref() {
                for _ in 0..4 {
                    let processed = cq.process_once(|kind| dispatch_iommu_command(ctrl, kind));
                    if processed == 0 {
                        break;
                    }
                }
            }
        }
    }

    // 2. Process active global backend (AMD queue)
    if let Some(driver) = get_iommu_driver() {
        if let IommuBackend::Amd(ref amd_driver) = **driver {
            if let Some(ref cq) = amd_driver.command_queue {
                for _ in 0..4 {
                    let processed =
                        cq.process_once(|kind| amd_driver.handle_command_queue_entry(kind));
                    if processed == 0 {
                        break;
                    }
                }
            }
        }
    }
}
