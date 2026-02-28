// ============================================================================
// kernel/src/io/iommu/vendors/intel/driver_ops/invalidation.rs
// ============================================================================

use super::*;

impl IntelIommuDriver {
    // ========================================================================
    // Flush Operations (for emergency isolation)
    // ========================================================================

    /// Invalidate IOTLB entries for a specific domain.
    pub(crate) fn invalidate_iotlb(
        &self,
        domain_id: u16,
        _iova: Option<u64>,
        any_ats: bool,
    ) -> Result<(), IommuError> {
        let registry = self.registry()?;

        for controller in &registry.controllers {
            controller.invalidate_iotlb(domain_id, any_ats);
        }

        Ok(())
    }

    /// Invalidate all IOTLB entries globally.
    pub(crate) fn invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;

        for controller in &registry.controllers {
            // Use global invalidation - domain_id 0 with special flag
            // The controller's invalidate_iotlb_global handles this
            if let Err(e) = controller.invalidate_iotlb_global_sync() {
                log::warn!(
                    "[IOMMU] Global IOTLB invalidation failed on controller seg={}: {:?}",
                    controller.segment,
                    e
                );
            }
        }

        Ok(())
    }

    /// Invalidate context cache globally.
    pub(crate) fn invalidate_context_global(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;

        for controller in &registry.controllers {
            if let Err(e) = controller.invalidate_context_global_sync() {
                log::warn!(
                    "[IOMMU] Global context cache invalidation failed on controller seg={}: {:?}",
                    controller.segment,
                    e
                );
            }
        }

        Ok(())
    }
}
