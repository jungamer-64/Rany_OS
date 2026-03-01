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
        let mut first_err = None;

        for controller in &registry.controllers {
            if let Err(e) = controller.invalidate_iotlb(domain_id, any_ats) {
                log::error!(
                    "[IOMMU][SECURITY] IOTLB invalidation failed on controller seg={}: {:?}",
                    controller.segment,
                    e
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }

        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    /// Invalidate all IOTLB entries globally.
    pub(crate) fn invalidate_iotlb_global(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;
        let mut first_err = None;

        for controller in &registry.controllers {
            // Use global invalidation - domain_id 0 with special flag
            // The controller's invalidate_iotlb_global handles this
            if let Err(e) = controller.invalidate_iotlb_global_sync() {
                log::error!(
                    "[IOMMU][SECURITY] Global IOTLB invalidation failed on controller seg={}: {:?}",
                    controller.segment,
                    e
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }

        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }

    /// Invalidate context cache globally.
    pub(crate) fn invalidate_context_global(&self) -> Result<(), IommuError> {
        let registry = self.registry()?;
        let mut first_err = None;

        for controller in &registry.controllers {
            if let Err(e) = controller.invalidate_context_global_sync() {
                log::error!(
                    "[IOMMU][SECURITY] Global context cache invalidation failed on controller seg={}: {:?}",
                    controller.segment,
                    e
                );
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }

        if let Some(e) = first_err {
            Err(e)
        } else {
            Ok(())
        }
    }
}
