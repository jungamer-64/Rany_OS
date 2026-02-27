// ============================================================================
// kernel/src/io/iommu/backends/intel/driver_ops/domain_query.rs
// ============================================================================

use super::*;

impl IntelIommuDriver {

    /// Get domain by ID
    pub(crate) fn get_domain(&self, domain_id: u16) -> Result<Arc<IommuDomain>, IommuError> {
        let registry = self.registry()?;
        for controller in &registry.controllers {
            if let Some(domain_arc) = controller.domain(domain_id) {
                return Ok(domain_arc);
            }
        }
        Err(IommuError::DomainNotFound)
    }

    pub(crate) fn get_domain_numa(&self, domain_id: u16) -> Result<Option<usize>, IommuError> {
        let registry = self.registry()?;
        for controller in &registry.controllers {
            if let Some(domain_arc) = controller.domain(domain_id) {
                return Ok(domain_arc.numa_node());
            }
        }

        Err(IommuError::DomainNotFound)
    }



    /// Lookup the domain ID for a device.
    pub(crate) fn lookup_device_domain(&self, source_id: u16) -> Option<u16> {
        let registry = self.registry().ok()?;

        // Parse source_id into bus/dev/func
        let bus = ((source_id >> 8) & 0xFF) as u8;
        let devfn = (source_id & 0xFF) as u8;

        for controller in &registry.controllers {
            if let Some(domain_id) = controller.device_to_domain(bus, devfn) {
                return Some(domain_id);
            }
        }

        None
    }

    pub(crate) fn dump_diagnostics(&self) {
        let registry = match self.registry() {
            Ok(r) => r,
            Err(e) => {
                log::warn!("[IOMMU] diagnostics skipped: registry unavailable ({:?})", e);
                return;
            }
        };

        for (idx, controller) in registry.controllers.iter().enumerate() {
            match controller.qi_stats() {
                Ok(Some(stats)) => {
                    log::info!(
                        "[IOMMU] Ctrl #{} seg={} QI: submits={} full_checks={} head_refreshes={} waits={} wait_timeouts={}",
                        idx,
                        controller.segment,
                        stats.submits,
                        stats.full_checks,
                        stats.head_refreshes,
                        stats.waits,
                        stats.wait_timeouts
                    );
                    if stats.full_checks > 0 || stats.waits > 0 {
                        log::warn!(
                            "[IOMMU] Ctrl #{} seg={} QI pressure detected (full_checks={}, waits={})",
                            idx,
                            controller.segment,
                            stats.full_checks,
                            stats.waits
                        );
                    }
                }
                Ok(None) => {
                    log::info!(
                        "[IOMMU] Ctrl #{} seg={} QI not initialized",
                        idx,
                        controller.segment
                    );
                }
                Err(e) => {
                    log::warn!(
                        "[IOMMU] Ctrl #{} seg={} QI stats unavailable ({:?})",
                        idx,
                        controller.segment,
                        e
                    );
                }
            }
        }
    }
}
