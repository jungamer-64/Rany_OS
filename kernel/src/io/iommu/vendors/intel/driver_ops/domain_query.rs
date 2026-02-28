// ============================================================================
// kernel/src/io/iommu/vendors/intel/driver_ops/domain_query.rs
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
}
