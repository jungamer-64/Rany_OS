// ============================================================================
// kernel/src/io/iommu/testkit/fixtures/mod.rs
// ============================================================================

#[cfg(any(test, feature = "qemu-test-export"))]
use alloc::sync::Arc;

#[cfg(feature = "qemu-test-export")]
pub use crate::io::iommu::testkit::qemu::wave2::MockSecurityNotifier;

#[cfg(any(test, feature = "qemu-test-export"))]
pub fn ensure_test_intel_iommu_device(device: crate::io::iommu::types::DeviceId) {
    use crate::io::iommu::types::IommuDomainType;
    use crate::io::iommu::vendors::intel::IntelIommuDriver;
    use crate::io::iommu::vendors::intel::controller::IommuController;
    use crate::io::iommu::vendors::intel::controller::dma::DomainManager;
    use crate::io::iommu::vendors::intel::controller::iova::IovaManager;
    use crate::io::iommu::vendors::intel::registry::{
        IommuRegistry, get_iommu_registry, init_registry,
    };

    let controller = if let Some(registry) = get_iommu_registry() {
        registry
            .controllers
            .first()
            .cloned()
            .expect("test IOMMU registry missing controller")
    } else {
        let controller = Arc::new(IommuController::new(0, device.segment));
        init_registry(IommuRegistry {
            controllers: alloc::vec![controller.clone()],
            default_iommu_idx: Some(0),
            reserved_regions: alloc::vec![],
        });
        controller
    };

    let _ = controller.init_iova(0x1000, 0x1_0000_0000 - 0x1000);
    if crate::io::iommu::runtime::registry::get_iommu_driver().is_none() {
        IntelIommuDriver::register_driver();
    }

    let mut device_domains = controller
        .device_domains
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if device_domains.contains_key(&device) {
        return;
    }
    let domain_id = controller
        .create_domain(None, IommuDomainType::Translated)
        .expect("create test IOMMU domain");
    device_domains.insert(device, domain_id);
}
