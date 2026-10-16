use crate::io::iommu::common::tables::HardwareTable;
use crate::io::iommu::types::{IommuDomainType, IommuError};
use crate::io::iommu::vendors::intel::controller::IommuController;
use crate::io::iommu::vendors::intel::controller::dma::DomainManager;
use crate::io::iommu::vendors::intel::tables::ContextEntry;
use alloc::sync::Arc;
use core::sync::atomic::Ordering;

struct RegisterMemory(core::cell::UnsafeCell<[u64; 512]>);
// SAFETY: the local controller alone accesses this retained aperture.
// No interrupt, device, worker or independent RAM borrow can access it.
unsafe impl Sync for RegisterMemory {}

fn unpublished_controller() -> IommuController {
    let mut words = [0; 512];
    words[1] = (2 << 8) | (47 << 16) | (0x30 << 24);
    words[2] = 0x20 << 8;
    let owner = Arc::new(RegisterMemory(core::cell::UnsafeCell::new(words)));
    let base = owner.0.get().cast::<u64>().addr();
    // SAFETY: construction transfers exclusive register access to the
    // controller, while the aperture's sole owner remains retained by it.
    let registers = unsafe { hal::MappedMmio::from_raw_parts(owner, base, 4096) }
        .expect("local retained registers");
    IommuController::new(registers, 0).expect("unpublished controller")
}

pub(crate) fn retained_iommu_ownership(dispose: impl FnOnce(IommuController, u16)) -> bool {
    let controller = unpublished_controller();
    let id = controller
        .create_domain(None, IommuDomainType::Translated)
        .expect("registered physical domain");
    let root = controller
        .domain(id)
        .expect("healthy lookup")
        .page_table_addr();
    {
        let mut hardware = controller.hardware.lock().expect("healthy hardware state");
        let mut table = HardwareTable::<ContextEntry>::new(256, None).expect("owned context RAM");
        table
            .get_mut(0)
            .unwrap()
            .set_sl_pt(root, id, controller.selected_agaw_code());
        table
            .get_mut(8)
            .unwrap()
            .set_sl_pt(root, id, controller.selected_agaw_code());
        hardware.legacy_context_tables.push(table);
    }
    // This fixture belongs to the lock implementation so it can construct
    // an unavailable local lock without exposing mutation authority to callers.
    // Guard poisoning itself is covered by the lock's native transition tests.
    controller.domains.poisoned.store(true, Ordering::Release);
    assert!(controller.domains.is_poisoned());
    assert!(controller.domain(id).is_none());
    assert_eq!(
        controller.create_domain(None, IommuDomainType::Translated),
        Err(IommuError::HardwareError)
    );
    assert_eq!(controller.destroy_domain(id), Err(IommuError::Poisoned));
    {
        let domains = controller
            .domains
            .lock()
            .err()
            .expect("poisoned registry")
            .into_inner();
        assert_eq!(domains.len(), 1);
        let retained = domains.get(&id).expect("retained domain owner");
        assert_eq!(retained.page_table_addr(), root);
        assert_eq!(Arc::strong_count(retained), 1);
    }

    controller.hardware.poisoned.store(true, Ordering::Release);
    assert_eq!(controller.disable_device_context_entry(0, 0, 0), Some(id));
    assert_eq!(controller.disable_device_context_entry(0, 0, 0), None);
    {
        let hardware = controller
            .hardware
            .lock()
            .expect_err("hardware stays poisoned")
            .into_inner();
        assert_eq!(hardware.legacy_context_tables.len(), 1);
        let table = &hardware.legacy_context_tables[0];
        assert!(!table.get(0).unwrap().is_present());
        assert!(table.get(8).unwrap().is_present());
        assert_eq!(table.get(8).unwrap().domain_id(), id);
        assert!(hardware.root_table.is_none());
        assert!(hardware.scalable_context_tables.is_empty());
    }
    assert!(
        controller
            .device_domains
            .lock()
            .expect("no device publication")
            .is_empty()
    );
    // Ownership crosses to the IOMMU test scope for its restricted physical
    // retirement operation. No fixture borrow survives this transfer.
    dispose(controller, id);
    true
}
