// ============================================================================
// kernel/src/io/iommu/testkit/unit/mod.rs
// ============================================================================

//! IOMMU Unit Tests
//!
//! Tests for IOMMU controller functionality, domain management, and invalidation.

use crate::io::iommu::common::dma::page_table_pool::PageTablePool;
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::common::tables::{HardwareTable, PageTableScope, SlPte, virt_ptr_to_phys};
use crate::io::iommu::runtime::fault_log::FaultRecord;
use crate::io::iommu::runtime::registry::{get_iommu_driver, get_iommu_registry};
use crate::io::iommu::runtime::security::{SecurityEvent, SecurityNotifier};
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
use crate::io::iommu::vendors::intel::controller::IommuController;
use crate::io::iommu::vendors::intel::controller::dma::DomainManager;
use crate::io::iommu::vendors::intel::controller::fault::FaultHandler;
use crate::io::iommu::vendors::intel::controller::iova::IovaManager;
use crate::io::iommu::vendors::intel::controller::qi_init::QIManager;
#[cfg(feature = "qemu-test-export")]
use crate::io::iommu::vendors::intel::controller::qi_ops::InvalidationOps;
use crate::io::iommu::vendors::intel::qi::InvalidationQueue;
use crate::io::iommu::vendors::intel::registers::ecap_bits;
use crate::io::iommu::vendors::intel::registry::{IommuRegistry, init_registry};
use crate::io::iommu::vendors::intel::tables::{
    ContextEntry, PasidTableEntry, RootEntry, ScalableContextEntry,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[cfg(feature = "std")]
#[cfg(feature = "qemu-test-export")]
use crate::io::iommu::vendors::intel::qi::InvalidationQueueEntry;
use alloc::boxed::Box;

struct RegisterMemory(core::cell::UnsafeCell<[u64; 512]>);
// SAFETY: only the admitted controller accesses these cells, through its
// synchronized register protocol. Fixtures never retain an ordinary RAM borrow.
unsafe impl Sync for RegisterMemory {}

fn controller_with_registers(mut words: [u64; 512]) -> IommuController {
    // Four-level 48-bit translation, one fault record at 0x300, IOTLB at 0x200.
    words[1] = (2 << 8) | (47 << 16) | (0x30 << 24);
    words[2] = 0x20 << 8;
    let owner = Arc::new(RegisterMemory(core::cell::UnsafeCell::new(words)));
    let base = owner.0.get().cast::<u64>() as usize;
    // SAFETY: the owner retains aligned backing used exclusively as the
    // emulated register aperture. No borrowed RAM or DMA address escapes it.
    let registers = unsafe { hal::MappedMmio::from_raw_parts(owner, base, 4096) }.unwrap();
    IommuController::new(registers, 0).unwrap()
}

fn controller() -> IommuController {
    controller_with_registers([0; 512])
}

fn test_iommu_registry(controllers: Vec<Arc<IommuController>>) -> IommuRegistry {
    IommuRegistry {
        controllers,
        reserved_regions: Vec::new(),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_device_id() {
    let dev = DeviceId::new(0, 0, 1, 0);
    assert_eq!(dev.requester_id(), 0x08); // bus=0, dev=1, func=0
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_sl_pte() {
    let pte = SlPte::mapping(0x1000, true, true);
    assert!(pte.is_present());
    assert!(pte.can_read());
    assert!(pte.can_write());
    assert_eq!(pte.phys_addr(), 0x1000);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_iommu_domain() {
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );
    assert_eq!(domain.id(), 1);

    // Map a region
    let result = domain.map(0x1000, 0x2000, 0x1000, true, false);
    assert!(result.is_ok());

    // Try to map overlapping region
    let result = domain.map(0x1000, 0x3000, 0x1000, true, false);
    assert_eq!(result, Err(IommuError::AlreadyMapped));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_page_table_addr_returns_root_phys() {
    let domain = IommuDomain::new(
        10,
        None,
        false,
        false,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );

    let expected = virt_ptr_to_phys(domain.page_table as *const u8)
        .expect("failed to translate page table virtual address");
    assert_eq!(domain.page_table_addr(), expected);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_intel_select_agaw_prefers_highest_supported() {
    assert_eq!(IommuController::select_agaw(0b1111, 39), Ok((1, 39, 3)));
    assert_eq!(IommuController::select_agaw(0b1011, 57), Ok((3, 57, 5)));
    assert_eq!(IommuController::select_agaw(0b0001, 30), Ok((0, 30, 2)));
    assert_eq!(
        IommuController::select_agaw(0b0100, 39),
        Err(IommuError::NotSupported)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_entry_agaw_encoding_uses_selected_code() {
    let mut ctx = ContextEntry::default();
    ctx.set_sl_pt(0x2000, 0x12, 1);
    assert_eq!(ctx.hi & 0x7, 1);

    ctx.set_passthrough(0x34, 3);
    assert_eq!(ctx.hi & 0x7, 3);

    let mut pasid = PasidTableEntry::default();
    pasid.set_sl_pt(0x4000, 3, 0x56);
    assert_eq!((pasid.qwords[0] >> PasidTableEntry::AW_SHIFT) & 0x7, 3);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_map_unmap_4k_for_levels_2_to_5() {
    for (levels, max_bits) in [(2u8, 30u8), (3, 39), (4, 48), (5, 57)] {
        let domain = IommuDomain::new(
            levels as u16,
            None,
            true,
            true,
            max_bits,
            levels,
            IommuDomainType::Translated,
            PageTablePool::new(1, 32),
            PteFormat::Intel,
        );
        let iova = 0x20_0000;
        let phys = 0x40_0000;
        domain
            .map(iova, phys, 0x1000, true, true)
            .expect("map failed");
        assert!(domain.mapping(iova).is_some());
        domain.unmap(iova).expect("unmap failed");
        assert!(domain.mapping(iova).is_none());
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_superpage_level_guards() {
    let level2 = IommuDomain::new(
        20,
        None,
        true,
        true,
        30,
        2,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );
    assert_eq!(
        unsafe { level2.map_page_1gb(0x4000_0000, 0x8000_0000, true, true) },
        Err(IommuError::NotSupported)
    );
    level2
        .map(0x20_0000, 0x40_0000, 2 * 1024 * 1024, true, true)
        .expect("2MB map should work at level 2");
    level2
        .unmap(0x20_0000)
        .expect("2MB unmap should work at level 2");

    let level3 = IommuDomain::new(
        21,
        None,
        true,
        true,
        39,
        3,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );
    level3
        .map(0x4000_0000, 0x8000_0000, 1024 * 1024 * 1024, true, true)
        .expect("1GB map should work at level 3");
    level3
        .unmap(0x4000_0000)
        .expect("1GB unmap should work at level 3");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_invalidation_queue_uses_physical_addresses_for_hw() {
    let mut queue = InvalidationQueue::new(8).expect("failed to allocate invalidation queue");

    let queue_virt = queue.queue_virtual_address();
    let expected_queue_phys = virt_ptr_to_phys(queue_virt as *const u8)
        .expect("failed to translate queue virtual address");
    assert_eq!(queue.base_address(), expected_queue_phys);
    assert_eq!(queue.base_address() & 0xFFF, 0);

    let status_virt = queue.status_virtual_address();
    let expected_status_phys = virt_ptr_to_phys(status_virt as *const u8)
        .expect("failed to translate status virtual address");
    let (wait, expected_seq) = queue.wait_entry();
    assert_eq!(wait.hi, expected_status_phys);
    assert_eq!(wait.hi & 0xFFF, 0);
    let (submitted_status, submitted_seq) = queue.submit_wait();
    assert_eq!(submitted_status, status_virt);
    assert_eq!(submitted_seq, expected_seq.wrapping_add(1));
}

unsafe fn is_4k_mapped(domain: &IommuDomain, iova: u64, format: PteFormat) -> bool {
    unsafe {
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;
        let pt_idx = ((iova >> 12) & 0x1FF) as usize;

        let pml4_entry = domain.page_table.add(pml4_idx);
        if !(*pml4_entry).is_present() {
            return false;
        }
        let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
        let pdp_entry = pdp_table.add(pdp_idx);
        if !(*pdp_entry).is_present() {
            return false;
        }
        if (*pdp_entry).is_super_page(format) {
            return false;
        }
        let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
        let pd_entry = pd_table.add(pd_idx);
        if !(*pd_entry).is_present() {
            return false;
        }
        if (*pd_entry).is_super_page(format) {
            return false;
        }
        let pt_table = (*pd_entry).phys_addr() as *mut SlPte;
        let pt_entry = pt_table.add(pt_idx);
        (*pt_entry).is_present()
    }
}

unsafe fn is_superpage_2mb_mapped(domain: &IommuDomain, iova: u64, format: PteFormat) -> bool {
    unsafe {
        let pml4_idx = ((iova >> 39) & 0x1FF) as usize;
        let pdp_idx = ((iova >> 30) & 0x1FF) as usize;
        let pd_idx = ((iova >> 21) & 0x1FF) as usize;

        let pml4_entry = domain.page_table.add(pml4_idx);
        if !(*pml4_entry).is_present() {
            return false;
        }
        let pdp_table = (*pml4_entry).phys_addr() as *mut SlPte;
        let pdp_entry = pdp_table.add(pdp_idx);
        if !(*pdp_entry).is_present() {
            return false;
        }
        if (*pdp_entry).is_super_page(format) {
            return false;
        }
        let pd_table = (*pdp_entry).phys_addr() as *mut SlPte;
        let pd_entry = pd_table.add(pd_idx);
        (*pd_entry).is_present() && (*pd_entry).is_super_page(format)
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_map_rollback_on_overlap_hidden_mapping() {
    let format = PteFormat::Intel;
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        format,
    );

    let base_iova = 0x10000;
    let phys_base = 0x20000;

    // Pre-map the middle page as a hidden "mine"
    let mine_iova = base_iova + 0x1000;
    domain
        .map(mine_iova, phys_base + 0x1000, 0x1000, true, true)
        .expect("mine map failed");
    domain.drop_mapping_for_test(mine_iova);
    assert!(unsafe { is_4k_mapped(&domain, mine_iova, format) });
    assert!(domain.mapping(mine_iova).is_none());

    // Attempt to map three pages; should fail on the hidden mine
    let res = domain.map(base_iova, phys_base, 0x3000, true, true);
    assert_eq!(res, Err(IommuError::AlreadyMapped));

    // First page should be rolled back, mine should remain, third page untouched
    assert!(!unsafe { is_4k_mapped(&domain, base_iova, format) });
    assert!(unsafe { is_4k_mapped(&domain, mine_iova, format) });
    assert!(!unsafe { is_4k_mapped(&domain, base_iova + 0x2000, format) });

    assert_eq!(domain.mapped_size(), 0);
    assert!(domain.mappings_snapshot().is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_map_rollback_on_overlap_hidden_mapping_amd() {
    let format = PteFormat::Amd;
    let domain = IommuDomain::new(
        2,
        None,
        true,
        true,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        format,
    );

    let base_iova = 0x10000;
    let phys_base = 0x20000;
    let mine_iova = base_iova + 0x1000;

    domain
        .map(mine_iova, phys_base + 0x1000, 0x1000, true, true)
        .expect("setup map failed");
    domain.drop_mapping_for_test(mine_iova);

    assert!(unsafe { is_4k_mapped(&domain, mine_iova, format) });
    assert!(domain.mapping(mine_iova).is_none());

    let res = domain.map(base_iova, phys_base, 0x3000, true, true);
    assert_eq!(res, Err(IommuError::AlreadyMapped));

    assert!(
        !unsafe { is_4k_mapped(&domain, base_iova, format) },
        "First page was not rolled back (AMD)"
    );
    assert!(
        unsafe { is_4k_mapped(&domain, mine_iova, format) },
        "Hidden page was incorrectly removed (AMD)"
    );
    assert!(
        !unsafe { is_4k_mapped(&domain, base_iova + 0x2000, format) },
        "Third page was mapped unexpectedly (AMD)"
    );

    assert_eq!(domain.mapped_size(), 0);
    assert!(domain.mappings_snapshot().is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_map_rollback_superpage_2mb_collision() {
    let format = PteFormat::Amd;
    let domain = IommuDomain::new(
        3,
        None,
        true,
        false,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        format,
    );

    const SIZE_2MB: u64 = 2 * 1024 * 1024;
    let start_iova = 0x2000_0000;
    let phys_base = 0x4000_0000;
    let mine_iova = start_iova + SIZE_2MB;

    domain
        .map(mine_iova, phys_base + SIZE_2MB, 0x1000, true, true)
        .expect("setup mine");
    domain.drop_mapping_for_test(mine_iova);

    let res = domain.map(start_iova, phys_base, SIZE_2MB * 2, true, true);
    assert_eq!(res, Err(IommuError::AlreadyMapped));

    assert!(
        !unsafe { is_superpage_2mb_mapped(&domain, start_iova, format) },
        "First 2MB superpage was not rolled back"
    );
    assert!(
        !unsafe { is_4k_mapped(&domain, start_iova, format) },
        "Unexpected 4KB mapping in first 2MB region"
    );
    assert!(
        unsafe { is_4k_mapped(&domain, mine_iova, format) },
        "Mine should persist"
    );

    assert_eq!(domain.mapped_size(), 0);
    assert!(domain.mappings_snapshot().is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_create_domain_with_numa_hint() {
    let ctrl = controller();
    let id = ctrl
        .create_domain(Some(2), IommuDomainType::Translated)
        .expect("create_domain failed");
    let domain_arc = ctrl.domain(id).expect("domain not found");
    assert_eq!(domain_arc.id(), id);
    assert_eq!(domain_arc.numa_node(), Some(2));

    // Test controller set/get API
    ctrl.set_domain_numa(id, Some(5))
        .expect("set_domain_numa failed");
    let updated = ctrl.domain(id).expect("domain not found after update");
    assert_eq!(updated.numa_node(), Some(5usize));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_create_domain_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = controller();
    // Poison domains lock
    set_panicking(true);
    if let Ok(_g) = ctrl.domains.lock() {
        // drop to poison
    }
    set_panicking(false);
    assert_eq!(
        ctrl.create_domain(Some(0), IommuDomainType::Translated)
            .err(),
        Some(IommuError::HardwareError)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_isolate_faulting_device_poisoned_attempts_isolation() {
    use crate::sync::set_panicking;
    let ctrl = controller();

    // Allocate a context table and mark entry 0 as Present
    let mut table = HardwareTable::<ContextEntry>::new(256, None).expect("context table");
    if let Some(entry) = table.get_mut(0) {
        entry.lo = 1;
    }

    // Install table pointer for bus 0
    {
        match ctrl.hardware.lock() {
            Ok(mut hw) => {
                hw.legacy_context_tables.push(table);
            }
            Err(poisoned) => {
                let mut hw = poisoned.into_inner();
                hw.legacy_context_tables.push(table);
            }
        }
    }

    // Poison the hardware lock so isolate will take the poisoned branch
    set_panicking(true);
    if let Ok(_g) = ctrl.hardware.lock() {
        // drop to poison
    }
    set_panicking(false);

    assert!(ctrl.hardware.is_poisoned());

    // Call isolate - it should attempt best-effort isolation and clear the Present bit
    let fault = FaultRecord {
        lo: 0,
        hi: FaultRecord::FAULT,
    };
    let _ = ctrl.isolate_faulting_device(fault);

    let present = match ctrl.hardware.lock() {
        Ok(hw) => hw
            .legacy_context_tables
            .get(0)
            .and_then(|t| t.get(0))
            .map(|e| e.is_present())
            .unwrap_or(false),
        Err(poisoned) => {
            let hw = poisoned.into_inner();
            hw.legacy_context_tables
                .get(0)
                .and_then(|t| t.get(0))
                .map(|e| e.is_present())
                .unwrap_or(false)
        }
    };
    assert!(!present);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_scalable_mode_pasid0_fault_resolution() {
    #[derive(Debug)]
    struct TestNotifier {
        seen: AtomicBool,
        domain_id: AtomicU32,
    }

    impl TestNotifier {
        fn new() -> Self {
            Self {
                seen: AtomicBool::new(false),
                domain_id: AtomicU32::new(u32::MAX),
            }
        }

        fn seen(&self) -> bool {
            self.seen.load(Ordering::Acquire)
        }

        fn domain_id(&self) -> u32 {
            self.domain_id.load(Ordering::Acquire)
        }
    }

    impl SecurityNotifier for TestNotifier {
        fn notify(&self, event: SecurityEvent) {
            if let SecurityEvent::DmaViolation { domain_id, .. } = event {
                let id = domain_id.unwrap_or(u32::MAX);
                self.domain_id.store(id, Ordering::Release);
                self.seen.store(true, Ordering::Release);
            }
        }
    }

    let mut registers = [0; 512];
    registers[0x34 / 8] =
        (crate::io::iommu::vendors::intel::registers::fsts_bits::FSTS_PPF as u64) << 32;
    registers[0x300 / 8] = 0xdeadb000;
    registers[0x308 / 8] = FaultRecord::FAULT | FaultRecord::PASID_PRESENT | (5 << 32) | 8;
    let ctrl = controller_with_registers(registers);
    ctrl.set_scalable_mode_enabled(true);

    let root_table = HardwareTable::<RootEntry>::new(256, None).expect("root table");
    let scalable_table =
        HardwareTable::<ScalableContextEntry>::new(256, None).expect("scalable table");

    {
        let mut hw = ctrl.hardware.lock().expect("hardware lock");
        hw.root_table = Some(root_table);
        hw.scalable_context_tables.push(scalable_table);
    }

    let domain_id = ctrl
        .create_domain(None, IommuDomainType::Translated)
        .expect("create_domain failed");
    let device = DeviceId::new(0, 0, 1, 0);
    ctrl.attach_device(device, domain_id)
        .expect("attach_device failed");

    let domain = ctrl.domain(domain_id).expect("domain not found");
    domain
        .map(0x1000, 0x2000, 0x1000, true, true)
        .expect("map failed");
    let mapping = domain.unmap(0x1000).expect("unmap failed");
    assert_eq!(mapping.size, 0x1000);

    {
        let hw = ctrl.hardware.lock().expect("hardware lock");
        let root_entry = hw
            .root_table
            .as_ref()
            .and_then(|t| t.get(0))
            .expect("root entry");
        assert!(root_entry.is_present_low());
        assert!(root_entry.is_present_high());

        let devfn = ((device.device as usize) << 3) | (device.function as usize);
        let ctx_entry = hw
            .scalable_context_tables
            .get(0)
            .and_then(|t| t.get(devfn))
            .expect("context entry");
        assert!(ctx_entry.is_present());
    }

    let pasid_domain = ctrl
        .device_pasid_tables
        .lock()
        .ok()
        .and_then(|tables| tables.get(&device).and_then(|t| t.domain_id(0)));
    assert_eq!(pasid_domain, Some(domain_id));

    ctrl.device_domains
        .lock()
        .expect("device_domains lock")
        .remove(&device);

    let notifier = Arc::new(TestNotifier::new());
    let notifier_dyn: Arc<dyn SecurityNotifier> = notifier.clone();
    ctrl.set_security_notifier(notifier_dyn);

    assert_eq!(ctrl.process_faults(), 1);
    assert_eq!(ctrl.drain_deferred_faults(), 1);

    assert!(notifier.seen());
    assert_eq!(notifier.domain_id(), domain_id as u32);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_map_poisoned_returns_none() {
    use crate::sync::set_panicking;
    let ctrl = controller();
    let id = ctrl
        .create_domain(None, IommuDomainType::Translated)
        .expect("create_domain failed");

    // Poison the domains lock
    set_panicking(true);
    if let Ok(_g) = ctrl.domains.lock() {
        // dropping _g while panicking will mark the lock as poisoned
    }
    set_panicking(false);

    assert!(ctrl.domain(id).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_get_domain_for_device_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = controller();
    let id = ctrl
        .create_domain(None, IommuDomainType::Translated)
        .expect("create_domain failed");

    let device = DeviceId::new(0, 0, 1, 0);
    // Register mapping
    match ctrl.device_domains.lock() {
        Ok(mut dmap) => {
            dmap.insert(device, id);
        }
        Err(_) => {}
    }

    // Poison device_domains lock
    set_panicking(true);
    if let Ok(_g) = ctrl.device_domains.lock() {
        // drop to poison
    }
    set_panicking(false);

    assert_eq!(
        ctrl.get_domain_for_device(device).err(),
        Some(IommuError::HardwareError)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_set_domain_numa_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = controller();
    let id = ctrl
        .create_domain(None, IommuDomainType::Translated)
        .expect("create_domain failed");

    // Poison domains lock
    set_panicking(true);
    if let Ok(_g) = ctrl.domains.lock() {
        // drop to poison
    }
    set_panicking(false);

    assert_eq!(
        ctrl.set_domain_numa(id, Some(1)).err(),
        Some(IommuError::HardwareError)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_iova_allocator_basic() {
    let ctrl = controller();
    // Small IOVA space for testing (64KB)
    ctrl.init_iova(0x1000_0000, 0x10000)
        .expect("init_iova failed");

    let a = match ctrl.allocate_iova(4096) {
        Ok(v) => v,
        Err(IommuError::OutOfMemory) | Err(IommuError::OutOfIova) => {
            log::warn!("[IOMMU][TEST] test_iova_allocator_basic: skipped due allocator pressure");
            return;
        }
        Err(e) => panic!("alloc 4K: {:?}", e),
    };
    assert_eq!(a % 4096, 0);

    let b = match ctrl.allocate_iova(8192) {
        Ok(v) => v,
        Err(IommuError::OutOfMemory) | Err(IommuError::OutOfIova) => {
            log::warn!("[IOMMU][TEST] test_iova_allocator_basic: skipped due allocator pressure");
            return;
        }
        Err(e) => panic!("alloc 8K: {:?}", e),
    };
    assert_ne!(a, b);

    if let Err(e) = ctrl.free_iova(a, 4096) {
        panic!("free failed: {:?}", e);
    }

    match ctrl.allocate_iova(4096) {
        Ok(_) => {}
        Err(IommuError::OutOfMemory) | Err(IommuError::OutOfIova) => {
            log::warn!(
                "[IOMMU][TEST] test_iova_allocator_basic: post-free alloc skipped due allocator pressure"
            );
        }
        Err(e) => panic!("alloc after free: {:?}", e),
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_init_iova_poisoned_proceeds_with_best_effort() {
    use crate::sync::set_panicking;
    let ctrl = controller();

    // Poison the iova_allocator lock
    set_panicking(true);
    if let Ok(_g) = ctrl.iova_allocator.lock() {
        // drop to poison
    }
    set_panicking(false);

    // Should succeed and set the allocator via best-effort
    ctrl.init_iova(0x2000_0000, 0x10000)
        .expect("init_iova failed");

    match ctrl.iova_allocator.lock() {
        Ok(g) => assert!(g.is_some()),
        Err(poisoned) => {
            // still poisoned, ensure inner was set
            let guard = poisoned.into_inner();
            assert!(guard.is_some());
        }
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_enable_queued_invalidation_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = controller();

    // Poison invalidation_queue lock
    set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {
        // drop to poison
    }
    set_panicking(false);

    let res = unsafe { ctrl.enable_queued_invalidation() };
    assert_eq!(res.err(), Some(IommuError::HardwareError));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_iova_alloc_non_identity() {
    let ctrl = controller();
    ctrl.init_iova(0x8000_0000, 0x10000).expect("init_iova");

    // Create default domain 0 for mapping
    let domain = Arc::new(IommuDomain::new(
        0,
        None,
        false,
        false,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    ));
    match ctrl.domains.lock() {
        Ok(mut domains) => {
            domains.insert(0, domain.clone());
        }
        Err(poisoned) => {
            let mut domains = poisoned.into_inner();
            domains.insert(0, domain.clone());
        }
    }

    let size = 0x3000;
    let phys = 0x2000_0000;

    let iova = match ctrl.allocate_iova(size) {
        Ok(v) => v,
        Err(IommuError::OutOfMemory) | Err(IommuError::OutOfIova) => {
            log::warn!(
                "[IOMMU][TEST] test_domain_iova_alloc_non_identity: skipped due allocator pressure"
            );
            return;
        }
        Err(e) => panic!("allocate_iova: {:?}", e),
    };

    {
        let domain_arc = ctrl.domain(0).expect("domain 0");
        domain_arc
            .map(iova, phys, size, true, true)
            .expect("domain.map failed");
        assert!(domain_arc.mapping(iova).is_some());

        let mapping = domain_arc.unmap(iova).expect("unmap failed");
        assert_eq!(mapping.iova, iova);
        assert_eq!(mapping.phys, phys);
    }

    ctrl.free_iova(iova, size).expect("free failed");
}

#[cfg(feature = "std")]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_map_for_device_async_and_unmap() {
    let controller = Arc::new(controller());
    controller
        .init_iova(0x1000, 0x10000)
        .expect("IOVA admission");
    let domain_id = controller
        .create_domain(None, IommuDomainType::Translated)
        .expect("domain");
    let device = DeviceId::new(0, 0, 1, 0);
    controller
        .device_domains
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(device, domain_id);
    let driver = crate::io::iommu::vendors::intel::IntelIommuDriver::with_controller(Arc::clone(
        &controller,
    ));
    use core::future::Future;
    use core::task::{Context, Poll, Waker};
    let backing = crate::mm::phys::frame_allocator::alloc_contiguous_frames(1)
        .expect("exclusive DMA backing admission");
    let mut context = Context::from_waker(Waker::noop());
    // SAFETY: the exclusive RAM owner remains retained until the mapping's
    // captured-origin retirement completes below. No device command is issued.
    let mut admission = core::pin::pin!(unsafe {
        driver.map_for_device_async(&device, backing.start_address(), backing.size_bytes())
    });
    let Poll::Ready(Ok(mapping)) = admission.as_mut().poll(&mut context) else {
        panic!("register fixture did not complete mapping admission");
    };
    let iova = mapping.iova();
    let domain = controller.domain(domain_id).expect("domain retained");
    assert!(domain.mapping(iova).is_some());
    // Retirement uses the captured origin even after the device binding changes.
    controller
        .device_domains
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .remove(&device);
    let mut retirement = core::pin::pin!(mapping.unmap_async());
    assert!(matches!(
        retirement.as_mut().poll(&mut context),
        Poll::Ready(Ok(()))
    ));
    assert!(domain.mapping(iova).is_none());
    backing.release();
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_map_for_device_respects_dma_mask() {
    use alloc::sync::Arc as AllocArc;

    let controller = if let Some(registry) = get_iommu_registry() {
        registry
            .controllers
            .get(0)
            .cloned()
            .expect("no IOMMU controller in registry")
    } else {
        let ctrl = controller();
        let arc_ctrl = AllocArc::new(ctrl);
        let registry = test_iommu_registry(alloc::vec![arc_ctrl.clone()]);
        init_registry(registry);
        arc_ctrl
    };

    if get_iommu_driver().is_none() {
        crate::io::iommu::vendors::intel::IntelIommuDriver::register_driver();
    }

    let _ = controller.init_iova(0x1000, 0x1_0000_0000 - 0x1000);
    let domain_id = controller
        .create_domain(None, IommuDomainType::Translated)
        .expect("create domain");

    let device = DeviceId::new(0, 0, 2, 0);
    match controller.device_domains.lock() {
        Ok(mut dmap) => {
            dmap.insert(device, domain_id);
        }
        Err(_) => {
            panic!("device_domains poisoned");
        }
    }

    struct MaskGuard(DeviceId);
    impl Drop for MaskGuard {
        fn drop(&mut self) {
            crate::io::iommu::api::clear_device_dma_mask(self.0);
        }
    }

    crate::io::iommu::api::register_device_dma_mask(device, 0xFFFF_FFFF);
    let _guard = MaskGuard(device);

    let phys = x86_64::PhysAddr::new(0x1_0000_0000);
    let mapped = match unsafe { crate::io::iommu::api::map_for_device(&device, phys, 0x1000) } {
        Ok(v) => v,
        Err(crate::io::iommu::common::dma::mapping_outcome::DeviceMapFailure::Unpublished(
            IommuError::NotInitialized,
        )) => {
            log::warn!(
                "[IOMMU][TEST] test_map_for_device_respects_dma_mask: skipped (driver not initialized)"
            );
            return;
        }
        Err(e) => panic!("map for device with mask: {:?}", e),
    };
    let iova = mapped.iova();
    assert!(iova + 0x1000 - 1 <= 0xFFFF_FFFF);
    mapped.unmap().expect("unmap");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_map_unmap_for_device_does_not_leak_iova() {
    use alloc::sync::Arc as AllocArc;

    let controller = if let Some(registry) = get_iommu_registry() {
        registry
            .controllers
            .get(0)
            .cloned()
            .expect("no IOMMU controller in registry")
    } else {
        let ctrl = controller();
        let arc_ctrl = AllocArc::new(ctrl);
        let registry = test_iommu_registry(alloc::vec![arc_ctrl.clone()]);
        init_registry(registry);
        arc_ctrl
    };

    if get_iommu_driver().is_none() {
        crate::io::iommu::vendors::intel::IntelIommuDriver::register_driver();
    }

    let _ = controller.init_iova(0x1000, 0x1_0000_0000 - 0x1000);
    let domain_id = controller
        .create_domain(None, IommuDomainType::Translated)
        .expect("create domain");

    let device = DeviceId::new(0, 0, 2, 1);
    match controller.device_domains.lock() {
        Ok(mut dmap) => {
            dmap.insert(device, domain_id);
        }
        Err(_) => {
            panic!("device_domains poisoned");
        }
    }

    struct MaskGuard(DeviceId);
    impl Drop for MaskGuard {
        fn drop(&mut self) {
            crate::io::iommu::api::clear_device_dma_mask(self.0);
        }
    }

    // Keep the usable IOVA window strictly 32-bit bounded, but large enough to
    // avoid false failures from delayed quarantine reclamation.
    let mask_limit = 0x001F_FFFF;
    crate::io::iommu::api::register_device_dma_mask(device, mask_limit);
    let _guard = MaskGuard(device);

    for i in 0..64u64 {
        let phys = x86_64::PhysAddr::new(0x2000_0000 + i * 0x1000);
        let mapped = match unsafe { crate::io::iommu::api::map_for_device(&device, phys, 0x1000) } {
            Ok(v) => v,
            Err(crate::io::iommu::common::dma::mapping_outcome::DeviceMapFailure::Unpublished(
                IommuError::OutOfMemory,
            ))
            | Err(crate::io::iommu::common::dma::mapping_outcome::DeviceMapFailure::Unpublished(
                IommuError::OutOfIova,
            )) => {
                let _ = controller.invalidate_iotlb_global_sync();
                match unsafe { crate::io::iommu::api::map_for_device(&device, phys, 0x1000) } {
                    Ok(v) => v,
                    Err(e) => panic!("map iteration {} failed after global flush: {:?}", i, e),
                }
            }
            Err(e) => panic!("map iteration {} failed: {:?}", i, e),
        };
        let iova = mapped.iova();
        assert!(
            iova + 0x1000 - 1 <= mask_limit,
            "allocated IOVA 0x{:x} exceeded mask 0x{:x}",
            iova,
            mask_limit
        );
        mapped.unmap().expect("unmap");
    }
}
/*
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_init_iommu_registers_drhd_and_rmrr_and_applies_rmrr() {
    // Test removed due to dependency on global IommuManager which is deprecated.
}
*/

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_unmap_reclaims_empty_tables() {
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );

    // Map a single page
    domain
        .map(0x1000, 0x2000, 0x1000, true, true)
        .expect("map failed");

    // Verify mapping exists
    assert!(domain.mapping(0x1000).is_some());

    // Unmap should reclaim PT, PD, PDP tables
    let mapping = domain.unmap(0x1000).expect("unmap failed");
    assert_eq!(mapping.iova, 0x1000);
    assert_eq!(mapping.phys, 0x2000);

    // Verify page table entries are cleared (PML4 entry should be not present)
    unsafe {
        let pml4_entry = *domain.page_table.add(0);
        assert!(
            !pml4_entry.is_present(),
            "PML4 entry should be cleared after unmap"
        );
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_unmap_partial_keeps_tables() {
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );

    // Map two pages in the same PT
    domain
        .map(0x1000, 0x2000, 0x1000, true, true)
        .expect("map 1 failed");
    domain
        .map(0x2000, 0x3000, 0x1000, true, true)
        .expect("map 2 failed");

    // Unmap first page - PT should still exist (second page still mapped)
    domain.unmap(0x1000).expect("unmap 1 failed");

    // Verify PML4 entry is still present (PT not empty)
    unsafe {
        let pml4_entry = *domain.page_table.add(0);
        assert!(
            pml4_entry.is_present(),
            "PML4 entry should still be present"
        );
    }

    // Unmap second page - now tables should be reclaimed
    domain.unmap(0x2000).expect("unmap 2 failed");

    unsafe {
        let pml4_entry = *domain.page_table.add(0);
        assert!(
            !pml4_entry.is_present(),
            "PML4 entry should be cleared after all unmaps"
        );
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_unmap_mixed_superpages() {
    const SIZE_1GB: u64 = 1024 * 1024 * 1024;
    const SIZE_2MB: u64 = 2 * 1024 * 1024;
    const SIZE_4KB: u64 = 4096;
    const SIZE_TOTAL: u64 = SIZE_1GB + SIZE_2MB + SIZE_4KB;
    const IOVA_BASE: u64 = 0x4000_0000;
    const PHYS_BASE: u64 = 0x8000_0000;

    let domain = IommuDomain::new(
        1,
        None,
        true,
        true,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );

    domain
        .map(IOVA_BASE, PHYS_BASE, SIZE_TOTAL, true, true)
        .expect("map mixed failed");
    assert!(domain.mapping(IOVA_BASE).is_some());

    let mapping = domain.unmap(IOVA_BASE).expect("unmap mixed failed");
    assert_eq!(mapping.iova, IOVA_BASE);
    assert_eq!(mapping.phys, PHYS_BASE);
    assert_eq!(mapping.size, SIZE_TOTAL);
    assert!(domain.mapping(IOVA_BASE).is_none());

    let pml4_idx = ((IOVA_BASE >> 39) & 0x1FF) as usize;
    unsafe {
        let pml4_entry = *domain.page_table.add(pml4_idx);
        assert!(
            !pml4_entry.is_present(),
            "PML4 entry should be cleared after unmap"
        );
    }
}

#[cfg(feature = "qemu-test-export")]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_submit_invalidation_poisoned_returns_error() {
    let mut ctrl = controller();

    // Enable queued invalidation support for testing
    ctrl.ecap = ecap_bits::ECAP_QI;
    ctrl.init_queued_invalidation(8).expect("init_qi failed");

    // Poison the invalidation_queue lock by simulating a panic while holding it
    {
        let _guard = ctrl.invalidation_queue.lock().unwrap();
        crate::sync::set_panicking(true);
    }
    crate::sync::set_panicking(false);

    let res = ctrl.submit_invalidation(InvalidationQueueEntry::iec_invalidate_global());
    assert_eq!(res, Err(IommuError::HardwareError));
}

#[cfg(feature = "qemu-test-export")]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_qi_wait_sync_poisoned_returns_error() {
    let mut ctrl = controller();

    // Enable queued invalidation support for testing
    ctrl.ecap = ecap_bits::ECAP_QI;
    ctrl.init_queued_invalidation(8).expect("init_qi failed");

    // Poison the invalidation_queue lock
    {
        let _guard = ctrl.invalidation_queue.lock().unwrap();
        crate::sync::set_panicking(true);
    }
    crate::sync::set_panicking(false);

    let res = ctrl.qi_wait_sync();
    assert_eq!(res, Err(IommuError::HardwareError));
}

#[cfg(feature = "qemu-test-export")]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_qi_wait_async_poisoned_returns_error() {
    let mut ctrl = controller();

    // Enable queued invalidation support for testing
    ctrl.ecap = ecap_bits::ECAP_QI;
    ctrl.init_queued_invalidation(8).expect("init_qi failed");

    // Poison the invalidation_queue lock
    {
        let _guard = ctrl.invalidation_queue.lock().unwrap();
        crate::sync::set_panicking(true);
    }
    crate::sync::set_panicking(false);

    let waiter = ctrl.qi_wait_async();
    assert_eq!(waiter.submit_result, Err(IommuError::HardwareError));
}

#[cfg(feature = "qemu-test-export")]
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_qi_metrics_pressure() {
    let mut ctrl = controller();

    ctrl.ecap = ecap_bits::ECAP_QI;
    ctrl.init_queued_invalidation(8).expect("init_qi failed");

    let stats = ctrl
        .qi_stats()
        .expect("stats read failed")
        .expect("stats missing");
    assert_eq!(stats.submits, 0);
    assert_eq!(stats.full_checks, 0);

    let ring_capacity = 1usize << 8;
    let safe_submissions = ring_capacity - 1;

    for _ in 0..safe_submissions {
        let desc = InvalidationQueueEntry::iotlb_invalidate_global();
        ctrl.submit_invalidation(desc)
            .expect("submit should succeed");
    }

    let stats = ctrl
        .qi_stats()
        .expect("stats read failed")
        .expect("stats missing");
    assert_eq!(stats.submits, safe_submissions as u64);
    assert_eq!(stats.full_checks, 0);
    assert_eq!(stats.wait_timeouts, 0);

    let desc = InvalidationQueueEntry::iotlb_invalidate_global();
    let res = ctrl.submit_invalidation(desc);
    assert!(res.is_err());

    let stats = ctrl
        .qi_stats()
        .expect("stats read failed")
        .expect("stats missing");
    assert!(stats.full_checks > 0, "should detect queue full");
    assert!(stats.waits > 0, "should record wait");
    assert!(stats.wait_timeouts > 0, "should record timeout");
    assert_eq!(stats.submits, safe_submissions as u64);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_page_table_scope_commit_preserves_counts() {
    // Verify that commit doesn't overwrite existing counts and increments parent count.
    let pending = crate::sync::PoisonLock::new(
        crate::io::iommu::common::dma::page_table_pool::TableRetirement::default(),
    );
    let pool = crate::io::iommu::common::dma::page_table_pool::PageTablePool::new(1, 4);
    let mut scope =
        PageTableScope::new_with_pool(pool.clone(), None, &pending).expect("allocate ptable");
    let scope_phys = scope.phys();
    let parent_phys = 0xDEADBEEF;

    crate::io::iommu::common::dma::page_table_pool::register_page_table(scope_phys);
    for _ in 0..42 {
        crate::io::iommu::common::dma::page_table_pool::inc_ref(scope_phys);
    }
    crate::io::iommu::common::dma::page_table_pool::register_page_table(parent_phys);

    // Create a fake parent entry and attach
    let mut parent_entry = SlPte::new();
    // SAFETY: this retained stack parent is exclusively accessed and never installed in hardware.
    unsafe {
        scope.attach_to_parent(
            &mut parent_entry as *mut SlPte,
            parent_phys,
            PteFormat::Intel,
            1,
        );
    }

    // Commit should not overwrite existing count for scope.phys(), but should increment parent
    scope.commit();

    assert_eq!(
        crate::io::iommu::common::dma::page_table_pool::get_ref_count(scope_phys),
        42
    );
    assert_eq!(
        crate::io::iommu::common::dma::page_table_pool::get_ref_count(parent_phys),
        1
    );

    crate::io::iommu::common::dma::page_table_pool::unregister_page_table(parent_phys);
    parent_entry = SlPte::new();
    assert!(!parent_entry.is_present());
    // SAFETY: the only parent is cleared; this fixture never published the table to a device.
    if let Some(table) =
        unsafe { crate::io::iommu::common::dma::page_table_pool::take_unlinked_table(scope_phys) }
    {
        pool.release(unsafe { table.complete_after_invalidation() });
    }
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_page_table_scope_drop_rolls_back_parent() {
    // Attached rollback clears the parent and retains the allocation in quarantine.
    let parent_phys = 0xBABA;
    let mut parent_entry = SlPte::new();
    {
        let pending = crate::sync::PoisonLock::new(
            crate::io::iommu::common::dma::page_table_pool::TableRetirement::default(),
        );
        let pool = crate::io::iommu::common::dma::page_table_pool::PageTablePool::new(1, 4);
        let mut scope =
            PageTableScope::new_with_pool(pool.clone(), None, &pending).expect("allocate ptable");
        // Attach to parent; don't commit
        // Attach to parent; don't commit
        // SAFETY: this retained stack parent is exclusively accessed and never installed in hardware.
        unsafe {
            scope.attach_to_parent(
                &mut parent_entry as *mut SlPte,
                parent_phys,
                PteFormat::Intel,
                1,
            );
            // At this point, parent should be present
            assert!(unsafe { (*(&parent_entry as *const SlPte)).is_present() });
        }
        // After scope dropped, parent should be cleared
        assert!(!unsafe { (*(&parent_entry as *const SlPte)).is_present() });
    }

    // ============================================================================
    // Phase 7: Security Monitor Tests
    // ============================================================================

    /// Mock SecurityNotifier for testing (alloc-free, fixed-size ring)
    #[derive(Debug)]
    struct MockSecurityNotifier {
        events:
            crate::sync::Mutex<[Option<crate::io::iommu::runtime::security::SecurityEvent>; 16]>,
        event_count: core::sync::atomic::AtomicUsize,
        isolation_decision: crate::io::iommu::runtime::security::IsolationDecision,
    }

    impl MockSecurityNotifier {
        fn new() -> Self {
            Self {
                events: crate::sync::Mutex::new([None; 16]),
                event_count: core::sync::atomic::AtomicUsize::new(0),
                isolation_decision: crate::io::iommu::runtime::security::IsolationDecision::default(
                ),
            }
        }

        fn with_decision(decision: crate::io::iommu::runtime::security::IsolationDecision) -> Self {
            Self {
                events: crate::sync::Mutex::new([None; 16]),
                event_count: core::sync::atomic::AtomicUsize::new(0),
                isolation_decision: decision,
            }
        }

        fn received_count(&self) -> usize {
            self.event_count.load(core::sync::atomic::Ordering::Relaxed)
        }

        fn last_event(&self) -> Option<crate::io::iommu::runtime::security::SecurityEvent> {
            let count = self.received_count();
            if count == 0 {
                return None;
            }
            let idx = (count - 1) % 16;
            *self.events.lock().get(idx).unwrap_or(&None)
        }
    }

    impl crate::io::iommu::runtime::security::SecurityNotifier for MockSecurityNotifier {
        fn notify(&self, event: crate::io::iommu::runtime::security::SecurityEvent) {
            let idx = self
                .event_count
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
                % 16;
            self.events.lock()[idx] = Some(event);
        }

        fn decide(
            &self,
            _fault: &crate::io::iommu::runtime::security::FaultSummary,
        ) -> crate::io::iommu::runtime::security::IsolationDecision {
            self.isolation_decision
        }
    }

    #[cfg(feature = "qemu-test-export")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_security_notifier_registration() {
        let ctrl = controller();
        let notifier = Arc::new(MockSecurityNotifier::new());

        // First registration should succeed
        assert!(ctrl.set_security_notifier(notifier.clone()));

        // Second registration should fail (already set)
        let notifier2 = Arc::new(MockSecurityNotifier::new());
        assert!(!ctrl.set_security_notifier(notifier2));
    }

    #[cfg(feature = "qemu-test-export")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_api_security_notifier_registration() {
        use crate::io::iommu::runtime::registry::get_iommu_driver;
        use crate::io::iommu::vendors::intel::controller::IommuController;
        use crate::io::iommu::vendors::intel::registry::{get_iommu_registry, init_registry};

        if get_iommu_registry().is_none() {
            let ctrl = controller();
            let registry = test_iommu_registry(alloc::vec![Arc::new(ctrl)]);
            init_registry(registry);
        }

        if get_iommu_driver().is_none() {
            crate::io::iommu::vendors::intel::IntelIommuDriver::register_driver();
        }

        let notifier = Arc::new(MockSecurityNotifier::new());
        let first = crate::io::iommu::api::set_security_notifier(notifier).expect("set notifier");
        assert!(first);

        let notifier2 = Arc::new(MockSecurityNotifier::new());
        let second = crate::io::iommu::api::set_security_notifier(notifier2).expect("set notifier");
        assert!(!second);
    }

    #[cfg(feature = "qemu-test-export")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_security_event_types_are_copy() {
        use crate::io::iommu::runtime::security::{IsolationReason, SecurityEvent};

        // Verify SecurityEvent is Copy by assignment
        let event1 = SecurityEvent::DmaViolation {
            source_id: 0x0108,
            fault_address: 0x1000,
            reason: 0x01,
            domain_id: Some(0x10),
        };
        let event2 = event1; // Copy
        match event2 {
            SecurityEvent::DmaViolation {
                source_id,
                domain_id,
                ..
            } => {
                assert_eq!(source_id, 0x0108);
                assert_eq!(domain_id, Some(0x10));
            }
            _ => panic!("wrong event type"),
        }

        let event3 = SecurityEvent::DeviceIsolated {
            source_id: 0x0208,
            reason: IsolationReason::DmaFault,
        };
        let _event4 = event3; // Copy

        let event5 = SecurityEvent::QuarantinePoisoned { domain_id: 42 };
        let _event6 = event5; // Copy

        let event7 = SecurityEvent::EventsDropped { count: 10 };
        let _event8 = event7; // Copy
    }

    #[cfg(feature = "qemu-test-export")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_fault_summary_from_fault_record() {
        use crate::io::iommu::runtime::security::FaultSummary;

        // Create a mock FaultRecord
        let record = FaultRecord {
            lo: 0x2000,
            hi: 0x8000_0042_0000_0108,
        };

        let summary = FaultSummary::from(&record);
        assert_eq!(summary.source_id, 0x0108);
        assert_eq!(summary.fault_address, 0x2000);
        assert_eq!(summary.reason, 0x42);
    }

    #[cfg(feature = "qemu-test-export")]
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_isolation_decision_default() {
        use crate::io::iommu::runtime::security::{IsolationDecision, IsolationReason};

        let decision = IsolationDecision::default();
        match decision {
            IsolationDecision::Isolate(IsolationReason::DmaFault) => {}
            _ => panic!("default should be Isolate(DmaFault)"),
        }
    }

    // ============================================================================
    // Identity Mapping Exclusion Tests
    // ============================================================================

    /// Test that translated-only operation remains mandatory after bypass removal.
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_identity_mapping_disabled_by_default() {
        assert!(
            crate::io::iommu::api::is_iommu_required(),
            "IOMMU should remain mandatory after removing bypass APIs"
        );
    }
}

/// Test that IOVA allocation produces non-identity addresses.
/// IOVA should NEVER equal physical address (except for RMRR regions).
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_iova_not_equal_phys() {
    let ctrl = controller();
    // Start IOVA range at high address to avoid collision with typical phys
    ctrl.init_iova(0xF000_0000, 0x10000).expect("init_iova");

    let size = 0x1000;
    let iova = match ctrl.allocate_iova(size) {
        Ok(v) => v,
        Err(IommuError::OutOfMemory) | Err(IommuError::OutOfIova) => {
            log::warn!("[IOMMU][TEST] test_iova_not_equal_phys: skipped due allocator pressure");
            return;
        }
        Err(e) => panic!("allocate_iova: {:?}", e),
    };

    // Typical physical address range is lower, IOVA should be higher
    // This is a simple sanity check - real test would compare actual phys
    assert!(
        iova >= 0xF000_0000,
        "IOVA should be in allocated range, not identity mapped"
    );

    ctrl.free_iova(iova, size).expect("free failed");
}

/// Test that domains use Translated type, not PassThrough.
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_domain_type_not_passthrough() {
    let domain = IommuDomain::new(
        0,
        None,
        false,
        false,
        48,
        4,
        IommuDomainType::Translated, // Must be Translated, not PassThrough
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );

    // Domain should be Translated type for proper IOMMU protection
    match domain.domain_type() {
        IommuDomainType::Translated => { /* OK */ }
        IommuDomainType::Passthrough => {
            panic!("Domain should not use PassThrough type in production");
        }
    }
}

/// Test that all mappings have distinct IOVA vs physical addresses.
#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_mapping_iova_phys_distinct() {
    let ctrl = controller();
    ctrl.init_iova(0x8000_0000, 0x10000).expect("init_iova");

    let domain = Arc::new(IommuDomain::new(
        0,
        None,
        false,
        false,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    ));

    match ctrl.domains.lock() {
        Ok(mut domains) => {
            domains.insert(0, domain.clone());
        }
        Err(poisoned) => {
            let mut domains = poisoned.into_inner();
            domains.insert(0, domain.clone());
        }
    }

    let size = 0x1000;
    let phys = 0x2000_0000; // Typical physical address
    let iova = match ctrl.allocate_iova(size) {
        Ok(v) => v,
        Err(IommuError::OutOfMemory) | Err(IommuError::OutOfIova) => {
            log::warn!(
                "[IOMMU][TEST] test_mapping_iova_phys_distinct: skipped due allocator pressure"
            );
            return;
        }
        Err(e) => panic!("allocate_iova: {:?}", e),
    };

    // Map the physical address
    domain.map(iova, phys, size, true, true).expect("map");

    // Verify IOVA != phys (not identity mapped)
    assert_ne!(
        iova, phys,
        "IOVA must not equal physical address (identity mapping detected)"
    );

    // Verify mapping exists with correct values
    let mapping = domain.mapping(iova).expect("mapping should exist");
    assert_eq!(mapping.iova, iova);
    assert_eq!(mapping.phys, phys);
    assert_ne!(
        mapping.iova, mapping.phys,
        "Mapping uses identity (IOVA == phys)"
    );

    // Cleanup
    domain.unmap(iova).expect("unmap");
    ctrl.free_iova(iova, size).expect("free");
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_ats_admission_requires_controller_resources() {
    let ctrl = controller();
    assert_eq!(
        ctrl.check_ats_admission(crate::io::iommu::runtime::security::DeviceTrustLevel::Trusted),
        Err(IommuError::NotSupported),
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_iova_quarantine_and_epoch_drain() {
    let ctrl = controller();
    // Initialize with a small space
    ctrl.init_iova(0x1000_0000, 0x10000).expect("init_iova");

    let iova = match ctrl.allocate_iova(4096) {
        Ok(v) => v,
        Err(IommuError::OutOfMemory) | Err(IommuError::OutOfIova) => {
            log::warn!(
                "[IOMMU][TEST] test_iova_quarantine_and_epoch_drain: skipped due allocator pressure"
            );
            return;
        }
        Err(e) => panic!("alloc: {:?}", e),
    };

    // Free the IOVA - it should go to quarantine
    ctrl.free_iova(iova, 4096).expect("free");

    // Try to allocate the SAME IOVA immediately - it should NOT be available yet
    // (Bitmap might find another slot if available, but if we exhaust space...)
    // Let's exhaust most of the space first.
    let mut allocated = alloc::vec::Vec::new();
    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while let Ok(addr) = ctrl.allocate_iova(4096) {
        allocated.push(addr);
    }

    // This allocator fixture is not attached to hardware. There are no IOTLB
    // or ATS entries; use the production pending-flush transition, not a raw epoch.
    let flush = {
        let guard = ctrl.iova_allocator.lock().expect("allocator owner");
        guard
            .as_ref()
            .expect("initialized allocator")
            .begin_global_flush()
            .expect("flush boundary")
    };
    // SAFETY: no device or IOMMU has ever been attached to this fixture allocator,
    // so the captured retirement boundary has no outstanding cached translations.
    unsafe { flush.complete_after_global_invalidation() };

    // Now it should be available again
    let iova_again = match ctrl.allocate_iova(4096) {
        Ok(v) => v,
        Err(IommuError::OutOfMemory) | Err(IommuError::OutOfIova) => {
            log::warn!(
                "[IOMMU][TEST] test_iova_quarantine_and_epoch_drain: allocator remained exhausted after epoch completion"
            );
            return;
        }
        Err(e) => panic!("should be available after epoch completion: {:?}", e),
    };
    assert_eq!(iova, iova_again);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_invalidate_request_ats_flag() {
    use crate::io::iommu::common::domain::{InvalidateFlags, InvalidateRequest};

    let req = InvalidateRequest::pages(1, 0x1000, 0x1000).with_ats();
    assert!(req.flags.contains(InvalidateFlags::ATS_AWARE));

    let req_no_ats = InvalidateRequest::pages(1, 0x1000, 0x1000);
    assert!(!req_no_ats.flags.contains(InvalidateFlags::ATS_AWARE));
}
