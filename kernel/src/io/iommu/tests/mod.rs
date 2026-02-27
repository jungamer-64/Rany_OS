// ============================================================================
// kernel/src/io/iommu/tests/mod.rs
// ============================================================================

//! IOMMU Unit Tests
//!
//! Tests for IOMMU controller functionality, domain management, and invalidation.

#[cfg(feature = "qemu-test-export")]
pub mod qemu;

use crate::io::iommu::runtime::config::IommuConfig;
use crate::io::iommu::core::domain::IommuDomain;
use crate::io::iommu::runtime::fault_log::FaultRecord;
use crate::io::iommu::core::dma::page_table_pool::PageTablePool;
use crate::io::iommu::runtime::registry::{get_iommu_driver, get_iommu_registry, init_registry, IommuRegistry};
use crate::io::iommu::core::tables::{HardwareTable, PageTableScope, SlPte, virt_ptr_to_phys};
use crate::io::iommu::core::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
use crate::io::iommu::backends::intel::controller::IommuController;
use crate::io::iommu::backends::intel::tables::{ContextEntry, RootEntry, ScalableContextEntry};
use alloc::sync::Arc;
use crate::io::iommu::backends::intel::controller::dma::DomainManager;
use crate::io::iommu::backends::intel::controller::fault::{
    drain_deferred_faults_with_controller, push_deferred_fault_for_test, RawFaultEvent,
};
use crate::io::iommu::backends::intel::controller::iova::IovaManager;
use crate::io::iommu::backends::intel::controller::ir::InterruptRemapper;
use crate::io::iommu::backends::intel::controller::pri::PageRequestManager;
use crate::io::iommu::backends::intel::controller::qi_init::QIManager;
use crate::io::iommu::backends::intel::controller::qi_ops::InvalidationOps;
use crate::io::iommu::backends::intel::qi::{InvalidationQueue, InvalidationQueueEntry};
use crate::io::iommu::backends::intel::registers::ecap_bits;
use crate::io::iommu::runtime::security::{SecurityEvent, SecurityNotifier};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

#[test_case]
fn test_device_id() {
    let dev = DeviceId::new(0, 0, 1, 0);
    assert_eq!(dev.requester_id(), 0x08); // bus=0, dev=1, func=0
}

#[test_case]
fn test_sl_pte() {
    let pte = SlPte::mapping(0x1000, true, true);
    assert!(pte.is_present());
    assert!(pte.can_read());
    assert!(pte.can_write());
    assert_eq!(pte.phys_addr(), 0x1000);
}

#[test_case]
fn test_iommu_domain() {
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
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

#[test_case]
fn test_page_table_addr_returns_root_phys() {
    let domain = IommuDomain::new(
        10,
        None,
        false,
        false,
        48,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );

    let expected = virt_ptr_to_phys(domain.page_table as *const u8)
        .expect("failed to translate page table virtual address");
    assert_eq!(domain.page_table_addr(), expected);
}

#[test_case]
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
    let wait = queue.wait_entry();
    assert_eq!(wait.hi, expected_status_phys);
    assert_eq!(wait.hi & 0xFFF, 0);
    assert_eq!(queue.submit_wait(), status_virt);
}

unsafe fn is_4k_mapped(domain: &IommuDomain, iova: u64, format: PteFormat) -> bool {
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

unsafe fn is_superpage_2mb_mapped(domain: &IommuDomain, iova: u64, format: PteFormat) -> bool {
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

#[test_case]
fn test_map_rollback_on_overlap_hidden_mapping() {
    let format = PteFormat::Intel;
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
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

#[test_case]
fn test_map_rollback_on_overlap_hidden_mapping_amd() {
    let format = PteFormat::Amd;
    let domain = IommuDomain::new(
        2,
        None,
        true,
        true,
        48,
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

#[test_case]
fn test_map_rollback_superpage_2mb_collision() {
    let format = PteFormat::Amd;
    let domain = IommuDomain::new(
        3,
        None,
        true,
        false,
        48,
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

#[test_case]
fn test_create_domain_with_numa_hint() {
    let ctrl = IommuController::new(0x0, 0);
    let id = ctrl
        .create_domain(Some(2), IommuDomainType::Translated)
        .expect("create_domain failed");
    let domain_arc = ctrl.domain(id).expect("domain not found");
    assert_eq!(domain_arc.id(), id);
    assert_eq!(domain_arc.numa_node(), Some(2));

    // Test controller set/get API
    ctrl.set_domain_numa(id, Some(5))
        .expect("set_domain_numa failed");
    assert_eq!(ctrl.get_domain_numa(id), Some(5usize));
}

#[test_case]
fn test_process_page_requests_poisoned_returns_empty() {
    use crate::sync::set_panicking;
    let mut ctrl = IommuController::new(0x0, 0);
    set_panicking(true);
    if let Ok(_g) = ctrl.page_request_queue.lock() {
        // drop to poison
    }
    set_panicking(false);
    let requests = ctrl.process_page_requests();
    assert!(requests.is_empty());
}

#[test_case]
fn test_create_domain_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = IommuController::new(0x0, 0);
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

#[test_case]
fn test_isolate_faulting_device_poisoned_attempts_isolation() {
    use crate::sync::set_panicking;
    let ctrl = IommuController::new(0x0, 0);

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
        lo: FaultRecord::FAULT,
        hi: 0,
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

#[test_case]
fn test_scalable_mode_pasid0_fault_resolution() {
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

    let ctrl = IommuController::new(0x0, 0);
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
    ctrl.set_security_notifier(Arc::clone(&notifier));

    push_deferred_fault_for_test(RawFaultEvent {
        source_id: device.requester_id(),
        fault_address: 0xdeadbeef,
        reason: 0x05,
        pasid: Some(0),
        lo: 0,
        hi: 0,
        is_overflow: false,
    });

    drain_deferred_faults_with_controller(Some(&ctrl));

    assert!(notifier.seen());
    assert_eq!(notifier.domain_id(), domain_id as u32);
}

#[test_case]
fn test_domain_map_poisoned_returns_none() {
    use crate::sync::set_panicking;
    let ctrl = IommuController::new(0x0, 0);
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

#[test_case]
fn test_get_domain_for_device_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = IommuController::new(0x0, 0);
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

#[test_case]
fn test_set_domain_numa_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = IommuController::new(0x0, 0);
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

#[test_case]
fn test_iova_allocator_basic() {
    let ctrl = IommuController::new(0x0, 0);
    // Small IOVA space for testing (64KB)
    ctrl.init_iova(0x1000_0000, 0x10000)
        .expect("init_iova failed");

    let a = ctrl.allocate_iova(4096).expect("alloc 4K");
    assert_eq!(a % 4096, 0);

    let b = ctrl.allocate_iova(8192).expect("alloc 8K");
    assert_ne!(a, b);

    ctrl.free_iova(a, 4096).expect("free failed");

    let _c = ctrl.allocate_iova(4096).expect("alloc after free");
}

#[test_case]
fn test_init_iova_poisoned_proceeds_with_best_effort() {
    use crate::sync::set_panicking;
    let ctrl = IommuController::new(0x0, 0);

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

#[test_case]
fn test_init_interrupt_remapping_poisoned_proceeds_with_best_effort() {
    use crate::sync::set_panicking;
    let mut ctrl = IommuController::new(0x0, 0);

    // Enable Interrupt Remapping capability
    ctrl.ecap |= ecap_bits::ECAP_IR;

    // Poison the interrupt_remap_table lock during init
    set_panicking(true);
    if let Ok(_g) = ctrl.interrupt_remap_table.lock() {
        // drop to poison
    }
    set_panicking(false);

    // Init should proceed with best-effort
    ctrl.init_interrupt_remapping(4)
        .expect("init_interrupt_remapping failed");

    match ctrl.interrupt_remap_table.lock() {
        Ok(g) => assert!(g.is_some()),
        Err(poisoned) => {
            let guard = poisoned.into_inner();
            assert!(guard.is_some());
        }
    }
}

#[test_case]
fn test_enable_queued_invalidation_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = IommuController::new(0x0, 0);

    // Poison invalidation_queue lock
    set_panicking(true);
    if let Ok(_g) = ctrl.invalidation_queue.lock() {
        // drop to poison
    }
    set_panicking(false);

    let res = unsafe { ctrl.enable_queued_invalidation() };
    assert_eq!(res.err(), Some(IommuError::HardwareError));
}

#[test_case]
fn test_map_for_dma_alloc_non_identity() {
    let ctrl = IommuController::new(0x0, 0);
    ctrl.init_iova(0x8000_0000, 0x10000).expect("init_iova");

    // Create default domain 0 for mapping
    let domain = Arc::new(IommuDomain::new(
        0,
        None,
        false,
        false,
        48,
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

    let iova = ctrl.allocate_iova(size).expect("allocate_iova");

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

#[test_case]
fn test_cmdqueue_map_unmap_with_domain() {
    // Construct a controller locally and attach a CQ (avoid global init timing issues)
    let mut ctrl_local = IommuController::new(0x0, 0);
    ctrl_local.command_queue = Some(crate::io::iommu::runtime::command::queue::CommandQueue::new());

    // Leak so we can reference it from threads in test
    let ctrl: &'static IommuController = Box::leak(Box::new(ctrl_local));
    let cq = ctrl.command_queue.as_ref().expect("cq present");

    // Create domain
    let domain_id = ctrl
        .create_domain(None, IommuDomainType::Translated)
        .expect("create domain");

    // Worker thread: act like executor and service mapping/unmapping commands
    let worker_cq: &'static crate::io::iommu::runtime::command::queue::CommandQueue = cq;
    let worker_ctrl: &'static IommuController = ctrl;
    let worker = std::thread::spawn(move || {
        let mut map_done = false;
        let mut unmap_done = false;
        let mut attempts = 0;
        while !(map_done && unmap_done) {
            eprintln!("[test][CQ] worker loop attempt {}", attempts);
            let processed = worker_cq.process_once(|k| match k {
                crate::io::iommu::runtime::command::queue::IommuCommandKind::MapRegion { .. } => {
                    eprintln!("[test][CQ] handling MapRegion");
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(_) => {
                            map_done = true;
                            Ok(0)
                        }
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu::runtime::command::queue::IommuCommandKind::MapRegionDevice { .. } => Err(()),
                crate::io::iommu::runtime::command::queue::IommuCommandKind::UnmapRegion { .. } => {
                    eprintln!("[test][CQ] handling UnmapRegion");
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(_) => {
                            unmap_done = true;
                            Ok(0)
                        }
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu::runtime::command::queue::IommuCommandKind::UnmapRegionDevice { .. } => Err(()),
                crate::io::iommu::runtime::command::queue::IommuCommandKind::InvalidateIotlbDomain { .. } => {
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu::runtime::command::queue::IommuCommandKind::InvalidateIotlbGlobal => {
                    match worker_ctrl.handle_command_queue_entry(k) {
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
            });

            if processed > 0 {
                eprintln!("[test][CQ] worker processed {} commands", processed);
            }

            attempts += 1;
            if attempts > 2000 {
                panic!("CQ worker timed out");
            }
            std::thread::yield_now();
        }
    });

    // Submit MapRegion (blocking until worker processes)
    let map_cmd = crate::io::iommu::runtime::command::queue::IommuCommandKind::MapRegion {
        domain: domain_id,
        iova: 0x1000,
        phys: 0x2000,
        size: 0x1000,
        read: true,
        write: true,
    };
    assert!(cq.submit_sync(map_cmd).is_ok());

    // Confirm mapping exists
    let domain_arc = ctrl.domain(domain_id).expect("domain not found");
    assert!(domain_arc.mapping(0x1000).is_some());

    // Submit UnmapRegion
    let unmap_cmd = crate::io::iommu::runtime::command::queue::IommuCommandKind::UnmapRegion {
        domain: domain_id,
        iova: 0x1000,
        size: 0x1000,
    };
    assert!(cq.submit_sync(unmap_cmd).is_ok());

    worker.join().expect("worker join failed");

    assert!(domain_arc.mapping(0x1000).is_none());
}

#[test_case]
fn test_map_for_device_async_and_unmap() {
    // Construct a controller locally and attach a CQ (avoid global init timing issues)
    let mut ctrl_local = IommuController::new(0x0, 0);
    ctrl_local.command_queue = Some(crate::io::iommu::runtime::command::queue::CommandQueue::new());

    // Instead of leaking, wrap the controller in an Arc and register it in the global registry
    use alloc::sync::Arc as AllocArc;
    let arc_ctrl = AllocArc::new(ctrl_local);

    // Build a registry containing our test controller and install it (Once)
    let registry = IommuRegistry::new(
        alloc::vec![arc_ctrl.clone()],
        Vec::new(),
        IommuConfig::default(),
    );
    init_registry(registry);
    arc_ctrl
        .init_iova(0x1000, 0x1_0000_0000 - 0x1000)
        .expect("init_iova");
    if get_iommu_driver().is_none() {
        crate::io::iommu::backends::intel::IntelIommuDriver::register_driver();
    }

    // Obtain controller Arc for worker
    let worker_ctrl = arc_ctrl.clone();

    // Create domain for the device
    let domain_id = arc_ctrl
        .create_domain(None, IommuDomainType::Translated)
        .expect("create domain");

    // Register device -> domain mapping
    let device = DeviceId::new(0, 0, 1, 0);
    match arc_ctrl.device_domains.lock() {
        Ok(mut dmap) => {
            dmap.insert(device, domain_id);
        }
        Err(_) => {
            panic!("device_domains poisoned");
        }
    }

    // Worker thread: act like executor and service mapping/unmapping commands
    let worker =
        std::thread::spawn(move || {
            let mut map_done = false;
            let mut unmap_done = false;
            let mut attempts = 0;
            while !(map_done && unmap_done) {
                let processed =
                    worker_ctrl
                        .command_queue
                        .as_ref()
                        .expect("cq present")
                        .process_once(|k| {
                            match k {
                crate::io::iommu::runtime::command::queue::IommuCommandKind::MapRegion { .. } => {
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(0) => { map_done = true; Ok(0) },
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu::runtime::command::queue::IommuCommandKind::MapRegionDevice { .. } => Err(()),
                crate::io::iommu::runtime::command::queue::IommuCommandKind::UnmapRegion { .. } => {
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(0) => { unmap_done = true; Ok(0) },
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu::runtime::command::queue::IommuCommandKind::UnmapRegionDevice { .. } => Err(()),
                crate::io::iommu::runtime::command::queue::IommuCommandKind::InvalidateIotlbDomain { .. } => {
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu::runtime::command::queue::IommuCommandKind::InvalidateIotlbGlobal => {
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
            }
                        });

                if processed > 0 { /* continue */ }

                attempts += 1;
                if attempts > 2000 {
                    panic!("CQ worker timed out");
                }
                std::thread::yield_now();
            }
        });

    let phys = x86_64::PhysAddr::new(0x2000);
    // Submit MapRegion asynchronously and block-wait for completion
    let iova = crate::task::block_on(async {
        // SAFETY: Test-allocated physical address for testing purposes
        unsafe { map_for_device_async(&device, phys, 0x1000).await }.expect("map")
    });

    // Confirm mapping exists
    let domain_arc = arc_ctrl.domain(domain_id).expect("domain not found");
    assert!(domain_arc.mapping(iova).is_some());

    // Submit UnmapRegion asynchronously and wait
    crate::task::block_on(async {
        unmap_for_device_async(&device, iova, 0x1000)
            .await
            .expect("unmap")
    });

    worker.join().expect("worker join failed");

    assert!(domain_arc.mapping(iova).is_none());
}

#[test_case]
fn test_map_for_device_respects_dma_mask() {
    use alloc::sync::Arc as AllocArc;

    let controller = if let Some(registry) = get_iommu_registry() {
        registry
            .controllers
            .get(0)
            .cloned()
            .expect("no IOMMU controller in registry")
    } else {
        let ctrl = IommuController::new(0x0, 0);
        let arc_ctrl = AllocArc::new(ctrl);
        let registry = IommuRegistry::new(
            alloc::vec![arc_ctrl.clone()],
            Vec::new(),
            IommuConfig::default(),
        );
        init_registry(registry);
        arc_ctrl
    };

    if get_iommu_driver().is_none() {
        crate::io::iommu::backends::intel::IntelIommuDriver::register_driver();
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
    let iova = unsafe { crate::io::iommu::api::map_for_device(&device, phys, 0x1000) }
        .expect("map for device with mask");
    assert!(iova + 0x1000 - 1 <= 0xFFFF_FFFF);
    crate::io::iommu::api::unmap_for_device(&device, iova, 0x1000).expect("unmap");
}
/*
#[test_case]
fn test_init_iommu_registers_drhd_and_rmrr_and_applies_rmrr() {
    // Test removed due to dependency on global IommuManager which is deprecated.
}
*/

#[test_case]
fn test_unmap_reclaims_empty_tables() {
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
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

#[test_case]
fn test_unmap_partial_keeps_tables() {
    let domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        48,
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

#[test_case]
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

#[test_case]
fn test_submit_invalidation_poisoned_returns_error() {
    let mut ctrl = IommuController::new(0x0, 0);

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

#[test_case]
fn test_qi_wait_sync_poisoned_returns_error() {
    let mut ctrl = IommuController::new(0x0, 0);

    // Enable queued invalidation support for testing
    ctrl.ecap = ecap_bits::ECAP_QI;
    eprintln!("[test] calling init_queued_invalidation");
    ctrl.init_queued_invalidation(8).expect("init_qi failed");
    eprintln!("[test] init_queued_invalidation returned");

    // Poison the invalidation_queue lock
    eprintln!("[test] before acquiring guard");
    {
        let _guard = ctrl.invalidation_queue.lock().unwrap();
        eprintln!("[test] acquired guard; setting panicking");
        crate::sync::set_panicking(true);
        eprintln!("[test] set_panicking(true) called");
    }
    eprintln!("[test] dropped guard; clearing panicking");
    crate::sync::set_panicking(false);
    eprintln!("[test] calling qi_wait_sync");

    let res = ctrl.qi_wait_sync();
    eprintln!("[test] qi_wait_sync returned: {:?}", res);
    assert_eq!(res, Err(IommuError::HardwareError));
}

#[test_case]
fn test_qi_wait_async_poisoned_returns_error() {
    let mut ctrl = IommuController::new(0x0, 0);

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

#[test_case]
fn test_qi_metrics_pressure() {
    let mut ctrl = IommuController::new(0x0, 0);

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

#[test_case]
fn test_page_table_scope_commit_preserves_counts() {
    // Verify that commit doesn't overwrite existing counts and increments parent count.
    let mut scope = PageTableScope::new(None).expect("allocate ptable");
    let scope_phys = scope.phys();
    let parent_phys = 0xDEADBEEF;

    crate::io::iommu::core::dma::page_table_pool::register_page_table(scope_phys, 0, 0);
    for _ in 0..42 {
        crate::io::iommu::core::dma::page_table_pool::inc_ref(scope_phys);
    }
    crate::io::iommu::core::dma::page_table_pool::register_page_table(parent_phys, 0, 0);

    // Create a fake parent entry and attach
    let mut parent_entry = SlPte::new();
    scope.attach_to_parent(
        &mut parent_entry as *mut SlPte,
        parent_phys,
        PteFormat::Intel,
        1,
    );

    // Commit should not overwrite existing count for scope.phys(), but should increment parent
    scope.commit();

    assert_eq!(crate::io::iommu::core::dma::page_table_pool::get_ref_count(scope_phys), 42);
    assert_eq!(crate::io::iommu::core::dma::page_table_pool::get_ref_count(parent_phys), 1);

    crate::io::iommu::core::dma::page_table_pool::unregister_page_table(parent_phys);
    crate::io::iommu::core::dma::page_table_pool::unregister_page_table(scope_phys);
}

#[test_case]
fn test_page_table_scope_drop_rolls_back_parent() {
    // Verify that dropping an uncommitted scope clears parent entry and frees memory.
    let parent_phys = 0xBABA;
    let mut parent_entry = SlPte::new();
    {
        let mut scope = PageTableScope::new(None).expect("allocate ptable");
        // Attach to parent; don't commit
        // Attach to parent; don't commit
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
    events: spin::Mutex<[Option<crate::io::iommu::runtime::security::SecurityEvent>; 16]>,
    event_count: core::sync::atomic::AtomicUsize,
    isolation_decision: crate::io::iommu::runtime::security::IsolationDecision,
}

impl MockSecurityNotifier {
    fn new() -> Self {
        Self {
            events: spin::Mutex::new([None; 16]),
            event_count: core::sync::atomic::AtomicUsize::new(0),
            isolation_decision: crate::io::iommu::runtime::security::IsolationDecision::default(),
        }
    }

    fn with_decision(decision: crate::io::iommu::runtime::security::IsolationDecision) -> Self {
        Self {
            events: spin::Mutex::new([None; 16]),
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

    fn decide(&self, _fault: &crate::io::iommu::runtime::security::FaultSummary) -> crate::io::iommu::runtime::security::IsolationDecision {
        self.isolation_decision
    }
}

#[test_case]
fn test_security_notifier_registration() {
    let ctrl = crate::io::iommu::backends::intel::controller::IommuController::new(0x0, 0);
    let notifier = Arc::new(MockSecurityNotifier::new());

    // First registration should succeed
    assert!(ctrl.set_security_notifier(notifier.clone()));

    // Second registration should fail (already set)
    let notifier2 = Arc::new(MockSecurityNotifier::new());
    assert!(!ctrl.set_security_notifier(notifier2));
}

#[test_case]
fn test_api_security_notifier_registration() {
    use crate::io::iommu::backends::intel::registry::{get_iommu_registry, init_registry, IommuRegistry};
    use crate::io::iommu::runtime::registry::get_iommu_driver;
    use crate::io::iommu::runtime::config::IommuConfig;
    use crate::io::iommu::backends::intel::controller::IommuController;

    if get_iommu_registry().is_none() {
        let ctrl = IommuController::new(0x0, 0);
        let registry =
            IommuRegistry::new(alloc::vec![Arc::new(ctrl)], Vec::new(), IommuConfig::default());
        init_registry(registry);
    }

    if get_iommu_driver().is_none() {
        crate::io::iommu::backends::intel::IntelIommuDriver::register_driver();
    }

    let notifier = Arc::new(MockSecurityNotifier::new());
    let first = crate::io::iommu::api::set_security_notifier(notifier).expect("set notifier");
    assert!(first);

    let notifier2 = Arc::new(MockSecurityNotifier::new());
    let second = crate::io::iommu::api::set_security_notifier(notifier2).expect("set notifier");
    assert!(!second);
}

#[test_case]
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

#[test_case]
fn test_fault_summary_from_fault_record() {
    use crate::io::iommu::runtime::security::FaultSummary;

    // Create a mock FaultRecord
    let record = FaultRecord {
        lo: (0x0108u64 << FaultRecord::SID_SHIFT) | 0x42, // source_id=0x0108, reason=0x42
        hi: 0x2000,                                       // fault_address=0x2000
    };

    let summary = FaultSummary::from(&record);
    assert_eq!(summary.source_id, 0x0108);
    assert_eq!(summary.fault_address, 0x2000);
    assert_eq!(summary.reason, 0x42);
}

#[test_case]
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

/// Test that identity mapping is disabled by default in release builds.
/// This ensures that IOVAs are always different from physical addresses.
#[test_case]
fn test_identity_mapping_disabled_by_default() {
    // In release builds without unsafe_iommu_bypass, identity mapping should be disabled
    #[cfg(not(any(feature = "unsafe_iommu_bypass", debug_assertions)))]
    {
        assert!(
            !crate::io::iommu::api::is_unsafe_identity_mapping_allowed(),
            "Identity mapping should be disabled by default in release builds"
        );
    }
}

/// Test that IOVA allocation produces non-identity addresses.
/// IOVA should NEVER equal physical address (except for RMRR regions).
#[test_case]
fn test_iova_not_equal_phys() {
    let ctrl = IommuController::new(0x0, 0);
    // Start IOVA range at high address to avoid collision with typical phys
    ctrl.init_iova(0xF000_0000, 0x10000).expect("init_iova");

    let size = 0x1000;
    let iova = ctrl.allocate_iova(size).expect("allocate_iova");

    // Typical physical address range is lower, IOVA should be higher
    // This is a simple sanity check - real test would compare actual phys
    assert!(
        iova >= 0xF000_0000,
        "IOVA should be in allocated range, not identity mapped"
    );

    ctrl.free_iova(iova, size).expect("free failed");
}

/// Test that domains use Translated type, not PassThrough.
#[test_case]
fn test_domain_type_not_passthrough() {
    let domain = IommuDomain::new(
        0,
        None,
        false,
        false,
        48,
        IommuDomainType::Translated, // Must be Translated, not PassThrough
        PageTablePool::new(1, 32),
        PteFormat::Intel,
    );

    // Domain should be Translated type for proper IOMMU protection
    match domain.domain_type() {
        IommuDomainType::Translated => { /* OK */ }
        IommuDomainType::PassThrough => {
            panic!("Domain should not use PassThrough type in production");
        }
    }
}

/// Test that all mappings have distinct IOVA vs physical addresses.
#[test_case]
fn test_mapping_iova_phys_distinct() {
    let ctrl = IommuController::new(0x0, 0);
    ctrl.init_iova(0x8000_0000, 0x10000).expect("init_iova");

    let domain = Arc::new(IommuDomain::new(
        0,
        None,
        false,
        false,
        48,
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
    let iova = ctrl.allocate_iova(size).expect("allocate_iova");

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
    assert_ne!(mapping.iova, mapping.phys, "Mapping uses identity (IOVA == phys)");

    // Cleanup
    domain.unmap(iova).expect("unmap");
    ctrl.free_iova(iova, size).expect("free");
}


#[test_case]
fn test_ats_enable_requires_qi() {
    let ctrl = IommuController::new(0x0, 0);
    let device = DeviceId::new(0, 0, 1, 0);
    
    // 1. Try to enable ATS without QI enabled
    ctrl.qi_enabled.store(false, Ordering::Release);
    let success = ctrl.enable_ats_for_device(device, crate::io::iommu::runtime::security::DeviceTrustLevel::Trusted);
    assert!(!success, "ATS should not be enabled if QI is disabled");
    
    // 2. Enable QI support (mock)
    ctrl.ecap |= ecap_bits::ECAP_QI;
    ctrl.qi_enabled.store(true, Ordering::Release);
    
    // Now it should succeed
    let success = ctrl.enable_ats_for_device(device, crate::io::iommu::runtime::security::DeviceTrustLevel::Trusted);
    assert!(success, "ATS should be enabled if QI is enabled and device is trusted");
    assert!(ctrl.is_ats_enabled(&device));
}

#[test_case]
fn test_iova_quarantine_and_epoch_drain() {
    let ctrl = IommuController::new(0x0, 0);
    // Initialize with a small space
    ctrl.init_iova(0x1000_0000, 0x10000).expect("init_iova");

    let iova = ctrl.allocate_iova(4096).expect("alloc");
    
    // Advance epoch so the free will be associated with a new epoch
    let epoch = if let Ok(guard) = ctrl.iova_allocator.lock() {
        guard.as_ref().unwrap().advance_epoch()
    } else {
        panic!("lock failed");
    };

    // Free the IOVA - it should go to quarantine
    ctrl.free_iova(iova, 4096).expect("free");

    // Try to allocate the SAME IOVA immediately - it should NOT be available yet
    // (Bitmap might find another slot if available, but if we exhaust space...)
    // Let's exhaust most of the space first.
    let mut allocated = alloc::vec::Vec::new();
    while let Ok(addr) = ctrl.allocate_iova(4096) {
        allocated.push(addr);
    }
    
    // Now space is exhausted. If we complete the epoch, `iova` should become available.
    if let Ok(guard) = ctrl.iova_allocator.lock() {
        guard.as_ref().unwrap().complete_epoch(epoch);
    }

    // Now it should be available again
    let iova_again = ctrl.allocate_iova(4096).expect("should be available after epoch completion");
    assert_eq!(iova, iova_again);
}

#[test_case]
fn test_invalidate_request_ats_flag() {
    use crate::io::iommu::core::domain::{InvalidateRequest, InvalidateFlags};
    
    let req = InvalidateRequest::pages(1, 0x1000, 0x1000).with_ats();
    assert!(req.flags.contains(InvalidateFlags::ATS_AWARE));
    
    let req_no_ats = InvalidateRequest::pages(1, 0x1000, 0x1000);
    assert!(!req_no_ats.flags.contains(InvalidateFlags::ATS_AWARE));
}
