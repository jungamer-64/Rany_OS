// ============================================================================
// kernel/src/io/iommu/tests.rs
// ============================================================================

//! IOMMU Unit Tests
//!
//! Tests for IOMMU controller functionality, domain management, and invalidation.

use super::*;
use crate::io::iommu::controller::dma::DomainManager;
use crate::io::iommu::controller::iova::IovaManager;
use crate::io::iommu::controller::ir::InterruptRemapper;
use crate::io::iommu::controller::pri::PageRequestManager;
use crate::io::iommu::controller::qi_init::QIManager;
use crate::io::iommu::controller::qi_ops::InvalidationOps;

#[test]
fn test_device_id() {
    let dev = DeviceId::new(0, 0, 1, 0);
    assert_eq!(dev.requester_id(), 0x08); // bus=0, dev=1, func=0
}

#[test]
fn test_sl_pte() {
    let pte = SlPte::mapping(0x1000, true, true);
    assert!(pte.is_present());
    assert!(pte.can_read());
    assert!(pte.can_write());
    assert_eq!(pte.phys_addr(), 0x1000);
}

#[test]
fn test_iommu_domain() {
    let mut domain = IommuDomain::new(
        1,
        None,
        false,
        false,
        IommuDomainType::Translated,
        super::page_table_pool::PageTablePool::new(1, 32),
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

#[test]
fn test_create_domain_with_numa_hint() {
    let ctrl = IommuController::new(0x0, 0);
    let id = ctrl
        .create_domain(Some(2), IommuDomainType::Translated)
        .expect("create_domain failed");
    let domain_arc = ctrl.domain(id).expect("domain not found");
    {
        // Scope the guard so it is dropped before we call `set_domain_numa`
        let d = match domain_arc.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        assert_eq!(d.id(), id);
        assert_eq!(d.numa_node, Some(2));
    }

    // Test controller set/get API
    ctrl.set_domain_numa(id, Some(5))
        .expect("set_domain_numa failed");
    assert_eq!(ctrl.get_domain_numa(id), Some(5usize));
}

#[test]
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

#[test]
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

#[test]
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
                hw.context_tables.push(table);
            }
            Err(poisoned) => {
                let mut hw = poisoned.into_inner();
                hw.context_tables.push(table);
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
            .context_tables
            .get(0)
            .and_then(|t| t.get(0))
            .map(|e| e.is_present())
            .unwrap_or(false),
        Err(poisoned) => {
            let hw = poisoned.into_inner();
            hw.context_tables
                .get(0)
                .and_then(|t| t.get(0))
                .map(|e| e.is_present())
                .unwrap_or(false)
        }
    };
    assert!(!present);
}

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
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

#[test]
fn test_map_for_dma_alloc_non_identity() {
    let ctrl = IommuController::new(0x0, 0);
    ctrl.init_iova(0x8000_0000, 0x10000).expect("init_iova");

    // Create default domain 0 for mapping (use PoisonLock)
    let domain = Arc::new(PoisonLock::new(IommuDomain::new(
        0,
        None,
        false,
        false,
        IommuDomainType::Translated,
        super::page_table_pool::PageTablePool::new(1, 32),
        PteFormat::Intel,
    )));
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
        let mut domain = match domain_arc.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        domain
            .map(iova, phys, size, true, true)
            .expect("domain.map failed");
        assert!(domain.mappings().contains_key(&iova));

        let mapping = domain.unmap(iova).expect("unmap failed");
        assert_eq!(mapping.iova, iova);
        assert_eq!(mapping.phys, phys);
    }

    ctrl.free_iova(iova, size).expect("free failed");
}

#[test]
fn test_cmdqueue_map_unmap_with_domain() {
    // Construct a controller locally and attach a CQ (avoid global init timing issues)
    let mut ctrl_local = IommuController::new(0x0, 0);
    ctrl_local.command_queue = Some(crate::io::iommu_cmdqueue::CommandQueue::new());

    // Leak so we can reference it from threads in test
    let ctrl: &'static IommuController = Box::leak(Box::new(ctrl_local));
    let cq = ctrl.command_queue.as_ref().expect("cq present");

    // Create domain
    let domain_id = ctrl
        .create_domain(None, IommuDomainType::Translated)
        .expect("create domain");

    // Worker thread: act like executor and service mapping/unmapping commands
    let worker_cq: &'static crate::io::iommu_cmdqueue::CommandQueue = cq;
    let worker_ctrl: &'static IommuController = ctrl;
    let worker = std::thread::spawn(move || {
        let mut map_done = false;
        let mut unmap_done = false;
        let mut attempts = 0;
        while !(map_done && unmap_done) {
            eprintln!("[test][CQ] worker loop attempt {}", attempts);
            let processed = worker_cq.process_once(|k| match k {
                crate::io::iommu_cmdqueue::IommuCommandKind::MapRegion { .. } => {
                    eprintln!("[test][CQ] handling MapRegion");
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(_) => {
                            map_done = true;
                            Ok(0)
                        }
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu_cmdqueue::IommuCommandKind::UnmapRegion { .. } => {
                    eprintln!("[test][CQ] handling UnmapRegion");
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(_) => {
                            unmap_done = true;
                            Ok(0)
                        }
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu_cmdqueue::IommuCommandKind::InvalidateIotlbDomain { .. } => {
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu_cmdqueue::IommuCommandKind::InvalidateIotlbGlobal => {
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
    let map_cmd = crate::io::iommu_cmdqueue::IommuCommandKind::MapRegion {
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
    let d = match domain_arc.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert!(d.mappings().contains_key(&0x1000));
    drop(d);

    // Submit UnmapRegion
    let unmap_cmd = crate::io::iommu_cmdqueue::IommuCommandKind::UnmapRegion {
        domain: domain_id,
        iova: 0x1000,
        size: 0x1000,
    };
    assert!(cq.submit_sync(unmap_cmd).is_ok());

    worker.join().expect("worker join failed");

    let d = match domain_arc.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert!(!d.mappings().contains_key(&0x1000));
}

#[test]
fn test_map_for_device_async_and_unmap() {
    // Construct a controller locally and attach a CQ (avoid global init timing issues)
    let mut ctrl_local = IommuController::new(0x0, 0);
    ctrl_local.command_queue = Some(crate::io::iommu_cmdqueue::CommandQueue::new());

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
    if get_iommu_driver().is_none() {
        super::intel::IntelIommuDriver::register_driver();
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
                crate::io::iommu_cmdqueue::IommuCommandKind::MapRegion { .. } => {
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(0) => { map_done = true; Ok(0) },
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu_cmdqueue::IommuCommandKind::UnmapRegion { .. } => {
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(0) => { unmap_done = true; Ok(0) },
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu_cmdqueue::IommuCommandKind::InvalidateIotlbDomain { .. } => {
                    match worker_ctrl.handle_command_queue_entry(&k) {
                        Ok(_) => Ok(0),
                        Err(_) => Err(()),
                    }
                }
                crate::io::iommu_cmdqueue::IommuCommandKind::InvalidateIotlbGlobal => {
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
    let d = domain_arc.lock_for_init("test_map_for_device_async_and_unmap - confirming mapping");
    assert!(d.mappings().contains_key(&iova));
    drop(d);

    // Submit UnmapRegion asynchronously and wait
    crate::task::block_on(async {
        unmap_for_device_async(&device, iova, 0x1000)
            .await
            .expect("unmap")
    });

    worker.join().expect("worker join failed");

    let d = domain_arc.lock_for_init("test_map_for_device_async_and_unmap - confirming unmap");
    assert!(!d.mappings().contains_key(&iova));
}
/*
#[test]
fn test_init_iommu_registers_drhd_and_rmrr_and_applies_rmrr() {
    // Test removed due to dependency on global IommuManager which is deprecated.
}
*/

#[test]
fn test_unmap_reclaims_empty_tables() {
    let domain = Arc::new(PoisonLock::new(IommuDomain::new(
        1,
        None,
        false,
        false,
        IommuDomainType::Translated,
        super::page_table_pool::PageTablePool::new(1, 32),
        PteFormat::Intel,
    )));

    {
        let mut d = match domain.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Map a single page
        d.map(0x1000, 0x2000, 0x1000, true, true)
            .expect("map failed");

        // Verify mapping exists
        assert!(d.mappings().contains_key(&0x1000));

        // Unmap should reclaim PT, PD, PDP tables
        let mapping = d.unmap(0x1000).expect("unmap failed");
        assert_eq!(mapping.iova, 0x1000);
        assert_eq!(mapping.phys, 0x2000);

        // Verify page table entries are cleared (PML4 entry should be not present)
        unsafe {
            let pml4_entry = *d.page_table.add(0);
            assert!(
                !pml4_entry.is_present(),
                "PML4 entry should be cleared after unmap"
            );
        }
    }
}

#[test]
fn test_unmap_partial_keeps_tables() {
    let domain_arc = Arc::new(PoisonLock::new(IommuDomain::new(
        1,
        None,
        false,
        false,
        IommuDomainType::Translated,
        super::page_table_pool::PageTablePool::new(1, 32),
        PteFormat::Intel,
    )));
    let mut domain = match domain_arc.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

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

#[test]
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

#[test]
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

#[test]
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

#[test]
fn test_page_table_scope_commit_preserves_counts() {
    // Verify that commit doesn't overwrite existing counts and increments parent count.
    let mut page_table_counts = alloc::collections::BTreeMap::new();

    // Allocate a new page table scope
    let mut scope = PageTableScope::new(None).expect("allocate ptable");

    // Pre-populate a count for this table (simulate prior increment)
    page_table_counts.insert(scope.phys(), 42);

    // Create a fake parent entry and attach
    let mut parent_entry = SlPte::new();
    let parent_phys = 0xDEADBEEF;
    scope.attach_to_parent(
        &mut parent_entry as *mut SlPte,
        parent_phys,
        PteFormat::Intel,
        1,
    );

    // Commit should not overwrite existing count for scope.phys(), but should increment parent
    scope.commit(&mut page_table_counts);

    assert_eq!(page_table_counts.get(&scope.phys()), Some(&42u16));
    assert_eq!(page_table_counts.get(&parent_phys), Some(&1u16));
}

#[test]
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
struct MockSecurityNotifier {
    events: spin::Mutex<[Option<super::security::SecurityEvent>; 16]>,
    event_count: core::sync::atomic::AtomicUsize,
    isolation_decision: super::security::IsolationDecision,
}

impl MockSecurityNotifier {
    fn new() -> Self {
        Self {
            events: spin::Mutex::new([None; 16]),
            event_count: core::sync::atomic::AtomicUsize::new(0),
            isolation_decision: super::security::IsolationDecision::default(),
        }
    }

    fn with_decision(decision: super::security::IsolationDecision) -> Self {
        Self {
            events: spin::Mutex::new([None; 16]),
            event_count: core::sync::atomic::AtomicUsize::new(0),
            isolation_decision: decision,
        }
    }

    fn received_count(&self) -> usize {
        self.event_count.load(core::sync::atomic::Ordering::Relaxed)
    }

    fn last_event(&self) -> Option<super::security::SecurityEvent> {
        let count = self.received_count();
        if count == 0 {
            return None;
        }
        let idx = (count - 1) % 16;
        *self.events.lock().get(idx).unwrap_or(&None)
    }
}

impl super::security::SecurityNotifier for MockSecurityNotifier {
    fn notify(&self, event: super::security::SecurityEvent) {
        let idx = self
            .event_count
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed)
            % 16;
        self.events.lock()[idx] = Some(event);
    }

    fn decide(&self, _fault: &super::security::FaultSummary) -> super::security::IsolationDecision {
        self.isolation_decision
    }
}

#[test]
fn test_security_notifier_registration() {
    let ctrl = IommuController::new(0x0, 0);
    let notifier = Arc::new(MockSecurityNotifier::new());

    // First registration should succeed
    assert!(ctrl.set_security_notifier(notifier.clone()));

    // Second registration should fail (already set)
    let notifier2 = Arc::new(MockSecurityNotifier::new());
    assert!(!ctrl.set_security_notifier(notifier2));
}

#[test]
fn test_security_event_types_are_copy() {
    use super::security::{IsolationReason, SecurityEvent};

    // Verify SecurityEvent is Copy by assignment
    let event1 = SecurityEvent::DmaViolation {
        source_id: 0x0108,
        fault_address: 0x1000,
        reason: 0x01,
    };
    let event2 = event1; // Copy
    match event2 {
        SecurityEvent::DmaViolation { source_id, .. } => {
            assert_eq!(source_id, 0x0108);
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

#[test]
fn test_fault_summary_from_fault_record() {
    use super::fault_log::FaultRecord;
    use super::security::FaultSummary;

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

#[test]
fn test_isolation_decision_default() {
    use super::security::{IsolationDecision, IsolationReason};

    let decision = IsolationDecision::default();
    match decision {
        IsolationDecision::Isolate(IsolationReason::DmaFault) => {}
        _ => panic!("default should be Isolate(DmaFault)"),
    }
}
