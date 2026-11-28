// ============================================================================
// kernel/src/io/iommu/testkit/unit/mod.rs
// ============================================================================

//! IOMMU Unit Tests
//!
//! Tests for IOMMU controller functionality, domain management, and invalidation.

use crate::io::iommu::common::dma::page_table_pool::PageTablePool;
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::common::tables::SlPte;
use crate::io::iommu::runtime::fault_log::FaultRecord;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
use crate::io::iommu::vendors::intel::controller::IommuController;
use crate::io::iommu::vendors::intel::controller::dma::DomainManager;
use crate::io::iommu::vendors::intel::controller::qi_init::QIManager;
#[cfg(feature = "qemu-test-export")]
use crate::io::iommu::vendors::intel::controller::qi_ops::InvalidationOps;
use crate::io::iommu::vendors::intel::registers::ecap_bits;
use crate::io::iommu::vendors::intel::tables::{ContextEntry, PasidTableEntry};
use alloc::sync::Arc;

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
fn domain_creation_rejects_unadmitted_numa_node_without_publication() {
    let ctrl = controller();
    assert_eq!(
        ctrl.create_domain(
            Some(crate::mm::types::NumaNodeId::MAX_NODES),
            IommuDomainType::Translated,
        ),
        Err(IommuError::InvalidAddress)
    );
    assert!(ctrl.domains.lock().expect("domain registry").is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_create_domain_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = controller();
    // Poison domains lock
    let held = ctrl.domains.lock().expect("unpoisoned fixture lock");
    set_panicking(true);
    drop(held);
    set_panicking(false);
    assert!(ctrl.domains.is_poisoned());
    assert_eq!(
        ctrl.create_domain(Some(0), IommuDomainType::Translated)
            .err(),
        Some(IommuError::HardwareError)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_get_domain_for_device_poisoned_returns_hw_error() {
    use crate::sync::set_panicking;
    let ctrl = controller();
    let device = DeviceId::new(0, 0, 1, 0);
    assert_eq!(ctrl.get_domain_for_device(device), Ok(None));

    // Poison device_bindings lock
    let held = ctrl
        .device_bindings
        .lock()
        .expect("unpoisoned fixture lock");
    set_panicking(true);
    drop(held);
    set_panicking(false);
    assert!(ctrl.device_bindings.is_poisoned());

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
    assert_eq!(
        ctrl.set_domain_numa(0, Some(0)),
        Err(IommuError::DomainNotFound)
    );

    // Poison domains lock
    let held = ctrl.domains.lock().expect("unpoisoned fixture lock");
    set_panicking(true);
    drop(held);
    set_panicking(false);
    assert!(ctrl.domains.is_poisoned());

    assert_eq!(
        ctrl.set_domain_numa(0, Some(0)).err(),
        Some(IommuError::HardwareError)
    );
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_init_iova_poisoned_proceeds_with_best_effort() {
    use crate::sync::set_panicking;
    let ctrl = controller();

    // Poison the iova_allocator lock
    let held = ctrl.iova_allocator.lock().expect("unpoisoned fixture lock");
    set_panicking(true);
    drop(held);
    set_panicking(false);
    assert!(ctrl.iova_allocator.is_poisoned());

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
    let held = ctrl
        .invalidation_queue
        .lock()
        .expect("unpoisoned fixture lock");
    set_panicking(true);
    drop(held);
    set_panicking(false);
    assert!(ctrl.invalidation_queue.is_poisoned());

    let res = unsafe { ctrl.enable_queued_invalidation() };
    assert_eq!(res.err(), Some(IommuError::HardwareError));
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
fn test_ats_admission_requires_controller_resources() {
    let ctrl = controller();
    assert_eq!(
        ctrl.check_ats_admission(crate::io::iommu::runtime::security::DeviceTrustLevel::Trusted),
        Err(IommuError::NotSupported),
    );
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

#[cfg_attr(any(feature = "std", target_os = "linux"), test)]
#[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
fn fault_summary_decodes_requester_address_and_reason() {
    let record = FaultRecord {
        lo: 0x2000,
        hi: 0x8000_0042_0000_0108,
    };
    let summary = crate::io::iommu::runtime::security::FaultSummary::from(&record);
    assert_eq!(summary.source_id, 0x0108);
    assert_eq!(summary.fault_address, 0x2000);
    assert_eq!(summary.reason, 0x42);
}

#[cfg_attr(any(feature = "std", target_os = "linux"), test)]
#[cfg_attr(not(any(feature = "std", target_os = "linux")), test_case)]
fn faults_default_to_device_isolation() {
    use crate::io::iommu::runtime::security::{IsolationDecision, IsolationReason};
    assert!(matches!(
        IsolationDecision::default(),
        IsolationDecision::Isolate(IsolationReason::DmaFault)
    ));
}
