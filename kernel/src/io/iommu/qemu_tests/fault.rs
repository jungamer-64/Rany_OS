use crate::io::iommu::common::tables::HardwareTable;
use crate::io::iommu::runtime::security::{
    FaultSummary, IsolationDecision, SecurityEvent, SecurityNotifier,
};
use crate::io::iommu::types::{DeviceId, IommuDomainType};
use crate::io::iommu::vendors::intel::controller::IommuController;
use crate::io::iommu::vendors::intel::controller::dma::DomainManager;
use crate::io::iommu::vendors::intel::controller::fault::FaultHandler;
use crate::io::iommu::vendors::intel::tables::{RootEntry, ScalableContextEntry};
use crate::sync::PoisonLock;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

struct RegisterMemory(core::cell::UnsafeCell<[u64; 512]>);
// SAFETY: construction transfers the sole register access to one local
// controller. No other CPU, interrupt, worker or RAM borrow accesses it.
unsafe impl Sync for RegisterMemory {}

fn unpublished_controller(fault_high: u64) -> IommuController {
    let mut words = [0; 512];
    // One FRCD at 0x300, four-level 48-bit translation and IOTLB at 0x200.
    words[1] = (2 << 8) | (47 << 16) | (0x30 << 24);
    words[2] = 0x20 << 8;
    words[0x34 / 8] = 2 << 32; // FSTS.PPF
    words[0x300 / 8] = 0xdead_b000;
    words[0x308 / 8] = fault_high;
    let owner = Arc::new(RegisterMemory(core::cell::UnsafeCell::new(words)));
    let base = owner.0.get().cast::<u64>().addr();
    // SAFETY: this retained aligned aperture is exclusively accessed through
    // the controller's register protocol. It is never device-visible MMIO.
    let registers = unsafe { hal::MappedMmio::from_raw_parts(owner, base, 4096) }
        .expect("local fault register aperture");
    IommuController::new(registers, 0).expect("unpublished controller admission")
}

#[derive(Debug)]
struct Observation {
    event: PoisonLock<Option<SecurityEvent>>,
    decisions: AtomicUsize,
}

impl SecurityNotifier for Observation {
    fn notify(&self, event: SecurityEvent) {
        let mut observed = self.event.lock().expect("fault observation");
        assert!(observed.replace(event).is_none());
    }

    fn decide(&self, _: &FaultSummary) -> IsolationDecision {
        self.decisions.fetch_add(1, Ordering::Relaxed);
        // This local hierarchy has no device references to revoke.
        IsolationDecision::LogOnly
    }
}

fn observe_fault(fault_high: u64, expected_domain_index: Option<usize>) {
    let controller = unpublished_controller(fault_high);
    controller.set_scalable_mode_enabled(true);
    let domains = [
        controller
            .create_domain(None, IommuDomainType::Translated)
            .expect("RID domain"),
        controller
            .create_domain(None, IommuDomainType::Translated)
            .expect("PASID domain"),
    ];
    let roots = domains.map(|id| {
        controller
            .domain(id)
            .expect("registered domain")
            .page_table_addr()
    });
    let device = DeviceId::new(0, 0, 1, 0);
    {
        let mut hardware = controller.hardware.lock().expect("local context owner");
        hardware.root_table = Some(HardwareTable::<RootEntry>::new(256, None).expect("root RAM"));
        hardware
            .scalable_context_tables
            .push(HardwareTable::<ScalableContextEntry>::new(256, None).expect("context RAM"));
        controller
            .attach_device_scalable(
                &mut hardware,
                0,
                8,
                IommuDomainType::Translated,
                roots[0],
                domains[0],
                device,
            )
            .expect("unpublished scalable context preparation");
        let root = hardware.root_table.as_ref().unwrap().get(0).unwrap();
        assert_eq!(root.lo & 1, 1);
        assert_eq!(root.hi & 1, 1);
        let context = hardware.scalable_context_tables[0].get(8).unwrap();
        assert!(context.is_present());
        assert_eq!(context.qwords[1] & 0xfffff, 0);
    }
    {
        let mut tables = controller
            .device_pasid_tables
            .lock()
            .unwrap_or_else(|_| panic!("PASID owner registry poisoned"));
        let table = tables.get_mut(&device).expect("prepared PASID directory");
        table
            .setup_sl_entry(5, roots[1], controller.selected_agaw_code(), domains[1])
            .expect("independent PASID association");
        assert_eq!(table.domain_id(0), Some(domains[0]));
        assert_eq!(table.domain_id(5), Some(domains[1]));
        assert_eq!(table.domain_id(6), None);
        assert_eq!(table.domain_id(64), None);
    }
    assert!(
        controller
            .device_domains
            .lock()
            .expect("RID registry")
            .is_empty()
    );
    let observation = Arc::new(Observation {
        event: PoisonLock::new(None),
        decisions: AtomicUsize::new(0),
    });
    let notifier = Arc::clone(&observation);
    assert!(controller.set_security_notifier(notifier));

    assert_eq!(controller.process_faults(), 1);
    assert!(
        observation
            .event
            .lock()
            .expect("before deferred drain")
            .is_none()
    );
    assert_eq!(observation.decisions.load(Ordering::Relaxed), 0);
    assert_eq!(controller.drain_deferred_faults(), 1);
    assert_eq!(controller.drain_deferred_faults(), 0);
    assert_eq!(observation.decisions.load(Ordering::Relaxed), 1);
    match observation
        .event
        .lock()
        .expect("deferred notification")
        .take()
    {
        Some(SecurityEvent::DmaViolation {
            source_id,
            fault_address,
            reason,
            domain_id,
        }) => {
            assert_eq!(source_id, 8);
            assert_eq!(fault_address, 0xdead_b000);
            assert_eq!(reason, 5);
            assert_eq!(
                domain_id,
                expected_domain_index.map(|index| u32::from(domains[index]))
            );
        }
        other => panic!("unexpected deferred event: {other:?}"),
    }

    // Remove all context/PASID references before releasing their domain roots.
    // This controller was never registered, enabled or attached to hardware.
    let hardware = core::mem::take(&mut *controller.hardware.lock().expect("take contexts"));
    let pasid = controller
        .device_pasid_tables
        .lock()
        .unwrap_or_else(|_| panic!("PASID owner registry poisoned"))
        .remove(&device)
        .expect("retained PASID owner");
    // SAFETY: the unique local hierarchy never reached RTADDR or a device.
    // Deferred processing is complete and no CPU borrower remains.
    unsafe {
        hardware.root_table.unwrap().retire_after_invalidation();
        for table in hardware.scalable_context_tables {
            table.retire_after_invalidation();
        }
        pasid.directory.retire_after_invalidation();
        pasid.table.retire_after_invalidation();
    }
    for id in domains {
        let owner = controller
            .domains
            .lock()
            .unwrap_or_else(|_| panic!("domain registry poisoned"))
            .remove(&id)
            .expect("retained domain owner");
        let domain = Arc::try_unwrap(owner).unwrap_or_else(|_| panic!("domain borrower remains"));
        // SAFETY: every unpublished context reference was retired above.
        unsafe { domain.retire_after_invalidation() };
    }
}

pub(crate) fn scalable_fault_domain_resolution() -> bool {
    // VT-d FRCD[127:64]: F=63, PV=59:40, FR=39:32, PP=31, SID=15:0.
    // Independent register vectors cover untagged RID, PASID zero, distinct
    // PASID, absent entry and a PASID outside the admitted table.
    for (high, expected) in [
        (0x8000_0005_0000_0008, Some(0)),
        (0x8000_0005_8000_0008, Some(0)),
        (0x8000_0505_8000_0008, Some(1)),
        (0x8000_0605_8000_0008, None),
        (0x8000_4005_8000_0008, None),
    ] {
        observe_fault(high, expected);
    }
    true
}
