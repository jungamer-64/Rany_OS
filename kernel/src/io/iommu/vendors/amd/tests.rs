// ============================================================================
// kernel/src/io/iommu/vendors/amd/tests.rs
// ============================================================================

#![cfg(feature = "qemu-test-export")]

//! Unit tests for the AMD-Vi IOMMU subsystem.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64};

use hashbrown::HashMap;
use x86_64::PhysAddr;

use crate::io::acpi::ivrs::IvhdDeviceEntry;
use crate::io::iommu::runtime::command::queue::{CommandQueue, IommuCommandKind};
use crate::io::iommu::common::domain::IommuDomain as DomainState;
use crate::io::iommu::common::dma::page_table_pool::PageTablePool;
use crate::io::iommu::runtime::security::SecurityNotifier;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
use crate::mm::types::PAGE_SIZE_4K;
use crate::io::iommu::common::dma::iova_allocator::{IovaAllocator, IovaAllocatorFast};
use crate::sync::PoisonLock;

use crate::io::iommu::common::domain::map_ivmd_ranges;
use super::registers::AMD_DEFAULT_MAX_ADDR_BITS;
use super::{AmdDomainInfo, AmdIommuDriver, AmdIommuUnit, AmdIvmdRange};

fn make_driver(entries: Vec<IvhdDeviceEntry>) -> AmdIommuDriver {
    let unit = AmdIommuUnit {
        segment: 0,
        base_addr: 0,
        flags: 0,
        device_id: 0,
        iommu_info: 0,
        iommu_feature: 0,
        device_entries: entries,
        max_addr_bits: AMD_DEFAULT_MAX_ADDR_BITS,
    };

    AmdIommuDriver {
        units: alloc::vec![unit],
        ivmd_ranges: Vec::new(),
        cmd_states: Vec::new(),
        event_logs: Vec::new(),
        device_tables: HashMap::new(),
        domains: PoisonLock::new(HashMap::new()),
        device_domains: PoisonLock::new(HashMap::new()),
        next_domain_id: AtomicU64::new(1),
        page_table_pool: PageTablePool::new(1, 1),
        command_queue: None,
        iova_allocator: IovaAllocatorFast::new(
            PAGE_SIZE_4K as u64,
            (1u64 << AMD_DEFAULT_MAX_ADDR_BITS).saturating_sub(PAGE_SIZE_4K as u64),
        ),
        enabled: AtomicBool::new(false),
        security_notifier: spin::Once::new(),
        max_addr_bits: AMD_DEFAULT_MAX_ADDR_BITS,
        interrupt_remap_tables: alloc::vec![None],
    }
}

#[test_case]
fn test_alias_devids_for_device_dedup() {
    let device = DeviceId::new(0, 1, 0, 0);
    let devid = device.requester_id();
    let driver = make_driver(alloc::vec![
        IvhdDeviceEntry::Select { devid, flags: 0 },
        IvhdDeviceEntry::Alias {
            devid,
            alias: 0x0200,
            flags: 0,
        },
        IvhdDeviceEntry::AliasRange {
            start: devid,
            end: devid + 3,
            alias: 0x0300,
            flags: 0,
        },
        IvhdDeviceEntry::Alias {
            devid,
            alias: 0x0200,
            flags: 0,
        },
        IvhdDeviceEntry::Alias {
            devid,
            alias: devid,
            flags: 0,
        },
    ]);

    let aliases = driver.alias_devids_for_device(device);
    assert_eq!(aliases, alloc::vec![0x0200, 0x0300]);
}

#[test_case]
fn test_alias_devids_for_device_no_match() {
    let driver = make_driver(alloc::vec![IvhdDeviceEntry::Select {
        devid: 0x0100,
        flags: 0,
    }]);
    let device = DeviceId::new(0, 2, 0, 0);
    let aliases = driver.alias_devids_for_device(device);
    assert!(aliases.is_empty());
}

#[test_case]
fn test_ivhd_flags_for_device_combined() {
    let device = DeviceId::new(0, 2, 0, 0);
    let devid = device.requester_id();
    let driver = make_driver(alloc::vec![
        IvhdDeviceEntry::All { flags: 0x01 },
        IvhdDeviceEntry::Select { devid, flags: 0x02 },
        IvhdDeviceEntry::Range {
            start: devid,
            end: devid + 0x0f,
            flags: 0x04,
        },
        IvhdDeviceEntry::Alias {
            devid: 0x0100,
            alias: devid,
            flags: 0x08,
        },
        IvhdDeviceEntry::AliasRange {
            start: 0x0300,
            end: 0x030f,
            alias: devid,
            flags: 0x10,
        },
        IvhdDeviceEntry::ExtSelect {
            devid,
            flags: 0x20,
            ext_flags: 0,
        },
        IvhdDeviceEntry::ExtRange {
            start: devid,
            end: devid,
            flags: 0x40,
            ext_flags: 0,
        },
        IvhdDeviceEntry::Special {
            devid,
            flags: 0x80,
            handle: 0,
            variety: 0,
        },
    ]);

    let flags = driver.ivhd_flags_for_device(device);
    assert_eq!(flags, 0xff);
}

#[test_case]
fn test_ivhd_flags_for_device_acpi_hid() {
    let device = DeviceId::new(0, 2, 0, 0);
    let devid = device.requester_id();
    let driver = make_driver(alloc::vec![IvhdDeviceEntry::AcpiHid { devid, flags: 0x03 }]);

    let flags = driver.ivhd_flags_for_device(device);
    assert_eq!(flags, 0x03);
}

#[test_case]
fn test_map_ivmd_ranges_exclusion_splits() {
    let pool = PageTablePool::new(1, 1);
    let domain = DomainState::new(
        0,
        None,
        false,
        false,
        AMD_DEFAULT_MAX_ADDR_BITS,
        IommuDomainType::Translated,
        pool,
        PteFormat::Amd,
    );

    let ranges = alloc::vec![
        AmdIvmdRange {
            segment: 0,
            devid_start: 0,
            devid_end: u16::MAX,
            range_start: 0x1000,
            range_end: 0x5000,
            unity_map: true,
            read: true,
            write: true,
            exclusion: false,
        },
        AmdIvmdRange {
            segment: 0,
            devid_start: 0,
            devid_end: u16::MAX,
            range_start: 0x2000,
            range_end: 0x3000,
            unity_map: false,
            read: true,
            write: true,
            exclusion: true,
        },
    ];

    map_ivmd_ranges(&domain, &ranges).expect("map ivmd ranges");

    let mappings = domain.mappings_snapshot();
    assert!(mappings.iter().any(|m| m.iova == 0x1000));
    assert!(mappings.iter().any(|m| m.iova == 0x3000));
    assert!(!mappings.iter().any(|m| m.iova == 0x2000));
    assert_eq!(mappings.len(), 2);
}

#[test_case]
fn test_map_for_device_rejects_exclusion_range() {
    let device = DeviceId::new(0, 0, 1, 0);
    let devid = device.requester_id();
    let mut driver = make_driver(Vec::new());
    driver.ivmd_ranges = alloc::vec![AmdIvmdRange {
        segment: device.segment,
        devid_start: devid,
        devid_end: devid,
        range_start: 0x2000,
        range_end: 0x3000,
        unity_map: false,
        read: true,
        write: true,
        exclusion: true,
    }];

    let domain_id = 1u16;
    let domain = DomainState::new(
        domain_id,
        None,
        false,
        false,
        AMD_DEFAULT_MAX_ADDR_BITS,
        IommuDomainType::Translated,
        driver.page_table_pool.clone(),
        PteFormat::Amd,
    );
    let domain = alloc::sync::Arc::new(domain);
    {
        let mut domains = match driver.domains.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        domains.insert(domain_id, AmdDomainInfo { domain });
    }

    {
        let mut device_domains = match driver.device_domains.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        device_domains.insert(device, domain_id);
    }

    let result =
        unsafe { driver.map_for_device(&device, PhysAddr::new(0x2000), 0x1000) };
    assert_eq!(result, Err(IommuError::InvalidAddress));
}

// ---------------------------------------------------------------------------
// Wave1 test support
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TestMockNotifier;

impl SecurityNotifier for TestMockNotifier {
    fn notify(&self, _event: crate::io::iommu::runtime::security::SecurityEvent) {}
}

fn make_test_driver_small() -> AmdIommuDriver {
    let unit = AmdIommuUnit {
        segment: 0,
        base_addr: 0,
        flags: 0,
        device_id: 0,
        iommu_info: 0,
        iommu_feature: 0,
        device_entries: alloc::vec![IvhdDeviceEntry::All { flags: 0 }],
        max_addr_bits: AMD_DEFAULT_MAX_ADDR_BITS,
    };

    let page_table_pool = PageTablePool::new(1, 1);
    let iova_allocator = IovaAllocatorFast::new(
        PAGE_SIZE_4K as u64,
        (1u64 << 20) - PAGE_SIZE_4K as u64,
    );

    let default_domain = DomainState::new(
        0,
        None,
        false,
        false,
        AMD_DEFAULT_MAX_ADDR_BITS,
        IommuDomainType::Translated,
        page_table_pool.clone(),
        PteFormat::Amd,
    );
    let default_domain = alloc::sync::Arc::new(default_domain);
    let mut domain_map = HashMap::new();
    domain_map.insert(0, AmdDomainInfo { domain: default_domain });

    AmdIommuDriver {
        units: alloc::vec![unit],
        ivmd_ranges: Vec::new(),
        cmd_states: Vec::new(),
        event_logs: Vec::new(),
        device_tables: HashMap::new(),
        domains: PoisonLock::new(domain_map),
        device_domains: PoisonLock::new(HashMap::new()),
        next_domain_id: AtomicU64::new(1),
        page_table_pool,
        command_queue: None,
        iova_allocator,
        enabled: AtomicBool::new(false),
        security_notifier: spin::Once::new(),
        max_addr_bits: AMD_DEFAULT_MAX_ADDR_BITS,
        interrupt_remap_tables: alloc::vec![None],
    }
}

// ---------------------------------------------------------------------------
// Wave1 #[test_case] tests
// ---------------------------------------------------------------------------

#[test_case]
fn test_cmdqueue_map_unmap_with_domain() {
    let driver = make_test_driver_small();

    let domain_id = driver.create_domain(None, IommuDomainType::Translated).unwrap();
    let device = DeviceId::new(0, 1, 0, 0);
    {
        let mut dd = match driver.device_domains.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        dd.insert(device, domain_id);
    }

    let cq = alloc::boxed::Box::leak(alloc::boxed::Box::new(CommandQueue::new()));

    let iova = 0x1000u64;
    let phys = 0x10000u64;
    let size = 0x1000u64;

    let comp = cq
        .submit(IommuCommandKind::MapRegionDevice {
            device,
            iova,
            phys,
            size,
            read: true,
            write: true,
        })
        .expect("submit map");

    let processed = cq.process_once(|kind| match kind {
        IommuCommandKind::MapRegionDevice {
            device: d,
            iova: i,
            phys: p,
            size: s,
            read: r,
            write: w,
        } => {
            let did = driver.domain_id_for_device(*d).map_err(|_| ())?;
            let domain = driver.domain_for_id(did).map_err(|_| ())?;
            domain.map(*i, *p, *s, *r, *w).map_err(|_| ())?;
            Ok(0)
        }
        _ => Err(()),
    });
    assert_eq!(processed, 1);
    assert_eq!(comp.wait_blocking(), 0);

    let domain = driver.domain_for_id(domain_id).unwrap();
    assert!(domain.mapping(iova).is_some());

    let comp2 = cq
        .submit(IommuCommandKind::UnmapRegionDevice {
            device,
            iova,
            size,
        })
        .expect("submit unmap");

    let processed2 = cq.process_once(|kind| match kind {
        IommuCommandKind::UnmapRegionDevice {
            device: d,
            iova: i,
            ..
        } => {
            let did = driver.domain_id_for_device(*d).map_err(|_| ())?;
            let domain = driver.domain_for_id(did).map_err(|_| ())?;
            domain.unmap(*i).map(|_| 0).map_err(|_| ())
        }
        _ => Err(()),
    });
    assert_eq!(processed2, 1);
    assert_eq!(comp2.wait_blocking(), 0);
    assert!(domain.mapping(iova).is_none());
}

#[test_case]
fn test_map_device_nonblocking() {
    let driver = make_test_driver_small();

    let domain_id = driver.create_domain(None, IommuDomainType::Translated).unwrap();
    let device = DeviceId::new(0, 1, 0, 0);
    {
        let mut dd = match driver.device_domains.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        dd.insert(device, domain_id);
    }

    let size = PAGE_SIZE_4K as u64;
    let iova = driver.allocate_iova_fast(size, None).unwrap();
    let domain = driver.domain_for_id(domain_id).unwrap();

    domain.map(iova, 0x10000, size, true, true).unwrap();
    assert!(domain.mapping(iova).is_some());

    domain.unmap(iova).unwrap();
    driver.free_iova_fast(iova, size).unwrap();
    assert!(domain.mapping(iova).is_none());
}

#[test_case]
fn test_dma_mask_respects_32bit_limit() {
    let driver = make_test_driver_small();

    let size = PAGE_SIZE_4K as u64;
    let mask = 0xFFFF_FFFFu64;

    let iova = driver.allocate_iova(size, Some(mask)).unwrap();
    assert!(iova < 0x1_0000_0000, "IOVA {:#x} exceeds 32-bit mask", iova);
    driver.free_iova(iova, size).unwrap();
}

#[test_case]
fn test_security_notifier_dispatch() {
    let driver = make_test_driver_small();
    let notifier: alloc::sync::Arc<dyn SecurityNotifier> =
        alloc::sync::Arc::new(TestMockNotifier);

    assert!(driver.set_security_notifier(alloc::sync::Arc::clone(&notifier)));
    assert!(!driver.set_security_notifier(alloc::sync::Arc::clone(&notifier)));

    // Domain created after notifier was set should succeed
    let _domain_id = driver.create_domain(None, IommuDomainType::Translated).unwrap();
}

#[test_case]
fn test_cmdqueue_pressure() {
    let cq = alloc::boxed::Box::leak(alloc::boxed::Box::new(CommandQueue::new()));
    let count = 32usize;
    let device = DeviceId::new(0, 1, 0, 0);
    let mut completions = Vec::new();

    for i in 0..count {
        let cmd = IommuCommandKind::MapRegionDevice {
            device,
            iova: (i as u64 + 1) * 0x1000,
            phys: (i as u64 + 1) * 0x1000,
            size: 0x1000,
            read: true,
            write: true,
        };
        completions.push(cq.submit(cmd).expect("submit"));
    }

    let mut total_processed = 0;
    loop {
        let n = cq.process_once(|_| Ok(0));
        total_processed += n;
        if n == 0 {
            break;
        }
    }

    assert_eq!(total_processed, count);
    drop(completions);
    assert_eq!(cq.processed_total(), count);
}

// ---------------------------------------------------------------------------
// Wave5 (Interrupt Remapping) #[test_case] tests
// ---------------------------------------------------------------------------

use super::irt::{AmdInterruptRemapTable, AmdIrte, AmdUnitIrt, encode_remap_msi};
use super::cmd::AmdCommand;

#[test_case]
fn test_wave5_irt_entry_construction() {
    let irte = AmdIrte::fixed(0x42, 0x0A, false, None);
    assert!(irte.is_present());
    assert_eq!(irte.vector(), 0x42);
    assert_eq!(irte.destination(), 0x0A);
    assert!(!irte.is_logical());

    let irte_logical = AmdIrte::fixed(0xFF, 0xDEAD, true, None);
    assert!(irte_logical.is_logical());
    assert_eq!(irte_logical.vector(), 0xFF);
    assert_eq!(irte_logical.destination(), 0xDEAD);

    let empty = AmdIrte::new();
    assert!(!empty.is_present());
}

#[test_case]
fn test_wave5_irt_alloc_free() {
    let mut irt = AmdInterruptRemapTable::new(4).unwrap();
    let h0 = irt.allocate().unwrap();
    let h1 = irt.allocate().unwrap();
    let h2 = irt.allocate().unwrap();
    assert_ne!(h0, h1);
    assert_ne!(h1, h2);
    assert_ne!(h0, h2);

    irt.set_entry(h0, AmdIrte::fixed(0x30, 1, false, None)).unwrap();
    irt.free(h0).unwrap();
    irt.free(h1).unwrap();
    irt.free(h2).unwrap();

    assert!(!irt.get_entry(h0).unwrap().is_present());
}

#[test_case]
fn test_wave5_irt_exhaustion() {
    let mut irt = AmdInterruptRemapTable::new(2).unwrap(); // 4 entries
    assert_eq!(irt.capacity(), 4);

    let mut handles = alloc::vec::Vec::new();
    for _ in 0..4 {
        handles.push(irt.allocate().unwrap());
    }
    assert!(irt.allocate().is_err());

    irt.free(handles[1]).unwrap();
    assert_eq!(irt.allocate().unwrap(), handles[1]);
}

#[test_case]
fn test_wave5_irt_invalidation_cmd_format() {
    let devid: u16 = 0x0108;
    let cmd = AmdCommand::invalidate_interrupt_table(devid);
    assert_eq!(cmd.data[0] & 0xFFFF, devid as u32);
    assert_eq!((cmd.data[1] >> 28) & 0x0F, 0x05);
}

#[test_case]
fn test_wave5_map_interrupt_returns_handle() {
    let mut driver = make_test_driver_small();
    let unit_irt = AmdUnitIrt::new(4).unwrap();
    if let Some(slot) = driver.interrupt_remap_tables.get_mut(0) {
        *slot = Some(PoisonLock::new(unit_irt));
    } else {
        panic!("no IRT slot for unit 0");
    }
    let handle = driver.map_interrupt(0, 0, 1, 0, 0x42, 0x0A, false).unwrap();
    assert!(handle < 16); // 2^4 = 16 entries
}

#[test_case]
fn test_wave5_get_remap_msi_message_format() {
    let (addr, _data) = encode_remap_msi(5);
    assert_eq!(addr & 0xFFF0_0000, 0xFEE0_0000);
    assert_ne!(addr & 0x04, 0); // bit 2 = remapped format
    assert_eq!((addr >> 2) & 0xFFFF, 5);

    let (addr2, _) = encode_remap_msi(10);
    assert_ne!(addr, addr2);
}
