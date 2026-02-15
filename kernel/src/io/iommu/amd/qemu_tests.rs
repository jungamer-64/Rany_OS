// ============================================================================
// kernel/src/io/iommu/amd/qemu_tests.rs
// ============================================================================
//! AMD-Vi deterministic smoke exports for qemu-test-export.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64};

use hashbrown::HashMap;
use x86_64::PhysAddr;

use crate::io::acpi::ivrs::IvhdDeviceEntry;
use crate::io::iommu::domain::IommuDomain as DomainState;
use crate::io::iommu::page_table_pool::PageTablePool;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
use crate::io::iommu::{IovaAllocatorFast, PAGE_SIZE_4K};
use crate::sync::PoisonLock;

use super::domain::map_ivmd_ranges;
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
    }
}

pub fn wave0_alias_devids_for_device_dedup_smoke() -> bool {
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
    aliases == alloc::vec![0x0200, 0x0300]
}

pub fn wave0_alias_devids_for_device_no_match_smoke() -> bool {
    let driver = make_driver(alloc::vec![IvhdDeviceEntry::Select {
        devid: 0x0100,
        flags: 0,
    }]);
    let device = DeviceId::new(0, 2, 0, 0);
    let aliases = driver.alias_devids_for_device(device);
    aliases.is_empty()
}

pub fn wave0_ivhd_flags_for_device_combined_smoke() -> bool {
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

    driver.ivhd_flags_for_device(device) == 0xff
}

pub fn wave0_ivhd_flags_for_device_acpi_hid_smoke() -> bool {
    let device = DeviceId::new(0, 2, 0, 0);
    let devid = device.requester_id();
    let driver = make_driver(alloc::vec![IvhdDeviceEntry::AcpiHid { devid, flags: 0x03 }]);

    driver.ivhd_flags_for_device(device) == 0x03
}

pub fn wave0_map_ivmd_ranges_exclusion_splits_smoke() -> bool {
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

    if map_ivmd_ranges(&domain, &ranges).is_err() {
        return false;
    }

    let mappings = domain.mappings_snapshot();
    mappings.iter().any(|m| m.iova == 0x1000)
        && mappings.iter().any(|m| m.iova == 0x3000)
        && !mappings.iter().any(|m| m.iova == 0x2000)
        && mappings.len() == 2
}

pub fn wave0_map_for_device_rejects_exclusion_range_smoke() -> bool {
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
    let domain = Arc::new(domain);
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

    let result = unsafe { driver.map_for_device(&device, PhysAddr::new(0x2000), 0x1000) };
    result == Err(IommuError::InvalidAddress)
}
