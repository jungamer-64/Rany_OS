// ============================================================================
// kernel/src/io/iommu/vendors/amd/tests.rs
// ============================================================================

#![cfg(feature = "qemu-test-export")]

//! Unit tests for the AMD-Vi IOMMU subsystem.

use alloc::vec::Vec;

use crate::io::iommu::common::dma::iova_allocator::IovaAllocator;
use crate::io::iommu::common::dma::page_table_pool::PageTablePool;
use crate::io::iommu::common::domain::IommuDomain as DomainState;
use crate::io::iommu::runtime::command::queue::{CommandQueue, IommuCommandKind};
use crate::io::iommu::runtime::security::SecurityNotifier;
use crate::io::iommu::types::{DeviceId, IommuDomainType, IommuError, PteFormat};
use crate::mm::types::PAGE_SIZE_4K;
use acpi_driver::ivrs::IvhdDeviceEntry;

use super::AmdIvmdRange;
use super::domain::{aliases_for_entries, flags_for_entries, reject_excluded_ranges};
use super::map_ivmd_ranges;
use super::registers::AMD_DEFAULT_MAX_ADDR_BITS;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_alias_devids_for_device_dedup() {
    let device = DeviceId::new(0, 1, 0, 0);
    let devid = device.requester_id();
    let entries = alloc::vec![
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
    ];

    let aliases = aliases_for_entries(&entries, device.requester_id());
    assert_eq!(aliases, alloc::vec![0x0200, 0x0300]);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_alias_devids_for_device_no_match() {
    let entries = alloc::vec![IvhdDeviceEntry::Select {
        devid: 0x0100,
        flags: 0,
    }];
    let device = DeviceId::new(0, 2, 0, 0);
    let aliases = aliases_for_entries(&entries, device.requester_id());
    assert!(aliases.is_empty());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_ivhd_flags_for_device_combined() {
    let device = DeviceId::new(0, 2, 0, 0);
    let devid = device.requester_id();
    let entries = alloc::vec![
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
    ];

    let flags = flags_for_entries(&entries, devid);
    assert_eq!(flags, 0xff);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_ivhd_flags_for_device_acpi_hid() {
    let device = DeviceId::new(0, 2, 0, 0);
    let devid = device.requester_id();
    let entries = alloc::vec![IvhdDeviceEntry::AcpiHid { devid, flags: 0x03 }];

    let flags = flags_for_entries(&entries, devid);
    assert_eq!(flags, 0x03);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_map_ivmd_ranges_exclusion_splits() {
    let pool = PageTablePool::new(1, 1);
    let domain = DomainState::new(
        0,
        None,
        false,
        false,
        AMD_DEFAULT_MAX_ADDR_BITS,
        4,
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

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_map_for_device_rejects_exclusion_range() {
    let device = DeviceId::new(0, 0, 1, 0);
    let devid = device.requester_id();
    let ranges = [AmdIvmdRange {
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
    assert_eq!(
        reject_excluded_ranges(&ranges, 0x2000, 0x1000),
        Err(IommuError::InvalidAddress)
    );
    assert_eq!(reject_excluded_ranges(&ranges, 0x1000, 0x1000), Ok(()));
    assert_eq!(
        reject_excluded_ranges(&ranges, u64::MAX - 0xfff, 0x1000),
        Err(IommuError::InvalidAddress)
    );
}

// ---------------------------------------------------------------------------
// Wave1 test support
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct TestMockNotifier;

impl SecurityNotifier for TestMockNotifier {
    fn notify(&self, _event: crate::io::iommu::runtime::security::SecurityEvent) {}
}

fn make_domain() -> DomainState {
    DomainState::new(
        1,
        None,
        false,
        false,
        AMD_DEFAULT_MAX_ADDR_BITS,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 1),
        PteFormat::Amd,
    )
}

// ---------------------------------------------------------------------------
// Wave1 #[test_case] tests
// ---------------------------------------------------------------------------

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_cmdqueue_map_unmap_with_domain() {
    let domain = make_domain();
    let device = DeviceId::new(0, 1, 0, 0);

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
            if *d != device {
                return Err(());
            }
            domain.map(*i, *p, *s, *r, *w).map_err(|_| ())?;
            Ok(0)
        }
        _ => Err(()),
    });
    assert_eq!(processed, 1);
    assert_eq!(comp.wait_blocking(), 0);

    assert!(domain.mapping(iova).is_some());

    let comp2 = cq
        .submit(IommuCommandKind::UnmapRegionDevice { device, iova, size })
        .expect("submit unmap");

    let processed2 = cq.process_once(|kind| match kind {
        IommuCommandKind::UnmapRegionDevice {
            device: d, iova: i, ..
        } => {
            if *d != device {
                return Err(());
            }
            domain.unmap(*i).map(|_| 0).map_err(|_| ())
        }
        _ => Err(()),
    });
    assert_eq!(processed2, 1);
    assert_eq!(comp2.wait_blocking(), 0);
    assert!(domain.mapping(iova).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_map_device_nonblocking() {
    let domain = make_domain();

    let size = PAGE_SIZE_4K as u64;
    let allocator = IovaAllocator::new(PAGE_SIZE_4K as u64, (1u64 << 20) - PAGE_SIZE_4K as u64);
    let iova = allocator
        .allocate(
            size,
            crate::io::iommu::common::dma::iova_allocator::PageGranularity::Page4K,
        )
        .unwrap();

    domain.map(iova, 0x10000, size, true, true).unwrap();
    assert!(domain.mapping(iova).is_some());

    domain.unmap(iova).unwrap();
    allocator.free(iova, size).unwrap();
    assert!(domain.mapping(iova).is_none());
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_dma_mask_respects_32bit_limit() {
    let allocator = IovaAllocator::new(PAGE_SIZE_4K as u64, (1u64 << 20) - PAGE_SIZE_4K as u64);

    let size = PAGE_SIZE_4K as u64;
    let mask = 0xFFFF_FFFFu64;

    let iova = allocator
        .allocate_with_limit(
            size,
            crate::io::iommu::common::dma::iova_allocator::PageGranularity::Page4K,
            mask,
        )
        .unwrap();
    assert!(iova < 0x1_0000_0000, "IOVA {:#x} exceeds 32-bit mask", iova);
    allocator.free(iova, size).unwrap();
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_security_notifier_dispatch() {
    let domain = make_domain();
    let notifier: alloc::sync::Arc<dyn SecurityNotifier> = alloc::sync::Arc::new(TestMockNotifier);

    assert!(domain.set_security_notifier(alloc::sync::Arc::clone(&notifier)));
    assert!(!domain.set_security_notifier(alloc::sync::Arc::clone(&notifier)));
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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
    // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
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

use super::cmd::AmdCommand;
use super::irt::encode_remap_msi;

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_wave5_irt_invalidation_cmd_format() {
    let devid: u16 = 0x0108;
    let cmd = AmdCommand::invalidate_interrupt_table(devid);
    assert_eq!(cmd.data[0] & 0xFFFF, devid as u32);
    assert_eq!((cmd.data[1] >> 28) & 0x0F, 0x05);
}

#[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
#[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
fn test_wave5_get_remap_msi_message_format() {
    let (addr, _data) = encode_remap_msi(5);
    assert_eq!(addr & 0xFFF0_0000, 0xFEE0_0000);
    assert_ne!(addr & 0x04, 0); // bit 2 = remapped format
    assert_eq!((addr >> 2) & 0xFFFF, 5);

    let (addr2, _) = encode_remap_msi(10);
    assert_ne!(addr, addr2);
}
