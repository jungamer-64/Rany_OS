use crate::io::iommu::common::dma::page_table_pool::PageTablePool;
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::types::{IommuDomainType, IommuError, PteFormat};
use crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned;
use crate::mm::types::PAGE_SIZE_4K;

enum OverlapLayout {
    Pages4K,
    Pages2M,
}

fn overlapping_region_keeps_original_mapping(format: PteFormat, layout: OverlapLayout) {
    let (unit, units, supports_2mb) = match layout {
        OverlapLayout::Pages4K => (PAGE_SIZE_4K, 3, false),
        OverlapLayout::Pages2M => (2 * 1024 * 1024, 2, true),
    };
    let span = unit * units;
    let backing = alloc_contiguous_frames_aligned(span / PAGE_SIZE_4K, unit)
        .expect("owned translation fixture RAM");
    let physical = backing.as_u64();
    let domain = IommuDomain::try_new(
        0x8000,
        Some(backing.node().as_usize()),
        supports_2mb,
        false,
        48,
        4,
        IommuDomainType::Translated,
        PageTablePool::new(1, 32),
        format,
    )
    .expect("owned translation domain");
    let start = 0x1_0000_0000;
    let occupied = start + unit as u64;
    let occupied_physical = physical + unit as u64;
    domain
        .map(
            occupied,
            occupied_physical,
            PAGE_SIZE_4K as u64,
            true,
            false,
        )
        .expect("original page admission");

    assert_eq!(
        domain.map(start, physical, span as u64, true, true),
        Err(IommuError::AlreadyMapped)
    );
    assert_eq!(domain.mapped_size(), PAGE_SIZE_4K as u64);
    assert!(domain.mapping(start).is_none());
    let original = domain.mapping(occupied).expect("original mapping retained");
    assert_eq!(original.iova, occupied);
    assert_eq!(original.phys, occupied_physical);
    assert_eq!(original.size, PAGE_SIZE_4K as u64);
    assert!(original.read);
    assert!(!original.write);
    assert_eq!(domain.mappings_snapshot().len(), 1);

    let returned = domain.unmap(occupied).expect("original mapping retirement");
    assert_eq!(returned.phys, occupied_physical);
    assert_eq!(returned.size, PAGE_SIZE_4K as u64);
    assert_eq!(domain.mapped_size(), 0);
    assert_eq!(
        domain.map(start, physical, span as u64, false, false),
        Err(IommuError::InvalidPermissions)
    );
    assert!(domain.mappings_snapshot().is_empty());

    // Successful admission of the entire span observes that the rejected
    // operation left no conflicting prefix/suffix translation behind.
    domain
        .map(start, physical, span as u64, true, true)
        .expect("full span after original retirement");
    assert_eq!(domain.mapped_size(), span as u64);
    let returned = domain.unmap(start).expect("full span retirement");
    assert_eq!(returned.phys, physical);
    assert_eq!(returned.size, span as u64);
    assert_eq!(domain.mapped_size(), 0);
    assert!(domain.mappings_snapshot().is_empty());

    // SAFETY: this unique local domain was never installed in a controller,
    // device context or driver registry. No hardware translation or CPU
    // borrower can reference its tables or this retained data RAM.
    unsafe { domain.retire_after_invalidation() };
    backing.release();
}

pub fn mapping_overlap_retains_domain_ownership_smoke() -> bool {
    overlapping_region_keeps_original_mapping(PteFormat::Intel, OverlapLayout::Pages4K);
    overlapping_region_keeps_original_mapping(PteFormat::Amd, OverlapLayout::Pages4K);
    overlapping_region_keeps_original_mapping(PteFormat::Amd, OverlapLayout::Pages2M);
    true
}

pub mod wave3 {
    pub fn cmdqueue_reclaim_completed_slot_smoke() -> bool {
        crate::io::iommu::runtime::command::queue::qemu_smoke_reclaim_completed_slot()
    }

    pub async fn cmdqueue_cancel_queued_command_smoke() -> bool {
        crate::io::iommu::runtime::command::queue::qemu_smoke_cancel_queued_command().await
    }

    pub fn cmdqueue_drop_triggers_cancel_smoke() -> bool {
        crate::io::iommu::runtime::command::queue::qemu_smoke_drop_triggers_cancel()
    }

    pub fn cmdqueue_process_up_to_respects_fuel_smoke() -> bool {
        crate::io::iommu::runtime::command::queue::qemu_smoke_process_up_to_respects_fuel()
    }

    pub fn cmdqueue_metrics_counts_smoke() -> bool {
        crate::io::iommu::runtime::command::queue::qemu_smoke_metrics_counts()
    }
}
