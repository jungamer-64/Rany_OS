use crate::io::iommu::common::dma::page_table_pool::PageTablePool;
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::types::{IommuDomainType, IommuError, PteFormat};
use crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned;
use crate::mm::types::PAGE_SIZE_4K;
mod page_table_pool;

pub fn page_table_recycling_retains_ownership_smoke() -> bool {
    page_table_pool::cached_table_is_zeroed();
    page_table_pool::committed_scope_preserves_live_child_entries();
    page_table_pool::retirement_cohort_excludes_later_unlinks();
    page_table_pool::attached_rollback_retains_ram_until_completion();
    true
}

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

pub fn domain_depth_and_root_physical_address_smoke() -> bool {
    for format in [PteFormat::Intel, PteFormat::Amd] {
        for (levels, max_bits) in [(2, 30), (3, 39), (4, 48), (5, 57)] {
            let backing = alloc_contiguous_frames_aligned(1, PAGE_SIZE_4K)
                .expect("depth fixture RAM admission");
            let physical = backing.as_u64();
            let domain = IommuDomain::try_new(
                0x8001,
                Some(backing.node().as_usize()),
                true,
                true,
                max_bits,
                levels,
                IommuDomainType::Translated,
                PageTablePool::new(1, 32),
                format,
            )
            .expect("depth fixture domain");
            let root = domain.page_table_addr();
            let root_virtual = crate::mm::virt::higher_half::VirtAddr::new(
                x86_64::VirtAddr::from_ptr(domain.page_table).as_u64(),
            );
            let expected = crate::mm::virt::higher_half::global_translate(root_virtual)
                .expect("CPU page-table translation of the retained root");
            assert_eq!(root, expected.as_u64());
            assert_eq!(root % PAGE_SIZE_4K as u64, 0);
            let iova = 0x20_0000;
            domain
                .map(iova, physical, PAGE_SIZE_4K as u64, true, true)
                .expect("4K mapping at admitted depth");
            let mapping = domain.mapping(iova).expect("live depth mapping");
            assert_eq!(mapping.phys, physical);
            assert_eq!(mapping.size, PAGE_SIZE_4K as u64);
            let returned = domain.unmap(iova).expect("depth mapping retirement");
            assert_eq!(returned.phys, physical);
            assert_eq!(domain.mapped_size(), 0);
            // SAFETY: this unique local domain never entered a hardware context
            // or registry. All CPU table borrows ended before consuming it.
            unsafe { domain.retire_after_invalidation() };
            backing.release();
        }
    }
    true
}

pub fn iova_retirement_preserves_later_extents_smoke() -> bool {
    use crate::io::iommu::common::dma::iova_allocator::IovaAllocator;
    let _current = crate::cpu::CurrentCpu::acquire().expect("bootstrapped CPU quarantine owner");
    let page = PAGE_SIZE_4K as u64;
    let allocator = alloc::sync::Arc::new(
        IovaAllocator::new(page, 5 * page).expect("local IOVA address space"),
    );
    let first = allocator
        .allocate_contiguous(3 * page, page)
        .expect("first extent");
    let later = allocator
        .allocate_contiguous(2 * page, page)
        .expect("later extent");
    allocator.free(first, 3 * page).expect("first retirement");
    let first_flush = allocator
        .begin_global_flush()
        .expect("first invalidation capture");
    allocator
        .free(later, 2 * page)
        .expect("retirement after capture");
    assert!(allocator.allocate_4k().is_none());
    // SAFETY: this private allocator was never installed in any hardware
    // context. No IOTLB or ATS cache can contain either of its extents.
    unsafe { first_flush.complete_after_global_invalidation() };
    assert_eq!(allocator.allocate_contiguous(3 * page, page), Some(first));
    assert!(allocator.allocate_4k().is_none());
    let later_flush = allocator
        .begin_global_flush()
        .expect("later invalidation capture");
    // SAFETY: the later cohort also has no hardware translation users.
    unsafe { later_flush.complete_after_global_invalidation() };
    assert_eq!(allocator.allocate_contiguous(2 * page, page), Some(later));
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
