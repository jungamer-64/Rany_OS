use crate::io::iommu::common::dma::page_table_pool::PageTablePool;
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::common::tables::{SlPte, phys_to_virt_usize};
use crate::io::iommu::types::{IommuDomainType, IommuError, PteFormat};
use crate::io::iommu::vendors::amd::tables::AmdPte;
use crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned;
use crate::mm::types::PAGE_SIZE_4K;
mod fault;
mod mapped_range;
mod page_table_pool;
pub(crate) use fault::scalable_fault_domain_resolution;
pub(crate) use mapped_range::masked_mapping_retirement;

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

/// # Safety
/// The caller retains this entire local hierarchy and excludes mutation or
/// retirement through the walk. `levels` and `format` describe that root.
unsafe fn observed_leaf(
    mut table: *const SlPte,
    levels: u8,
    format: PteFormat,
    iova: u64,
) -> Option<(SlPte, u8)> {
    // LOOP_PROOF: mode=bounded; reason=Validated domain roots contain at most five levels, and each iteration descends one level.;
    for level in (1..=levels).rev() {
        let shift = 12 + 9 * u32::from(level - 1);
        let index = ((iova >> shift) & 0x1ff) as usize;
        // SAFETY: the caller retains each reachable table and the masked index
        // addresses one of its 512 entries. No mutation overlaps this read.
        let entry = unsafe { *table.add(index) };
        if !entry.is_present() {
            return None;
        }
        if level == 1 || entry.is_super_page(format) {
            return Some((entry, level));
        }
        table = phys_to_virt_usize(entry.phys_addr()) as *const SlPte;
    }
    None
}

pub fn domain_depth_and_root_physical_address_smoke() -> bool {
    for format in [PteFormat::Intel, PteFormat::Amd] {
        for (levels, max_bits) in [(2, 30), (3, 39), (4, 48), (5, 57)] {
            let backing = alloc_contiguous_frames_aligned(2, PAGE_SIZE_4K)
                .expect("depth fixture RAM admission");
            let physical = backing.as_u64();
            let pool = PageTablePool::new(1, 32);
            let domain = IommuDomain::try_new(
                0x8001,
                Some(backing.node().as_usize()),
                true,
                true,
                max_bits,
                levels,
                IommuDomainType::Translated,
                pool.clone(),
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
            let second = iova + PAGE_SIZE_4K as u64;
            domain
                .map(
                    second,
                    physical + PAGE_SIZE_4K as u64,
                    PAGE_SIZE_4K as u64,
                    true,
                    true,
                )
                .expect("second page in the same table");
            // SAFETY: this unshared local domain retains every reachable table
            // and both data pages; no hardware context can mutate its entries.
            let original = unsafe { observed_leaf(domain.page_table, levels, format, second) }
                .expect("second hardware leaf");
            assert_eq!(original.1, 1);
            assert_eq!(original.0.phys_addr(), physical + PAGE_SIZE_4K as u64);
            let returned = domain.unmap(iova).expect("depth mapping retirement");
            assert_eq!(returned.phys, physical);
            assert_eq!(domain.mapped_size(), PAGE_SIZE_4K as u64);
            // SAFETY: mutation completed and the same uniquely retained domain
            // keeps the surviving leaf reachable throughout both observations.
            unsafe {
                assert!(observed_leaf(domain.page_table, levels, format, iova).is_none());
                let surviving = observed_leaf(domain.page_table, levels, format, second)
                    .expect("partial unmap retains the other hardware leaf");
                assert_eq!(surviving.0.0, original.0.0);
                assert_eq!(surviving.1, 1);
            }
            domain.unmap(second).expect("last small page retirement");
            assert_eq!(domain.mapped_size(), 0);

            let huge_size = 2 * 1024 * 1024;
            let mixed_size = huge_size + PAGE_SIZE_4K;
            let mixed = alloc_contiguous_frames_aligned(mixed_size / PAGE_SIZE_4K, huge_size)
                .expect("owned mixed-size data RAM");
            domain
                .map(iova, mixed.as_u64(), mixed_size as u64, true, false)
                .expect("mixed 2MiB and 4KiB mapping");
            assert_eq!(domain.mapped_size(), mixed_size as u64);
            // SAFETY: this local domain and the mixed data owner remain live;
            // all leaf publication ended before these independent table walks.
            unsafe {
                let huge = observed_leaf(domain.page_table, levels, format, iova)
                    .expect("mixed huge leaf");
                let tail =
                    observed_leaf(domain.page_table, levels, format, iova + huge_size as u64)
                        .expect("mixed small tail leaf");
                assert_eq!(huge.1, 2);
                assert_eq!(huge.0.phys_addr(), mixed.as_u64());
                assert_eq!(tail.1, 1);
                assert_eq!(tail.0.phys_addr(), mixed.as_u64() + huge_size as u64);
                let (read, write) = match format {
                    PteFormat::Intel => (SlPte::READ, SlPte::WRITE),
                    PteFormat::Amd => (AmdPte::READ, AmdPte::WRITE),
                };
                assert_eq!(huge.0.0 & (read | write), read);
                assert_eq!(tail.0.0 & (read | write), read);
            }
            let returned = domain.unmap(iova).expect("mixed mapping retirement");
            assert_eq!(returned.phys, mixed.as_u64());
            assert_eq!(returned.size, mixed_size as u64);
            assert_eq!(domain.mapped_size(), 0);
            assert!(domain.mappings_snapshot().is_empty());
            // SAFETY: unmap ended, and domain ownership still retains any
            // empty paging structures until completion is established below.
            unsafe {
                assert!(observed_leaf(domain.page_table, levels, format, iova).is_none());
                assert!(
                    observed_leaf(domain.page_table, levels, format, iova + huge_size as u64)
                        .is_none()
                );
            }
            assert_eq!(pool.cached_count(0), 0, "unmap has no completion proof");
            // SAFETY: this unique local domain never entered a hardware context
            // or registry. All CPU table borrows ended before consuming it.
            unsafe { domain.retire_after_invalidation() };
            assert!(pool.cached_count(0) > 0, "completed tables are reusable");
            mixed.release();
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

pub(crate) fn poisoned_ownership() -> bool {
    crate::sync::poison_lock::qemu_tests::retained_iommu_ownership(|controller, id| {
        let mut hardware = core::mem::take(
            &mut *controller
                .hardware
                .lock()
                .expect_err("fixture hardware is poisoned")
                .into_inner(),
        );
        let table = hardware
            .legacy_context_tables
            .pop()
            .expect("retained local context");
        assert!(hardware.legacy_context_tables.is_empty());
        assert!(hardware.root_table.is_none());
        assert!(hardware.scalable_context_tables.is_empty());
        let owner = controller
            .domains
            .lock()
            .err()
            .expect("fixture registry is poisoned")
            .into_inner()
            .remove(&id)
            .expect("unique local domain");
        let domain = alloc::sync::Arc::try_unwrap(owner)
            .unwrap_or_else(|_| panic!("local domain borrower remains"));
        // SAFETY: the fixture controller and all of its tables were never
        // registered, enabled or published to devices. Context ownership is
        // removed and every CPU borrower is gone before domain root retirement.
        unsafe {
            table.retire_after_invalidation();
            domain.retire_after_invalidation();
        }
    })
}
