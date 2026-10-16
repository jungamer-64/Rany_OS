use crate::io::iommu::common::dma::iova_allocator::{IovaAllocator, PageGranularity};
use crate::io::iommu::common::dma::mapping_outcome::{DeviceMappedRange, DmaInvalidationSource};
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::types::{IommuDomainType, PteFormat};
use crate::io::iommu::vendors::intel::controller::IommuController;
use crate::io::iommu::vendors::intel::controller::dma::DomainManager;
use crate::mm::types::PAGE_SIZE_4K;
use alloc::sync::Arc;

const MASK: u64 = 0x2fff;

async fn map_owned_page(
    controller: &Arc<IommuController>,
    domain: &Arc<IommuDomain>,
    allocator: &Arc<IovaAllocator>,
    physical: u64,
) -> DeviceMappedRange {
    let page = PAGE_SIZE_4K as u64;
    let iova = allocator
        .allocate_with_limit(page, PageGranularity::Page4K, MASK)
        .expect("masked IOVA admission");
    assert!(iova.checked_add(page - 1).expect("bounded endpoint") <= MASK);
    // The test retains the real data allocation until every mapping completes.
    // This fresh domain belongs to this hardware source and has no devices;
    // its private address space cannot overlap another device's mappings.
    let mapping = DeviceMappedRange::admitted(
        Arc::clone(domain),
        DmaInvalidationSource::Intel(Arc::clone(controller)),
        Arc::clone(allocator),
        iova,
        physical,
        page,
    );
    domain
        .map(iova, physical, page, true, true)
        .expect("owned data leaf publication");
    mapping
        .synchronize_map_async()
        .await
        .expect("hardware map synchronization");
    mapping
}

fn check_live_page(controller: &IommuController, domain: &IommuDomain, iova: u64, physical: u64) {
    // SAFETY: the retained domain and completed map own the full hierarchy.
    // The test is the only data-leaf mutator and no mutation overlaps this walk.
    let (entry, level) = unsafe {
        super::observed_leaf(
            domain.page_table,
            controller.selected_levels(),
            PteFormat::Intel,
            iova,
        )
    }
    .expect("retained live leaf");
    assert_eq!(level, 1);
    assert_eq!(entry.phys_addr(), physical);
    assert!(entry.can_read() && entry.can_write());
}

pub(crate) async fn masked_mapping_retirement() -> bool {
    let controller = crate::io::iommu::runtime::registry::get_iommu_registry()
        .expect("boot IOMMU registry")
        .controllers
        .iter()
        .find(|controller| controller.is_translation_enabled())
        .map(Arc::clone)
        .expect("live Intel invalidation source");
    let id = controller
        .create_domain(None, IommuDomainType::Translated)
        .expect("isolated hardware domain admission");
    let domain = controller
        .domain(id)
        .expect("retained domain registry owner");
    let data = crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned(2, PAGE_SIZE_4K)
        .expect("owned DMA data pages");
    let physical = data.as_u64();
    let page = PAGE_SIZE_4K as u64;
    // RAM lies outside this intentionally small DMA address window.
    assert!(physical > MASK);
    let allocator =
        Arc::new(IovaAllocator::new(page, 3 * page).expect("private bounded IOVA space"));
    let live = map_owned_page(&controller, &domain, &allocator, physical).await;
    let live_iova = live.iova();
    assert_eq!(live_iova, page);
    check_live_page(&controller, &domain, live_iova, physical);
    // One byte below the remaining page's endpoint must reject that page.
    assert!(
        allocator
            .allocate_with_limit(page, PageGranularity::Page4K, MASK - 1)
            .is_none()
    );

    for _ in 0..64 {
        let cycling = map_owned_page(&controller, &domain, &allocator, physical + page).await;
        let cycling_iova = cycling.iova();
        assert_eq!(cycling_iova, 2 * page);
        assert_eq!(domain.mapped_size(), 2 * page);
        check_live_page(&controller, &domain, cycling_iova, physical + page);
        assert!(
            allocator
                .allocate_with_limit(page, PageGranularity::Page4K, MASK)
                .is_none()
        );
        cycling
            .unmap_async()
            .await
            .expect("completed cycling retirement");
        assert!(domain.mapping(cycling_iova).is_none());
        assert_eq!(domain.mapped_size(), page);
        check_live_page(&controller, &domain, live_iova, physical);
    }
    live.unmap_async().await.expect("completed live retirement");
    assert_eq!(domain.mapped_size(), 0);
    assert!(domain.mappings_snapshot().is_empty());

    // Both masked slots and the unconsumed outside slot remain available.
    let first = allocator
        .allocate_with_limit(page, PageGranularity::Page4K, MASK)
        .unwrap();
    let second = allocator
        .allocate_with_limit(page, PageGranularity::Page4K, MASK)
        .unwrap();
    assert_eq!([first, second], [page, 2 * page]);
    assert!(
        allocator
            .allocate_with_limit(page, PageGranularity::Page4K, MASK)
            .is_none()
    );
    let outside = allocator
        .allocate_contiguous(page, page)
        .expect("outside-mask capacity");
    assert_eq!(outside, 3 * page);
    // These three reservations never published data leaves or device access.
    for iova in [first, second, outside] {
        allocator
            .free_immediate(iova, page)
            .expect("unpublished IOVA release");
    }
    drop(domain);
    controller
        .destroy_domain(id)
        .expect("completed hardware domain retirement");
    data.release();
    true
}
