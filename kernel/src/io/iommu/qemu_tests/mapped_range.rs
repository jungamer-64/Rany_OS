use crate::io::iommu::common::dma::iova_allocator::{IovaAllocator, PageGranularity};
use crate::io::iommu::common::dma::mapping_outcome::{DeviceMappedRange, DmaInvalidationSource};
use crate::io::iommu::common::domain::IommuDomain;
use crate::io::iommu::types::{DeviceId, IommuDomainType, PteFormat};
use crate::io::iommu::vendors::intel::IntelIommuDriver;
use crate::io::iommu::vendors::intel::controller::IommuController;
use crate::io::iommu::vendors::intel::controller::dma::DomainManager;
use crate::io::iommu::vendors::intel::controller::dma::{DeviceBinding, PublishedContext};
use crate::mm::types::PAGE_SIZE_4K;
use alloc::sync::Arc;

const MASK: u64 = 0x2fff;

async fn map_owned_range(
    controller: &Arc<IommuController>,
    domain: &Arc<IommuDomain>,
    allocator: &Arc<IovaAllocator>,
    physical: u64,
    bytes: u64,
    mask: u64,
) -> DeviceMappedRange {
    let iova = allocator
        .allocate_with_limit(bytes, PageGranularity::Page4K, mask)
        .expect("masked IOVA admission");
    assert!(iova.checked_add(bytes - 1).expect("bounded endpoint") <= mask);
    // The test retains the real data allocation until every mapping completes.
    // This fresh domain belongs to this hardware source and has no devices;
    // its private address space cannot overlap another device's mappings.
    let mapping = DeviceMappedRange::admitted(
        Arc::clone(domain),
        DmaInvalidationSource::Intel(Arc::clone(controller)),
        Arc::clone(allocator),
        iova,
        physical,
        bytes,
    );
    domain
        .map(iova, physical, bytes, true, true)
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
    let data = crate::mm::phys::frame_allocator::alloc_contiguous_frames_aligned(3, PAGE_SIZE_4K)
        .expect("owned DMA data pages");
    let physical = data.as_u64();
    let page = PAGE_SIZE_4K as u64;
    // RAM lies outside this intentionally small DMA address window.
    assert!(physical > MASK);
    let allocator =
        Arc::new(IovaAllocator::new(page, 3 * page).expect("private bounded IOVA space"));
    let live = map_owned_range(&controller, &domain, &allocator, physical, page, MASK).await;
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
        let cycling = map_owned_range(
            &controller,
            &domain,
            &allocator,
            physical + page,
            page,
            MASK,
        )
        .await;
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

    // Three pages at a four-page-aligned base require AM=2 when PSI is available.
    let base = 4 * page;
    let span = 3 * page;
    let mask = base + span - 1;
    let allocator = Arc::new(IovaAllocator::new(base, span).expect("aligned IOVA window"));
    let range = map_owned_range(&controller, &domain, &allocator, physical, span, mask).await;
    assert_eq!(range.iova(), base);
    check_live_page(&controller, &domain, base + 2 * page, physical + 2 * page);
    range
        .unmap_async()
        .await
        .expect("multi-page IOTLB completion");
    assert_eq!(domain.mapped_size(), 0);
    let recycled = allocator
        .allocate_with_limit(span, PageGranularity::Page4K, mask)
        .expect("the entire retired range is reusable");
    assert_eq!(recycled, base);
    allocator
        .free_immediate(recycled, span)
        .expect("unpublished range release");

    // The QEMU PCI bus has no device in this segment. Publish a software
    // binding only, so no device can access the fixture RAM.
    let device = DeviceId::new(u16::MAX, 0, 0, 0);
    {
        let mut bindings = controller
            .device_bindings
            .lock()
            .unwrap_or_else(|_| panic!("device bindings"));
        assert!(!bindings.contains_key(&device));
        bindings.insert(
            device,
            DeviceBinding::Attached(PublishedContext::new(Arc::clone(&domain), None)),
        );
    }
    let driver = IntelIommuDriver::with_controller(Arc::clone(&controller));
    // SAFETY: data owns the aligned RAM through translation retirement.
    let admission = unsafe {
        driver
            .map_for_device_async(&device, data.start_address(), page)
            .await
    };
    let prior = controller
        .device_bindings
        .lock()
        .unwrap_or_else(|_| panic!("device bindings"))
        .remove(&device);
    assert!(matches!(prior, Some(DeviceBinding::Attached(_))));
    drop(prior);
    let mapping = admission.expect("synchronized device mapping");
    let iova = mapping.iova();
    check_live_page(&controller, &domain, iova, physical);
    mapping
        .unmap_async()
        .await
        .expect("retirement through the captured origin after binding removal");
    assert!(domain.mapping(iova).is_none());

    drop(domain);
    controller
        .destroy_domain(id)
        .expect("completed hardware domain retirement");
    data.release();
    true
}
