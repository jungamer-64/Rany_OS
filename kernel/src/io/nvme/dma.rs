use crate::io::dma::{CpuOwned, DeviceOwned, SliceDmaGuard, TypedDmaSlice};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use alloc::vec::Vec;
use x86_64::PhysAddr;

pub(crate) const NVME_PAGE_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NvmeDmaError {
    InvalidLen,
    OutOfMemory,
    IommuDeviceMissing,
    IommuIdentityBlocked,
    IommuMappingFailed,
}

#[inline]
pub(crate) fn align_up_page(value: usize) -> usize {
    (value + NVME_PAGE_SIZE - 1) & !(NVME_PAGE_SIZE - 1)
}

#[inline]
fn page_count(len: usize) -> usize {
    len.div_ceil(NVME_PAGE_SIZE)
}

#[inline]
fn direct_prp2(base_addr: u64, alloc_len: usize) -> Option<u64> {
    match page_count(alloc_len) {
        0 | 1 => None,
        2 => Some(base_addr + NVME_PAGE_SIZE as u64),
        _ => None,
    }
}

#[derive(Debug)]
struct IommuMapping {
    device: IommuDeviceId,
    iova: u64,
    size: u64,
}

impl Drop for IommuMapping {
    fn drop(&mut self) {
        let _ = crate::io::iommu::api::unmap_for_device(&self.device, self.iova, self.size);
    }
}

#[derive(Debug)]
struct PrpListPage {
    dev: Option<TypedDmaSlice<DeviceOwned>>,
    guard: Option<SliceDmaGuard>,
    map: Option<IommuMapping>,
    iova: u64,
}

impl Drop for PrpListPage {
    fn drop(&mut self) {
        if let (Some(guard), Some(dev)) = (self.guard.take(), self.dev.take()) {
            let _ = guard.complete(dev);
        }
        let _ = self.map.take();
    }
}

#[derive(Debug)]
struct PrpListChain {
    pages: Vec<PrpListPage>,
}

impl PrpListChain {
    fn first_iova(&self) -> u64 {
        self.pages.first().map(|p| p.iova).unwrap_or(0)
    }
}

fn map_for_iommu(
    device: Option<IommuDeviceId>,
    phys_addr: PhysAddr,
    size: usize,
) -> Result<(u64, Option<IommuMapping>), NvmeDmaError> {
    if !crate::io::iommu::api::is_iommu_enabled() {
        if crate::io::iommu::api::is_iommu_required()
            || !crate::io::iommu::api::is_unsafe_identity_mapping_allowed()
        {
            return Err(NvmeDmaError::IommuIdentityBlocked);
        }
        return Ok((phys_addr.as_u64(), None));
    }

    let dev = device.ok_or(NvmeDmaError::IommuDeviceMissing)?;
    let map_len = align_up_page(size) as u64;
    let iova = unsafe { crate::io::iommu::api::map_for_device(&dev, phys_addr, map_len) }
        .map_err(|_| NvmeDmaError::IommuMappingFailed)?;

    Ok((
        iova,
        Some(IommuMapping {
            device: dev,
            iova,
            size: map_len,
        }),
    ))
}

fn allocate_prp_list_buffers(
    device: Option<IommuDeviceId>,
    total_entries: usize,
) -> Result<
    (
        Vec<TypedDmaSlice<CpuOwned>>,
        Vec<u64>,
        Vec<Option<IommuMapping>>,
    ),
    NvmeDmaError,
> {
    let mut remaining = total_entries;
    let mut list_buffers = Vec::new();

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while remaining > 0 {
        let list =
            TypedDmaSlice::<CpuOwned>::new(NVME_PAGE_SIZE).ok_or(NvmeDmaError::OutOfMemory)?;
        list_buffers.push(list);
        remaining = if remaining > 512 { remaining - 511 } else { 0 };
    }

    let mut list_iovas = Vec::with_capacity(list_buffers.len());
    let mut list_maps = Vec::with_capacity(list_buffers.len());
    for list in &list_buffers {
        let (list_addr, list_map) = map_for_iommu(device, list.phys_addr(), NVME_PAGE_SIZE)?;
        list_iovas.push(list_addr);
        list_maps.push(list_map);
    }

    Ok((list_buffers, list_iovas, list_maps))
}

fn fill_prp_entries(
    list_buffers: &mut [TypedDmaSlice<CpuOwned>],
    list_iovas: &[u64],
    base_addr: u64,
    total_entries: usize,
) -> Result<(), NvmeDmaError> {
    let mut filled = 0usize;
    for idx in 0..list_buffers.len() {
        let remaining_entries = total_entries - filled;
        let needs_chain = remaining_entries > 512;
        let data_capacity = if needs_chain { 511 } else { remaining_entries };

        let entries = unsafe {
            core::slice::from_raw_parts_mut(
                list_buffers[idx].as_mut_slice().as_mut_ptr() as *mut u64,
                NVME_PAGE_SIZE / 8,
            )
        };

        for j in 0..data_capacity {
            entries[j] = base_addr + ((filled + j + 1) * NVME_PAGE_SIZE) as u64;
        }

        if needs_chain {
            entries[511] = list_iovas
                .get(idx + 1)
                .copied()
                .ok_or(NvmeDmaError::IommuMappingFailed)?;
        }

        filled += data_capacity;
    }
    Ok(())
}

fn build_prp_list(
    device: Option<IommuDeviceId>,
    base_addr: u64,
    alloc_len: usize,
) -> Result<(u64, Option<PrpListChain>), NvmeDmaError> {
    if alloc_len == 0 {
        return Err(NvmeDmaError::InvalidLen);
    }

    if let Some(prp2) = direct_prp2(base_addr, alloc_len) {
        return Ok((prp2, None));
    }
    if page_count(alloc_len) <= 1 {
        return Ok((0, None));
    }

    let total_entries = page_count(alloc_len) - 1;
    let (mut list_buffers, list_iovas, list_maps) =
        allocate_prp_list_buffers(device, total_entries)?;
    fill_prp_entries(&mut list_buffers, &list_iovas, base_addr, total_entries)?;

    let mut prp_pages = Vec::with_capacity(list_buffers.len());
    for ((list, map), iova) in list_buffers.into_iter().zip(list_maps).zip(list_iovas) {
        let (dev, guard) = list.start_dma();
        prp_pages.push(PrpListPage {
            dev: Some(dev),
            guard: Some(guard),
            map,
            iova,
        });
    }

    let chain = PrpListChain { pages: prp_pages };
    let prp2 = chain.first_iova();
    Ok((prp2, Some(chain)))
}

#[derive(Debug)]
pub(crate) struct NvmeDmaRegion {
    data_dev: Option<TypedDmaSlice<DeviceOwned>>,
    data_guard: Option<SliceDmaGuard>,
    data_map: Option<IommuMapping>,
    prp_list: Option<PrpListChain>,
    prp1: u64,
    prp2: u64,
    logical_len: usize,
    alloc_len: usize,
    phys_addr: PhysAddr,
}

impl NvmeDmaRegion {
    pub(crate) fn for_read(
        logical_len: usize,
        device: Option<IommuDeviceId>,
    ) -> Result<Self, NvmeDmaError> {
        if logical_len == 0 {
            return Err(NvmeDmaError::InvalidLen);
        }

        let alloc_len = align_up_page(logical_len);
        let data = TypedDmaSlice::<CpuOwned>::new(alloc_len).ok_or(NvmeDmaError::OutOfMemory)?;
        Self::from_cpu_owned(data, logical_len, device)
    }

    pub(crate) fn for_write(
        logical_len: usize,
        src: &[u8],
        device: Option<IommuDeviceId>,
    ) -> Result<Self, NvmeDmaError> {
        if logical_len == 0 || src.len() > logical_len {
            return Err(NvmeDmaError::InvalidLen);
        }

        let alloc_len = align_up_page(logical_len);
        let mut data =
            TypedDmaSlice::<CpuOwned>::new(alloc_len).ok_or(NvmeDmaError::OutOfMemory)?;
        data.as_mut_slice()[..src.len()].copy_from_slice(src);
        data.as_mut_slice()[src.len()..].fill(0);
        Self::from_cpu_owned(data, logical_len, device)
    }

    fn from_cpu_owned(
        data: TypedDmaSlice<CpuOwned>,
        logical_len: usize,
        device: Option<IommuDeviceId>,
    ) -> Result<Self, NvmeDmaError> {
        let alloc_len = data.len();
        let phys_addr = data.phys_addr();
        let (prp1, data_map) = map_for_iommu(device, phys_addr, alloc_len)?;
        let (prp2, prp_list) = build_prp_list(device, prp1, alloc_len)?;
        let (data_dev, data_guard) = data.start_dma();

        Ok(Self {
            data_dev: Some(data_dev),
            data_guard: Some(data_guard),
            data_map,
            prp_list,
            prp1,
            prp2,
            logical_len,
            alloc_len,
            phys_addr,
        })
    }

    pub(crate) fn prp1(&self) -> u64 {
        self.prp1
    }

    pub(crate) fn prp2(&self) -> u64 {
        self.prp2
    }

    pub(crate) fn logical_len(&self) -> usize {
        self.logical_len
    }

    pub(crate) fn alloc_len(&self) -> usize {
        self.alloc_len
    }

    pub(crate) fn phys_addr(&self) -> PhysAddr {
        self.phys_addr
    }

    pub(crate) fn copy_into(self, dst: &mut [u8]) {
        let copy_len = core::cmp::min(dst.len(), self.logical_len);
        let data = self.complete();
        dst[..copy_len].copy_from_slice(&data.as_slice()[..copy_len]);
    }

    pub(crate) fn complete(mut self) -> TypedDmaSlice<CpuOwned> {
        let _ = self.prp_list.take();
        let data_dev = self
            .data_dev
            .take()
            .expect("missing NVMe DMA device buffer");
        let data_guard = self
            .data_guard
            .take()
            .expect("missing NVMe DMA completion guard");
        let _ = self.data_map.take();
        data_guard.complete(data_dev)
    }
}

impl Drop for NvmeDmaRegion {
    fn drop(&mut self) {
        let _ = self.prp_list.take();
        if let (Some(guard), Some(dev)) = (self.data_guard.take(), self.data_dev.take()) {
            let _ = guard.complete(dev);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct IdentityFallbackGuard {
        prev_required: bool,
        #[cfg(debug_assertions)]
        prev_identity: bool,
    }

    impl IdentityFallbackGuard {
        fn new() -> Self {
            let prev_required = crate::io::iommu::api::is_iommu_required();
            crate::io::iommu::api::set_iommu_required(false);

            #[cfg(debug_assertions)]
            let prev_identity = crate::io::iommu::api::is_unsafe_identity_mapping_allowed();
            #[cfg(debug_assertions)]
            unsafe {
                crate::io::iommu::runtime::security::set_unsafe_identity_mapping_allowed(true);
            }

            Self {
                prev_required,
                #[cfg(debug_assertions)]
                prev_identity,
            }
        }
    }

    impl Drop for IdentityFallbackGuard {
        fn drop(&mut self) {
            #[cfg(debug_assertions)]
            unsafe {
                crate::io::iommu::runtime::security::set_unsafe_identity_mapping_allowed(
                    self.prev_identity,
                );
            }
            crate::io::iommu::api::set_iommu_required(self.prev_required);
        }
    }

    #[test_case]
    fn align_up_page_rounds_to_4k() {
        assert_eq!(align_up_page(1), NVME_PAGE_SIZE);
        assert_eq!(align_up_page(NVME_PAGE_SIZE), NVME_PAGE_SIZE);
        assert_eq!(align_up_page(NVME_PAGE_SIZE + 1), NVME_PAGE_SIZE * 2);
    }

    #[test_case]
    fn write_region_tracks_logical_and_alloc_len() {
        let _guard = IdentityFallbackGuard::new();
        let dma = NvmeDmaRegion::for_write(5, &[1, 2, 3], None).expect("write region");

        assert_eq!(dma.logical_len(), 5);
        assert_eq!(dma.alloc_len(), NVME_PAGE_SIZE);
        assert_eq!(dma.prp2(), 0);
    }

    #[test_case]
    fn write_region_zero_fills_tail_and_copy_respects_logical_len() {
        let _guard = IdentityFallbackGuard::new();
        let dma = NvmeDmaRegion::for_write(5, &[1, 2, 3], None).expect("write region");
        let data = dma.complete();

        assert_eq!(&data.as_slice()[..5], &[1, 2, 3, 0, 0]);
        assert!(data.as_slice()[5..].iter().all(|byte| *byte == 0));

        let dma = NvmeDmaRegion::for_write(5, &[9, 8, 7], None).expect("copy region");
        let mut out = [0xAAu8; 7];
        dma.copy_into(&mut out);
        assert_eq!(&out[..5], &[9, 8, 7, 0, 0]);
        assert_eq!(&out[5..], &[0xAA, 0xAA]);
    }

    #[test_case]
    fn prp2_selection_handles_two_page_transfer() {
        let _guard = IdentityFallbackGuard::new();
        let dma = NvmeDmaRegion::for_write(NVME_PAGE_SIZE + 1, &[0x5A], None).expect("two pages");

        assert_eq!(dma.alloc_len(), NVME_PAGE_SIZE * 2);
        assert_eq!(dma.prp2(), dma.prp1() + NVME_PAGE_SIZE as u64);
    }

    #[test_case]
    fn prp2_selection_uses_prp_list_for_multi_page_transfer() {
        let _guard = IdentityFallbackGuard::new();
        let dma = NvmeDmaRegion::for_write((NVME_PAGE_SIZE * 2) + 1, &vec![0xCC; 32], None)
            .expect("three pages");

        assert_eq!(dma.alloc_len(), NVME_PAGE_SIZE * 3);
        assert_ne!(dma.prp2(), 0);
        assert_ne!(dma.prp2(), dma.prp1() + NVME_PAGE_SIZE as u64);
    }
}
