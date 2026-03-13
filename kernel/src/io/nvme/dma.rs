use crate::io::dma::{
    DeviceDmaContext, DeviceDmaMapping, DmaDirection, DmaMemoryAttributes, DmaRegion,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use alloc::vec::Vec;
use x86_64::PhysAddr;

pub(crate) const NVME_PAGE_SIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NvmeDmaError {
    InvalidLen,
    OutOfMemory,
    IommuDeviceMissing,
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
struct PrpListPage {
    map: Option<DeviceDmaMapping>,
    region: DmaRegion,
    iova: u64,
}

impl Drop for PrpListPage {
    fn drop(&mut self) {
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
    device: IommuDeviceId,
    phys_addr: PhysAddr,
    size: usize,
) -> Result<(u64, Option<DeviceDmaMapping>), NvmeDmaError> {
    let ctx = DeviceDmaContext::for_attached_device(device);
    let mapping = ctx
        .map_physical_range(phys_addr, size, DmaDirection::Bidirectional)
        .map_err(|_| NvmeDmaError::IommuMappingFailed)?;
    let iova = mapping.device_addr();

    Ok((iova, Some(mapping)))
}

fn allocate_prp_list_buffers(
    device: IommuDeviceId,
    total_entries: usize,
) -> Result<(Vec<DmaRegion>, Vec<u64>, Vec<Option<DeviceDmaMapping>>), NvmeDmaError> {
    let mut remaining = total_entries;
    let mut list_buffers = Vec::new();

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
    while remaining > 0 {
        let list = DmaRegion::new(NVME_PAGE_SIZE, DmaMemoryAttributes::TO_DEVICE)
            .ok_or(NvmeDmaError::OutOfMemory)?;
        list_buffers.push(list);
        remaining = if remaining > 512 { remaining - 511 } else { 0 };
    }

    let mut list_iovas = Vec::with_capacity(list_buffers.len());
    let mut list_maps = Vec::with_capacity(list_buffers.len());
    for list in &list_buffers {
        let (list_addr, list_map) =
            map_for_iommu(device, PhysAddr::new(list.host_addr()), NVME_PAGE_SIZE)?;
        list_iovas.push(list_addr);
        list_maps.push(list_map);
    }

    Ok((list_buffers, list_iovas, list_maps))
}

fn fill_prp_entries(
    list_buffers: &mut [DmaRegion],
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
    device: IommuDeviceId,
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
        list.prepare_for_device();
        prp_pages.push(PrpListPage {
            map,
            region: list,
            iova,
        });
    }

    let chain = PrpListChain { pages: prp_pages };
    let prp2 = chain.first_iova();
    Ok((prp2, Some(chain)))
}

#[derive(Debug)]
pub(crate) struct NvmeDmaRegion {
    data_map: Option<DeviceDmaMapping>,
    data_region: Option<DmaRegion>,
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
        device: IommuDeviceId,
    ) -> Result<Self, NvmeDmaError> {
        if logical_len == 0 {
            return Err(NvmeDmaError::InvalidLen);
        }

        let alloc_len = align_up_page(logical_len);
        let data = DmaRegion::new(alloc_len, DmaMemoryAttributes::FROM_DEVICE)
            .ok_or(NvmeDmaError::OutOfMemory)?;
        Self::from_region(data, logical_len, device)
    }

    pub(crate) fn for_write(
        logical_len: usize,
        src: &[u8],
        device: IommuDeviceId,
    ) -> Result<Self, NvmeDmaError> {
        if logical_len == 0 || src.len() > logical_len {
            return Err(NvmeDmaError::InvalidLen);
        }

        let alloc_len = align_up_page(logical_len);
        let mut data = DmaRegion::new(alloc_len, DmaMemoryAttributes::TO_DEVICE)
            .ok_or(NvmeDmaError::OutOfMemory)?;
        unsafe {
            data.as_mut_slice()[..src.len()].copy_from_slice(src);
            data.as_mut_slice()[src.len()..].fill(0);
        }
        Self::from_region(data, logical_len, device)
    }

    pub(crate) fn from_region(
        data: DmaRegion,
        logical_len: usize,
        device: IommuDeviceId,
    ) -> Result<Self, NvmeDmaError> {
        let alloc_len = data.size();
        let phys_addr = PhysAddr::new(data.host_addr());
        let (prp1, data_map) = map_for_iommu(device, phys_addr, alloc_len)?;
        let (prp2, prp_list) = build_prp_list(device, prp1, alloc_len)?;
        data.prepare_for_device();

        Ok(Self {
            data_map,
            data_region: Some(data),
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
        dst[..copy_len].copy_from_slice(&unsafe { data.as_slice() }[..copy_len]);
    }

    pub(crate) fn complete(mut self) -> DmaRegion {
        let _ = self.prp_list.take();
        let data = self.data_region.take().expect("missing NVMe DMA region");
        let _ = self.data_map.take();
        data.finish_from_device();
        data
    }
}

impl Drop for NvmeDmaRegion {
    fn drop(&mut self) {
        let _ = self.prp_list.take();
        let _ = self.data_map.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn test_device() -> IommuDeviceId {
        let device = IommuDeviceId::new(0, 0, 0x1f, 0);
        crate::io::iommu::testkit::fixtures::ensure_test_intel_iommu_device(device);
        device
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn align_up_page_rounds_to_4k() {
        assert_eq!(align_up_page(1), NVME_PAGE_SIZE);
        assert_eq!(align_up_page(NVME_PAGE_SIZE), NVME_PAGE_SIZE);
        assert_eq!(align_up_page(NVME_PAGE_SIZE + 1), NVME_PAGE_SIZE * 2);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn write_region_tracks_logical_and_alloc_len() {
        let dma = NvmeDmaRegion::for_write(5, &[1, 2, 3], test_device()).expect("write region");

        assert_eq!(dma.logical_len(), 5);
        assert_eq!(dma.alloc_len(), NVME_PAGE_SIZE);
        assert_eq!(dma.prp2(), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn write_region_zero_fills_tail_and_copy_respects_logical_len() {
        let dma = NvmeDmaRegion::for_write(5, &[1, 2, 3], test_device()).expect("write region");
        let data = dma.complete();

        assert_eq!(&unsafe { data.as_slice() }[..5], &[1, 2, 3, 0, 0]);
        assert!(
            unsafe { data.as_slice() }[5..]
                .iter()
                .all(|byte| *byte == 0)
        );

        let dma = NvmeDmaRegion::for_write(5, &[9, 8, 7], test_device()).expect("copy region");
        let mut out = [0xAAu8; 7];
        dma.copy_into(&mut out);
        assert_eq!(&out[..5], &[9, 8, 7, 0, 0]);
        assert_eq!(&out[5..], &[0xAA, 0xAA]);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn prp2_selection_handles_two_page_transfer() {
        let dma = NvmeDmaRegion::for_write(NVME_PAGE_SIZE + 1, &[0x5A], test_device())
            .expect("two pages");

        assert_eq!(dma.alloc_len(), NVME_PAGE_SIZE * 2);
        assert_eq!(dma.prp2(), dma.prp1() + NVME_PAGE_SIZE as u64);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]

    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn prp2_selection_uses_prp_list_for_multi_page_transfer() {
        let dma =
            NvmeDmaRegion::for_write((NVME_PAGE_SIZE * 2) + 1, &vec![0xCC; 32], test_device())
                .expect("three pages");

        assert_eq!(dma.alloc_len(), NVME_PAGE_SIZE * 3);
        assert_ne!(dma.prp2(), 0);
        assert_ne!(dma.prp2(), dma.prp1() + NVME_PAGE_SIZE as u64);
    }
}
