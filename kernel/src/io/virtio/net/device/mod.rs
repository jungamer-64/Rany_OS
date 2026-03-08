use super::*;
use crate::sync::lockfree::MpmcRingBuffer;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use alloc::boxed::Box;
use alloc::vec::Vec;
use crate::io::virtio::virtqueue::{VringAvail, VringDesc, VringUsed};
use kernel_api::dma::{CpuOwned, DmaSlice};
use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes, iommu_align_len};
use crate::io::iommu::api::{is_iommu_enabled, is_iommu_required, unmap_dma, unmap_for_device};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::defs::{VirtioDeviceType, status};
use crate::io::virtio::transport::{TransportType, VirtioTransport};

mod dma;
pub use dma::*;
mod irq;
mod mac;
mod registry;
mod rx;
mod tx;
pub use registry::*;

impl Drop for NetVirtQueue {
    fn drop(&mut self) {
        if let Some(map) = self.iommu_map.take() {
            if let Some(handle) = map.handle {
                if let Err(err) = handle.unmap() {
                    log::warn!("[VIRTIO-NET] failed to unmap DMA handle: {:?}", err);
                }
            } else {
                let result = match map.device {
                    Some(device) => unmap_for_device(&device, map.iova, map.len as u64),
                    None => unmap_dma(map.iova, map.len as u64),
                };
                if let Err(err) = result {
                    log::warn!("[VIRTIO-NET] failed to unmap queue DMA: {:?}", err);
                }
            }
        }
    }
}

// ============================================================================
// VirtIO Net Device
// ============================================================================

/// VirtIO ネットワークデバイス
#[derive(Debug)]
pub struct VirtioNetDevice {
    /// トランスポート層（MMIO/PCI共通インターフェース）
    pub(crate) transport: alloc::sync::Arc<dyn VirtioTransport>,
    /// Shared device core
    pub(crate) core: virtio_driver::net::device::VirtioNetDevice,
    /// VirtIO-Net device index (multi-NIC support)
    pub(crate) virtio_index: u8,
    /// Bound logical network interface id (assigned by NetworkManager)
    pub(crate) net_if_id: Option<crate::net::runtime::manager::NetIfId>,
    /// Optional IOMMU device identifier for device-scoped mappings
    iommu_device_id: Option<IommuDeviceId>,
    /// 受信キューリスト (各ペアにつき1つ、インデックス0,2,...)
    rx_queues: Vec<NetVirtQueue>,
    /// 送信キューリスト (各ペアにつき1つ、インデックス1,3,...)
    tx_queues: Vec<NetVirtQueue>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 統計: 受信パケット数
    pub(crate) rx_packets: AtomicU32,
    /// 統計: 受信バイト数
    pub(super) rx_bytes: AtomicU32,
    /// 統計: 送信パケット数
    pub(crate) tx_packets: AtomicU32,
    /// 統計: 送信バイト数
    pub(super) tx_bytes: AtomicU32,
    /// プール済み送信用バウンスバッファ
    tx_bounce_pool: MpmcRingBuffer<CoherentDmaBuffer, 256>,
    /// プール済み受信用バウンスバッファ
    rx_bounce_pool: MpmcRingBuffer<CoherentDmaBuffer, 256>,
}

impl VirtioNetDevice {
    /// 新しいデバイスを作成
    pub fn new(transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_index_and_device(0, transport, None)
    }

    /// 新しいデバイスを作成（IOMMUデバイスIDを指定）
    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self::new_with_index_and_device(0, transport, iommu_device_id)
    }

    /// 新しいデバイスを作成（デバイス index 指定）
    pub fn new_at_index(index: u8, transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_index_and_device(index, transport, None)
    }

    /// 新しいデバイスを作成（デバイス index + IOMMUデバイスID指定）
    pub fn new_with_index_and_device(
        index: u8,
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self {
            transport: alloc::sync::Arc::from(transport),
            core: virtio_driver::net::device::VirtioNetDevice::new(),
            virtio_index: index,
            net_if_id: None,
            iommu_device_id,
            rx_queues: Vec::new(),
            tx_queues: Vec::new(),
            initialized: AtomicBool::new(false),
            rx_packets: AtomicU32::new(0),
            rx_bytes: AtomicU32::new(0),
            tx_packets: AtomicU32::new(0),
            tx_bytes: AtomicU32::new(0),
            tx_bounce_pool: MpmcRingBuffer::new(),
            rx_bounce_pool: MpmcRingBuffer::new(),
        }
    }

    pub fn first_rx_queue(&self) -> Option<&NetVirtQueue> {
        self.rx_queues.get(0)
    }

    pub fn first_tx_queue(&self) -> Option<&NetVirtQueue> {
        self.tx_queues.get(0)
    }

    pub fn iommu_device_id(&self) -> Option<IommuDeviceId> {
        self.iommu_device_id
    }

    pub fn set_net_if_id(&mut self, if_id: crate::net::runtime::manager::NetIfId) {
        self.net_if_id = Some(if_id);
    }

    pub fn net_if_id(&self) -> Option<crate::net::runtime::manager::NetIfId> {
        self.net_if_id
    }

    pub(crate) fn mut_transport(&mut self) -> &mut dyn VirtioTransport {
        alloc::sync::Arc::get_mut(&mut self.transport)
            .expect("Transport must not be shared during init")
    }

    fn validate_iommu_device_requirement(
        iommu_enabled: bool,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Result<(), VirtioNetError> {
        if iommu_enabled && iommu_device_id.is_none() {
            log::error!(
                "[VIRTIO-NET] strict IOMMU mode requires iommu_device_id when IOMMU is enabled"
            );
            return Err(VirtioNetError::DeviceError);
        }
        Ok(())
    }

    pub fn init(&mut self) -> Result<(), VirtioNetError> {
        if self.transport.device_type() != VirtioDeviceType::Network {
            return Err(VirtioNetError::DeviceError);
        }

        Self::validate_iommu_device_requirement(is_iommu_enabled(), self.iommu_device_id)?;

        self.core.init(self.transport.as_ref()).map_err(|_| VirtioNetError::DeviceError)?;

        if let Err(e) = self.setup_queues() {
            log::error!("[VIRTIO-NET] Failed to setup queues: {:?}", e);
            self.mut_transport()
                .set_status(status::VIRTIO_STATUS_FAILED);
            return Err(e);
        }

        self.mut_transport().add_status(status::VIRTIO_STATUS_DRIVER_OK);

        for rxq in &self.rx_queues {
            rxq.notify(self.transport.as_ref());
        }

        if let Err(e) = self.init_bounce_pools() {
            log::error!("[VIRTIO-NET] Failed to init bounce pools: {:?}", e);
            self.mut_transport()
                .set_status(status::VIRTIO_STATUS_FAILED);
            return Err(e);
        }

        self.initialized.store(true, Ordering::Release);
        Ok(())
    }
}

impl virtio_driver::net::NetRuntime for VirtioNetDevice {
    fn alloc_dma(
        &self,
        size: usize,
        _purpose: virtio_driver::net::NetDmaPurpose,
    ) -> Result<DmaSlice<CpuOwned>, VirtioNetError> {
        let buffer = CoherentDmaBuffer::new(size, DmaMemoryAttributes::MMIO)
            .ok_or(VirtioNetError::DeviceError)?;
        
        let (phys, iova, virt, len, _releaser) = buffer.into_raw_parts();
        Ok(unsafe { DmaSlice::from_raw_parts(phys, iova, virt, len, None) })
    }

    fn alloc_packet(&self) -> Option<PacketRef> {
        crate::net::datapath::mempool::alloc_packet()
    }

    fn schedule_wake(&self, queue_index: u16) {
        if (queue_index % 2) == 0 {
            if let Some(q) = self.rx_queues.get((queue_index / 2) as usize) {
                q.pending_wakers.wake_all();
            }
        } else {
            if let Some(q) = self.tx_queues.get((queue_index / 2) as usize) {
                q.pending_wakers.wake_all();
            }
        }
    }

    fn log(&self, _level: log::Level, msg: core::fmt::Arguments) {
        log::info!("[VIRTIO-NET-CORE] {}", msg);
    }
}

impl VirtioNetDevice {
    pub fn refill_rx_queues(&self) {
        for (i, rx_queue) in self.rx_queues.iter().enumerate() {
            let q_idx = (i * 2) as u16;
            if let Ok(inner) = rx_queue.inner.lock() {
                let count = self.core.refill_rx_queue(self, q_idx, &inner);
                if count > 0 {
                    rx_queue.notify(self.transport.as_ref());
                }
            }
        }
    }

    fn init_bounce_pools(&self) -> Result<(), VirtioNetError> {
        let pool_size = 128;
        let buffer_size = 4096;

        for _ in 0..pool_size {
            let tx_buf = match self.iommu_device_id {
                Some(dev) => {
                    CoherentDmaBuffer::new_for_device(buffer_size, DmaMemoryAttributes::MMIO, &dev)
                }
                None => CoherentDmaBuffer::new(buffer_size, DmaMemoryAttributes::MMIO),
            }
            .ok_or(VirtioNetError::DeviceError)?;
            let _ = self.tx_bounce_pool.push(tx_buf);

            let rx_buf = match self.iommu_device_id {
                Some(dev) => {
                    CoherentDmaBuffer::new_for_device(buffer_size, DmaMemoryAttributes::MMIO, &dev)
                }
                None => CoherentDmaBuffer::new(buffer_size, DmaMemoryAttributes::MMIO),
            }
            .ok_or(VirtioNetError::DeviceError)?;
            let _ = self.rx_bounce_pool.push(rx_buf);
        }
        Ok(())
    }

    pub(crate) fn get_tx_bounce_buffer(
        &self,
        size: usize,
    ) -> Result<crate::io::dma::CoherentDmaBuffer, VirtioNetError> {
        if let Some(buf) = self.tx_bounce_pool.pop() {
            if buf.size() >= size {
                return Ok(buf);
            }
            let _ = self.tx_bounce_pool.push(buf);
        }
        let alloc_size = core::cmp::max(size, 4096);
        match self.iommu_device_id {
            Some(dev) => crate::io::dma::CoherentDmaBuffer::new_for_device(
                alloc_size,
                crate::io::dma::DmaMemoryAttributes::MMIO,
                &dev,
            ),
            None => crate::io::dma::CoherentDmaBuffer::new(
                alloc_size,
                crate::io::dma::DmaMemoryAttributes::MMIO,
            ),
        }
        .ok_or(VirtioNetError::DeviceError)
    }

    pub(crate) fn return_tx_bounce_buffer(&self, buffer: crate::io::dma::CoherentDmaBuffer) {
        let _ = self.tx_bounce_pool.push(buffer);
    }

    pub(crate) fn get_rx_bounce_buffer(
        &self,
        size: usize,
    ) -> Result<crate::io::dma::CoherentDmaBuffer, VirtioNetError> {
        if let Some(buf) = self.rx_bounce_pool.pop() {
            if buf.size() >= size {
                return Ok(buf);
            }
            let _ = self.rx_bounce_pool.push(buf);
        }
        let alloc_size = core::cmp::max(size, 4096);
        match self.iommu_device_id {
            Some(dev) => crate::io::dma::CoherentDmaBuffer::new_for_device(
                alloc_size,
                crate::io::dma::DmaMemoryAttributes::MMIO,
                &dev,
            ),
            None => crate::io::dma::CoherentDmaBuffer::new(
                alloc_size,
                crate::io::dma::DmaMemoryAttributes::MMIO,
            ),
        }
        .ok_or(VirtioNetError::DeviceError)
    }

    pub(crate) fn return_rx_bounce_buffer(&self, buffer: crate::io::dma::CoherentDmaBuffer) {
        let _ = self.rx_bounce_pool.push(buffer);
    }

    pub(super) fn setup_queues(&mut self) -> Result<(), VirtioNetError> {
        let pair_count = self.core.get_pair_count();
        for i in 0..pair_count {
            let rx_index = (i * 2) as u16;
            let rxq = self.setup_single_queue(rx_index)?;
            self.rx_queues.push(rxq);

            let tx_index = rx_index + 1;
            let txq = self.setup_single_queue(tx_index)?;
            self.tx_queues.push(txq);
        }

        Ok(())
    }

    pub(super) fn setup_single_queue(
        &mut self,
        queue_index: u16,
    ) -> Result<NetVirtQueue, VirtioNetError> {
        let (queue_size, layout) = self.core.prepare_queue(self.transport.as_ref(), queue_index)
            .map_err(|_| VirtioNetError::DeviceError)?;

        let (buffer, _dma_len) = self.allocate_queue_dma(layout.total_size)?;

        let phys_base = buffer.device_addr();
        let ptr = unsafe { buffer.as_slice().as_ptr() } as *mut u8;

        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(layout.desc_size) as *mut VringAvail };
        let used_ring = unsafe { ptr.add(layout.used_offset) as *mut VringUsed };
        let notify_addr = self.mut_transport().get_notify_addr(queue_index);
        let notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);

        let (dma_base, iommu_map) = self.setup_iommu_dma_mapping(&buffer, layout.total_size, phys_base)?;

        let (tx_headers, tx_header_dma_base) = if (queue_index % 2) == 1 {
            let header_ptr = unsafe { ptr.add(layout.header_offset) as *mut VirtioNetHeader };
            let header_dma_base = dma_base + layout.header_offset as u64;
            (Some(header_ptr), Some(header_dma_base))
        } else {
            (None, None)
        };

        let features = self.transport.get_device_features_low() as u64
            | ((self.transport.get_device_features_high() as u64) << 32);

        // Core trackers
        if (queue_index % 2) == 0 {
            self.core.rx_trackers.push(virtio_driver::net::InflightTracker::new(queue_size));
        } else {
            self.core.tx_trackers.push(virtio_driver::net::InflightTracker::new(queue_size));
        }

        let desc_addr = dma_base;
        let avail_addr = dma_base + layout.desc_size as u64;
        let used_addr = dma_base + layout.used_offset as u64;
        self.core.commit_queue(self.transport.as_ref(), queue_index, desc_addr, avail_addr, used_addr);

        let queue = unsafe {
            NetVirtQueue::new(
                queue_index,
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                Some(buffer),
                notify_addr,
                notify_is_32bit,
                iommu_map,
                tx_headers,
                tx_header_dma_base,
                features,
            )
        };

        if (queue_index % 2) == 0 {
            if let Ok(inner) = queue.inner.lock() {
                self.core.refill_rx_queue(self, queue_index, &inner);
            }
        }

        self.mut_transport().enable_queue();

        Ok(queue)
    }

    pub(super) fn allocate_queue_dma(
        &self,
        total_size: usize,
    ) -> Result<(CoherentDmaBuffer, usize), VirtioNetError> {
        if is_iommu_required() && !is_iommu_enabled() {
            return Err(VirtioNetError::DeviceError);
        }

        if is_iommu_enabled() {
            let aligned_len = iommu_align_len(total_size).ok_or(VirtioNetError::DeviceError)?;
            let device_id = self.iommu_device_id.ok_or_else(|| {
                VirtioNetError::DeviceError
            })?;
            let buffer = CoherentDmaBuffer::new_for_device(
                aligned_len,
                DmaMemoryAttributes::MMIO,
                &device_id,
            )
            .ok_or(VirtioNetError::DeviceError)?;
            Ok((buffer, aligned_len))
        } else {
            let buffer = CoherentDmaBuffer::new(total_size, DmaMemoryAttributes::MMIO)
                .ok_or(VirtioNetError::DeviceError)?;
            Ok((buffer, total_size))
        }
    }

    pub(super) fn setup_iommu_dma_mapping(
        &self,
        buffer: &CoherentDmaBuffer,
        _dma_len: usize,
        phys_base: u64,
    ) -> Result<(u64, Option<IommuMapping>), VirtioNetError> {
        if !is_iommu_enabled() {
            return Ok((phys_base, None));
        }
        Ok((buffer.device_addr(), None))
    }

    pub fn notify_queue(&mut self, queue_index: u16) {
        self.transport.notify_queue(queue_index);
    }
}

impl Drop for VirtioNetDevice {
    fn drop(&mut self) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_validate_iommu_device_requirement_rejects_missing_device_id_when_enabled() {
        let result = VirtioNetDevice::validate_iommu_device_requirement(true, None);
        assert_eq!(result, Err(VirtioNetError::DeviceError));
    }

    #[test_case]
    fn test_validate_iommu_device_requirement_accepts_device_id_when_enabled() {
        let device = IommuDeviceId::new(0, 0, 1, 0);
        let result = VirtioNetDevice::validate_iommu_device_requirement(true, Some(device));
        assert_eq!(result, Ok(()));
    }

    #[test_case]
    fn test_validate_iommu_device_requirement_accepts_missing_device_id_when_disabled() {
        let result = VirtioNetDevice::validate_iommu_device_requirement(false, None);
        assert_eq!(result, Ok(()));
    }
}
