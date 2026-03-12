// ============================================================================
// src/io/virtio/net.rs - VirtIO Network Device Driver
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// 設計書 7.1: VirtIOドライバのRust実装
// ============================================================================
#![allow(dead_code)]

use crate::io::dma::CoherentDmaBuffer;
use crate::io::iommu::api::unmap_for_device;
use crate::io::iommu::runtime::registry::get_device_dma_mask;
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::transport::VirtioTransport;
use crate::io::virtio::virtqueue::{VringAvail, VringDesc, VringUsed};
use crate::sync::IrqPoisonLock;
use crate::sync::PoisonLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU16;
// Import PacketRef for zero-copy
use crate::net::datapath::mempool::PacketRef;
pub use virtio_driver::net::{
    NetDmaDirection, NetDmaPurpose, NetRuntime, VirtioNetConfig, VirtioNetError, VirtioNetHeader,
    VirtioNetStats,
};

pub mod device;
pub use device::*;

// Features re-exported from driver crate
pub use virtio_driver::net::features;

// ============================================================================
// VirtIO Net Transport Helper Functions
// ============================================================================

fn dma_mask_allows_range(mask: u64, addr: u64, size: u64) -> bool {
    if size == 0 {
        return true;
    }

    let end = match addr.checked_add(size) {
        Some(end) => end,
        None => return false,
    };

    let limit = (mask as u128) + 1;
    (addr as u128) <= (mask as u128) && (end as u128) <= limit
}

fn check_device_dma_mask(
    device: Option<IommuDeviceId>,
    addr: u64,
    size: usize,
) -> Result<(), VirtioNetError> {
    let Some(device) = device else {
        return Ok(());
    };
    let Some(mask) = get_device_dma_mask(&device) else {
        return Ok(());
    };
    if dma_mask_allows_range(mask, addr, size as u64) {
        Ok(())
    } else {
        Err(VirtioNetError::DeviceError)
    }
}

fn unmap_iommu_addr(device: Option<IommuDeviceId>, iova: u64, len: usize) {
    let Some(device) = device else {
        log::error!(
            "[VIRTIO-NET] missing device id for DMA unmap (iova=0x{:x}, len={})",
            iova,
            len
        );
        return;
    };
    if let Err(err) = unmap_for_device(&device, iova, len as u64) {
        log::warn!("[VIRTIO-NET] failed to unmap DMA buffer: {:?}", err);
    }
}

fn dma_direction_for_net(direction: NetDmaDirection) -> crate::io::dma::DmaDirection {
    match direction {
        NetDmaDirection::ToDevice => crate::io::dma::DmaDirection::ToDevice,
        NetDmaDirection::FromDevice => crate::io::dma::DmaDirection::FromDevice,
        NetDmaDirection::Bidirectional => crate::io::dma::DmaDirection::Bidirectional,
    }
}

fn map_net_dma_for_range(
    device: IommuDeviceId,
    phys_addr: u64,
    size: usize,
    direction: NetDmaDirection,
) -> Result<virtio_driver::net::NetDmaMappingToken, VirtioNetError> {
    let ctx = crate::io::dma::DeviceDmaContext::for_attached_device(device);
    let mapping = ctx
        .map_physical_range(
            x86_64::PhysAddr::new(phys_addr),
            size,
            dma_direction_for_net(direction),
        )
        .map_err(|_| VirtioNetError::DeviceError)?;
    let device_addr = mapping.device_addr();
    let (_device_id, release_key, mapped_len) = mapping.into_parts();
    Ok(virtio_driver::net::NetDmaMappingToken::mapped(
        device_addr,
        release_key,
        mapped_len,
    ))
}

fn release_net_dma_mapping(
    device: Option<IommuDeviceId>,
    mapping: virtio_driver::net::NetDmaMappingToken,
) {
    if let Some(release_key) = mapping.release_key() {
        unmap_iommu_addr(device, release_key, mapping.mapped_len() as usize);
    }
}

// ============================================================================
// Send-safe pointer wrapper
// ============================================================================

// ============================================================================
// Internal Mutability and Synchronization
// ============================================================================

/// ネットワーク VirtQueue
#[derive(Debug)]
pub struct NetVirtQueue {
    /// Shared implementation from virtio-driver crate
    pub inner: IrqPoisonLock<virtio_driver::net::NetVirtQueue>,
    /// 最後に処理した Used インデックス (Atomic for non-blocking poll)
    pub last_used_idx: AtomicU16,
    /// 割り込み待機中のWaker
    pub pending_wakers: crate::sync::WakerQueue,
    /// DMA Buffer to keep memory alive (Shared logic doesn't hold this)
    pub dma_buffer: Option<CoherentDmaBuffer>,
    /// Completed descriptors for async waiters
    completion_map: PoisonLock<BTreeMap<u16, u32>>,
}

// NetVirtQueueをSend/Syncにする
unsafe impl Send for NetVirtQueue {}
unsafe impl Sync for NetVirtQueue {}

impl NetVirtQueue {
    pub unsafe fn new(
        index: u16,
        size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
        dma_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
        _notify_addr: Option<u64>,
        _notify_is_32bit: bool,
        tx_headers: Option<*mut VirtioNetHeader>,
        tx_header_dma_base: Option<u64>,
        features: u64,
    ) -> Self {
        let vq_inner = virtio_driver::core::VirtQueue::new(
            index,
            size,
            desc_table,
            avail_ring as *mut virtio_driver::defs::VringAvailHeader,
            used_ring as *mut virtio_driver::defs::VringUsedHeader,
            features,
        )
        .expect("[VIRTIO-NET] failed to init core virtqueue");

        let net_vq_core =
            virtio_driver::net::NetVirtQueue::new(vq_inner, tx_header_dma_base, tx_headers);

        Self {
            inner: IrqPoisonLock::new(net_vq_core),
            last_used_idx: AtomicU16::new(0),
            pending_wakers: crate::sync::WakerQueue::new(),
            dma_buffer,
            completion_map: PoisonLock::new(BTreeMap::new()),
        }
    }

    /// Notify the device that new buffers are available.
    pub fn notify(&self, transport: &dyn VirtioTransport) {
        if let Ok(inner) = self.inner.lock() {
            inner.vq.notify(transport);
        }
    }

    /// 送信バッファを追加
    pub fn add_tx_buffer(
        &self,
        header: &VirtioNetHeader,
        data: &[u8],
    ) -> Result<u16, VirtioNetError> {
        let inner = self.inner.lock().map_err(|_| VirtioNetError::DeviceError)?;
        unsafe { inner.add_tx_buffer(header, data.as_ptr() as u64, data.len()) }
    }

    /// ゼロコピー送信バッファを追加
    pub fn add_tx_buffer_zero_copy_with_header(
        &self,
        phys_addr: u64,
        data_len: usize,
        header: VirtioNetHeader,
    ) -> Result<u16, VirtioNetError> {
        let inner = self.inner.lock().map_err(|_| VirtioNetError::DeviceError)?;
        unsafe { inner.add_tx_buffer(&header, phys_addr, data_len) }
    }

    pub fn add_tx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        data_len: usize,
    ) -> Result<u16, VirtioNetError> {
        self.add_tx_buffer_zero_copy_with_header(phys_addr, data_len, VirtioNetHeader::new_tx())
    }

    /// 受信バッファを追加
    pub fn add_rx_buffer(&self, buffer: &mut [u8]) -> Result<u16, VirtioNetError> {
        let inner = self.inner.lock().map_err(|_| VirtioNetError::DeviceError)?;
        unsafe { inner.add_rx_buffer(buffer.as_ptr() as u64, buffer.len()) }
    }

    /// ゼロコピー受信バッファを追加
    pub fn add_rx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        buffer_len: usize,
    ) -> Result<u16, VirtioNetError> {
        let inner = self.inner.lock().map_err(|_| VirtioNetError::DeviceError)?;
        unsafe { inner.add_rx_buffer(phys_addr, buffer_len) }
    }

    /// 完了したバッファを処理
    pub fn process_used_with<F>(&self, mut on_complete: F) -> usize
    where
        F: FnMut(u16, u32),
    {
        let inner = match self.inner.lock() {
            Ok(guard) => guard,
            Err(_) => return 0,
        };

        let mut count = 0;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some((desc_idx, len)) = inner.vq.poll_complete() {
            self.completion_map
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(desc_idx, len);
            on_complete(desc_idx, len);
            count += 1;
        }

        if count > 0 {
            self.pending_wakers.wake_all();
        }

        count
    }

    pub fn process_used(&self) -> Vec<(u16, u32)> {
        let mut completed = Vec::new();
        let _ = self.process_used_with(|desc_idx, len| {
            completed.push((desc_idx, len));
        });
        completed
    }

    pub fn register_waker(&self, waker: core::task::Waker) {
        self.pending_wakers.register(&waker);
    }

    pub fn take_completion(&self, desc_idx: u16) -> Option<u32> {
        if let Some(len) = self
            .completion_map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&desc_idx)
        {
            return Some(len);
        }

        let _ = self.process_used();
        self.completion_map
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&desc_idx)
    }

    pub(crate) fn free_desc_chain(&self, head: u16) {
        if let Ok(inner) = self.inner.lock() {
            inner.vq.free_desc_chain(head);
        }
    }

    pub fn has_pending(&self) -> bool {
        if let Ok(inner) = self.inner.lock() {
            inner.vq.has_pending()
        } else {
            false
        }
    }
}
