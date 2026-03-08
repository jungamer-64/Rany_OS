// ============================================================================
// src/io/virtio/net.rs - VirtIO Network Device Driver
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// 設計書 7.1: VirtIOドライバのRust実装
// ============================================================================
#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use core::task::{Context, Poll, Waker};
use x86_64::{PhysAddr, VirtAddr};

// Import VirtIO common definitions
use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes, iommu_align_len};
use crate::io::iommu::api::{
    get_device_dma_mask, is_iommu_enabled, is_iommu_required, map_for_device_with_perms, unmap_dma,
    unmap_for_device,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::defs::{VirtioDeviceType, status};
use crate::io::virtio::transport::{TransportType, VirtioTransport};
use crate::io::virtio::virtqueue::{VirtQueue, VringAvail, VringDesc, VringUsed};
use crate::sync::IrqPoisonLock;
// Import PacketRef for zero-copy
use crate::net::datapath::mempool::PacketRef;
pub use virtio_driver::net::{
    NetDmaPurpose, NetRuntime, VirtioNetConfig, VirtioNetError, VirtioNetHeader, VirtioNetStats,
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

use crate::util::align_up_usize as align_up;

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
    let result = match device {
        Some(device) => unmap_for_device(&device, iova, len as u64),
        None => unmap_dma(iova, len as u64),
    };
    if let Err(err) = result {
        log::warn!("[VIRTIO-NET] failed to unmap DMA buffer: {:?}", err);
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
    pub pending_wakers: IrqPoisonLock<Vec<Waker>>,
    /// 完了済みディスクリプタの長さ (desc_id -> used len)
    pub pending_completions: IrqPoisonLock<Vec<Option<u32>>>,
    /// Optional IOMMU mapping for queue memory
    pub iommu_map: Option<IommuMapping>,
    /// DMA Buffer to keep memory alive (Shared logic doesn't hold this)
    pub dma_buffer: Option<CoherentDmaBuffer>,
}

// NetVirtQueueをSend/Syncにする
unsafe impl Send for NetVirtQueue {}
unsafe impl Sync for NetVirtQueue {}

#[derive(Debug)]
pub struct IommuMapping {
    device: Option<IommuDeviceId>,
    iova: u64,
    len: usize,
    /// Optional DmaHandle for bounce-based mappings
    handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

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
        iommu_map: Option<IommuMapping>,
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
        ).expect("[VIRTIO-NET] failed to init core virtqueue");

        let net_vq_core = virtio_driver::net::NetVirtQueue::new(
            vq_inner,
            tx_header_dma_base,
            tx_headers,
        );

        let mut pending = Vec::with_capacity(size as usize);
        pending.resize_with(size as usize, || None);

        Self {
            inner: IrqPoisonLock::new(net_vq_core),
            last_used_idx: AtomicU16::new(0),
            pending_wakers: IrqPoisonLock::new(Vec::new()),
            pending_completions: IrqPoisonLock::new(pending),
            iommu_map,
            dma_buffer,
        }
    }

    /// Notify the device that new buffers are available.
    pub fn notify(&self, transport: &dyn VirtioTransport) {
        if let Ok(inner) = self.inner.lock() {
            unsafe { inner.vq.notify(transport); }
        }
    }

    /// 送信バッファを追加
    pub fn add_tx_buffer(
        &self,
        header: &VirtioNetHeader,
        data: &[u8],
    ) -> Result<u16, VirtioNetError> {
        let inner = self.inner.lock().map_err(|_| VirtioNetError::DeviceError)?;
        unsafe {
            inner.add_tx_buffer(header, data.as_ptr() as u64, data.len())
        }
    }

    /// ゼロコピー送信バッファを追加
    pub fn add_tx_buffer_zero_copy_with_header(
        &self,
        phys_addr: u64,
        data_len: usize,
        header: VirtioNetHeader,
    ) -> Result<u16, VirtioNetError> {
        let inner = self.inner.lock().map_err(|_| VirtioNetError::DeviceError)?;
        unsafe {
            inner.add_tx_buffer(&header, phys_addr, data_len)
        }
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
        unsafe {
            inner.add_rx_buffer(buffer.as_ptr() as u64, buffer.len())
        }
    }

    /// ゼロコピー受信バッファを追加
    pub fn add_rx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        buffer_len: usize,
    ) -> Result<u16, VirtioNetError> {
        let inner = self.inner.lock().map_err(|_| VirtioNetError::DeviceError)?;
        unsafe {
            inner.add_rx_buffer(phys_addr, buffer_len)
        }
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
        while let Some((desc_idx, len)) = inner.vq.poll_complete() {
            if let Ok(mut pending) = self.pending_completions.lock() {
                if let Some(slot) = pending.get_mut(desc_idx as usize) {
                    *slot = Some(len);
                }
            }
            on_complete(desc_idx, len);
            count += 1;
        }

        if count > 0 {
            if let Ok(mut wakers) = self.pending_wakers.lock() {
                for waker in wakers.drain(..) {
                    waker.wake();
                }
            }
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

    /// Wakerを登録
    pub fn register_waker(&self, waker: Waker) {
        if let Ok(mut wakers) = self.pending_wakers.lock() {
            wakers.push(waker);
        }
    }

    /// 利用可能なディスクリプタ数を取得
    pub fn available_descriptors(&self) -> usize {
        if let Ok(inner) = self.inner.lock() {
            return inner.vq.free_count() as usize;
        }
        0
    }

    /// ポリングで完了を確認
    pub fn take_completion(&self, desc_idx: u16) -> Option<u32> {
        if let Ok(mut pending) = self.pending_completions.lock() {
            if let Some(slot) = pending.get_mut(desc_idx as usize) {
                if let Some(len) = slot.take() {
                    drop(pending);
                    self.free_desc_chain(desc_idx);
                    return Some(len);
                }
            }
        }

        let _ = self.process_used_with(|_, _| {});

        if let Ok(mut pending) = self.pending_completions.lock() {
            let len = pending
                .get_mut(desc_idx as usize)
                .and_then(|slot| slot.take());
            if len.is_some() {
                drop(pending);
                self.free_desc_chain(desc_idx);
            }
            len
        } else {
            None
        }
    }

    fn free_desc_chain(&self, head: u16) {
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
