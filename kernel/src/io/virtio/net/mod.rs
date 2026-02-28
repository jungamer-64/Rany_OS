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
use spin::MutexGuard;
use x86_64::{PhysAddr, VirtAddr};

// Import VirtIO common definitions
use crate::io::virtio::defs::{VirtioDeviceType, status};
use crate::io::virtio::transport::{TransportType, VirtioTransport};
use crate::io::virtio::virtqueue::{VirtQueue, VringAvail, VringDesc, VringUsed, vring_flags};
use crate::io::dma::{
    iommu_align_len, CoherentDmaBuffer,
    DmaMemoryAttributes,
};
use crate::sync::IrqPoisonLock;
use crate::io::iommu::api::{
    get_device_dma_mask, is_iommu_enabled, is_iommu_required,
    unmap_dma, unmap_for_device, map_for_device_with_perms,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
// Import PacketRef for zero-copy
use crate::net::mempool::PacketRef;

mod device_impl;
pub use device_impl::*;

// ============================================================================
// VirtIO Net Transport Helper Functions
// ============================================================================

/// トランスポートからMACアドレスを読み取り（Net device config space）
fn read_mac_address(transport: &dyn VirtioTransport) -> [u8; 6] {
    [
        transport.read_config_u8(0),
        transport.read_config_u8(1),
        transport.read_config_u8(2),
        transport.read_config_u8(3),
        transport.read_config_u8(4),
        transport.read_config_u8(5),
    ]
}

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
// VirtIO Net Device Feature Flags
// ============================================================================

pub mod features {
    /// デバイスはチェックサムオフロードをサポート
    pub const VIRTIO_NET_F_CSUM: u64 = 1 << 0;
    /// ゲストはチェックサムオフロードを使用可能
    pub const VIRTIO_NET_F_GUEST_CSUM: u64 = 1 << 1;
    /// MTU設定をサポート
    pub const VIRTIO_NET_F_MTU: u64 = 1 << 3;
    /// MACアドレスをサポート
    pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
    /// TCPセグメンテーションオフロード
    pub const VIRTIO_NET_F_GSO: u64 = 1 << 6;
    /// ゲストTSO4
    pub const VIRTIO_NET_F_GUEST_TSO4: u64 = 1 << 7;
    /// ゲストTSO6
    pub const VIRTIO_NET_F_GUEST_TSO6: u64 = 1 << 8;
    /// マルチキューサポート
    pub const VIRTIO_NET_F_MQ: u64 = 1 << 22;
    /// CTRL_VQサポート
    pub const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;
    /// 割り込み抑制
    pub const VIRTIO_NET_F_NOTIF_COAL: u64 = 1 << 52;
}

// ============================================================================
// VirtIO Net Header
// ============================================================================

/// VirtIO ネットワークヘッダ
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioNetHeader {
    /// フラグ
    pub flags: u8,
    /// GSOタイプ
    pub gso_type: u8,
    /// ヘッダ長
    pub hdr_len: u16,
    /// GSOサイズ
    pub gso_size: u16,
    /// チェックサム開始オフセット
    pub csum_start: u16,
    /// チェックサムオフセット
    pub csum_offset: u16,
    /// バッファ数（マルチバッファモード用）
    pub num_buffers: u16,
}

impl VirtioNetHeader {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    /// VIRTIO_NET_HDR_F_NEEDS_CSUM
    pub const F_NEEDS_CSUM: u8 = 1;
    /// VIRTIO_NET_HDR_GSO_TCPV4
    pub const GSO_TCPV4: u8 = 1;

    /// 単純な送信用ヘッダを作成
    pub fn new_tx() -> Self {
        Self::default()
    }

    /// チェックサムオフロードを有効化
    pub fn with_checksum_offload(mut self, start: u16, offset: u16) -> Self {
        self.flags |= Self::F_NEEDS_CSUM;
        self.csum_start = start;
        self.csum_offset = offset;
        self
    }

    /// TCPv4 GSOを有効化
    pub fn with_gso_tcpv4(mut self, hdr_len: u16, gso_size: u16) -> Self {
        self.gso_type = Self::GSO_TCPV4;
        self.hdr_len = hdr_len;
        self.gso_size = gso_size;
        self
    }
}

// ============================================================================
// VirtQueue for Network
// ============================================================================

// Redundant vring and descriptor definitions removed. Uses common definitions from virtqueue module.

// ============================================================================
// Send-safe pointer wrapper
// ============================================================================

// ============================================================================
// Internal Mutability and Synchronization
// ============================================================================

/// ネットワーク VirtQueue の送信/追加（Submission）側状態で、排他制御が必要なものをまとめた構造体
pub struct NetVirtQueueInner {
    /// ディスクリプタテーブル
    desc_table: *mut VringDesc,
    /// Available Ring
    avail_ring: *mut VringAvail,
    /// 空きディスクリプタ (desc_id stack)
    free_descs: Vec<u16>,
    /// TX header table (one header per descriptor)
    tx_headers: Option<*mut VirtioNetHeader>,
    /// TX header table DMA base (IOVA or phys)
    tx_header_dma_base: Option<u64>,
}

/// ネットワーク VirtQueue
#[derive(Debug)]
pub struct NetVirtQueue {
    /// VirtQueue core implementation (descriptor management, etc.)
    pub vq: IrqPoisonLock<VirtQueue>,
    /// TX header table (one header per descriptor)
    pub tx_headers: Option<*mut VirtioNetHeader>,
    /// TX header table DMA base (IOVA or phys)
    pub tx_header_dma_base: Option<u64>,
    /// 最後に処理した Used インデックス (Atomic for non-blocking poll)
    pub last_used_idx: AtomicU16,
    /// 割り込み待機中のWaker
    pub pending_wakers: IrqPoisonLock<Vec<Waker>>,
    /// 完了済みディスクリプタの長さ (desc_id -> used len)
    pub pending_completions: IrqPoisonLock<Vec<Option<u32>>>,
    /// Optional IOMMU mapping for queue memory
    pub iommu_map: Option<IommuMapping>,
}

// NetVirtQueueをSend/Syncにする
// SAFETY: Raw pointers are safely encapsulated. The `inner` state is protected by a Mutex,
// ensuring no data races or Rust aliasing rules are violated during queue submisson.
// The `used_ring` is read-only for the driver.
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
        let vq = VirtQueue::new(
            size,
            desc_table,
            avail_ring,
            used_ring,
            dma_buffer,
            index,
            features,
        );

        let mut pending = Vec::with_capacity(size as usize);
        pending.resize_with(size as usize, || None);

        Self {
            vq: IrqPoisonLock::new(vq),
            tx_headers,
            tx_header_dma_base,
            last_used_idx: AtomicU16::new(0),
            pending_wakers: IrqPoisonLock::new(Vec::new()),
            pending_completions: IrqPoisonLock::new(pending),
            iommu_map,
        }
    }

    /// ディスクリプタを割り当て
    fn alloc_desc(inner: &mut MutexGuard<NetVirtQueueInner>) -> Option<u16> {
        let idx = inner.free_descs.pop()?;
        Some(idx)
    }

    fn alloc_desc_pair(inner: &mut MutexGuard<NetVirtQueueInner>) -> Option<(u16, u16)> {
        let first = inner.free_descs.pop()?;
        let second = match inner.free_descs.pop() {
            Some(second) => second,
            None => {
                inner.free_descs.push(first);
                return None;
            }
        };
        Some((first, second))
    }

    /// Notify the device that new buffers are available.
    pub fn notify(&self, transport: &dyn VirtioTransport) {
        if let Ok(vq) = self.vq.lock() {
            vq.notify(transport);
        }
    }

    /// 送信バッファを追加
    pub fn add_tx_buffer(
        &self,
        header: &VirtioNetHeader,
        data: &[u8],
    ) -> Result<u16, VirtioNetError> {
        let mut vq_guard = self.vq.lock().map_err(|_| VirtioNetError::DeviceError)?;
        
        let desc_idx = vq_guard.alloc_desc().ok_or(VirtioNetError::QueueFull)?;
        let data_desc_idx = match vq_guard.alloc_desc() {
            Some(idx) => idx,
            None => {
                vq_guard.free_desc(desc_idx);
                return Err(VirtioNetError::QueueFull);
            }
        };

        let (header_ptr, header_dma_base) = match (self.tx_headers, self.tx_header_dma_base) {
            (Some(ptr), Some(base)) => (ptr, base),
            _ => {
                vq_guard.free_desc(data_desc_idx);
                vq_guard.free_desc(desc_idx);
                return Err(VirtioNetError::DeviceError);
            }
        };

        unsafe {
            let header_slot = &mut *header_ptr.add(desc_idx as usize);
            *header_slot = *header;

            let desc_table = vq_guard.desc_table.as_ptr();

            // ヘッダーディスクリプタ
            let desc_ptr = desc_table.add(desc_idx as usize);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).addr), header_dma_base + (desc_idx as u64 * VirtioNetHeader::SIZE as u64));
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).len), VirtioNetHeader::SIZE as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).flags), vring_flags::VRING_DESC_F_NEXT);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).next), data_desc_idx);

            // データーディスクリプタ
            let data_desc_ptr = desc_table.add(data_desc_idx as usize);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*data_desc_ptr).addr), data.as_ptr() as u64);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*data_desc_ptr).len), data.len() as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*data_desc_ptr).flags), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*data_desc_ptr).next), 0);

            vq_guard.submit(desc_idx);
        }

        Ok(desc_idx)
    }

    /// ゼロコピー送信バッファを追加
    pub fn add_tx_buffer_zero_copy_with_header(
        &self,
        phys_addr: u64,
        data_len: usize,
        header: VirtioNetHeader,
    ) -> Result<u16, VirtioNetError> {
        let mut vq_guard = self.vq.lock().map_err(|_| VirtioNetError::DeviceError)?;
        
        let desc_idx = vq_guard.alloc_desc().ok_or(VirtioNetError::QueueFull)?;
        let data_desc_idx = match vq_guard.alloc_desc() {
            Some(idx) => idx,
            None => {
                vq_guard.free_desc(desc_idx);
                return Err(VirtioNetError::QueueFull);
            }
        };

        let (header_ptr, header_dma_base) = match (self.tx_headers, self.tx_header_dma_base) {
            (Some(ptr), Some(base)) => (ptr, base),
            _ => {
                vq_guard.free_desc(data_desc_idx);
                vq_guard.free_desc(desc_idx);
                return Err(VirtioNetError::DeviceError);
            }
        };

        unsafe {
            let header_slot = &mut *header_ptr.add(desc_idx as usize);
            *header_slot = header;

            let desc_table = vq_guard.desc_table.as_ptr();

            // ヘッダーディスクリプタ
            let desc_ptr = desc_table.add(desc_idx as usize);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).addr), header_dma_base + (desc_idx as u64 * VirtioNetHeader::SIZE as u64));
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).len), VirtioNetHeader::SIZE as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).flags), vring_flags::VRING_DESC_F_NEXT);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).next), data_desc_idx);

            // データーディスクリプタ
            let data_desc_ptr = desc_table.add(data_desc_idx as usize);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*data_desc_ptr).addr), phys_addr);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*data_desc_ptr).len), data_len as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*data_desc_ptr).flags), 0);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*data_desc_ptr).next), 0);

            vq_guard.submit(desc_idx);
        }

        Ok(desc_idx)
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
        let mut vq_guard = self.vq.lock().map_err(|_| VirtioNetError::DeviceError)?;
        let desc_idx = vq_guard.alloc_desc().ok_or(VirtioNetError::QueueFull)?;

        unsafe {
            let desc_ptr = vq_guard.desc_table.as_ptr().add(desc_idx as usize);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).addr), buffer.as_ptr() as u64);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).len), buffer.len() as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).flags), vring_flags::VRING_DESC_F_WRITE);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).next), 0);

            vq_guard.submit(desc_idx);
        }

        Ok(desc_idx)
    }

    /// ゼロコピー受信バッファを追加
    pub fn add_rx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        buffer_len: usize,
    ) -> Result<u16, VirtioNetError> {
        let mut vq_guard = self.vq.lock().map_err(|_| VirtioNetError::DeviceError)?;
        let desc_idx = vq_guard.alloc_desc().ok_or(VirtioNetError::QueueFull)?;

        unsafe {
            let desc_ptr = vq_guard.desc_table.as_ptr().add(desc_idx as usize);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).addr), phys_addr);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).len), buffer_len as u32);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).flags), vring_flags::VRING_DESC_F_WRITE);
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*desc_ptr).next), 0);

            vq_guard.submit(desc_idx);
        }

        Ok(desc_idx)
    }

    /// 完了したバッファを処理
    pub fn process_used_with<F>(&self, mut on_complete: F) -> usize
    where
        F: FnMut(u16, u32),
    {
        let mut vq_guard = match self.vq.lock() {
            Ok(guard) => guard,
            Err(_) => return 0,
        };

        let count = vq_guard.poll_completions(|desc_idx, len| {
            if let Ok(mut pending) = self.pending_completions.lock() {
                if let Some(slot) = pending.get_mut(desc_idx as usize) {
                    *slot = Some(len);
                }
            }
            on_complete(desc_idx, len);
        });

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
        if let Ok(vq) = self.vq.lock() {
            if let Ok(list) = vq.free_list.lock() {
                return list.len();
            }
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
            let len = pending.get_mut(desc_idx as usize).and_then(|slot| slot.take());
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
        if let Ok(vq) = self.vq.lock() {
            let mut current = head;
            let size = vq.queue_size;
            let desc_table = vq.desc_table.as_ptr();

            for _ in 0..size {
                if current >= size {
                    break;
                }
                let desc = unsafe { &*desc_table.add(current as usize) };
                let next = desc.next;
                let flags = desc.flags;
                
                vq.free_desc(current);
                
                if (flags & vring_flags::VRING_DESC_F_NEXT) == 0 {
                    break;
                }
                current = next;
            }
        }
    }

    pub fn has_pending(&self) -> bool {
        if let Ok(vq) = self.vq.lock() {
             vq.has_pending()
        } else {
            false
        }
    }
}
