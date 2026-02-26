// ============================================================================
// src/io/virtio/net.rs - VirtIO Network Device Driver
// 設計書 6.2: ネットワークスタック：真のゼロコピー
// 設計書 7.1: VirtIOドライバのRust実装
// ============================================================================
#![allow(dead_code)]


use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

// Import VirtIO common definitions
use super::defs::{VirtioDeviceType, status};
use super::transport::{TransportType, VirtioTransport};
use crate::io::dma::{
    allocate_iommu_bounce_bytes, iommu_align_len, CoherentDmaBuffer,
    DmaMemoryAttributes, IommuBounceAllocError,
};
use crate::io::iommu::api::{
    get_device_dma_mask, is_iommu_enabled, is_iommu_required, map_rref_slice_for_device,
    unmap_dma, unmap_for_device, DmaDirection, DmaHandle, map_for_device_with_perms,
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

    /// 単純な送信用ヘッダを作成
    pub fn new_tx() -> Self {
        Self::default()
    }
}

// ============================================================================
// VirtQueue for Network
// ============================================================================

/// VirtQueue ディスクリプタ
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VringDesc {
    /// バッファの物理アドレス
    pub addr: u64,
    /// バッファの長さ
    pub len: u32,
    /// フラグ
    pub flags: u16,
    /// 次のディスクリプタのインデックス
    pub next: u16,
}

impl VringDesc {
    /// 書き込み可能フラグ
    pub const VRING_DESC_F_WRITE: u16 = 2;
    /// 次のディスクリプタが続くフラグ
    pub const VRING_DESC_F_NEXT: u16 = 1;
}

/// VirtQueue Available Ring
#[repr(C)]
pub struct VringAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 256],
}

/// VirtQueue Used Ring Element
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VringUsedElem {
    pub id: u32,
    pub len: u32,
}

/// VirtQueue Used Ring
#[repr(C)]
pub struct VringUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VringUsedElem; 256],
}

// ============================================================================
// Send-safe pointer wrapper
// ============================================================================

/// 生ポインタをSend可能にするラッパー
///
/// # Safety
/// このラッパーを使う側が、ポインタの有効性とスレッド安全性を保証する必要がある
pub struct SendPtr<T>(*mut T);

unsafe impl<T> Send for SendPtr<T> {}
unsafe impl<T> Sync for SendPtr<T> {}

impl<T> SendPtr<T> {
    fn new(ptr: *mut T) -> Self {
        Self(ptr)
    }

    fn as_ptr(&self) -> *mut T {
        self.0
    }
}

impl<T> Clone for SendPtr<T> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<T> Copy for SendPtr<T> {}

/// ネットワーク VirtQueue
pub struct NetVirtQueue {
    /// キューインデックス (0=RX, 1=TX)
    pub index: u16,
    /// キューサイズ
    pub size: u16,
    /// ディスクリプタテーブル
    desc_table: SendPtr<VringDesc>,
    /// Available Ring
    avail_ring: SendPtr<VringAvail>,
    /// Used Ring
    used_ring: SendPtr<VringUsed>,
    /// Queue notify address (transport-provided)
    #[deprecated(since = "0.3.0", note = "Prefer transport-level notify methods and interrupt-driven notifications; avoid per-queue MMIO `notify_addr` when possible.")]
    notify_addr: Option<u64>,
    /// Notify width (MMIO uses 32-bit, PCI uses 16-bit)
    notify_is_32bit: bool,
    /// 最後に処理した Used インデックス
    last_used_idx: AtomicU16,
    /// 完了キャッシュのstale検知回数
    stale_completion_count: AtomicU64,
    /// 空きディスクリプタ (desc_id stack)
    free_descs: Mutex<Vec<u16>>,
    /// 割り込み待機中のWaker
    pending_wakers: Mutex<Vec<Waker>>,
    /// 完了済みディスクリプタの長さ (desc_id -> used len)
    pending_completions: Mutex<Vec<Option<u32>>>,
    /// DMA Buffer to keep memory alive
    dma_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
    /// Optional IOMMU mapping for queue memory
    iommu_map: Option<IommuMapping>,
    /// TX header table (one header per descriptor)
    tx_headers: Option<SendPtr<VirtioNetHeader>>,
    /// TX header table DMA base (IOVA or phys)
    tx_header_dma_base: Option<u64>,
}

// NetVirtQueueをSend/Syncにする
unsafe impl Send for NetVirtQueue {}
unsafe impl Sync for NetVirtQueue {}

pub struct IommuMapping {
    device: Option<IommuDeviceId>,
    iova: u64,
    len: usize,
    /// Optional DmaHandle for bounce-based mappings
    handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

impl NetVirtQueue {
    /// 新しいVirtQueueを作成
    ///
    /// # Safety
    /// desc_table, avail_ring, used_ring は有効なDMA可能メモリを指している必要がある
    #[allow(deprecated)]
    pub unsafe fn new(
        index: u16,
        size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
        dma_buffer: Option<crate::io::dma::CoherentDmaBuffer>,
        notify_addr: Option<u64>,
        notify_is_32bit: bool,
        iommu_map: Option<IommuMapping>,
        tx_headers: Option<SendPtr<VirtioNetHeader>>,
        tx_header_dma_base: Option<u64>,
    ) -> Self {
        // ペンディングバッファ配列を初期化
        let mut pending = Vec::with_capacity(size as usize);
        pending.resize_with(size as usize, || None);
        let mut free_descs = Vec::with_capacity(size as usize);
        for idx in (0..size).rev() {
            free_descs.push(idx);
        }

        Self {
            index,
            size,
            desc_table: SendPtr::new(desc_table),
            avail_ring: SendPtr::new(avail_ring),
            used_ring: SendPtr::new(used_ring),
            notify_addr,
            notify_is_32bit,
            last_used_idx: AtomicU16::new(0),
            stale_completion_count: AtomicU64::new(0),
            free_descs: Mutex::new(free_descs),
            pending_wakers: Mutex::new(Vec::new()),
            pending_completions: Mutex::new(pending),
            dma_buffer,
            iommu_map,
            tx_headers,
            tx_header_dma_base,
        }
    }

    /// ディスクリプタを割り当て
    fn alloc_desc(&self) -> Option<u16> {
        let idx = self.free_descs.lock().pop()?;
        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] alloc_desc -> {}\n", idx));
        self.clear_stale_completion(idx);
        Some(idx)
    }

    fn alloc_desc_pair(&self) -> Option<(u16, u16)> {
        let mut free_descs = self.free_descs.lock();
        let first = free_descs.pop()?;
        let second = match free_descs.pop() {
            Some(second) => second,
            None => {
                free_descs.push(first);
                return None;
            }
        };
        drop(free_descs);
        self.clear_stale_completion(first);
        self.clear_stale_completion(second);
        Some((first, second))
    }

    /// Notify the device that new buffers are available.
    #[allow(deprecated)]
    pub fn notify(&self) {
        let Some(addr) = self.notify_addr else {
            return;
        };

        log::info!(
            "[VIRTIO-NET] notify called for queue {} addr=0x{:x} is_32bit={}",
            self.index,
            addr,
            self.notify_is_32bit
        );
        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] notify called for queue {} addr=0x{:x} is_32bit={}\n", self.index, addr, self.notify_is_32bit));

        // Diagnostic: show avail and used indices and last ring slot
        unsafe {
            let avail = &*self.avail_ring.as_ptr();
            let used = &*self.used_ring.as_ptr();
            let last_slot = if avail.idx == 0 {
                avail.ring[(avail.idx % self.size) as usize]
            } else {
                avail.ring[((avail.idx.wrapping_sub(1)) % self.size) as usize]
            };
            crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] notify: avail_idx={} last_ring_slot={} used_idx=0x{:x}\n", avail.idx, last_slot, used.idx));
        }

        if self.notify_is_32bit {
            crate::io::mmio::mmio_write_u32(addr as usize, self.index as u32);
        } else {
            crate::io::mmio::mmio_write_u16(addr as usize, self.index);
        }
    }

    /// 送信バッファを追加
    pub fn add_tx_buffer(
        &self,
        header: &VirtioNetHeader,
        data: &[u8],
    ) -> Result<u16, VirtioNetError> {
        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] add_tx_buffer called data_ptr=0x{:x} len={}\n", data.as_ptr() as u64, data.len()));
        let (desc_idx, data_desc_idx) = self.alloc_desc_pair().ok_or(VirtioNetError::QueueFull)?;
        let (header_ptr, header_dma_base) = match (self.tx_headers, self.tx_header_dma_base) {
            (Some(ptr), Some(base)) => (ptr, base),
            _ => return Err(VirtioNetError::DeviceError),
        };

        unsafe {
            let header_slot = &mut *header_ptr.as_ptr().add(desc_idx as usize);
            *header_slot = *header;

            // ヘッダーディスクリプタ
            let desc = &mut *self.desc_table.as_ptr().add(desc_idx as usize);
            desc.addr = header_dma_base + (desc_idx as u64 * VirtioNetHeader::SIZE as u64);
            desc.len = VirtioNetHeader::SIZE as u32;
            desc.flags = VringDesc::VRING_DESC_F_NEXT;
            desc.next = data_desc_idx;

            // データーディスクリプタ
            let data_desc = &mut *self.desc_table.as_ptr().add(data_desc_idx as usize);
            data_desc.addr = data.as_ptr() as u64;
            data_desc.len = data.len() as u32;
            data_desc.flags = 0;
            data_desc.next = 0;

            // Available Ringに追加
            let avail = &mut *self.avail_ring.as_ptr();
            let avail_idx = avail.idx;
            avail.ring[(avail_idx % self.size) as usize] = desc_idx;

            // メモリバリア
            core::sync::atomic::fence(Ordering::Release);

            avail.idx = avail_idx.wrapping_add(1);
        }

        log::info!(
            "[VIRTIO-NET] add_tx desc {} data_ptr=0x{:x} len={}",
            desc_idx,
            data.as_ptr() as u64,
            data.len()
        );

        Ok(desc_idx)
    }

    /// ゼロコピー送信バッファを追加（設計書 6.2準拠）
    /// 物理アドレスを直接使用し、メモリコピーを回避
    pub fn add_tx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        data_len: usize,
    ) -> Result<u16, VirtioNetError> {
        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] add_tx_buffer_zero_copy called phys=0x{:x} len={}\n", phys_addr, data_len));
        let (desc_idx, data_desc_idx) = self.alloc_desc_pair().ok_or(VirtioNetError::QueueFull)?;
        let (header_ptr, header_dma_base) = match (self.tx_headers, self.tx_header_dma_base) {
            (Some(ptr), Some(base)) => (ptr, base),
            _ => return Err(VirtioNetError::DeviceError),
        };

        unsafe {
            let header = &mut *header_ptr.as_ptr().add(desc_idx as usize);
            *header = VirtioNetHeader::new_tx();

            // ヘッダーディスクリプタ
            let desc = &mut *self.desc_table.as_ptr().add(desc_idx as usize);
            desc.addr = header_dma_base + (desc_idx as u64 * VirtioNetHeader::SIZE as u64);
            desc.len = VirtioNetHeader::SIZE as u32;
            desc.flags = VringDesc::VRING_DESC_F_NEXT;
            desc.next = data_desc_idx;

            // データーディスクリプタ
            let data_desc = &mut *self.desc_table.as_ptr().add(data_desc_idx as usize);
            data_desc.addr = phys_addr;
            data_desc.len = data_len as u32;
            data_desc.flags = 0;
            data_desc.next = 0;

            crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] add_tx_zero preparing desc={} phys=0x{:x} len={}\n", desc_idx, phys_addr, data_len));

            // Available Ringに追加
            let avail = &mut *self.avail_ring.as_ptr();
            let avail_idx = avail.idx;
            // used idx for diagnostics
            let used_idx = (*self.used_ring.as_ptr()).idx;

            avail.ring[(avail_idx % self.size) as usize] = desc_idx;

            // メモリバリア
            core::sync::atomic::fence(Ordering::Release);

            avail.idx = avail_idx.wrapping_add(1);

            crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] add_tx_zero desc={} pre_avail_idx={} post_avail_idx={} ring_slot={} used_idx_before=0x{:x}\n", desc_idx, avail_idx, avail.idx, avail.ring[(avail_idx % self.size) as usize], used_idx));
        }

        log::info!(
            "[VIRTIO-NET] add_tx_zero desc {} phys=0x{:x} len={}",
            desc_idx,
            phys_addr,
            data_len
        );

        Ok(desc_idx)
    }

    /// 受信バッファを追加
    pub fn add_rx_buffer(&self, buffer: &mut [u8]) -> Result<u16, VirtioNetError> {
        let desc_idx = self.alloc_desc().ok_or(VirtioNetError::QueueFull)?;

        unsafe {
            // ディスクリプタを設定（書き込み可能）
            let desc = &mut *self.desc_table.as_ptr().add(desc_idx as usize);
            desc.addr = buffer.as_ptr() as u64;
            desc.len = buffer.len() as u32;
            desc.flags = VringDesc::VRING_DESC_F_WRITE;
            desc.next = 0;

            // Available Ringに追加
            let avail = &mut *self.avail_ring.as_ptr();
            let avail_idx = avail.idx;
            avail.ring[(avail_idx % self.size) as usize] = desc_idx;

            core::sync::atomic::fence(Ordering::Release);

            avail.idx = avail_idx.wrapping_add(1);
        }

        log::info!("[VIRTIO-NET] add_rx desc={} ptr=0x{:x} len={}", desc_idx, buffer.as_ptr() as u64, buffer.len());

        Ok(desc_idx)
    }

    /// ゼロコピー受信バッファを追加（設計書 6.2準拠）
    /// Mempool物理アドレスを直接使用
    pub fn add_rx_buffer_zero_copy(
        &self,
        phys_addr: u64,
        buffer_len: usize,
    ) -> Result<u16, VirtioNetError> {
        let desc_idx = self.alloc_desc().ok_or(VirtioNetError::QueueFull)?;

        unsafe {
            // ディスクリプタを設定（書き込み可能、物理アドレス直接使用）
            let desc = &mut *self.desc_table.as_ptr().add(desc_idx as usize);
            desc.addr = phys_addr;
            desc.len = buffer_len as u32;
            desc.flags = VringDesc::VRING_DESC_F_WRITE;
            desc.next = 0;

            // Available Ringに追加
            let avail = &mut *self.avail_ring.as_ptr();
            let avail_idx = avail.idx;
            avail.ring[(avail_idx % self.size) as usize] = desc_idx;

            core::sync::atomic::fence(Ordering::Release);

            avail.idx = avail_idx.wrapping_add(1);
        }

        log::info!("[VIRTIO-NET] add_rx_zero desc={} phys=0x{:x} len={}", desc_idx, phys_addr, buffer_len);

        Ok(desc_idx)
    }

    /// 完了したバッファを処理
    pub fn process_used(&self) -> Vec<(u16, u32)> {
        let mut completed = Vec::new();
        let _ = self.process_used_with(|desc_idx, len| {
            completed.push((desc_idx, len));
        });
        completed
    }

    pub fn process_used_count(&self) -> usize {
        self.process_used_with(|_, _| {})
    }

    fn process_used_with<F>(&self, mut on_complete: F) -> usize
    where
        F: FnMut(u16, u32),
    {
        let mut count = 0;
        let mut pending = self.pending_completions.lock();

        unsafe {
            let used = &*self.used_ring.as_ptr();
            let mut last_idx = self.last_used_idx.load(Ordering::Acquire);

            while last_idx != used.idx {
                let elem = &used.ring[(last_idx % self.size) as usize];
                let desc_idx = elem.id as u16;
                let len = elem.len;
                if let Some(slot) = pending.get_mut(desc_idx as usize) {
                    *slot = Some(len);
                }
                on_complete(desc_idx, len);
                count += 1;
                last_idx = last_idx.wrapping_add(1);
            }

            self.last_used_idx.store(last_idx, Ordering::Release);
        }

        drop(pending);

        if count > 0 {
            let wakers: Vec<Waker> = self.pending_wakers.lock().drain(..).collect();
            for waker in wakers {
                waker.wake();
            }
        }

        count
    }

    /// Wakerを登録
    pub fn register_waker(&self, waker: Waker) {
        self.pending_wakers.lock().push(waker);
    }

    pub fn take_completion(&self, desc_idx: u16) -> Option<u32> {
        {
            let mut pending = self.pending_completions.lock();
            if let Some(slot) = pending.get_mut(desc_idx as usize) {
                if let Some(len) = slot.take() {
                    drop(pending);
                    self.free_desc_chain(desc_idx);
                    return Some(len);
                }
            }
        }

        let used_idx = unsafe { (*self.used_ring.as_ptr()).idx };
        let last_idx = self.last_used_idx.load(Ordering::Acquire);
        if used_idx == last_idx {
            return None;
        }

        let _ = self.process_used_count();
        let mut pending = self.pending_completions.lock();
        let len = pending
            .get_mut(desc_idx as usize)
            .and_then(|slot| slot.take());
        drop(pending);
        if len.is_some() {
            self.free_desc_chain(desc_idx);
        }
        len
    }

    fn free_desc_chain(&self, head: u16) {
        let mut free_descs = self.free_descs.lock();
        let mut current = head;
        for _ in 0..self.size {
            if current >= self.size {
                break;
            }
            free_descs.push(current);
            let desc = unsafe { &*self.desc_table.as_ptr().add(current as usize) };
            if (desc.flags & VringDesc::VRING_DESC_F_NEXT) == 0 {
                break;
            }
            current = desc.next;
        }
    }

    fn clear_stale_completion(&self, desc_idx: u16) {
        let mut pending = self.pending_completions.lock();
        if let Some(slot) = pending.get_mut(desc_idx as usize) {
            if slot.is_some() {
                self.stale_completion_count
                    .fetch_add(1, Ordering::Relaxed);
                log::warn!(
                    "[VIRTIO-NET] stale completion detected for desc {}",
                    desc_idx
                );
                *slot = None;
            }
        }
    }

    pub fn stale_completion_count(&self) -> u64 {
        self.stale_completion_count.load(Ordering::Relaxed)
    }

    /// ペンディングバッファがあるかチェック
    pub fn has_pending(&self) -> bool {
        unsafe {
            let used = &*self.used_ring.as_ptr();
            let last_idx = self.last_used_idx.load(Ordering::Acquire);
            last_idx != used.idx
        }
    }
}
