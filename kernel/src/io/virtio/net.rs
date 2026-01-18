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
    allocate_iommu_bounce_bytes, iommu_align_len, CoherentDmaBuffer, CpuOwned, DeviceOwned,
    DmaMemoryAttributes, IommuBounceAllocError, SliceDmaGuard, TypedDmaSlice,
};
use crate::io::iommu::api::{
    get_device_dma_mask, is_iommu_enabled, is_iommu_required, map_rref_slice_for_device,
    unmap_dma, unmap_for_device, DmaDirection, DmaHandle,
};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::io_scheduler::{DeviceId, IoRequestId, IoResult, PollHandler, hybrid_coordinator};
// Import PacketRef for zero-copy
use crate::net::mempool::PacketRef;

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

fn align_up(value: usize, align: usize) -> usize {
    if align.is_power_of_two() {
        (value + align - 1) & !(align - 1)
    } else {
        value
    }
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

impl Drop for NetVirtQueue {
    fn drop(&mut self) {
        if let Some(map) = self.iommu_map.take() {
            // Prefer DmaHandle unmap if available
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

/// VirtIO ネットワークデバイス設定
#[derive(Debug, Clone)]
pub struct VirtioNetConfig {
    /// MACアドレス
    pub mac: [u8; 6],
    /// 最大キュー数
    pub max_queues: u16,
    /// MTU
    pub mtu: u16,
}

impl Default for VirtioNetConfig {
    fn default() -> Self {
        Self {
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], // QEMU default
            max_queues: 1,
            mtu: 1500,
        }
    }
}

/// In-flight entry for a zero-copy TX packet. Holds cleanup handles for unmapping when completed.
struct TxPacketInflight {
    packet: crate::net::PacketRef,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
    dma_iova: Option<u64>,
    dma_len: usize,
}

/// VirtIO ネットワークデバイス
pub struct VirtioNetDevice {
    /// トランスポート層（MMIO/PCI共通インターフェース）
    transport: Box<dyn VirtioTransport>,
    /// 設定
    config: VirtioNetConfig,
    /// Optional IOMMU device identifier for device-scoped mappings
    iommu_device_id: Option<IommuDeviceId>,
    /// 受信キュー
    rx_queue: Option<NetVirtQueue>,
    /// 送信キュー
    tx_queue: Option<NetVirtQueue>,
    /// 初期化済みフラグ
    initialized: AtomicBool,
    /// 統計: 送信パケット数
    tx_packets: AtomicU32,
    /// 統計: 受信パケット数
    rx_packets: AtomicU32,
    /// 統計: 送信バイト数
    tx_bytes: AtomicU32,
    /// 統計: 受信バイト数
    rx_bytes: AtomicU32,
    /// 受信用バッファマップ (desc_idx -> VirtioNetRxDmaBuffer)
    rx_buffers: Mutex<BTreeMap<u16, VirtioNetRxDmaBuffer>>,
    /// 受信用バッファマップ (desc_idx -> PacketRef) - zero-copy posted buffers from mempool
    rx_packetrefs: Mutex<BTreeMap<u16, crate::net::PacketRef>>,
    /// 送信用 PacketRef インフライトマップ (desc_idx -> TxPacketInflight)
    tx_packetrefs: Mutex<BTreeMap<u16, TxPacketInflight>>,
    /// 送信用インフライトバッファ (desc_idx -> CoherentDmaBuffer)
    tx_inflight: Mutex<BTreeMap<u16, CoherentDmaBuffer>>,
}

impl VirtioNetDevice {
    /// 新しいデバイスを作成
    ///
    /// # Arguments
    /// * `transport` - 初期化済みの VirtioTransport 実装（MMIO または PCI）
    ///   トランスポートはmagic/version検証を通過している必要がある
    pub fn new(transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_device(transport, None)
    }

    /// 新しいデバイスを作成（IOMMUデバイスIDを指定）
    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self {
            transport,
            config: VirtioNetConfig {
                mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
                max_queues: 1,
                mtu: 1500,
            },
            iommu_device_id,
            rx_queue: None,
            tx_queue: None,
            initialized: AtomicBool::new(false),
            tx_packets: AtomicU32::new(0),
            rx_packets: AtomicU32::new(0),
            tx_bytes: AtomicU32::new(0),
            rx_bytes: AtomicU32::new(0),
            rx_buffers: Mutex::new(BTreeMap::new()),
            rx_packetrefs: Mutex::new(BTreeMap::new()),
            tx_packetrefs: Mutex::new(BTreeMap::new()),
            tx_inflight: Mutex::new(BTreeMap::new()),
        }
    }

    /// デバイスを初期化
    pub fn init(&mut self) -> Result<(), VirtioNetError> {
        // 1. デバイスタイプ確認（トランスポートはすでにmagic/version検証済み）
        if self.transport.device_type() != VirtioDeviceType::Network {
            return Err(VirtioNetError::DeviceError);
        }

        // 2. デバイスリセット
        self.transport.reset();

        // 3. ACKNOWLEDGE ステータスビットを設定
        self.transport.set_status(status::VIRTIO_STATUS_ACKNOWLEDGE);

        // 4. DRIVER ステータスビットを設定
        self.transport
            .set_status(status::VIRTIO_STATUS_ACKNOWLEDGE | status::VIRTIO_STATUS_DRIVER);

        // 5. Feature negotiation
        let device_features_low = self.transport.get_device_features_low();
        let device_features_high = self.transport.get_device_features_high();

        // 必要なフィーチャーのみを受け入れる
        let accepted_features_low = device_features_low
            & (features::VIRTIO_NET_F_MAC as u32 | features::VIRTIO_NET_F_CSUM as u32);
        let accepted_features_high = device_features_high;

        self.transport
            .set_driver_features_low(accepted_features_low);
        self.transport
            .set_driver_features_high(accepted_features_high);

        // 6. FEATURES_OK を設定
        self.transport.set_status(
            status::VIRTIO_STATUS_ACKNOWLEDGE
                | status::VIRTIO_STATUS_DRIVER
                | status::VIRTIO_STATUS_FEATURES_OK,
        );

        // FEATURES_OK が設定されたか確認
        if (self.transport.get_status() & status::VIRTIO_STATUS_FEATURES_OK) == 0 {
            self.transport.set_status(status::VIRTIO_STATUS_FAILED);
            return Err(VirtioNetError::DeviceError);
        }

        // 7. MACアドレスを読み取り
        if (accepted_features_low & features::VIRTIO_NET_F_MAC as u32) != 0 {
            self.config.mac = read_mac_address(self.transport.as_ref());
        }

        // 8. キューの設定
        self.setup_queues()?;

        // 9. DRIVER_OK を設定
        self.transport.set_status(
            status::VIRTIO_STATUS_ACKNOWLEDGE
                | status::VIRTIO_STATUS_DRIVER
                | status::VIRTIO_STATUS_FEATURES_OK
                | status::VIRTIO_STATUS_DRIVER_OK,
        );

        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    /// VirtQueueを設定
    fn setup_queues(&mut self) -> Result<(), VirtioNetError> {
        // RX queue (queue 0)
        self.setup_single_queue(0)?;

        // TX queue (queue 1)
        self.setup_single_queue(1)?;

        Ok(())
    }

    /// 単一のキューを設定
    fn setup_single_queue(&mut self, queue_index: u16) -> Result<(), VirtioNetError> {
        // キューを選択
        self.transport.select_queue(queue_index);

        // 最大キューサイズを取得
        let max_size = self.transport.get_queue_max_size();
        if max_size == 0 {
            return Err(VirtioNetError::DeviceError);
        }

        // キューサイズを設定（最大256エントリに制限）
        let queue_size = max_size.min(256);
        self.transport.set_queue_size(queue_size);

        // メモリをアロケート（DmaAllocatorを使用）
        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize;
        let used_size = 6 + 8 * queue_size as usize;

        // Ensure the used Ring is aligned to a 4-byte boundary per VirtIO requirements
        let used_align = core::mem::align_of::<VringUsed>();
        let used_offset = align_up(desc_size + avail_size, used_align);

        let header_align = core::mem::align_of::<VirtioNetHeader>();
        let header_stride = VirtioNetHeader::SIZE;
        let header_offset = align_up(used_offset + used_size, header_align);
        let header_size = header_stride * queue_size as usize;
        let total_size = if queue_index == 1 {
            header_offset + header_size
        } else {
            used_offset + used_size
        };

        if is_iommu_required() && !is_iommu_enabled() {
            return Err(VirtioNetError::DeviceError);
        }

        let (buffer, dma_len) = if is_iommu_enabled() {
            let aligned_len = iommu_align_len(total_size).ok_or(VirtioNetError::DeviceError)?;
            let buffer = crate::io::dma::CoherentDmaBuffer::new(
                aligned_len,
                crate::io::dma::DmaMemoryAttributes::MMIO,
            )
            .ok_or(VirtioNetError::DeviceError)?;
            (buffer, aligned_len)
        } else {
            let buffer = crate::io::dma::CoherentDmaBuffer::new(
                total_size,
                crate::io::dma::DmaMemoryAttributes::MMIO,
            )
            .ok_or(VirtioNetError::DeviceError)?;
            (buffer, total_size)
        };

        let phys_base = buffer.phys_addr().as_u64();
        let ptr = unsafe { buffer.as_slice().as_ptr() } as *mut u8;

        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(desc_size) as *mut VringAvail };
        let used_ring = unsafe { ptr.add(used_offset) as *mut VringUsed };
        let notify_addr = self.transport.get_notify_addr(queue_index);
        let notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);
        let (dma_base, iommu_map) = if is_iommu_enabled() {
            // Allocate a page-aligned bounce buffer and map it via DmaHandle to avoid raw API usage
            let mut rref = match crate::io::dma::allocate_iommu_bounce_bytes(dma_len) {
                Ok(r) => r,
                Err(_) => return Err(VirtioNetError::DeviceError),
            };
            // Copy initial contents from the coherent buffer into the bounce buffer
            let src = unsafe { buffer.as_slice() };
            rref[..dma_len].copy_from_slice(&src[..dma_len]);

            let handle = match self.iommu_device_id {
                Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::Bidirectional),
                None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::Bidirectional),
            }
            .map_err(|_| VirtioNetError::DeviceError)?;

            let iova = handle.iova();
            (
                iova,
                Some(IommuMapping {
                    device: self.iommu_device_id,
                    iova,
                    len: dma_len,
                    handle: Some(handle),
                }),
            )
        } else {
            (phys_base, None)
        };

        let (tx_headers, tx_header_dma_base) = if queue_index == 1 {
            let header_ptr = unsafe { ptr.add(header_offset) as *mut VirtioNetHeader };
            let header_dma_base = dma_base + header_offset as u64;
            (Some(SendPtr::new(header_ptr)), Some(header_dma_base))
        } else {
            (None, None)
        };

        // 各リングを初期化
        for i in 0..queue_size {
            unsafe {
                (*desc_table.add(i as usize)) = VringDesc::default();
            }
        }
        unsafe {
            (*avail_ring).flags = 0;
            (*avail_ring).idx = 0;
            (*used_ring).flags = 0;
            (*used_ring).idx = 0;
        }
        if let Some(header_ptr) = tx_headers {
            for i in 0..queue_size {
                unsafe {
                    *header_ptr.as_ptr().add(i as usize) = VirtioNetHeader::default();
                }
            }
        }

        // デバイスにアドレスを設定
        let desc_addr = dma_base;
        let avail_addr = dma_base + desc_size as u64;
        let used_addr = dma_base + used_offset as u64;

        crate::io::log::early_print(&alloc::format!(
            "[EARLY][VIRTIO-NET] queue {}: dma_base=0x{:x} desc_size={} avail_size={} used_offset={} used_addr=0x{:x} used_size={}\n",
            queue_index,
            dma_base,
            desc_size,
            avail_size,
            used_offset,
            used_addr,
            used_size
        ));

        self.transport.set_queue_desc_addr(desc_addr);
        self.transport.set_queue_avail_addr(avail_addr);
        self.transport.set_queue_used_addr(used_addr);

        crate::io::log::early_print(&alloc::format!(
            "[EARLY][VIRTIO-NET] set_queue_desc_addr=0x{:x} avail_addr=0x{:x} used_addr=0x{:x}\n",
            desc_addr,
            avail_addr,
            used_addr
        ));

        // キューを作成
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
            )
        };

        if queue_index == 0 {
            self.rx_queue = Some(queue);

            // Pre-allocate and post several RX DMA buffers to the queue
            // so that we can receive packets without a separate async task.
            if let Some(ref rxq) = self.rx_queue {
                let mut added = 0usize;
                for _ in 0..8 {
                    // Prefer allocating PacketRef and posting it for true zero-copy
                    if let Some(packet) = crate::net::mempool::alloc_packet() {
                        let phys = packet.phys_addr().as_u64();
                        let buf_len = packet.capacity();
                        match rxq.add_rx_buffer_zero_copy(phys, buf_len) {
                            Ok(desc_idx) => {
                                log::info!(
                                    "[VIRTIO-NET] posted RX PacketRef desc={} phys=0x{:x} len={}",
                                    desc_idx,
                                    phys,
                                    buf_len
                                );
                                self.rx_packetrefs.lock().insert(desc_idx, packet);
                                added += 1;
                                continue;
                            }
                            Err(e) => {
                                log::warn!("[VIRTIO-NET] failed to post PacketRef rx buffer: {:?}", e);
                                // Fall through to allocate a VirtioNetRxDmaBuffer
                            }
                        }
                    }

                    // Fallback to legacy VirtioNetRxDmaBuffer allocation
                    if let Some(mut vbuf) = VirtioNetRxDmaBuffer::new() {
                        match vbuf.start_receive() {
                            Ok(phys) => {
                                let buf_len = vbuf.alloc_size;
                                match rxq.add_rx_buffer_zero_copy(phys, buf_len) {
                                    Ok(desc_idx) => {
                                        log::info!(
                                            "[VIRTIO-NET] posted RX desc={} phys=0x{:x} len={}",
                                            desc_idx,
                                            phys,
                                            buf_len
                                        );
                                        self.rx_buffers.lock().insert(desc_idx, vbuf);
                                        added += 1;
                                    }
                                    Err(e) => {
                                        log::warn!("[VIRTIO-NET] failed to add rx buffer: {:?}", e);
                                        // Drop vbuf and continue
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!("[VIRTIO-NET] failed to start rx buffer: {}", e);
                            }
                        }
                    } else {
                        log::warn!("[VIRTIO-NET] failed to allocate rx buffer");
                        break;
                    }
                }
                log::info!("[VIRTIO-NET] posted {} initial RX buffers", added);
            }
        } else {
            self.tx_queue = Some(queue);
        }
        self.transport.enable_queue();

        Ok(())
    }

    /// デバイスに通知（キュー更新）
    pub fn notify(&mut self, queue_index: u16) {
        self.transport.notify_queue(queue_index);
    }

    /// Submit a transmit packet synchronously by copying into a coherent DMA buffer and
    /// adding it to the TX queue. The buffer is retained in `tx_inflight` until completion
    /// and freed in the interrupt handler.
    pub fn submit_tx(&self, data: &[u8]) -> Result<(), VirtioNetError> {
        let data_len = data.len();
        crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] submit_tx called len={}\n", data_len));
        if data_len >= 14 {
            log::info!(
                "[NET-TX] submit_tx len={} dst={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                data_len,
                data[0],
                data[1],
                data[2],
                data[3],
                data[4],
                data[5]
            );
        } else {
            log::info!("[NET-TX] submit_tx len={}", data_len);
        }
        let mut buffer = crate::io::dma::CoherentDmaBuffer::new(
            data_len,
            crate::io::dma::DmaMemoryAttributes::MMIO,
        )
        .ok_or(VirtioNetError::DeviceError)?;

        // Copy payload into the DMA buffer
        let dst = unsafe { buffer.as_mut_slice() };
        if dst.len() < data_len {
            return Err(VirtioNetError::BufferTooSmall);
        }
        dst[..data_len].copy_from_slice(data);

        if let Some(ref tx_queue) = self.tx_queue {
            let phys = buffer.phys_addr().as_u64();
            crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] about to call add_tx_buffer_zero_copy phys=0x{:x} len={}\n", phys, data_len));
            match tx_queue.add_tx_buffer_zero_copy(phys, data_len) {
                Ok(desc_idx) => {
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] add_tx_buffer_zero_copy returned desc={}\n", desc_idx));
                    self.tx_inflight.lock().insert(desc_idx, buffer);
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] queued desc={} phys=0x{:x} len={}\n", desc_idx, phys, data_len));
                    log::info!("[NET-TX] queued desc={} phys=0x{:x} len={}", desc_idx, phys, data_len);
                    // Diagnostic: read device status/features before notifying
                    let dev_status = self.transport.get_status();
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] transport.get_status()=0x{:x}\n", dev_status));
                    let dev_features = self.transport.get_device_features();
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] transport.get_device_features()=0x{:x}\n", dev_features));

                    tx_queue.notify();
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] notify called for queue={}\n", tx_queue.index));

                    // Diagnostic: check device interrupt status and process used ring immediately
                    let intr_status = self.transport.get_interrupt_status();
                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] transport.get_interrupt_status()=0x{:x}\n", intr_status));

                    if let Some(ref txq) = self.tx_queue {
                        let completions = txq.process_used();
                        if !completions.is_empty() {
                            crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] post-notify found {} completions\n", completions.len()));
                            for (didx, len) in completions {
                                crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] completion desc={} len={}\n", didx, len));
                                if let Some(_buf) = self.tx_inflight.lock().remove(&didx) {
                                    crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] TX-COMP freed buffer for desc={} len={}\n", didx, len));
                                } else {
                                    crate::io::log::early_print(&alloc::format!("[EARLY][NET-TX] TX completion for unknown desc {}\n", didx));
                                }
                            }
                        } else {
                            crate::io::log::early_print("[EARLY][NET-TX] no completions found after notify\n");
                        }
                    }

                    log::info!("[NET-TX] notify called for queue={}", tx_queue.index);
                    Ok(())
                }
                Err(e) => {
                    log::warn!("[NET-TX] failed to add tx buffer: {:?}", e);
                    Err(e)
                }
            }
        } else {
            log::warn!("[NET-TX] device not initialized");
            Err(VirtioNetError::NotInitialized)
        }
    }

    /// パケットを送信（非同期）
    pub fn send_async(&self, data: &[u8]) -> SendFuture<'_> {
        SendFuture {
            device: self,
            data: data.as_ptr(),
            len: data.len(),
            submitted: false,
            desc_idx: 0,
            dma_len: 0,
            dma_iova: None,
            bounce_handle: None,
        }
    }

    /// ゼロコピーパケット送信（設計書 6.2準拠）
    ///
    /// PacketRefを直接使用し、コピーなしでDMAバッファに渡す。
    /// 送信完了まで所有権を保持し、完了後に自動解放される。
    pub fn send_zero_copy(&self, packet: PacketRef) -> ZeroCopySendFuture<'_> {
        ZeroCopySendFuture {
            device: self,
            packet: Some(packet),
            submitted: false,
            desc_idx: 0,
            dma_len: 0,
            dma_iova: None,
            bounce_handle: None,
        }
    }

    /// Enqueue a zero-copy PacketRef for transmission without waiting for completion.
    /// Ownership of `packet` is moved into the device's inflight map; completion will
    /// perform unmap/cleanup and return the buffer to the pool.
    pub fn enqueue_send_zero_copy(&self, packet: crate::net::PacketRef) -> Result<(), VirtioNetError> {
        // Prepare addresses and mapping similar to ZeroCopySendFuture::poll submission
        if let Some(ref tx_queue) = self.tx_queue {
            let data = packet.data();
            let phys_addr = packet.phys_addr();
            let data_len = core::mem::size_of::<VirtioNetHeader>() + data.len();
            let phys_addr_val = phys_addr.as_u64();
            let page_mask = (crate::mm::PAGE_SIZE_4K as u64) - 1;
            let page_base = phys_addr_val & !page_mask;
            let page_offset = (phys_addr_val - page_base) as usize;
            let map_len = crate::mm::PAGE_SIZE_4K;
            let can_map_page = page_offset + data_len <= map_len;

            let mut dma_addr = phys_addr_val;
            let mapped_iova: Option<u64> = None;
            let mut mapped_len = 0usize;
            let mut bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>> = None;

            if is_iommu_enabled() {
                if !can_map_page {
                    let mut rref = match allocate_iommu_bounce_bytes(data_len).map_err(|err| match err {
                        IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                        IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                    }) {
                        Ok(rref) => rref,
                        Err(err) => return Err(err),
                    };
                    if data_len > 0 {
                        rref[..data_len].fill(0);
                        let copy_len = core::cmp::min(data.len(), data_len);
                        rref[..copy_len].copy_from_slice(&data[..copy_len]);
                    }

                    let handle = match self.iommu_device_id {
                        Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice),
                        None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
                    }
                    .map_err(|_| VirtioNetError::DeviceError)?;
                    dma_addr = handle.iova();
                    bounce_handle = Some(handle);
                } else {
                    let mut rref = match allocate_iommu_bounce_bytes(map_len).map_err(|err| match err {
                        IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                        IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                    }) {
                        Ok(rref) => rref,
                        Err(err) => return Err(err),
                    };

                    if data_len > 0 {
                        rref[page_offset..page_offset + data_len].fill(0);
                        let copy_len = core::cmp::min(data.len(), data_len);
                        rref[page_offset..page_offset + copy_len].copy_from_slice(&data[..copy_len]);
                    }

                    let handle = match self.iommu_device_id {
                        Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice),
                        None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
                    }
                    .map_err(|_| VirtioNetError::DeviceError)?;

                    dma_addr = handle.iova() + page_offset as u64;
                    bounce_handle = Some(handle);
                    mapped_len = map_len;
                }
            } else {
                if is_iommu_required() {
                    return Err(VirtioNetError::DeviceError);
                }
            }

            if let Err(err) = check_device_dma_mask(self.iommu_device_id, dma_addr, data_len) {
                if let Some(handle) = bounce_handle {
                    let _ = handle.unmap();
                }
                if let Some(iova) = mapped_iova {
                    let _ = unmap_iommu_addr(self.iommu_device_id, iova, mapped_len);
                }
                return Err(err);
            }

            match tx_queue.add_tx_buffer_zero_copy(dma_addr, data.len()) {
                Ok(desc_idx) => {
                    let entry = TxPacketInflight {
                        packet,
                        bounce_handle,
                        dma_iova: mapped_iova,
                        dma_len: mapped_len,
                    };
                    self.tx_packetrefs.lock().insert(desc_idx, entry);
                    tx_queue.notify();
                    Ok(())
                }
                Err(e) => {
                    if let Some(handle) = bounce_handle {
                        let _ = handle.unmap();
                    }
                    if let Some(iova) = mapped_iova {
                        let _ = unmap_iommu_addr(self.iommu_device_id, iova, mapped_len);
                    }
                    Err(e)
                }
            }
        } else {
            Err(VirtioNetError::NotInitialized)
        }
    }
    /// パケットを受信（非同期）
    pub fn recv_async<'a>(&'a self, buffer: &'a mut [u8]) -> RecvFuture<'a> {
        RecvFuture {
            device: self,
            buffer,
            submitted: false,
            desc_idx: 0,
            dma_len: 0,
            dma_iova: None,
            bounce_handle: None,
        }
    }

    /// ゼロコピーパケット受信（設計書 6.2準拠）
    ///
    /// Mempoolから割り当てられたバッファに直接受信し、
    /// PacketRefとして返却する。
    pub fn recv_zero_copy(
        &self,
        pool: &'static crate::net::mempool::Mempool,
    ) -> ZeroCopyRecvFuture<'_> {
        ZeroCopyRecvFuture {
            device: self,
            pool,
            packet: None,
            submitted: false,
            desc_idx: 0,
            dma_len: 0,
            dma_iova: None,
            bounce_handle: None,
        }
    }

    /// MACアドレスを取得
    pub fn mac_address(&self) -> [u8; 6] {
        self.config.mac
    }

    /// 割り込みハンドラ
    pub fn handle_interrupt(&self) {
        // RXキュー完了を処理し、パケットをスタックに渡す
        if let Some(ref rx_queue) = self.rx_queue {
            let completions = rx_queue.process_used();
            if !completions.is_empty() {
                for (desc_idx, len) in completions {
                    self.rx_packets.fetch_add(1, Ordering::Relaxed);

                    // First, check for a PacketRef posted by the driver_bridge (zero-copy)
                    if let Some(packet) = self.rx_packetrefs.lock().remove(&desc_idx) {
                        // This was a PacketRef we posted earlier. Hand it to the bridge without copying.
                        let header_size = core::mem::size_of::<VirtioNetHeader>();
                        let payload_len = (len as usize).saturating_sub(header_size);
                        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET][RX-COMP] desc={} len={} payload_len={} (packetref)\n", desc_idx, len, payload_len));

                        // Pass PacketRef to bridge for zero-copy processing
                        crate::net::driver_bridge::process_received_packet_zero_copy(packet, header_size, payload_len);

                        // Re-post a new PacketRef buffer to the queue so we keep a steady supply
                        if let Some(new_pkt) = crate::net::mempool::alloc_packet() {
                            let phys = new_pkt.phys_addr().as_u64();
                            let buf_len = new_pkt.capacity();
                            match rx_queue.add_rx_buffer_zero_copy(phys, buf_len) {
                                Ok(new_desc_idx) => {
                                    log::info!("[VIRTIO-NET] re-queued RX PacketRef desc={} phys=0x{:x} len={}", new_desc_idx, phys, buf_len);
                                    self.rx_packetrefs.lock().insert(new_desc_idx, new_pkt);
                                }
                                Err(e) => {
                                    log::warn!("[VIRTIO-NET] failed to re-add rx PacketRef: {:?}", e);
                                    // Drop new_pkt and try to fall back to vbuf
                                }
                            }
                        } else {
                            log::warn!("[VIRTIO-NET] OOM allocating replacement PacketRef");
                        }

                        continue; // Process next completion
                    }

                    // Find the RX buffer we queued earlier and complete it
                    if let Some(mut vbuf) = self.rx_buffers.lock().remove(&desc_idx) {
                        if let Err(e) = vbuf.complete_receive() {
                            log::warn!("[VIRTIO-NET] failed to complete rx buffer {}: {}", desc_idx, e);
                        } else {
                            // Compute payload length and hand to network stack
                            let header_size = core::mem::size_of::<VirtioNetHeader>();
                            let payload_len = (len as usize).saturating_sub(header_size);
                            if let Some(data) = vbuf.received_data() {
                                let payload_cap = data.len();
                                let actual_len = core::cmp::min(payload_len, payload_cap);
                                let payload_slice = &data[..actual_len];

                                if actual_len >= 12 {
                                    log::info!(
                                        "[VIRTIO-NET][RX-COMP] desc={} len={} payload_len={} src={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                                        desc_idx,
                                        len,
                                        actual_len,
                                        payload_slice[6],
                                        payload_slice[7],
                                        payload_slice[8],
                                        payload_slice[9],
                                        payload_slice[10],
                                        payload_slice[11]
                                    );
                                } else {
                                    log::info!(
                                        "[VIRTIO-NET][RX-COMP] desc={} len={} payload_len={}",
                                        desc_idx,
                                        len,
                                        actual_len
                                    );
                                }

                                crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] handing payload desc={} payload_len={} to bridge\n", desc_idx, actual_len));
                                // Allocate a PacketRef and delegate to the zero-copy bridge API
                                if let Some(mut packet) = crate::net::mempool::alloc_packet() {
                                    let len_to_copy = core::cmp::min(actual_len, packet.capacity());
                                    packet.data_mut()[..len_to_copy].copy_from_slice(&payload_slice[..len_to_copy]);
                                    crate::net::driver_bridge::process_received_packet_zero_copy(packet, 0, len_to_copy);
                                } else {
                                    #[cfg(debug_assertions)]
                                    {
                                        log::warn!("[VIRTIO-NET] OOM allocating packet for rx copy");
                                    }
                                }
                            } else {
                                log::warn!("[VIRTIO-NET] Received completion for unknown desc {}", desc_idx);
                            }
                        }
                    }
                }
            }
        }

        // TXキュー完了を処理し、インフライトバッファを解放
        if let Some(ref tx_queue) = self.tx_queue {
            let completions = tx_queue.process_used();
            if !completions.is_empty() {
                for (desc_idx, len) in completions {
                    self.tx_packets.fetch_add(1, Ordering::Relaxed);
                    self.tx_bytes.fetch_add(len, Ordering::Relaxed);

                    log::info!("[VIRTIO-NET][TX-COMP] desc={} len={}", desc_idx, len);

                    if let Some(_buf) = self.tx_inflight.lock().remove(&desc_idx) {
                        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] TX-COMP freed buffer for desc={} len={}\n", desc_idx, len));
                        log::info!("[VIRTIO-NET][TX-COMP] freed buffer for desc={}", desc_idx);
                        // Buffer dropped here
                    } else if let Some(entry) = self.tx_packetrefs.lock().remove(&desc_idx) {
                        // Zero-copy PacketRef completed: unmap any bounce/IOMMU mappings
                        if let Some(handle) = entry.bounce_handle {
                            if let Err(err) = handle.unmap() {
                                log::warn!("[VIRTIO-NET] failed to unmap bounce buffer: {:?}", err);
                            }
                        }
                        if let Some(iova) = entry.dma_iova {
                            // unmap_iommu_addr logs failures internally
                            unmap_iommu_addr(self.iommu_device_id, iova, entry.dma_len);
                        }
                        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] TX-COMP freed PacketRef for desc={} len={}\n", desc_idx, len));
                        log::info!("[VIRTIO-NET][TX-COMP] freed PacketRef for desc={}", desc_idx);
                    } else {
                        log::warn!("[VIRTIO-NET] TX completion for unknown desc {}", desc_idx);
                    }
                }

                // Notify network stack that TX resources became available
                crate::net::endpoint::event::send_event_ignore(
                    crate::net::endpoint::event::NetworkEvent::TxAvailable,
                );
            }
        }

        // HybridIoCoordinator 経由でパケット処理を通知（io_scheduler 統一後）
        // Note: 旧 polling::net_io_controller() は削除済み
        // io_scheduler の complete_request はリクエストID単位のため、
        // ここではwaker通知のみで十分

        // Interrupt-Wakerブリッジに通知（設計書 4.2）
        // RX/TXで待機中のFutureを起床
        crate::task::interrupt_waker::wake_from_interrupt(
            crate::task::interrupt_waker::InterruptSource::VirtioNet(0),
        );
    }

    /// 統計を取得
    pub fn stats(&self) -> VirtioNetStats {
        VirtioNetStats {
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
        }
    }
}

// ============================================================================
// Async Futures
// ============================================================================

/// 送信用Future
pub struct SendFuture<'a> {
    device: &'a VirtioNetDevice,
    data: *const u8,
    len: usize,
    submitted: bool,
    desc_idx: u16,
    dma_len: usize,
    dma_iova: Option<u64>,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

impl<'a> Future for SendFuture<'a> {
    type Output = Result<usize, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if !this.submitted {
            if let Some(ref tx_queue) = this.device.tx_queue {
                let data_len = this.len;
                let virt_addr = VirtAddr::new(this.data as u64);
                let phys_addr = crate::mm::mapping::virt_to_phys(virt_addr);
                let phys_addr_val = phys_addr.as_u64();
                let page_mask = (crate::mm::PAGE_SIZE_4K as u64) - 1;
                let page_base = phys_addr_val & !page_mask;
                let page_offset = (phys_addr_val - page_base) as usize;
                let map_len = crate::mm::PAGE_SIZE_4K;
                let can_map_page = page_offset + data_len <= map_len;

                let mut dma_addr = phys_addr_val;
                let mut mapped_iova: Option<u64> = None;
                let mut mapped_len = 0usize;
                let mut bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>> = None;

                if is_iommu_enabled() {
                    if !can_map_page {
                        let mut rref =
                            match allocate_iommu_bounce_bytes(data_len).map_err(|err| match err {
                                IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                                IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                            }) {
                                Ok(rref) => rref,
                                Err(err) => return Poll::Ready(Err(err)),
                            };
                        if data_len > 0 {
                            let data =
                                unsafe { crate::util::raw_ptr_as_slice(this.data, data_len) };
                            rref[..data_len].copy_from_slice(data);
                        }
                        let handle = match this.device.iommu_device_id {
                            Some(device) => {
                                map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice)
                            }
                            None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
                        }
                        .map_err(|_| VirtioNetError::DeviceError);
                        let handle = match handle {
                            Ok(handle) => handle,
                            Err(err) => return Poll::Ready(Err(err)),
                        };
                        dma_addr = handle.iova();
                        bounce_handle = Some(handle);
                    } else {
                        // Allocate a page-aligned bounce buffer and copy the relevant page
                        let mut rref = match allocate_iommu_bounce_bytes(map_len).map_err(|err| match err {
                            IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                            IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                        }) {
                            Ok(rref) => rref,
                            Err(err) => return Poll::Ready(Err(err)),
                        };

                        if data_len > 0 {
                            let data = unsafe { crate::util::raw_ptr_as_slice(this.data, data_len) };
                            rref[page_offset..page_offset + data_len].copy_from_slice(data);
                        }

                        let handle = match this.device.iommu_device_id {
                            Some(device) => {
                                map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice)
                            }
                            None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
                        }
                        .map_err(|_| VirtioNetError::DeviceError);
                        let handle = match handle {
                            Ok(handle) => handle,
                            Err(err) => return Poll::Ready(Err(err)),
                        };

                        dma_addr = handle.iova() + page_offset as u64;
                        bounce_handle = Some(handle);
                        mapped_len = map_len;
                    }
                } else if is_iommu_required() {
                    return Poll::Ready(Err(VirtioNetError::DeviceError));
                }

                if let Err(err) = check_device_dma_mask(
                    this.device.iommu_device_id,
                    dma_addr,
                    data_len,
                ) {
                    if let Some(handle) = bounce_handle.take() {
                        if let Err(e) = handle.unmap() {
                            log::warn!("[VIRTIO-NET] failed to unmap bounce buffer: {:?}", e);
                        }
                    }
                    if let Some(iova) = mapped_iova.take() {
                        unmap_iommu_addr(this.device.iommu_device_id, iova, mapped_len);
                    }
                    return Poll::Ready(Err(err));
                }

                match tx_queue.add_tx_buffer_zero_copy(dma_addr, data_len) {
                    Ok(desc_idx) => {
                        this.submitted = true;
                        this.desc_idx = desc_idx;
                        this.dma_iova = mapped_iova;
                        this.dma_len = mapped_len;
                        this.bounce_handle = bounce_handle;
                        tx_queue.register_waker(cx.waker().clone());
                        tx_queue.notify();
                    }
                    Err(e) => {
                        if let Some(handle) = bounce_handle {
                            if let Err(err) = handle.unmap() {
                                log::warn!(
                                    "[VIRTIO-NET] failed to unmap bounce buffer: {:?}",
                                    err
                                );
                            }
                        }
                        if let Some(iova) = mapped_iova {
                            unmap_iommu_addr(this.device.iommu_device_id, iova, mapped_len);
                        }
                        return Poll::Ready(Err(e));
                    }
                }
            } else {
                return Poll::Ready(Err(VirtioNetError::NotInitialized));
            }
        }

        if let Some(ref tx_queue) = this.device.tx_queue {
            if tx_queue.take_completion(this.desc_idx).is_some() {
                if let Some(handle) = this.bounce_handle.take() {
                    if let Err(err) = handle.unmap() {
                        log::warn!(
                            "[VIRTIO-NET] failed to unmap bounce buffer: {:?}",
                            err
                        );
                        return Poll::Ready(Err(VirtioNetError::DeviceError));
                    }
                }
                if let Some(iova) = this.dma_iova.take() {
                    unmap_iommu_addr(this.device.iommu_device_id, iova, this.dma_len);
                }
                Poll::Ready(Ok(this.len))
            } else {
                tx_queue.register_waker(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(VirtioNetError::NotInitialized))
        }
    }
}

/// 受信用Future
pub struct RecvFuture<'a> {
    device: &'a VirtioNetDevice,
    buffer: &'a mut [u8],
    submitted: bool,
    desc_idx: u16,
    dma_len: usize,
    dma_iova: Option<u64>,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

impl<'a> Future for RecvFuture<'a> {
    type Output = Result<usize, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if !this.submitted {
            if this.buffer.len() < VirtioNetHeader::SIZE {
                return Poll::Ready(Err(VirtioNetError::BufferTooSmall));
            }

            if let Some(ref rx_queue) = this.device.rx_queue {
                let buffer_len = this.buffer.len();
                let virt_addr = VirtAddr::new(this.buffer.as_ptr() as u64);
                let phys_addr = crate::mm::mapping::virt_to_phys(virt_addr);
                let phys_addr_val = phys_addr.as_u64();
                let page_mask = (crate::mm::PAGE_SIZE_4K as u64) - 1;
                let page_base = phys_addr_val & !page_mask;
                let page_offset = (phys_addr_val - page_base) as usize;
                let map_len = crate::mm::PAGE_SIZE_4K;
                let can_map_page = page_offset + buffer_len <= map_len;

                let mut dma_addr = phys_addr_val;
                let mut mapped_iova: Option<u64> = None;
                let mut mapped_len = 0usize;
                let mut bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>> = None;

                if is_iommu_enabled() {
                    if !can_map_page {
                        let rref =
                            match allocate_iommu_bounce_bytes(buffer_len).map_err(|err| match err {
                                IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                                IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                            }) {
                                Ok(rref) => rref,
                                Err(err) => return Poll::Ready(Err(err)),
                            };
                        let handle = match this.device.iommu_device_id {
                            Some(device) => {
                                map_rref_slice_for_device(rref, &device, DmaDirection::FromDevice)
                            }
                            None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::FromDevice),
                        }
                        .map_err(|_| VirtioNetError::DeviceError);
                        let handle = match handle {
                            Ok(handle) => handle,
                            Err(err) => return Poll::Ready(Err(err)),
                        };
                        dma_addr = handle.iova();
                        bounce_handle = Some(handle);
                    } else {
                        // Allocate a page-aligned bounce buffer and map it for device writes
                        let rref = match allocate_iommu_bounce_bytes(map_len).map_err(|err| match err {
                            IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                            IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                        }) {
                            Ok(rref) => rref,
                            Err(err) => return Poll::Ready(Err(err)),
                        };

                        let handle = match this.device.iommu_device_id {
                            Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::FromDevice),
                            None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::FromDevice),
                        }
                        .map_err(|_| VirtioNetError::DeviceError);
                        let handle = match handle {
                            Ok(handle) => handle,
                            Err(err) => return Poll::Ready(Err(err)),
                        };

                        dma_addr = handle.iova() + page_offset as u64;
                        bounce_handle = Some(handle);
                        mapped_len = map_len;
                    }
                } else if is_iommu_required() {
                    return Poll::Ready(Err(VirtioNetError::DeviceError));
                }

                if bounce_handle.is_none() {
                    if let Err(err) = check_device_dma_mask(
                        this.device.iommu_device_id,
                        dma_addr,
                        buffer_len,
                    ) {
                        if let Some(iova) = mapped_iova.take() {
                            unmap_iommu_addr(this.device.iommu_device_id, iova, mapped_len);
                        }
                        return Poll::Ready(Err(err));
                    }
                }

                match rx_queue.add_rx_buffer_zero_copy(dma_addr, buffer_len) {
                    Ok(desc_idx) => {
                        this.submitted = true;
                        this.desc_idx = desc_idx;
                        this.dma_iova = mapped_iova;
                        this.dma_len = mapped_len;
                        this.bounce_handle = bounce_handle;
                        rx_queue.register_waker(cx.waker().clone());
                    }
                    Err(e) => {
                        if let Some(handle) = bounce_handle {
                            if let Err(err) = handle.unmap() {
                                log::warn!(
                                    "[VIRTIO-NET] failed to unmap bounce buffer: {:?}",
                                    err
                                );
                            }
                        }
                        if let Some(iova) = mapped_iova {
                            unmap_iommu_addr(this.device.iommu_device_id, iova, mapped_len);
                        }
                        return Poll::Ready(Err(e));
                    }
                }
            } else {
                return Poll::Ready(Err(VirtioNetError::NotInitialized));
            }
        }

        if let Some(ref rx_queue) = this.device.rx_queue {
            if let Some(len) = rx_queue.take_completion(this.desc_idx) {
                let total_len = len as usize;
                let payload_len = total_len.saturating_sub(VirtioNetHeader::SIZE);
                let payload_cap = this
                    .buffer
                    .len()
                    .saturating_sub(VirtioNetHeader::SIZE);
                let payload_len = core::cmp::min(payload_len, payload_cap);

                if let Some(handle) = this.bounce_handle.take() {
                    let rref = match handle.unmap() {
                        Ok(rref) => rref,
                        Err(err) => {
                            log::warn!(
                                "[VIRTIO-NET] failed to unmap bounce buffer: {:?}",
                                err
                            );
                            return Poll::Ready(Err(VirtioNetError::DeviceError));
                        }
                    };
                    if payload_len > 0 {
                        this.buffer[..payload_len].copy_from_slice(
                            &rref[VirtioNetHeader::SIZE..(VirtioNetHeader::SIZE + payload_len)],
                        );
                    }
                } else {
                    if payload_len > 0 {
                        let buf_ptr = this.buffer.as_mut_ptr();
                        unsafe {
                            core::ptr::copy(
                                buf_ptr.add(VirtioNetHeader::SIZE),
                                buf_ptr,
                                payload_len,
                            );
                        }
                    }
                }

                if let Some(iova) = this.dma_iova.take() {
                    unmap_iommu_addr(this.device.iommu_device_id, iova, this.dma_len);
                }

                Poll::Ready(Ok(payload_len))
            } else {
                rx_queue.register_waker(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(VirtioNetError::NotInitialized))
        }
    }
}

// ============================================================================
// ゼロコピー送受信 Futures（設計書 6.2）
// ============================================================================

/// ゼロコピー送信用Future
///
/// PacketRefの所有権を取得し、DMA転送が完了するまで保持する。
/// 完了後、PacketRefは自動的にMempoolに返却される。
pub struct ZeroCopySendFuture<'a> {
    device: &'a VirtioNetDevice,
    packet: Option<PacketRef>,
    submitted: bool,
    desc_idx: u16,
    dma_len: usize,
    dma_iova: Option<u64>,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

impl<'a> Future for ZeroCopySendFuture<'a> {
    type Output = Result<usize, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if !this.submitted {
            // 送信をキューに追加
            if let Some(ref tx_queue) = this.device.tx_queue {
                if let Some(ref packet) = this.packet {
                    let data = packet.data();
                    let phys_addr = packet.phys_addr();
                    let data_len = VirtioNetHeader::SIZE + data.len();
                    let phys_addr_val = phys_addr.as_u64();
                    let page_mask = (crate::mm::PAGE_SIZE_4K as u64) - 1;
                    let page_base = phys_addr_val & !page_mask;
                    let page_offset = (phys_addr_val - page_base) as usize;
                    let map_len = crate::mm::PAGE_SIZE_4K;
                    let can_map_page = page_offset + data_len <= map_len;

                    let mut dma_addr = phys_addr_val;
                    let mut mapped_iova: Option<u64> = None;
                    let mut mapped_len = 0usize;
                    let mut bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>> = None;

                    if is_iommu_enabled() {
                        if !can_map_page {
                            let mut rref =
                                match allocate_iommu_bounce_bytes(data_len).map_err(|err| match err {
                                    IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                                    IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                                }) {
                                    Ok(rref) => rref,
                                    Err(err) => return Poll::Ready(Err(err)),
                                };
                            if data_len > 0 {
                                rref[..data_len].fill(0);
                                let copy_len = core::cmp::min(data.len(), data_len);
                                rref[..copy_len].copy_from_slice(&data[..copy_len]);
                            }
                            let handle = match this.device.iommu_device_id {
                                Some(device) => {
                                    map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice)
                                }
                                None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
                            }
                            .map_err(|_| VirtioNetError::DeviceError);
                            let handle = match handle {
                                Ok(handle) => handle,
                                Err(err) => return Poll::Ready(Err(err)),
                            };
                            dma_addr = handle.iova();
                            bounce_handle = Some(handle);
                        } else {
                            // Allocate a page-aligned bounce buffer and copy the relevant page
                            let mut rref = match allocate_iommu_bounce_bytes(map_len).map_err(|err| match err {
                                IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                                IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                            }) {
                                Ok(rref) => rref,
                                Err(err) => return Poll::Ready(Err(err)),
                            };

                            if data_len > 0 {
                                rref[page_offset..page_offset + data_len].fill(0);
                                let copy_len = core::cmp::min(data.len(), data_len);
                                rref[page_offset..page_offset + copy_len].copy_from_slice(&data[..copy_len]);
                            }

                            let handle = match this.device.iommu_device_id {
                                Some(device) => {
                                    map_rref_slice_for_device(rref, &device, DmaDirection::ToDevice)
                                }
                                None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::ToDevice),
                            }
                            .map_err(|_| VirtioNetError::DeviceError);
                            let handle = match handle {
                                Ok(handle) => handle,
                                Err(err) => return Poll::Ready(Err(err)),
                            };

                            dma_addr = handle.iova() + page_offset as u64;
                            bounce_handle = Some(handle);
                            mapped_len = map_len;
                        }
                    } else {
                        if is_iommu_required() {
                            return Poll::Ready(Err(VirtioNetError::DeviceError));
                        }
                    }

                    if let Err(err) = check_device_dma_mask(
                        this.device.iommu_device_id,
                        dma_addr,
                        data_len,
                    ) {
                        if let Some(handle) = bounce_handle.take() {
                            if let Err(e) = handle.unmap() {
                                log::warn!("[VIRTIO-NET] failed to unmap bounce buffer: {:?}", e);
                            }
                        }
                        if let Some(iova) = mapped_iova.take() {
                            unmap_iommu_addr(this.device.iommu_device_id, iova, mapped_len);
                        }
                        return Poll::Ready(Err(err));
                    }

                    // ゼロコピー: 物理/IOVA アドレスを直接VirtQueueに渡す
                    match tx_queue.add_tx_buffer_zero_copy(dma_addr, data.len()) {
                        Ok(desc_idx) => {
                            this.submitted = true;
                            this.desc_idx = desc_idx;
                            this.dma_iova = mapped_iova;
                            this.dma_len = mapped_len;
                            this.bounce_handle = bounce_handle;
                            tx_queue.register_waker(cx.waker().clone());
                        }
                        Err(e) => {
                            if let Some(handle) = bounce_handle {
                                if let Err(err) = handle.unmap() {
                                    log::warn!(
                                        "[VIRTIO-NET] failed to unmap bounce buffer: {:?}",
                                        err
                                    );
                                }
                            }
                            if let Some(iova) = mapped_iova {
                                unmap_iommu_addr(this.device.iommu_device_id, iova, mapped_len);
                            }
                            return Poll::Ready(Err(e));
                        }
                    }
                } else {
                    return Poll::Ready(Err(VirtioNetError::BufferTooSmall));
                }
            } else {
                return Poll::Ready(Err(VirtioNetError::NotInitialized));
            }
        }

        // 完了を確認
        if let Some(ref tx_queue) = this.device.tx_queue {
            if tx_queue.take_completion(this.desc_idx).is_some() {
                if let Some(handle) = this.bounce_handle.take() {
                    if let Err(err) = handle.unmap() {
                        log::warn!(
                            "[VIRTIO-NET] failed to unmap bounce buffer: {:?}",
                            err
                        );
                        return Poll::Ready(Err(VirtioNetError::DeviceError));
                    }
                }
                if let Some(iova) = this.dma_iova.take() {
                    unmap_iommu_addr(this.device.iommu_device_id, iova, this.dma_len);
                }
                // 送信完了: PacketRefをドロップしてMempoolに返却
                let packet = this.packet.take();
                let len = packet.map(|p: crate::net::mempool::PacketRef| p.data().len()).unwrap_or(0);
                Poll::Ready(Ok(len))
            } else {
                tx_queue.register_waker(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(VirtioNetError::NotInitialized))
        }
    }
}

/// ゼロコピー受信用Future
///
/// Mempoolから直接バッファを割り当て、DMAバッファとして使用。
/// 受信完了後、PacketRefとしてデータを返却する。
pub struct ZeroCopyRecvFuture<'a> {
    device: &'a VirtioNetDevice,
    pool: &'static crate::net::mempool::Mempool,
    packet: Option<PacketRef>,
    submitted: bool,
    desc_idx: u16,
    dma_len: usize,
    dma_iova: Option<u64>,
    bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>>,
}

impl<'a> Future for ZeroCopyRecvFuture<'a> {
    type Output = Result<PacketRef, VirtioNetError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        if !this.submitted {
            // Mempoolからバッファを割り当て
            let packet = this.pool.alloc().ok_or(VirtioNetError::BufferTooSmall)?;
            let phys_addr = packet.phys_addr();
            let buffer_len = packet.capacity();
            let data_len = buffer_len;
            let phys_addr_val = phys_addr.as_u64();
            let page_mask = (crate::mm::PAGE_SIZE_4K as u64) - 1;
            let page_base = phys_addr_val & !page_mask;
            let page_offset = (phys_addr_val - page_base) as usize;
            let map_len = crate::mm::PAGE_SIZE_4K;
            let can_map_page = page_offset + data_len <= map_len;

            let mut dma_addr = phys_addr_val;
            let mut mapped_iova: Option<u64> = None;
            let mut mapped_len = 0usize;
            let mut bounce_handle: Option<crate::io::iommu::api::DmaHandle<[u8]>> = None;

            if is_iommu_enabled() {
                if !can_map_page {
                    let rref =
                        match allocate_iommu_bounce_bytes(data_len).map_err(|err| match err {
                            IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                            IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                        }) {
                            Ok(rref) => rref,
                            Err(err) => return Poll::Ready(Err(err)),
                        };
                    let handle = match this.device.iommu_device_id {
                        Some(device) => {
                            map_rref_slice_for_device(rref, &device, DmaDirection::FromDevice)
                        }
                        None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::FromDevice),
                    }
                    .map_err(|_| VirtioNetError::DeviceError);
                    let handle = match handle {
                        Ok(handle) => handle,
                        Err(err) => return Poll::Ready(Err(err)),
                    };
                    dma_addr = handle.iova();
                    bounce_handle = Some(handle);
                } else {
                    // Allocate a page-aligned bounce buffer and map it for device writes
                    let rref = match allocate_iommu_bounce_bytes(map_len).map_err(|err| match err {
                        IommuBounceAllocError::InvalidLen => VirtioNetError::BufferTooSmall,
                        IommuBounceAllocError::AllocFailed => VirtioNetError::DeviceError,
                    }) {
                        Ok(rref) => rref,
                        Err(err) => return Poll::Ready(Err(err)),
                    };

                    let handle = match this.device.iommu_device_id {
                        Some(device) => map_rref_slice_for_device(rref, &device, DmaDirection::FromDevice),
                        None => DmaHandle::map_rref_slice(rref, 0, DmaDirection::FromDevice),
                    }
                    .map_err(|_| VirtioNetError::DeviceError);
                    let handle = match handle {
                        Ok(handle) => handle,
                        Err(err) => return Poll::Ready(Err(err)),
                    };

                    dma_addr = handle.iova() + page_offset as u64;
                    bounce_handle = Some(handle);
                    mapped_len = map_len;
                }
            } else {
                if is_iommu_required() {
                    return Poll::Ready(Err(VirtioNetError::DeviceError));
                }
            }

            if let Err(err) = check_device_dma_mask(
                this.device.iommu_device_id,
                dma_addr,
                data_len,
            ) {
                if let Some(handle) = bounce_handle.take() {
                    if let Err(e) = handle.unmap() {
                        log::warn!("[VIRTIO-NET] failed to unmap bounce buffer: {:?}", e);
                    }
                }
                if let Some(iova) = mapped_iova.take() {
                    unmap_iommu_addr(this.device.iommu_device_id, iova, mapped_len);
                }
                return Poll::Ready(Err(err));
            }

            // 受信バッファをキューに追加
            if let Some(ref rx_queue) = this.device.rx_queue {
                match rx_queue.add_rx_buffer_zero_copy(dma_addr, buffer_len) {
                    Ok(desc_idx) => {
                        this.packet = Some(packet);
                        this.submitted = true;
                        this.desc_idx = desc_idx;
                        this.dma_iova = mapped_iova;
                        this.dma_len = mapped_len;
                        this.bounce_handle = bounce_handle;
                        rx_queue.register_waker(cx.waker().clone());
                    }
                    Err(e) => {
                        if let Some(handle) = bounce_handle {
                            if let Err(err) = handle.unmap() {
                                log::warn!(
                                    "[VIRTIO-NET] failed to unmap bounce buffer: {:?}",
                                    err
                                );
                            }
                        }
                        if let Some(iova) = mapped_iova {
                            unmap_iommu_addr(this.device.iommu_device_id, iova, mapped_len);
                        }
                        return Poll::Ready(Err(e));
                    }
                }
            } else {
                return Poll::Ready(Err(VirtioNetError::NotInitialized));
            }
        }

        // 完了を確認
        if let Some(ref rx_queue) = this.device.rx_queue {
            if let Some(len) = rx_queue.take_completion(this.desc_idx) {
                if let Some(handle) = this.bounce_handle.take() {
                    let rref = match handle.unmap() {
                        Ok(rref) => rref,
                        Err(err) => {
                            log::warn!(
                                "[VIRTIO-NET] failed to unmap bounce buffer: {:?}",
                                err
                            );
                            return Poll::Ready(Err(VirtioNetError::DeviceError));
                        }
                    };
                    if let Some(mut packet) = this.packet.take() {
                        let copy_len = core::cmp::min(len as usize, packet.capacity() as usize);
                        packet.set_len(copy_len);
                        packet.data_mut()[..copy_len].copy_from_slice(&rref[..copy_len]);
                        packet.advance(VirtioNetHeader::SIZE);
                        return Poll::Ready(Ok(packet));
                    }
                    return Poll::Ready(Err(VirtioNetError::BufferTooSmall));
                }

                if let Some(iova) = this.dma_iova.take() {
                    unmap_iommu_addr(this.device.iommu_device_id, iova, this.dma_len);
                }

                // 受信完了: データ長を設定してPacketRefを返却
                if let Some(mut packet) = this.packet.take() {
                    let copy_len = core::cmp::min(len as usize, packet.capacity() as usize);
                    packet.set_len(copy_len);
                    packet.advance(VirtioNetHeader::SIZE);
                    return Poll::Ready(Ok(packet));
                }
                return Poll::Ready(Err(VirtioNetError::BufferTooSmall));
            } else {
                rx_queue.register_waker(cx.waker().clone());
                Poll::Pending
            }
        } else {
            Poll::Ready(Err(VirtioNetError::NotInitialized))
        }
    }
}

// ============================================================================
// Error Types
// ============================================================================

/// VirtIO ネットワークエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioNetError {
    /// デバイスが初期化されていない
    NotInitialized,
    /// キューが満杯
    QueueFull,
    /// バッファが不足
    BufferTooSmall,
    /// デバイスエラー
    DeviceError,
    /// タイムアウト
    Timeout,
}

impl core::fmt::Display for VirtioNetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VirtioNetError::NotInitialized => write!(f, "Device not initialized"),
            VirtioNetError::QueueFull => write!(f, "Queue is full"),
            VirtioNetError::BufferTooSmall => write!(f, "Buffer too small"),
            VirtioNetError::DeviceError => write!(f, "Device error"),
            VirtioNetError::Timeout => write!(f, "Operation timed out"),
        }
    }
}

// ============================================================================
// Statistics
// ============================================================================

/// VirtIO ネットワーク統計
#[derive(Debug, Clone)]
pub struct VirtioNetStats {
    pub tx_packets: u32,
    pub rx_packets: u32,
    pub tx_bytes: u32,
    pub rx_bytes: u32,
}

// ============================================================================
// Global Device Instance
// ============================================================================

use super::transport::VirtioMmioTransport;

static VIRTIO_NET_DEVICE: Mutex<Option<VirtioNetDevice>> = Mutex::new(None);

/// VirtIO ネットワークデバイス（MMIO）を初期化
///
/// # Safety
/// `base_addr` は有効なVirtIO MMIOデバイスのベースアドレスを指す必要がある
pub fn init_virtio_net(base_addr: usize) -> Result<(), VirtioNetError> {
    // トランスポート作成（magic/version検証含む）
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device = VirtioNetDevice::new(Box::new(transport));
    device.init()?;
    *VIRTIO_NET_DEVICE.lock() = Some(device);
    Ok(())
}

/// VirtIO ネットワークデバイス（MMIO）を初期化（IOMMUデバイスID付き）
///
/// # Safety
/// `base_addr` は有効なVirtIO MMIOデバイスのベースアドレスを指す必要がある
pub fn init_virtio_net_for_device(
    base_addr: usize,
    device: IommuDeviceId,
) -> Result<(), VirtioNetError> {
    let transport =
        unsafe { VirtioMmioTransport::new(base_addr).map_err(|_| VirtioNetError::DeviceError)? };

    let mut device = VirtioNetDevice::new_with_device(Box::new(transport), Some(device));
    device.init()?;
    *VIRTIO_NET_DEVICE.lock() = Some(device);
    Ok(())
}

/// Initialize VirtIO-Net from an existing VirtioTransport (MMIO or PCI)
pub fn init_virtio_net_with_transport(
    transport: Box<dyn VirtioTransport>,
) -> Result<(), VirtioNetError> {
    let mut device = VirtioNetDevice::new(transport);
    device.init()?;
    *VIRTIO_NET_DEVICE.lock() = Some(device);
    Ok(())
}

/// VirtIO ネットワークデバイスにアクセス
pub fn with_virtio_net<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&VirtioNetDevice) -> R,
{
    VIRTIO_NET_DEVICE.lock().as_ref().map(f)
}

/// 割り込みハンドラ
pub fn handle_virtio_net_interrupt() {
    if let Some(ref mut device) = *VIRTIO_NET_DEVICE.lock() {
        // Read and ack interrupt status for diagnostics and clearing the device
        let status = device.transport.get_interrupt_status();
        crate::io::log::early_print(&alloc::format!("[EARLY][VIRTIO-NET] IRQ status read=0x{:x}\n", status));
        device.transport.ack_interrupt(status);

        // Now process completions
        device.handle_interrupt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_virtio_net_header() {
        let header = VirtioNetHeader::new_tx();
        assert_eq!(header.flags, 0);
        assert_eq!(VirtioNetHeader::SIZE, 12);
    }
}

// ============================================================================
// IoScheduler Integration
// ============================================================================

/// VirtIO ネットワーク PollHandler 実装
pub struct VirtioNetPollHandler {
    /// デバイスへの参照
    device_lock: &'static Mutex<Option<VirtioNetDevice>>,
    /// 保留中リクエスト (IoRequestId -> buffer_index)
    pending_rx: Mutex<BTreeMap<IoRequestId, u16>>,
    pending_tx: Mutex<BTreeMap<IoRequestId, u16>>,
    /// 次のリクエストID
    next_request_id: AtomicU64,
}

impl VirtioNetPollHandler {
    /// 新しい VirtioNetPollHandler を作成
    pub fn new() -> Self {
        Self {
            device_lock: &VIRTIO_NET_DEVICE,
            pending_rx: Mutex::new(BTreeMap::new()),
            pending_tx: Mutex::new(BTreeMap::new()),
            next_request_id: AtomicU64::new(1),
        }
    }

    /// 新しいリクエストIDを生成
    pub fn next_request_id(&self) -> IoRequestId {
        IoRequestId(self.next_request_id.fetch_add(1, Ordering::SeqCst))
    }

    /// RX リクエストを追加
    pub fn add_pending_rx(&self, id: IoRequestId, buffer_idx: u16) {
        self.pending_rx.lock().insert(id, buffer_idx);
    }

    /// TX リクエストを追加
    pub fn add_pending_tx(&self, id: IoRequestId, buffer_idx: u16) {
        self.pending_tx.lock().insert(id, buffer_idx);
    }
}

impl PollHandler for VirtioNetPollHandler {
    fn poll_completions(&self) -> Vec<(IoRequestId, IoResult)> {
        let mut results = Vec::new();

        if let Some(ref device) = *self.device_lock.lock() {
            // RX 完了をチェック - rx_queue が存在するか確認
            if let Some(ref rx_queue) = device.rx_queue {
                let mut pending = self.pending_rx.lock();
                let mut completed = Vec::new();

                // 簡略化: キューにリクエストがあれば完了とみなす
                // 実際の実装では used ring のインデックスを追跡
                for (&id, &_buf_idx) in pending.iter() {
                    // rx_queue の状態をチェック
                    let _ = rx_queue; // 使用を示す
                    results.push((id, IoResult::Success(1514))); // MTU
                    completed.push(id);
                    break; // 1つずつ処理
                }

                for id in completed {
                    pending.remove(&id);
                }
            }

            // TX 完了をチェック
            if let Some(ref tx_queue) = device.tx_queue {
                let mut pending = self.pending_tx.lock();
                let mut completed = Vec::new();

                for (&id, &_buf_idx) in pending.iter() {
                    let _ = tx_queue;
                    results.push((id, IoResult::Success(0)));
                    completed.push(id);
                    break;
                }

                for id in completed {
                    pending.remove(&id);
                }
            }
        }

        results
    }

    fn is_ready(&self) -> bool {
        self.device_lock.lock().is_some()
    }
}

// SAFETY: VirtioNetPollHandler はスレッドセーフ
// - 内部の Mutex で安全に同期
unsafe impl Send for VirtioNetPollHandler {}
unsafe impl Sync for VirtioNetPollHandler {}

/// VirtIO ネットワークを IoScheduler に登録（依存注入版）
pub fn register_virtio_net_with(
    coordinator: &alloc::sync::Arc<crate::io::io_scheduler::HybridIoCoordinator>,
    index: u8,
) {
    let handler = VirtioNetPollHandler::new();
    let handler: Box<dyn PollHandler + Send + Sync> = Box::new(handler);
    coordinator.polling_executor().register_handler(DeviceId::VirtioNet { index }, handler);
}

/// VirtIO ネットワークを IoScheduler に登録（後方互換wrapper）
pub fn register_virtio_net_with_io_scheduler(index: u8) {
    register_virtio_net_with(&hybrid_coordinator(), index);
}

// ============================================================================
// 型安全 DMA バッファ (VirtIO Network)
// ============================================================================

/// VirtIO ネットワーク最大フレームサイズ
const VIRTIO_NET_MTU: usize = 1514;

/// VirtIO ネットワーク受信用DMAバッファ
///
/// 型状態パターンで DMA 転送中の不正アクセスを防止
pub struct VirtioNetRxDmaBuffer {
    /// CPU所有状態のバッファ
    buffer: Option<TypedDmaSlice<CpuOwned>>,
    /// デバイス所有状態（転送中）+ Guard
    inflight: Option<(TypedDmaSlice<DeviceOwned>, SliceDmaGuard)>,
    /// アロケート済みバッファサイズ（4Kアライン）
    alloc_size: usize,
}

impl VirtioNetRxDmaBuffer {
    /// MTUサイズの受信バッファを作成
    pub fn new() -> Option<Self> {
        // VirtIO net header + MTU
        let size = core::mem::size_of::<VirtioNetHeader>() + VIRTIO_NET_MTU;
        let alloc_size = iommu_align_len(size)?;
        let buffer = TypedDmaSlice::new(alloc_size)?;

        Some(Self {
            buffer: Some(buffer),
            inflight: None,
            alloc_size,
        })
    }

    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        self.buffer
            .as_ref()
            .map(|b| b.phys_addr())
            .or_else(|| self.inflight.as_ref().map(|(b, _)| b.phys_addr()))
    }

    /// DMA転送を開始（VirtQueueへのバッファ追加時）
    pub fn start_receive(&mut self) -> Result<u64, &'static str> {
        let buffer = self.buffer.take().ok_or("Buffer already in use")?;
        let phys = buffer.phys_addr().as_u64();
        let (dev, guard) = buffer.start_dma();
        self.inflight = Some((dev, guard));
        Ok(phys)
    }

    /// DMA転送完了（受信完了時）
    pub fn complete_receive(&mut self) -> Result<(), &'static str> {
        let (dev, guard) = self.inflight.take().ok_or("No receive in progress")?;
        self.buffer = Some(guard.complete(dev));
        Ok(())
    }

    /// 受信データを取得（完了後のみ）
    pub fn received_data(&self) -> Option<&[u8]> {
        self.buffer.as_ref().map(|b| {
            // Skip VirtIO net header
            let slice = b.as_slice();
            let header_size = core::mem::size_of::<VirtioNetHeader>();
            let end = header_size + VIRTIO_NET_MTU;
            &slice[header_size..end]
        })
    }

    /// Take ownership of the CPU-owned TypedDmaSlice when completed.
    /// This consumes the internal buffer and returns it, allowing the caller to
    /// take ownership and avoid copying (true zero-copy path).
    pub fn take_cpu_buffer(&mut self) -> Option<crate::io::dma::TypedDmaSlice<crate::io::dma::CpuOwned>> {
        self.buffer.take()
    }

    /// バッファ全体のサイズ（4Kアライン済み）
    pub fn size(&self) -> usize {
        self.alloc_size
    }
}

impl Default for VirtioNetRxDmaBuffer {
    fn default() -> Self {
        Self::new().expect("Failed to allocate VirtIO net RX buffer")
    }
}

/// VirtIO ネットワーク送信用DMAバッファ
pub struct VirtioNetTxDmaBuffer {
    buffer: Option<TypedDmaSlice<CpuOwned>>,
    inflight: Option<(TypedDmaSlice<DeviceOwned>, SliceDmaGuard)>,
    data_len: usize,
    alloc_size: usize,
}

impl VirtioNetTxDmaBuffer {
    /// 送信データからバッファを作成
    pub fn with_data(data: &[u8]) -> Option<Self> {
        let header_size = core::mem::size_of::<VirtioNetHeader>();
        let total_size = header_size + data.len();
        let alloc_size = iommu_align_len(total_size)?;

        let mut buffer = TypedDmaSlice::new(alloc_size)?;

        {
            let slice = buffer.as_mut_slice();
            // VirtIO net header をゼロクリア（初期化済み）
            // slice[..header_size] は既に 0
            // データをコピー
            let data_end = header_size + data.len();
            slice[header_size..data_end].copy_from_slice(data);
        }

        Some(Self {
            buffer: Some(buffer),
            inflight: None,
            data_len: data.len(),
            alloc_size,
        })
    }

    /// 物理アドレスを取得
    pub fn phys_addr(&self) -> Option<PhysAddr> {
        self.buffer
            .as_ref()
            .map(|b| b.phys_addr())
            .or_else(|| self.inflight.as_ref().map(|(b, _)| b.phys_addr()))
    }

    /// DMA転送を開始
    pub fn start_transmit(&mut self) -> Result<u64, &'static str> {
        let buffer = self.buffer.take().ok_or("Buffer already in use")?;
        let phys = buffer.phys_addr().as_u64();
        let (dev, guard) = buffer.start_dma();
        self.inflight = Some((dev, guard));
        Ok(phys)
    }

    /// DMA転送完了
    pub fn complete_transmit(&mut self) -> Result<(), &'static str> {
        let (dev, guard) = self.inflight.take().ok_or("No transmit in progress")?;
        self.buffer = Some(guard.complete(dev));
        Ok(())
    }

    /// 送信データ長
    pub fn data_len(&self) -> usize {
        self.data_len
    }

    /// 合計バッファサイズ（4Kアライン済み）
    pub fn total_size(&self) -> usize {
        self.alloc_size
    }
}

/// コヒーレントDMAバッファを使用したVirtQueue
///
/// VirtQueueの記述子テーブル、Availableリング、Usedリングに使用
pub struct VirtQueueDmaBuffers {
    /// 記述子テーブル
    pub desc_table: CoherentDmaBuffer,
    /// Available リング
    pub avail_ring: CoherentDmaBuffer,
    /// Used リング  
    pub used_ring: CoherentDmaBuffer,
}

impl VirtQueueDmaBuffers {
    /// VirtQueue用のDMAバッファセットを作成
    ///
    /// # Arguments
    /// * `queue_size` - キューサイズ（記述子数）
    pub fn new(queue_size: u16) -> Option<Self> {
        let desc_size = queue_size as usize * 16; // VirtqDesc は 16 バイト
        let avail_size = 6 + queue_size as usize * 2; // header + entries
        let used_size = 6 + queue_size as usize * 8; // header + entries

        let desc_table = CoherentDmaBuffer::new(desc_size, DmaMemoryAttributes::MMIO)?;
        let avail_ring = CoherentDmaBuffer::new(avail_size, DmaMemoryAttributes::MMIO)?;
        let used_ring = CoherentDmaBuffer::new(used_size, DmaMemoryAttributes::FROM_DEVICE)?;

        Some(Self {
            desc_table,
            avail_ring,
            used_ring,
        })
    }

    /// 記述子テーブルの物理アドレス
    pub fn desc_table_addr(&self) -> u64 {
        self.desc_table.phys_addr().as_u64()
    }

    /// Available リングの物理アドレス
    pub fn avail_ring_addr(&self) -> u64 {
        self.avail_ring.phys_addr().as_u64()
    }

    /// Used リングの物理アドレス
    pub fn used_ring_addr(&self) -> u64 {
        self.used_ring.phys_addr().as_u64()
    }
}

