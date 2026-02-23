//! VirtIO GPU ドライバ
//!
//! VirtIO GPUデバイスのサポート (VirtIO Spec 5.7)
//! - 2D レンダリング (ResourceCreate2D, TransferToHost2D, Flush)
//! - ディスプレイ管理 (GetDisplayInfo, SetScanout)
//! - カーソル制御 (UpdateCursor, MoveCursor)
//! - VirtioTransport抽象化によるMMIO/PCI両対応

#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::transport::VirtioTransport; // trait object for transport implementations

pub mod gpu_driver;

// =============================================================================
// 定数
// =============================================================================

/// VirtIO GPU フィーチャービット
mod gpu_impl;
pub use gpu_impl::*;
const VIRTIO_GPU_F_VIRGL: u64 = 1 << 0;
const VIRTIO_GPU_F_EDID: u64 = 1 << 1;
const VIRTIO_GPU_F_RESOURCE_UUID: u64 = 1 << 2;
const VIRTIO_GPU_F_RESOURCE_BLOB: u64 = 1 << 3;

/// キューインデックス
const VIRTQUEUE_CTRL: u16 = 0;
const VIRTQUEUE_CURSOR: u16 = 1;

/// 最大スキャンアウト数
const MAX_SCANOUTS: usize = 16;

/// VirtQueue最大サイズ
const VIRTQUEUE_MAX_SIZE: u16 = 256;

// =============================================================================
// VirtIO Device Status Bits
// =============================================================================

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VirtioDeviceStatus {
    Acknowledge = 1,
    Driver = 2,
    DriverOk = 4,
    FeaturesOk = 8,
    DeviceNeedsReset = 64,
    Failed = 128,
}

// =============================================================================
// VirtQueue Implementation (local, same pattern as balloon.rs)
// =============================================================================

mod vring_flags {
    pub const VRING_DESC_F_NEXT: u16 = 1;
    pub const VRING_DESC_F_WRITE: u16 = 2;
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct VringDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct VringAvail {
    flags: u16,
    idx: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct VringUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
struct VringUsed {
    flags: u16,
    idx: u16,
}

struct VirtQueue {
    queue_size: u16,
    desc_table: *mut VringDesc,
    avail_ring: *mut VringAvail,
    used_ring: *mut VringUsed,
    free_bitmap: AtomicU64,
    last_used_idx: AtomicU32,
    dma_buffer: Option<CoherentDmaBuffer>,
    index: u16,
    notify_addr: Option<u64>,
    notify_is_32bit: bool,
}

unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    unsafe fn new(
        queue_size: u16,
        desc_table: *mut VringDesc,
        avail_ring: *mut VringAvail,
        used_ring: *mut VringUsed,
        dma_buffer: Option<CoherentDmaBuffer>,
        index: u16,
        notify_addr: Option<u64>,
        notify_is_32bit: bool,
    ) -> Self {
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

        Self {
            queue_size,
            desc_table,
            avail_ring,
            used_ring,
            free_bitmap: AtomicU64::new((1u64 << queue_size.min(64)) - 1),
            last_used_idx: AtomicU32::new(0),
            dma_buffer,
            index,
            notify_addr,
            notify_is_32bit,
        }
    }

    fn alloc_desc(&self) -> Option<u16> {
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            if bitmap == 0 {
                return None;
            }
            let idx = bitmap.trailing_zeros() as u16;
            let new_bitmap = bitmap & !(1u64 << idx);
            if self
                .free_bitmap
                .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(idx);
            }
        }
    }

    fn free_desc(&self, idx: u16) {
        loop {
            let bitmap = self.free_bitmap.load(Ordering::Acquire);
            let new_bitmap = bitmap | (1u64 << idx);
            if self
                .free_bitmap
                .compare_exchange(bitmap, new_bitmap, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return;
            }
        }
    }

    unsafe fn submit(&self, head: u16) -> u16 {
        core::sync::atomic::fence(Ordering::Release);
        let avail_idx = unsafe { (*self.avail_ring).idx };
        let ring_ptr = unsafe { (self.avail_ring as *mut u16).add(2) };
        unsafe {
            *ring_ptr.add((avail_idx % self.queue_size) as usize) = head;
        }
        core::sync::atomic::fence(Ordering::Release);
        unsafe {
            (*self.avail_ring).idx = avail_idx.wrapping_add(1);
        }
        self.index
    }

    fn notify(&self) {
        let Some(addr) = self.notify_addr else {
            return;
        };
        if self.notify_is_32bit {
            crate::io::mmio::mmio_write_u32(addr as usize, self.index as u32);
        } else {
            crate::io::mmio::mmio_write_u16(addr as usize, self.index);
        }
    }

    fn poll_completions(&self) -> Option<(u16, u32)> {
        let last_used = self.last_used_idx.load(Ordering::Acquire);
        core::sync::atomic::fence(Ordering::Acquire);
        let used_idx = unsafe { (*self.used_ring).idx } as u32;
        if last_used == used_idx {
            return None;
        }
        let ring_ptr = unsafe { (self.used_ring as *const u8).add(4) as *const VringUsedElem };
        let elem = unsafe { *ring_ptr.add((last_used % self.queue_size as u32) as usize) };
        self.last_used_idx
            .store(last_used.wrapping_add(1), Ordering::Release);
        Some((elem.id as u16, elem.len))
    }
}

// =============================================================================
// エラー
// =============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuError {
    DeviceNotFound,
    InitFailed,
    ResourceNotFound,
    InvalidParameter,
    OutOfMemory,
    DeviceError,
    Timeout,
    NotSupported,
}

pub type GpuResult<T> = Result<T, GpuError>;

// =============================================================================
// GPU コマンド
// =============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuCmd {
    GetDisplayInfo = 0x0100,
    ResourceCreate2D = 0x0101,
    ResourceUnref = 0x0102,
    SetScanout = 0x0103,
    ResourceFlush = 0x0104,
    TransferToHost2D = 0x0105,
    ResourceAttachBacking = 0x0106,
    ResourceDetachBacking = 0x0107,
    GetCapsetInfo = 0x0108,
    GetCapset = 0x0109,
    GetEdid = 0x010A,
    UpdateCursor = 0x0300,
    MoveCursor = 0x0301,
    CtxCreate = 0x0200,
    CtxDestroy = 0x0201,
    CtxAttachResource = 0x0202,
    CtxDetachResource = 0x0203,
    ResourceCreate3D = 0x0204,
    TransferToHost3D = 0x0205,
    TransferFromHost3D = 0x0206,
    Submit3D = 0x0207,
    RespOkNoData = 0x1100,
    RespOkDisplayInfo = 0x1101,
    RespOkCapsetInfo = 0x1102,
    RespOkCapset = 0x1103,
    RespOkEdid = 0x1104,
    RespErrUnspec = 0x1200,
    RespErrOutOfMemory = 0x1201,
    RespErrInvalidScanoutId = 0x1202,
    RespErrInvalidResourceId = 0x1203,
    RespErrInvalidCtxId = 0x1204,
    RespErrInvalidParameter = 0x1205,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct GpuCtrlHdr {
    pub cmd_type: u32,
    pub flags: u32,
    pub fence_id: u64,
    pub ctx_id: u32,
    pub _padding: u32,
}

impl GpuCtrlHdr {
    pub fn new(cmd_type: GpuCmd) -> Self {
        Self {
            cmd_type: cmd_type as u32,
            flags: 0,
            fence_id: 0,
            ctx_id: 0,
            _padding: 0,
        }
    }

    pub fn with_fence(mut self, fence_id: u64) -> Self {
        self.flags |= 1; // VIRTIO_GPU_FLAG_FENCE
        self.fence_id = fence_id;
        self
    }
}

// =============================================================================
// ディスプレイ情報
// =============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn new(x: u32, y: u32, width: u32, height: u32) -> Self {
        Self { x, y, width, height }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DisplayMode {
    pub rect: Rect,
    pub enabled: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct DisplayInfo {
    pub modes: [DisplayMode; MAX_SCANOUTS],
}

// =============================================================================
// リソース
// =============================================================================

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    B8G8R8A8Unorm = 1,
    B8G8R8X8Unorm = 2,
    A8R8G8B8Unorm = 3,
    X8R8G8B8Unorm = 4,
    R8G8B8A8Unorm = 67,
    X8B8G8R8Unorm = 68,
    A8B8G8R8Unorm = 121,
    R8G8B8X8Unorm = 134,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceCreate2D {
    pub hdr: GpuCtrlHdr,
    pub resource_id: u32,
    pub format: u32,
    pub width: u32,
    pub height: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemEntry {
    pub addr: u64,
    pub length: u32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceAttachBacking {
    pub hdr: GpuCtrlHdr,
    pub resource_id: u32,
    pub nr_entries: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TransferToHost2D {
    pub hdr: GpuCtrlHdr,
    pub rect: Rect,
    pub offset: u64,
    pub resource_id: u32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SetScanout {
    pub hdr: GpuCtrlHdr,
    pub rect: Rect,
    pub scanout_id: u32,
    pub resource_id: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceFlush {
    pub hdr: GpuCtrlHdr,
    pub rect: Rect,
    pub resource_id: u32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ResourceUnref {
    pub hdr: GpuCtrlHdr,
    pub resource_id: u32,
    pub _padding: u32,
}

// =============================================================================
// カーソル
// =============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CursorPos {
    pub scanout_id: u32,
    pub x: u32,
    pub y: u32,
    pub _padding: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct UpdateCursor {
    pub hdr: GpuCtrlHdr,
    pub pos: CursorPos,
    pub resource_id: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    pub _padding: u32,
}

// =============================================================================
// フレームバッファ (DMA-backed)
// =============================================================================

pub struct Framebuffer {
    pub resource_id: u32,
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    buffer: CoherentDmaBuffer,
    pub stride: u32,
}

impl Framebuffer {
    pub fn new(resource_id: u32, width: u32, height: u32, format: PixelFormat) -> Option<Self> {
        let bpp = 4u32;
        let stride = width * bpp;
        let size = (stride * height) as usize;

        let buffer = CoherentDmaBuffer::new(size, DmaMemoryAttributes::MMIO)?;

        Some(Self {
            resource_id,
            width,
            height,
            format,
            buffer,
            stride,
        })
    }

    /// IOMMU デバイス向けフレームバッファを作成する。
    pub fn new_for_device(
        resource_id: u32,
        width: u32,
        height: u32,
        format: PixelFormat,
        device_id: &IommuDeviceId,
    ) -> Option<Self> {
        let bpp = 4u32;
        let stride = width * bpp;
        let size = (stride * height) as usize;

        let buffer = CoherentDmaBuffer::new_for_device(size, DmaMemoryAttributes::MMIO, device_id)?;

        Some(Self {
            resource_id,
            width,
            height,
            format,
            buffer,
            stride,
        })
    }

    pub fn set_pixel(&mut self, x: u32, y: u32, color: u32) {
        if x >= self.width || y >= self.height {
            return;
        }
        let offset = ((y * self.stride) + (x * 4)) as usize;
        let buf = unsafe { self.buffer.as_mut_slice() };
        if offset + 4 <= buf.len() {
            buf[offset..offset + 4].copy_from_slice(&color.to_le_bytes());
        }
    }

    pub fn clear(&mut self, color: u32) {
        let bytes = color.to_le_bytes();
        let buf = unsafe { self.buffer.as_mut_slice() };
        for chunk in buf.chunks_exact_mut(4) {
            chunk.copy_from_slice(&bytes);
        }
    }

    pub fn fill_rect(&mut self, rect: &Rect, color: u32) {
        let x_end = (rect.x + rect.width).min(self.width);
        let y_end = (rect.y + rect.height).min(self.height);
        for y in rect.y..y_end {
            for x in rect.x..x_end {
                self.set_pixel(x, y, color);
            }
        }
    }

    pub fn phys_addr(&self) -> x86_64::PhysAddr {
        self.buffer.phys_addr()
    }

    /// ハードウェアに渡すバッファアドレスを返す。
    /// IOMMU マッピングが有効な場合は IOVA、そうでなければ物理アドレスを返す。
    pub fn device_addr(&self) -> u64 {
        self.buffer.device_addr()
    }

    pub fn size(&self) -> usize {
        self.buffer.size()
    }

    pub fn as_ptr(&self) -> *const u8 {
        unsafe { self.buffer.as_slice().as_ptr() }
    }
}

// =============================================================================
// VirtIO GPU デバイス
// =============================================================================

pub struct VirtioGpu {
    transport: Box<dyn VirtioTransport>,
    ctrl_queue: Option<Arc<Mutex<VirtQueue>>>,
    cursor_queue: Option<Arc<Mutex<VirtQueue>>>,
    features: u64,
    next_resource_id: AtomicU32,
    next_fence_id: AtomicU32,
    display_info: RwLock<Option<DisplayInfo>>,
    active_scanouts: RwLock<Vec<u32>>,
    framebuffers: RwLock<Vec<Framebuffer>>,
    initialized: AtomicBool,
    has_3d: bool,
    iommu_device_id: Option<IommuDeviceId>,
}
