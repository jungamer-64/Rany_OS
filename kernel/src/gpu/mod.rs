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
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::transport::{TransportType, VirtioMmioTransport, VirtioTransport};

pub mod gpu_driver;

// =============================================================================
// 定数
// =============================================================================

/// VirtIO GPU フィーチャービット
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

unsafe impl Send for VirtioGpu {}
unsafe impl Sync for VirtioGpu {}

impl VirtioGpu {
    pub fn new(transport: Box<dyn VirtioTransport>) -> Self {
        Self::new_with_device(transport, None)
    }

    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: Option<IommuDeviceId>,
    ) -> Self {
        Self {
            transport,
            ctrl_queue: None,
            cursor_queue: None,
            features: 0,
            next_resource_id: AtomicU32::new(1),
            next_fence_id: AtomicU32::new(1),
            display_info: RwLock::new(None),
            active_scanouts: RwLock::new(Vec::new()),
            framebuffers: RwLock::new(Vec::new()),
            initialized: AtomicBool::new(false),
            has_3d: false,
            iommu_device_id,
        }
    }

    /// IOMMU対応のDMAバッファを割り当てるヘルパー。
    ///
    /// `iommu_device_id` が設定されている場合は `CoherentDmaBuffer::new_for_device()` を
    /// 使い、IOMMU マッピングを自動登録する。設定されていない場合は従来の `new()` に
    /// フォールバックする。
    fn alloc_coherent(
        &self,
        size: usize,
        attrs: DmaMemoryAttributes,
    ) -> Option<CoherentDmaBuffer> {
        match &self.iommu_device_id {
            Some(dev_id) => CoherentDmaBuffer::new_for_device(size, attrs, dev_id),
            None => CoherentDmaBuffer::new(size, attrs),
        }
    }

    /// Initialize the VirtIO GPU device following the standard init sequence.
    ///
    /// # Safety
    /// Caller must ensure the transport's backing MMIO/PCI address is valid.
    pub unsafe fn init(&mut self) -> GpuResult<()> {
        // Step 1: Reset
        self.transport.set_status(0);

        // Step 2: Acknowledge
        self.transport
            .set_status(VirtioDeviceStatus::Acknowledge as u8);

        // Step 3: Driver
        self.transport
            .set_status(VirtioDeviceStatus::Acknowledge as u8 | VirtioDeviceStatus::Driver as u8);

        // Step 4: Negotiate features
        let device_features = self.transport.get_device_features();
        let driver_features = device_features & (VIRTIO_GPU_F_VIRGL | VIRTIO_GPU_F_EDID);
        self.transport.set_driver_features(driver_features);
        self.features = driver_features;
        self.has_3d = (self.features & VIRTIO_GPU_F_VIRGL) != 0;

        // Step 5: Features OK
        self.transport.set_status(
            VirtioDeviceStatus::Acknowledge as u8
                | VirtioDeviceStatus::Driver as u8
                | VirtioDeviceStatus::FeaturesOk as u8,
        );

        let status = self.transport.get_status();
        if (status & VirtioDeviceStatus::FeaturesOk as u8) == 0 {
            self.transport.set_status(VirtioDeviceStatus::Failed as u8);
            return Err(GpuError::InitFailed);
        }

        // Step 6: Setup queues
        self.setup_queue(VIRTQUEUE_CTRL)?;
        self.setup_queue(VIRTQUEUE_CURSOR)?;

        // Step 7: Driver OK
        self.transport.set_status(
            VirtioDeviceStatus::Acknowledge as u8
                | VirtioDeviceStatus::Driver as u8
                | VirtioDeviceStatus::FeaturesOk as u8
                | VirtioDeviceStatus::DriverOk as u8,
        );

        // Fetch display info
        self.refresh_display_info()?;

        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    fn setup_queue(&mut self, queue_idx: u16) -> GpuResult<()> {
        self.transport.select_queue(queue_idx);
        let max_size = self.transport.get_queue_max_size();
        if max_size == 0 {
            return Err(GpuError::InitFailed);
        }

        let queue_size = max_size.min(VIRTQUEUE_MAX_SIZE);
        let notify_addr = self.transport.get_notify_addr(queue_idx);
        let notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);

        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize;
        let used_size = 6 + 8 * queue_size as usize;
        let used_align = core::mem::align_of::<VringUsed>();
        let used_offset = align_up(desc_size + avail_size, used_align);
        let total_size = used_offset + used_size;

        let buffer = self.alloc_coherent(total_size, DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;

        let dev_base = buffer.device_addr();
        let ptr = unsafe { buffer.as_slice().as_ptr() } as *mut u8;

        let desc_table = ptr as *mut VringDesc;
        let avail_ring = unsafe { ptr.add(desc_size) as *mut VringAvail };
        let used_ring = unsafe { ptr.add(used_offset) as *mut VringUsed };

        self.transport.set_queue_size(queue_size);
        self.transport.set_queue_desc_addr(dev_base);
        self.transport
            .set_queue_avail_addr(dev_base + desc_size as u64);
        self.transport
            .set_queue_used_addr(dev_base + used_offset as u64);

        self.transport.enable_queue();

        let virtqueue = unsafe {
            VirtQueue::new(
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                Some(buffer),
                queue_idx,
                notify_addr,
                notify_is_32bit,
            )
        };

        match queue_idx {
            VIRTQUEUE_CTRL => self.ctrl_queue = Some(Arc::new(Mutex::new(virtqueue))),
            VIRTQUEUE_CURSOR => self.cursor_queue = Some(Arc::new(Mutex::new(virtqueue))),
            _ => {}
        }

        Ok(())
    }

    // =========================================================================
    // Command submission
    // =========================================================================

    /// Send a raw command to the controlq and synchronously wait for response.
    ///
    /// Returns the response DMA buffer (caller reads the response from it).
    fn send_command_raw(
        &self,
        req_bytes: &[u8],
        resp_size: usize,
    ) -> GpuResult<CoherentDmaBuffer> {
        let queue = self.ctrl_queue.as_ref().ok_or(GpuError::InitFailed)?;
        let queue_guard = queue.lock();

        let mut req_buf = self.alloc_coherent(req_bytes.len(), DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;
        let resp_buf = self.alloc_coherent(resp_size, DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;

        unsafe {
            req_buf.as_mut_slice()[..req_bytes.len()].copy_from_slice(req_bytes);
        }

        let desc0 = queue_guard.alloc_desc().ok_or(GpuError::OutOfMemory)?;
        let desc1 = queue_guard.alloc_desc().ok_or_else(|| {
            queue_guard.free_desc(desc0);
            GpuError::OutOfMemory
        })?;

        unsafe {
            (*queue_guard.desc_table.add(desc0 as usize)) = VringDesc {
                addr: req_buf.device_addr(),
                len: req_bytes.len() as u32,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc1,
            };
            (*queue_guard.desc_table.add(desc1 as usize)) = VringDesc {
                addr: resp_buf.device_addr(),
                len: resp_size as u32,
                flags: vring_flags::VRING_DESC_F_WRITE,
                next: 0,
            };
            queue_guard.submit(desc0);
        }

        queue_guard.notify();

        // Poll for completion (synchronous)
        loop {
            if let Some((_id, _len)) = queue_guard.poll_completions() {
                queue_guard.free_desc(desc0);
                queue_guard.free_desc(desc1);
                break;
            }
            core::hint::spin_loop();
        }

        Ok(resp_buf)
    }

    /// Send a typed command struct and expect a GpuCtrlHdr response.
    fn send_command<Req: Copy>(&self, req: &Req) -> GpuResult<GpuCtrlHdr> {
        let req_bytes = unsafe {
            core::slice::from_raw_parts(
                req as *const Req as *const u8,
                core::mem::size_of::<Req>(),
            )
        };
        let resp_buf =
            self.send_command_raw(req_bytes, core::mem::size_of::<GpuCtrlHdr>())?;
        let hdr = unsafe {
            core::ptr::read_volatile(resp_buf.as_slice().as_ptr() as *const GpuCtrlHdr)
        };
        if hdr.cmd_type >= GpuCmd::RespErrUnspec as u32 {
            return Err(GpuError::DeviceError);
        }
        Ok(hdr)
    }

    /// Send a cursor command to the cursor queue.
    fn send_cursor_command<Req: Copy>(&self, req: &Req) -> GpuResult<()> {
        let queue = self.cursor_queue.as_ref().ok_or(GpuError::InitFailed)?;
        let queue_guard = queue.lock();

        let req_size = core::mem::size_of::<Req>();
        let mut req_buf = self.alloc_coherent(req_size, DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;

        unsafe {
            let src = core::slice::from_raw_parts(req as *const Req as *const u8, req_size);
            req_buf.as_mut_slice()[..req_size].copy_from_slice(src);
        }

        let desc0 = queue_guard.alloc_desc().ok_or(GpuError::OutOfMemory)?;

        unsafe {
            (*queue_guard.desc_table.add(desc0 as usize)) = VringDesc {
                addr: req_buf.device_addr(),
                len: req_size as u32,
                flags: 0,
                next: 0,
            };
            queue_guard.submit(desc0);
        }

        queue_guard.notify();

        // Poll for completion
        loop {
            if let Some((_id, _len)) = queue_guard.poll_completions() {
                queue_guard.free_desc(desc0);
                break;
            }
            core::hint::spin_loop();
        }

        Ok(())
    }

    /// Send a command with an extra data buffer (3-descriptor chain).
    /// Used by attach_backing which needs: header + entries array + response.
    fn send_command_with_data(
        &self,
        req_bytes: &[u8],
        data_bytes: &[u8],
        resp_size: usize,
    ) -> GpuResult<CoherentDmaBuffer> {
        let queue = self.ctrl_queue.as_ref().ok_or(GpuError::InitFailed)?;
        let queue_guard = queue.lock();

        let mut req_buf = self.alloc_coherent(req_bytes.len(), DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;
        let mut data_buf = self.alloc_coherent(data_bytes.len(), DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;
        let resp_buf = self.alloc_coherent(resp_size, DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;

        unsafe {
            req_buf.as_mut_slice()[..req_bytes.len()].copy_from_slice(req_bytes);
            data_buf.as_mut_slice()[..data_bytes.len()].copy_from_slice(data_bytes);
        }

        let desc0 = queue_guard.alloc_desc().ok_or(GpuError::OutOfMemory)?;
        let desc1 = queue_guard.alloc_desc().ok_or_else(|| {
            queue_guard.free_desc(desc0);
            GpuError::OutOfMemory
        })?;
        let desc2 = queue_guard.alloc_desc().ok_or_else(|| {
            queue_guard.free_desc(desc0);
            queue_guard.free_desc(desc1);
            GpuError::OutOfMemory
        })?;

        unsafe {
            (*queue_guard.desc_table.add(desc0 as usize)) = VringDesc {
                addr: req_buf.device_addr(),
                len: req_bytes.len() as u32,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc1,
            };
            (*queue_guard.desc_table.add(desc1 as usize)) = VringDesc {
                addr: data_buf.device_addr(),
                len: data_bytes.len() as u32,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc2,
            };
            (*queue_guard.desc_table.add(desc2 as usize)) = VringDesc {
                addr: resp_buf.device_addr(),
                len: resp_size as u32,
                flags: vring_flags::VRING_DESC_F_WRITE,
                next: 0,
            };
            queue_guard.submit(desc0);
        }

        queue_guard.notify();

        loop {
            if let Some((_id, _len)) = queue_guard.poll_completions() {
                queue_guard.free_desc(desc0);
                queue_guard.free_desc(desc1);
                queue_guard.free_desc(desc2);
                break;
            }
            core::hint::spin_loop();
        }

        Ok(resp_buf)
    }

    // =========================================================================
    // GPU Operations
    // =========================================================================

    fn alloc_resource_id(&self) -> u32 {
        self.next_resource_id.fetch_add(1, Ordering::SeqCst)
    }

    fn alloc_fence_id(&self) -> u32 {
        self.next_fence_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Get display information from the device.
    fn refresh_display_info(&self) -> GpuResult<()> {
        let hdr = GpuCtrlHdr::new(GpuCmd::GetDisplayInfo);
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(
                &hdr as *const GpuCtrlHdr as *const u8,
                core::mem::size_of::<GpuCtrlHdr>(),
            )
        };

        // Response: GpuCtrlHdr + DisplayInfo
        let resp_size =
            core::mem::size_of::<GpuCtrlHdr>() + core::mem::size_of::<DisplayInfo>();
        let resp_buf = self.send_command_raw(hdr_bytes, resp_size)?;

        let resp_slice = unsafe { resp_buf.as_slice() };
        let resp_hdr =
            unsafe { core::ptr::read_volatile(resp_slice.as_ptr() as *const GpuCtrlHdr) };

        if resp_hdr.cmd_type != GpuCmd::RespOkDisplayInfo as u32 {
            return Err(GpuError::DeviceError);
        }

        // Parse DisplayInfo from offset after GpuCtrlHdr
        let info_offset = core::mem::size_of::<GpuCtrlHdr>();
        if resp_slice.len() >= info_offset + core::mem::size_of::<DisplayInfo>() {
            let info = unsafe {
                core::ptr::read_volatile(
                    resp_slice.as_ptr().add(info_offset) as *const DisplayInfo,
                )
            };
            *self.display_info.write() = Some(info);
        }

        Ok(())
    }

    pub fn get_display_info(&self) -> GpuResult<DisplayInfo> {
        if let Some(info) = self.display_info.read().clone() {
            return Ok(info);
        }
        self.refresh_display_info()?;
        self.display_info
            .read()
            .clone()
            .ok_or(GpuError::DeviceError)
    }

    pub fn create_resource_2d(
        &self,
        width: u32,
        height: u32,
        format: PixelFormat,
    ) -> GpuResult<u32> {
        let resource_id = self.alloc_resource_id();
        let req = ResourceCreate2D {
            hdr: GpuCtrlHdr::new(GpuCmd::ResourceCreate2D),
            resource_id,
            format: format as u32,
            width,
            height,
        };
        self.send_command(&req)?;
        Ok(resource_id)
    }

    pub fn unref_resource(&self, resource_id: u32) -> GpuResult<()> {
        let req = ResourceUnref {
            hdr: GpuCtrlHdr::new(GpuCmd::ResourceUnref),
            resource_id,
            _padding: 0,
        };
        self.send_command(&req)?;
        Ok(())
    }

    /// Attach backing memory (DMA buffer) to a resource.
    pub fn attach_backing(&self, resource_id: u32, phys_addr: u64, size: u32) -> GpuResult<()> {
        let req = ResourceAttachBacking {
            hdr: GpuCtrlHdr::new(GpuCmd::ResourceAttachBacking),
            resource_id,
            nr_entries: 1,
        };
        let entry = MemEntry {
            addr: phys_addr,
            length: size,
            _padding: 0,
        };

        let req_bytes = unsafe {
            core::slice::from_raw_parts(
                &req as *const ResourceAttachBacking as *const u8,
                core::mem::size_of::<ResourceAttachBacking>(),
            )
        };
        let entry_bytes = unsafe {
            core::slice::from_raw_parts(
                &entry as *const MemEntry as *const u8,
                core::mem::size_of::<MemEntry>(),
            )
        };

        let resp_buf = self.send_command_with_data(
            req_bytes,
            entry_bytes,
            core::mem::size_of::<GpuCtrlHdr>(),
        )?;

        let hdr = unsafe {
            core::ptr::read_volatile(resp_buf.as_slice().as_ptr() as *const GpuCtrlHdr)
        };
        if hdr.cmd_type >= GpuCmd::RespErrUnspec as u32 {
            return Err(GpuError::DeviceError);
        }
        Ok(())
    }

    pub fn transfer_to_host_2d(
        &self,
        resource_id: u32,
        rect: &Rect,
        offset: u64,
    ) -> GpuResult<()> {
        let req = TransferToHost2D {
            hdr: GpuCtrlHdr::new(GpuCmd::TransferToHost2D),
            rect: *rect,
            offset,
            resource_id,
            _padding: 0,
        };
        self.send_command(&req)?;
        Ok(())
    }

    pub fn set_scanout(&self, scanout_id: u32, resource_id: u32, rect: &Rect) -> GpuResult<()> {
        let req = SetScanout {
            hdr: GpuCtrlHdr::new(GpuCmd::SetScanout),
            rect: *rect,
            scanout_id,
            resource_id,
        };
        self.send_command(&req)?;
        self.active_scanouts.write().push(scanout_id);
        Ok(())
    }

    pub fn flush(&self, resource_id: u32, rect: &Rect) -> GpuResult<()> {
        let req = ResourceFlush {
            hdr: GpuCtrlHdr::new(GpuCmd::ResourceFlush),
            rect: *rect,
            resource_id,
            _padding: 0,
        };
        self.send_command(&req)?;
        Ok(())
    }

    /// Create a framebuffer with DMA-backed memory and attach it to a GPU resource.
    pub fn create_framebuffer(&self, width: u32, height: u32) -> GpuResult<u32> {
        let format = PixelFormat::B8G8R8A8Unorm;
        let resource_id = self.create_resource_2d(width, height, format)?;

        let fb = match &self.iommu_device_id {
            Some(dev_id) => Framebuffer::new_for_device(resource_id, width, height, format, dev_id),
            None => Framebuffer::new(resource_id, width, height, format),
        }
        .ok_or(GpuError::OutOfMemory)?;

        // Attach the DMA buffer as backing memory
        self.attach_backing(resource_id, fb.device_addr(), fb.size() as u32)?;

        self.framebuffers.write().push(fb);
        Ok(resource_id)
    }

    /// Present a framebuffer: transfer to host then flush.
    pub fn present(&self, resource_id: u32) -> GpuResult<()> {
        let fbs = self.framebuffers.read();
        let fb = fbs
            .iter()
            .find(|fb| fb.resource_id == resource_id)
            .ok_or(GpuError::ResourceNotFound)?;

        let rect = Rect::new(0, 0, fb.width, fb.height);
        drop(fbs);

        self.transfer_to_host_2d(resource_id, &rect, 0)?;
        self.flush(resource_id, &rect)?;
        Ok(())
    }

    pub fn update_cursor(
        &self,
        resource_id: u32,
        scanout_id: u32,
        x: u32,
        y: u32,
        hot_x: u32,
        hot_y: u32,
    ) -> GpuResult<()> {
        let req = UpdateCursor {
            hdr: GpuCtrlHdr::new(GpuCmd::UpdateCursor),
            pos: CursorPos {
                scanout_id,
                x,
                y,
                _padding: 0,
            },
            resource_id,
            hot_x,
            hot_y,
            _padding: 0,
        };
        self.send_cursor_command(&req)
    }

    pub fn move_cursor(&self, scanout_id: u32, x: u32, y: u32) -> GpuResult<()> {
        let req = UpdateCursor {
            hdr: GpuCtrlHdr::new(GpuCmd::MoveCursor),
            pos: CursorPos {
                scanout_id,
                x,
                y,
                _padding: 0,
            },
            resource_id: 0,
            hot_x: 0,
            hot_y: 0,
            _padding: 0,
        };
        self.send_cursor_command(&req)
    }

    pub fn handle_interrupt(&self) {
        let status = self.transport.get_interrupt_status();
        self.transport.ack_interrupt(status);
        // Synchronous GPU: completions are handled inline in send_command.
        // This handler is for interrupt-driven mode (future enhancement).
    }

    pub fn has_3d_support(&self) -> bool {
        self.has_3d
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Relaxed)
    }
}

// =============================================================================
// グラフィックスマネージャ
// =============================================================================

pub struct GraphicsManager {
    gpu: Mutex<Option<VirtioGpu>>,
    primary_scanout: AtomicU32,
    primary_framebuffer: AtomicU32,
}

impl GraphicsManager {
    pub const fn new() -> Self {
        Self {
            gpu: Mutex::new(None),
            primary_scanout: AtomicU32::new(0),
            primary_framebuffer: AtomicU32::new(0),
        }
    }

    pub fn init(&self, transport: Box<dyn VirtioTransport>) -> GpuResult<()> {
        let mut gpu = VirtioGpu::new(transport);
        unsafe { gpu.init()? };

        let display_info = gpu.get_display_info()?;
        if let Some(mode) = display_info.modes.iter().find(|m| m.enabled != 0) {
            let fb_id = gpu.create_framebuffer(mode.rect.width, mode.rect.height)?;
            gpu.set_scanout(0, fb_id, &mode.rect)?;
            self.primary_framebuffer.store(fb_id, Ordering::SeqCst);
        }

        *self.gpu.lock() = Some(gpu);
        Ok(())
    }

    pub fn clear(&self, color: u32) -> GpuResult<()> {
        let mut gpu_guard = self.gpu.lock();
        let gpu = gpu_guard.as_mut().ok_or(GpuError::DeviceNotFound)?;
        let fb_id = self.primary_framebuffer.load(Ordering::Relaxed);

        {
            let mut fbs = gpu.framebuffers.write();
            if let Some(fb) = fbs.iter_mut().find(|fb| fb.resource_id == fb_id) {
                fb.clear(color);
            }
        }

        gpu.present(fb_id)?;
        Ok(())
    }

    pub fn present(&self) -> GpuResult<()> {
        let gpu_guard = self.gpu.lock();
        let gpu = gpu_guard.as_ref().ok_or(GpuError::DeviceNotFound)?;
        let fb_id = self.primary_framebuffer.load(Ordering::Relaxed);
        gpu.present(fb_id)
    }
}

// =============================================================================
// グローバルインスタンス
// =============================================================================

static GRAPHICS_MANAGER: spin::Once<GraphicsManager> = spin::Once::new();

pub fn graphics_manager() -> &'static GraphicsManager {
    GRAPHICS_MANAGER.call_once(GraphicsManager::new)
}

/// Global VirtIO GPU device instance
static VIRTIO_GPU_DEVICE: Mutex<Option<Arc<VirtioGpu>>> = Mutex::new(None);

/// Initialize the global VirtIO GPU device.
///
/// # Safety
/// Caller must ensure the transport's backing address is valid.
pub unsafe fn init_virtio_gpu(transport: Box<dyn VirtioTransport>) -> GpuResult<()> {
    let mut gpu = VirtioGpu::new(transport);
    unsafe { gpu.init()? };
    *VIRTIO_GPU_DEVICE.lock() = Some(Arc::new(gpu));
    Ok(())
}

/// Initialize the global VirtIO GPU device with an IOMMU device ID.
///
/// # Safety
/// Caller must ensure the transport's backing address is valid.
pub unsafe fn init_virtio_gpu_for_device(
    transport: Box<dyn VirtioTransport>,
    iommu_device_id: IommuDeviceId,
) -> GpuResult<()> {
    let mut gpu = VirtioGpu::new_with_device(transport, Some(iommu_device_id));
    unsafe { gpu.init()? };
    *VIRTIO_GPU_DEVICE.lock() = Some(Arc::new(gpu));
    Ok(())
}

/// Handle VirtIO GPU interrupt.
pub fn handle_virtio_gpu_interrupt() {
    if let Some(device) = VIRTIO_GPU_DEVICE.lock().as_ref() {
        device.handle_interrupt();
    }
}

/// Get a clone of the global VirtIO GPU device Arc if initialized.
pub fn get_virtio_gpu_device() -> Option<Arc<VirtioGpu>> {
    VIRTIO_GPU_DEVICE.lock().as_ref().cloned()
}

/// Initialize via GraphicsManager.
pub fn init(transport: Box<dyn VirtioTransport>) -> GpuResult<()> {
    graphics_manager().init(transport)
}

fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::virtio::{TransportType, VirtioDeviceType, VirtioTransport};

    struct NoopTransport;

    impl VirtioTransport for NoopTransport {
        fn device_type(&self) -> VirtioDeviceType {
            VirtioDeviceType::Gpu
        }
        fn get_status(&self) -> u8 {
            VirtioDeviceStatus::Acknowledge as u8
                | VirtioDeviceStatus::Driver as u8
                | VirtioDeviceStatus::FeaturesOk as u8
        }
        fn set_status(&mut self, _status: u8) {}
        fn get_device_features_low(&self) -> u32 {
            0
        }
        fn get_device_features_high(&self) -> u32 {
            0
        }
        fn set_driver_features_low(&mut self, _features: u32) {}
        fn set_driver_features_high(&mut self, _features: u32) {}
        fn get_num_queues(&self) -> u16 {
            2
        }
        fn select_queue(&mut self, _queue_index: u16) {}
        fn get_queue_max_size(&self) -> u16 {
            VIRTQUEUE_MAX_SIZE
        }
        fn set_queue_size(&mut self, _size: u16) {}
        fn is_queue_ready(&self) -> bool {
            false
        }
        fn enable_queue(&mut self) {}
        fn disable_queue(&mut self) {}
        fn set_queue_desc_addr(&mut self, _addr: u64) {}
        fn set_queue_avail_addr(&mut self, _addr: u64) {}
        fn set_queue_used_addr(&mut self, _addr: u64) {}
        fn notify_queue(&mut self, _queue_index: u16) {}
        fn get_notify_addr(&mut self, _queue_index: u16) -> Option<u64> {
            None
        }
        fn get_interrupt_status(&self) -> u32 {
            0
        }
        fn ack_interrupt(&self, _status: u32) {}
        fn read_config_u8(&self, _offset: usize) -> u8 {
            0
        }
        fn read_config_u16(&self, _offset: usize) -> u16 {
            0
        }
        fn read_config_u32(&self, _offset: usize) -> u32 {
            0
        }
        fn write_config_u8(&mut self, _offset: usize, _value: u8) {}
        fn write_config_u16(&mut self, _offset: usize, _value: u16) {}
        fn write_config_u32(&mut self, _offset: usize, _value: u32) {}
        fn transport_type(&self) -> TransportType {
            TransportType::Mmio
        }
    }

    #[test_case]
    fn test_gpu_device_creation() {
        let gpu = VirtioGpu::new(Box::new(NoopTransport));
        assert!(!gpu.is_initialized());
        assert!(!gpu.has_3d_support());
    }

    #[test_case]
    fn test_gpu_alloc_resource_id() {
        let gpu = VirtioGpu::new(Box::new(NoopTransport));
        assert_eq!(gpu.alloc_resource_id(), 1);
        assert_eq!(gpu.alloc_resource_id(), 2);
        assert_eq!(gpu.alloc_resource_id(), 3);
    }

    #[test_case]
    fn test_gpu_alloc_fence_id() {
        let gpu = VirtioGpu::new(Box::new(NoopTransport));
        assert_eq!(gpu.alloc_fence_id(), 1);
        assert_eq!(gpu.alloc_fence_id(), 2);
    }

    #[test_case]
    fn test_gpu_ctrl_hdr_new() {
        let hdr = GpuCtrlHdr::new(GpuCmd::GetDisplayInfo);
        assert_eq!(hdr.cmd_type, GpuCmd::GetDisplayInfo as u32);
        assert_eq!(hdr.flags, 0);
        assert_eq!(hdr.fence_id, 0);
    }

    #[test_case]
    fn test_gpu_ctrl_hdr_with_fence() {
        let hdr = GpuCtrlHdr::new(GpuCmd::ResourceFlush).with_fence(42);
        assert_eq!(hdr.flags, 1);
        assert_eq!(hdr.fence_id, 42);
    }

    #[test_case]
    fn test_rect_new() {
        let r = Rect::new(10, 20, 640, 480);
        assert_eq!(r.x, 10);
        assert_eq!(r.y, 20);
        assert_eq!(r.width, 640);
        assert_eq!(r.height, 480);
    }

    #[test_case]
    fn test_gpu_error_variants() {
        assert_ne!(GpuError::DeviceNotFound, GpuError::InitFailed);
        assert_ne!(GpuError::OutOfMemory, GpuError::DeviceError);
    }

    #[test_case]
    fn test_align_up() {
        assert_eq!(align_up(0, 4), 0);
        assert_eq!(align_up(1, 4), 4);
        assert_eq!(align_up(4, 4), 4);
        assert_eq!(align_up(5, 4), 8);
        assert_eq!(align_up(4096, 4096), 4096);
        assert_eq!(align_up(4097, 4096), 8192);
    }

    #[test_case]
    fn test_pixel_format_values() {
        assert_eq!(PixelFormat::B8G8R8A8Unorm as u32, 1);
        assert_eq!(PixelFormat::R8G8B8A8Unorm as u32, 67);
    }
}
