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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::{Mutex, RwLock};
use virtio_driver::defs::{
    VRING_USED_ALIGN, VringAvailHeader as VringAvail, VringDesc,
    VringUsedHeader as VringUsed, vring_flags,
};

use crate::io::dma::{CoherentDmaBuffer, DmaMemoryAttributes};
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use crate::io::virtio::transport::VirtioTransport; // trait object for transport implementations

pub mod gpu_driver;
pub mod gpu_impl;

use virtio_driver::gpu::*;

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
    ctrl_queue: Option<Arc<Mutex<crate::io::virtio::virtqueue::VirtQueue>>>,
    cursor_queue: Option<Arc<Mutex<crate::io::virtio::virtqueue::VirtQueue>>>,
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
