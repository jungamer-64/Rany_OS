// ============================================================================
// drivers/virtio/src/gpu/mod.rs - VirtIO GPU driver
// ============================================================================

use crate::defs::{
    VRING_USED_ALIGN, VringAvailHeader as VringAvail, VringDesc, VringUsedHeader as VringUsed,
    status, vring_flags,
};
use crate::dma::{VirtioDmaBuffer, alloc_dma_buffer};
use crate::transport::{TransportType, VirtioTransport};
use crate::virtqueue::VirtQueue;
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use graphic_types::{Color, PixelFormat as GraphicsPixelFormat};
use kernel_api::abi::driver::PackedPciLocation;
use kernel_api::dma::{CpuOwned, DmaSlice};
use spin::{Mutex, Once, RwLock};

pub mod defs;
pub mod driver;
#[cfg(test)]
mod tests;

pub use defs::*;
pub use driver::VirtioGpuDriver;

/// Display mode description shared with kernel graphics code.
#[derive(Debug, Clone, Copy)]
pub struct DisplayMode {
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub bpp: u8,
    pub format: GraphicsPixelFormat,
}

/// Dirty rectangle for flush/present paths.
#[derive(Debug, Clone, Copy)]
pub struct DamagedRegion {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

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

/// Runtime hooks required by a portable VirtIO GPU implementation.
pub trait GpuRuntime: Send + Sync {
    fn alloc_dma(&self, size: usize) -> Result<DmaSlice<CpuOwned>, GpuError>;
    fn log(&self, level: log::Level, msg: core::fmt::Arguments);
}

/// Common color constants used by the graphics stack.
pub mod colors {
    use super::Color;

    pub const BLACK: Color = Color::new(0, 0, 0);
    pub const WHITE: Color = Color::new(255, 255, 255);
    pub const RED: Color = Color::new(255, 0, 0);
    pub const GREEN: Color = Color::new(0, 255, 0);
    pub const BLUE: Color = Color::new(0, 0, 255);
}

const GPU_QUEUE_WAIT_SPINS: usize = 1_000_000;
const GPU_QUEUE_WAIT_WARN_INTERVAL: usize = 250_000;

fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

fn wait_for_queue_completion(queue_name: &str, queue: &mut VirtQueue) -> GpuResult<()> {
    for spin in 0..GPU_QUEUE_WAIT_SPINS {
        if queue.poll_complete().is_some() {
            return Ok(());
        }
        if spin > 0 && (spin % GPU_QUEUE_WAIT_WARN_INTERVAL) == 0 {
            log::warn!(
                target: "virtio_gpu",
                "timed wait still pending on {} queue after {} spins",
                queue_name,
                spin
            );
        }
        core::hint::spin_loop();
    }

    log::error!(
        target: "virtio_gpu",
        "timed out waiting for {} queue completion after {} spins; leaving descriptors owned by device",
        queue_name,
        GPU_QUEUE_WAIT_SPINS
    );
    Err(GpuError::Timeout)
}

pub struct Framebuffer {
    pub resource_id: u32,
    pub width: u32,
    pub height: u32,
    pub format: PixelFormat,
    buffer: VirtioDmaBuffer,
    pub stride: u32,
}

impl Framebuffer {
    pub fn new_for_device(
        resource_id: u32,
        width: u32,
        height: u32,
        format: PixelFormat,
        pci_locator: PackedPciLocation,
    ) -> Option<Self> {
        let bpp = 4u32;
        let stride = width * bpp;
        let size = (stride * height) as usize;
        let buffer = alloc_dma_buffer(size, pci_locator)?;

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
        let buf = self.buffer.as_slice_mut();
        if offset + 4 <= buf.len() {
            buf[offset..offset + 4].copy_from_slice(&color.to_le_bytes());
        }
    }

    pub fn clear(&mut self, color: u32) {
        let bytes = color.to_le_bytes();
        let buf = self.buffer.as_slice_mut();
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

    pub fn device_addr(&self) -> u64 {
        self.buffer.device_address()
    }

    pub fn size(&self) -> usize {
        self.buffer.size()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr() as *const u8
    }
}

pub struct VirtioGpu {
    transport: Box<dyn VirtioTransport>,
    ctrl_queue: Option<Arc<Mutex<VirtQueue>>>,
    cursor_queue: Option<Arc<Mutex<VirtQueue>>>,
    features: u64,
    next_resource_id: AtomicU32,
    next_fence_id: AtomicU32,
    display_info: RwLock<Option<defs::DisplayInfo>>,
    active_scanouts: RwLock<Vec<u32>>,
    framebuffers: RwLock<Vec<Framebuffer>>,
    initialized: AtomicBool,
    has_3d: bool,
    pci_locator: PackedPciLocation,
}

unsafe impl Send for VirtioGpu {}
unsafe impl Sync for VirtioGpu {}

impl VirtioGpu {
    pub fn new(transport: Box<dyn VirtioTransport>, pci_locator: PackedPciLocation) -> Self {
        Self::new_with_device(transport, pci_locator)
    }

    pub fn new_with_device(
        transport: Box<dyn VirtioTransport>,
        pci_locator: PackedPciLocation,
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
            pci_locator,
        }
    }

    fn alloc_coherent(&self, size: usize) -> Option<VirtioDmaBuffer> {
        alloc_dma_buffer(size, self.pci_locator)
    }

    /// Caller must ensure the transport mapping is valid.
    pub unsafe fn init(&mut self) -> GpuResult<()> {
        self.transport.reset();
        self.transport.add_status(status::VIRTIO_STATUS_ACKNOWLEDGE);
        self.transport.add_status(status::VIRTIO_STATUS_DRIVER);

        let device_features = self.transport.get_device_features();
        let driver_features = device_features & (VIRTIO_GPU_F_VIRGL | VIRTIO_GPU_F_EDID);
        self.transport.set_driver_features(driver_features);
        self.features = driver_features;
        self.has_3d = (self.features & VIRTIO_GPU_F_VIRGL) != 0;

        self.transport.add_status(status::VIRTIO_STATUS_FEATURES_OK);
        if (self.transport.get_status() & status::VIRTIO_STATUS_FEATURES_OK) == 0 {
            self.transport.add_status(status::VIRTIO_STATUS_FAILED);
            return Err(GpuError::InitFailed);
        }

        self.setup_queue(VIRTQUEUE_CTRL)?;
        self.setup_queue(VIRTQUEUE_CURSOR)?;

        self.transport.add_status(status::VIRTIO_STATUS_DRIVER_OK);
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

        let queue_size = max_size.min(crate::VIRTQUEUE_MAX_SIZE);
        let _notify_is_32bit = matches!(self.transport.transport_type(), TransportType::Mmio);

        let desc_size = core::mem::size_of::<VringDesc>() * queue_size as usize;
        let avail_size = 6 + 2 * queue_size as usize;
        let used_size = 6 + 8 * queue_size as usize;
        let used_offset = align_up(desc_size + avail_size, VRING_USED_ALIGN);
        let total_size = used_offset + used_size;

        let buffer = self.alloc_coherent(total_size).ok_or(GpuError::OutOfMemory)?;
        let dev_base = buffer.device_address();
        let ptr = buffer.as_ptr();
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
                queue_idx,
                queue_size,
                desc_table,
                avail_ring,
                used_ring,
                Some(buffer),
                self.features,
            )
        }
        .map_err(|_| GpuError::InitFailed)?;

        match queue_idx {
            VIRTQUEUE_CTRL => self.ctrl_queue = Some(Arc::new(Mutex::new(virtqueue))),
            VIRTQUEUE_CURSOR => self.cursor_queue = Some(Arc::new(Mutex::new(virtqueue))),
            _ => {}
        }

        Ok(())
    }

    fn send_command_raw(&self, req_bytes: &[u8], resp_size: usize) -> GpuResult<VirtioDmaBuffer> {
        let queue = self.ctrl_queue.as_ref().ok_or(GpuError::InitFailed)?;
        let mut queue_guard = queue.lock();

        let mut req_buf = self
            .alloc_coherent(req_bytes.len())
            .ok_or(GpuError::OutOfMemory)?;
        let resp_buf = self.alloc_coherent(resp_size).ok_or(GpuError::OutOfMemory)?;
        req_buf.as_slice_mut()[..req_bytes.len()].copy_from_slice(req_bytes);

        let desc0 = queue_guard.alloc_desc().ok_or(GpuError::OutOfMemory)?;
        let desc1 = queue_guard.alloc_desc().ok_or_else(|| {
            queue_guard.free_desc(desc0);
            GpuError::OutOfMemory
        })?;

        unsafe {
            (*queue_guard.desc_table_ptr().add(desc0 as usize)) = VringDesc {
                addr: req_buf.device_address(),
                len: req_bytes.len() as u32,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc1,
            };
            (*queue_guard.desc_table_ptr().add(desc1 as usize)) = VringDesc {
                addr: resp_buf.device_address(),
                len: resp_size as u32,
                flags: vring_flags::VRING_DESC_F_WRITE,
                next: 0,
            };
        }
        queue_guard.submit(desc0);
        queue_guard.notify(self.transport.as_ref());

        if let Err(err) = wait_for_queue_completion("control", &mut queue_guard) {
            core::mem::forget(req_buf);
            core::mem::forget(resp_buf);
            return Err(err);
        }

        queue_guard.free_desc_chain(desc0);
        Ok(resp_buf)
    }

    fn send_command<Req: Copy>(&self, req: &Req) -> GpuResult<GpuCtrlHdr> {
        let req_bytes = unsafe {
            core::slice::from_raw_parts(req as *const Req as *const u8, core::mem::size_of::<Req>())
        };
        let resp_buf = self.send_command_raw(req_bytes, core::mem::size_of::<GpuCtrlHdr>())?;
        let hdr = unsafe { core::ptr::read_volatile(resp_buf.as_slice().as_ptr() as *const GpuCtrlHdr) };
        if hdr.cmd_type >= GpuCmd::RespErrUnspec as u32 {
            return Err(GpuError::DeviceError);
        }
        Ok(hdr)
    }

    fn send_cursor_command<Req: Copy>(&self, req: &Req) -> GpuResult<()> {
        let queue = self.cursor_queue.as_ref().ok_or(GpuError::InitFailed)?;
        let mut queue_guard = queue.lock();

        let req_size = core::mem::size_of::<Req>();
        let mut req_buf = self.alloc_coherent(req_size).ok_or(GpuError::OutOfMemory)?;
        let src = unsafe { core::slice::from_raw_parts(req as *const Req as *const u8, req_size) };
        req_buf.as_slice_mut()[..req_size].copy_from_slice(src);

        let desc0 = queue_guard.alloc_desc().ok_or(GpuError::OutOfMemory)?;
        unsafe {
            (*queue_guard.desc_table_ptr().add(desc0 as usize)) = VringDesc {
                addr: req_buf.device_address(),
                len: req_size as u32,
                flags: 0,
                next: 0,
            };
        }
        queue_guard.submit(desc0);
        queue_guard.notify(self.transport.as_ref());

        if let Err(err) = wait_for_queue_completion("cursor", &mut queue_guard) {
            core::mem::forget(req_buf);
            return Err(err);
        }

        queue_guard.free_desc_chain(desc0);
        Ok(())
    }

    fn alloc_command_buffers(
        &self,
        req_bytes: &[u8],
        data_bytes: &[u8],
        resp_size: usize,
    ) -> GpuResult<(VirtioDmaBuffer, VirtioDmaBuffer, VirtioDmaBuffer)> {
        let mut req_buf = self
            .alloc_coherent(req_bytes.len())
            .ok_or(GpuError::OutOfMemory)?;
        let mut data_buf = self
            .alloc_coherent(data_bytes.len())
            .ok_or(GpuError::OutOfMemory)?;
        let resp_buf = self.alloc_coherent(resp_size).ok_or(GpuError::OutOfMemory)?;
        req_buf.as_slice_mut()[..req_bytes.len()].copy_from_slice(req_bytes);
        data_buf.as_slice_mut()[..data_bytes.len()].copy_from_slice(data_bytes);
        Ok((req_buf, data_buf, resp_buf))
    }

    fn send_command_with_data(
        &self,
        req_bytes: &[u8],
        data_bytes: &[u8],
        resp_size: usize,
    ) -> GpuResult<VirtioDmaBuffer> {
        let queue = self.ctrl_queue.as_ref().ok_or(GpuError::InitFailed)?;
        let mut queue_guard = queue.lock();

        let (req_buf, data_buf, resp_buf) =
            self.alloc_command_buffers(req_bytes, data_bytes, resp_size)?;

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
            (*queue_guard.desc_table_ptr().add(desc0 as usize)) = VringDesc {
                addr: req_buf.device_address(),
                len: req_bytes.len() as u32,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc1,
            };
            (*queue_guard.desc_table_ptr().add(desc1 as usize)) = VringDesc {
                addr: data_buf.device_address(),
                len: data_bytes.len() as u32,
                flags: vring_flags::VRING_DESC_F_NEXT,
                next: desc2,
            };
            (*queue_guard.desc_table_ptr().add(desc2 as usize)) = VringDesc {
                addr: resp_buf.device_address(),
                len: resp_size as u32,
                flags: vring_flags::VRING_DESC_F_WRITE,
                next: 0,
            };
        }
        queue_guard.submit(desc0);
        queue_guard.notify(self.transport.as_ref());

        if let Err(err) = wait_for_queue_completion("control", &mut queue_guard) {
            core::mem::forget(req_buf);
            core::mem::forget(data_buf);
            core::mem::forget(resp_buf);
            return Err(err);
        }

        queue_guard.free_desc_chain(desc0);
        Ok(resp_buf)
    }

    pub(super) fn alloc_resource_id(&self) -> u32 {
        self.next_resource_id.fetch_add(1, Ordering::SeqCst)
    }

    pub(super) fn alloc_fence_id(&self) -> u32 {
        self.next_fence_id.fetch_add(1, Ordering::SeqCst)
    }

    pub(super) fn refresh_display_info(&self) -> GpuResult<()> {
        let hdr = GpuCtrlHdr::new(GpuCmd::GetDisplayInfo);
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(
                &hdr as *const GpuCtrlHdr as *const u8,
                core::mem::size_of::<GpuCtrlHdr>(),
            )
        };

        let resp_size = core::mem::size_of::<GpuCtrlHdr>() + core::mem::size_of::<defs::DisplayInfo>();
        let resp_buf = self.send_command_raw(hdr_bytes, resp_size)?;
        let resp_slice = resp_buf.as_slice();
        let resp_hdr = unsafe { core::ptr::read_volatile(resp_slice.as_ptr() as *const GpuCtrlHdr) };
        if resp_hdr.cmd_type != GpuCmd::RespOkDisplayInfo as u32 {
            return Err(GpuError::DeviceError);
        }

        let info_offset = core::mem::size_of::<GpuCtrlHdr>();
        if resp_slice.len() >= info_offset + core::mem::size_of::<defs::DisplayInfo>() {
            let info = unsafe {
                core::ptr::read_volatile(
                    resp_slice.as_ptr().add(info_offset) as *const defs::DisplayInfo,
                )
            };
            *self.display_info.write() = Some(info);
        }

        Ok(())
    }

    pub fn get_display_info(&self) -> GpuResult<defs::DisplayInfo> {
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

    pub fn attach_backing(&self, resource_id: u32, device_addr: u64, size: u32) -> GpuResult<()> {
        let req = ResourceAttachBacking {
            hdr: GpuCtrlHdr::new(GpuCmd::ResourceAttachBacking),
            resource_id,
            nr_entries: 1,
        };
        let entry = MemEntry {
            addr: device_addr,
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
        let hdr = unsafe { core::ptr::read_volatile(resp_buf.as_slice().as_ptr() as *const GpuCtrlHdr) };
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

    pub fn create_framebuffer(&self, width: u32, height: u32) -> GpuResult<u32> {
        let format = PixelFormat::B8G8R8A8Unorm;
        let resource_id = self.create_resource_2d(width, height, format)?;
        let fb = Framebuffer::new_for_device(
            resource_id,
            width,
            height,
            format,
            self.pci_locator,
        )
        .ok_or(GpuError::OutOfMemory)?;

        self.attach_backing(resource_id, fb.device_addr(), fb.size() as u32)?;
        self.framebuffers.write().push(fb);
        Ok(resource_id)
    }

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
        let irq_status = self.transport.get_interrupt_status();
        self.transport.ack_interrupt(irq_status);
    }

    pub fn has_3d_support(&self) -> bool {
        self.has_3d
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Relaxed)
    }
}

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

    pub fn init(
        &self,
        transport: Box<dyn VirtioTransport>,
        pci_locator: PackedPciLocation,
    ) -> GpuResult<()> {
        let mut gpu = VirtioGpu::new(transport, pci_locator);
        unsafe { gpu.init()? };

        let display_info = gpu.get_display_info()?;
        if let Some(mode) = display_info.modes.iter().find(|m| m.enabled != 0) {
            let fb_id = gpu.create_framebuffer(mode.rect.width, mode.rect.height)?;
            gpu.set_scanout(0, fb_id, &mode.rect)?;
            self.primary_scanout.store(0, Ordering::SeqCst);
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

pub(crate) static GRAPHICS_MANAGER: Once<GraphicsManager> = Once::new();

pub fn graphics_manager() -> &'static GraphicsManager {
    GRAPHICS_MANAGER.call_once(GraphicsManager::new)
}

pub fn init(transport: Box<dyn VirtioTransport>, pci_locator: PackedPciLocation) -> GpuResult<()> {
    graphics_manager().init(transport, pci_locator)
}

#[cfg(test)]
pub unsafe fn init_virtio_gpu_at_index(index: u8, mmio_base: u64) -> GpuResult<()> {
    let transport =
        unsafe { crate::transport::VirtioMmioTransport::new(mmio_base as usize).map_err(|_| GpuError::InitFailed)? };
    init(Box::new(transport), PackedPciLocation::new(0, 0, index, 0))
}
