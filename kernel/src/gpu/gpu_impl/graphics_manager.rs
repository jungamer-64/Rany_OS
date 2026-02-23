use super::*;
use alloc::sync::Arc;


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

pub(crate) static GRAPHICS_MANAGER: spin::Once<GraphicsManager> = spin::Once::new();

pub fn graphics_manager() -> &'static GraphicsManager {
    GRAPHICS_MANAGER.call_once(GraphicsManager::new)
}

/// Global VirtIO GPU device instance
pub(crate) static VIRTIO_GPU_DEVICE: Mutex<Option<Arc<VirtioGpu>>> = Mutex::new(None);

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

pub(crate) fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[path = "../tests.rs"]
mod tests;
