use super::*;

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

    pub fn init(
        &self,
        transport: Box<dyn VirtioTransport>,
        iommu_device_id: IommuDeviceId,
    ) -> GpuResult<()> {
        let mut gpu = VirtioGpu::new(transport, iommu_device_id);
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

/// Initialize via GraphicsManager.
pub fn init(transport: Box<dyn VirtioTransport>, iommu_device_id: IommuDeviceId) -> GpuResult<()> {
    graphics_manager().init(transport, iommu_device_id)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[path = "../tests.rs"]
mod tests;
