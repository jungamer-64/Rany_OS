use super::*;
use crate::io::virtio::TransportType;
use crate::util::align_up_usize as align_up;
use alloc::sync::Arc;

mod graphics_manager;
pub use self::graphics_manager::*;
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
    pub(super) fn alloc_coherent(
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

    pub(super) fn setup_queue(&mut self, queue_idx: u16) -> GpuResult<()> {
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

        let buffer = self
            .alloc_coherent(total_size, DmaMemoryAttributes::MMIO)
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
    pub(super) fn send_command_raw(
        &self,
        req_bytes: &[u8],
        resp_size: usize,
    ) -> GpuResult<CoherentDmaBuffer> {
        let queue = self.ctrl_queue.as_ref().ok_or(GpuError::InitFailed)?;
        let queue_guard = queue.lock();

        let mut req_buf = self
            .alloc_coherent(req_bytes.len(), DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;
        let resp_buf = self
            .alloc_coherent(resp_size, DmaMemoryAttributes::MMIO)
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
    pub(super) fn send_command<Req: Copy>(&self, req: &Req) -> GpuResult<GpuCtrlHdr> {
        let req_bytes = unsafe {
            core::slice::from_raw_parts(req as *const Req as *const u8, core::mem::size_of::<Req>())
        };
        let resp_buf = self.send_command_raw(req_bytes, core::mem::size_of::<GpuCtrlHdr>())?;
        let hdr =
            unsafe { core::ptr::read_volatile(resp_buf.as_slice().as_ptr() as *const GpuCtrlHdr) };
        if hdr.cmd_type >= GpuCmd::RespErrUnspec as u32 {
            return Err(GpuError::DeviceError);
        }
        Ok(hdr)
    }

    /// Send a cursor command to the cursor queue.
    pub(super) fn send_cursor_command<Req: Copy>(&self, req: &Req) -> GpuResult<()> {
        let queue = self.cursor_queue.as_ref().ok_or(GpuError::InitFailed)?;
        let queue_guard = queue.lock();

        let req_size = core::mem::size_of::<Req>();
        let mut req_buf = self
            .alloc_coherent(req_size, DmaMemoryAttributes::MMIO)
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

    /// Allocate and initialize 3 coherent DMA buffers for a command with data
    pub(super) fn alloc_command_buffers(
        &self,
        req_bytes: &[u8],
        data_bytes: &[u8],
        resp_size: usize,
    ) -> GpuResult<(CoherentDmaBuffer, CoherentDmaBuffer, CoherentDmaBuffer)> {
        let mut req_buf = self
            .alloc_coherent(req_bytes.len(), DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;
        let mut data_buf = self
            .alloc_coherent(data_bytes.len(), DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;
        let resp_buf = self
            .alloc_coherent(resp_size, DmaMemoryAttributes::MMIO)
            .ok_or(GpuError::OutOfMemory)?;
        unsafe {
            req_buf.as_mut_slice()[..req_bytes.len()].copy_from_slice(req_bytes);
            data_buf.as_mut_slice()[..data_bytes.len()].copy_from_slice(data_bytes);
        }
        Ok((req_buf, data_buf, resp_buf))
    }

    /// Send a command with an extra data buffer (3-descriptor chain).
    /// Used by attach_backing which needs: header + entries array + response.
    pub(super) fn send_command_with_data(
        &self,
        req_bytes: &[u8],
        data_bytes: &[u8],
        resp_size: usize,
    ) -> GpuResult<CoherentDmaBuffer> {
        let queue = self.ctrl_queue.as_ref().ok_or(GpuError::InitFailed)?;
        let queue_guard = queue.lock();

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

        while queue_guard.poll_completions().is_none() {
            core::hint::spin_loop();
        }
        queue_guard.free_desc(desc0);
        queue_guard.free_desc(desc1);
        queue_guard.free_desc(desc2);

        Ok(resp_buf)
    }

    // =========================================================================
    // GPU Operations
    // =========================================================================

    pub(super) fn alloc_resource_id(&self) -> u32 {
        self.next_resource_id.fetch_add(1, Ordering::SeqCst)
    }

    pub(super) fn alloc_fence_id(&self) -> u32 {
        self.next_fence_id.fetch_add(1, Ordering::SeqCst)
    }

    /// Get display information from the device.
    pub(super) fn refresh_display_info(&self) -> GpuResult<()> {
        let hdr = GpuCtrlHdr::new(GpuCmd::GetDisplayInfo);
        let hdr_bytes = unsafe {
            core::slice::from_raw_parts(
                &hdr as *const GpuCtrlHdr as *const u8,
                core::mem::size_of::<GpuCtrlHdr>(),
            )
        };

        // Response: GpuCtrlHdr + DisplayInfo
        let resp_size = core::mem::size_of::<GpuCtrlHdr>() + core::mem::size_of::<DisplayInfo>();
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
                core::ptr::read_volatile(resp_slice.as_ptr().add(info_offset) as *const DisplayInfo)
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

        let hdr =
            unsafe { core::ptr::read_volatile(resp_buf.as_slice().as_ptr() as *const GpuCtrlHdr) };
        if hdr.cmd_type >= GpuCmd::RespErrUnspec as u32 {
            return Err(GpuError::DeviceError);
        }
        Ok(())
    }

    pub fn transfer_to_host_2d(&self, resource_id: u32, rect: &Rect, offset: u64) -> GpuResult<()> {
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
