use super::*;
use crate::io::iommu::types::DeviceId as IommuDeviceId;

/// Pack IommuDeviceId into u64 for API boundary
fn pack_device_id(d: IommuDeviceId) -> u64 {
    ((d.segment as u64) << 32)
        | ((d.bus as u64) << 16)
        | ((d.device as u64) << 8)
        | (d.function as u64)
}

/// Unpack u64 into IommuDeviceId
fn unpack_device_id(id: u64) -> IommuDeviceId {
    IommuDeviceId {
        segment: (id >> 32) as u16,
        bus: (id >> 16) as u8,
        device: (id >> 8) as u8,
        function: id as u8,
    }
}


// SAFETY: ExoKernel is stateless and accesses thread-safe globals
mod gui_services;
pub use self::gui_services::*;
unsafe impl Send for ExoKernel {}
unsafe impl Sync for ExoKernel {}

impl KernelServices for ExoKernel {
    // ========================================================================
    // Task Management
    // ========================================================================

    fn spawn_task(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Result<TaskHandle, KapiError> {
        // Use Task::new_boxed to avoid double-boxing (optimization)
        let task = Task::new_boxed(future, Priority::Normal, None);
        let task_id = task.metadata.id.as_u64();

        // Submit to ExecutorManager for load-balanced scheduling
        executor_manager().spawn(task);

        Ok(TaskHandle::new(task_id))
    }

    fn current_tick(&self) -> u64 {
        timer::current_tick()
    }

    fn current_task_id(&self) -> u64 {
        context::current_task_id()
    }

    // ========================================================================
    // Memory Management
    // ========================================================================

    fn alloc_dma(&self, size: usize) -> Result<DmaBuffer, KapiError> {
        // Use CoherentDmaBuffer for proper DMA allocation with correct physical address
        match dma::CoherentDmaBuffer::new(size, dma::DmaMemoryAttributes::MMIO) {
            Some(buffer) => {
                let phys = buffer.phys_addr().as_u64();
                let dev_addr = buffer.device_addr();
                let virt_ptr = unsafe { buffer.as_slice().as_ptr() } as usize;
                // Box up the buffer and register by virtual address so it can be freed later
                let boxed: Box<dyn core::any::Any + Send> = Box::new(buffer);
                DMA_REGISTRY.register_with_key(virt_ptr, boxed);
                Ok(DmaBuffer::new_with_device_addr(phys, dev_addr, virt_ptr as *mut u8, size))
            }
            None => Err(KapiError::OutOfMemory),
        }
    }

    fn alloc_dma_for_device(&self, size: usize, device_id: u64) -> Result<DmaBuffer, KapiError> {
        let dev_id = unpack_device_id(device_id);
        match dma::CoherentDmaBuffer::new_for_device(size, dma::DmaMemoryAttributes::MMIO, &dev_id) {
            Some(buffer) => {
                let phys = buffer.phys_addr().as_u64();
                let dev_addr = buffer.device_addr();
                let virt_ptr = unsafe { buffer.as_slice().as_ptr() } as usize;
                
                let boxed: Box<dyn core::any::Any + Send> = Box::new(buffer);
                DMA_REGISTRY.register_with_key(virt_ptr, boxed);
                Ok(DmaBuffer::new_with_device_addr(phys, dev_addr, virt_ptr as *mut u8, size))
            }
            None => Err(KapiError::OutOfMemory),
        }
    }

    fn free_dma(&self, buffer: DmaBuffer) {
        // Try to lookup the registered buffer by its virtual pointer
        let virt_ptr = buffer.as_ptr() as usize;
        if DMA_REGISTRY.unregister(virt_ptr).is_some() {
            // Successfully unregistered and dropped
            return;
        }

        // If we couldn't find it, quietly ignore (or log) — do not panic in kernel
        log::info!("[KAPI] free_dma: unknown buffer: {:x}\n", virt_ptr);
    }

    // ========================================================================
    // I/O Operations
    // ========================================================================

    fn port_read_u8(&self, port: u16) -> u8 {
        hal::port_io::PortU8::new(port).read()
    }

    fn port_write_u8(&self, port: u16, value: u8) {
        hal::port_io::PortU8::new(port).write(value)
    }

    // ========================================================================
    // Logging
    // ========================================================================

    fn log(&self, message: &str) {
        log::info!("{}", message);
    }

    // ========================================================================
    // Network (Connected to network stack)
    // ========================================================================

    fn net_create_endpoint(&self) -> Result<TcpEndpoint, KapiError> {
        use crate::net::endpoint::create_tcp_socket;

        let owned = create_tcp_socket();
        let fd = owned.fd();

        // Detach from OwnedSocket so it remains registered in SocketManager
        // and doesn't close on drop.
        let _ = owned.into_inner();

        Ok(TcpEndpoint::new(fd.raw() as u64))
    }
    fn net_close_endpoint(&self, endpoint: TcpEndpoint) -> Result<(), KapiError> {
        use crate::net::endpoint::{SocketFd, socket_manager};

        let fd = SocketFd::from_raw(endpoint.id() as u32);

        if let Some(mgr_lock) = socket_manager() {
            let guard = mgr_lock.read();
            if let Some(mgr) = guard.as_ref() {
                if mgr.unregister(fd).is_some() {
                    return Ok(());
                }
            }
        }

        Err(KapiError::InvalidHandle)
    }

    fn net_recv_packet(&self, endpoint: TcpEndpoint) -> Pin<Box<dyn Future<Output = KapiResult<Packet>> + Send>> {
        Box::pin(async move {
            use crate::net::endpoint::{SocketFd, socket_manager};

            let fd = SocketFd::from_raw(endpoint.id() as u32);

            if let Some(mgr_lock) = socket_manager() {
                let guard = mgr_lock.read();
                if let Some(mgr) = guard.as_ref() {
                    if let Some(socket) = mgr.get(fd) {
                        // Create and await RecvFuture
                        let fut = crate::net::endpoint::futures::RecvFuture::new(socket.clone(), crate::net::stack::MAX_PACKET_SIZE);
                        match fut.await {
                            Ok(vec) => Ok(Packet::new(vec)),
                            Err(_) => Err(KapiError::IoError),
                        }
                    } else {
                        Err(KapiError::InvalidHandle)
                    }
                } else {
                    Err(KapiError::InvalidHandle)
                }
            } else {
                Err(KapiError::NotFound)
            }
        })
    }

    fn net_send_packet(&self, endpoint: TcpEndpoint, packet: Packet) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            use crate::net::endpoint::{SocketFd, socket_manager};

            let fd = SocketFd::from_raw(endpoint.id() as u32);

            if let Some(mgr_lock) = socket_manager() {
                let guard = mgr_lock.read();
                if let Some(mgr) = guard.as_ref() {
                    if let Some(socket) = mgr.get(fd) {
                        // Clone/convert packet data for socket send
                        let data = packet.data().to_vec();
                        let fut = crate::net::endpoint::futures::SendFuture::new(socket.clone(), data);
                        match fut.await {
                            Ok(_) => Ok(()),
                            Err(_) => Err(KapiError::IoError),
                        }
                    } else {
                        Err(KapiError::InvalidHandle)
                    }
                } else {
                    Err(KapiError::InvalidHandle)
                }
            } else {
                Err(KapiError::NotFound)
            }
        })
    }

    fn net_create_raw_socket(&self) -> Result<RawSocketHandle, KapiError> {
        use crate::net::endpoint::create_raw_socket;

        let owned = create_raw_socket();
        let fd = owned.fd();

        // Detach so it remains registered
        let _ = owned.into_inner();

        Ok(RawSocketHandle::new(fd.raw() as u64))
    }

    fn net_close_raw_socket(&self, endpoint: RawSocketHandle) -> Result<(), KapiError> {
        use crate::net::endpoint::{SocketFd, socket_manager};

        let fd = SocketFd::from_raw(endpoint.id() as u32);

        if let Some(mgr_lock) = socket_manager() {
            let guard = mgr_lock.read();
            if let Some(mgr) = guard.as_ref() {
                if mgr.unregister(fd).is_some() {
                    return Ok(());
                }
            }
        }

        Err(KapiError::InvalidHandle)
    }

    fn net_recv_raw(&self, endpoint: RawSocketHandle) -> Pin<Box<dyn Future<Output = KapiResult<Packet>> + Send>> {
        Box::pin(async move {
            use crate::net::endpoint::{SocketFd, socket_manager};

            let fd = SocketFd::from_raw(endpoint.id() as u32);

            if let Some(mgr_lock) = socket_manager() {
                let guard = mgr_lock.read();
                if let Some(mgr) = guard.as_ref() {
                    if let Some(socket) = mgr.get(fd) {
                        let fut = crate::net::endpoint::futures::RecvFuture::new(socket.clone(), crate::net::stack::MAX_PACKET_SIZE);
                        match fut.await {
                            Ok(vec) => Ok(Packet::new(vec)),
                            Err(_) => Err(KapiError::IoError),
                        }
                    } else {
                        Err(KapiError::InvalidHandle)
                    }
                } else {
                    Err(KapiError::InvalidHandle)
                }
            } else {
                Err(KapiError::NotFound)
            }
        })
    }

    fn net_send_raw(&self, endpoint: RawSocketHandle, packet: Packet) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            use crate::net::endpoint::{SocketFd, socket_manager};

            let fd = SocketFd::from_raw(endpoint.id() as u32);

            if let Some(mgr_lock) = socket_manager() {
                let guard = mgr_lock.read();
                if let Some(mgr) = guard.as_ref() {
                    if let Some(socket) = mgr.get(fd) {
                        let data = packet.data().to_vec();
                        let fut = crate::net::endpoint::futures::SendFuture::new(socket.clone(), data);
                        match fut.await {
                            Ok(_) => Ok(()),
                            Err(_) => Err(KapiError::IoError),
                        }
                    } else {
                        Err(KapiError::InvalidHandle)
                    }
                } else {
                    Err(KapiError::InvalidHandle)
                }
            } else {
                Err(KapiError::NotFound)
            }
        })
    }

    // ========================================================================
    // Filesystem (Connected to memfs)
    // ========================================================================

    fn fs_open(&self, path: &str, mode: OpenMode) -> Result<FileHandle, KapiError> {
        // Backward-compatible: open without token
        self.fs_open_with_token(path, mode, None)
    }

    fn fs_open_with_token(&self, path: &str, mode: OpenMode, token: Option<u64>) -> Result<FileHandle, KapiError> {
        use crate::fs::memfs;

        // Check if file exists
        let path_buf = alloc::string::String::from(path);

        match mode {
            OpenMode::Read => {
                // For read, file must exist
                if memfs::stat_file(&path_buf, "/").is_err() {
                    return Err(KapiError::NotFound);
                }
            }
            OpenMode::Write | OpenMode::ReadWrite | OpenMode::Append | OpenMode::Create => {
                // For write, create if not exists
                if memfs::stat_file(&path_buf, "/").is_err() {
                    if let Err(_) = memfs::touch_file(&path_buf, "/") {
                        return Err(KapiError::IoError);
                    }
                }
            }
        }

        let caller = context::current_subject().domain.as_u64();

        // If token provided, validate and increment in-flight counter
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller, t, crate::security::capability::CAP_FOWNER) {
                return Err(KapiError::PermissionDenied);
            }

            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(KapiError::PermissionDenied);
            }
        }

        // Register in file handle table (recording owner domain for /proc/<pid>/fd)
        let handle_id = FILE_HANDLE_REGISTRY.register(FileHandleEntry {
            path: path_buf,
            mode,
            position: 0,
            token,
            owner: caller,
        });

        Ok(FileHandle::new(handle_id, mode))
    }

    fn fs_close(&self, handle: FileHandle) -> Result<(), KapiError> {
        let handle_id = handle.id();
        if let Some(entry) = FILE_HANDLE_REGISTRY.unregister(handle_id) {
            if let Some(t) = entry.token {
                let _ = crate::security::capability::manager().decrement_in_flight(t);
            }
            Ok(())
        } else {
            Err(KapiError::InvalidHandle)
        }
    }

    fn nvme_open_direct(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
    ) -> Result<DirectBlockHandle, KapiError> {
        // Backward-compatible: open without token
        self.nvme_open_direct_with_token(device_id, start_block, block_count, None)
    }

    fn nvme_open_direct_with_token(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        token: Option<u64>,
    ) -> Result<DirectBlockHandle, KapiError> {
        if block_count == 0 {
            return Err(KapiError::IoError);
        }

        let nsid = if device_id == 0 { 1 } else { device_id as u32 };
        let block_size =
            crate::io::nvme::with_driver(|driver| driver.namespace_block_size(nsid))
                .unwrap_or(512);

        let caller = context::current_subject().domain.as_u64();

        // If token provided, validate and increment in-flight counter
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(caller, t, crate::security::capability::CAP_DMA) {
                return Err(KapiError::PermissionDenied);
            }
            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(KapiError::PermissionDenied);
            }
        }

        // Register the open in kernel registry and return a handle with open_id
        let id = NVME_DIRECT_REGISTRY.register(device_id, start_block, block_count, block_size, caller, token);
        Ok(DirectBlockHandle::new_with_id(device_id, start_block, block_count, block_size, id))
    }

    fn nvme_close_direct(&self, handle: DirectBlockHandle) -> Result<(), KapiError> {
        let id = handle.open_id();
        if id == 0 {
            return Err(KapiError::InvalidHandle);
        }

        let caller = context::current_subject().domain.as_u64();

        match NVME_DIRECT_REGISTRY.unregister_if_owner_or_admin(id, caller) {
            Some(entry) => {
                if let Some(t) = entry.token {
                    // Best-effort decrement
                    let _ = crate::security::capability::manager().decrement_in_flight(t);
                }
                Ok(())
            }
            None => Err(KapiError::InvalidHandle),
        }
    }

    fn nvme_read_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct
                .read_blocks_dma(block_offset, buffer)
                .await
                .map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_write_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct
                .write_blocks_dma(block_offset, buffer)
                .await
                .map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_flush_direct(
        &self,
        handle: DirectBlockHandle,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct.flush().await.map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_discard_direct(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        block_count: u64,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            let direct = crate::fs::DirectBlockHandle::new(
                handle.device_id(),
                handle.start_block(),
                handle.block_count(),
                handle.block_size(),
            );
            direct
                .discard(block_offset, block_count)
                .await
                .map_err(|_| KapiError::IoError)
        })
    }

    fn nvme_block_size(&self, device_id: u64) -> Option<u64> {
        let nsid = if device_id == 0 { 1 } else { device_id as u32 };
        crate::io::nvme::with_driver(|driver| driver.namespace_block_size(nsid) as u64)
    }

    fn nvme_sgl_max_entries(&self, _device_id: u64) -> Option<usize> {
        crate::io::nvme::global::with_driver(|driver: &crate::io::nvme::NvmePollingDriver| {
            driver.sgl_max_entries()
        })
        .flatten()
    }

    fn nvme_prepare_dma_read(&self, _device_id: u64, len: usize) -> KapiResult<NvmeDmaHandle> {
        if len == 0 {
            return Err(KapiError::IoError);
        }

        let alloc_len = align_up_page(len);
        let data = TypedDmaSlice::<CpuOwned>::new(alloc_len)
            .ok_or(KapiError::OutOfMemory)?;
        let data_phys = data.phys_addr().as_u64();

        let device = crate::io::nvme::iommu_device();
        let (data_addr, data_map) = map_for_iommu(device, data_phys, alloc_len)?;
        let (prp2, prp_list) = build_prp_list_internal(device, data_addr, alloc_len)?;

        let (data_dev, data_guard) = data.start_dma();

        let entry = NvmeDmaContextEntry {
            data_dev: Some(data_dev),
            data_guard: Some(data_guard),
            prp_list,
            data_map,
            logical_len: len,
        };

        let id = NVME_DMA_CONTEXT_REGISTRY.register(entry);
        Ok(NvmeDmaHandle::new(id, data_addr, prp2, len))
    }

    fn nvme_prepare_dma_write(&self, _device_id: u64, data: &[u8]) -> KapiResult<NvmeDmaHandle> {
        if data.is_empty() {
            return Err(KapiError::IoError);
        }

        let alloc_len = align_up_page(data.len());
        let mut dma_buf = TypedDmaSlice::<CpuOwned>::new(alloc_len)
            .ok_or(KapiError::OutOfMemory)?;

        // Copy data into DMA buffer
        dma_buf.as_mut_slice()[..data.len()].copy_from_slice(data);
        if alloc_len > data.len() {
            dma_buf.as_mut_slice()[data.len()..].fill(0);
        }

        let data_phys = dma_buf.phys_addr().as_u64();
        let device = crate::io::nvme::iommu_device();
        let (data_addr, data_map) = map_for_iommu(device, data_phys, alloc_len)?;
        let (prp2, prp_list) = build_prp_list_internal(device, data_addr, alloc_len)?;

        let (data_dev, data_guard) = dma_buf.start_dma();

        let entry = NvmeDmaContextEntry {
            data_dev: Some(data_dev),
            data_guard: Some(data_guard),
            prp_list,
            data_map,
            logical_len: data.len(),
        };

        let id = NVME_DMA_CONTEXT_REGISTRY.register(entry);
        Ok(NvmeDmaHandle::new(id, data_addr, prp2, data.len()))
    }

    fn nvme_complete_dma_read(&self, handle: NvmeDmaHandle) -> KapiResult<alloc::vec::Vec<u8>> {
        let entry = NVME_DMA_CONTEXT_REGISTRY.unregister(handle.id())
            .ok_or(KapiError::InvalidHandle)?;
        let logical_len = entry.logical_len;
        let dma_slice = entry.complete();

        // Copy data from DMA buffer
        let mut result = alloc::vec![0u8; logical_len];
        result.copy_from_slice(&dma_slice.as_slice()[..logical_len]);
        Ok(result)
    }

    fn nvme_complete_dma_write(&self, handle: NvmeDmaHandle) -> KapiResult<()> {
        let entry = NVME_DMA_CONTEXT_REGISTRY.unregister(handle.id())
            .ok_or(KapiError::InvalidHandle)?;
        let _ = entry.complete();
        Ok(())
    }

    fn nvme_iommu_device_id(&self, _device_id: u64) -> Option<u64> {
        crate::io::nvme::iommu_device().map(|d| {
            // Pack IommuDeviceId into u64 for API boundary
            // DeviceId has public fields: segment, bus, device, function
            ((d.segment as u64) << 32) | ((d.bus as u64) << 16) | ((d.device as u64) << 8) | (d.function as u64)
        })
    }

    fn nvme_iommu_map(
        &self,
        _device_id: u64,
        phys_addr: u64,
        size: usize,
    ) -> KapiResult<(u64, u64)> {
        let device = crate::io::nvme::iommu_device();
        let (iova, mapping) = map_for_iommu(device, phys_addr, size)?;
        
        // If we have a mapping, register it and return the ID
        if let Some(m) = mapping {
            let id = IOMMU_MAPPING_REGISTRY.register(m);
            Ok((iova, id))
        } else {
            // No IOMMU - identity mapping
            Ok((iova, 0))
        }
    }

    fn nvme_iommu_unmap(&self, mapping_id: u64) -> KapiResult<()> {
        if mapping_id == 0 {
            // Identity mapping, nothing to unmap
            return Ok(());
        }
        
        if let Some(mapping) = IOMMU_MAPPING_REGISTRY.unregister(mapping_id) {
            mapping.unmap();
        }
        Ok(())
    }

    fn nvme_submit_rw(
        &self,
        request: NvmeRwRequest,
        io_type: NvmeIoType,
    ) -> KapiResult<NvmeIoHandle> {
        use crate::io::io_scheduler::{
            DeviceId as IoDeviceId, IoPriority, IoCommand, DmaBufHandle,
        };

        let device = IoDeviceId::Nvme {
            controller: 0,
            namespace: request.namespace_id,
        };

        let priority = match request.priority {
            NvmeIoPriority::Background => IoPriority::Background,
            NvmeIoPriority::Idle => IoPriority::Idle,
            NvmeIoPriority::Normal => IoPriority::Normal,
            NvmeIoPriority::High => IoPriority::High,
            NvmeIoPriority::Realtime => IoPriority::Realtime,
        };

        // Build IoCommand (new API) and submit via submit_io_command
        let command = match io_type {
            NvmeIoType::Read => IoCommand::BlockRead {
                lba: request.lba,
                blocks: request.blocks,
                bytes: request.bytes,
                buf: DmaBufHandle {
                    iova: request.prp1,
                    len: request.bytes,
                },
            },
            NvmeIoType::Write => IoCommand::BlockWrite {
                lba: request.lba,
                blocks: request.blocks,
                bytes: request.bytes,
                buf: DmaBufHandle {
                    iova: request.prp1,
                    len: request.bytes,
                },
            },
            NvmeIoType::Flush => IoCommand::Flush,
            NvmeIoType::Discard => IoCommand::Discard {
                lba: request.lba,
                blocks: request.blocks as u16,
            },
        };

        let future = crate::io::io_scheduler::hybrid_coordinator().submit_io_command(
            device, command, priority,
        );
        let request_id = future.request_id().0;

        Ok(NvmeIoHandle::new(request_id))
    }

    fn nvme_wait_io(
        &self,
        handle: NvmeIoHandle,
    ) -> Pin<Box<dyn Future<Output = NvmeIoResult> + Send>> {
        use crate::io::io_scheduler::{IoRequestId, IoResult as SchedIoResult};

        let request_id = IoRequestId(handle.request_id());
        
        Box::pin(async move {
            // Poll the io_scheduler for completion
            loop {
                if let Some(result) = crate::io::io_scheduler::io_scheduler().take_result(request_id) {
                    return match result {
                        SchedIoResult::Success(bytes) => NvmeIoResult::Success(bytes),
                        SchedIoResult::Error(e) => match e {
                            crate::io::io_scheduler::IoError::Timeout => NvmeIoResult::Timeout,
                            crate::io::io_scheduler::IoError::Cancelled => NvmeIoResult::Cancelled,
                            crate::io::io_scheduler::IoError::InvalidParameter => NvmeIoResult::InvalidParameter,
                            _ => NvmeIoResult::DeviceError,
                        },
                    };
                }
                // Yield to allow other tasks to run
                core::hint::spin_loop();
            }
        })
    }

    fn nvme_register_completion_hook(
        &self,
        handle: NvmeIoHandle,
        hook: Box<dyn FnOnce(NvmeIoResult) + Send>,
    ) {
        use crate::io::io_scheduler::{CompletionHook, IoRequestId, IoResult as SchedIoResult};

        let request_id = IoRequestId(handle.request_id());
        
        let wrapper: CompletionHook = Box::new(move |result: SchedIoResult| {
            let converted = match result {
                SchedIoResult::Success(bytes) => NvmeIoResult::Success(bytes),
                SchedIoResult::Error(e) => match e {
                    crate::io::io_scheduler::IoError::Timeout => NvmeIoResult::Timeout,
                    crate::io::io_scheduler::IoError::Cancelled => NvmeIoResult::Cancelled,
                    crate::io::io_scheduler::IoError::InvalidParameter => NvmeIoResult::InvalidParameter,
                    _ => NvmeIoResult::DeviceError,
                },
            };
            hook(converted);
        });

        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, wrapper);
    }

    fn ipc_create_channel(&self) -> Result<(ChannelHandle, ChannelHandle), KapiError> {
        // Create a new pipe
        let pipe = crate::ipc::pipe::pipe();

        // Register reader and writer
        let reader_id = CHANNEL_REGISTRY.register(ChannelEntry::Reader(pipe.reader));
        let writer_id = CHANNEL_REGISTRY.register(ChannelEntry::Writer(pipe.writer));

        Ok((ChannelHandle::new(writer_id), ChannelHandle::new(reader_id))) // Return (Sender, Receiver)
    }

    fn ipc_close(&self, channel: ChannelHandle) -> Result<(), KapiError> {
        let channel_id = channel.id();
        if CHANNEL_REGISTRY.unregister(channel_id).is_some() {
            Ok(())
        } else {
            Err(KapiError::InvalidHandle)
        }
    }

    fn time_service(&self) -> Option<&dyn kernel_api::time::TimeService> {
        Some(time_driver::time_service())
    }

    fn gui(&self) -> Option<&dyn kernel_api::gui::GuiServices> {
        #[cfg(not(any(test, feature = "bench")))]
        {
            // GUI services are available only if framebuffer exists
            if crate::graphics::framebuffer().is_some() {
                Some(self)
            } else {
                None
            }
        }

        #[cfg(any(test, feature = "bench"))]
        {
            // In test/bench builds, graphics subsystem is disabled
            None
        }
    }

    fn shell(&self) -> Option<&dyn kernel_api::shell::ShellServices> {
        // Shell services are always available
        Some(self)
    }
}
