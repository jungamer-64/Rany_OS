use super::*;
use crate::io::iommu::types::DeviceId as IommuDeviceId;
use kernel_api::abi::driver::{
    AbiAudioControllerRegistration, AbiBlockDeviceRegistration, AbiNetPortRegistrationV3,
    AbiNvmeNamespaceRegistration, AbiRRefRaw, PackedPciLocation,
};
use kernel_api::msix::MsixVectorInfo;

fn unpack_device_id(locator: PackedPciLocation) -> IommuDeviceId {
    IommuDeviceId {
        segment: locator.segment(),
        bus: locator.bus(),
        device: locator.device(),
        function: locator.function(),
    }
}

fn stack_scope(
    scope: kernel_api::resource::net::InterfaceScope,
) -> crate::net::types::InterfaceScope {
    match scope {
        kernel_api::resource::net::InterfaceScope::Any => crate::net::types::InterfaceScope::Any,
        kernel_api::resource::net::InterfaceScope::Pinned(if_id) => {
            crate::net::types::InterfaceScope::Pinned(crate::net::runtime::manager::NetIfId(if_id))
        }
    }
}

fn apply_endpoint_scope(
    endpoint: &crate::net::l4::endpoint::endpoint_core::Endpoint,
    scope: kernel_api::resource::net::InterfaceScope,
) {
    let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
    inner.scope = stack_scope(scope);
}

fn endpoint_addr_from_kapi(
    addr: kernel_api::resource::net::NetSocketAddr,
) -> crate::net::l4::endpoint::EndpointAddr {
    match addr {
        kernel_api::resource::net::NetSocketAddr::V4 { ip, port } => {
            crate::net::l4::endpoint::EndpointAddr::new(ip, port)
        }
        kernel_api::resource::net::NetSocketAddr::V6 { ip, port } => {
            crate::net::l4::endpoint::EndpointAddr::new_v6(ip, port)
        }
    }
}

fn endpoint_error_to_kapi(error: crate::net::l4::endpoint::EndpointError) -> KapiError {
    match error {
        crate::net::l4::endpoint::EndpointError::Timeout => KapiError::Timeout,
        crate::net::l4::endpoint::EndpointError::PortInUse
        | crate::net::l4::endpoint::EndpointError::AddressInUse => KapiError::ResourceExhausted,
        crate::net::l4::endpoint::EndpointError::PermissionDenied => KapiError::PermissionDenied,
        crate::net::l4::endpoint::EndpointError::NotFound => KapiError::InvalidHandle,
        _ => KapiError::IoError,
    }
}

fn tcp_error_to_kapi(error: crate::net::l4::tcp::TcpError) -> KapiError {
    match error {
        crate::net::l4::tcp::TcpError::Timeout => KapiError::Timeout,
        crate::net::l4::tcp::TcpError::AddressInUse | crate::net::l4::tcp::TcpError::BufferFull => {
            KapiError::ResourceExhausted
        }
        crate::net::l4::tcp::TcpError::PermissionDenied => KapiError::PermissionDenied,
        crate::net::l4::tcp::TcpError::NetworkUnreachable => KapiError::NotFound,
        _ => KapiError::IoError,
    }
}

fn network_error_to_kapi(error: crate::net::types::NetworkError) -> KapiError {
    match error {
        crate::net::types::NetworkError::PermissionDenied => KapiError::PermissionDenied,
        crate::net::types::NetworkError::PortInUse => KapiError::ResourceExhausted,
        crate::net::types::NetworkError::Timeout => KapiError::Timeout,
        crate::net::types::NetworkError::NetworkUnreachable => KapiError::NotFound,
        crate::net::types::NetworkError::BufferTooSmall
        | crate::net::types::NetworkError::ArpResolutionPending
        | crate::net::types::NetworkError::TransmitFailed => KapiError::ResourceExhausted,
        _ => KapiError::IoError,
    }
}

fn lookup_endpoint(
    fd: crate::net::l4::endpoint::EndpointFd,
) -> Result<crate::net::l4::endpoint::endpoint_core::Endpoint, KapiError> {
    let Some(mgr_lock) = crate::net::l4::endpoint::endpoint_manager() else {
        return Err(KapiError::NotFound);
    };
    let guard = mgr_lock.read().unwrap_or_else(|e| e.into_inner());
    let Some(mgr) = guard.as_ref() else {
        return Err(KapiError::NotFound);
    };
    mgr.get(fd).ok_or(KapiError::InvalidHandle)
}

fn close_endpoint_handle(fd: crate::net::l4::endpoint::EndpointFd) -> Result<(), KapiError> {
    let socket = lookup_endpoint(fd)?;
    socket.close_sync().map_err(endpoint_error_to_kapi)?;

    if let Some(mgr_lock) = crate::net::l4::endpoint::endpoint_manager() {
        let guard = mgr_lock.read().unwrap_or_else(|e| e.into_inner());
        if let Some(mgr) = guard.as_ref() {
            let _ = mgr.unregister(fd);
        }
    }

    Ok(())
}

// SAFETY: ExoKernel is stateless and accesses thread-safe globals
mod gui_services;
pub use self::gui_services::*;
unsafe impl Send for ExoKernel {}
unsafe impl Sync for ExoKernel {}

pub(crate) unsafe fn release_dma_buffer(dma_handle_id: u64) {
    let caller = context::current_subject().domain.as_u64();
    let dma_handle_id = dma_handle_id as usize;

    if let Some(owner) = DMA_REGISTRY.get_owner(dma_handle_id) {
        if owner != caller {
            log::error!(
                "[KAPI][SECURITY] release_dma_buffer: Domain {} tried to drop DMA handle {} owned by Domain {}",
                caller,
                dma_handle_id,
                owner
            );
            return;
        }
    }

    if let Some(entry) = DMA_REGISTRY.unregister(dma_handle_id) {
        PHYS_OWNERSHIP_REGISTRY.unregister(entry.phys);
        return;
    }

    log::info!(
        "[KAPI] release_dma_buffer: unknown DMA handle: {}\n",
        dma_handle_id
    );
}

impl KernelServices for ExoKernel {
    // ========================================================================
    // Task Management
    // ========================================================================

    fn spawn_task(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Result<TaskHandle, KapiError> {
        let domain_id = context::current_subject().domain.as_u64();
        let task_id =
            task::spawn_detached_in_domain(future, crate::domain_system::DomainId::new(domain_id))
                .as_u64();

        Ok(TaskHandle::new(task_id))
    }

    fn current_tick(&self) -> u64 {
        task::current_tick()
    }

    fn current_task_id(&self) -> u64 {
        context::current_task_id()
    }

    // ========================================================================
    // Memory Management
    // ========================================================================

    fn alloc_dma_for_device(
        &self,
        size: usize,
        device_id: PackedPciLocation,
    ) -> Result<DmaBuffer, KapiError> {
        if device_id.is_null() {
            log::warn!("[KAPI] alloc_dma_for_device rejected null PCI locator");
            return Err(KapiError::NotSupported);
        }

        let caller = context::current_subject().domain.as_u64();
        let dev_id = unpack_device_id(device_id);
        let ctx = dma::DeviceDmaContext::for_attached_device(dev_id);
        match ctx.alloc_region(size, dma::DmaMemoryAttributes::MMIO) {
            Ok(region) => {
                let slot = region.full_slot();
                let phys = slot.host_addr();
                let dev_addr = slot.device_addr();
                let virt_ptr = slot.as_ptr() as usize;

                // SECURITY: Track physical address ownership
                PHYS_OWNERSHIP_REGISTRY.register(phys, size, caller);

                let boxed: Box<dyn core::any::Any + Send> = Box::new(region.into_inner());
                let dma_handle_id = DMA_REGISTRY.register(boxed, phys, caller) as u64;
                Ok(unsafe {
                    DmaBuffer::from_kernel_parts(
                        phys,
                        dma_handle_id,
                        dev_addr,
                        virt_ptr as *mut u8,
                        size,
                        Some(release_dma_buffer),
                    )
                })
            }
            Err(_) => Err(KapiError::OutOfMemory),
        }
    }

    fn enable_msix(
        &self,
        device_id: PackedPciLocation,
        requested_count: u16,
    ) -> Result<alloc::vec::Vec<MsixVectorInfo>, KapiError> {
        crate::io::msix::enable_for_owner(
            context::current_subject().domain,
            device_id,
            requested_count,
        )
    }

    fn disable_msix(&self, device_id: PackedPciLocation) -> Result<(), KapiError> {
        let owner = context::current_subject().domain;
        let vectors = crate::io::msix::owned_vectors(owner, device_id)?;
        crate::driver_registry::unbind_irqs_for_owner(owner, &vectors);
        crate::io::msix::disable_for_owner(owner, device_id)
    }

    fn net_alloc_packet(
        &self,
        len: usize,
        headroom: usize,
    ) -> Result<kernel_api::resource::net::PacketRef, KapiError> {
        crate::net::payload::alloc_packet_with_headroom(len, headroom).ok_or(KapiError::OutOfMemory)
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

    fn register_block_device(
        &self,
        registration: &AbiBlockDeviceRegistration,
    ) -> Result<u64, KapiError> {
        crate::runtime_bridge::register_block_device(registration)
            .map_err(|_| KapiError::PermissionDenied)
    }

    fn unregister_block_device(&self, handle: u64) -> Result<(), KapiError> {
        crate::runtime_bridge::unregister_block_device(handle)
            .map_err(|_| KapiError::PermissionDenied)
    }

    fn register_nvme_namespace(
        &self,
        registration: &AbiNvmeNamespaceRegistration,
    ) -> Result<u64, KapiError> {
        crate::runtime_bridge::register_nvme_namespace(registration)
            .map_err(|_| KapiError::PermissionDenied)
    }

    fn unregister_nvme_namespace(&self, handle: u64) -> Result<(), KapiError> {
        crate::runtime_bridge::unregister_nvme_namespace(handle)
            .map_err(|_| KapiError::PermissionDenied)
    }

    fn register_netdev_port(
        &self,
        registration: &AbiNetPortRegistrationV3,
    ) -> Result<u64, KapiError> {
        crate::runtime_bridge::register_netdev_port(registration)
            .map_err(|_| KapiError::PermissionDenied)
    }

    fn unregister_netdev_port(&self, handle: u64) -> Result<(), KapiError> {
        crate::runtime_bridge::unregister_netdev_port(handle)
            .map_err(|_| KapiError::PermissionDenied)
    }

    fn register_audio_controller(
        &self,
        registration: &AbiAudioControllerRegistration,
    ) -> Result<u64, KapiError> {
        crate::runtime_bridge::register_audio_controller(registration)
            .map_err(|_| KapiError::PermissionDenied)
    }

    fn unregister_audio_controller(&self, handle: u64) -> Result<(), KapiError> {
        crate::runtime_bridge::unregister_audio_controller(handle)
            .map_err(|_| KapiError::PermissionDenied)
    }

    // ========================================================================
    // Network (Connected to network stack)
    // ========================================================================

    fn net_open_tcp_stream(
        &self,
        remote: kernel_api::resource::net::NetSocketAddr,
        scope: kernel_api::resource::net::InterfaceScope,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::TcpStream>> + Send>>
    {
        Box::pin(async move {
            let remote = endpoint_addr_from_kapi(remote);
            let owned = crate::net::l4::endpoint::create_tcp_endpoint();
            let endpoint = owned.endpoint().ok_or(KapiError::NotFound)?.clone();
            apply_endpoint_scope(&endpoint, scope);
            endpoint
                .open_connection(remote)
                .await
                .map_err(endpoint_error_to_kapi)?;

            let endpoint = owned.into_inner().ok_or(KapiError::NotFound)?;
            let stream = crate::net::l4::tcp::TcpStream::from_endpoint_with_drop(endpoint, false);
            let fd = stream.into_retained_handle();
            Ok(kernel_api::resource::net::TcpStream::from_raw_parts(
                fd.raw() as u64,
                scope,
            ))
        })
    }

    fn net_open_tcp_listener(
        &self,
        local: kernel_api::resource::net::NetSocketAddr,
        scope: kernel_api::resource::net::InterfaceScope,
        backlog: u32,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::TcpListener>> + Send>>
    {
        Box::pin(async move {
            let local = endpoint_addr_from_kapi(local);
            let owned = crate::net::l4::endpoint::create_tcp_endpoint();
            let endpoint = owned.endpoint().ok_or(KapiError::NotFound)?.clone();
            apply_endpoint_scope(&endpoint, scope);
            endpoint
                .set_local_addr(local)
                .map_err(endpoint_error_to_kapi)?;
            endpoint
                .start_listening(backlog)
                .await
                .map_err(endpoint_error_to_kapi)?;

            let endpoint = owned.into_inner().ok_or(KapiError::NotFound)?;
            let listener =
                crate::net::l4::tcp::TcpListener::from_endpoint_with_drop(endpoint, false);
            let fd = listener.into_retained_handle();
            Ok(kernel_api::resource::net::TcpListener::from_raw_parts(
                fd.raw() as u64,
                scope,
            ))
        })
    }

    fn net_tcp_listener_accept(
        &self,
        listener: kernel_api::resource::net::TcpListener,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::TcpStream>> + Send>>
    {
        Box::pin(async move {
            let fd = crate::net::l4::endpoint::EndpointFd::from_raw(listener.id() as u32);
            let socket = lookup_endpoint(fd)?;
            let (accepted, _addr, _if_id) =
                socket.accept().await.map_err(endpoint_error_to_kapi)?;
            let endpoint = accepted.into_inner().ok_or(KapiError::NotFound)?;
            let stream = crate::net::l4::tcp::TcpStream::from_endpoint_with_drop(endpoint, false);
            let fd = stream.into_retained_handle();
            Ok(kernel_api::resource::net::TcpStream::from_raw_parts(
                fd.raw() as u64,
                listener.default_scope(),
            ))
        })
    }

    fn net_close_tcp_stream(
        &self,
        stream: kernel_api::resource::net::TcpStream,
    ) -> Result<(), KapiError> {
        close_endpoint_handle(crate::net::l4::endpoint::EndpointFd::from_raw(
            stream.id() as u32
        ))
    }

    fn net_close_tcp_listener(
        &self,
        listener: kernel_api::resource::net::TcpListener,
    ) -> Result<(), KapiError> {
        close_endpoint_handle(crate::net::l4::endpoint::EndpointFd::from_raw(
            listener.id() as u32,
        ))
    }

    fn net_tcp_stream_recv_payload(
        &self,
        stream: kernel_api::resource::net::TcpStream,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::PacketPayload>> + Send>>
    {
        Box::pin(async move {
            let fd = crate::net::l4::endpoint::EndpointFd::from_raw(stream.id() as u32);
            let socket = lookup_endpoint(fd)?;
            let mut stream = crate::net::l4::tcp::TcpStream::from_endpoint_with_drop(socket, false);
            match stream.read_zero_copy().await {
                Some(packet) => Ok(kernel_api::resource::net::PacketPayload::single(packet)),
                None => Ok(kernel_api::resource::net::PacketPayload::default()),
            }
        })
    }

    fn net_tcp_stream_send_payload(
        &self,
        stream: kernel_api::resource::net::TcpStream,
        payload: kernel_api::resource::net::PacketPayload,
    ) -> Pin<Box<dyn Future<Output = KapiResult<usize>> + Send>> {
        Box::pin(async move {
            let fd = crate::net::l4::endpoint::EndpointFd::from_raw(stream.id() as u32);
            let socket = lookup_endpoint(fd)?;
            let mut stream = crate::net::l4::tcp::TcpStream::from_endpoint_with_drop(socket, false);
            let mut sent = 0usize;
            for packet in payload.into_segments() {
                let len = packet.len();
                if len == 0 {
                    continue;
                }
                stream
                    .write_zero_copy(packet)
                    .await
                    .map_err(tcp_error_to_kapi)?;
                sent = sent.saturating_add(len);
            }
            Ok(sent)
        })
    }

    fn net_open_raw_endpoint(
        &self,
        scope: kernel_api::resource::net::InterfaceScope,
    ) -> Result<kernel_api::resource::net::RawEndpoint, KapiError> {
        // Security: Check for CAP_NET_RAW capability (Design Doc 8.2)
        let caller = context::current_subject().domain.as_u64();
        if !crate::security::capability::manager()
            .has_capability(caller, crate::security::capability::CAP_NET_RAW)
        {
            log::warn!(
                "[KAPI][SECURITY] Domain {} tried to create a raw endpoint without CAP_NET_RAW",
                caller
            );
            return Err(KapiError::PermissionDenied);
        }

        use crate::net::l4::endpoint::create_raw_endpoint;

        let owned = create_raw_endpoint();
        if let Some(endpoint) = owned.endpoint() {
            apply_endpoint_scope(endpoint, scope);
            let mut inner = endpoint.inner().lock().unwrap_or_else(|e| e.into_inner());
            inner.ensure_raw();
            inner
                .transition_to(crate::net::l4::endpoint::types::EndpointState::Bound)
                .map_err(endpoint_error_to_kapi)?;
        }

        if let Some(mgr_lock) = crate::net::l4::endpoint::endpoint_manager() {
            let guard = mgr_lock.read().unwrap_or_else(|e| e.into_inner());
            if let Some(mgr) = guard.as_ref() {
                mgr.register_raw_scope(stack_scope(scope), owned.fd())
                    .map_err(endpoint_error_to_kapi)?;
            }
        }
        let fd = owned.fd();

        // Detach so it remains registered
        let _ = owned.into_inner();

        Ok(kernel_api::resource::net::RawEndpoint::from_raw_parts(
            fd.raw() as u64,
            scope,
        ))
    }

    fn net_close_raw_endpoint(
        &self,
        endpoint: kernel_api::resource::net::RawEndpoint,
    ) -> Result<(), KapiError> {
        close_endpoint_handle(crate::net::l4::endpoint::EndpointFd::from_raw(
            endpoint.id() as u32,
        ))
    }

    fn net_raw_recv_payload(
        &self,
        endpoint: kernel_api::resource::net::RawEndpoint,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::PacketPayload>> + Send>>
    {
        // Security: Check for CAP_NET_RAW capability
        let caller = context::current_subject().domain.as_u64();
        if !crate::security::capability::manager()
            .has_capability(caller, crate::security::capability::CAP_NET_RAW)
        {
            log::warn!(
                "[KAPI][SECURITY] Domain {} tried to recv raw without CAP_NET_RAW",
                caller
            );
            return Box::pin(async { Err(KapiError::PermissionDenied) });
        }

        Box::pin(async move {
            let fd = crate::net::l4::endpoint::EndpointFd::from_raw(endpoint.id() as u32);
            let socket = lookup_endpoint(fd)?;

            core::future::poll_fn(|cx| match socket.recv_raw_payload_sync() {
                Ok((payload, _if_id)) => core::task::Poll::Ready(Ok(payload)),
                Err(crate::net::l4::endpoint::EndpointError::Timeout) => {
                    socket.register_recv_waker(cx.waker().clone());
                    core::task::Poll::Pending
                }
                Err(err) => core::task::Poll::Ready(Err(endpoint_error_to_kapi(err))),
            })
            .await
        })
    }

    fn net_raw_send_payload(
        &self,
        endpoint: kernel_api::resource::net::RawEndpoint,
        payload: kernel_api::resource::net::PacketPayload,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        // Security: Check for CAP_NET_RAW capability
        let caller = context::current_subject().domain.as_u64();
        if !crate::security::capability::manager()
            .has_capability(caller, crate::security::capability::CAP_NET_RAW)
        {
            log::warn!(
                "[KAPI][SECURITY] Domain {} tried to send raw without CAP_NET_RAW",
                caller
            );
            return Box::pin(async { Err(KapiError::PermissionDenied) });
        }

        Box::pin(async move {
            let resolved_scope = endpoint.default_scope();
            let fd = crate::net::l4::endpoint::EndpointFd::from_raw(endpoint.id() as u32);
            let socket = lookup_endpoint(fd)?;
            apply_endpoint_scope(&socket, resolved_scope);

            let runtime = socket.runtime();
            let mut guard = crate::net::runtime::stack::stack_in(runtime)
                .lock()
                .map_err(|_| KapiError::IoError)?;
            let stack = guard.as_mut().ok_or(KapiError::NotFound)?;
            stack
                .send_raw_ip_payload_scoped(stack_scope(resolved_scope), payload)
                .map_err(network_error_to_kapi)
        })
    }

    // ========================================================================
    // Filesystem (Connected to memfs)
    // ========================================================================

    fn fs_open_with_token(
        &self,
        path: &str,
        mode: OpenMode,
        token: Option<u64>,
    ) -> Result<FileHandle, KapiError> {
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
            if !crate::security::capability::manager().validate_token(
                caller,
                t,
                crate::security::capability::CAP_FOWNER,
            ) {
                return Err(KapiError::PermissionDenied);
            }

            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(KapiError::PermissionDenied);
            }
        }

        // Register in file handle table
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
        let block_size = crate::runtime_bridge::standalone_nvme_namespace_info(nsid)
            .map(|info| info.block_size)
            .or_else(|| crate::io::nvme::with_driver(|driver| driver.namespace_block_size(nsid)))
            .unwrap_or(512);

        let caller = context::current_subject().domain.as_u64();

        // If token provided, validate and increment in-flight counter
        if let Some(t) = token {
            if !crate::security::capability::manager().validate_token(
                caller,
                t,
                crate::security::capability::CAP_DMA,
            ) {
                return Err(KapiError::PermissionDenied);
            }
            if let Err(_) = crate::security::capability::manager().increment_in_flight(t) {
                return Err(KapiError::PermissionDenied);
            }
        }

        // Register the open in kernel registry and return a handle with open_id
        let id = NVME_DIRECT_REGISTRY.register(
            device_id,
            start_block,
            block_count,
            block_size,
            caller,
            token,
        );
        Ok(DirectBlockHandle::new_with_id(
            device_id,
            start_block,
            block_count,
            block_size,
            id,
        ))
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
        crate::runtime_bridge::standalone_nvme_namespace_info(nsid)
            .map(|info| info.block_size as u64)
            .or_else(|| {
                crate::io::nvme::with_driver(|driver| driver.namespace_block_size(nsid) as u64)
            })
    }

    fn nvme_sgl_max_entries(&self, device_id: u64) -> Option<usize> {
        let nsid = if device_id == 0 { 1 } else { device_id as u32 };
        crate::runtime_bridge::standalone_nvme_namespace_info(nsid)
            .map(|info| info.max_sgl_entries as usize)
            .or_else(|| {
                crate::io::nvme::global::with_driver(
                    |driver: &crate::io::nvme::NvmePollingDriver| driver.sgl_max_entries(),
                )
                .flatten()
            })
    }

    fn nvme_submit_rw(
        &self,
        request: NvmeRwRequest,
        io_type: NvmeIoType,
    ) -> KapiResult<NvmeIoHandle> {
        use crate::io::io_scheduler::{
            DeviceId as IoDeviceId, DmaBufHandle, IoCommand, IoPriority,
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

        let future = crate::io::io_scheduler::hybrid_coordinator()
            .submit_io_command(device, command, priority);
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
            // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
            loop {
                if let Some(result) =
                    crate::io::io_scheduler::io_scheduler().take_result(request_id)
                {
                    return match result {
                        SchedIoResult::Success(bytes) => NvmeIoResult::Success(bytes),
                        SchedIoResult::Error(e) => match e {
                            crate::io::io_scheduler::IoError::Timeout => NvmeIoResult::Timeout,
                            crate::io::io_scheduler::IoError::Cancelled => NvmeIoResult::Cancelled,
                            crate::io::io_scheduler::IoError::InvalidParameter => {
                                NvmeIoResult::InvalidParameter
                            }
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
                    crate::io::io_scheduler::IoError::InvalidParameter => {
                        NvmeIoResult::InvalidParameter
                    }
                    _ => NvmeIoResult::DeviceError,
                },
            };
            hook(converted);
        });

        crate::io::io_scheduler::io_scheduler().register_completion_hook(request_id, wrapper);
    }

    fn ipc_create_channel(&self) -> Result<(ChannelHandle, ChannelHandle), KapiError> {
        let (writer_id, reader_id) = CHANNEL_REGISTRY.create_channel();
        Ok((ChannelHandle::new(writer_id), ChannelHandle::new(reader_id)))
    }

    fn ipc_close(&self, channel: ChannelHandle) -> Result<(), KapiError> {
        let channel_id = channel.id();
        if CHANNEL_REGISTRY.unregister(channel_id).is_some() {
            Ok(())
        } else {
            Err(KapiError::InvalidHandle)
        }
    }

    fn ipc_current_domain(&self) -> kernel_api::ipc::DomainId {
        kernel_api::ipc::DomainId::new(context::current_subject().domain.as_u64())
    }

    fn exchange_alloc_raw(
        &self,
        size: usize,
        align: usize,
    ) -> Result<(NonNull<u8>, kernel_api::ipc::DomainId), KapiError> {
        let layout = core::alloc::Layout::from_size_align(size.max(1), align.max(1))
            .map_err(|_| KapiError::InvalidHandle)?;
        let owner = context::current_subject().domain;
        let ptr =
            crate::mm::cache::exchange_heap::allocate_raw(layout).ok_or(KapiError::OutOfMemory)?;
        crate::sas::register_object(ptr.as_ptr() as usize, layout.size(), owner);
        Ok((ptr, kernel_api::ipc::DomainId::new(owner.as_u64())))
    }

    fn exchange_dealloc_raw(
        &self,
        ptr: NonNull<u8>,
        owner: kernel_api::ipc::DomainId,
        size: usize,
        align: usize,
    ) -> Result<(), KapiError> {
        let caller = context::current_subject().domain.as_u64();
        if owner != kernel_api::ipc::DomainId::KERNEL && caller != owner.as_u64() {
            return Err(KapiError::PermissionDenied);
        }
        if owner != kernel_api::ipc::DomainId::KERNEL
            && crate::sas::get_owner(ptr.as_ptr() as usize)
                != Some(crate::domain_system::DomainId::new(owner.as_u64()))
        {
            return Err(KapiError::PermissionDenied);
        }

        let layout = core::alloc::Layout::from_size_align(size.max(1), align.max(1))
            .map_err(|_| KapiError::InvalidHandle)?;
        crate::sas::unregister_any(ptr.as_ptr() as usize);
        unsafe {
            crate::mm::cache::exchange_heap::deallocate_raw(ptr, layout);
        }
        Ok(())
    }

    fn exchange_transfer_raw(
        &self,
        ptr: NonNull<u8>,
        from: kernel_api::ipc::DomainId,
        to: kernel_api::ipc::DomainId,
    ) -> Result<(), KapiError> {
        let caller = context::current_subject().domain.as_u64();
        if from != kernel_api::ipc::DomainId::KERNEL && caller != from.as_u64() {
            return Err(KapiError::PermissionDenied);
        }
        crate::sas::transfer_ownership(
            ptr.as_ptr() as usize,
            crate::domain_system::DomainId::new(from.as_u64()),
            crate::domain_system::DomainId::new(to.as_u64()),
        )
        .map_err(|_| KapiError::PermissionDenied)
    }

    fn ipc_send_raw(&self, channel: ChannelHandle, mut raw: AbiRRefRaw) -> Result<(), KapiError> {
        let caller = context::current_subject().domain;
        let ptr = NonNull::new(raw.ptr).ok_or(KapiError::InvalidHandle)?;
        if let Err(err) = self.exchange_transfer_raw(
            ptr,
            kernel_api::ipc::DomainId::new(caller.as_u64()),
            kernel_api::ipc::DomainId::KERNEL,
        ) {
            drop_abi_rref_raw(raw);
            return Err(err);
        }

        raw.owner = kernel_api::ipc::DomainId::KERNEL.as_u64();
        if let Err(err) = CHANNEL_REGISTRY.send_raw(channel, caller.as_u64(), raw) {
            if crate::sas::transfer_ownership(
                ptr.as_ptr() as usize,
                crate::domain_system::DomainId::KERNEL,
                caller,
            )
            .is_ok()
            {
                raw.owner = caller.as_u64();
            }
            drop_abi_rref_raw(raw);
            return Err(err);
        }
        Ok(())
    }

    fn ipc_recv_raw(&self, channel: ChannelHandle) -> Result<AbiRRefRaw, KapiError> {
        let caller = context::current_subject().domain;
        let mut raw = CHANNEL_REGISTRY.recv_raw(channel, caller.as_u64())?;
        let ptr = NonNull::new(raw.ptr).ok_or(KapiError::InvalidHandle)?;
        self.exchange_transfer_raw(
            ptr,
            kernel_api::ipc::DomainId::KERNEL,
            kernel_api::ipc::DomainId::new(caller.as_u64()),
        )?;
        raw.owner = caller.as_u64();
        Ok(raw)
    }

    fn time_service(&self) -> Option<&dyn kernel_api::service::time::TimeService> {
        crate::provider_registry::time_service()
    }

    fn platform_acpi(&self) -> Option<&dyn kernel_api::service::platform::AcpiServices> {
        crate::provider_registry::acpi_service()
    }

    fn platform_pci(&self) -> Option<&dyn kernel_api::service::platform::PciServices> {
        crate::provider_registry::pci_service()
    }

    fn platform_apic(&self) -> Option<&dyn kernel_api::service::platform::ApicServices> {
        crate::provider_registry::apic_service()
    }

    fn storage(&self) -> Option<&dyn kernel_api::service::storage::StorageServices> {
        crate::provider_registry::storage_service()
    }

    fn netdev(&self) -> Option<&dyn kernel_api::service::netdev::NetDeviceServices> {
        crate::provider_registry::netdev_service()
    }

    fn input(&self) -> Option<&dyn kernel_api::service::input::InputServices> {
        crate::provider_registry::input_service()
    }

    fn serial(&self) -> Option<&dyn kernel_api::service::serial::SerialServices> {
        crate::provider_registry::serial_service()
    }

    fn graphics(&self) -> Option<&dyn kernel_api::service::graphics::GraphicsServices> {
        crate::provider_registry::graphics_service()
    }

    fn audio(&self) -> Option<&dyn kernel_api::service::audio::AudioServices> {
        crate::provider_registry::audio_service()
    }

    fn gui(&self) -> Option<&dyn kernel_api::service::gui::GuiServices> {
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

    fn shell(&self) -> Option<&dyn kernel_api::service::shell::ShellServices> {
        // Shell services are always available
        Some(self)
    }
}
