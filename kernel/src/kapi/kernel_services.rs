use super::*;
use crate::kapi::device_registration::{
    authorize_dma_device_for_current_subject, register_block_device_for_current_subject,
    register_netdev_port_for_current_subject, register_nvme_namespace_for_current_subject,
    unregister_block_device_for_current_subject, unregister_netdev_port_for_current_subject,
    unregister_nvme_namespace_for_current_subject,
};
use crate::kapi::memory::release_dma_buffer;
use crate::kapi::net::{
    close_socket_handle, endpoint_addr_from_kapi, endpoint_error_to_kapi, lookup_socket,
    stack_scope, tcp_error_to_kapi,
};
use kernel_api::abi::driver::{
    AbiBlockDeviceRegistration, AbiNetPortRegistration, AbiNvmeNamespaceRegistration, AbiRRefRaw,
    PackedPciLocation,
};
use kernel_api::msix::MsixVectorInfo;

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
        crate::kapi::task::spawn_task(future)
    }

    fn current_tick(&self) -> u64 {
        crate::kapi::task::current_tick()
    }

    fn current_task_id(&self) -> u64 {
        crate::kapi::task::current_task_id()
    }

    // ========================================================================
    // Memory Management
    // ========================================================================

    fn alloc_dma_for_device(
        &self,
        size: usize,
        device_id: PackedPciLocation,
    ) -> Result<DmaBuffer, KapiError> {
        let caller = current_subject().domain.as_u64();
        let dev_id = authorize_dma_device_for_current_subject(device_id)?;
        let ctx = dma::DeviceDmaContext::for_attached_device(dev_id);
        match ctx.alloc_region(size, dma::DmaMemoryAttributes::MMIO) {
            Ok(region) => {
                let slot = region.full_slot();
                let phys = slot.host_addr();
                let dev_addr = slot.device_addr();
                let virt_ptr = slot.as_ptr() as usize;

                let boxed: Box<dyn core::any::Any + Send> = Box::new(region.into_inner());
                let dma_handle_id =
                    crate::resource_registry::dma::register_allocation(boxed, phys, size, caller);
                Ok(unsafe {
                    // SAFETY: `virt_ptr`/`size` come from a live DMA region that remains owned by
                    // the kernel registry until the exported handle releaser is invoked.
                    DmaBuffer::from_internal_parts_unchecked(
                        phys,
                        dev_addr,
                        virt_ptr as *mut u8,
                        size,
                        kernel_api::dma::InternalDmaReclaimer::KernelHandle {
                            dma_handle_id,
                            releaser: Some(release_dma_buffer),
                        },
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
        crate::io::msix::enable_for_owner(current_subject().domain, device_id, requested_count)
    }

    fn disable_msix(&self, device_id: PackedPciLocation) -> Result<(), KapiError> {
        let owner = current_subject().domain;
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
        register_block_device_for_current_subject(registration)
    }

    fn unregister_block_device(&self, handle: u64) -> Result<(), KapiError> {
        unregister_block_device_for_current_subject(handle)
    }

    fn register_nvme_namespace(
        &self,
        registration: &AbiNvmeNamespaceRegistration,
    ) -> Result<u64, KapiError> {
        register_nvme_namespace_for_current_subject(registration)
    }

    fn unregister_nvme_namespace(&self, handle: u64) -> Result<(), KapiError> {
        unregister_nvme_namespace_for_current_subject(handle)
    }

    fn register_netdev_port(
        &self,
        registration: &AbiNetPortRegistration,
    ) -> Result<u64, KapiError> {
        register_netdev_port_for_current_subject(registration)
    }

    fn unregister_netdev_port(&self, handle: u64) -> Result<(), KapiError> {
        unregister_netdev_port_for_current_subject(handle)
    }

    // ========================================================================
    // Network (Connected to network stack)
    // ========================================================================

    fn net_tcp_connection_dial(
        &self,
        remote: kernel_api::resource::net::NetSocketAddr,
        scope: kernel_api::resource::net::InterfaceScope,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::TcpConnection>> + Send>>
    {
        Box::pin(async move {
            let remote = endpoint_addr_from_kapi(remote);
            let stream = crate::net::l4::tcp::TcpConnection::dial_scoped_in(
                crate::net::runtime::default_runtime(),
                stack_scope(scope),
                remote,
            )
            .await
            .map_err(tcp_error_to_kapi)?;
            let fd = stream.into_retained_handle();
            Ok(kernel_api::resource::net::TcpConnection::from_raw_parts(
                fd.raw() as u64,
                scope,
            ))
        })
    }

    fn net_tcp_acceptor_bind(
        &self,
        local: kernel_api::resource::net::NetSocketAddr,
        scope: kernel_api::resource::net::InterfaceScope,
        backlog: u32,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::TcpAcceptor>> + Send>>
    {
        Box::pin(async move {
            let local = endpoint_addr_from_kapi(local);
            let acceptor = crate::net::l4::tcp::TcpAcceptor::bind_scoped_in(
                crate::net::runtime::default_runtime(),
                stack_scope(scope),
                local,
                backlog,
            )
            .await
            .map_err(tcp_error_to_kapi)?;
            let fd = acceptor.into_retained_handle();
            Ok(kernel_api::resource::net::TcpAcceptor::from_raw_parts(
                fd.raw() as u64,
                scope,
            ))
        })
    }

    fn net_tcp_acceptor_next_connection(
        &self,
        listener: kernel_api::resource::net::TcpAcceptor,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::TcpConnection>> + Send>>
    {
        let default_scope = listener.default_scope();
        Box::pin(async move {
            let fd = crate::net::l4::types::SocketId::from_raw(listener.id() as u32);
            let socket = lookup_socket(fd)?;
            let acceptor = crate::net::l4::tcp::TcpAcceptor::from_retained_socket(socket);
            let (connection, _addr) = acceptor
                .next_connection()
                .await
                .map_err(tcp_error_to_kapi)?;
            let fd = connection.into_retained_handle();
            Ok(kernel_api::resource::net::TcpConnection::from_raw_parts(
                fd.raw() as u64,
                default_scope,
            ))
        })
    }

    fn net_tcp_connection_close(
        &self,
        stream: kernel_api::resource::net::TcpConnection,
    ) -> Result<(), KapiError> {
        close_socket_handle(crate::net::l4::types::SocketId::from_raw(stream.id() as u32))
    }

    fn net_tcp_acceptor_close(
        &self,
        listener: kernel_api::resource::net::TcpAcceptor,
    ) -> Result<(), KapiError> {
        close_socket_handle(crate::net::l4::types::SocketId::from_raw(
            listener.id() as u32
        ))
    }

    fn net_tcp_connection_recv_payload(
        &self,
        stream: kernel_api::resource::net::TcpConnection,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::PacketPayload>> + Send>>
    {
        Box::pin(async move {
            let fd = crate::net::l4::types::SocketId::from_raw(stream.id() as u32);
            let socket = lookup_socket(fd)?;
            let mut connection = crate::net::l4::tcp::TcpConnection::from_retained_socket(socket);
            match connection.recv_payload().await {
                Some(payload) => Ok(payload),
                None => Ok(kernel_api::resource::net::PacketPayload::default()),
            }
        })
    }

    fn net_tcp_connection_send_payload(
        &self,
        stream: kernel_api::resource::net::TcpConnection,
        payload: kernel_api::resource::net::PacketPayload,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        Box::pin(async move {
            let fd = crate::net::l4::types::SocketId::from_raw(stream.id() as u32);
            let socket = lookup_socket(fd)?;
            let mut connection = crate::net::l4::tcp::TcpConnection::from_retained_socket(socket);
            connection
                .send_payload(payload)
                .await
                .map_err(tcp_error_to_kapi)
        })
    }

    fn net_raw_endpoint_open(
        &self,
        scope: kernel_api::resource::net::InterfaceScope,
    ) -> Result<kernel_api::resource::net::RawEndpoint, KapiError> {
        // Security: Check for CAP_NET_RAW capability (Design Doc 8.2)
        let caller = current_subject().domain.as_u64();
        if !crate::security::capability::manager()
            .has_capability(caller, crate::security::capability::CAP_NET_RAW)
        {
            log::warn!(
                "[KAPI][SECURITY] Domain {} tried to create a raw endpoint without CAP_NET_RAW",
                caller
            );
            return Err(KapiError::PermissionDenied);
        }

        let endpoint = crate::net::l4::raw::RawEndpoint::open_in(
            crate::net::runtime::default_runtime(),
            stack_scope(scope),
        )
        .map_err(endpoint_error_to_kapi)?;
        let fd = endpoint.into_retained_handle();

        Ok(kernel_api::resource::net::RawEndpoint::from_raw_parts(
            fd.raw() as u64,
            scope,
        ))
    }

    fn net_raw_endpoint_close(
        &self,
        endpoint: kernel_api::resource::net::RawEndpoint,
    ) -> Result<(), KapiError> {
        let fd = crate::net::l4::types::SocketId::from_raw(endpoint.id() as u32);
        let socket = lookup_socket(fd)?;
        crate::net::l4::raw::RawEndpoint::from_registered_socket(socket)
            .close()
            .map_err(endpoint_error_to_kapi)
    }

    fn net_raw_endpoint_recv_payload(
        &self,
        endpoint: kernel_api::resource::net::RawEndpoint,
    ) -> Pin<Box<dyn Future<Output = KapiResult<kernel_api::resource::net::PacketPayload>> + Send>>
    {
        // Security: Check for CAP_NET_RAW capability
        let caller = current_subject().domain.as_u64();
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
            let fd = crate::net::l4::types::SocketId::from_raw(endpoint.id() as u32);
            let socket = lookup_socket(fd)?;
            let raw = crate::net::l4::raw::RawEndpoint::from_retained_socket(socket);
            raw.recv_payload()
                .await
                .map(|(payload, _if_id)| payload)
                .map_err(endpoint_error_to_kapi)
        })
    }

    fn net_raw_endpoint_send_payload(
        &self,
        endpoint: kernel_api::resource::net::RawEndpoint,
        payload: kernel_api::resource::net::PacketPayload,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        // Security: Check for CAP_NET_RAW capability
        let caller = current_subject().domain.as_u64();
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
            let fd = crate::net::l4::types::SocketId::from_raw(endpoint.id() as u32);
            let socket = lookup_socket(fd)?;
            let raw = crate::net::l4::raw::RawEndpoint::from_retained_socket(socket);
            raw.set_scope(stack_scope(resolved_scope));
            raw.send_payload(payload)
                .await
                .map_err(endpoint_error_to_kapi)
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
        crate::kapi::fs::open_with_token(path, mode, token)
    }

    fn fs_close(&self, handle: FileHandle) -> Result<(), KapiError> {
        crate::kapi::fs::close(handle)
    }

    fn nvme_open_direct_with_token(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        token: Option<u64>,
    ) -> Result<DirectBlockHandle, KapiError> {
        crate::kapi::storage::open_direct_with_token(device_id, start_block, block_count, token)
    }

    fn nvme_close_direct(&self, handle: DirectBlockHandle) -> Result<(), KapiError> {
        crate::kapi::storage::close_direct(handle)
    }

    fn nvme_read_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
        crate::kapi::storage::read_blocks_dma(handle, block_offset, buffer)
    }

    fn nvme_write_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>> {
        crate::kapi::storage::write_blocks_dma(handle, block_offset, buffer)
    }

    fn nvme_flush_direct(
        &self,
        handle: DirectBlockHandle,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        crate::kapi::storage::flush_direct(handle)
    }

    fn nvme_discard_direct(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        block_count: u64,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
        crate::kapi::storage::discard_direct(handle, block_offset, block_count)
    }

    fn nvme_block_size(&self, device_id: u64) -> Option<u64> {
        crate::kapi::storage::block_size(device_id)
    }

    fn nvme_sgl_max_entries(&self, device_id: u64) -> Option<usize> {
        crate::kapi::storage::sgl_max_entries(device_id)
    }

    fn nvme_submit_rw(
        &self,
        request: NvmeRwRequest,
        io_type: NvmeIoType,
    ) -> KapiResult<NvmeIoHandle> {
        crate::kapi::storage::submit_rw(request, io_type)
    }

    fn nvme_wait_io(
        &self,
        handle: NvmeIoHandle,
    ) -> Pin<Box<dyn Future<Output = NvmeIoResult> + Send>> {
        crate::kapi::storage::wait_io(handle)
    }

    fn nvme_register_completion_hook(
        &self,
        handle: NvmeIoHandle,
        hook: Box<dyn FnOnce(NvmeIoResult) + Send>,
    ) {
        crate::kapi::storage::register_completion_hook(handle, hook)
    }

    fn ipc_create_channel(&self) -> Result<(ChannelHandle, ChannelHandle), KapiError> {
        crate::kapi::ipc::create_channel()
    }

    fn ipc_close(&self, channel: ChannelHandle) -> Result<(), KapiError> {
        crate::kapi::ipc::close(channel)
    }

    fn ipc_current_domain(&self) -> kernel_api::ipc::DomainId {
        crate::kapi::ipc::current_domain()
    }

    fn exchange_alloc_raw(
        &self,
        size: usize,
        align: usize,
    ) -> Result<(NonNull<u8>, kernel_api::ipc::DomainId), KapiError> {
        crate::kapi::ipc::exchange_alloc_raw(size, align)
    }

    fn exchange_dealloc_raw(
        &self,
        ptr: NonNull<u8>,
        owner: kernel_api::ipc::DomainId,
        size: usize,
        align: usize,
    ) -> Result<(), KapiError> {
        crate::kapi::ipc::exchange_dealloc_raw(ptr, owner, size, align)
    }

    fn exchange_transfer_raw(
        &self,
        ptr: NonNull<u8>,
        from: kernel_api::ipc::DomainId,
        to: kernel_api::ipc::DomainId,
    ) -> Result<(), KapiError> {
        crate::kapi::ipc::exchange_transfer_raw(ptr, from, to)
    }

    fn ipc_send_raw(&self, channel: ChannelHandle, raw: AbiRRefRaw) -> Result<(), KapiError> {
        crate::kapi::ipc::send_raw(channel, raw)
    }

    fn ipc_recv_raw(&self, channel: ChannelHandle) -> Result<AbiRRefRaw, KapiError> {
        crate::kapi::ipc::recv_raw(channel)
    }

    fn time_service(&self) -> Option<&dyn kernel_api::service::time::TimeService> {
        crate::kapi::providers::time_service()
    }

    fn platform_acpi(&self) -> Option<&dyn kernel_api::service::platform::AcpiServices> {
        crate::kapi::providers::acpi_service()
    }

    fn platform_pci(&self) -> Option<&dyn kernel_api::service::platform::PciServices> {
        crate::kapi::providers::pci_service()
    }

    fn platform_apic(&self) -> Option<&dyn kernel_api::service::platform::ApicServices> {
        crate::kapi::providers::apic_service()
    }

    fn storage(&self) -> Option<&dyn kernel_api::service::storage::StorageServices> {
        crate::kapi::providers::storage_service()
    }

    fn netdev(&self) -> Option<&dyn kernel_api::service::netdev::NetDeviceServices> {
        crate::kapi::providers::netdev_service()
    }

    fn input(&self) -> Option<&dyn kernel_api::service::input::InputServices> {
        crate::kapi::providers::input_service()
    }

    fn serial(&self) -> Option<&dyn kernel_api::service::serial::SerialServices> {
        crate::kapi::providers::serial_service()
    }
}

#[cfg(test)]
mod dma_tests {
    use super::*;
    use crate::domain::{DomainCredentials, DomainId};
    use crate::task::{ExecutionContext, Subject, TaskId};
    use core::sync::atomic::{AtomicUsize, Ordering};
    use kernel_api::ipc::{RRef, RRefError};
    use kernel_api::service::kernel::KernelServices;

    static DROP_COUNTER_A: AtomicUsize = AtomicUsize::new(0);
    static DROP_COUNTER_B: AtomicUsize = AtomicUsize::new(0);
    static DROP_COUNTER_C: AtomicUsize = AtomicUsize::new(0);

    fn reset_drop_counters() {
        DROP_COUNTER_A.store(0, Ordering::SeqCst);
        DROP_COUNTER_B.store(0, Ordering::SeqCst);
        DROP_COUNTER_C.store(0, Ordering::SeqCst);
    }

    fn set_current_subject(domain_id: DomainId) -> crate::cpu::ExecutionContextGuard {
        let current = crate::cpu::CurrentCpu::acquire().expect("test CPU-local state");
        let caps = crate::security::capability::manager().get_capabilities(domain_id.as_u64());
        current.enter_execution(ExecutionContext {
            subject: Subject {
                domain: domain_id,
                task: TaskId::new(),
                cred: DomainCredentials::ROOT,
                caps,
            },
        })
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn authorize_pci_locator_allows_kernel_domain() {
        let locator = PackedPciLocation::new(0, 0, 1, 0);
        assert!(authorize_pci_locator_for_domain(DomainId::KERNEL, locator, None).is_ok());
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn authorize_pci_locator_rejects_missing_driver_binding() {
        let locator = PackedPciLocation::new(0, 0, 2, 0);
        let err = authorize_pci_locator_for_domain(DomainId::new(800), locator, None).unwrap_err();
        assert!(matches!(err, KapiError::PermissionDenied));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn authorize_pci_locator_rejects_mismatched_driver_binding() {
        let bound = PackedPciLocation::new(0, 0, 3, 0);
        let requested = PackedPciLocation::new(0, 0, 4, 0);
        let err = authorize_pci_locator_for_domain(DomainId::new(801), requested, Some(bound))
            .unwrap_err();
        assert!(matches!(err, KapiError::PermissionDenied));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn authorize_pci_locator_accepts_matching_driver_binding() {
        let locator = PackedPciLocation::new(0, 0, 5, 0);
        assert!(
            authorize_pci_locator_for_domain(DomainId::new(802), locator, Some(locator)).is_ok()
        );
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn authorize_dma_device_for_current_subject_rejects_unbound_domain() {
        let _subject_guard = set_current_subject(DomainId::new(803));
        let locator = PackedPciLocation::new(0, 0, 6, 0);
        let err = authorize_dma_device_for_current_subject(locator).unwrap_err();
        assert!(matches!(err, KapiError::PermissionDenied));
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn authorize_dma_device_for_current_subject_allows_kernel_domain() {
        let _subject_guard = set_current_subject(DomainId::KERNEL);
        let locator = PackedPciLocation::new(0x1234, 0x56, 0x07, 0x01);
        let device = authorize_dma_device_for_current_subject(locator)
            .expect("kernel domain should bypass driver binding lookup");

        assert_eq!(device.segment, 0x1234);
        assert_eq!(device.bus, 0x56);
        assert_eq!(device.device, 0x07);
        assert_eq!(device.function, 0x01);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn release_dma_buffer_checked_rejects_foreign_owner_and_keeps_entry() {
        let _dma_guard = crate::resource_registry::dma::testing::acquire_test_dma_state_guard();
        reset_drop_counters();

        let owner = DomainId::new(500);
        let caller = DomainId::new(501);
        let phys = 0x1000;
        let size = 4096;
        let handle = crate::resource_registry::dma::testing::register_test_dma_entry(
            owner.as_u64(),
            phys,
            size,
            &DROP_COUNTER_A,
        );

        let _caller_guard = set_current_subject(caller);
        let err = release_dma_buffer_checked(handle).unwrap_err();

        assert!(matches!(err, KapiError::PermissionDenied));
        assert!(crate::resource_registry::dma::testing::test_dma_handle_exists(handle));
        assert!(
            crate::resource_registry::dma::testing::test_dma_phys_owned_by(
                phys,
                size,
                owner.as_u64()
            )
        );
        assert_eq!(DROP_COUNTER_A.load(Ordering::SeqCst), 0);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn release_dma_buffer_checked_releases_owned_entry() {
        let _dma_guard = crate::resource_registry::dma::testing::acquire_test_dma_state_guard();
        reset_drop_counters();

        let owner = DomainId::new(600);
        let phys = 0x2000;
        let size = 2048;
        let handle = crate::resource_registry::dma::testing::register_test_dma_entry(
            owner.as_u64(),
            phys,
            size,
            &DROP_COUNTER_A,
        );

        let _owner_guard = set_current_subject(owner);
        release_dma_buffer_checked(handle).expect("owned DMA handle release should succeed");

        assert!(!crate::resource_registry::dma::testing::test_dma_handle_exists(handle));
        assert!(
            !crate::resource_registry::dma::testing::test_dma_phys_owned_by(
                phys,
                size,
                owner.as_u64()
            )
        );
        assert_eq!(DROP_COUNTER_A.load(Ordering::SeqCst), 1);
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn fs_close_rejects_foreign_owner() {
        let owner = DomainId::new(900);
        let caller = DomainId::new(901);

        let handle = {
            let _owner_guard = set_current_subject(owner);
            EXOKERNEL
                .fs_open_with_token("foreign-close-test", OpenMode::Write, None)
                .expect("owner should open file")
        };
        let handle_id = handle.id();
        let mode = handle.mode();

        {
            let _caller_guard = set_current_subject(caller);
            let err = EXOKERNEL.fs_close(handle).unwrap_err();
            assert!(matches!(err, KapiError::PermissionDenied));
        }

        {
            let _owner_guard = set_current_subject(owner);
            EXOKERNEL
                .fs_close(FileHandle::new(handle_id, mode))
                .expect("owner should still be able to close file");
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn nvme_direct_handle_rejects_use_after_close() {
        let owner = DomainId::new(910);
        let handle = {
            let _owner_guard = set_current_subject(owner);
            EXOKERNEL
                .nvme_open_direct_with_token(0, 0, 1, None)
                .expect("owner should open direct handle")
        };

        {
            let _owner_guard = set_current_subject(owner);
            EXOKERNEL
                .nvme_close_direct(handle)
                .expect("owner should close direct handle");
        }

        {
            let _owner_guard = set_current_subject(owner);
            let err = crate::task::block_on(EXOKERNEL.nvme_flush_direct(handle)).unwrap_err();
            assert!(matches!(err, KapiError::InvalidHandle));
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn nvme_direct_handle_rejects_foreign_domain_use() {
        let owner = DomainId::new(911);
        let caller = DomainId::new(912);
        let handle = {
            let _owner_guard = set_current_subject(owner);
            EXOKERNEL
                .nvme_open_direct_with_token(0, 0, 1, None)
                .expect("owner should open direct handle")
        };

        {
            let _caller_guard = set_current_subject(caller);
            let err = crate::task::block_on(EXOKERNEL.nvme_flush_direct(handle)).unwrap_err();
            assert!(matches!(err, KapiError::PermissionDenied));
        }

        {
            let _owner_guard = set_current_subject(owner);
            EXOKERNEL
                .nvme_close_direct(handle)
                .expect("owner should still be able to close direct handle");
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ipc_close_rejects_foreign_owner() {
        let owner = DomainId::new(920);
        let caller = DomainId::new(921);

        let (sender, receiver) = {
            let _owner_guard = set_current_subject(owner);
            EXOKERNEL
                .ipc_create_channel()
                .expect("owner should create channel")
        };
        let sender_id = sender.id();

        {
            let _caller_guard = set_current_subject(caller);
            let err = EXOKERNEL.ipc_close(sender).unwrap_err();
            assert!(matches!(err, KapiError::PermissionDenied));
        }

        {
            let _owner_guard = set_current_subject(owner);
            EXOKERNEL
                .ipc_close(ChannelHandle::new(sender_id))
                .expect("owner should close sender");
            EXOKERNEL
                .ipc_close(receiver)
                .expect("owner should close receiver");
        }
    }

    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn ipc_send_and_recv_reject_foreign_owner() {
        let owner = DomainId::new(930);
        let caller = DomainId::new(931);

        let (sender, receiver) = {
            let _owner_guard = set_current_subject(owner);
            EXOKERNEL
                .ipc_create_channel()
                .expect("owner should create channel")
        };
        let sender_id = sender.id();
        let receiver_id = receiver.id();

        {
            let _caller_guard = set_current_subject(caller);
            let err = RRef::<u64>::new(7)
                .expect("caller should allocate exchange object")
                .send(ChannelHandle::new(sender_id))
                .unwrap_err();
            assert!(matches!(
                err,
                RRefError::Kernel(KapiError::PermissionDenied)
            ));
        }

        {
            let _owner_guard = set_current_subject(owner);
            RRef::<u64>::new(42)
                .expect("owner should allocate exchange object")
                .send(ChannelHandle::new(sender_id))
                .expect("owner should send on owned channel");
        }

        {
            let _caller_guard = set_current_subject(caller);
            let err = RRef::<u64>::recv(ChannelHandle::new(receiver_id)).unwrap_err();
            assert!(matches!(
                err,
                RRefError::Kernel(KapiError::PermissionDenied)
            ));
        }

        {
            let _owner_guard = set_current_subject(owner);
            let value = RRef::<u64>::recv(ChannelHandle::new(receiver_id))
                .expect("owner should still receive queued value");
            assert_eq!(*value, 42);
            EXOKERNEL
                .ipc_close(ChannelHandle::new(sender_id))
                .expect("owner should close sender");
            EXOKERNEL
                .ipc_close(ChannelHandle::new(receiver_id))
                .expect("owner should close receiver");
        }
    }
}
