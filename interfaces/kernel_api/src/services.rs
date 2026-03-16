// ============================================================================
// kernel_api/src/services.rs - Kernel Services Trait (Dependency Inversion)
// ============================================================================
//!
//! # Kernel Services Interface
//!
//! This module defines the trait that the kernel must implement.
//! Applications and drivers depend only on this trait, not on kernel internals.

extern crate alloc;

use crate::KapiResult;
use crate::abi::driver::{
    AbiAudioControllerRegistration, AbiBlockDeviceRegistration, AbiNetPortRegistration,
    AbiNvmeNamespaceRegistration, AbiRRefRaw, KernelApiV3, PackedPciLocation,
};
use crate::dma::{CpuOwned, DmaSlice};
use crate::ipc::{ChannelHandle, DomainId};
use crate::msix::MsixVectorInfo;
use crate::resource::fs::{FileHandle, OpenMode};
use crate::resource::net::{
    InterfaceScope, NetSocketAddr, Packet, RawEndpointHandle, TcpChunk, TcpListenerHandle,
    TcpStreamHandle,
};
use crate::resource::storage::{
    DirectBlockHandle, NvmeIoHandle, NvmeIoResult, NvmeIoType, NvmeRwRequest,
};
use crate::resource::task::TaskHandle;
use crate::service::{
    audio::AudioServices,
    graphics::GraphicsServices,
    gui::GuiServices,
    input::InputServices,
    netdev::NetDeviceServices,
    platform::{AcpiServices, ApicServices, PciServices},
    serial::SerialServices,
    shell::ShellServices,
    storage::StorageServices,
    time::TimeService,
};
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::ptr::NonNull;

/// Kernel services trait - the contract between kernel and all other components
///
/// The kernel implements this trait and registers itself at boot time.
/// All KAPI functions delegate to this implementation.
pub trait KernelServices: Send + Sync {
    // ========================================================================
    // Task Management
    // ========================================================================

    /// Spawn a new async task
    ///
    /// Returns the TaskHandle on success.
    ///
    /// # Errors
    /// - `KapiError::OutOfMemory` if the kernel cannot allocate resources for the task
    fn spawn_task(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> KapiResult<TaskHandle>;

    /// Get current tick count (milliseconds since boot)
    fn current_tick(&self) -> u64;

    /// Get current task ID
    fn current_task_id(&self) -> u64;

    // ========================================================================
    // Memory Management
    // ========================================================================

    /// Allocate DMA-capable memory for a specific device (IOMMU-aware)
    ///
    /// The locator encodes PCI segment, bus, device, and function.
    /// Implementation should use this to create IOMMU mappings if the device is protected.
    ///
    /// ```compile_fail
    /// let _ = kernel_api::service::kernel::instance().alloc_dma(4096);
    /// ```
    ///
    /// # Errors
    /// - `KapiError::OutOfMemory` if allocation fails
    /// - `KapiError::NotSupported` if `device_id` is null or device-scoped DMA is unavailable
    fn alloc_dma_for_device(
        &self,
        size: usize,
        device_id: PackedPciLocation,
    ) -> KapiResult<DmaSlice<CpuOwned>>;

    /// Enable MSI-X for a PCI device and return the configured table slots.
    fn enable_msix(
        &self,
        device_id: PackedPciLocation,
        requested_count: u16,
    ) -> KapiResult<alloc::vec::Vec<MsixVectorInfo>>;

    /// Disable MSI-X for a PCI device owned by the caller.
    fn disable_msix(&self, device_id: PackedPciLocation) -> KapiResult<()>;

    // ========================================================================
    // I/O Operations
    // ========================================================================

    /// Read from I/O port
    fn port_read_u8(&self, port: u16) -> u8;

    /// Write to I/O port
    fn port_write_u8(&self, port: u16, value: u8);

    // ========================================================================
    // Logging
    // ========================================================================

    /// Debug log output
    fn log(&self, message: &str);

    // ========================================================================
    // Runtime-Owned Device Registration
    // ========================================================================

    /// Register a block device bridge owned by the current driver domain.
    fn register_block_device(&self, registration: &AbiBlockDeviceRegistration) -> KapiResult<u64>;

    /// Unregister a previously registered block device bridge.
    fn unregister_block_device(&self, handle: u64) -> KapiResult<()>;

    /// Register NVMe namespace metadata for the current driver domain.
    fn register_nvme_namespace(
        &self,
        registration: &AbiNvmeNamespaceRegistration,
    ) -> KapiResult<u64>;

    /// Unregister a previously registered NVMe namespace bridge.
    fn unregister_nvme_namespace(&self, handle: u64) -> KapiResult<()>;

    /// Register a network port bridge owned by the current driver domain.
    fn register_netdev_port(&self, registration: &AbiNetPortRegistration) -> KapiResult<u64>;

    /// Unregister a previously registered network port bridge.
    fn unregister_netdev_port(&self, handle: u64) -> KapiResult<()>;

    /// Register an audio controller bridge owned by the current driver domain.
    fn register_audio_controller(
        &self,
        registration: &AbiAudioControllerRegistration,
    ) -> KapiResult<u64>;

    /// Unregister a previously registered audio controller bridge.
    fn unregister_audio_controller(&self, handle: u64) -> KapiResult<()>;

    // ========================================================================
    // Network
    // ========================================================================

    /// Open a TCP connection and return a stream handle.
    fn net_tcp_connect(
        &self,
        remote: NetSocketAddr,
        scope: InterfaceScope,
    ) -> Pin<Box<dyn Future<Output = KapiResult<TcpStreamHandle>> + Send>>;

    /// Start listening for TCP connections and return a listener handle.
    fn net_tcp_listen(
        &self,
        local: NetSocketAddr,
        scope: InterfaceScope,
        backlog: u32,
    ) -> Pin<Box<dyn Future<Output = KapiResult<TcpListenerHandle>> + Send>>;

    /// Accept a new TCP connection from a listener.
    fn net_tcp_accept(
        &self,
        listener: TcpListenerHandle,
    ) -> Pin<Box<dyn Future<Output = KapiResult<TcpStreamHandle>> + Send>>;

    /// Close a connected TCP stream.
    fn net_tcp_close_stream(&self, stream: TcpStreamHandle) -> KapiResult<()>;

    /// Close a listening TCP socket.
    fn net_tcp_close_listener(&self, listener: TcpListenerHandle) -> KapiResult<()>;

    /// Read bytes from a TCP stream.
    fn net_tcp_read(
        &self,
        stream: TcpStreamHandle,
        max_len: usize,
    ) -> Pin<Box<dyn Future<Output = KapiResult<TcpChunk>> + Send>>;

    /// Write bytes to a TCP stream.
    fn net_tcp_write(
        &self,
        stream: TcpStreamHandle,
        chunk: TcpChunk,
    ) -> Pin<Box<dyn Future<Output = KapiResult<usize>> + Send>>;
    /// Create a raw (packet-oriented) endpoint
    fn net_create_raw_endpoint(&self, scope: InterfaceScope) -> KapiResult<RawEndpointHandle>;

    /// Close a raw endpoint
    fn net_close_raw_endpoint(&self, endpoint: RawEndpointHandle) -> KapiResult<()>;

    /// Receive a raw packet (async)
    fn net_recv_raw(
        &self,
        endpoint: RawEndpointHandle,
    ) -> Pin<Box<dyn Future<Output = KapiResult<Packet>> + Send>>;

    /// Send a raw packet (async)
    fn net_send_raw(
        &self,
        endpoint: RawEndpointHandle,
        scope: InterfaceScope,
        packet: Packet,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>>;
    // ========================================================================
    // Filesystem
    // ========================================================================

    /// Open a file and associate with an optional token.
    /// If `token` is Some(id) then the token must validate for `CAP_FOWNER`
    /// and the manager's in-flight counter will be incremented until `fs_close`.
    fn fs_open_with_token(
        &self,
        path: &str,
        mode: OpenMode,
        token: Option<u64>,
    ) -> KapiResult<FileHandle>;

    /// Close a file
    ///
    /// # Errors
    /// - `KapiError::InvalidHandle` if the file handle is not valid
    fn fs_close(&self, handle: FileHandle) -> KapiResult<()>;

    // ========================================================================
    // Direct NVMe Block I/O
    // ========================================================================

    /// Open a direct NVMe block handle and associate it with an optional token.
    /// If `token` is Some(id) the token must validate for `CAP_DMA` and the manager's
    /// in-flight counter will be incremented until `nvme_close_direct` is called.
    fn nvme_open_direct_with_token(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        token: Option<u64>,
    ) -> KapiResult<DirectBlockHandle>;

    /// Close a kernel-registered direct NVMe open.
    fn nvme_close_direct(&self, handle: DirectBlockHandle) -> KapiResult<()>;

    /// Read blocks into a DMA buffer (buffer returned on completion)
    fn nvme_read_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaSlice<CpuOwned>,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaSlice<CpuOwned>>> + Send>>;

    /// Write blocks from a DMA buffer (buffer returned on completion)
    fn nvme_write_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: DmaSlice<CpuOwned>,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaSlice<CpuOwned>>> + Send>>;

    /// Flush pending writes for a direct handle
    fn nvme_flush_direct(
        &self,
        handle: DirectBlockHandle,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>>;

    /// Discard blocks (TRIM)
    fn nvme_discard_direct(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        block_count: u64,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>>;

    /// Get block size for an NVMe namespace
    ///
    /// Returns the block size in bytes for the specified device (namespace).
    /// Returns `None` if the device is not available or not an NVMe device.
    fn nvme_block_size(&self, device_id: u64) -> Option<u64>;

    /// Get maximum SGL (Scatter-Gather List) entries supported
    ///
    /// Returns the maximum number of SGL entries that can be used in a single
    /// I/O command for the specified device. Used for optimizing scatter-gather
    /// operations. Returns `None` if the device doesn't support SGLs or is not available.
    fn nvme_sgl_max_entries(&self, device_id: u64) -> Option<usize>;

    /// Submit an NVMe read/write I/O request
    ///
    /// This abstracts the io_scheduler submit and completion handling.
    /// Returns a handle that can be used to wait for completion.
    fn nvme_submit_rw(
        &self,
        request: NvmeRwRequest,
        io_type: NvmeIoType,
    ) -> KapiResult<NvmeIoHandle>;

    /// Wait for an NVMe I/O request to complete
    ///
    /// Blocks until the I/O completes and returns the result.
    fn nvme_wait_io(
        &self,
        handle: NvmeIoHandle,
    ) -> Pin<Box<dyn Future<Output = NvmeIoResult> + Send>>;

    /// Register a completion callback for an NVMe I/O request
    fn nvme_register_completion_hook(
        &self,
        handle: NvmeIoHandle,
        hook: Box<dyn FnOnce(NvmeIoResult) + Send>,
    );

    // ========================================================================
    // IPC (Inter-Process Communication)
    // ========================================================================

    /// Create an IPC channel
    ///
    /// Returns (sender_handle, receiver_handle) on success
    ///
    /// # Errors
    /// - `KapiError::ResourceExhausted` if channel creation fails
    fn ipc_create_channel(&self) -> KapiResult<(ChannelHandle, ChannelHandle)>;

    /// Close an IPC channel endpoint
    ///
    /// # Errors
    /// - `KapiError::InvalidHandle` if the channel handle is invalid
    fn ipc_close(&self, channel: ChannelHandle) -> KapiResult<()>;

    /// Return the caller's current domain identifier.
    fn ipc_current_domain(&self) -> DomainId;

    /// Allocate a raw Exchange Heap region owned by the current domain.
    fn exchange_alloc_raw(&self, size: usize, align: usize) -> KapiResult<(NonNull<u8>, DomainId)>;

    /// Deallocate a raw Exchange Heap region on behalf of `owner`.
    fn exchange_dealloc_raw(
        &self,
        ptr: NonNull<u8>,
        owner: DomainId,
        size: usize,
        align: usize,
    ) -> KapiResult<()>;

    /// Transfer Exchange Heap ownership between domains.
    fn exchange_transfer_raw(
        &self,
        ptr: NonNull<u8>,
        from: DomainId,
        to: DomainId,
    ) -> KapiResult<()>;

    /// Send a raw zero-copy payload through an IPC channel.
    fn ipc_send_raw(&self, channel: ChannelHandle, raw: AbiRRefRaw) -> KapiResult<()>;

    /// Receive a raw zero-copy payload from an IPC channel.
    fn ipc_recv_raw(&self, channel: ChannelHandle) -> KapiResult<AbiRRefRaw>;

    // ========================================================================
    // GUI Services (Optional)
    // ========================================================================

    /// Access time management services
    fn time_service(&self) -> Option<&dyn TimeService>;

    /// Access ACPI platform services if available
    fn platform_acpi(&self) -> Option<&dyn AcpiServices> {
        None
    }

    /// Access PCI platform services if available
    fn platform_pci(&self) -> Option<&dyn PciServices> {
        None
    }

    /// Access APIC platform services if available
    fn platform_apic(&self) -> Option<&dyn ApicServices> {
        None
    }

    /// Access storage services if available
    fn storage(&self) -> Option<&dyn StorageServices> {
        None
    }

    /// Access network device services if available
    fn netdev(&self) -> Option<&dyn NetDeviceServices> {
        None
    }

    /// Access input services if available
    fn input(&self) -> Option<&dyn InputServices> {
        None
    }

    /// Access serial services if available
    fn serial(&self) -> Option<&dyn SerialServices> {
        None
    }

    /// Access graphics services if available
    fn graphics(&self) -> Option<&dyn GraphicsServices> {
        None
    }

    /// Access audio services if available
    fn audio(&self) -> Option<&dyn AudioServices> {
        None
    }

    /// Access GUI services if available
    fn gui(&self) -> Option<&dyn GuiServices>;

    // ========================================================================
    // Shell Services (Optional)
    // ========================================================================

    /// Access shell services if available
    fn shell(&self) -> Option<&dyn ShellServices>;
}

// ============================================================================
// Global Kernel Registration
// ============================================================================

use spin::Once;

/// Global kernel services instance
static KERNEL: Once<&'static dyn KernelServices> = Once::new();

/// Register the kernel implementation
///
/// # Safety
/// Must be called exactly once during kernel initialization,
/// before any KAPI functions are used.
pub unsafe fn install(services: &'static dyn KernelServices) {
    KERNEL.call_once(|| services);
}

/// Get the registered kernel services
///
/// # Panics
/// Panics if called before `install`
#[inline]
pub fn instance() -> &'static dyn KernelServices {
    if let Some(services) = KERNEL.get() {
        return *services;
    }

    #[cfg(feature = "cell_runtime")]
    {
        return standalone::instance();
    }

    #[cfg(not(feature = "cell_runtime"))]
    panic!("Kernel not initialized! Call install() first.")
}

/// Check if kernel is registered
#[inline]
pub fn is_installed() -> bool {
    KERNEL.get().is_some()
}

// ============================================================================
// Stable ABI Kernel API
// ============================================================================

unsafe extern "C" {
    /// The global KernelApiV3 instance exported by the kernel.
    static __exorust_kernel_api_v3: KernelApiV3;
}

/// Get the stable ABI kernel API table
///
/// This is used by drivers and standalone cells to access kernel services
/// through the ABI-stable interface.
#[inline]
pub fn abi() -> &'static KernelApiV3 {
    unsafe { &__exorust_kernel_api_v3 }
}

#[cfg(feature = "cell_runtime")]
mod standalone {
    use super::*;
    use crate::KapiError;
    use crate::abi::driver::{AbiDmaSlice, AbiError, AbiMsixVectorInfo};

    static STANDALONE_KERNEL: StandaloneKernelServices = StandaloneKernelServices;

    pub(super) fn instance() -> &'static dyn KernelServices {
        &STANDALONE_KERNEL
    }

    fn map_abi_error(code: i32) -> KapiError {
        match AbiError::from_raw(code) {
            AbiError::Success => KapiError::Internal(code),
            AbiError::InvalidParam => KapiError::InvalidHandle,
            AbiError::OutOfMemory => KapiError::OutOfMemory,
            AbiError::PermissionDenied => KapiError::PermissionDenied,
            AbiError::NotSupported => KapiError::NotSupported,
            AbiError::Timeout => KapiError::Timeout,
            AbiError::DeviceNotFound => KapiError::NotFound,
            AbiError::DeviceBusy => KapiError::ResourceExhausted,
            AbiError::AlreadyInitialized => KapiError::AlreadyExists,
            AbiError::NotInitialized => KapiError::NotFound,
            AbiError::IoError | AbiError::Error => KapiError::IoError,
        }
    }

    fn unsupported_future<T: Send + 'static>() -> Pin<Box<dyn Future<Output = KapiResult<T>> + Send>>
    {
        Box::pin(async { Err(KapiError::NotSupported) })
    }

    unsafe fn release_dma_from_abi(dma_handle_id: u64) {
        let status = (super::abi().release_dma_raw)(dma_handle_id);
        debug_assert_eq!(status, AbiError::Success as i32);
    }

    fn alloc_from_raw(raw: AbiDmaSlice) -> DmaSlice<CpuOwned> {
        unsafe {
            DmaSlice::from_raw_parts(
                raw.dma_handle_id,
                raw.device_addr,
                raw.virt_addr as usize as *mut u8,
                raw.size,
                Some(release_dma_from_abi),
            )
        }
    }

    fn alloc_dma_for_device(
        size: usize,
        device_id: PackedPciLocation,
    ) -> KapiResult<DmaSlice<CpuOwned>> {
        let mut raw = AbiDmaSlice::default();
        let status = (super::abi().alloc_dma_for_device_raw)(size, device_id.raw(), 1, &mut raw);
        if AbiError::from_raw(status).is_success() {
            Ok(alloc_from_raw(raw))
        } else {
            Err(map_abi_error(status))
        }
    }

    fn enable_msix(
        device_id: PackedPciLocation,
        requested_count: u16,
    ) -> KapiResult<alloc::vec::Vec<MsixVectorInfo>> {
        type EnableMsixRaw = extern "C" fn(
            device_id: u64,
            requested_count: u16,
            out_vectors: *mut AbiMsixVectorInfo,
            capacity: usize,
            written: *mut usize,
        ) -> i32;

        if requested_count == 0 {
            return Err(KapiError::InvalidHandle);
        }

        let api = super::abi();
        if (api.abi_size as usize)
            < core::mem::offset_of!(KernelApiV3, enable_msix_raw)
                + core::mem::size_of::<Option<EnableMsixRaw>>()
        {
            return Err(KapiError::NotSupported);
        }
        let Some(enable) = api.enable_msix_raw else {
            return Err(KapiError::NotSupported);
        };

        let mut raw = alloc::vec![AbiMsixVectorInfo::default(); requested_count as usize];
        let mut written = 0usize;
        let status = enable(
            device_id.raw(),
            requested_count,
            raw.as_mut_ptr(),
            raw.len(),
            &mut written,
        );
        if !AbiError::from_raw(status).is_success() {
            return Err(map_abi_error(status));
        }
        if written != requested_count as usize {
            return Err(KapiError::IoError);
        }

        Ok(raw
            .into_iter()
            .take(written)
            .map(|entry| MsixVectorInfo::new(entry.vector, entry.table_index))
            .collect())
    }

    fn disable_msix(device_id: PackedPciLocation) -> KapiResult<()> {
        type DisableMsixRaw = extern "C" fn(device_id: u64) -> i32;

        let api = super::abi();
        if (api.abi_size as usize)
            < core::mem::offset_of!(KernelApiV3, disable_msix_raw)
                + core::mem::size_of::<Option<DisableMsixRaw>>()
        {
            return Err(KapiError::NotSupported);
        }
        let Some(disable) = api.disable_msix_raw else {
            return Err(KapiError::NotSupported);
        };

        let status = disable(device_id.raw());
        if AbiError::from_raw(status).is_success() {
            Ok(())
        } else {
            Err(map_abi_error(status))
        }
    }

    fn require_full_kernel_api() -> KapiResult<&'static KernelApiV3> {
        let api = super::abi();
        if (api.abi_size as usize) < core::mem::size_of::<KernelApiV3>() {
            Err(KapiError::NotSupported)
        } else {
            Ok(api)
        }
    }

    fn current_domain() -> DomainId {
        match require_full_kernel_api() {
            Ok(api) => DomainId::new((api.current_domain_id)()),
            Err(_) => DomainId::KERNEL,
        }
    }

    fn exchange_alloc_raw(size: usize, align: usize) -> KapiResult<(NonNull<u8>, DomainId)> {
        let api = require_full_kernel_api()?;
        let mut ptr = core::ptr::null_mut();
        let mut owner = 0u64;
        let status = (api.exchange_alloc_raw)(size, align, &mut ptr, &mut owner);
        if AbiError::from_raw(status).is_success() {
            let ptr = NonNull::new(ptr).ok_or(KapiError::IoError)?;
            Ok((ptr, DomainId::new(owner)))
        } else {
            Err(map_abi_error(status))
        }
    }

    fn exchange_dealloc_raw(
        ptr: NonNull<u8>,
        owner: DomainId,
        size: usize,
        align: usize,
    ) -> KapiResult<()> {
        let api = require_full_kernel_api()?;
        let status = (api.exchange_dealloc_raw)(ptr.as_ptr(), owner.as_u64(), size, align);
        if AbiError::from_raw(status).is_success() {
            Ok(())
        } else {
            Err(map_abi_error(status))
        }
    }

    fn exchange_transfer_raw(ptr: NonNull<u8>, from: DomainId, to: DomainId) -> KapiResult<()> {
        let api = require_full_kernel_api()?;
        let status = (api.exchange_transfer_raw)(ptr.as_ptr(), from.as_u64(), to.as_u64());
        if AbiError::from_raw(status).is_success() {
            Ok(())
        } else {
            Err(map_abi_error(status))
        }
    }

    fn ipc_create_channel() -> KapiResult<(ChannelHandle, ChannelHandle)> {
        let api = require_full_kernel_api()?;
        let mut sender = 0u64;
        let mut receiver = 0u64;
        let status = (api.ipc_create_channel_raw)(&mut sender, &mut receiver);
        if AbiError::from_raw(status).is_success() {
            Ok((ChannelHandle::new(sender), ChannelHandle::new(receiver)))
        } else {
            Err(map_abi_error(status))
        }
    }

    fn ipc_close(channel: ChannelHandle) -> KapiResult<()> {
        let api = require_full_kernel_api()?;
        let status = (api.ipc_close_raw)(channel.id());
        if AbiError::from_raw(status).is_success() {
            Ok(())
        } else {
            Err(map_abi_error(status))
        }
    }

    fn ipc_send_raw(channel: ChannelHandle, raw: AbiRRefRaw) -> KapiResult<()> {
        let api = require_full_kernel_api()?;
        let status = (api.ipc_send_raw)(channel.id(), &raw);
        if AbiError::from_raw(status).is_success() {
            Ok(())
        } else {
            Err(map_abi_error(status))
        }
    }

    fn ipc_recv_raw(channel: ChannelHandle) -> KapiResult<AbiRRefRaw> {
        let api = require_full_kernel_api()?;
        let mut raw = AbiRRefRaw::default();
        let status = (api.ipc_recv_raw)(channel.id(), &mut raw);
        if AbiError::from_raw(status).is_success() {
            Ok(raw)
        } else {
            Err(map_abi_error(status))
        }
    }

    struct StandaloneKernelServices;

    impl KernelServices for StandaloneKernelServices {
        fn spawn_task(
            &self,
            future: Pin<Box<dyn Future<Output = ()> + Send>>,
        ) -> KapiResult<TaskHandle> {
            let _ = future;
            Err(KapiError::NotSupported)
        }

        fn current_tick(&self) -> u64 {
            0
        }

        fn current_task_id(&self) -> u64 {
            0
        }

        fn alloc_dma_for_device(
            &self,
            size: usize,
            device_id: PackedPciLocation,
        ) -> KapiResult<DmaSlice<CpuOwned>> {
            alloc_dma_for_device(size, device_id)
        }

        fn enable_msix(
            &self,
            device_id: PackedPciLocation,
            requested_count: u16,
        ) -> KapiResult<alloc::vec::Vec<MsixVectorInfo>> {
            enable_msix(device_id, requested_count)
        }

        fn disable_msix(&self, device_id: PackedPciLocation) -> KapiResult<()> {
            disable_msix(device_id)
        }

        fn port_read_u8(&self, port: u16) -> u8 {
            (super::abi().port_read_u8)(port)
        }

        fn port_write_u8(&self, port: u16, value: u8) {
            (super::abi().port_write_u8)(port, value);
        }

        fn log(&self, message: &str) {
            if !message.is_empty() {
                (super::abi().log)(0, message.as_ptr(), message.len());
            }
        }

        fn register_block_device(
            &self,
            registration: &AbiBlockDeviceRegistration,
        ) -> KapiResult<u64> {
            let mut handle = 0u64;
            let status = (super::abi().register_block_device)(registration, &mut handle);
            if AbiError::from_raw(status).is_success() {
                Ok(handle)
            } else {
                Err(map_abi_error(status))
            }
        }

        fn unregister_block_device(&self, handle: u64) -> KapiResult<()> {
            let status = (super::abi().unregister_block_device)(handle);
            if AbiError::from_raw(status).is_success() {
                Ok(())
            } else {
                Err(map_abi_error(status))
            }
        }

        fn register_nvme_namespace(
            &self,
            registration: &AbiNvmeNamespaceRegistration,
        ) -> KapiResult<u64> {
            let mut handle = 0u64;
            let status = (super::abi().register_nvme_namespace)(registration, &mut handle);
            if AbiError::from_raw(status).is_success() {
                Ok(handle)
            } else {
                Err(map_abi_error(status))
            }
        }

        fn unregister_nvme_namespace(&self, handle: u64) -> KapiResult<()> {
            let status = (super::abi().unregister_nvme_namespace)(handle);
            if AbiError::from_raw(status).is_success() {
                Ok(())
            } else {
                Err(map_abi_error(status))
            }
        }

        fn register_netdev_port(&self, registration: &AbiNetPortRegistration) -> KapiResult<u64> {
            let mut handle = 0u64;
            let status = (super::abi().register_netdev_port)(registration, &mut handle);
            if AbiError::from_raw(status).is_success() {
                Ok(handle)
            } else {
                Err(map_abi_error(status))
            }
        }

        fn unregister_netdev_port(&self, handle: u64) -> KapiResult<()> {
            let status = (super::abi().unregister_netdev_port)(handle);
            if AbiError::from_raw(status).is_success() {
                Ok(())
            } else {
                Err(map_abi_error(status))
            }
        }

        fn register_audio_controller(
            &self,
            registration: &AbiAudioControllerRegistration,
        ) -> KapiResult<u64> {
            let mut handle = 0u64;
            let status = (super::abi().register_audio_controller)(registration, &mut handle);
            if AbiError::from_raw(status).is_success() {
                Ok(handle)
            } else {
                Err(map_abi_error(status))
            }
        }

        fn unregister_audio_controller(&self, handle: u64) -> KapiResult<()> {
            let status = (super::abi().unregister_audio_controller)(handle);
            if AbiError::from_raw(status).is_success() {
                Ok(())
            } else {
                Err(map_abi_error(status))
            }
        }

        fn net_tcp_connect(
            &self,
            remote: NetSocketAddr,
            scope: InterfaceScope,
        ) -> Pin<Box<dyn Future<Output = KapiResult<TcpStreamHandle>> + Send>> {
            let _ = (remote, scope);
            unsupported_future()
        }

        fn net_tcp_listen(
            &self,
            local: NetSocketAddr,
            scope: InterfaceScope,
            backlog: u32,
        ) -> Pin<Box<dyn Future<Output = KapiResult<TcpListenerHandle>> + Send>> {
            let _ = (local, scope, backlog);
            unsupported_future()
        }

        fn net_tcp_accept(
            &self,
            listener: TcpListenerHandle,
        ) -> Pin<Box<dyn Future<Output = KapiResult<TcpStreamHandle>> + Send>> {
            let _ = listener;
            unsupported_future()
        }

        fn net_tcp_close_stream(&self, stream: TcpStreamHandle) -> KapiResult<()> {
            let _ = stream;
            Err(KapiError::NotSupported)
        }

        fn net_tcp_close_listener(&self, listener: TcpListenerHandle) -> KapiResult<()> {
            let _ = listener;
            Err(KapiError::NotSupported)
        }

        fn net_tcp_read(
            &self,
            stream: TcpStreamHandle,
            max_len: usize,
        ) -> Pin<Box<dyn Future<Output = KapiResult<TcpChunk>> + Send>> {
            let _ = (stream, max_len);
            unsupported_future()
        }

        fn net_tcp_write(
            &self,
            stream: TcpStreamHandle,
            chunk: TcpChunk,
        ) -> Pin<Box<dyn Future<Output = KapiResult<usize>> + Send>> {
            let _ = (stream, chunk);
            unsupported_future()
        }

        fn net_create_raw_endpoint(&self, scope: InterfaceScope) -> KapiResult<RawEndpointHandle> {
            let _ = scope;
            Err(KapiError::NotSupported)
        }

        fn net_close_raw_endpoint(&self, endpoint: RawEndpointHandle) -> KapiResult<()> {
            let _ = endpoint;
            Err(KapiError::NotSupported)
        }

        fn net_recv_raw(
            &self,
            endpoint: RawEndpointHandle,
        ) -> Pin<Box<dyn Future<Output = KapiResult<Packet>> + Send>> {
            let _ = endpoint;
            unsupported_future()
        }

        fn net_send_raw(
            &self,
            endpoint: RawEndpointHandle,
            scope: InterfaceScope,
            packet: Packet,
        ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
            let _ = (endpoint, scope, packet);
            unsupported_future()
        }

        fn fs_open_with_token(
            &self,
            path: &str,
            mode: OpenMode,
            token: Option<u64>,
        ) -> KapiResult<FileHandle> {
            let _ = (path, mode, token);
            Err(KapiError::NotSupported)
        }

        fn fs_close(&self, handle: FileHandle) -> KapiResult<()> {
            let _ = handle;
            Err(KapiError::NotSupported)
        }

        fn nvme_open_direct_with_token(
            &self,
            device_id: u64,
            start_block: u64,
            block_count: u64,
            token: Option<u64>,
        ) -> KapiResult<DirectBlockHandle> {
            let _ = (device_id, start_block, block_count, token);
            Err(KapiError::NotSupported)
        }

        fn nvme_close_direct(&self, handle: DirectBlockHandle) -> KapiResult<()> {
            let _ = handle;
            Err(KapiError::NotSupported)
        }

        fn nvme_read_blocks_dma(
            &self,
            handle: DirectBlockHandle,
            block_offset: u64,
            buffer: DmaSlice<CpuOwned>,
        ) -> Pin<Box<dyn Future<Output = KapiResult<DmaSlice<CpuOwned>>> + Send>> {
            let _ = (handle, block_offset, buffer);
            unsupported_future()
        }

        fn nvme_write_blocks_dma(
            &self,
            handle: DirectBlockHandle,
            block_offset: u64,
            buffer: DmaSlice<CpuOwned>,
        ) -> Pin<Box<dyn Future<Output = KapiResult<DmaSlice<CpuOwned>>> + Send>> {
            let _ = (handle, block_offset, buffer);
            unsupported_future()
        }

        fn nvme_flush_direct(
            &self,
            handle: DirectBlockHandle,
        ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
            let _ = handle;
            unsupported_future()
        }

        fn nvme_discard_direct(
            &self,
            handle: DirectBlockHandle,
            block_offset: u64,
            block_count: u64,
        ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
            let _ = (handle, block_offset, block_count);
            unsupported_future()
        }

        fn nvme_block_size(&self, device_id: u64) -> Option<u64> {
            let _ = device_id;
            None
        }

        fn nvme_sgl_max_entries(&self, device_id: u64) -> Option<usize> {
            let _ = device_id;
            None
        }

        fn nvme_submit_rw(
            &self,
            request: NvmeRwRequest,
            io_type: NvmeIoType,
        ) -> KapiResult<NvmeIoHandle> {
            let _ = (request, io_type);
            Err(KapiError::NotSupported)
        }

        fn nvme_wait_io(
            &self,
            handle: NvmeIoHandle,
        ) -> Pin<Box<dyn Future<Output = NvmeIoResult> + Send>> {
            let _ = handle;
            Box::pin(async { NvmeIoResult::Cancelled })
        }

        fn nvme_register_completion_hook(
            &self,
            handle: NvmeIoHandle,
            hook: Box<dyn FnOnce(NvmeIoResult) + Send>,
        ) {
            let _ = (handle, hook);
        }

        fn ipc_create_channel(&self) -> KapiResult<(ChannelHandle, ChannelHandle)> {
            ipc_create_channel()
        }

        fn ipc_close(&self, channel: ChannelHandle) -> KapiResult<()> {
            ipc_close(channel)
        }

        fn ipc_current_domain(&self) -> DomainId {
            current_domain()
        }

        fn exchange_alloc_raw(
            &self,
            size: usize,
            align: usize,
        ) -> KapiResult<(NonNull<u8>, DomainId)> {
            exchange_alloc_raw(size, align)
        }

        fn exchange_dealloc_raw(
            &self,
            ptr: NonNull<u8>,
            owner: DomainId,
            size: usize,
            align: usize,
        ) -> KapiResult<()> {
            exchange_dealloc_raw(ptr, owner, size, align)
        }

        fn exchange_transfer_raw(
            &self,
            ptr: NonNull<u8>,
            from: DomainId,
            to: DomainId,
        ) -> KapiResult<()> {
            exchange_transfer_raw(ptr, from, to)
        }

        fn ipc_send_raw(&self, channel: ChannelHandle, raw: AbiRRefRaw) -> KapiResult<()> {
            ipc_send_raw(channel, raw)
        }

        fn ipc_recv_raw(&self, channel: ChannelHandle) -> KapiResult<AbiRRefRaw> {
            ipc_recv_raw(channel)
        }

        fn time_service(&self) -> Option<&dyn TimeService> {
            None
        }

        fn gui(&self) -> Option<&dyn GuiServices> {
            None
        }

        fn shell(&self) -> Option<&dyn ShellServices> {
            None
        }
    }
}
