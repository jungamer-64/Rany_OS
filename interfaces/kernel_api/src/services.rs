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
    AbiBlockDeviceRegistration, AbiNetPortRegistration, AbiNvmeNamespaceRegistration, AbiRRefRaw,
    KernelApiV4, PackedPciLocation,
};
use crate::dma::{CpuDmaLease, DmaAllocationRequest};
#[cfg(any(feature = "cell_runtime", test))]
use crate::dma::{
    DmaDeviceAddress, DmaDirection, DmaLeaseAuthority, DmaLeaseError, DmaLeaseId, DmaLeaseState,
};
use crate::ipc::{ChannelHandle, DomainId};
use crate::msix::MsixVectorInfo;
use crate::resource::fs::{FileHandle, OpenMode};
use crate::resource::net::{
    InterfaceScope, NetSocketAddr, PacketPayload, RawEndpoint, TcpAcceptor, TcpConnection,
};
use crate::resource::storage::{
    DirectBlockHandle, NvmeIoHandle, NvmeIoResult, NvmeIoType, NvmeRwRequest,
};
use crate::resource::task::TaskHandle;
use crate::service::{
    input::InputServices,
    netdev::NetDeviceServices,
    platform::{AcpiServices, ApicServices, PciServices},
    serial::SerialServices,
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
        request: DmaAllocationRequest,
        device_id: PackedPciLocation,
    ) -> KapiResult<CpuDmaLease>;

    /// Enable MSI-X for a PCI device and return the configured table slots.
    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or cannot be completed.
    fn enable_msix(
        &self,
        device_id: PackedPciLocation,
        requested_count: u16,
    ) -> KapiResult<alloc::vec::Vec<MsixVectorInfo>>;

    /// Disable MSI-X for a PCI device owned by the caller.
    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or cannot be completed.
    fn disable_msix(&self, device_id: PackedPciLocation) -> KapiResult<()>;

    /// Allocate a packet-backed network buffer owned by the kernel datapath.
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    fn net_alloc_packet(
        &self,
        len: usize,
        headroom: usize,
    ) -> KapiResult<crate::resource::net::PacketRef>;

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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    fn register_block_device(&self, registration: &AbiBlockDeviceRegistration) -> KapiResult<u64>;

    /// Unregister a previously registered block device bridge.
    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    fn unregister_block_device(&self, handle: u64) -> KapiResult<()>;

    /// Register NVMe namespace metadata for the current driver domain.
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    fn register_nvme_namespace(
        &self,
        registration: &AbiNvmeNamespaceRegistration,
    ) -> KapiResult<u64>;

    /// Unregister a previously registered NVMe namespace bridge.
    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    fn unregister_nvme_namespace(&self, handle: u64) -> KapiResult<()>;

    /// Register a network port bridge owned by the current driver domain.
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    fn register_netdev_port(&self, registration: &AbiNetPortRegistration) -> KapiResult<u64>;

    /// Unregister a previously registered network port bridge.
    ///
    /// # Errors
    ///
    /// Returns an error if `handle` is invalid or the port cannot be removed.
    fn unregister_netdev_port(&self, handle: u64) -> KapiResult<()>;

    // ========================================================================
    // Network
    // ========================================================================

    /// Open a TCP connection and return a connection handle.
    fn net_tcp_connection_dial(
        &self,
        remote: NetSocketAddr,
        scope: InterfaceScope,
    ) -> Pin<Box<dyn Future<Output = KapiResult<TcpConnection>> + Send>>;

    /// Bind a TCP acceptor and return the handle.
    fn net_tcp_acceptor_bind(
        &self,
        local: NetSocketAddr,
        scope: InterfaceScope,
        backlog: u32,
    ) -> Pin<Box<dyn Future<Output = KapiResult<TcpAcceptor>> + Send>>;

    /// Dequeue the next TCP connection from a bound acceptor.
    fn net_tcp_acceptor_next_connection(
        &self,
        acceptor: TcpAcceptor,
    ) -> Pin<Box<dyn Future<Output = KapiResult<TcpConnection>> + Send>>;

    /// Close a connected TCP connection.
    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    fn net_tcp_connection_close(&self, connection: TcpConnection) -> KapiResult<()>;

    /// Close a bound TCP acceptor.
    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    fn net_tcp_acceptor_close(&self, acceptor: TcpAcceptor) -> KapiResult<()>;

    /// Receive a packet-backed payload from a TCP connection.
    fn net_tcp_connection_recv_payload(
        &self,
        connection: TcpConnection,
    ) -> Pin<Box<dyn Future<Output = KapiResult<crate::resource::net::TcpReceiveOutcome>> + Send>>;

    /// Send a packet-backed payload through a TCP connection.
    fn net_tcp_connection_send_payload(
        &self,
        connection: TcpConnection,
        payload: PacketPayload,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::resource::net::PayloadSendError>> + Send>>;
    /// Create a raw (packet-oriented) endpoint.
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    fn net_raw_endpoint_open(&self, scope: InterfaceScope) -> KapiResult<RawEndpoint>;

    /// Close a raw endpoint.
    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    fn net_raw_endpoint_close(&self, endpoint: RawEndpoint) -> KapiResult<()>;

    /// Receive a raw payload (async).
    fn net_raw_endpoint_recv_payload(
        &self,
        endpoint: RawEndpoint,
    ) -> Pin<Box<dyn Future<Output = KapiResult<PacketPayload>> + Send>>;

    /// Send a raw payload (async).
    fn net_raw_endpoint_send_payload(
        &self,
        endpoint: RawEndpoint,
        payload: PacketPayload,
    ) -> Pin<Box<dyn Future<Output = Result<(), crate::resource::net::PayloadSendError>> + Send>>;
    // ========================================================================
    // Filesystem
    // ========================================================================

    /// Open a file and associate with an optional token.
    /// If `token` is Some(id) then the token must validate for `CAP_FOWNER`
    /// and the manager's in-flight counter will be incremented until `fs_close`.
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    fn nvme_open_direct_with_token(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        token: Option<u64>,
    ) -> KapiResult<DirectBlockHandle>;

    /// Close a kernel-registered direct NVMe open.
    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    fn nvme_close_direct(&self, handle: DirectBlockHandle) -> KapiResult<()>;

    /// Read blocks into a DMA buffer (buffer returned on completion)
    fn nvme_read_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: CpuDmaLease,
    ) -> Pin<Box<dyn Future<Output = KapiResult<CpuDmaLease>> + Send>>;

    /// Write blocks from a DMA buffer (buffer returned on completion)
    fn nvme_write_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: CpuDmaLease,
    ) -> Pin<Box<dyn Future<Output = KapiResult<CpuDmaLease>> + Send>>;

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
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the receiver cannot accept the operation.
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
    /// # Errors
    ///
    /// Returns an error if the supplied configuration is invalid or the required resources cannot be acquired.
    fn exchange_alloc_raw(&self, size: usize, align: usize) -> KapiResult<(NonNull<u8>, DomainId)>;

    /// Deallocate a raw Exchange Heap region on behalf of `owner`.
    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    fn exchange_dealloc_raw(
        &self,
        ptr: NonNull<u8>,
        owner: DomainId,
        size: usize,
        align: usize,
    ) -> KapiResult<()>;

    /// Transfer Exchange Heap ownership between domains.
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    fn exchange_transfer_raw(
        &self,
        ptr: NonNull<u8>,
        from: DomainId,
        to: DomainId,
    ) -> KapiResult<()>;

    /// Send a raw zero-copy payload through an IPC channel.
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the receiver cannot accept the operation.
    fn ipc_send_raw(&self, channel: ChannelHandle, raw: AbiRRefRaw) -> KapiResult<()>;

    /// Receive a raw zero-copy payload from an IPC channel.
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required state cannot be read.
    fn ipc_recv_raw(&self, channel: ChannelHandle) -> KapiResult<AbiRRefRaw>;

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
        standalone::instance()
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
    /// The global KernelApiV4 instance exported by the kernel.
    static __exorust_kernel_api_v4: KernelApiV4;
}

/// Get the stable ABI kernel API table
///
/// This is used by drivers and standalone cells to access kernel services
/// through the ABI-stable interface.
#[inline]
pub fn abi() -> &'static KernelApiV4 {
    unsafe { &__exorust_kernel_api_v4 }
}

#[cfg(any(feature = "cell_runtime", test))]
struct AbiDmaLeaseAuthority {
    lease_id: DmaLeaseId,
    device_address: DmaDeviceAddress,
    virtual_address: usize,
    byte_count: crate::dma::DmaByteCount,
    direction: DmaDirection,
    release: fn(DmaLeaseId) -> Result<(), DmaLeaseError>,
    state: core::sync::atomic::AtomicU8,
}

#[cfg(any(feature = "cell_runtime", test))]
impl AbiDmaLeaseAuthority {
    const CPU_OWNED: u8 = 0;
    const QUARANTINED: u8 = 1;
    const CLOSED: u8 = 2;

    fn require_cpu_owned(&self) -> Result<(), DmaLeaseError> {
        if self.state.load(core::sync::atomic::Ordering::Acquire) == Self::CPU_OWNED {
            Ok(())
        } else {
            Err(DmaLeaseError::InvalidState)
        }
    }
}

// SAFETY: Construction validates the ABI owner token, pointer, and length as
// one registry allocation. CPU visits are locally serialized by the
// non-Sync CpuDmaLease capability, and failed release moves this bridge to a
// non-accessible quarantined state without freeing the backing allocation.
#[cfg(any(feature = "cell_runtime", test))]
unsafe impl DmaLeaseAuthority for AbiDmaLeaseAuthority {
    fn lease_id(&self) -> DmaLeaseId {
        self.lease_id
    }

    fn device_address(&self) -> DmaDeviceAddress {
        self.device_address
    }

    fn byte_count(&self) -> crate::dma::DmaByteCount {
        self.byte_count
    }

    fn direction(&self) -> DmaDirection {
        self.direction
    }

    fn with_cpu_bytes(&self, visitor: &mut dyn FnMut(&[u8])) -> Result<(), DmaLeaseError> {
        self.require_cpu_owned()?;
        // SAFETY: import_dma_lease_from_abi validated a non-null allocation
        // whose registry lease remains live until explicit release succeeds.
        let bytes = unsafe {
            core::slice::from_raw_parts(self.virtual_address as *const u8, self.byte_count.get())
        };
        visitor(bytes);
        Ok(())
    }

    fn with_cpu_bytes_mut(&self, visitor: &mut dyn FnMut(&mut [u8])) -> Result<(), DmaLeaseError> {
        self.require_cpu_owned()?;
        // SAFETY: CpuDmaLease is non-Sync and uniquely owns mutable CPU access;
        // the stable ABI registry retains the allocation for this lease.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(self.virtual_address as *mut u8, self.byte_count.get())
        };
        visitor(bytes);
        Ok(())
    }

    fn prepare(&self, _queue: crate::dma::DmaQueueIdentity) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }

    fn prepared_queue(&self) -> Option<crate::dma::DmaQueueIdentity> {
        None
    }

    fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }

    fn accept(&self) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }

    fn complete(
        &self,
        _queue: crate::dma::DmaQueueIdentity,
        _lease: DmaLeaseId,
    ) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }

    fn return_to_cpu(&self) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }

    fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError> {
        self.state
            .store(Self::QUARANTINED, core::sync::atomic::Ordering::Release);
        Ok(())
    }

    fn revoke_after_reset(
        &self,
        _device: PackedPciLocation,
        _reset_generation: u64,
    ) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }

    fn reconcile(
        &self,
        _device: PackedPciLocation,
        _reset_generation: u64,
    ) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }

    fn close(&self) -> Result<(), DmaLeaseError> {
        self.require_cpu_owned()?;
        match (self.release)(self.lease_id) {
            Ok(()) => {
                self.state
                    .store(Self::CLOSED, core::sync::atomic::Ordering::Release);
                Ok(())
            }
            Err(error) => {
                self.state
                    .store(Self::QUARANTINED, core::sync::atomic::Ordering::Release);
                Err(error)
            }
        }
    }

    fn retry_close_after_reconcile(
        &self,
        _device: PackedPciLocation,
        _reset_generation: u64,
    ) -> Result<(), DmaLeaseError> {
        Err(DmaLeaseError::NotSupported)
    }

    fn abandon(&self, _observed_state: DmaLeaseState) {
        if self.state.load(core::sync::atomic::Ordering::Acquire) != Self::CLOSED {
            self.state
                .store(Self::QUARANTINED, core::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(any(feature = "cell_runtime", test))]
fn import_dma_lease_from_abi(
    raw: crate::abi::driver::AbiDmaSlice,
    direction: DmaDirection,
    release: fn(DmaLeaseId) -> Result<(), DmaLeaseError>,
) -> KapiResult<CpuDmaLease> {
    let lease_id =
        DmaLeaseId::from_abi(raw.dma_handle_id).ok_or(crate::error::KapiError::IoError)?;
    let byte_count =
        crate::dma::DmaByteCount::new(raw.size).ok_or(crate::error::KapiError::IoError)?;
    let virtual_address = usize::try_from(raw.virt_addr)
        .ok()
        .filter(|address| *address != 0)
        .ok_or(crate::error::KapiError::IoError)?;

    Ok(CpuDmaLease::from_authority(alloc::sync::Arc::new(
        AbiDmaLeaseAuthority {
            lease_id,
            device_address: DmaDeviceAddress::from_abi(raw.device_addr),
            virtual_address,
            byte_count,
            direction,
            release,
            state: core::sync::atomic::AtomicU8::new(AbiDmaLeaseAuthority::CPU_OWNED),
        },
    )))
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

    fn release_dma_from_abi(dma_handle_id: DmaLeaseId) -> Result<(), DmaLeaseError> {
        let status = (super::abi().release_dma_raw)(dma_handle_id.into_abi());
        if AbiError::from_raw(status).is_success() {
            Ok(())
        } else {
            Err(DmaLeaseError::IommuFailure)
        }
    }

    fn alloc_dma_for_device(
        request: DmaAllocationRequest,
        device_id: PackedPciLocation,
    ) -> KapiResult<CpuDmaLease> {
        let mut raw = AbiDmaSlice::default();
        let status = (super::abi().alloc_dma_for_device_raw)(
            request.byte_count().get(),
            device_id.raw(),
            1,
            request.direction() as u8,
            &mut raw,
        );
        if AbiError::from_raw(status).is_success() {
            super::import_dma_lease_from_abi(raw, request.direction(), release_dma_from_abi)
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
            < core::mem::offset_of!(KernelApiV4, enable_msix_raw)
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
            < core::mem::offset_of!(KernelApiV4, disable_msix_raw)
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

    fn require_full_kernel_api() -> KapiResult<&'static KernelApiV4> {
        let api = super::abi();
        if (api.abi_size as usize) < core::mem::size_of::<KernelApiV4>() {
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
            core::mem::drop(future);
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
            request: DmaAllocationRequest,
            device_id: PackedPciLocation,
        ) -> KapiResult<CpuDmaLease> {
            alloc_dma_for_device(request, device_id)
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

        fn net_alloc_packet(
            &self,
            _len: usize,
            _headroom: usize,
        ) -> KapiResult<crate::resource::net::PacketRef> {
            Err(KapiError::NotSupported)
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

        fn net_tcp_connection_dial(
            &self,
            remote: NetSocketAddr,
            scope: InterfaceScope,
        ) -> Pin<Box<dyn Future<Output = KapiResult<TcpConnection>> + Send>> {
            let _ = (remote, scope);
            unsupported_future()
        }

        fn net_tcp_acceptor_bind(
            &self,
            local: NetSocketAddr,
            scope: InterfaceScope,
            backlog: u32,
        ) -> Pin<Box<dyn Future<Output = KapiResult<TcpAcceptor>> + Send>> {
            let _ = (local, scope, backlog);
            unsupported_future()
        }

        fn net_tcp_acceptor_next_connection(
            &self,
            acceptor: TcpAcceptor,
        ) -> Pin<Box<dyn Future<Output = KapiResult<TcpConnection>> + Send>> {
            let _ = acceptor;
            unsupported_future()
        }

        fn net_tcp_connection_close(&self, connection: TcpConnection) -> KapiResult<()> {
            let _ = connection;
            Err(KapiError::NotSupported)
        }

        fn net_tcp_acceptor_close(&self, acceptor: TcpAcceptor) -> KapiResult<()> {
            let _ = acceptor;
            Err(KapiError::NotSupported)
        }

        fn net_tcp_connection_recv_payload(
            &self,
            connection: TcpConnection,
        ) -> Pin<Box<dyn Future<Output = KapiResult<crate::resource::net::TcpReceiveOutcome>> + Send>>
        {
            let _ = connection;
            unsupported_future()
        }

        fn net_tcp_connection_send_payload(
            &self,
            connection: TcpConnection,
            payload: PacketPayload,
        ) -> Pin<Box<dyn Future<Output = Result<(), crate::resource::net::PayloadSendError>> + Send>>
        {
            let _ = connection;
            Box::pin(async move {
                Err(crate::resource::net::PayloadSendError::new(
                    KapiError::NotSupported,
                    payload,
                ))
            })
        }

        fn net_raw_endpoint_open(&self, scope: InterfaceScope) -> KapiResult<RawEndpoint> {
            let _ = scope;
            Err(KapiError::NotSupported)
        }

        fn net_raw_endpoint_close(&self, endpoint: RawEndpoint) -> KapiResult<()> {
            let _ = endpoint;
            Err(KapiError::NotSupported)
        }

        fn net_raw_endpoint_recv_payload(
            &self,
            endpoint: RawEndpoint,
        ) -> Pin<Box<dyn Future<Output = KapiResult<PacketPayload>> + Send>> {
            let _ = endpoint;
            unsupported_future()
        }

        fn net_raw_endpoint_send_payload(
            &self,
            endpoint: RawEndpoint,
            payload: PacketPayload,
        ) -> Pin<Box<dyn Future<Output = Result<(), crate::resource::net::PayloadSendError>> + Send>>
        {
            let _ = endpoint;
            Box::pin(async move {
                Err(crate::resource::net::PayloadSendError::new(
                    KapiError::NotSupported,
                    payload,
                ))
            })
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
            buffer: CpuDmaLease,
        ) -> Pin<Box<dyn Future<Output = KapiResult<CpuDmaLease>> + Send>> {
            let _ = (handle, block_offset, buffer);
            unsupported_future()
        }

        fn nvme_write_blocks_dma(
            &self,
            handle: DirectBlockHandle,
            block_offset: u64,
            buffer: CpuDmaLease,
        ) -> Pin<Box<dyn Future<Output = KapiResult<CpuDmaLease>> + Send>> {
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
    }
}

#[cfg(test)]
mod dma_bridge_tests {
    use super::*;
    use crate::abi::driver::AbiDmaSlice;
    use core::sync::atomic::{AtomicU64, Ordering};

    static RELEASED_DMA_HANDLE: AtomicU64 = AtomicU64::new(0);

    fn record_dma_release(dma_handle_id: DmaLeaseId) -> Result<(), DmaLeaseError> {
        RELEASED_DMA_HANDLE.store(dma_handle_id.into_abi(), Ordering::SeqCst);
        Ok(())
    }

    #[test]
    fn abi_dma_bridge_rejects_zero_sized_buffer() {
        let raw = AbiDmaSlice {
            dma_handle_id: 1,
            device_addr: 0x2000,
            virt_addr: 0x1000,
            size: 0,
        };

        let err = import_dma_lease_from_abi(raw, DmaDirection::Bidirectional, record_dma_release)
            .unwrap_err();
        assert!(matches!(err, crate::error::KapiError::IoError));
    }

    #[test]
    fn abi_dma_bridge_rejects_null_pointer() {
        let raw = AbiDmaSlice {
            dma_handle_id: 1,
            device_addr: 0x2000,
            virt_addr: 0,
            size: 64,
        };

        let err = import_dma_lease_from_abi(raw, DmaDirection::Bidirectional, record_dma_release)
            .unwrap_err();
        assert!(matches!(err, crate::error::KapiError::IoError));
    }

    #[test]
    fn abi_dma_bridge_requires_observed_close() {
        RELEASED_DMA_HANDLE.store(0, Ordering::SeqCst);

        let mut backing = [0u8; 8];
        backing.copy_from_slice(b"dma-test");

        let raw = AbiDmaSlice {
            dma_handle_id: 42,
            device_addr: 0x9000,
            virt_addr: backing.as_mut_ptr() as usize as u64,
            size: backing.len(),
        };

        let dma = import_dma_lease_from_abi(raw, DmaDirection::Bidirectional, record_dma_release)
            .expect("valid ABI DMA lease");
        assert_eq!(dma.read(|bytes| bytes == b"dma-test"), Ok(true));
        assert_eq!(RELEASED_DMA_HANDLE.load(Ordering::SeqCst), 0);
        dma.close()
            .expect("explicit close must report release success");

        assert_eq!(RELEASED_DMA_HANDLE.load(Ordering::SeqCst), 42);
    }
}
