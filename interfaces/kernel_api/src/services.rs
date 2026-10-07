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
#[cfg(feature = "cell_runtime")]
use crate::dma::{
    DmaAccessWidth, DmaCompletionWitness, DmaDeviceAddress, DmaDirection, DmaLeaseAuthority,
    DmaLeaseError, DmaLeaseId, DmaLeaseState, DmaQueueIdentity, DmaQuiesceWitness,
    DmaReconcileWitness, DmaResetWitness,
};
use crate::ipc::{ChannelHandle, DomainId};
use crate::mmio::{MmioAcquireError, PciMmioRequest};
use crate::msix::MsixVectorInfo;
use crate::pci_config::{PciConfigReadError, PciConfigSnapshot};
#[cfg(feature = "cell_runtime")]
#[path = "services/cell_mmio.rs"]
mod cell_mmio;
#[cfg(feature = "cell_runtime")]
#[path = "services/cell_time.rs"]
mod cell_time;
use crate::resource::fs::{FileHandle, OpenMode};
use crate::resource::net::{
    InterfaceScope, NetSocketAddr, PacketPayload, RawEndpoint, TcpAcceptor, TcpConnection,
};
use crate::resource::storage::DirectBlockHandle;
use crate::resource::task::{SpawnError, TaskId, TaskOptions};
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
    /// Observe the conventional header of the caller's authorized PCI function.
    /// The provider pins enumeration while reading; the returned snapshot retains
    /// no resource. Register acquisition separately pins its complete lifetime.
    ///
    /// # Errors
    /// Distinguishes function validity, authorization, absence, resource
    /// admission and an unavailable configuration access mechanism.
    fn read_pci_config(
        &self,
        device: PackedPciLocation,
    ) -> Result<PciConfigSnapshot, PciConfigReadError>;

    /// Acquires the caller's PCI register aperture. Request validity alone does
    /// not grant access: the implementation authorizes the function, excludes
    /// RAM/conflicting grants, pins PCI configuration, and retains cache-correct
    /// mappings until the final derived register retires.
    ///
    /// # Errors
    /// Returns the validation, authorization, admission, cache, or mapping cause.
    fn acquire_pci_mmio(
        &self,
        request: PciMmioRequest,
    ) -> Result<hal::MappedMmio, MmioAcquireError>;
    // ========================================================================
    // Task Management
    // ========================================================================

    /// Publish a task only after its guarded stack, context, and registration
    /// resources are owned. A failed admission drops the supplied Future.
    ///
    /// # Errors
    /// Distinguishes scheduler/placement availability, identity or slot limits,
    /// physical memory, mapping and domain admission failures. A foreign
    /// runtime may additionally reject malformed input, receipts or an
    /// incompatible notification representation before transferring ownership.
    fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
        options: TaskOptions,
    ) -> Result<TaskId, SpawnError>;

    /// Get current tick count (milliseconds since boot)
    fn current_tick(&self) -> u64;

    /// Get current task ID
    fn current_task_id(&self) -> u64;

    // ========================================================================
    // Memory Management
    // ========================================================================

    /// Allocate device-scoped backing admitted through its IOMMU context.
    /// A CPU lease is returned only after translation admission completes;
    /// published backing remains retained during failed translation retirement.
    ///
    /// # Errors
    /// - `KapiError::OutOfMemory` if RAM or allocation metadata cannot be acquired
    /// - `KapiError::ResourceExhausted` if registry, IOVA or retirement admission is full
    /// - `KapiError::InvalidSize` or `InvalidAlignment` if the range cannot be mapped
    /// - `KapiError::NotInitialized` if the required allocator or IOMMU is not ready
    /// - `KapiError::IoError` if translation synchronization fails; the kernel
    ///   retains published backing until retirement completes
    /// - `KapiError::NotSupported` if `device_id` is null or device-scoped DMA is unavailable
    fn alloc_dma_for_device(
        &self,
        request: DmaAllocationRequest,
        device_id: PackedPciLocation,
    ) -> KapiResult<CpuDmaLease>;

    /// Reserve an exclusive host physical page for a bound balloon function.
    /// The page has no CPU access API and remains outside allocator reuse until
    /// explicit unaccepted return, acknowledged deflation or device reset.
    /// # Errors
    /// Distinguishes finite reservation exhaustion, memory quota, physical RAM,
    /// address geometry, authorization and owner admission failures.
    fn reserve_balloon_page(
        &self,
        device: PackedPciLocation,
    ) -> Result<crate::balloon::ReservedBalloonPage, crate::balloon::BalloonPageError>;

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

    /// Bind an owned MSI-X vector to the driver's ordinary-task IRQ relay.
    /// The caller retains its IRQ source and code until unbinding and stop.
    /// # Errors
    /// Rejects foreign vectors, duplicate bindings or relay task admission failure.
    fn bind_irq(&self, vector: u32, cookie: u64) -> KapiResult<()>;

    /// Close relay admission for an owned vector. A relay already in flight
    /// still retains the instance and must observe its stopped resource state.
    /// # Errors
    /// Rejects unknown vectors and bindings owned by another domain.
    fn unbind_irq(&self, vector: u32) -> KapiResult<()>;

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
    fn fs_open_with_token<'a>(
        &'a self,
        path: &'a str,
        mode: OpenMode,
        token: Option<u64>,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<FileHandle, crate::resource::fs::FsMutationError>>
                + Send
                + 'a,
        >,
    >;

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

    /// Transfer a DMA lease into a read. Rejection returns the usable lease;
    /// uncertain completion retains it with the device reconciliation owner.
    fn nvme_read_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: CpuDmaLease,
    ) -> Pin<Box<dyn Future<Output = crate::service::storage::BlockTransferOutcome> + Send>>;

    /// Transfer a DMA lease into a write, preserving returned versus retained
    /// ownership even when the operation fails.
    fn nvme_write_blocks_dma(
        &self,
        handle: DirectBlockHandle,
        block_offset: u64,
        buffer: CpuDmaLease,
    ) -> Pin<Box<dyn Future<Output = crate::service::storage::BlockTransferOutcome> + Send>>;

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

use exorust_sync::InitOnce;

/// Global kernel services instance
static KERNEL: InitOnce<&'static dyn KernelServices> = InitOnce::new();

/// Register the kernel implementation
///
/// # Safety
/// Must be called exactly once during kernel initialization,
/// before any KAPI functions are used.
pub unsafe fn install(services: &'static dyn KernelServices) {
    KERNEL.call_once(|| services);
}

/// Resolve the service boundary published for this runtime. A loaded cell uses
/// its kernel ABI provider even though it owns no local kernel registration.
#[inline]
pub fn try_instance() -> Option<&'static dyn KernelServices> {
    if let Some(services) = KERNEL.get() {
        return Some(*services);
    }

    #[cfg(feature = "cell_runtime")]
    {
        Some(standalone::instance())
    }

    #[cfg(not(feature = "cell_runtime"))]
    None
}

/// # Panics
///
/// Panics before the native kernel publishes its service boundary.
#[inline]
pub fn instance() -> &'static dyn KernelServices {
    try_instance().expect("Kernel services unavailable")
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

#[cfg(feature = "cell_runtime")]
struct CellDmaLeaseAuthority {
    lease: DmaLeaseId,
    device_address: DmaDeviceAddress,
    byte_count: crate::dma::DmaByteCount,
    direction: DmaDirection,
}

#[cfg(feature = "cell_runtime")]
impl CellDmaLeaseAuthority {
    fn request(
        operation: crate::abi::driver::AbiDmaOperation,
    ) -> crate::abi::driver::AbiDmaRequest {
        crate::abi::driver::AbiDmaRequest {
            operation: operation as u32,
            ..crate::abi::driver::AbiDmaRequest::default()
        }
    }

    fn queue_request(
        operation: crate::abi::driver::AbiDmaOperation,
        queue: DmaQueueIdentity,
    ) -> crate::abi::driver::AbiDmaRequest {
        crate::abi::driver::AbiDmaRequest {
            operation: operation as u32,
            device: queue.device().raw(),
            queue: queue.index(),
            generation: queue.generation(),
            ..crate::abi::driver::AbiDmaRequest::default()
        }
    }

    fn call(
        &self,
        request: &crate::abi::driver::AbiDmaRequest,
    ) -> Result<crate::abi::driver::AbiDmaResponse, DmaLeaseError> {
        let mut response = crate::abi::driver::AbiDmaResponse::default();
        // SAFETY: both ABI records are live, aligned, and remain borrowed for
        // the synchronous call. Hardware-evidence operations are reached only
        // from methods that consume the corresponding non-cloneable witness.
        let raw_status =
            unsafe { (abi().dma_command)(self.lease.into_abi(), request, &mut response) };
        let status = crate::abi::driver::AbiDmaStatus::from_raw(raw_status)
            .ok_or(DmaLeaseError::AuthorityViolation)?;
        status.into_result()?;
        Ok(response)
    }

    fn status(raw_status: i32) -> Result<(), DmaLeaseError> {
        crate::abi::driver::AbiDmaStatus::from_raw(raw_status)
            .ok_or(DmaLeaseError::AuthorityViolation)?
            .into_result()
    }
}

#[cfg(feature = "cell_runtime")]
struct ReadVisitor<'visitor> {
    visitor: &'visitor mut dyn FnMut(&[u8]),
}

#[cfg(feature = "cell_runtime")]
unsafe extern "C" fn visit_read_bytes(context: *mut u8, bytes: *const u8, len: usize) {
    // SAFETY: `with_cpu_bytes` passes a live `ReadVisitor` for this synchronous
    // callback and the kernel guarantees a non-null initialized range for `len`.
    let context = unsafe { &mut *context.cast::<ReadVisitor<'_>>() };
    // SAFETY: the registry pins the allocation in CpuOwned for this callback;
    // the slice cannot escape the visitor's higher-ranked call boundary.
    let bytes = unsafe { core::slice::from_raw_parts(bytes, len) };
    (context.visitor)(bytes);
}

#[cfg(feature = "cell_runtime")]
struct WriteVisitor<'visitor> {
    visitor: &'visitor mut dyn FnMut(&mut [u8]),
}

#[cfg(feature = "cell_runtime")]
unsafe extern "C" fn visit_write_bytes(context: *mut u8, bytes: *mut u8, len: usize) {
    // SAFETY: `with_cpu_bytes_mut` passes a live `WriteVisitor` and the registry
    // grants this callback exclusive access to the initialized range.
    let context = unsafe { &mut *context.cast::<WriteVisitor<'_>>() };
    // SAFETY: pointer validity, initialization, exclusivity, and callback
    // duration are established by the registry-owned ABI implementation.
    let bytes = unsafe { core::slice::from_raw_parts_mut(bytes, len) };
    (context.visitor)(bytes);
}

// SAFETY: This proxy owns no backing pointer or independent lifecycle state.
// Every operation is synchronously validated and serialized by the kernel
// registry for one immutable lease generation. CPU pointers exist only during
// a registry callback and cannot be retained by this implementation.
#[cfg(feature = "cell_runtime")]
unsafe impl DmaLeaseAuthority for CellDmaLeaseAuthority {
    fn lease_id(&self) -> DmaLeaseId {
        self.lease
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
        let mut context = ReadVisitor { visitor };
        // SAFETY: the context and callback are live for the synchronous call;
        // the kernel validates lease ownership/state before exposing bytes.
        let status = unsafe {
            (abi().dma_read)(
                self.lease.into_abi(),
                core::ptr::addr_of_mut!(context).cast(),
                visit_read_bytes,
            )
        };
        Self::status(status)
    }

    fn with_cpu_bytes_mut(&self, visitor: &mut dyn FnMut(&mut [u8])) -> Result<(), DmaLeaseError> {
        let mut context = WriteVisitor { visitor };
        // SAFETY: as above, with exclusive registry access for the callback.
        let status = unsafe {
            (abi().dma_write)(
                self.lease.into_abi(),
                core::ptr::addr_of_mut!(context).cast(),
                visit_write_bytes,
            )
        };
        Self::status(status)
    }

    fn prepare(&self, queue: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
        self.call(&Self::queue_request(
            crate::abi::driver::AbiDmaOperation::Prepare,
            queue,
        ))
        .map(|_| ())
    }

    fn prepared_queue(&self) -> Result<DmaQueueIdentity, DmaLeaseError> {
        let response = self.call(&Self::request(
            crate::abi::driver::AbiDmaOperation::PreparedQueue,
        ))?;
        DmaQueueIdentity::new(
            PackedPciLocation::from_raw(response.device),
            response.queue,
            response.generation,
        )
        .ok_or(DmaLeaseError::AuthorityViolation)
    }

    fn abort_prepared(&self) -> Result<(), DmaLeaseError> {
        self.call(&Self::request(crate::abi::driver::AbiDmaOperation::Abort))
            .map(|_| ())
    }

    fn arm(&self) -> Result<(), DmaLeaseError> {
        self.call(&Self::request(crate::abi::driver::AbiDmaOperation::Arm))
            .map(|_| ())
    }

    fn complete(&self, witness: DmaCompletionWitness) -> Result<(), DmaLeaseError> {
        let mut request = Self::queue_request(
            crate::abi::driver::AbiDmaOperation::Complete,
            witness.queue(),
        );
        request.witness_lease = witness.lease_id().into_abi();
        self.call(&request).map(|_| ())
    }

    fn return_to_cpu(&self) -> Result<(), DmaLeaseError> {
        self.call(&Self::request(
            crate::abi::driver::AbiDmaOperation::ReturnToCpu,
        ))
        .map(|_| ())
    }

    fn mark_outcome_unknown(&self) -> Result<(), DmaLeaseError> {
        self.call(&Self::request(
            crate::abi::driver::AbiDmaOperation::OutcomeUnknown,
        ))
        .map(|_| ())
    }

    fn revoke_after_reset(&self, witness: DmaResetWitness) -> Result<(), DmaLeaseError> {
        let mut request = Self::request(crate::abi::driver::AbiDmaOperation::Revoke);
        request.device = witness.device().raw();
        request.generation = witness.generation();
        self.call(&request).map(|_| ())
    }

    fn reconcile(&self, witness: DmaReconcileWitness) -> Result<(), DmaLeaseError> {
        let mut request = Self::request(crate::abi::driver::AbiDmaOperation::Reconcile);
        request.device = witness.device().raw();
        request.generation = witness.generation();
        self.call(&request).map(|_| ())
    }

    fn close(&self) -> Result<(), DmaLeaseError> {
        self.call(&Self::request(crate::abi::driver::AbiDmaOperation::Close))
            .map(|_| ())
    }

    fn prepare_shared(&self, queue: DmaQueueIdentity) -> Result<(), DmaLeaseError> {
        self.call(&Self::queue_request(
            crate::abi::driver::AbiDmaOperation::PrepareShared,
            queue,
        ))
        .map(|_| ())
    }

    fn activate_shared(&self) -> Result<(), DmaLeaseError> {
        self.call(&Self::request(
            crate::abi::driver::AbiDmaOperation::ActivateShared,
        ))
        .map(|_| ())
    }

    fn read_shared_word(&self, offset: usize, width: DmaAccessWidth) -> Result<u64, DmaLeaseError> {
        let mut request = Self::request(crate::abi::driver::AbiDmaOperation::ReadShared);
        request.offset = offset;
        request.width = width.into_abi();
        self.call(&request).map(|response| response.value)
    }

    fn write_shared_word(
        &self,
        offset: usize,
        width: DmaAccessWidth,
        value: u64,
    ) -> Result<(), DmaLeaseError> {
        let mut request = Self::request(crate::abi::driver::AbiDmaOperation::WriteShared);
        request.offset = offset;
        request.width = width.into_abi();
        request.value = value;
        self.call(&request).map(|_| ())
    }

    fn quiesce_shared(&self, witness: DmaQuiesceWitness) -> Result<(), DmaLeaseError> {
        let mut request = Self::queue_request(
            crate::abi::driver::AbiDmaOperation::QuiesceShared,
            witness.queue(),
        );
        request.witness_lease = witness.lease_id().into_abi();
        self.call(&request).map(|_| ())
    }

    fn retry_close(&self) -> Result<(), DmaLeaseError> {
        let request = Self::request(crate::abi::driver::AbiDmaOperation::RetryClose);
        self.call(&request).map(|_| ())
    }

    fn abandon(&self, observed_state: DmaLeaseState) {
        let mut request = Self::request(crate::abi::driver::AbiDmaOperation::Abandon);
        request.state = observed_state.into_abi();
        if let Err(error) = self.call(&request) {
            log::error!("DMA ABI abandon failed for {:?}: {:?}", self.lease, error);
        }
    }
}

#[cfg(feature = "cell_runtime")]
fn import_dma_allocation(
    raw: crate::abi::driver::AbiDmaAllocation,
    direction: DmaDirection,
) -> KapiResult<CpuDmaLease> {
    let lease = DmaLeaseId::from_abi(raw.lease_id).ok_or(crate::error::KapiError::IoError)?;
    let byte_count =
        crate::dma::DmaByteCount::new(raw.byte_count).ok_or(crate::error::KapiError::IoError)?;
    Ok(CpuDmaLease::from_authority(alloc::sync::Arc::new(
        CellDmaLeaseAuthority {
            lease,
            device_address: DmaDeviceAddress::from_abi(raw.device_address),
            byte_count,
            direction,
        },
    )))
}

#[cfg(feature = "cell_runtime")]
mod standalone {
    use super::*;
    use crate::KapiError;
    use crate::abi::driver::{AbiDmaAllocation, AbiError, AbiMsixVectorInfo};

    static STANDALONE_KERNEL: StandaloneKernelServices = StandaloneKernelServices;

    pub(super) fn instance() -> &'static dyn KernelServices {
        &STANDALONE_KERNEL
    }

    fn unsupported_future<T: Send + 'static>() -> Pin<Box<dyn Future<Output = KapiResult<T>> + Send>>
    {
        Box::pin(async { Err(KapiError::NotSupported) })
    }

    fn alloc_dma_for_device(
        request: DmaAllocationRequest,
        device_id: PackedPciLocation,
    ) -> KapiResult<CpuDmaLease> {
        let mut raw = AbiDmaAllocation::default();
        // SAFETY: `raw` is writable and aligned for the complete synchronous
        // call; the request has already validated its non-zero byte count.
        let status = unsafe {
            (super::abi().dma_allocate)(
                request.byte_count().get(),
                device_id.raw(),
                request.direction().into_abi(),
                &mut raw,
            )
        };
        AbiError::from_raw(status).into_result()?;
        super::import_dma_allocation(raw, request.direction())
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
        AbiError::from_raw(status).into_result()?;
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
        AbiError::from_raw(status).into_result()
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
        AbiError::from_raw(status).into_result()?;
        let ptr = NonNull::new(ptr).ok_or(KapiError::IoError)?;
        Ok((ptr, DomainId::new(owner)))
    }

    fn exchange_dealloc_raw(
        ptr: NonNull<u8>,
        owner: DomainId,
        size: usize,
        align: usize,
    ) -> KapiResult<()> {
        let api = require_full_kernel_api()?;
        let status = (api.exchange_dealloc_raw)(ptr.as_ptr(), owner.as_u64(), size, align);
        AbiError::from_raw(status).into_result()
    }

    fn exchange_transfer_raw(ptr: NonNull<u8>, from: DomainId, to: DomainId) -> KapiResult<()> {
        let api = require_full_kernel_api()?;
        let status = (api.exchange_transfer_raw)(ptr.as_ptr(), from.as_u64(), to.as_u64());
        AbiError::from_raw(status).into_result()
    }

    fn ipc_create_channel() -> KapiResult<(ChannelHandle, ChannelHandle)> {
        let api = require_full_kernel_api()?;
        let mut sender = 0u64;
        let mut receiver = 0u64;
        let status = (api.ipc_create_channel_raw)(&mut sender, &mut receiver);
        AbiError::from_raw(status).into_result()?;
        Ok((ChannelHandle::new(sender), ChannelHandle::new(receiver)))
    }

    fn ipc_close(channel: ChannelHandle) -> KapiResult<()> {
        let api = require_full_kernel_api()?;
        let status = (api.ipc_close_raw)(channel.id());
        AbiError::from_raw(status).into_result()
    }

    fn ipc_send_raw(channel: ChannelHandle, raw: AbiRRefRaw) -> KapiResult<()> {
        let api = require_full_kernel_api()?;
        let status = (api.ipc_send_raw)(channel.id(), &raw);
        AbiError::from_raw(status).into_result()
    }

    fn ipc_recv_raw(channel: ChannelHandle) -> KapiResult<AbiRRefRaw> {
        let api = require_full_kernel_api()?;
        let mut raw = AbiRRefRaw::default();
        let status = (api.ipc_recv_raw)(channel.id(), &mut raw);
        AbiError::from_raw(status).into_result()?;
        Ok(raw)
    }

    struct StandaloneKernelServices;

    impl KernelServices for StandaloneKernelServices {
        fn spawn(
            &self,
            future: Pin<Box<dyn Future<Output = ()> + Send>>,
            options: TaskOptions,
        ) -> Result<TaskId, SpawnError> {
            use crate::abi::driver::{AbiTaskFuture, AbiTaskOptions};
            if super::abi().task_waker_abi != crate::abi::driver::TASK_WAKER_ABI {
                return Err(SpawnError::RuntimeAbiMismatch);
            }
            let mut future = AbiTaskFuture::new(future)?;
            let options = AbiTaskOptions::from_options(options);
            // SAFETY: these stack inputs are initialized, aligned and uniquely
            // borrowed. The current invocation retains originating code while
            // the provider consumes or rejects its single Future owner.
            unsafe { (super::abi().spawn)(&mut future, &options) }.into_result()
        }

        fn read_pci_config(
            &self,
            device: PackedPciLocation,
        ) -> Result<PciConfigSnapshot, PciConfigReadError> {
            super::cell_mmio::read_pci_config(device)
        }

        fn acquire_pci_mmio(
            &self,
            request: PciMmioRequest,
        ) -> Result<hal::MappedMmio, MmioAcquireError> {
            super::cell_mmio::acquire(request)
        }

        fn current_tick(&self) -> u64 {
            (super::abi().current_tick)()
        }

        fn current_task_id(&self) -> u64 {
            (super::abi().current_task_id)()
        }

        fn alloc_dma_for_device(
            &self,
            request: DmaAllocationRequest,
            device_id: PackedPciLocation,
        ) -> KapiResult<CpuDmaLease> {
            alloc_dma_for_device(request, device_id)
        }

        fn reserve_balloon_page(
            &self,
            device: PackedPciLocation,
        ) -> Result<crate::balloon::ReservedBalloonPage, crate::balloon::BalloonPageError> {
            use crate::balloon::{AbiBalloonPage, BalloonPageError, ReservedBalloonPage};
            let api = super::abi();
            if (api.abi_size as usize) < core::mem::size_of::<KernelApiV4>() {
                return Err(BalloonPageError::MalformedAbi);
            }
            let mut raw = AbiBalloonPage::default();
            // SAFETY: output is uniquely borrowed, initialized and aligned for
            // the permanent provider's synchronous allocation publication.
            BalloonPageError::from_status(unsafe {
                (api.balloon_page_reserve)(device.raw(), &mut raw)
            })?;
            // SAFETY: successful publication issued a unique retained page for
            // this bound function; kernel callback code outlives the reservation.
            unsafe { ReservedBalloonPage::from_allocator(raw, device, api.balloon_page_command) }
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

        fn bind_irq(&self, vector: u32, cookie: u64) -> KapiResult<()> {
            AbiError::from_raw((super::abi().irq_bind)(vector, cookie)).into_result()
        }

        fn unbind_irq(&self, vector: u32) -> KapiResult<()> {
            AbiError::from_raw((super::abi().irq_unbind)(vector)).into_result()
        }

        fn net_alloc_packet(
            &self,
            _len: usize,
            _headroom: usize,
        ) -> KapiResult<crate::resource::net::PacketRef> {
            Err(KapiError::NotSupported)
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
            AbiError::from_raw(status).into_result()?;
            Ok(handle)
        }

        fn unregister_block_device(&self, handle: u64) -> KapiResult<()> {
            let status = (super::abi().unregister_block_device)(handle);
            AbiError::from_raw(status).into_result()
        }

        fn register_nvme_namespace(
            &self,
            registration: &AbiNvmeNamespaceRegistration,
        ) -> KapiResult<u64> {
            let mut handle = 0u64;
            let status = (super::abi().register_nvme_namespace)(registration, &mut handle);
            AbiError::from_raw(status).into_result()?;
            Ok(handle)
        }

        fn unregister_nvme_namespace(&self, handle: u64) -> KapiResult<()> {
            let status = (super::abi().unregister_nvme_namespace)(handle);
            AbiError::from_raw(status).into_result()
        }

        fn register_netdev_port(&self, registration: &AbiNetPortRegistration) -> KapiResult<u64> {
            let mut handle = 0u64;
            let status = (super::abi().register_netdev_port)(registration, &mut handle);
            if AbiError::from_raw(status).is_success() {
                Ok(handle)
            } else if handle != 0 {
                Err(KapiError::NetRegistrationRetained { handle })
            } else {
                AbiError::from_raw(status).into_result().map(|()| handle)
            }
        }

        fn unregister_netdev_port(&self, handle: u64) -> KapiResult<()> {
            let status = (super::abi().unregister_netdev_port)(handle);
            AbiError::from_raw(status).into_result()
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

        fn fs_open_with_token<'a>(
            &'a self,
            path: &'a str,
            mode: OpenMode,
            token: Option<u64>,
        ) -> Pin<
            Box<
                dyn Future<Output = Result<FileHandle, crate::resource::fs::FsMutationError>>
                    + Send
                    + 'a,
            >,
        > {
            let _ = (path, mode, token);
            Box::pin(async {
                Err(crate::resource::fs::FsMutationError::Filesystem(
                    KapiError::NotSupported,
                ))
            })
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
        ) -> Pin<Box<dyn Future<Output = crate::service::storage::BlockTransferOutcome> + Send>>
        {
            let _ = (handle, block_offset);
            Box::pin(async move {
                crate::service::storage::BlockTransferOutcome::Returned {
                    result: Err(crate::service::storage::BlockTransferError::NotSupported),
                    buffer,
                }
            })
        }

        fn nvme_write_blocks_dma(
            &self,
            handle: DirectBlockHandle,
            block_offset: u64,
            buffer: CpuDmaLease,
        ) -> Pin<Box<dyn Future<Output = crate::service::storage::BlockTransferOutcome> + Send>>
        {
            let _ = (handle, block_offset);
            Box::pin(async move {
                crate::service::storage::BlockTransferOutcome::Returned {
                    result: Err(crate::service::storage::BlockTransferError::NotSupported),
                    buffer,
                }
            })
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
            ((super::abi().time_snapshot)().available == 1)
                .then_some(&super::cell_time::TIME as &dyn TimeService)
        }
    }
}
