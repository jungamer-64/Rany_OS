// ============================================================================
// kernel_api/src/services.rs - Kernel Services Trait (Dependency Inversion)
// ============================================================================
//!
//! # Kernel Services Interface
//!
//! This module defines the trait that the kernel must implement.
//! Applications and drivers depend only on this trait, not on kernel internals.

extern crate alloc;

use crate::{ChannelHandle, DmaBuffer, FileHandle, KapiResult, TaskHandle, TcpEndpoint};
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;

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

    /// Allocate DMA-capable memory
    ///
    /// Returns a typed `DmaBuffer` that contains the physical and virtual addresses
    /// of the allocated region.
    ///
    /// # Errors
    /// - `KapiError::OutOfMemory` if allocation fails
    fn alloc_dma(&self, size: usize) -> KapiResult<DmaBuffer>;

    /// Allocate DMA-capable memory for a specific device (IOMMU-aware)
    ///
    /// The `device_id` is a packed PCI BDF (Bus, Device, Function) and segment.
    /// Implementation should use this to create IOMMU mappings if the device is protected.
    ///
    /// # Default Behavior
    /// Delegates to `alloc_dma` for backward compatibility.
    fn alloc_dma_for_device(&self, size: usize, _device_id: u64) -> KapiResult<DmaBuffer> {
        self.alloc_dma(size)
    }

    /// Free DMA memory
    ///
    /// # Safety
    /// The provided `DmaBuffer` must have been originally allocated by `alloc_dma` or `alloc_dma_for_device`.
    fn free_dma(&self, buffer: DmaBuffer);

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
    // Network
    // ========================================================================

    /// Create a TCP endpoint
    ///
    /// Returns a typed `TcpEndpoint` on success.
    ///
    /// # Errors
    /// - `KapiError::ResourceExhausted` if the kernel cannot allocate a socket
    fn net_create_endpoint(&self) -> KapiResult<TcpEndpoint>;

    /// Close a TCP endpoint
    ///
    /// # Errors
    /// - `KapiError::InvalidHandle` if the endpoint handle is not recognized
    fn net_close_endpoint(&self, endpoint: TcpEndpoint) -> KapiResult<()>;

    /// Receive a packet (async). Returns an owned `Packet` on success.
    ///
    /// This returns a future that resolves when data is available for the
    /// specified endpoint. The implementation may allocate/copy data as
    /// necessary for cross-domain safety.
    fn net_recv_packet(
        &self,
        endpoint: TcpEndpoint,
    ) -> Pin<Box<dyn Future<Output = KapiResult<crate::Packet>> + Send>>;

    /// Send a packet (async). Takes ownership of the `Packet`.
    ///
    /// This returns a future that completes when the packet has been queued
    /// for transmission (or an error occurred).
    fn net_send_packet(
        &self,
        endpoint: TcpEndpoint,
        packet: crate::Packet,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>>;
    /// Create a raw (packet-oriented) endpoint
    fn net_create_raw_endpoint(&self) -> KapiResult<crate::RawEndpointHandle>;

    /// Close a raw endpoint
    fn net_close_raw_endpoint(&self, endpoint: crate::RawEndpointHandle) -> KapiResult<()>;

    /// Receive a raw packet (async)
    fn net_recv_raw(
        &self,
        endpoint: crate::RawEndpointHandle,
    ) -> Pin<Box<dyn Future<Output = KapiResult<crate::Packet>> + Send>>;

    /// Send a raw packet (async)
    fn net_send_raw(
        &self,
        endpoint: crate::RawEndpointHandle,
        packet: crate::Packet,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>>;
    // ========================================================================
    // Filesystem
    // ========================================================================

    /// Open a file
    ///
    /// Returns a typed `FileHandle` on success.
    ///
    /// # Errors
    /// - `KapiError::NotFound` if the file does not exist and `Create` is not specified
    /// - `KapiError::PermissionDenied` if permissions prevent opening
    fn fs_open(&self, path: &str, mode: crate::OpenMode) -> KapiResult<FileHandle>;

    /// Open a file and associate with an optional token.
    /// If `token` is Some(id) then the token must validate for `CAP_FOWNER`
    /// and the manager's in-flight counter will be incremented until `fs_close`.
    fn fs_open_with_token(
        &self,
        path: &str,
        mode: crate::OpenMode,
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

    /// Open a direct NVMe block handle (namespace + range)
    fn nvme_open_direct(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
    ) -> KapiResult<crate::DirectBlockHandle>;

    /// Open a direct NVMe block handle and associate it with an optional token.
    /// If `token` is Some(id) the token must validate for `CAP_DMA` and the manager's
    /// in-flight counter will be incremented until `nvme_close_direct` is called.
    fn nvme_open_direct_with_token(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
        token: Option<u64>,
    ) -> KapiResult<crate::DirectBlockHandle>;

    /// Close a kernel-registered direct NVMe open.
    fn nvme_close_direct(&self, handle: crate::DirectBlockHandle) -> KapiResult<()>;

    /// Read blocks into a DMA buffer (buffer returned on completion)
    fn nvme_read_blocks_dma(
        &self,
        handle: crate::DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>>;

    /// Write blocks from a DMA buffer (buffer returned on completion)
    fn nvme_write_blocks_dma(
        &self,
        handle: crate::DirectBlockHandle,
        block_offset: u64,
        buffer: DmaBuffer,
    ) -> Pin<Box<dyn Future<Output = KapiResult<DmaBuffer>> + Send>>;

    /// Flush pending writes for a direct handle
    fn nvme_flush_direct(
        &self,
        handle: crate::DirectBlockHandle,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>>;

    /// Discard blocks (TRIM)
    fn nvme_discard_direct(
        &self,
        handle: crate::DirectBlockHandle,
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
    // NVMe DMA Context Management (Option B-2: Full Abstraction)
    // ========================================================================

    /// Prepare DMA context for NVMe read operation
    ///
    /// Allocates a DMA buffer, creates IOMMU mappings, and builds PRP list.
    /// Returns an opaque handle containing IOVA addresses for command building.
    ///
    /// The caller uses `handle.data_iova()` as PRP1 and `handle.prp2()` as PRP2.
    ///
    /// # Errors
    /// - `KapiError::OutOfMemory` if DMA allocation fails
    /// - `KapiError::IoError` if IOMMU mapping fails
    fn nvme_prepare_dma_read(&self, device_id: u64, len: usize)
    -> KapiResult<crate::NvmeDmaHandle>;

    /// Prepare DMA context for NVMe write operation
    ///
    /// Allocates a DMA buffer, copies data into it, creates IOMMU mappings,
    /// and builds PRP list.
    fn nvme_prepare_dma_write(
        &self,
        device_id: u64,
        data: &[u8],
    ) -> KapiResult<crate::NvmeDmaHandle>;

    /// Complete DMA context after read I/O finished
    ///
    /// Returns the data read from the device. Releases all DMA resources.
    fn nvme_complete_dma_read(
        &self,
        handle: crate::NvmeDmaHandle,
    ) -> KapiResult<alloc::vec::Vec<u8>>;

    /// Complete DMA context after write I/O finished
    ///
    /// Releases all DMA resources. Returns `Ok(())` on success.
    fn nvme_complete_dma_write(&self, handle: crate::NvmeDmaHandle) -> KapiResult<()>;

    /// Get IOMMU device ID for NVMe controller
    ///
    /// Returns the IOMMU device ID used for DMA mappings. This abstracts
    /// the `io::nvme::iommu_device()` call.
    fn nvme_iommu_device_id(&self, device_id: u64) -> Option<u64>;

    /// Map physical address for NVMe DMA access
    ///
    /// Creates an IOMMU mapping for the given physical address.
    /// Returns (iova, mapping_id) where iova is the device-visible address
    /// and mapping_id is used for later unmap.
    fn nvme_iommu_map(&self, device_id: u64, phys_addr: u64, size: usize)
    -> KapiResult<(u64, u64)>;

    /// Unmap a previous IOMMU mapping
    fn nvme_iommu_unmap(&self, mapping_id: u64) -> KapiResult<()>;

    /// Submit an NVMe read/write I/O request
    ///
    /// This abstracts the io_scheduler submit and completion handling.
    /// Returns a handle that can be used to wait for completion.
    fn nvme_submit_rw(
        &self,
        request: crate::NvmeRwRequest,
        io_type: crate::NvmeIoType,
    ) -> KapiResult<crate::NvmeIoHandle>;

    /// Wait for an NVMe I/O request to complete
    ///
    /// Blocks until the I/O completes and returns the result.
    fn nvme_wait_io(
        &self,
        handle: crate::NvmeIoHandle,
    ) -> Pin<Box<dyn Future<Output = crate::NvmeIoResult> + Send>>;

    /// Register a completion callback for an NVMe I/O request
    fn nvme_register_completion_hook(
        &self,
        handle: crate::NvmeIoHandle,
        hook: Box<dyn FnOnce(crate::NvmeIoResult) + Send>,
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

    // ========================================================================
    // GUI Services (Optional)
    // ========================================================================

    /// Access time management services
    fn time_service(&self) -> Option<&dyn crate::time::TimeService>;

    /// Access GUI services if available
    fn gui(&self) -> Option<&dyn crate::gui::GuiServices>;

    // ========================================================================
    // Shell Services (Optional)
    // ========================================================================

    /// Access shell services if available
    fn shell(&self) -> Option<&dyn crate::shell::ShellServices>;
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
pub unsafe fn register_kernel(services: &'static dyn KernelServices) {
    KERNEL.call_once(|| services);
}

/// Get the registered kernel services
///
/// # Panics
/// Panics if called before `register_kernel`
#[inline]
pub fn kernel() -> &'static dyn KernelServices {
    *KERNEL
        .get()
        .expect("Kernel not initialized! Call register_kernel first.")
}

/// Check if kernel is registered
#[inline]
pub fn is_kernel_registered() -> bool {
    KERNEL.get().is_some()
}
