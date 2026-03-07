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
use crate::abi::driver::KernelApiV2;
use crate::dma::{CpuOwned, DmaSlice};
use crate::ipc::ChannelHandle;
use crate::resource::fs::{FileHandle, OpenMode};
use crate::resource::net::{Packet, RawEndpointHandle, TcpEndpoint};
use crate::resource::storage::{
    DirectBlockHandle, NvmeDmaHandle, NvmeIoHandle, NvmeIoResult, NvmeIoType, NvmeRwRequest,
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
    /// Returns a CPU-owned DMA slice.
    /// of the allocated region.
    ///
    /// # Errors
    /// - `KapiError::OutOfMemory` if allocation fails
    fn alloc_dma(&self, size: usize) -> KapiResult<DmaSlice<CpuOwned>>;

    /// Allocate DMA-capable memory for a specific device (IOMMU-aware)
    ///
    /// The `device_id` is a packed PCI BDF (Bus, Device, Function) and segment.
    /// Implementation should use this to create IOMMU mappings if the device is protected.
    ///
    /// # Default Behavior
    /// Delegates to `alloc_dma` for backward compatibility.
    fn alloc_dma_for_device(&self, size: usize, _device_id: u64) -> KapiResult<DmaSlice<CpuOwned>> {
        self.alloc_dma(size)
    }

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
    ) -> Pin<Box<dyn Future<Output = KapiResult<Packet>> + Send>>;

    /// Send a packet (async). Takes ownership of the `Packet`.
    ///
    /// This returns a future that completes when the packet has been queued
    /// for transmission (or an error occurred).
    fn net_send_packet(
        &self,
        endpoint: TcpEndpoint,
        packet: Packet,
    ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>>;
    /// Create a raw (packet-oriented) endpoint
    fn net_create_raw_endpoint(&self) -> KapiResult<RawEndpointHandle>;

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
        packet: Packet,
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
    fn fs_open(&self, path: &str, mode: OpenMode) -> KapiResult<FileHandle>;

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

    /// Open a direct NVMe block handle (namespace + range)
    fn nvme_open_direct(
        &self,
        device_id: u64,
        start_block: u64,
        block_count: u64,
    ) -> KapiResult<DirectBlockHandle>;

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
    fn nvme_prepare_dma_read(&self, device_id: u64, len: usize) -> KapiResult<NvmeDmaHandle>;

    /// Prepare DMA context for NVMe write operation
    ///
    /// Allocates a DMA buffer, copies data into it, creates IOMMU mappings,
    /// and builds PRP list.
    fn nvme_prepare_dma_write(&self, device_id: u64, data: &[u8]) -> KapiResult<NvmeDmaHandle>;

    /// Complete DMA context after read I/O finished
    ///
    /// Returns the data read from the device. Releases all DMA resources.
    fn nvme_complete_dma_read(&self, handle: NvmeDmaHandle) -> KapiResult<alloc::vec::Vec<u8>>;

    /// Complete DMA context after write I/O finished
    ///
    /// Releases all DMA resources. Returns `Ok(())` on success.
    fn nvme_complete_dma_write(&self, handle: NvmeDmaHandle) -> KapiResult<()>;

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
    /// The global KernelApiV2 instance exported by the kernel.
    static __exorust_kernel_api_v2: KernelApiV2;
}

/// Get the stable ABI kernel API table
///
/// This is used by drivers and standalone cells to access kernel services
/// through the ABI-stable interface.
#[inline]
pub fn abi() -> &'static KernelApiV2 {
    unsafe { &__exorust_kernel_api_v2 }
}

#[cfg(feature = "cell_runtime")]
mod standalone {
    use super::*;
    use crate::KapiError;
    use crate::abi::driver::{AbiDmaSlice, AbiError};

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

    unsafe fn release_dma_from_abi(virt_addr: *mut u8, size: usize, phys_addr: u64) {
        let status = (super::abi().release_dma_raw)(virt_addr as u64, size, phys_addr);
        debug_assert_eq!(status, AbiError::Success as i32);
    }

    fn alloc_from_raw(raw: AbiDmaSlice) -> DmaSlice<CpuOwned> {
        unsafe {
            DmaSlice::from_raw_parts(
                raw.phys_addr,
                raw.device_addr,
                raw.virt_addr as usize as *mut u8,
                raw.size,
                Some(release_dma_from_abi),
            )
        }
    }

    fn alloc_dma(size: usize) -> KapiResult<DmaSlice<CpuOwned>> {
        let mut raw = AbiDmaSlice::default();
        let status = (super::abi().alloc_dma_raw)(size, 1, &mut raw);
        if AbiError::from_raw(status).is_success() {
            Ok(alloc_from_raw(raw))
        } else {
            Err(map_abi_error(status))
        }
    }

    fn alloc_dma_for_device(size: usize, device_id: u64) -> KapiResult<DmaSlice<CpuOwned>> {
        let mut raw = AbiDmaSlice::default();
        let status = (super::abi().alloc_dma_for_device_raw)(size, device_id, 1, &mut raw);
        if AbiError::from_raw(status).is_success() {
            Ok(alloc_from_raw(raw))
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

        fn alloc_dma(&self, size: usize) -> KapiResult<DmaSlice<CpuOwned>> {
            alloc_dma(size)
        }

        fn alloc_dma_for_device(
            &self,
            size: usize,
            device_id: u64,
        ) -> KapiResult<DmaSlice<CpuOwned>> {
            alloc_dma_for_device(size, device_id)
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

        fn net_create_endpoint(&self) -> KapiResult<TcpEndpoint> {
            Err(KapiError::NotSupported)
        }

        fn net_close_endpoint(&self, endpoint: TcpEndpoint) -> KapiResult<()> {
            let _ = endpoint;
            Err(KapiError::NotSupported)
        }

        fn net_recv_packet(
            &self,
            endpoint: TcpEndpoint,
        ) -> Pin<Box<dyn Future<Output = KapiResult<Packet>> + Send>> {
            let _ = endpoint;
            unsupported_future()
        }

        fn net_send_packet(
            &self,
            endpoint: TcpEndpoint,
            packet: Packet,
        ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
            let _ = (endpoint, packet);
            unsupported_future()
        }

        fn net_create_raw_endpoint(&self) -> KapiResult<RawEndpointHandle> {
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
            packet: Packet,
        ) -> Pin<Box<dyn Future<Output = KapiResult<()>> + Send>> {
            let _ = (endpoint, packet);
            unsupported_future()
        }

        fn fs_open(&self, path: &str, mode: OpenMode) -> KapiResult<FileHandle> {
            let _ = (path, mode);
            Err(KapiError::NotSupported)
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

        fn nvme_open_direct(
            &self,
            device_id: u64,
            start_block: u64,
            block_count: u64,
        ) -> KapiResult<DirectBlockHandle> {
            let _ = (device_id, start_block, block_count);
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

        fn nvme_prepare_dma_read(&self, device_id: u64, len: usize) -> KapiResult<NvmeDmaHandle> {
            let _ = (device_id, len);
            Err(KapiError::NotSupported)
        }

        fn nvme_prepare_dma_write(&self, device_id: u64, data: &[u8]) -> KapiResult<NvmeDmaHandle> {
            let _ = (device_id, data);
            Err(KapiError::NotSupported)
        }

        fn nvme_complete_dma_read(&self, handle: NvmeDmaHandle) -> KapiResult<alloc::vec::Vec<u8>> {
            let _ = handle;
            Err(KapiError::NotSupported)
        }

        fn nvme_complete_dma_write(&self, handle: NvmeDmaHandle) -> KapiResult<()> {
            let _ = handle;
            Err(KapiError::NotSupported)
        }

        fn nvme_iommu_device_id(&self, device_id: u64) -> Option<u64> {
            let _ = device_id;
            None
        }

        fn nvme_iommu_map(
            &self,
            device_id: u64,
            phys_addr: u64,
            size: usize,
        ) -> KapiResult<(u64, u64)> {
            let _ = (device_id, phys_addr, size);
            Err(KapiError::NotSupported)
        }

        fn nvme_iommu_unmap(&self, mapping_id: u64) -> KapiResult<()> {
            let _ = mapping_id;
            Err(KapiError::NotSupported)
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
            Err(KapiError::NotSupported)
        }

        fn ipc_close(&self, channel: ChannelHandle) -> KapiResult<()> {
            let _ = channel;
            Err(KapiError::NotSupported)
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
