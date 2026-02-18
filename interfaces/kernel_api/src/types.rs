// ============================================================================
// kernel_api/src/types.rs - Shared Type Definitions
// ============================================================================
//!
//! Pure type definitions that can be used by kernel, drivers, and applications.
//! These types have no kernel dependencies.

extern crate alloc;

use alloc::vec::Vec;

/// Task handle - opaque reference to a spawned task
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskHandle {
    id: u64,
}

impl TaskHandle {
    /// Create a new task handle (kernel-only)
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Get the task ID
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// DMA buffer - represents a region of DMA-capable memory
pub struct DmaBuffer {
    phys_addr: u64,
    /// Hardware-visible address (IOVA when IOMMU active, else phys_addr)
    device_addr: u64,
    virt_addr: *mut u8,
    size: usize,
}

// Safety: DmaBuffer is just address bookkeeping, actual memory access requires care
unsafe impl Send for DmaBuffer {}

impl DmaBuffer {
    /// Create a new DMA buffer (kernel-only)
    pub const fn new(phys_addr: u64, virt_addr: *mut u8, size: usize) -> Self {
        Self {
            phys_addr,
            device_addr: phys_addr,
            virt_addr,
            size,
        }
    }

    /// Create a new DMA buffer with explicit device address (IOMMU-aware)
    pub const fn new_with_device_addr(
        phys_addr: u64,
        device_addr: u64,
        virt_addr: *mut u8,
        size: usize,
    ) -> Self {
        Self {
            phys_addr,
            device_addr,
            virt_addr,
            size,
        }
    }

    /// Physical address of the buffer
    pub fn physical_address(&self) -> u64 {
        self.phys_addr
    }

    /// Device-visible address (IOVA when IOMMU is active, physical otherwise)
    pub fn device_address(&self) -> u64 {
        self.device_addr
    }

    /// Virtual address pointer
    pub fn as_ptr(&self) -> *mut u8 {
        self.virt_addr
    }

    /// Size in bytes
    pub fn size(&self) -> usize {
        self.size
    }

    /// Access as byte slice
    ///
    /// # Safety
    /// Caller must ensure the buffer is valid and properly initialized
    pub unsafe fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.virt_addr, self.size) }
    }

    /// Access as mutable byte slice
    ///
    /// # Safety
    /// Caller must ensure exclusive access and buffer validity
    pub unsafe fn as_slice_mut(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.virt_addr, self.size) }
    }
}

/// Network packet with ownership semantics
pub struct Packet {
    data: Vec<u8>,
    pub src_port: u16,
    pub dst_port: u16,
}

impl Packet {
    /// Create a new packet
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            src_port: 0,
            dst_port: 0,
        }
    }

    /// Create with port info
    pub fn with_ports(data: Vec<u8>, src_port: u16, dst_port: u16) -> Self {
        Self {
            data,
            src_port,
            dst_port,
        }
    }

    /// Get packet data
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable packet data
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }

    /// Packet length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Is packet empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

/// System information
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub total_memory: u64,
    pub free_memory: u64,
    pub uptime_ms: u64,
    pub cpu_count: u32,
}

/// File open mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    Read,
    Write,
    ReadWrite,
    Append,
    Create,
}

/// File handle
pub struct FileHandle {
    id: u64,
    mode: OpenMode,
}

impl FileHandle {
    /// Create new file handle (kernel-only)
    pub const fn new(id: u64, mode: OpenMode) -> Self {
        Self { id, mode }
    }

    /// Get file ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get open mode
    pub fn mode(&self) -> OpenMode {
        self.mode
    }
}

/// Direct block device handle (NVMe namespace)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectBlockHandle {
    device_id: u64,
    start_block: u64,
    block_count: u64,
    block_size: u32,
    /// Optional kernel-assigned open id (0 == not an open returned by kernel)
    open_id: u64,
}

impl DirectBlockHandle {
    /// Create a new direct block handle (kernel-only)
    /// This constructor represents a *standalone* handle (not a kernel-registered open).
    pub const fn new(
        device_id: u64,
        start_block: u64,
        block_count: u64,
        block_size: u32,
    ) -> Self {
        Self {
            device_id,
            start_block,
            block_count,
            block_size,
            open_id: 0,
        }
    }

    /// Create a kernel-registered handle with an `open_id`
    pub const fn new_with_id(
        device_id: u64,
        start_block: u64,
        block_count: u64,
        block_size: u32,
        open_id: u64,
    ) -> Self {
        Self {
            device_id,
            start_block,
            block_count,
            block_size,
            open_id,
        }
    }

    pub fn device_id(&self) -> u64 {
        self.device_id
    }

    pub fn start_block(&self) -> u64 {
        self.start_block
    }

    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Kernel-assigned open id (0 if not from `nvme_open_direct_with_token`/`nvme_open_direct`)
    pub fn open_id(&self) -> u64 {
        self.open_id
    }
}

/// IPC channel handle
pub struct ChannelHandle {
    id: u64,
}

impl ChannelHandle {
    /// Create new channel handle (kernel-only)
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Get channel ID
    pub fn id(&self) -> u64 {
        self.id
    }
}

/// TCP endpoint
pub struct TcpEndpoint {
    id: u64,
    connected: bool,
}

impl TcpEndpoint {
    /// Create new TCP endpoint
    pub fn new(id: u64) -> Self {
        Self {
            id,
            connected: false,
        }
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Set connection state (kernel-only)
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    /// Get raw endpoint id
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Consume the endpoint and return its raw id
    pub fn into_raw(self) -> u64 {
        self.id
    }
}

/// Raw socket handle (for raw/packet-oriented sockets)
pub struct RawSocketHandle {
    id: u64,
}

impl RawSocketHandle {
    /// Create new raw socket handle (kernel-only)
    pub const fn new(id: u64) -> Self {
        Self { id }
    }

    /// Get raw id
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Consume and return raw id
    pub fn into_raw(self) -> u64 {
        self.id
    }
}

// ============================================================================
// NVMe DMA Handle (Option B-2: Full DMA Abstraction)
// ============================================================================

/// Opaque handle to a prepared NVMe DMA context
///
/// Represents a DMA buffer ready for NVMe I/O, with all IOMMU mappings
/// and PRP/SGL lists prepared internally by the kernel. The caller only
/// receives the IOVA addresses needed for command building.
///
/// Must be completed via `KernelServices::nvme_complete_dma_*` after I/O
/// finishes to reclaim resources and retrieve data.
#[derive(Debug)]
pub struct NvmeDmaHandle {
    id: u64,
    /// Data buffer IOVA (PRP1 in NVMe command)
    data_iova: u64,
    /// PRP2 or SGL address
    prp2_or_sgl: u64,
    /// Logical size of the transfer
    len: usize,
}

impl NvmeDmaHandle {
    /// Create a new handle (kernel-only)
    pub const fn new(id: u64, data_iova: u64, prp2_or_sgl: u64, len: usize) -> Self {
        Self { id, data_iova, prp2_or_sgl, len }
    }

    /// Internal context ID
    pub fn id(&self) -> u64 {
        self.id
    }

    /// IOVA of data buffer (use as PRP1)
    pub fn data_iova(&self) -> u64 {
        self.data_iova
    }

    /// PRP2 value (second page IOVA or PRP list IOVA)
    pub fn prp2(&self) -> u64 {
        self.prp2_or_sgl
    }

    /// Logical transfer size
    pub fn len(&self) -> usize {
        self.len
    }

    /// Check if the transfer is empty
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ============================================================================
// NVMe I/O Request Types (io_scheduler abstraction)
// ============================================================================

/// NVMe I/O operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NvmeIoType {
    /// Read operation
    Read,
    /// Write operation
    Write,
    /// Flush operation
    Flush,
    /// Discard/TRIM operation
    Discard,
}

/// NVMe I/O priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NvmeIoPriority {
    /// Background (lowest)
    Background,
    /// Idle
    Idle,
    /// Normal (default)
    #[default]
    Normal,
    /// High priority
    High,
    /// Realtime (highest)
    Realtime,
}

/// NVMe Read/Write request parameters
#[derive(Debug, Clone)]
pub struct NvmeRwRequest {
    /// NVMe device ID
    pub device_id: u64,
    /// NVMe namespace ID
    pub namespace_id: u32,
    /// Starting LBA
    pub lba: u64,
    /// Number of blocks
    pub blocks: u16,
    /// PRP1 (first page IOVA)
    pub prp1: u64,
    /// PRP2 (second page or PRP list IOVA)
    pub prp2: u64,
    /// Transfer size in bytes
    pub bytes: usize,
    /// I/O priority
    pub priority: NvmeIoPriority,
}

/// NVMe I/O request handle
#[derive(Debug, Clone, Copy)]
pub struct NvmeIoHandle {
    request_id: u64,
}

impl NvmeIoHandle {
    /// Create a new handle (kernel-only)
    pub const fn new(request_id: u64) -> Self {
        Self { request_id }
    }

    /// Get the request ID
    pub fn request_id(&self) -> u64 {
        self.request_id
    }
}

/// NVMe I/O result
#[derive(Debug, Clone)]
pub enum NvmeIoResult {
    /// Success with transferred byte count
    Success(usize),
    /// Device error
    DeviceError,
    /// Timeout
    Timeout,
    /// Cancelled
    Cancelled,
    /// Invalid parameter
    InvalidParameter,
}
