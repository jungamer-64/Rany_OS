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
    virt_addr: *mut u8,
    size: usize,
}

// Safety: DmaBuffer is just address bookkeeping, actual memory access requires care
unsafe impl Send for DmaBuffer {}

impl DmaBuffer {
    /// Create a new DMA buffer (kernel-only)
    pub const fn new(phys_addr: u64, virt_addr: *mut u8, size: usize) -> Self {
        Self { phys_addr, virt_addr, size }
    }

    /// Physical address of the buffer
    pub fn physical_address(&self) -> u64 {
        self.phys_addr
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
        Self { data, src_port: 0, dst_port: 0 }
    }

    /// Create with port info
    pub fn with_ports(data: Vec<u8>, src_port: u16, dst_port: u16) -> Self {
        Self { data, src_port, dst_port }
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
        Self { id, connected: false }
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Set connection state (kernel-only)
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }
}
