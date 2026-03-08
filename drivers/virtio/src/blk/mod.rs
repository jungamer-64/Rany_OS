// ============================================================================
// drivers/virtio/src/blk/mod.rs - Shared VirtIO Blk types
// ============================================================================

use alloc::vec::Vec;

/// VirtIO feature bits for block devices
pub mod features {
    /// Maximum size of any single segment is in `size_max`
    pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
    /// Maximum number of segments in a request is in `seg_max`
    pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
    /// Disk-style geometry specified in `geometry`
    pub const VIRTIO_BLK_F_GEOMETRY: u64 = 1 << 4;
    /// Device is read-only
    pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
    /// Block size of disk is in `blk_size`
    pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
    /// Device supports request flushing
    pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
    /// Device supports topology information
    pub const VIRTIO_BLK_F_TOPOLOGY: u64 = 1 << 10;
    /// Device supports multiqueue
    pub const VIRTIO_BLK_F_MQ: u64 = 1 << 12;
    /// Device supports discard command
    pub const VIRTIO_BLK_F_DISCARD: u64 = 1 << 13;
    /// Device supports write zeroes command
    pub const VIRTIO_BLK_F_WRITE_ZEROES: u64 = 1 << 14;
}

/// VirtIO block request types
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioBlkReqType {
    /// Read from device
    In = 0,
    /// Write to device
    Out = 1,
    /// Flush data to device
    Flush = 4,
    /// Get device ID
    GetId = 8,
    /// Discard sectors
    Discard = 11,
    /// Write zeroes
    WriteZeroes = 13,
}

/// VirtIO block status codes
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VirtioBlkStatus {
    /// Success
    Ok = 0,
    /// I/O error
    IoErr = 1,
    /// Unsupported request
    Unsupported = 2,
}

// ============================================================================
// Block Request Format
// ============================================================================

/// VirtIO block request header
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtioBlkReqHeader {
    /// Request type (IN, OUT, FLUSH, etc.)
    pub req_type: u32,
    /// Reserved (for future use)
    pub reserved: u32,
    /// Sector number (512-byte sectors)
    pub sector: u64,
}

/// A block I/O request
pub struct BlockRequest {
    /// Request ID (descriptor index)
    pub id: u16,
    /// Request header
    pub header: VirtioBlkReqHeader,
    /// Data buffer
    pub data: Vec<u8>,
    /// Status byte (filled by device)
    pub status: u8,
}

// ============================================================================
// VirtIO Block Device
// ============================================================================

/// Block device configuration
#[derive(Clone, Debug)]
pub struct BlockDeviceConfig {
    /// Device capacity in 512-byte sectors
    pub capacity: u64,
    /// Block size (usually 512)
    pub block_size: u32,
    /// Maximum segment size
    pub seg_max: u32,
    /// Number of queues
    pub num_queues: u16,
    /// Read-only flag
    pub read_only: bool,
}

impl Default for BlockDeviceConfig {
    fn default() -> Self {
        Self {
            capacity: 0,
            block_size: 512,
            seg_max: 126,
            num_queues: 1,
            read_only: false,
        }
    }
}

/// Block device error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// Device not ready
    NotReady,
    /// Device is read-only
    ReadOnly,
    /// Invalid sector address
    InvalidSector,
    /// I/O error from device
    IoError,
    /// Queue full
    QueueFull,
    /// Unsupported operation
    Unsupported,
    /// Invalid buffer size
    InvalidBufferSize,
}
