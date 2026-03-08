// ============================================================================
// drivers/virtio/src/blk/mod.rs - Shared VirtIO Block types
// ============================================================================

pub mod device;

/// VirtIO feature bits for block devices
pub mod features {
    pub const VIRTIO_BLK_F_SIZE_MAX: u64 = 1 << 1;
    pub const VIRTIO_BLK_F_SEG_MAX: u64 = 1 << 2;
    pub const VIRTIO_BLK_F_GEOMETRY: u64 = 1 << 4;
    pub const VIRTIO_BLK_F_RO: u64 = 1 << 5;
    pub const VIRTIO_BLK_F_BLK_SIZE: u64 = 1 << 6;
    pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;
    pub const VIRTIO_BLK_F_TOPOLOGY: u64 = 1 << 10;
    pub const VIRTIO_BLK_F_CONFIG_WCE: u64 = 1 << 11;
    pub const VIRTIO_BLK_F_MQ: u64 = 1 << 12;
    pub const VIRTIO_BLK_F_DISCARD: u64 = 1 << 13;
    pub const VIRTIO_BLK_F_WRITE_ZEROES: u64 = 1 << 14;
}

pub use features::*;

// ============================================================================
// Block Request Types
// ============================================================================

pub const VIRTIO_BLK_T_IN: u32 = 0;
pub const VIRTIO_BLK_T_OUT: u32 = 1;
pub const VIRTIO_BLK_T_FLUSH: u32 = 4;
pub const VIRTIO_BLK_T_DISCARD: u32 = 11;
pub const VIRTIO_BLK_T_WRITE_ZEROES: u32 = 13;

pub const VIRTIO_BLK_S_OK: u8 = 0;
pub const VIRTIO_BLK_S_IOERR: u8 = 1;
pub const VIRTIO_BLK_S_UNSUPP: u8 = 2;

/// Block request header
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioBlkReqHeader {
    pub type_: u32,
    pub reserved: u32,
    pub sector: u64,
}

// ============================================================================
// Block Device Configuration
// ============================================================================

/// Block device configuration (from device config space)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct VirtioBlkConfig {
    pub capacity: u64,
    pub size_max: u32,
    pub seg_max: u32,
    pub cylinders: u16,
    pub heads: u8,
    pub sectors: u8,
    pub blk_size: u32,
    pub physical_block_exp: u8,
    pub alignment_offset: u8,
    pub min_io_size: u16,
    pub opt_io_size: u32,
}

// ============================================================================
// Block Error Types
// ============================================================================

/// Block device error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// Device not ready
    NotReady,
    /// I/O error from device
    IoError,
    /// Queue full
    QueueFull,
    /// Unsupported operation
    Unsupported,
    /// Invalid parameter
    InvalidParam,
}

impl core::fmt::Display for BlockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BlockError::NotReady => write!(f, "Device not ready"),
            BlockError::IoError => write!(f, "I/O error"),
            BlockError::QueueFull => write!(f, "Queue full"),
            BlockError::Unsupported => write!(f, "Unsupported operation"),
            BlockError::InvalidParam => write!(f, "Invalid parameter"),
        }
    }
}
