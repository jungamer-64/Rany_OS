// ============================================================================
// drivers/virtio/src/balloon/mod.rs - Shared VirtIO Balloon types
// ============================================================================

pub mod device;

/// VirtIO feature bits for balloon devices
pub mod features {
    /// Host must be told before pages are reclaimed
    pub const VIRTIO_BALLOON_F_MUST_TELL_HOST: u64 = 1 << 0;
    /// A virtqueue for reporting guest memory statistics is present
    pub const VIRTIO_BALLOON_F_STATS_VQ: u64 = 1 << 1;
    /// Deflate balloon on guest OOM
    pub const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u64 = 1 << 2;
    /// Free page hint reporting is supported
    pub const VIRTIO_BALLOON_F_FREE_PAGE_HINT: u64 = 1 << 3;
    /// Page reporting is supported
    pub const VIRTIO_BALLOON_F_PAGE_REPORTING: u64 = 1 << 5;
}

// ============================================================================
// Balloon Error Types
// ============================================================================

/// Balloon device error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BalloonError {
    /// Device not ready
    NotReady,
    /// I/O error from device
    IoError,
    /// Queue full
    QueueFull,
    /// DMA allocation failed
    AllocFailed,
}
