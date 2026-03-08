// ============================================================================
// drivers/virtio/src/console/mod.rs - Shared VirtIO Console types
// ============================================================================

pub mod device;

/// VirtIO feature bits for console devices
pub mod features {
    /// Console size (cols, rows) is available in config space
    pub const VIRTIO_CONSOLE_F_SIZE: u64 = 1 << 0;
    /// Device supports multiple ports
    pub const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;
    /// Device supports emergency write
    pub const VIRTIO_CONSOLE_F_EMERG_WRITE: u64 = 1 << 2;
}

// ============================================================================
// Console Configuration
// ============================================================================

/// VirtIO console device configuration (from device config space)
#[derive(Clone, Debug)]
pub struct VirtioConsoleConfig {
    /// Console width in columns (valid if VIRTIO_CONSOLE_F_SIZE is negotiated)
    pub cols: u16,
    /// Console height in rows (valid if VIRTIO_CONSOLE_F_SIZE is negotiated)
    pub rows: u16,
    /// Maximum number of ports (valid if VIRTIO_CONSOLE_F_MULTIPORT is negotiated)
    pub max_nr_ports: u32,
}

impl Default for VirtioConsoleConfig {
    fn default() -> Self {
        Self {
            cols: 80,
            rows: 24,
            max_nr_ports: 1,
        }
    }
}

// ============================================================================
// Console Error Types
// ============================================================================

/// Console device error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleError {
    /// Device not ready
    NotReady,
    /// I/O error from device
    IoError,
    /// Queue full
    QueueFull,
    /// Unsupported operation
    Unsupported,
}
