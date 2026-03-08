// ============================================================================
// drivers/virtio/src/input/mod.rs - Shared VirtIO Input types
// ============================================================================

pub mod config_select {
    /// Unset / no selection
    pub const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
    /// Query device name string (subsel = 0)
    pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
    /// Query device serial string (subsel = 0)
    pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
    /// Query device IDs (subsel = 0)
    pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
    /// Query property bits (subsel = property set)
    pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
    /// Query event type bits (subsel = event type)
    pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
    /// Query absolute axis info (subsel = axis)
    pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;
}

// ============================================================================
// VirtIO Input Event
// ============================================================================

/// A VirtIO input event, matching the Linux `input_event` layout
/// without the timestamp fields.
///
/// This is the data structure exchanged on the eventq between the device
/// and the driver. Each event is 8 bytes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VirtioInputEvent {
    /// Event type (e.g., EV_KEY, EV_REL, EV_ABS)
    pub type_: u16,
    /// Event code (e.g., KEY_A, REL_X)
    pub code: u16,
    /// Event value (e.g., 1 for press, 0 for release)
    pub value: u32,
}

// ============================================================================
// Error Type
// ============================================================================

/// Input device error types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputError {
    /// Device not ready
    NotReady,
    /// I/O error from device
    IoError,
    /// Queue full
    QueueFull,
}

impl core::fmt::Display for InputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            InputError::NotReady => write!(f, "Device not ready"),
            InputError::IoError => write!(f, "I/O error"),
            InputError::QueueFull => write!(f, "Queue full"),
        }
    }
}
