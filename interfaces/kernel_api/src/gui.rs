// ============================================================================
// kernel_api/src/gui.rs - GUI Cell Interface
// ============================================================================
//!
//! # GUI Cell Interface
//!
//! Defines the contract between the kernel and the graphical shell (or other GUI cells).
//!
//! ## Design Principles
//! - **Zero-Copy**: Framebuffer access via direct memory mapping (vaddr).
//! - **Capability-based**: Access requires proof of entitlement (DomainCapabilities).
//! - **Async-Ready**: Input streams are provided via handles for async polling.

use crate::{KapiResult, capability::DomainCapabilities};

/// Pixel format of the framebuffer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    /// 32-bit RGB (8-bit Red, 8-bit Green, 8-bit Blue, 8-bit Reserved)
    Rgb32 = 0,
    /// 32-bit BGR (8-bit Blue, 8-bit Green, 8-bit Red, 8-bit Reserved)
    Bgr32 = 1,
    /// 24-bit RGB
    Rgb24 = 2,
    /// 24-bit BGR
    Bgr24 = 3,
    /// Unknown or other format
    Unknown = 99,
}

/// Framebuffer information for direct access
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct FramebufferInfo {
    /// Width in pixels
    pub width: usize,
    /// Height in pixels
    pub height: usize,
    /// Bytes per line (including padding) - Essential for correct indexing
    pub stride: usize,
    /// Pixel format
    pub format: PixelFormat,
    /// Virtual address of the framebuffer (SAS: valid in all contexts)
    pub vaddr: usize,
    /// Total size in bytes
    pub size: usize,
}

/// Handle for an asynchronous input stream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct InputStreamHandle(pub u64);

// ============================================================================
// Input Event Types (for Cell separation)
// ============================================================================

/// Key state (pressed/released)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyState {
    /// Key was pressed
    Pressed = 0,
    /// Key was released
    Released = 1,
}

/// Simplified key code for GUI events
///
/// This is a cross-crate compatible representation.
/// The kernel translates internal HID key codes to this format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct KeyEvent {
    /// Scancode (raw hardware code)
    pub scancode: u16,
    /// ASCII character if printable (0 if not)
    pub char_value: u8,
    /// Key state
    pub state: KeyState,
    /// Modifier flags (Ctrl, Shift, Alt, etc.)
    pub modifiers: u8,
}

/// Mouse button flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct MouseButtons(pub u8);

impl MouseButtons {
    pub const LEFT: u8 = 0x01;
    pub const RIGHT: u8 = 0x02;
    pub const MIDDLE: u8 = 0x04;

    pub fn left(&self) -> bool {
        self.0 & Self::LEFT != 0
    }
    pub fn right(&self) -> bool {
        self.0 & Self::RIGHT != 0
    }
    pub fn middle(&self) -> bool {
        self.0 & Self::MIDDLE != 0
    }
}

/// Mouse event
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct MouseEvent {
    /// X movement delta
    pub dx: i16,
    /// Y movement delta
    pub dy: i16,
    /// Button state
    pub buttons: MouseButtons,
}

/// Unified input event
#[derive(Debug, Clone, Copy)]
pub enum InputEvent {
    /// Keyboard event
    Key(KeyEvent),
    /// Mouse event
    Mouse(MouseEvent),
}

/// Interface provided by the kernel to GUI cells
pub trait GuiServices: Send + Sync {
    /// Request direct access to the framebuffer
    ///
    /// Requires verification of capabilities (e.g., IO/DMA capabilities).
    ///
    /// # Arguments
    /// * `access_token` - Proof of capability to access hardware/DMA
    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the operation fails.
    fn request_framebuffer(&self, access_token: &DomainCapabilities)
    -> KapiResult<FramebufferInfo>;

    /// Get a handle to the input event stream
    ///
    /// The stream can be polled asynchronously by the client logic.
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required state cannot be read.
    fn get_input_stream_handle(&self) -> KapiResult<InputStreamHandle>;

    /// Get the current system tick count
    ///
    /// Used for timing operations like cursor blinking, animations, etc.
    fn current_tick(&self) -> u64;

    /// Poll for the next input event (keyboard or mouse)
    ///
    /// Returns `None` if no event is pending.
    fn poll_input_event(&self) -> Option<InputEvent>;

    /// Yield control to allow other tasks to run
    ///
    /// This is called at the end of each iteration to cooperatively yield
    /// to the scheduler. The implementation should arrange for the caller
    /// to be resumed later.
    fn yield_control(&self);
}
