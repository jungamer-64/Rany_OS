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

use crate::{KapiResult, security::DomainCapabilities};

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

/// Interface provided by the kernel to GUI cells
pub trait GuiServices: Send + Sync {
    /// Request direct access to the framebuffer
    ///
    /// Requires verification of capabilities (e.g., IO/DMA capabilities).
    ///
    /// # Arguments
    /// * `access_token` - Proof of capability to access hardware/DMA
    fn request_framebuffer(&self, access_token: &DomainCapabilities) -> KapiResult<FramebufferInfo>;

    /// Get a handle to the input event stream
    ///
    /// The stream can be polled asynchronously by the client logic.
    fn get_input_stream_handle(&self) -> KapiResult<InputStreamHandle>;
}
