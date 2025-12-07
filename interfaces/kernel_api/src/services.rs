// ============================================================================
// kernel_api/src/services.rs - Kernel Services Trait (Dependency Inversion)
// ============================================================================
//!
//! # Kernel Services Interface
//!
//! This module defines the trait that the kernel must implement.
//! Applications and drivers depend only on this trait, not on kernel internals.

extern crate alloc;

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use crate::error::KapiError;

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
    /// Returns the task ID on success
    fn spawn_task(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Result<u64, KapiError>;

    /// Get current tick count (milliseconds since boot)
    fn current_tick(&self) -> u64;

    /// Get current task ID
    fn current_task_id(&self) -> u64;

    // ========================================================================
    // Memory Management  
    // ========================================================================

    /// Allocate DMA-capable memory
    ///
    /// Returns (physical_address, virtual_address) on success
    fn alloc_dma(&self, size: usize) -> Result<(u64, *mut u8), KapiError>;

    /// Free DMA memory
    fn free_dma(&self, phys_addr: u64, size: usize);

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
    /// Returns endpoint ID on success
    fn net_create_endpoint(&self) -> Result<u64, KapiError>;

    /// Close a TCP endpoint
    fn net_close_endpoint(&self, endpoint_id: u64) -> Result<(), KapiError>;

    // ========================================================================
    // Filesystem
    // ========================================================================

    /// Open a file
    ///
    /// Returns file handle ID on success
    fn fs_open(&self, path: &str, mode: crate::OpenMode) -> Result<u64, KapiError>;

    /// Close a file
    fn fs_close(&self, handle_id: u64) -> Result<(), KapiError>;

    // ========================================================================
    // IPC (Inter-Process Communication)
    // ========================================================================

    /// Create an IPC channel
    ///
    /// Returns (sender_id, receiver_id) on success
    fn ipc_create_channel(&self) -> Result<(u64, u64), KapiError>;

    /// Close an IPC channel endpoint
    fn ipc_close(&self, channel_id: u64) -> Result<(), KapiError>;
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
pub unsafe fn register_kernel(services: &'static dyn KernelServices) {
    KERNEL.call_once(|| services);
}

/// Get the registered kernel services
///
/// # Panics
/// Panics if called before `register_kernel`
#[inline]
pub fn kernel() -> &'static dyn KernelServices {
    *KERNEL.get().expect("Kernel not initialized! Call register_kernel first.")
}

/// Check if kernel is registered
#[inline]
pub fn is_kernel_registered() -> bool {
    KERNEL.get().is_some()
}
