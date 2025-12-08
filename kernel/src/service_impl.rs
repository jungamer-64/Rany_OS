// ============================================================================
// kernel/src/service_impl.rs - KernelServices Implementation
// ============================================================================
//!
//! # ExoKernel Implementation of KernelServices
//!
//! This module implements the `KernelServices` trait from `kernel_api`,
//! bridging the contract defined in the interface to the kernel's internal
//! implementations.
//!
//! ## Design (設計書準拠)
//! - SPL: Single Privilege Level - all calls are direct function calls
//! - No syscall overhead - just vtable dispatch
//! - Type-safe capability model via traits
//!
//! ## Task Integration
//! Uses `per_core_executor::Task::new_boxed()` to avoid double-boxing
//! when receiving pre-boxed futures from external callers.

#![allow(dead_code)]

use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use kernel_api::error::KapiError;
use kernel_api::services::KernelServices;
use kernel_api::OpenMode;

use crate::task::per_core_executor::{Task, Priority, executor_manager};
use crate::task::timer;
use crate::task::context;
use crate::io::dma;

// ============================================================================
// ExoKernel: The KernelServices Implementation
// ============================================================================

/// ExoKernel - The concrete implementation of KernelServices
///
/// This struct has no fields; all state is managed via static globals
/// within the kernel. This keeps the implementation simple and allows
/// registration as a `&'static dyn KernelServices`.
pub struct ExoKernel;

impl ExoKernel {
    /// Create the singleton instance
    pub const fn new() -> Self {
        ExoKernel
    }
}

// SAFETY: ExoKernel is stateless and accesses thread-safe globals
unsafe impl Send for ExoKernel {}
unsafe impl Sync for ExoKernel {}

impl KernelServices for ExoKernel {
    // ========================================================================
    // Task Management
    // ========================================================================

    fn spawn_task(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Result<u64, KapiError> {
        // Use Task::new_boxed to avoid double-boxing (optimization)
        let task = Task::new_boxed(future, Priority::Normal, None);
        let task_id = task.metadata.id.as_u64();
        
        // Submit to ExecutorManager for load-balanced scheduling
        executor_manager().spawn(task);
        
        Ok(task_id)
    }

    fn current_tick(&self) -> u64 {
        timer::current_tick()
    }

    fn current_task_id(&self) -> u64 {
        context::current_task_id()
    }

    // ========================================================================
    // Memory Management
    // ========================================================================

    fn alloc_dma(&self, size: usize) -> Result<(u64, *mut u8), KapiError> {
        // Use TypedDmaSlice for coherent DMA allocation
        match dma::TypedDmaSlice::new(size) {
            Some(buffer) => {
                let phys = buffer.phys_addr().as_u64();
                // SAFETY: Leak the buffer to keep it alive for DMA use
                // TODO: Implement proper DMA buffer registry for tracking/freeing
                let ptr = Box::into_raw(Box::new(buffer)) as *mut u8;
                Ok((phys, ptr))
            }
            None => Err(KapiError::OutOfMemory),
        }
    }

    fn free_dma(&self, _phys_addr: u64, _size: usize) {
        // TODO: Implement proper DMA buffer tracking and deallocation
        // Current implementation leaks memory (acceptable for now)
    }

    // ========================================================================
    // I/O Operations
    // ========================================================================

    fn port_read_u8(&self, port: u16) -> u8 {
        hal::port_io::PortU8::new(port).read()
    }

    fn port_write_u8(&self, port: u16, value: u8) {
        hal::port_io::PortU8::new(port).write(value)
    }

    // ========================================================================
    // Logging
    // ========================================================================

    fn log(&self, message: &str) {
        crate::log!("{}", message);
    }

    // ========================================================================
    // Network (Stub implementations)
    // ========================================================================

    fn net_create_endpoint(&self) -> Result<u64, KapiError> {
        // TODO: Connect to net/tcp subsystem
        Err(KapiError::NotSupported)
    }

    fn net_close_endpoint(&self, _endpoint_id: u64) -> Result<(), KapiError> {
        Err(KapiError::NotSupported)
    }

    // ========================================================================
    // Filesystem (Stub implementations)
    // ========================================================================

    fn fs_open(&self, _path: &str, _mode: OpenMode) -> Result<u64, KapiError> {
        // TODO: Connect to VFS layer (crate::fs)
        Err(KapiError::NotSupported)
    }

    fn fs_close(&self, _handle_id: u64) -> Result<(), KapiError> {
        Err(KapiError::NotSupported)
    }

    // ========================================================================
    // IPC (Stub implementations)
    // ========================================================================

    fn ipc_create_channel(&self) -> Result<(u64, u64), KapiError> {
        // TODO: Connect to IPC subsystem (crate::ipc)
        Err(KapiError::NotSupported)
    }

    fn ipc_close(&self, _channel_id: u64) -> Result<(), KapiError> {
        Err(KapiError::NotSupported)
    }
}

// ============================================================================
// Global Kernel Instance
// ============================================================================

/// The global ExoKernel instance
static EXOKERNEL: ExoKernel = ExoKernel::new();

/// Register the kernel services (call from kmain early in boot)
///
/// # Safety
/// Must be called exactly once, before any KAPI functions are used.
pub unsafe fn register_kernel_services() {
    kernel_api::register_kernel(&EXOKERNEL);
}

/// Get a reference to the exokernel (for internal use)
pub fn exokernel() -> &'static ExoKernel {
    &EXOKERNEL
}
