// ============================================================================
// kernel_api/src/cell_runtime.rs - Standalone Cell Runtime Stubs
// ============================================================================
//!
//! # Cell Runtime
//!
//! Provides runtime stubs for Cells (dynamically loaded drivers/services)
//! when compiled as standalone cdylib. Includes:
//!
//! - Global allocator delegating to kernel's `sys_alloc`/`sys_dealloc`
//! - Panic handler calling kernel's `sys_panic`
//! - Logging via `sys_log`
//!
//! ## Usage
//!
//! Enable the `standalone` feature in your Cell's Cargo.toml:
//!
//! ```toml
//! [features]
//! standalone = ["kernel_api/cell_runtime"]
//! ```
//!
//! The runtime stubs will automatically be linked when building as cdylib.

#![allow(dead_code)]

use core::alloc::{GlobalAlloc, Layout};

// ============================================================================
// External Kernel Syscalls
// ============================================================================
//
// These symbols are provided by the kernel and resolved at load time
// by the ELF loader via the symbol table.

unsafe extern "C" {
    /// Allocate memory from kernel heap
    ///
    /// # Arguments
    /// * `size` - Size in bytes to allocate
    ///
    /// # Returns
    /// Pointer to allocated memory, or null on failure
    fn sys_alloc(size: usize) -> *mut u8;

    /// Deallocate memory to kernel heap
    ///
    /// # Arguments
    /// * `ptr` - Pointer previously returned by sys_alloc
    /// * `size` - Original allocation size
    fn sys_dealloc(ptr: *mut u8, size: usize);

    /// Log a message to kernel log
    ///
    /// # Arguments
    /// * `msg` - Pointer to UTF-8 message bytes
    /// * `len` - Length of message in bytes
    fn sys_log(msg: *const u8, len: usize);

    /// Panic handler - does not return
    fn sys_panic(msg: *const u8, len: usize) -> !;
}

// ============================================================================
// Global Allocator for Standalone Cells
// ============================================================================

/// Kernel-backed allocator for standalone Cells
///
/// Delegates all allocations to the kernel via `sys_alloc`/`sys_dealloc`.
/// This is only used when the Cell is loaded as a standalone cdylib;
/// when statically linked with the kernel, the kernel's allocator is used.
pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // Ensure minimum alignment
        let size = layout.size().max(layout.align());
        unsafe { sys_alloc(size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let size = layout.size().max(layout.align());
        unsafe { sys_dealloc(ptr, size) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let ptr = self.alloc(layout);
            if !ptr.is_null() {
                core::ptr::write_bytes(ptr, 0, layout.size());
            }
            ptr
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // Simple realloc: allocate new, copy, deallocate old
        let new_layout = match Layout::from_size_align(new_size, layout.align()) {
            Ok(l) => l,
            Err(_) => return core::ptr::null_mut(),
        };

        unsafe {
            let new_ptr = self.alloc(new_layout);
            if !new_ptr.is_null() {
                let copy_size = layout.size().min(new_size);
                core::ptr::copy_nonoverlapping(ptr, new_ptr, copy_size);
                self.dealloc(ptr, layout);
            }
            new_ptr
        }
    }
}

// ============================================================================
// Conditional Global Allocator Registration
// ============================================================================

/// Register global allocator when `cell_runtime` feature is enabled
///
/// This macro must be called at the crate root of standalone Cells.
#[macro_export]
#[cfg(feature = "cell_runtime")]
macro_rules! register_cell_runtime {
    () => {
        #[global_allocator]
        static CELL_ALLOCATOR: $crate::cell_runtime::KernelAllocator =
            $crate::cell_runtime::KernelAllocator;

        #[panic_handler]
        fn _cell_panic_handler(info: &core::panic::PanicInfo) -> ! {
            // Format panic message (limited, no_std)
            let msg = match info.location() {
                Some(loc) => {
                    // Can't use format! in no_std panic handler easily
                    // Just log a generic message with file info
                    $crate::cell_runtime::log_panic(loc.file(), loc.line());
                }
                None => {
                    $crate::cell_runtime::log_panic("unknown", 0);
                }
            };
            $crate::cell_runtime::panic_abort()
        }
    };
}

/// Log panic information to kernel
pub fn log_panic(file: &str, line: u32) {
    // Build a simple panic message
    let prefix = b"Cell panic at ";
    let suffix = b"\n";

    unsafe {
        sys_log(prefix.as_ptr(), prefix.len());
        sys_log(file.as_ptr(), file.len());
        // For line number, we'd need to format - skip for simplicity
        sys_log(suffix.as_ptr(), suffix.len());
    }
}

/// Abort after panic - never returns
pub fn panic_abort() -> ! {
    let msg = b"Cell panic - aborting";
    unsafe { sys_panic(msg.as_ptr(), msg.len()) }
}

// ============================================================================
// Logging Helper
// ============================================================================

/// Log a message to kernel console
///
/// # Example
/// ```rust
/// kernel_api::cell_runtime::log("NVMe Cell initialized");
/// ```
pub fn log(msg: &str) {
    unsafe {
        sys_log(msg.as_ptr(), msg.len());
    }
}
