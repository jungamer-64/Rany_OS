// ============================================================================
// kernel_api/src/cell_runtime.rs - Standalone Cell Runtime Stubs
// ============================================================================
//!
//! # Cell Runtime
//!
//! Provides runtime stubs for Cells (dynamically loaded drivers/services)
//! when compiled as standalone cdylib. Includes:
//!
//! - Global allocator delegating to kernel's `KernelApiV4` table
//! - Panic handler calling kernel panic abort hook
//! - Logging via kernel API table
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

use crate::abi::driver::{KERNEL_API_SYMBOL, KernelApiV4};
use core::alloc::{GlobalAlloc, Layout};
use core::mem::{align_of, size_of};
use core::ptr;

// ============================================================================
// External Kernel API Symbol
// ============================================================================
//
// This symbol is provided by the kernel and resolved at load time by the ELF
// loader via the symbol table.

unsafe extern "C" {
    static __exorust_kernel_api_v4: KernelApiV4;
}

#[inline]
fn kernel_api() -> &'static KernelApiV4 {
    // SAFETY: The kernel always exports this symbol before loading standalone
    // cells, and the table is immutable after publication.
    unsafe { &__exorust_kernel_api_v4 }
}

#[inline]
fn has_runtime_entries(api: &KernelApiV4) -> bool {
    (api.abi_size as usize) >= core::mem::size_of::<KernelApiV4>()
}

#[inline]
fn call_heap_alloc(size: usize) -> *mut u8 {
    let api = kernel_api();
    if !has_runtime_entries(api) {
        return ptr::null_mut();
    }
    api.heap_alloc.map_or(ptr::null_mut(), |f| f(size))
}

#[inline]
fn call_heap_dealloc(ptr: *mut u8, size: usize) {
    let api = kernel_api();
    if !has_runtime_entries(api) {
        return;
    }
    if let Some(f) = api.heap_dealloc {
        f(ptr, size);
    }
}

#[inline]
fn call_log(msg: &[u8]) {
    if msg.is_empty() {
        return;
    }
    let api = kernel_api();
    (api.log)(0, msg.as_ptr(), msg.len());
}

#[inline]
fn call_panic_abort(msg: &[u8]) -> ! {
    let api = kernel_api();
    if has_runtime_entries(api) && let Some(panic_abort) = api.panic_abort {
        panic_abort(msg.as_ptr(), msg.len());
    }
    panic!("Kernel API panic entry missing ({KERNEL_API_SYMBOL})");
}

// ============================================================================
// Global Allocator for Standalone Cells
// ============================================================================

/// Kernel-backed allocator for standalone Cells
///
/// Delegates all allocations to the kernel via `KernelApiV4`.
/// This is only used when the Cell is loaded as a standalone cdylib;
/// when statically linked with the kernel, the kernel's allocator is used.
pub struct KernelAllocator;

#[repr(C)]
struct AllocHeader {
    base_ptr: *mut u8,
    alloc_size: usize,
}

impl KernelAllocator {
    fn header_layout_values(layout: Layout) -> Option<(usize, usize, usize)> {
        let payload_size = layout.size().max(1);
        let align = layout.align().max(align_of::<AllocHeader>());
        let header_size = size_of::<AllocHeader>();
        let total_size = payload_size.checked_add(align)?.checked_add(header_size)?;
        Some((payload_size, align, total_size))
    }

    unsafe fn alloc_with_header(layout: Layout) -> *mut u8 {
        let (_, align, total_size) = match Self::header_layout_values(layout) {
            Some(v) => v,
            None => return ptr::null_mut(),
        };

        let base = call_heap_alloc(total_size);
        if base.is_null() {
            return ptr::null_mut();
        }

        let start = unsafe { base.add(size_of::<AllocHeader>()) } as usize;
        let aligned = (start + (align - 1)) & !(align - 1);
        let header_ptr_u8 = (aligned - size_of::<AllocHeader>()) as *mut u8;

        unsafe {
            // Use unaligned write to avoid assuming pointer alignment for static analysis.
            ptr::write_unaligned(
                header_ptr_u8 as *mut AllocHeader,
                AllocHeader {
                    base_ptr: base,
                    alloc_size: total_size,
                },
            );
        }

        aligned as *mut u8
    }

    unsafe fn read_header(ptr: *mut u8) -> AllocHeader {
        let header_ptr_u8 = unsafe { ptr.sub(size_of::<AllocHeader>()) } as *const u8;
        // Use unaligned read to avoid strict alignment assumptions caught by clippy
        unsafe { ptr::read_unaligned(header_ptr_u8 as *const AllocHeader) }
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { Self::alloc_with_header(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let _ = layout;
        if ptr.is_null() {
            return;
        }
        let header = unsafe { Self::read_header(ptr) };
        call_heap_dealloc(header.base_ptr, header.alloc_size);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe {
            let ptr = self.alloc(layout);
            if !ptr.is_null() {
                core::ptr::write_bytes(ptr, 0, layout.size().max(1));
            }
            ptr
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if new_size == 0 {
            unsafe { self.dealloc(ptr, layout) };
            return ptr::null_mut();
        }

        // Simple realloc: allocate new, copy, deallocate old
        let new_layout = match Layout::from_size_align(new_size, layout.align()) {
            Ok(l) => l,
            Err(_) => return ptr::null_mut(),
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
        $crate::register_cell_runtime!(dependencies: []);
    };

    (dependencies: [$($dep:expr),* $(,)?] $(,)?) => {
        #[cfg(target_os = "none")]
        $crate::declare_rany_type_id_section!(
            $crate::__type_id::MEMORY_ALLOCATOR_INTERFACE,
            $crate::__type_id::TASK_SCHEDULER_INTERFACE,
            $crate::__type_id::IPC_INTERFACE,
            $crate::__type_id::KERNEL_API_INTERFACE
            $(, $dep)*
        );

        #[cfg(target_os = "none")]
        #[global_allocator]
        static CELL_ALLOCATOR: $crate::cell_runtime::KernelAllocator =
            $crate::cell_runtime::KernelAllocator;

        #[cfg(target_os = "none")]
        #[panic_handler]
        fn _cell_panic_handler(info: &core::panic::PanicInfo) -> ! {
            // Format panic message (limited, no_std)
            match info.location() {
                Some(loc) => $crate::cell_runtime::log_panic(loc.file(), loc.line()),
                None => $crate::cell_runtime::log_panic("unknown", 0),
            }
            $crate::cell_runtime::panic_abort()
        }
    };
}

/// Log panic information to kernel
pub fn log_panic(file: &str, line: u32) {
    // Build a simple panic message
    let _ = line;
    let prefix = b"Cell panic at ";
    let suffix = b"\n";

    call_log(prefix);
    call_log(file.as_bytes());
    // For line number, we'd need to format - skip for simplicity
    call_log(suffix);
}

/// Abort after panic - never returns
pub fn panic_abort() -> ! {
    let msg = b"Cell panic - aborting";
    call_panic_abort(msg)
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
    call_log(msg.as_bytes());
}
