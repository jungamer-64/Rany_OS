// ============================================================================
// kernel_api/src/driver_abi.rs - Stable Driver ABI for Dynamic Loading
// ============================================================================
//!
//! # Stable Driver ABI
//!
//! This module defines a C-compatible, ABI-stable interface for dynamically
//! loaded drivers. Unlike Rust's `dyn Trait` which has unstable vtable layouts,
//! this uses `#[repr(C)]` to ensure binary compatibility across:
//!
//! - Different compiler versions
//! - Different build configurations
//! - Separately compiled driver binaries
//!
//! ## Usage
//!
//! Drivers export a symbol `_exorust_driver_entry` that returns a pointer
//! to a static `DriverVTable`. The kernel loads this symbol and uses the
//! vtable to call driver functions.
//!
//! ## ABI Stability Guidelines
//!
//! To maintain the validity of the text-based ABI hash verification in `build.rs`,
//! all ABI-critical structs (e.g., `DriverContext`, `DriverVTable`) MUST adhere to these rules:
//!
//! 1.  **Primitives Only**: Use only primitive types (`u64`, `u32`, `*mut T`, etc.) or types defined within this file.
//! 2.  **No External Types**: Do not produce fields using `type` aliases or structs defined in other modules.
//! 3.  **Self-Contained**: Ensure all types used in function signatures `extern "C"` are defined in this file.
//!
//! Violated this rule may cause the ABI hash to remain unchanged even when the memory layout changes,
//! leading to undefined behavior during driver loading.
//!
//! ## Safety
//!
//! All functions in the vtable use `extern "C"` calling convention and
//! only pass C-compatible types across the ABI boundary.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export_driver;

    fn test_probe(_ctx: &mut DriverContext) -> i32 {
        0
    }
    fn test_remove(_ctx: &mut DriverContext) -> i32 {
        0
    }
    fn test_start(_ctx: &mut DriverContext) -> i32 {
        123
    }
    fn test_name() -> &'static str {
        "testdrv"
    }
    fn test_irq(_ctx: &mut DriverContext) -> bool {
        true
    }

    export_driver!(
        probe: test_probe,
        remove: test_remove,
        name: test_name,
        driver_type: (AbiDriverType::Unknown as u32),
        version: 0,
        start: test_start,
        irq: test_irq
    );

    #[test]
    fn vtable_has_expected_values() {
        let entry: DriverEntryFn = _exorust_driver_entry;
        let vtbl_ptr = entry();
        assert!(!vtbl_ptr.is_null());
        let v = unsafe { &*vtbl_ptr };

        assert_eq!(v.abi_version, DRIVER_ABI_VERSION);
        assert_eq!(v.type_hash, DRIVER_TYPE_HASH);

        let mut ctx = DriverContext::new();
        let res_start = (v.start)(&mut ctx as *mut _);
        assert_eq!(res_start, 123);

        let res_stop = (v.stop)(&mut ctx as *mut _);
        assert_eq!(res_stop, 0);

        assert!(v.handle_irq.is_some());
        let irq_fn = v.handle_irq.unwrap();
        assert!(irq_fn(&mut ctx as *mut _));

        let name_ptr = (v.name)();
        let name_len = (v.name_len)();
        let name_slice = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
        assert_eq!(name_slice, b"testdrv");
    }
}

// ============================================================================
// ABI Version
// ============================================================================

/// Current ABI version for compatibility checking.
///
/// Increment this when making breaking changes to the vtable layout.
/// Drivers compiled with a different ABI version will be rejected.
/// Current ABI version for compatibility checking.
///
/// Increment this when making breaking changes to the vtable layout.
/// Drivers compiled with a different ABI version will be rejected.
pub const DRIVER_ABI_VERSION: u64 = 1;

// Include the generated type hash
include!(concat!(env!("OUT_DIR"), "/abi_hash.rs"));

/// The symbol name that all dynamically loadable drivers must export.
pub const DRIVER_ENTRY_SYMBOL: &str = "_exorust_driver_entry";

// ============================================================================
// Error Codes
// ============================================================================

/// ABI-stable error codes returned by driver functions.
///
/// These are C-compatible integers for cross-boundary safety.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiError {
    /// Success (no error)
    Success = 0,
    /// Generic error
    Error = -1,
    /// Device not found
    DeviceNotFound = -2,
    /// Device busy
    DeviceBusy = -3,
    /// Invalid parameter
    InvalidParam = -4,
    /// Out of memory
    OutOfMemory = -5,
    /// Not supported
    NotSupported = -6,
    /// Timeout
    Timeout = -7,
    /// I/O error
    IoError = -8,
    /// Permission denied
    PermissionDenied = -9,
    /// Already initialized
    AlreadyInitialized = -10,
    /// Not initialized
    NotInitialized = -11,
}

impl AbiError {
    /// Convert from raw i32 to AbiError
    pub fn from_raw(code: i32) -> Self {
        match code {
            0 => AbiError::Success,
            -2 => AbiError::DeviceNotFound,
            -3 => AbiError::DeviceBusy,
            -4 => AbiError::InvalidParam,
            -5 => AbiError::OutOfMemory,
            -6 => AbiError::NotSupported,
            -7 => AbiError::Timeout,
            -8 => AbiError::IoError,
            -9 => AbiError::PermissionDenied,
            -10 => AbiError::AlreadyInitialized,
            -11 => AbiError::NotInitialized,
            _ => AbiError::Error,
        }
    }

    /// Check if this represents success
    pub fn is_success(self) -> bool {
        self == AbiError::Success
    }
}

// ============================================================================
// Driver Types (ABI-stable)
// ============================================================================

/// ABI-stable driver type enumeration.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbiDriverType {
    /// Unknown/unspecified
    Unknown = 0,
    /// PCI device driver
    Pci = 1,
    /// USB device driver
    Usb = 2,
    /// Block device (storage)
    Block = 3,
    /// Network device
    Network = 4,
    /// HID (keyboard, mouse, etc.)
    Hid = 5,
    /// Graphics
    Graphics = 6,
    /// Serial/UART
    Serial = 7,
    /// Platform device
    Platform = 8,
}

// ============================================================================
// Driver Context
// ============================================================================

/// Context passed to driver functions.
///
/// This contains device-specific information needed by the driver.
/// The kernel populates this before calling probe().
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DriverContext {
    /// Base address of device memory (BAR0 for PCI, MMIO base, etc.)
    pub device_address: u64,
    /// Secondary device address (BAR1, etc.) or 0 if unused
    pub device_address_secondary: u64,
    /// Interrupt number (IRQ)
    pub irq: u32,
    /// Driver-specific flags
    pub flags: u32,
    /// PCI Vendor ID (if applicable)
    pub vendor_id: u16,
    /// PCI Device ID (if applicable)
    pub device_id: u16,
    /// PCI Class code (if applicable)
    pub class_code: u32,
    /// Driver-specific data pointer (used to store Box<Driver> raw pointer)
    pub driver_data: u64,
    /// Reserved for future use
    pub _reserved: [u64; 3],
}

impl DriverContext {
    /// Create a new empty context
    pub const fn new() -> Self {
        Self {
            device_address: 0,
            device_address_secondary: 0,
            irq: 0,
            flags: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            driver_data: 0,
            _reserved: [0; 3],
        }
    }

    /// Create context for a PCI device
    pub const fn for_pci(
        bar0: u64,
        irq: u32,
        vendor_id: u16,
        device_id: u16,
        class_code: u32,
    ) -> Self {
        Self {
            device_address: bar0,
            device_address_secondary: 0,
            irq,
            flags: 0,
            vendor_id,
            device_id,
            class_code,
            driver_data: 0,
            _reserved: [0; 3],
        }
    }
}

impl Default for DriverContext {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Driver Capabilities Request
// ============================================================================

/// Capabilities that a driver can request during probe.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DriverCapabilities {
    /// Request DMA capability
    pub needs_dma: bool,
    /// Request interrupt capability
    pub needs_irq: bool,
    /// Request I/O port access
    pub needs_io_ports: bool,
    /// Request MMIO access
    pub needs_mmio: bool,
    /// Padding for alignment
    _padding: [u8; 4],
}

// ============================================================================
// Driver VTable
// ============================================================================

/// The ABI-stable virtual function table for drivers.
///
/// This is the core interface between the kernel and dynamically loaded drivers.
/// All function pointers use `extern "C"` calling convention.
#[repr(C)]
pub struct DriverVTable {
    /// ABI version - MUST be first field for compatibility checking
    pub abi_version: u64,

    /// Type definition hash for ensuring layout compatibility
    pub type_hash: u64,

    /// Initialize and probe the device.
    pub probe: extern "C" fn(ctx: *mut DriverContext) -> i32,

    /// Start the driver after successful probe.
    ///
    /// # Asynchronous / Non-blocking Requirement
    ///
    /// This function MUST be non-blocking. It should only initiate the startup sequence
    /// (e.g., enabling interrupts, spawning a background task) and return immediately.
    ///
    /// If long-running initialization is required, it must be performed asynchronously.
    /// Blocking this function will stall the kernel executor.
    pub start: extern "C" fn(ctx: *mut DriverContext) -> i32,

    /// Stop the driver.
    pub stop: extern "C" fn(ctx: *mut DriverContext) -> i32,

    /// Remove/unload the driver.
    pub remove: extern "C" fn(ctx: *mut DriverContext) -> i32,

    /// Get driver name as a null-terminated C string.
    pub name: extern "C" fn() -> *const u8,

    /// Get driver name length (not including null terminator).
    pub name_len: extern "C" fn() -> usize,

    /// Get driver type.
    pub driver_type: extern "C" fn() -> u32,

    /// Get driver version as packed u64: (major << 32) | (minor << 16) | patch
    pub version: extern "C" fn() -> u64,

    /// Request capabilities needed by this driver (optional).
    pub request_capabilities: Option<extern "C" fn(caps: *mut DriverCapabilities)>,

    /// Handle interrupt (optional).
    pub handle_irq: Option<extern "C" fn(ctx: *mut DriverContext) -> bool>,

    /// Reserved for future expansion
    pub _reserved: [u64; 7],
}

impl DriverVTable {
    /// Validate that this vtable is compatible with the current ABI version.
    pub fn validate(&self) -> Result<(), AbiError> {
        if self.abi_version != DRIVER_ABI_VERSION {
            return Err(AbiError::NotSupported);
        }
        if self.type_hash != DRIVER_TYPE_HASH {
            return Err(AbiError::InvalidParam); // Or specific mismatch error
        }
        Ok(())
    }

    /// Construct a `DriverVTable` for a driver.
    ///
    /// This function is `pub` and `const` so other crates (drivers) can invoke it
    /// to create their static vtables without accessing private fields.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        abi_version: u64,
        probe: extern "C" fn(ctx: *mut DriverContext) -> i32,
        start: extern "C" fn(ctx: *mut DriverContext) -> i32,
        stop: extern "C" fn(ctx: *mut DriverContext) -> i32,
        remove: extern "C" fn(ctx: *mut DriverContext) -> i32,
        name: extern "C" fn() -> *const u8,
        name_len: extern "C" fn() -> usize,
        driver_type: extern "C" fn() -> u32,
        version: extern "C" fn() -> u64,
        request_capabilities: Option<extern "C" fn(caps: *mut DriverCapabilities)>,
        handle_irq: Option<extern "C" fn(ctx: *mut DriverContext) -> bool>,
    ) -> Self {
        Self {
            abi_version,
            type_hash: DRIVER_TYPE_HASH,
            probe,
            start,
            stop,
            remove,
            name,
            name_len,
            driver_type,
            version,
            request_capabilities,
            handle_irq,
            _reserved: [0; 7],
        }
    }
}

// ============================================================================
// Driver Entry Point
// ============================================================================

/// The type of the driver entry point function.
///
/// Every dynamically loadable driver must export a function with this signature
/// named `_exorust_driver_entry`. The function returns a pointer to a static
/// `DriverVTable`.
pub type DriverEntryFn = extern "C" fn() -> *const DriverVTable;

// ============================================================================
// Helper Functions
// ============================================================================

/// Helper to pack a version tuple into a u64.
#[inline]
#[must_use]
pub const fn pack_version(major: u16, minor: u16, patch: u16) -> u64 {
    ((major as u64) << 32) | ((minor as u64) << 16) | (patch as u64)
}

/// Helper to unpack a u64 version into (major, minor, patch).
#[inline]
#[must_use]
pub const fn unpack_version(packed: u64) -> (u16, u16, u16) {
    let major = ((packed >> 32) & 0xFFFF) as u16;
    let minor = ((packed >> 16) & 0xFFFF) as u16;
    let patch = (packed & 0xFFFF) as u16;
    (major, minor, patch)
}

// ============================================================================
// Exported Macro for drivers
// ============================================================================
/// Export a C-compatible `DriverVTable` from a driver crate.
///
/// Example:
/// ```rust
/// export_driver!(
///     probe: crate::probe_fn,
///     remove: crate::remove_fn,
///     name: crate::driver_name,
///     driver_type: (crate::driver::DriverType::Block as u32),
///     version: 0x00010000_00010000, // optional packed version field
/// );
/// ```
///
/// Optional arguments supported:
/// - `start: my_start_fn` — called after a successful `probe` to start the device
/// - `stop: my_stop_fn` — called to stop the device
/// - `irq: my_irq_fn` — optional IRQ handler; included in the vtable when provided
///
/// Example with optional handlers:
/// ```rust
/// export_driver!(
///     probe: my_probe,
///     remove: my_remove,
///     name: my_name,
///     driver_type: (crate::driver::DriverType::Pci as u32),
///     version: 1,
///     start: my_start,
///     irq: my_irq_handler,
/// );
/// ```
#[macro_export]
macro_rules! export_driver {
    // Internal implementation entrypoint that receives explicit Option values
    // Implementation when an IRQ handler is provided
    (@impl
        probe = $probe:expr,
        remove = $remove:expr,
        name = $name:expr,
        driver_type = $driver_type:expr,
        version = $version:expr
        $(, start = $start:path)?
        $(, stop = $stop:path)?
        , irq = $irq:path
    ) => {
            #[cfg(any(feature = "export_driver_entry", test))]
            #[unsafe(export_name = "_exorust_driver_entry")]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::driver_abi::DriverVTable {
            // --- Mandatory Adapters ---
            extern "C" fn probe_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                // SAFETY: The kernel guarantees ctx is valid when calling probe
                let ctx_safe = unsafe { &mut *ctx };
                ($probe)(ctx_safe)
            }
            extern "C" fn remove_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                ($remove)(ctx_safe)
            }
            extern "C" fn name_adapter() -> *const u8 {
                ($name)().as_ptr()
            }
            extern "C" fn name_len_adapter() -> usize {
                ($name)().len()
            }
            extern "C" fn type_adapter() -> u32 {
                ($driver_type) as u32
            }
            extern "C" fn version_adapter() -> u64 {
                $version as u64
            }

            // --- Optional Adapters (start/stop) ---
            extern "C" fn start_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($start)(ctx_safe); )?
                rv
            }
            extern "C" fn stop_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($stop)(ctx_safe); )?
                rv
            }

            // IRQ adapter that wraps the user's IRQ handler
            extern "C" fn irq_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> bool {
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                ($irq)(ctx_safe)
            }

            static VTABLE: $crate::driver_abi::DriverVTable = $crate::driver_abi::DriverVTable::new(
                $crate::driver_abi::DRIVER_ABI_VERSION,
                probe_adapter,
                start_adapter,
                stop_adapter,
                remove_adapter,
                name_adapter,
                name_len_adapter,
                type_adapter,
                version_adapter,
                None,
                Some(irq_adapter),
            );

            &VTABLE
        }
    };

    // Implementation when no IRQ handler is provided
    (@impl
        probe = $probe:expr,
        remove = $remove:expr,
        name = $name:expr,
        driver_type = $driver_type:expr,
        version = $version:expr
        $(, start = $start:path)?
        $(, stop = $stop:path)?
    ) => {
        #[cfg(any(feature = "export_driver_entry", test))]
        #[unsafe(export_name = "_exorust_driver_entry")]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::driver_abi::DriverVTable {
            // --- Mandatory Adapters ---
            extern "C" fn probe_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                ($probe)(ctx_safe)
            }
            extern "C" fn remove_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                ($remove)(ctx_safe)
            }
            extern "C" fn name_adapter() -> *const u8 {
                ($name)().as_ptr()
            }
            extern "C" fn name_len_adapter() -> usize {
                ($name)().len()
            }
            extern "C" fn type_adapter() -> u32 {
                ($driver_type) as u32
            }
            extern "C" fn version_adapter() -> u64 {
                $version as u64
            }

            // --- Optional Adapters (start/stop) ---
            extern "C" fn start_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($start)(ctx_safe); )?
                rv
            }
            extern "C" fn stop_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($stop)(ctx_safe); )?
                rv
            }

            static VTABLE: $crate::driver_abi::DriverVTable = $crate::driver_abi::DriverVTable::new(
                $crate::driver_abi::DRIVER_ABI_VERSION,
                probe_adapter,
                start_adapter,
                stop_adapter,
                remove_adapter,
                name_adapter,
                name_len_adapter,
                type_adapter,
                version_adapter,
                None,
                None,
            );

            &VTABLE
        }
    };

    // Public entry point - parses named arguments and builds Option values for optional fields
    (
        probe: $probe:path,
        remove: $remove:path,
        name: $name:path,
        driver_type: $driver_type:expr,
        version: $version:expr
        $(, start: $start:path)? // Optional start
        $(, stop: $stop:path)?   // Optional stop
        $(, irq: $irq:path)?     // Optional irq
    ) => {
        $crate::export_driver!(@impl
            probe = $probe,
            remove = $remove,
            name = $name,
            driver_type = $driver_type,
            version = $version
            $(, start = $start)?
            $(, stop = $stop)?
            $(, irq = $irq)?
        );
    };
}

/// Export an `AsyncDriver` implementation as a C-compatible `DriverVTable`.
#[macro_export]
macro_rules! export_async_driver {
    // Entry point: parse args and delegate to @impl
    (
        type: $driver_type:ty,
        constructor: $constructor:expr,
        name: $name:expr,
        driver_type: $dtype:expr,
        version: $version:expr
        $(, irq: $irq:path)?
    ) => {
        $crate::export_async_driver!(@impl
            type = $driver_type,
            constructor = $constructor,
            name = $name,
            driver_type = $dtype,
            version = $version
            $(, irq = $irq)?
        );
    };

    // Impl with IRQ
    (@impl
        type = $driver_type:ty,
        constructor = $constructor:expr,
        name = $name:expr,
        driver_type = $dtype:expr,
        version = $version:expr,
        irq = $irq:path
    ) => {
        #[cfg(any(feature = "export_driver_entry", test))]
        #[unsafe(export_name = "_exorust_driver_entry")]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::driver_abi::DriverVTable {
            $crate::export_async_driver!(@common_adapters
                type = $driver_type,
                constructor = $constructor,
                name = $name,
                driver_type = $dtype,
                version = $version
            );

            // IRQ Adapter
            extern "C" fn irq_adapter(ctx: *mut $crate::driver_abi::DriverContext) -> bool {
                let ctx_safe = unsafe { &mut *ctx };
                let driver_ptr = ctx_safe.driver_data as *mut $crate::driver_abi::AsyncDriverWrapper<$driver_type>;
                if driver_ptr.is_null() { return false; }
                let wrapper = unsafe { &mut *driver_ptr };
                // Optional: Check busy? IRQs usually are high priority.
                // Assuming IRQ handler is safe to run concurrent with async task logic
                // OR implementation must handle it.
                // However, safe bet: access wrapper.driver
                ($irq)(&mut wrapper.driver)
            }

            static VTABLE: $crate::driver_abi::DriverVTable = $crate::driver_abi::DriverVTable::new(
                $crate::driver_abi::DRIVER_ABI_VERSION,
                probe_adapter,
                start_adapter,
                stop_adapter,
                remove_adapter,
                name_adapter,
                name_len_adapter,
                type_adapter,
                version_adapter,
                None,
                Some(irq_adapter),
            );
            &VTABLE
        }
    };

    // Impl without IRQ
    (@impl
        type = $driver_type:ty,
        constructor = $constructor:expr,
        name = $name:expr,
        driver_type = $dtype:expr,
        version = $version:expr
    ) => {
        #[cfg(any(feature = "export_driver_entry", test))]
        #[unsafe(export_name = "_exorust_driver_entry")]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::driver_abi::DriverVTable {
             $crate::export_async_driver!(@common_adapters
                type = $driver_type,
                constructor = $constructor,
                name = $name,
                driver_type = $dtype,
                version = $version
            );

            static VTABLE: $crate::driver_abi::DriverVTable = $crate::driver_abi::DriverVTable::new(
                $crate::driver_abi::DRIVER_ABI_VERSION,
                probe_adapter,
                start_adapter,
                stop_adapter,
                remove_adapter,
                name_adapter,
                name_len_adapter,
                type_adapter,
                version_adapter,
                None,
                None,
            );
            &VTABLE
        }
    };

    // Common adapters generation
    (@common_adapters
        type = $driver_type:ty,
        constructor = $constructor:expr,
        name = $name:expr,
        driver_type = $dtype:expr,
        version = $version:expr
    ) => {
            use $crate::driver::{AsyncDriver, DriverType};
            use $crate::driver_abi::{DriverContext, DriverVTable, DRIVER_ABI_VERSION, AsyncDriverWrapper};
            use $crate::services::kernel;
            use alloc::boxed::Box;
            use core::sync::atomic::Ordering;

            extern "C" fn probe_adapter(ctx: *mut DriverContext) -> i32 {
                let ctx_safe = unsafe { &mut *ctx };

                // 1. Create the driver instance wrapped
                let driver = Box::new(AsyncDriverWrapper::new($constructor));
                let driver_ptr = Box::into_raw(driver);
                ctx_safe.driver_data = driver_ptr as u64;

                // 2. Spawn async probe
                let future = async move {
                    let wrapper = unsafe { &mut *driver_ptr };
                    let ctx_ref = unsafe { &mut *ctx };

                    // Mark busy
                    if wrapper.busy.swap(true, Ordering::Acquire) {
                        kernel().log("Async probe blocked: Driver busy");
                        return;
                    }

                    if let Err(_) = wrapper.driver.probe(ctx_ref).await {
                         // TODO: Proper error handling
                         kernel().log("Async probe failed");
                    }

                    // Release busy
                    wrapper.busy.store(false, Ordering::Release);
                };

                match kernel().spawn_task(Box::pin(future)) {
                    Ok(_) => 0,
                    Err(_) => -1,
                }
            }

            extern "C" fn start_adapter(ctx: *mut DriverContext) -> i32 {
                let ctx_safe = unsafe { &mut *ctx };
                let driver_ptr = ctx_safe.driver_data as *mut AsyncDriverWrapper<$driver_type>;
                if driver_ptr.is_null() { return -1; }

                // Check busy synchronously first (optimization)
                // CAUTION: Determining busy here is racy versus the task starting.
                // However, if we return -3 (DeviceBusy) synchronously, the kernel knows.
                // But the busy flag is set IN the task in probe_adapter.
                // So if we check here, we might miss it.
                // Ideally, we should set busy HERE?
                // If we set busy here, we own the state.
                let wrapper_ref = unsafe { &*driver_ptr };
                if wrapper_ref.busy.swap(true, Ordering::Acquire) {
                    return -3; // DeviceBusy
                }

                // We own the busy lock now. Pass it to task.
                let future = async move {
                    let wrapper = unsafe { &mut *driver_ptr };
                    let _ = wrapper.driver.start().await;
                    wrapper.busy.store(false, Ordering::Release);
                };

                // If spawn fails, we must release lock!
                match kernel().spawn_task(Box::pin(future)) {
                    Ok(_) => 0,
                    Err(_) => {
                        unsafe { (*driver_ptr).busy.store(false, Ordering::Release); }
                        -1
                    }
                }
            }

            extern "C" fn stop_adapter(ctx: *mut DriverContext) -> i32 {
                let ctx_safe = unsafe { &mut *ctx };
                let driver_ptr = ctx_safe.driver_data as *mut AsyncDriverWrapper<$driver_type>;
                if driver_ptr.is_null() { return 0; }

                let wrapper_ref = unsafe { &*driver_ptr };
                if wrapper_ref.busy.swap(true, Ordering::Acquire) {
                    return -3; // DeviceBusy
                }

                let future = async move {
                    let wrapper = unsafe { &mut *driver_ptr };
                    let _ = wrapper.driver.stop().await;
                    wrapper.busy.store(false, Ordering::Release);
                };

                match kernel().spawn_task(Box::pin(future)) {
                    Ok(_) => 0,
                    Err(_) => {
                         unsafe { (*driver_ptr).busy.store(false, Ordering::Release); }
                        -1
                    }
                }
            }

            extern "C" fn remove_adapter(ctx: *mut DriverContext) -> i32 {
                let ctx_safe = unsafe { &mut *ctx };
                let driver_ptr = ctx_safe.driver_data as *mut AsyncDriverWrapper<$driver_type>;
                if driver_ptr.is_null() { return 0; }

                // Remove logic should perhaps wait or force?
                // Let's try to take lock.
                let wrapper_ref = unsafe { &*driver_ptr };
                if wrapper_ref.busy.swap(true, Ordering::Acquire) {
                     return -3;
                }

                let future = async move {
                    let wrapper = unsafe { &mut *driver_ptr };
                    let _ = wrapper.driver.remove().await;
                    // Drop wrapper (and driver)
                    unsafe { let _ = Box::from_raw(driver_ptr); }
                    // No need to unlock busy, wrapper is gone.
                };

                match kernel().spawn_task(Box::pin(future)) {
                    Ok(_) => 0,
                    Err(_) => {
                        unsafe { (*driver_ptr).busy.store(false, Ordering::Release); }
                        -1
                    }
                }
            }

            extern "C" fn name_adapter() -> *const u8 {
                ($name)().as_ptr()
            }
            extern "C" fn name_len_adapter() -> usize {
                ($name)().len()
            }
            extern "C" fn type_adapter() -> u32 {
                ($dtype) as u32
            }
            extern "C" fn version_adapter() -> u64 {
                $version as u64
            }
    };
}
