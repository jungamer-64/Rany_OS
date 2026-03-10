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
//! Newer drivers can export a `DRIVER_EXPORTS` symbol that provides
//! a versioned `DriverExportsV1` header and a `KernelApiV2` function table
//! for initialization, while keeping `_exorust_driver_entry` as a fallback.
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
#[path = "driver_abi/export_macro.rs"]
mod export_macro;
use core::sync::atomic::AtomicBool;
pub const DRIVER_ABI_VERSION: u64 = 2;

// Include the generated type hash
include!(concat!(env!("OUT_DIR"), "/abi_hash.rs"));

/// The symbol name that all dynamically loadable drivers must export.
pub const DRIVER_ENTRY_SYMBOL: &str = "_exorust_driver_entry";
/// The symbol name for the driver exports table.
pub const DRIVER_EXPORTS_SYMBOL: &str = "DRIVER_EXPORTS";
/// The symbol name for the kernel API function table.
pub const KERNEL_API_SYMBOL: &str = "__exorust_kernel_api_v2";
/// ABI version for the KernelApiV2 table.
pub const KERNEL_API_ABI_VERSION: u32 = 3;
/// ABI version for the DriverExportsV1 header.
pub const DRIVER_EXPORTS_ABI_VERSION: u32 = 1;

/// Exporter for a driver's provider descriptor slice.
///
/// The function writes the descriptor count into `count_out` when non-null and
/// returns a raw pointer to the first `ProviderDescriptorV1` entry.
pub type ProviderDescriptorsFn = extern "C" fn(count_out: *mut usize) -> *const ();

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

/// ABI-stable PCI device locator packed into a single `u64`.
///
/// Layout:
/// - bits 63..32: PCI segment
/// - bits 23..16: bus
/// - bits 15..8: device
/// - bits 7..0: function
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PackedPciLocation(pub u64);

impl PackedPciLocation {
    pub const NULL: Self = Self(0);

    pub const fn new(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        Self(
            ((segment as u64) << 32)
                | ((bus as u64) << 16)
                | ((device as u64) << 8)
                | (function as u64),
        )
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn is_null(self) -> bool {
        self.0 == 0
    }

    pub const fn segment(self) -> u16 {
        (self.0 >> 32) as u16
    }

    pub const fn bus(self) -> u8 {
        (self.0 >> 16) as u8
    }

    pub const fn device(self) -> u8 {
        (self.0 >> 8) as u8
    }

    pub const fn function(self) -> u8 {
        self.0 as u8
    }
}

impl From<u64> for PackedPciLocation {
    fn from(value: u64) -> Self {
        Self::from_raw(value)
    }
}

impl From<PackedPciLocation> for u64 {
    fn from(value: PackedPciLocation) -> Self {
        value.raw()
    }
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
    /// Packed PCI segment:bus:device.function for device-scoped DMA
    pub pci_locator: u64,
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
    pub reserved: [u64; 2],
}

impl DriverContext {
    /// Create a new empty context
    pub const fn new() -> Self {
        Self {
            device_address: 0,
            device_address_secondary: 0,
            pci_locator: PackedPciLocation::NULL.raw(),
            irq: 0,
            flags: 0,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            driver_data: 0,
            reserved: [0; 2],
        }
    }

    /// Create context for a PCI device
    pub const fn for_pci(
        bar0: u64,
        irq: u32,
        vendor_id: u16,
        device_id: u16,
        class_code: u32,
        pci_locator: PackedPciLocation,
    ) -> Self {
        Self {
            device_address: bar0,
            device_address_secondary: 0,
            pci_locator: pci_locator.raw(),
            irq,
            flags: 0,
            vendor_id,
            device_id,
            class_code,
            driver_data: 0,
            reserved: [0; 2],
        }
    }

    pub const fn pci_location(&self) -> PackedPciLocation {
        PackedPciLocation::from_raw(self.pci_locator)
    }
}

impl Default for DriverContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal wrapper used by `export_async_driver!` to keep the async driver
/// instance plus a minimal busy flag alongside the ABI driver context.
pub struct AsyncDriverWrapper<T: crate::driver::AsyncDriver> {
    pub driver: T,
    pub busy: AtomicBool,
}

impl<T: crate::driver::AsyncDriver> AsyncDriverWrapper<T> {
    pub fn new(driver: T) -> Self {
        Self {
            driver,
            busy: AtomicBool::new(false),
        }
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

    /// Export provider descriptors for this driver instance (optional).
    pub provider_descriptors: Option<ProviderDescriptorsFn>,

    /// Reserved for future expansion
    pub reserved: [u64; 6],
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
            provider_descriptors: None,
            reserved: [0; 6],
        }
    }

    /// Attach a provider descriptor exporter without changing the ABI layout.
    pub const fn with_provider_descriptors_export(
        mut self,
        provider_export: Option<ProviderDescriptorsFn>,
    ) -> Self {
        self.provider_descriptors = provider_export;
        self
    }

    /// Read the optional provider descriptor exporter from the reserved tail.
    pub fn provider_descriptors_export(&self) -> Option<ProviderDescriptorsFn> {
        self.provider_descriptors
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
// Kernel API (Driver Domain C ABI)
// ============================================================================

/// ABI-stable DMA slice carrier for standalone driver cells.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiDmaSlice {
    pub phys_addr: u64,
    /// Hardware-visible address (IOVA when IOMMU active, else phys_addr)
    pub device_addr: u64,
    pub virt_addr: u64,
    pub size: usize,
}

/// ABI-stable MMIO mapping handle for driver domains.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiMmioHandle {
    pub base: u64,
    pub size: usize,
}

/// Kernel API function table for drivers.
///
/// Drivers must validate `abi_version` and `abi_size` before using optional
/// entries in this table. Older drivers may use only the prefix fields and
/// ignore optional tail entries introduced in later revisions.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelApiV2 {
    pub abi_version: u32,
    pub abi_size: u32,

    pub log: extern "C" fn(level: u32, msg_ptr: *const u8, msg_len: usize),

    pub alloc_dma_for_device_raw:
        extern "C" fn(size: usize, device_id: u64, align: usize, out: *mut AbiDmaSlice) -> i32,
    pub release_dma_raw: extern "C" fn(virt_addr: u64, size: usize, phys_addr: u64) -> i32,

    pub map_mmio: extern "C" fn(paddr: u64, size: usize, out: *mut AbiMmioHandle) -> i32,
    pub unmap_mmio: extern "C" fn(handle: *const AbiMmioHandle) -> i32,

    pub port_read_u8: extern "C" fn(port: u16) -> u8,
    pub port_write_u8: extern "C" fn(port: u16, value: u8),

    pub irq_bind: extern "C" fn(irq: u32, cookie: u64) -> i32,
    pub irq_unbind: extern "C" fn(irq: u32) -> i32,

    /// Optional heap allocator for standalone cell runtime.
    pub heap_alloc: Option<extern "C" fn(size: usize) -> *mut u8>,
    /// Optional heap deallocator paired with `heap_alloc`.
    pub heap_dealloc: Option<extern "C" fn(ptr: *mut u8, size: usize)>,
    /// Optional panic abort hook for standalone cell runtime.
    pub panic_abort: Option<extern "C" fn(msg_ptr: *const u8, msg_len: usize) -> !>,

    pub reserved: [u64; 8],
}

/// Driver export header for `DRIVER_EXPORTS`.
#[repr(C)]
pub struct DriverExportsV1 {
    pub abi_version: u32,
    pub abi_size: u32,

    pub name_ptr: *const u8,
    pub name_len: usize,

    pub entry: DriverEntryFn,
    pub init: Option<extern "C" fn(api: *const KernelApiV2) -> i32>,
    pub fini: Option<extern "C" fn() -> i32>,
    pub providers: Option<ProviderDescriptorsFn>,

    pub reserved: [u64; 7],
}

// SAFETY: `DriverExportsV1` is an immutable table of function pointers and raw
// pointers to static data emitted by a driver crate. It is read-only after
// initialization and safe to share as a `static`.
unsafe impl Sync for DriverExportsV1 {}

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
/// use kernel_api::export_driver;
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
/// use kernel_api::export_driver;
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
        , providers = $providers:expr
        $(, start = $start:path)?
        $(, stop = $stop:path)?
        , irq = $irq:path
    ) => {
            $crate::declare_rany_type_id_section!();
            #[cfg(all(feature = "export_driver_entry", not(test)))]
            #[unsafe(no_mangle)]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::abi::driver::DriverVTable {
            // --- Mandatory Adapters ---
            extern "C" fn probe_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
                // SAFETY: The kernel guarantees ctx is valid when calling probe
                let ctx_safe = unsafe { &mut *ctx };
                ($probe)(ctx_safe)
            }
            extern "C" fn remove_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
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
            extern "C" fn providers_adapter(count_out: *mut usize) -> *const () {
                let providers: &'static [$crate::provider::ProviderDescriptorV1] = $providers;
                if !count_out.is_null() {
                    unsafe {
                        *count_out = providers.len();
                    }
                }
                providers.as_ptr() as *const ()
            }

            // --- Optional Adapters (start/stop) ---
            extern "C" fn start_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($start)(ctx_safe); )?
                rv
            }
            extern "C" fn stop_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($stop)(ctx_safe); )?
                rv
            }

            // IRQ adapter that wraps the user's IRQ handler
            extern "C" fn irq_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> bool {
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                ($irq)(ctx_safe)
            }

            static VTABLE: $crate::abi::driver::DriverVTable = $crate::abi::driver::DriverVTable::new(
                $crate::abi::driver::DRIVER_ABI_VERSION,
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
            ).with_provider_descriptors_export(Some(providers_adapter));

            &VTABLE
        }
        // Provide a test-only entry symbol without export/no_mangle to make unit tests
        // able to call the entry function directly without requiring the feature.
        #[cfg(test)]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::abi::driver::DriverVTable {
            // --- Mandatory Adapters ---
            extern "C" fn probe_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
                let ctx_safe = unsafe { &mut *ctx };
                ($probe)(ctx_safe)
            }
            extern "C" fn remove_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
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
            extern "C" fn providers_adapter(count_out: *mut usize) -> *const () {
                let providers: &'static [$crate::provider::ProviderDescriptorV1] = $providers;
                if !count_out.is_null() {
                    unsafe {
                        *count_out = providers.len();
                    }
                }
                providers.as_ptr() as *const ()
            }

            // --- Optional Adapters (start/stop) ---
            extern "C" fn start_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($start)(ctx_safe); )?
                rv
            }
            extern "C" fn stop_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($stop)(ctx_safe); )?
                rv
            }

            // IRQ adapter that wraps the user's IRQ handler
            extern "C" fn irq_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> bool {
                let ctx_safe = unsafe { &mut *ctx };
                ($irq)(ctx_safe)
            }

            static VTABLE: $crate::abi::driver::DriverVTable = $crate::abi::driver::DriverVTable::new(
                $crate::abi::driver::DRIVER_ABI_VERSION,
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
            ).with_provider_descriptors_export(Some(providers_adapter));

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
        , providers = $providers:expr
        $(, start = $start:path)?
        $(, stop = $stop:path)?
    ) => {
        $crate::declare_rany_type_id_section!();
        #[cfg(feature = "export_driver_entry")]
        #[unsafe(no_mangle)]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::abi::driver::DriverVTable {
            // --- Mandatory Adapters ---

            extern "C" fn probe_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                ($probe)(ctx_safe)
            }
            extern "C" fn remove_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
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
            extern "C" fn providers_adapter(count_out: *mut usize) -> *const () {
                let providers: &'static [$crate::provider::ProviderDescriptorV1] = $providers;
                if !count_out.is_null() {
                    unsafe {
                        *count_out = providers.len();
                    }
                }
                providers.as_ptr() as *const ()
            }

            // --- Optional Adapters (start/stop) ---
            extern "C" fn start_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($start)(ctx_safe); )?
                rv
            }
            extern "C" fn stop_adapter(ctx: *mut $crate::abi::driver::DriverContext) -> i32 {
                let mut rv: i32 = 0;
                // SAFETY: The kernel guarantees ctx is valid
                let ctx_safe = unsafe { &mut *ctx };
                $( rv = ($stop)(ctx_safe); )?
                rv
            }

            static VTABLE: $crate::abi::driver::DriverVTable = $crate::abi::driver::DriverVTable::new(
                $crate::abi::driver::DRIVER_ABI_VERSION,
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
            ).with_provider_descriptors_export(Some(providers_adapter));

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
        $(, providers: $providers:expr)?
        $(, start: $start:path)? // Optional start
        $(, stop: $stop:path)?   // Optional stop
        $(, irq: $irq:path)?     // Optional irq
        $(,)? // allow optional trailing comma so doc examples can use a trailing comma
    ) => {
        $crate::export_driver!(@impl
            probe = $probe,
            remove = $remove,
            name = $name,
            driver_type = $driver_type,
            version = $version,
            providers = $crate::export_driver!(@providers $( $providers )?)
            $(, start = $start)?
            $(, stop = $stop)?
            $(, irq = $irq)?
        );
    };

    (@providers $providers:expr) => {
        $providers
    };

    (@providers) => {
        &[] as &[$crate::provider::ProviderDescriptorV1]
    };
}
