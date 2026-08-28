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
//! a versioned `DriverExportsV1` header and a `KernelApiV4` function table
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

use crate::resource::net::PacketByteCount;
use core::num::NonZeroU64;
use core::sync::atomic::AtomicBool;

#[path = "driver_abi/export_macro.rs"]
mod export_macro;

// ============================================================================
// ABI Version
// ============================================================================

/// Current ABI version for compatibility checking.
///
/// Increment this when making breaking changes to the vtable layout.
/// Drivers compiled with a different ABI version will be rejected.
pub const DRIVER_ABI_VERSION: u64 = 6;

// Include the generated type hash
include!(concat!(env!("OUT_DIR"), "/abi_hash.rs"));

/// The symbol name that all dynamically loadable drivers must export.
pub const DRIVER_ENTRY_SYMBOL: &str = "_exorust_driver_entry";
/// The symbol name for the driver exports table.
pub const DRIVER_EXPORTS_SYMBOL: &str = "DRIVER_EXPORTS";
/// The symbol name for the kernel API function table.
pub const KERNEL_API_SYMBOL: &str = "__exorust_kernel_api_v4";
/// ABI version for the KernelApiV4 table.
pub const KERNEL_API_ABI_VERSION: u32 = 10;
/// ABI version for the DriverExportsV1 header.
pub const DRIVER_EXPORTS_ABI_VERSION: u32 = 3;

/// Exporter for a driver's provider descriptor slice.
///
/// The function writes the descriptor count into `count_out` when non-null and
/// returns a raw pointer to the first `ProviderDescriptorV1` entry.
pub type ProviderDescriptorsFn = extern "C" fn(count_out: *mut usize) -> *const ();
pub type AbiRRefDropFn =
    unsafe extern "C" fn(ptr: *mut u8, owner: u64, meta: usize, size: usize, align: usize);
pub type DriverExportStateFn =
    extern "C" fn(ctx: *mut DriverContext, out: *mut AbiExportedState) -> i32;
pub type DriverImportStateFn =
    extern "C" fn(ctx: *mut DriverContext, state: *mut AbiExportedState) -> i32;

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
        let bytes = self.0.to_le_bytes();
        u16::from_le_bytes([bytes[4], bytes[5]])
    }

    pub const fn bus(self) -> u8 {
        self.0.to_le_bytes()[2]
    }

    pub const fn device(self) -> u8 {
        self.0.to_le_bytes()[1]
    }

    pub const fn function(self) -> u8 {
        self.0.to_le_bytes()[0]
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

#[derive(Clone, Copy)]
pub struct DriverVTableFns {
    pub probe: extern "C" fn(ctx: *mut DriverContext) -> i32,
    pub start: extern "C" fn(ctx: *mut DriverContext) -> i32,
    pub stop: extern "C" fn(ctx: *mut DriverContext) -> i32,
    pub remove: extern "C" fn(ctx: *mut DriverContext) -> i32,
    pub name: extern "C" fn() -> *const u8,
    pub name_len: extern "C" fn() -> usize,
    pub driver_type: extern "C" fn() -> u32,
    pub version: extern "C" fn() -> u64,
    pub request_capabilities: Option<extern "C" fn(caps: *mut DriverCapabilities)>,
    pub handle_irq: Option<extern "C" fn(ctx: *mut DriverContext) -> bool>,
}

impl DriverVTable {
    /// Validate that this vtable is compatible with the current ABI version.
    /// # Errors
    ///
    /// Returns an error if the supplied representation violates the required invariants.
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
    pub const fn new(abi_version: u64, fns: DriverVTableFns) -> Self {
        Self {
            abi_version,
            type_hash: DRIVER_TYPE_HASH,
            probe: fns.probe,
            start: fns.start,
            stop: fns.stop,
            remove: fns.remove,
            name: fns.name,
            name_len: fns.name_len,
            driver_type: fns.driver_type,
            version: fns.version,
            request_capabilities: fns.request_capabilities,
            handle_irq: fns.handle_irq,
            provider_descriptors: None,
            reserved: [0; 6],
        }
    }

    /// Attach a provider descriptor exporter without changing the ABI layout.
    /// NOTE: caller should use the returned value; mark as must_use.
    #[must_use]
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

/// ABI-stable MMIO mapping handle for driver domains.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiMmioHandle {
    pub base: u64,
    pub size: usize,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiBlockTransport {
    Nvme = 1,
    Ahci = 2,
    Other = 255,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiBlockCommandKind {
    Read = 1,
    Write = 2,
    Flush = 3,
    Discard = 4,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiIoCompletion {
    pub request_id: u64,
    pub status: i32,
    pub bytes: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiBlockDeviceInfo {
    pub device_id: u64,
    pub namespace_id: u32,
    pub block_size: u32,
    pub max_transfer_blocks: u32,
    pub transport: u32,
    pub flags: u32,
    pub controller_id: u32,
    pub port_id: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AbiBlockDeviceRegistration {
    pub abi_size: u64,
    pub info: AbiBlockDeviceInfo,
    pub opaque: u64,
    pub submit: extern "C" fn(
        opaque: u64,
        request_id: u64,
        command: u32,
        lba: u64,
        blocks: u32,
        bytes: usize,
        iova: u64,
    ) -> i32,
    pub poll: extern "C" fn(
        opaque: u64,
        out: *mut AbiIoCompletion,
        capacity: usize,
        written: *mut usize,
    ) -> i32,
    pub is_ready: extern "C" fn(opaque: u64) -> bool,
    pub reserved: [u64; 6],
}

impl AbiBlockDeviceRegistration {
    pub const fn new(
        info: AbiBlockDeviceInfo,
        opaque: u64,
        submit: extern "C" fn(u64, u64, u32, u64, u32, usize, u64) -> i32,
        poll: extern "C" fn(u64, *mut AbiIoCompletion, usize, *mut usize) -> i32,
        is_ready: extern "C" fn(u64) -> bool,
    ) -> Self {
        Self {
            // ABI header size recorded as u64 to avoid truncation on large targets.
            abi_size: core::mem::size_of::<Self>() as u64,
            info,
            opaque,
            submit,
            poll,
            is_ready,
            reserved: [0; 6],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiNvmeNamespaceInfo {
    pub device_id: u64,
    pub namespace_id: u32,
    pub block_size: u32,
    pub max_transfer_blocks: u32,
    pub max_sgl_entries: u32,
    pub total_blocks: u64,
    pub controller_id: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AbiNvmeNamespaceRegistration {
    pub abi_size: u64,
    pub info: AbiNvmeNamespaceInfo,
    pub reserved: [u64; 6],
}

impl AbiNvmeNamespaceRegistration {
    pub const fn new(info: AbiNvmeNamespaceInfo) -> Self {
        Self {
            // ABI header size recorded as u64 to avoid truncation on large targets.
            abi_size: core::mem::size_of::<Self>() as u64,
            info,
            reserved: [0; 6],
        }
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbiNetDriverEventKind {
    Interrupt = 1,
    QueueWake = 2,
    Poll = 3,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AbiNetRxFrameLayout {
    frame_len: usize,
    header_len: u16,
    payload_len: u16,
    reserved: u32,
}

impl AbiNetRxFrameLayout {
    pub fn new(frame_len: usize, header_len: usize, payload_len: usize) -> Option<Self> {
        if frame_len == 0
            || header_len > u16::MAX as usize
            || payload_len > u16::MAX as usize
            || header_len.checked_add(payload_len)? != frame_len
        {
            return None;
        }
        Some(Self {
            frame_len,
            header_len: header_len as u16,
            payload_len: payload_len as u16,
            reserved: 0,
        })
    }

    pub fn whole_payload(frame_len: usize) -> Option<Self> {
        Self::new(frame_len, 0, frame_len)
    }

    pub const fn frame_len(self) -> usize {
        self.frame_len
    }

    pub const fn header_len(self) -> usize {
        self.header_len as usize
    }

    pub const fn payload_len(self) -> usize {
        self.payload_len as usize
    }

    pub const fn is_valid(self) -> bool {
        self.frame_len != 0
            && self.header_len as usize + self.payload_len as usize == self.frame_len
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AbiNetRxMeta {
    queue_index: u16,
    reserved0: u16,
    flags: u32,
    layout: AbiNetRxFrameLayout,
}

impl AbiNetRxMeta {
    pub const fn new(queue_index: u16, layout: AbiNetRxFrameLayout, flags: u32) -> Self {
        Self {
            queue_index,
            reserved0: 0,
            flags,
            layout,
        }
    }

    pub const fn queue_index(self) -> u16 {
        self.queue_index
    }

    pub const fn flags(self) -> u32 {
        self.flags
    }

    pub const fn layout(self) -> AbiNetRxFrameLayout {
        self.layout
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiNetTxMeta {
    pub queue_index: u16,
    pub has_queue_index: bool,
    pub has_vlan_tag: bool,
    pub reserved0: u8,
    pub flags: u32,
    pub vlan_tag: u16,
    pub reserved1: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AbiNetTxSegment {
    cpu_ptr: *const u8,
    device_addr: u64,
    len: usize,
}

impl AbiNetTxSegment {
    pub const fn from_checked_parts(
        cpu_ptr: *const u8,
        device_addr: u64,
        len: PacketByteCount,
    ) -> Option<Self> {
        if cpu_ptr.is_null() || device_addr == 0 {
            return None;
        }
        Some(Self {
            cpu_ptr,
            device_addr,
            len: len.get(),
        })
    }

    pub const fn is_valid(self) -> bool {
        !self.cpu_ptr.is_null() && self.device_addr != 0 && self.len != 0
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CheckedAbiNetTxSegment<'a> {
    segment: &'a AbiNetTxSegment,
    len: PacketByteCount,
}

impl<'a> CheckedAbiNetTxSegment<'a> {
    fn new(segment: &'a AbiNetTxSegment) -> Option<Self> {
        Some(Self {
            segment,
            len: PacketByteCount::new(segment.len)?,
        })
    }

    pub const fn cpu_ptr(self) -> *const u8 {
        self.segment.cpu_ptr
    }

    pub const fn device_addr(self) -> u64 {
        self.segment.device_addr
    }

    pub const fn len(self) -> PacketByteCount {
        self.len
    }
}

pub struct AbiNetTxSegmentsIter<'a> {
    segments: core::slice::Iter<'a, AbiNetTxSegment>,
}

impl<'a> Iterator for AbiNetTxSegmentsIter<'a> {
    type Item = CheckedAbiNetTxSegment<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let segment = self.segments.next()?;
        Some(
            CheckedAbiNetTxSegment::new(segment)
                .expect("AbiNetTxSegments validates every TX segment"),
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AbiNetTxSegments<'a> {
    segments: &'a [AbiNetTxSegment],
}

impl<'a> AbiNetTxSegments<'a> {
    pub fn new(segments: &'a [AbiNetTxSegment]) -> Option<Self> {
        if segments.is_empty() || segments.iter().any(|segment| !segment.is_valid()) {
            return None;
        }
        Some(Self { segments })
    }

    pub fn iter(self) -> AbiNetTxSegmentsIter<'a> {
        AbiNetTxSegmentsIter {
            segments: self.segments.iter(),
        }
    }

    /// # Panics
    ///
    /// Panics only if the non-empty, fully validated segment invariant created
    /// by [`Self::new`] has been violated internally.
    pub fn first(self) -> CheckedAbiNetTxSegment<'a> {
        CheckedAbiNetTxSegment::new(&self.segments[0])
            .expect("AbiNetTxSegments validates every TX segment")
    }

    pub fn get(self, index: usize) -> Option<CheckedAbiNetTxSegment<'a>> {
        self.segments
            .get(index)
            .and_then(CheckedAbiNetTxSegment::new)
    }

    pub const fn count(self) -> usize {
        self.segments.len()
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct AbiNetTxSubmission {
    lease_id: u64,
    segments_ptr: *const AbiNetTxSegment,
    segments_len: usize,
}

impl AbiNetTxSubmission {
    pub fn new(
        lease_id: crate::service::netdev::TxLeaseId,
        segments: &[AbiNetTxSegment],
    ) -> Option<Self> {
        AbiNetTxSegments::new(segments)?;
        Some(Self {
            lease_id: lease_id.get(),
            segments_ptr: segments.as_ptr(),
            segments_len: segments.len(),
        })
    }

    pub const fn lease_id(self) -> Option<crate::service::netdev::TxLeaseId> {
        crate::service::netdev::TxLeaseId::new(self.lease_id)
    }

    pub fn segments(&self) -> Option<AbiNetTxSegments<'_>> {
        if self.segments_ptr.is_null() || self.segments_len == 0 {
            return None;
        }
        AbiNetTxSegments::new(unsafe {
            core::slice::from_raw_parts(self.segments_ptr, self.segments_len)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_tx_submission_rejects_empty_and_invalid_segments() {
        static BYTES: [u8; 4] = [0; 4];
        let valid_len = PacketByteCount::new(BYTES.len()).expect("non-empty segment");
        let valid = AbiNetTxSegment::from_checked_parts(BYTES.as_ptr(), 0x1000, valid_len)
            .expect("valid ABI segment");

        let lease_id = crate::service::netdev::TxLeaseId::new(1).expect("non-zero lease");
        assert!(AbiNetTxSubmission::new(lease_id, &[]).is_none());

        let null_cpu = [AbiNetTxSegment {
            cpu_ptr: core::ptr::null(),
            device_addr: 0x1000,
            len: 1,
        }];
        let zero_device = [AbiNetTxSegment {
            cpu_ptr: BYTES.as_ptr(),
            device_addr: 0,
            len: 1,
        }];
        let zero_len = [AbiNetTxSegment {
            cpu_ptr: BYTES.as_ptr(),
            device_addr: 0x1000,
            len: 0,
        }];

        assert!(AbiNetTxSegments::new(&null_cpu).is_none());
        assert!(AbiNetTxSegments::new(&zero_device).is_none());
        assert!(AbiNetTxSegments::new(&zero_len).is_none());

        let raw_invalid = AbiNetTxSubmission {
            lease_id: 7,
            segments_ptr: zero_len.as_ptr(),
            segments_len: zero_len.len(),
        };
        assert!(raw_invalid.segments().is_none());

        let valid_segments = [valid];
        let lease_id = crate::service::netdev::TxLeaseId::new(9).expect("non-zero lease");
        let submission =
            AbiNetTxSubmission::new(lease_id, &valid_segments).expect("valid ABI submission");
        assert_eq!(submission.lease_id(), Some(lease_id));
        assert_eq!(
            submission.segments().expect("validated segments").count(),
            1
        );
    }

    #[test]
    fn abi_tx_segments_preserve_fragmented_descriptor_windows() {
        static FIRST: [u8; 3] = [1, 2, 3];
        static SECOND: [u8; 5] = [4, 5, 6, 7, 8];
        let segments = [
            AbiNetTxSegment::from_checked_parts(
                FIRST.as_ptr(),
                0x1000,
                PacketByteCount::new(FIRST.len()).expect("first non-empty segment"),
            )
            .expect("first segment"),
            AbiNetTxSegment::from_checked_parts(
                SECOND.as_ptr(),
                0x2000,
                PacketByteCount::new(SECOND.len()).expect("second non-empty segment"),
            )
            .expect("second segment"),
        ];

        let validated = AbiNetTxSegments::new(&segments).expect("fragmented descriptors");
        assert_eq!(validated.count(), 2);
        assert_eq!(validated.first().device_addr(), 0x1000);
        assert_eq!(
            validated.get(1).expect("second segment").len().get(),
            SECOND.len()
        );

        let lease_id = crate::service::netdev::TxLeaseId::new(11).expect("non-zero lease");
        let submission =
            AbiNetTxSubmission::new(lease_id, &segments).expect("fragmented submission");
        let submitted = submission
            .segments()
            .expect("validated submission segments");
        assert_eq!(submitted.first().cpu_ptr(), FIRST.as_ptr());
        assert_eq!(
            submitted
                .get(1)
                .expect("second submitted segment")
                .device_addr(),
            0x2000
        );
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiNetDriverEvent {
    pub kind: u32,
    pub queue_index: u16,
    pub _padding: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiNetPortStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_errors: u64,
    pub rx_errors: u64,
    pub initialized: bool,
    pub reserved: [u8; 7],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiNetPortInfo {
    pub port_id: u64,
    pub queue_pairs: u16,
    pub max_tx_segments: u16,
    pub mtu: u32,
    pub flags: u32,
    pub mac: [u8; 6],
    pub reserved0: [u8; 2],
    pub name_ptr: *const u8,
    pub name_len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiRxWritableRegion {
    pub cpu_ptr: *mut u8,
    pub device_addr: u64,
    pub writable_len: usize,
}

#[repr(C)]
pub struct AbiRxLease {
    lease_id: u64,
    region: AbiRxWritableRegion,
    pub reserved: [u64; 2],
}

impl Default for AbiRxLease {
    fn default() -> Self {
        Self {
            lease_id: 0,
            region: AbiRxWritableRegion::default(),
            reserved: [0; 2],
        }
    }
}

unsafe impl Send for AbiRxLease {}

impl AbiRxLease {
    pub fn new(lease_id: NonZeroU64, region: AbiRxWritableRegion) -> Option<Self> {
        if region.cpu_ptr.is_null() || region.device_addr == 0 || region.writable_len == 0 {
            return None;
        }
        Some(Self {
            lease_id: lease_id.get(),
            region,
            reserved: [0; 2],
        })
    }

    pub const fn lease_id(&self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.lease_id)
    }

    pub const fn writable_region(&self) -> Option<AbiRxWritableRegion> {
        if self.lease_id == 0
            || self.region.cpu_ptr.is_null()
            || self.region.device_addr == 0
            || self.region.writable_len == 0
        {
            None
        } else {
            Some(self.region)
        }
    }

    /// # Safety
    /// `ptr` must be null or point to a valid `AbiRxLease` slot.
    pub unsafe fn take(ptr: *mut Self) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }
        let slot = unsafe { &mut *ptr };
        if slot.lease_id().is_none() {
            None
        } else {
            Some(core::mem::take(slot))
        }
    }
}

#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbiTxDeviceOutcome(u32);

impl AbiTxDeviceOutcome {
    pub const TRANSMITTED: Self = Self(0);
    pub const NOT_TRANSMITTED: Self = Self(1);
    pub const OUTCOME_UNKNOWN: Self = Self(2);

    pub const fn from_outcome(outcome: crate::service::netdev::TxDeviceOutcome) -> Self {
        match outcome {
            crate::service::netdev::TxDeviceOutcome::Transmitted => Self::TRANSMITTED,
            crate::service::netdev::TxDeviceOutcome::NotTransmitted => Self::NOT_TRANSMITTED,
            crate::service::netdev::TxDeviceOutcome::OutcomeUnknown => Self::OUTCOME_UNKNOWN,
        }
    }

    pub const fn into_outcome(self) -> Option<crate::service::netdev::TxDeviceOutcome> {
        match self.0 {
            0 => Some(crate::service::netdev::TxDeviceOutcome::Transmitted),
            1 => Some(crate::service::netdev::TxDeviceOutcome::NotTransmitted),
            2 => Some(crate::service::netdev::TxDeviceOutcome::OutcomeUnknown),
            _ => None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AbiNetPortRuntime {
    pub abi_size: u64,
    pub runtime_cookie: u64,
    pub lease_rx_buffer: extern "C" fn(runtime_cookie: u64, out_lease: *mut AbiRxLease) -> i32,
    pub release_rx_buffer: extern "C" fn(runtime_cookie: u64, lease: *mut AbiRxLease) -> i32,
    pub submit_rx_buffer:
        extern "C" fn(runtime_cookie: u64, lease: *mut AbiRxLease, meta: AbiNetRxMeta) -> i32,
    pub complete_tx_lease:
        extern "C" fn(runtime_cookie: u64, lease_id: u64, outcome: AbiTxDeviceOutcome) -> i32,
    pub schedule_event: extern "C" fn(runtime_cookie: u64, event: AbiNetDriverEvent) -> i32,
    pub update_link: extern "C" fn(runtime_cookie: u64, up: bool) -> i32,
    pub log: extern "C" fn(runtime_cookie: u64, level: u32, msg_ptr: *const u8, msg_len: usize),
    pub reserved: [u64; 1],
}

impl AbiNetPortRuntime {
    pub const fn new(
        runtime_cookie: u64,
        lease_rx_buffer: extern "C" fn(u64, *mut AbiRxLease) -> i32,
        release_rx_buffer: extern "C" fn(u64, *mut AbiRxLease) -> i32,
        submit_rx_buffer: extern "C" fn(u64, *mut AbiRxLease, AbiNetRxMeta) -> i32,
        complete_tx_lease: extern "C" fn(u64, u64, AbiTxDeviceOutcome) -> i32,
        schedule_event: extern "C" fn(u64, AbiNetDriverEvent) -> i32,
        update_link: extern "C" fn(u64, bool) -> i32,
        log: extern "C" fn(u64, u32, *const u8, usize),
    ) -> Self {
        Self {
            // ABI header size recorded as u64 to avoid truncation on large targets.
            abi_size: core::mem::size_of::<Self>() as u64,
            runtime_cookie,
            lease_rx_buffer,
            release_rx_buffer,
            submit_rx_buffer,
            complete_tx_lease,
            schedule_event,
            update_link,
            log,
            reserved: [0; 1],
        }
    }
}

/// Driver-side ownership guard for one kernel-owned RX DMA lease.
///
/// Dropping the guard returns the lease through the runtime that issued it.
/// Submitting a completed frame consumes the same authority and prevents a
/// second release.
pub struct AbiRxLeaseGuard {
    runtime: AbiNetPortRuntime,
    lease: AbiRxLease,
}

unsafe impl Send for AbiRxLeaseGuard {}

impl core::fmt::Debug for AbiRxLeaseGuard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AbiRxLeaseGuard")
            .field("lease_id", &self.lease.lease_id())
            .field("region", &self.lease.writable_region())
            .finish()
    }
}

impl AbiRxLeaseGuard {
    /// Acquire one RX DMA lease from `runtime`.
    ///
    /// # Errors
    ///
    /// Returns the runtime's typed ABI error, or `InvalidParam` if a successful
    /// callback did not publish a valid non-empty lease.
    pub fn acquire(runtime: AbiNetPortRuntime) -> Result<Self, AbiError> {
        let mut lease = AbiRxLease::default();
        let status = AbiError::from_raw((runtime.lease_rx_buffer)(
            runtime.runtime_cookie,
            &mut lease,
        ));
        if !status.is_success() {
            if lease.lease_id().is_some() {
                let _ = (runtime.release_rx_buffer)(runtime.runtime_cookie, &mut lease);
            }
            return Err(status);
        }
        if lease.writable_region().is_none() {
            if lease.lease_id().is_some() {
                let _ = (runtime.release_rx_buffer)(runtime.runtime_cookie, &mut lease);
            }
            return Err(AbiError::InvalidParam);
        }
        Ok(Self { runtime, lease })
    }

    pub const fn writable_region(&self) -> AbiRxWritableRegion {
        self.lease.region
    }

    /// Publish the exact device-written frame layout and consume this lease.
    pub fn submit(mut self, meta: AbiNetRxMeta) -> AbiError {
        AbiError::from_raw((self.runtime.submit_rx_buffer)(
            self.runtime.runtime_cookie,
            &mut self.lease,
            meta,
        ))
    }
}

impl Drop for AbiRxLeaseGuard {
    fn drop(&mut self) {
        if self.lease.lease_id().is_some() {
            let _ = (self.runtime.release_rx_buffer)(self.runtime.runtime_cookie, &mut self.lease);
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct AbiNetPortRegistration {
    pub abi_size: u64,
    pub info: AbiNetPortInfo,
    pub opaque: u64,
    pub start: extern "C" fn(opaque: u64, runtime: *const AbiNetPortRuntime) -> i32,
    pub bind: extern "C" fn(opaque: u64, if_id: u16) -> i32,
    pub submit_tx_chain: extern "C" fn(
        opaque: u64,
        submission: *const AbiNetTxSubmission,
        meta: AbiNetTxMeta,
    ) -> i32,
    pub poll: extern "C" fn(opaque: u64, if_id: u16) -> i32,
    pub handle_event: extern "C" fn(opaque: u64, if_id: u16, event: AbiNetDriverEvent) -> i32,
    pub stats: extern "C" fn(opaque: u64, out: *mut AbiNetPortStats) -> i32,
    pub stop: extern "C" fn(opaque: u64) -> i32,
    pub set_interrupts_enabled: extern "C" fn(opaque: u64, enabled: bool) -> i32,
    pub reserved: [u64; 3],
}

#[derive(Clone, Copy)]
pub struct AbiNetPortOps {
    pub start: extern "C" fn(u64, *const AbiNetPortRuntime) -> i32,
    pub bind: extern "C" fn(u64, u16) -> i32,
    pub submit_tx_chain: extern "C" fn(u64, *const AbiNetTxSubmission, AbiNetTxMeta) -> i32,
    pub poll: extern "C" fn(u64, u16) -> i32,
    pub handle_event: extern "C" fn(u64, u16, AbiNetDriverEvent) -> i32,
    pub stats: extern "C" fn(u64, *mut AbiNetPortStats) -> i32,
    pub stop: extern "C" fn(u64) -> i32,
    pub set_interrupts_enabled: extern "C" fn(u64, bool) -> i32,
}

impl AbiNetPortRegistration {
    pub const fn new(info: AbiNetPortInfo, opaque: u64, ops: AbiNetPortOps) -> Self {
        Self {
            abi_size: core::mem::size_of::<Self>() as u64,
            info,
            opaque,
            start: ops.start,
            bind: ops.bind,
            submit_tx_chain: ops.submit_tx_chain,
            poll: ops.poll,
            handle_event: ops.handle_event,
            stats: ops.stats,
            stop: ops.stop,
            set_interrupts_enabled: ops.set_interrupts_enabled,
            reserved: [0; 3],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiMsixVectorInfo {
    pub vector: u32,
    pub table_index: u16,
    pub reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiInterfaceScope {
    pub kind: u32,
    pub if_id: u16,
    pub reserved: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiRRefRaw {
    pub ptr: *mut u8,
    pub owner: u64,
    pub meta: usize,
    pub size: usize,
    pub align: usize,
    pub type_hash: u64,
    pub drop_fn: Option<AbiRRefDropFn>,
    pub reserved: [u64; 2],
}

unsafe impl Send for AbiRRefRaw {}
unsafe impl Sync for AbiRRefRaw {}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct AbiExportedState {
    pub version: u32,
    pub reserved0: u32,
    pub data_ptr: *mut u8,
    pub data_len: usize,
    pub data_cap: usize,
    pub reserved: [u64; 4],
}

/// Kernel API function table for drivers.
///
/// Drivers must validate `abi_version` and `abi_size` before using optional
/// entries in this table. Older drivers may use only the prefix fields and
/// ignore optional tail entries introduced in later revisions.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KernelApiV4 {
    pub abi_version: u32,
    pub abi_size: u64,

    pub log: extern "C" fn(level: u32, msg_ptr: *const u8, msg_len: usize),

    pub alloc_dma_for_device_raw: extern "C" fn(
        size: usize,
        device_id: u64,
        align: usize,
        direction: u8,
        out: *mut AbiDmaSlice,
    ) -> i32,
    pub release_dma_raw: extern "C" fn(dma_handle_id: u64) -> i32,

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
    pub current_domain_id: extern "C" fn() -> u64,
    pub exchange_alloc_raw:
        extern "C" fn(size: usize, align: usize, out_ptr: *mut *mut u8, out_owner: *mut u64) -> i32,
    pub exchange_dealloc_raw:
        extern "C" fn(ptr: *mut u8, owner: u64, size: usize, align: usize) -> i32,
    pub exchange_transfer_raw: extern "C" fn(ptr: *mut u8, from_owner: u64, to_owner: u64) -> i32,
    pub ipc_create_channel_raw: extern "C" fn(out_sender: *mut u64, out_receiver: *mut u64) -> i32,
    pub ipc_close_raw: extern "C" fn(handle: u64) -> i32,
    pub ipc_send_raw: extern "C" fn(handle: u64, raw: *const AbiRRefRaw) -> i32,
    pub ipc_recv_raw: extern "C" fn(handle: u64, out_raw: *mut AbiRRefRaw) -> i32,

    pub register_block_device:
        extern "C" fn(registration: *const AbiBlockDeviceRegistration, out_handle: *mut u64) -> i32,
    pub unregister_block_device: extern "C" fn(handle: u64) -> i32,

    pub register_nvme_namespace: extern "C" fn(
        registration: *const AbiNvmeNamespaceRegistration,
        out_handle: *mut u64,
    ) -> i32,
    pub unregister_nvme_namespace: extern "C" fn(handle: u64) -> i32,

    pub register_netdev_port:
        extern "C" fn(registration: *const AbiNetPortRegistration, out_handle: *mut u64) -> i32,
    pub unregister_netdev_port: extern "C" fn(handle: u64) -> i32,

    pub reserved: [u64; 2],
    pub enable_msix_raw: Option<
        extern "C" fn(
            device_id: u64,
            requested_count: u16,
            out_vectors: *mut AbiMsixVectorInfo,
            capacity: usize,
            written: *mut usize,
        ) -> i32,
    >,
    pub disable_msix_raw: Option<extern "C" fn(device_id: u64) -> i32>,
}

/// Driver export header for `DRIVER_EXPORTS`.
#[repr(C)]
pub struct DriverExportsV1 {
    pub abi_version: u32,
    pub abi_size: u64,

    pub name_ptr: *const u8,
    pub name_len: usize,

    pub entry: DriverEntryFn,
    pub init: Option<extern "C" fn(api: *const KernelApiV4) -> i32>,
    pub fini: Option<extern "C" fn() -> i32>,
    pub providers: Option<ProviderDescriptorsFn>,
    pub export_state: Option<DriverExportStateFn>,
    pub import_state: Option<DriverImportStateFn>,

    pub reserved: [u64; 5],
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
    let bytes = packed.to_le_bytes();
    let major = u16::from_le_bytes([bytes[4], bytes[5]]);
    let minor = u16::from_le_bytes([bytes[2], bytes[3]]);
    let patch = u16::from_le_bytes([bytes[0], bytes[1]]);
    (major, minor, patch)
}

// ============================================================================
// Exported Macro for drivers
// ============================================================================
/// Export a C-compatible `DriverVTable` from a driver crate.
///
/// Example:
/// ```rust
/// use kernel_api::abi::driver::DriverContext;
/// use kernel_api::driver::DriverType;
/// use kernel_api::export_driver;
/// # fn probe_fn(_ctx: &mut DriverContext) -> i32 { 0 }
/// # fn remove_fn(_ctx: &mut DriverContext) -> i32 { 0 }
/// # fn driver_name() -> &'static str { "example" }
/// export_driver!(
///     probe: probe_fn,
///     remove: remove_fn,
///     name: driver_name,
///     driver_type: (DriverType::Block as u32),
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
/// use kernel_api::abi::driver::DriverContext;
/// use kernel_api::driver::DriverType;
/// use kernel_api::export_driver;
/// # fn my_probe(_ctx: &mut DriverContext) -> i32 { 0 }
/// # fn my_remove(_ctx: &mut DriverContext) -> i32 { 0 }
/// # fn my_name() -> &'static str { "example-pci" }
/// # fn my_start(_ctx: &mut DriverContext) -> i32 { 0 }
/// # fn my_irq_handler(_ctx: &mut DriverContext) -> bool { false }
/// export_driver!(
///     probe: my_probe,
///     remove: my_remove,
///     name: my_name,
///     driver_type: (DriverType::Pci as u32),
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
        pub fn standalone_driver_vtable() -> *const $crate::abi::driver::DriverVTable {
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
                $crate::abi::driver::DriverVTableFns {
                    probe: probe_adapter,
                    start: start_adapter,
                    stop: stop_adapter,
                    remove: remove_adapter,
                    name: name_adapter,
                    name_len: name_len_adapter,
                    driver_type: type_adapter,
                    version: version_adapter,
                    request_capabilities: None,
                    handle_irq: Some(irq_adapter),
                },
            ).with_provider_descriptors_export(Some(providers_adapter));

            &VTABLE
        }

        #[cfg(all(feature = "export_driver_entry", not(test)))]
        #[unsafe(no_mangle)]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::abi::driver::DriverVTable {
            standalone_driver_vtable()
        }

        // Provide a test-only entry symbol without export/no_mangle to make unit tests
        // able to call the entry function directly without requiring the feature.
        #[cfg(test)]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::abi::driver::DriverVTable {
            standalone_driver_vtable()
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
        pub fn standalone_driver_vtable() -> *const $crate::abi::driver::DriverVTable {
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
                $crate::abi::driver::DriverVTableFns {
                    probe: probe_adapter,
                    start: start_adapter,
                    stop: stop_adapter,
                    remove: remove_adapter,
                    name: name_adapter,
                    name_len: name_len_adapter,
                    driver_type: type_adapter,
                    version: version_adapter,
                    request_capabilities: None,
                    handle_irq: None,
                },
            ).with_provider_descriptors_export(Some(providers_adapter));

            &VTABLE
        }

        #[cfg(all(feature = "export_driver_entry", not(test)))]
        #[unsafe(no_mangle)]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::abi::driver::DriverVTable {
            standalone_driver_vtable()
        }

        #[cfg(test)]
        pub extern "C" fn _exorust_driver_entry() -> *const $crate::abi::driver::DriverVTable {
            standalone_driver_vtable()
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
        $(, dependencies: [$($dep:expr),* $(,)?])?
        $(, start: $start:path)? // Optional start
        $(, stop: $stop:path)?   // Optional stop
        $(, irq: $irq:path)?     // Optional irq
        $(,)? // allow optional trailing comma so doc examples can use a trailing comma
    ) => {
        $crate::declare_rany_type_id_section!(
            $crate::__type_id::IPC_INTERFACE,
            $crate::__type_id::KERNEL_API_INTERFACE,
            $crate::__type_id::DRIVER_EXPORTS_INTERFACE
            $(, $($dep),*)?
        );
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
