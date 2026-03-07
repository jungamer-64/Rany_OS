// ============================================================================
// kernel/src/driver_registry.rs - Driver Registry and Lifecycle Management
// ============================================================================
//!
//! # Driver Registry
//!
//! Manages the lifecycle of all registered drivers in the kernel.
//! Provides a unified interface for driver discovery, probing, and control.
//!
//! ## Responsibilities
//! - Register/unregister drivers
//! - Probe drivers on device discovery
//! - Start/stop drivers
//! - Match devices to drivers
//!
//! ## Future: Hot-Swap Support
//! The registry is designed to support future hot-swap capabilities:
//! - Dynamic driver loading
//! - Safe driver unloading
//! - Driver replacement

#![allow(dead_code)]

extern crate alloc;

use crate::sync::PoisonLock;
use alloc::boxed::Box;
use alloc::string::String;

use alloc::vec::Vec;
use core::fmt;
use kernel_api::abi::driver::{
    AbiDmaSlice, AbiDriverType, AbiError as AbiErrorCode, AbiMmioHandle,
    DRIVER_EXPORTS_ABI_VERSION, DriverCapabilities as AbiDriverCapabilities,
    DriverContext as AbiDriverContext, DriverEntryFn as AbiEntryFn, DriverExportsV1,
    DriverVTable as AbiDriverVTable, KERNEL_API_ABI_VERSION, KernelApiV2,
};
use kernel_api::driver::{DeviceId, Driver, DriverState, DriverType};
use kernel_api::error::{KapiError, KapiResult};
mod registration_api;
pub use registration_api::*;

// ============================================================================
// Driver Registry
// ============================================================================

/// Registered driver entry
struct DriverEntry {
    /// The driver instance
    driver: Box<dyn Driver>,
    /// Current state
    state: DriverState,
}

impl DriverEntry {
    fn new(driver: Box<dyn Driver>) -> Self {
        Self {
            driver,
            state: DriverState::Registered,
        }
    }
}

/// Global driver registry
pub struct DriverRegistry {
    /// All registered drivers
    drivers: PoisonLock<Vec<DriverEntry>>,
}

impl DriverRegistry {
    /// Create a new registry
    pub const fn new() -> Self {
        Self {
            drivers: PoisonLock::new(Vec::new()),
        }
    }

    /// Register a new driver
    ///
    /// Returns `Err(DriverError::Poisoned)` if the registry lock is poisoned.
    pub fn register(&self, driver: Box<dyn Driver>) -> Result<DriverHandle, DriverError> {
        let mut drivers = self.drivers.lock().map_err(|_| {
            log::error!("[DRIVER] Registry lock is poisoned during register!");
            DriverError::Poisoned
        })?;
        let id = drivers.len();

        log::info!(
            "[DRIVER] Registering driver: {} (type: {:?})\n",
            driver.name(),
            driver.driver_type()
        );

        drivers.push(DriverEntry::new(driver));
        Ok(DriverHandle(id))
    }

    /// Probe a specific driver
    pub fn probe(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut drivers = self.drivers.lock().map_err(|_| {
            log::error!("[DRIVER] Registry lock is poisoned during probe!");
            DriverError::Poisoned
        })?;
        let entry = drivers.get_mut(handle.0).ok_or(DriverError::NotFound)?;

        if entry.state != DriverState::Registered {
            return Err(DriverError::InvalidState);
        }

        log::info!("[DRIVER] Probing driver: {}\n", entry.driver.name());

        match entry.driver.probe() {
            Ok(()) => {
                entry.state = DriverState::Probed;
                log::info!("[DRIVER] Probe successful: {}\n", entry.driver.name());
                Ok(())
            }
            Err(e) => {
                entry.state = DriverState::Error;
                log::info!("[DRIVER] Probe failed: {} - {:?}\n", entry.driver.name(), e);
                Err(DriverError::ProbeFailed)
            }
        }
    }

    /// Start a probed driver
    pub fn start(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut drivers = self.drivers.lock().map_err(|_| {
            log::error!("[DRIVER] Registry lock is poisoned during start!");
            DriverError::Poisoned
        })?;
        let entry = drivers.get_mut(handle.0).ok_or(DriverError::NotFound)?;

        if entry.state != DriverState::Probed && entry.state != DriverState::Stopped {
            return Err(DriverError::InvalidState);
        }

        log::info!("[DRIVER] Starting driver: {}\n", entry.driver.name());

        match entry.driver.start() {
            Ok(()) => {
                entry.state = DriverState::Running;
                Ok(())
            }
            Err(e) => {
                entry.state = DriverState::Error;
                log::info!("[DRIVER] Start failed: {} - {:?}\n", entry.driver.name(), e);
                Err(DriverError::StartFailed)
            }
        }
    }

    /// Stop a running driver
    pub fn stop(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut drivers = self.drivers.lock().map_err(|_| {
            log::error!("[DRIVER] Registry lock is poisoned during stop!");
            DriverError::Poisoned
        })?;
        let entry = drivers.get_mut(handle.0).ok_or(DriverError::NotFound)?;

        if entry.state != DriverState::Running {
            return Err(DriverError::InvalidState);
        }

        log::info!("[DRIVER] Stopping driver: {}\n", entry.driver.name());

        match entry.driver.stop() {
            Ok(()) => {
                entry.state = DriverState::Stopped;
                Ok(())
            }
            Err(_e) => {
                entry.state = DriverState::Error;
                Err(DriverError::StopFailed)
            }
        }
    }

    /// Probe and start a driver in one call
    pub fn probe_and_start(&self, handle: DriverHandle) -> Result<(), DriverError> {
        self.probe(handle)?;
        self.start(handle)
    }

    /// Get driver state
    pub fn state(&self, handle: DriverHandle) -> Option<DriverState> {
        match self.drivers.lock() {
            Ok(guard) => guard.get(handle.0).map(|e| e.state),
            Err(_) => {
                log::error!("[DRIVER] Registry poisoned (state)");
                None
            }
        }
    }

    /// Get driver name
    pub fn name(&self, handle: DriverHandle) -> Option<String> {
        match self.drivers.lock() {
            Ok(guard) => guard.get(handle.0).map(|e| String::from(e.driver.name())),
            Err(_) => {
                log::error!("[DRIVER] Registry poisoned (name)");
                None
            }
        }
    }

    /// Find drivers by type
    pub fn find_by_type(&self, driver_type: DriverType) -> Vec<DriverHandle> {
        match self.drivers.lock() {
            Ok(guard) => guard
                .iter()
                .enumerate()
                .filter(|(_, e)| e.driver.driver_type() == driver_type)
                .map(|(i, _)| DriverHandle(i))
                .collect(),
            Err(_) => {
                log::error!("[DRIVER] Registry poisoned (find_by_type)");
                Vec::new()
            }
        }
    }

    /// Find driver that supports a device
    pub fn find_for_device(&self, device_id: &DeviceId) -> Option<DriverHandle> {
        match self.drivers.lock() {
            Ok(guard) => guard
                .iter()
                .enumerate()
                .find(|(_, e)| {
                    e.driver
                        .supported_devices()
                        .iter()
                        .any(|d| d.vendor == device_id.vendor && d.device == device_id.device)
                })
                .map(|(i, _)| DriverHandle(i)),
            Err(_) => {
                log::error!("[DRIVER] Registry poisoned (find_for_device)");
                None
            }
        }
    }

    /// Get count of registered drivers
    pub fn count(&self) -> usize {
        match self.drivers.lock() {
            Ok(g) => g.len(),
            Err(_) => {
                log::error!("[DRIVER] Registry poisoned (count)");
                0
            }
        }
    }

    /// Get count of running drivers
    pub fn running_count(&self) -> usize {
        match self.drivers.lock() {
            Ok(g) => g.iter().filter(|e| e.state == DriverState::Running).count(),
            Err(_) => {
                log::error!("[DRIVER] Registry poisoned (running_count)");
                0
            }
        }
    }

    /// List all drivers with their states
    pub fn list(&self) -> Vec<(DriverHandle, String, DriverType, DriverState)> {
        match self.drivers.lock() {
            Ok(g) => g
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    (
                        DriverHandle(i),
                        String::from(e.driver.name()),
                        e.driver.driver_type(),
                        e.state,
                    )
                })
                .collect(),
            Err(_) => {
                log::error!("[DRIVER] Registry poisoned (list)");
                Vec::new()
            }
        }
    }

    /// Probe all registered drivers
    pub fn probe_all(&self) {
        let count = self.count();
        for i in 0..count {
            if let Err(e) = self.probe(DriverHandle(i)) {
                log::warn!("[DRIVER] Probe failed for handle {}: {}", i, e);
            }
        }
    }

    /// Start all probed drivers
    pub fn start_all(&self) {
        let count = self.count();
        for i in 0..count {
            if self.state(DriverHandle(i)) == Some(DriverState::Probed) {
                if let Err(e) = self.start(DriverHandle(i)) {
                    log::warn!("[DRIVER] Start failed for handle {}: {}", i, e);
                }
            }
        }
    }

    /// Stop all running drivers
    pub fn stop_all(&self) {
        let count = self.count();
        for i in 0..count {
            if self.state(DriverHandle(i)) == Some(DriverState::Running) {
                if let Err(e) = self.stop(DriverHandle(i)) {
                    log::warn!("[DRIVER] Stop failed for handle {}: {}", i, e);
                }
            }
        }
    }

    /// Initialize all drivers (probe + start in one call)
    ///
    /// This is the main entry point for bulk driver initialization.
    /// Logs success/failure for each driver.
    pub fn init_all(&self) {
        let count = self.count();
        log::info!("[DRIVER] Initializing {} registered drivers...\n", count);

        for i in 0..count {
            let handle = DriverHandle(i);
            let name = self
                .name(handle)
                .unwrap_or_else(|| alloc::string::String::from("unknown"));

            log::info!("[DRIVER] Initializing: {}\n", name);

            match self.probe_and_start(handle) {
                Ok(()) => {
                    log::info!("[DRIVER] {} initialized successfully\n", name);
                }
                Err(e) => {
                    log::info!("[DRIVER] {} initialization failed: {:?}\n", name, e);
                }
            }
        }

        log::info!(
            "[DRIVER] Driver initialization complete: {}/{} running\n",
            self.running_count(),
            count
        );
    }

    /// Unregister a driver and replace it with a null driver to allow cell unloading
    pub fn unregister(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut drivers = self.drivers.lock().map_err(|_| {
            log::error!("[DRIVER] Registry lock is poisoned during unregister!");
            DriverError::Poisoned
        })?;
        let entry = drivers.get_mut(handle.0).ok_or(DriverError::NotFound)?;

        if entry.state == DriverState::Running {
            return Err(DriverError::InvalidState);
        }

        // Preserve driver name and type for logging
        let old_name = alloc::string::String::from(entry.driver.name());
        let old_ty = entry.driver.driver_type();

        // Try to remove driver resources first
        let _ = entry.driver.remove();

        // Replace the driver with a null implementation and mark removed
        entry.driver = Box::new(NullDriver::new(&old_name, old_ty));
        entry.state = DriverState::Removed;

        log::info!("[DRIVER] Unregistered driver: {}\n", old_name);
        Ok(())
    }

    /// Replace a driver implementation with a new one (Hot Swap)
    ///
    /// # Safety
    /// Caller must ensure that the new driver is compatible with the old one's state requirements
    /// if state migration is needed (currently starts fresh).
    /// The old driver instance is dropped, but its code memory must valid until quiescent state.
    pub fn replace_driver(
        &self,
        handle: DriverHandle,
        new_driver: Box<dyn Driver>,
    ) -> Result<(), DriverError> {
        let mut drivers = self.drivers.lock().map_err(|_| {
            log::error!("[DRIVER] Registry lock is poisoned during replace_driver!");
            DriverError::Poisoned
        })?;
        let entry = drivers.get_mut(handle.0).ok_or(DriverError::NotFound)?;

        log::info!(
            "[DRIVER] Replacing driver {} ({}) with new version\n",
            entry.driver.name(),
            handle.index()
        );

        // We assume the new driver is in Registered state initially?
        // Or do we expect it to be Probed/Started if the old one was?
        // For simplicity, we just swap the implementation and keep the *Registry* state as is?
        // No, the new driver instance is fresh. Its internal state is uninitialized.
        // So we should likely transition the entry state to `Registered`.
        // The caller (LiveUpdateManager) is responsible for re-probing/re-starting if needed.

        // Swap the driver
        entry.driver = new_driver;
        entry.state = DriverState::Registered; // Reset state to Registered

        Ok(())
    }
}

// ============================================================================
// Driver Handle
// ============================================================================

/// Handle to a registered driver
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverHandle(usize);

impl DriverHandle {
    /// Get the internal index
    pub fn index(&self) -> usize {
        self.0
    }

    /// Create a handle from an index (for shell commands)
    pub fn from_index(index: usize) -> Self {
        Self(index)
    }
}

// ============================================================================
// Driver Errors
// ============================================================================

/// Driver operation errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverError {
    /// Driver not found
    NotFound,
    /// Invalid state for operation
    InvalidState,
    /// Probe failed
    ProbeFailed,
    /// Start failed
    StartFailed,
    /// Stop failed
    StopFailed,
    /// Registry lock is poisoned (previous holder panicked)
    Poisoned,
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "driver not found"),
            Self::InvalidState => write!(f, "invalid driver state for operation"),
            Self::ProbeFailed => write!(f, "driver probe failed"),
            Self::StartFailed => write!(f, "driver start failed"),
            Self::StopFailed => write!(f, "driver stop failed"),
            Self::Poisoned => write!(f, "registry lock poisoned (holder panicked)"),
        }
    }
}

// ============================================================================
// Kernel API Table (DriverExportsV1)
// ============================================================================

extern "C" fn kapi_log(level: u32, msg_ptr: *const u8, msg_len: usize) {
    crate::io::log::early_print("[KAPI] log enter\n");
    if msg_ptr.is_null() || msg_len == 0 {
        crate::io::log::early_print("[KAPI] log empty\n");
        return;
    }

    crate::io::log::early_print("[KAPI] log slice\n");
    let slice = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
    crate::io::log::early_print("[KAPI] log utf8\n");
    let msg = match core::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return,
    };
    crate::io::log::early_print("[KAPI] log utf8 ok\n");

    // Avoid potential logger reentrancy/lock issues while DriverExports init runs
    // during early DriverDomain startup. Keep output visible via serial early logger.
    match level {
        2 => crate::io::log::early_print("[KAPI][ERR] "),
        1 => crate::io::log::early_print("[KAPI][WRN] "),
        _ => crate::io::log::early_print("[KAPI][INF] "),
    }
    crate::io::log::early_print(msg);
    crate::io::log::early_print("\n");
    crate::io::log::early_print("[KAPI] log done\n");
}

extern "C" fn kapi_alloc_dma_raw(size: usize, _align: usize, out: *mut AbiDmaSlice) -> i32 {
    if out.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }

    match kernel_api::service::kernel::instance().alloc_dma(size) {
        Ok(buffer) => {
            unsafe {
                *out = AbiDmaSlice {
                    phys_addr: buffer.physical_address(),
                    device_addr: buffer.device_address(),
                    virt_addr: buffer.as_ptr() as usize as u64,
                    size: buffer.size(),
                };
            }
            core::mem::forget(buffer);
            AbiErrorCode::Success as i32
        }
        Err(_) => AbiErrorCode::OutOfMemory as i32,
    }
}

extern "C" fn kapi_alloc_dma_for_device_raw(
    size: usize,
    device_id: u64,
    _align: usize,
    out: *mut AbiDmaSlice,
) -> i32 {
    if out.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }

    match kernel_api::service::kernel::instance().alloc_dma_for_device(size, device_id) {
        Ok(buffer) => {
            unsafe {
                *out = AbiDmaSlice {
                    phys_addr: buffer.physical_address(),
                    device_addr: buffer.device_address(),
                    virt_addr: buffer.as_ptr() as usize as u64,
                    size: buffer.size(),
                };
            }
            core::mem::forget(buffer);
            AbiErrorCode::Success as i32
        }
        Err(_) => AbiErrorCode::OutOfMemory as i32,
    }
}

extern "C" fn kapi_release_dma_raw(virt_addr: u64, size: usize, phys_addr: u64) -> i32 {
    if virt_addr == 0 || size == 0 {
        return AbiErrorCode::InvalidParam as i32;
    }

    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    unsafe {
        crate::service_impl::release_dma_buffer(virt_addr as usize as *mut u8, size, phys_addr);
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    let _ = (virt_addr, size, phys_addr);

    AbiErrorCode::Success as i32
}

extern "C" fn kapi_map_mmio(paddr: u64, size: usize, out: *mut AbiMmioHandle) -> i32 {
    if out.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }

    // Security: Prevent mapping of protected physical regions (Kernel, IOMMU, APIC, etc.)
    // This is critical for preventing malicious or buggy drivers from corrupting the system.
    if crate::security::dma::range_overlaps_protected(paddr, size as u64) {
        log::error!(
            "[KAPI][SECURITY] Driver attempted to map protected MMIO range: {:#x}-{:#x}",
            paddr,
            paddr + size as u64
        );
        return AbiErrorCode::PermissionDenied as i32;
    }

    let virt = crate::memory::phys_to_virt(x86_64::PhysAddr::new_truncate(paddr)).as_u64();
    unsafe {
        *out = AbiMmioHandle { base: virt, size };
    }
    AbiErrorCode::Success as i32
}

extern "C" fn kapi_unmap_mmio(_handle: *const AbiMmioHandle) -> i32 {
    AbiErrorCode::Success as i32
}

extern "C" fn kapi_port_read_u8(port: u16) -> u8 {
    kernel_api::service::kernel::instance().port_read_u8(port)
}

extern "C" fn kapi_port_write_u8(port: u16, value: u8) {
    kernel_api::service::kernel::instance().port_write_u8(port, value);
}

extern "C" fn kapi_irq_bind(_irq: u32, _cookie: u64) -> i32 {
    AbiErrorCode::NotSupported as i32
}

extern "C" fn kapi_irq_unbind(_irq: u32) -> i32 {
    AbiErrorCode::NotSupported as i32
}

extern "C" fn kapi_heap_alloc(size: usize) -> *mut u8 {
    use core::alloc::Layout;

    if size == 0 {
        return core::ptr::null_mut();
    }

    let layout = match Layout::from_size_align(size, 8) {
        Ok(l) => l,
        Err(_) => return core::ptr::null_mut(),
    };

    // SAFETY: Layout検証済み。グローバルアロケータに委譲。
    unsafe { alloc::alloc::alloc(layout) }
}

extern "C" fn kapi_heap_dealloc(ptr: *mut u8, size: usize) {
    use core::alloc::Layout;

    if ptr.is_null() || size == 0 {
        return;
    }

    let layout = match Layout::from_size_align(size, 8) {
        Ok(l) => l,
        Err(_) => return,
    };

    // SAFETY: ptrは非null検証済み。layoutはkapi_heap_allocと同一のアライメントで構築。
    unsafe { alloc::alloc::dealloc(ptr, layout) }
}

extern "C" fn kapi_panic_abort(msg_ptr: *const u8, msg_len: usize) -> ! {
    if !msg_ptr.is_null() && msg_len > 0 {
        let slice = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
        if let Ok(s) = core::str::from_utf8(slice) {
            log::error!(target: "cell", "Cell panic: {}", s);
        }
    }
    panic!("Cell panic - aborting");
}

#[unsafe(no_mangle)]
pub static __exorust_kernel_api_v2: KernelApiV2 = KernelApiV2 {
    abi_version: KERNEL_API_ABI_VERSION,
    abi_size: core::mem::size_of::<KernelApiV2>() as u32,
    log: kapi_log,
    alloc_dma_raw: kapi_alloc_dma_raw,
    alloc_dma_for_device_raw: kapi_alloc_dma_for_device_raw,
    release_dma_raw: kapi_release_dma_raw,
    map_mmio: kapi_map_mmio,
    unmap_mmio: kapi_unmap_mmio,
    port_read_u8: kapi_port_read_u8,
    port_write_u8: kapi_port_write_u8,
    irq_bind: kapi_irq_bind,
    irq_unbind: kapi_irq_unbind,
    heap_alloc: Some(kapi_heap_alloc),
    heap_dealloc: Some(kapi_heap_dealloc),
    panic_abort: Some(kapi_panic_abort),
    reserved: [0; 8],
};

pub(crate) fn kernel_api_v2() -> &'static KernelApiV2 {
    &__exorust_kernel_api_v2
}

// ============================================================================
// Global Instance
// ============================================================================

/// Global driver registry
static DRIVER_REGISTRY: DriverRegistry = DriverRegistry::new();

/// Get the global driver registry
pub fn driver_registry() -> &'static DriverRegistry {
    &DRIVER_REGISTRY
}

/// Register a driver (convenience function)
pub fn register_driver(driver: Box<dyn Driver>) -> Result<DriverHandle, DriverError> {
    DRIVER_REGISTRY.register(driver)
}

/// Initialize all registered drivers (probe + start)
///
/// This is the simplified API for main.rs to call after registering all drivers.
pub fn init_all_drivers() {
    DRIVER_REGISTRY.init_all()
}

fn build_abi_driver(
    entry: AbiEntryFn,
    exports_fini: Option<extern "C" fn() -> i32>,
) -> Result<Box<dyn Driver>, DriverError> {
    // Call the entry to get vtable pointer
    crate::io::log::early_print("[DRIVER] build_abi_driver: entry()\n");
    let vtable_ptr = entry();
    crate::io::log::early_print("[DRIVER] build_abi_driver: entry done\n");
    if vtable_ptr.is_null() {
        return Err(DriverError::InvalidState);
    }
    if (vtable_ptr as usize) % core::mem::align_of::<AbiDriverVTable>() != 0 {
        log::error!(
            "[DRIVER] ABI vtable pointer is unaligned: ptr={:#x}, align={}",
            vtable_ptr as usize,
            core::mem::align_of::<AbiDriverVTable>()
        );
        return Err(DriverError::InvalidState);
    }

    let vtable = unsafe { &*vtable_ptr };

    // Validate ABI version
    crate::io::log::early_print("[DRIVER] build_abi_driver: validate\n");
    if vtable.validate().is_err() {
        return Err(DriverError::InvalidState);
    }
    crate::io::log::early_print("[DRIVER] build_abi_driver: validate done\n");

    // Read name
    let name_ptr = (vtable.name)();
    let name_len = (vtable.name_len)();
    let name = if name_ptr.is_null() || name_len == 0 {
        alloc::string::String::from("abi_driver")
    } else {
        let bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
        alloc::string::String::from_utf8_lossy(bytes).into_owned()
    };
    crate::io::log::early_print("[DRIVER] build_abi_driver: name done\n");

    // Build AbiDriver wrapper
    let abi_driver = Box::new(AbiDriver {
        vtable: vtable_ptr,
        name,
        ctx: AbiDriverContext::new(),
        exports_fini,
    });

    Ok(abi_driver)
}

pub(crate) struct PreparedDriverExports {
    pub entry: AbiEntryFn,
    pub fini: Option<extern "C" fn() -> i32>,
}

pub(crate) fn prepare_driver_exports(
    exports: *const DriverExportsV1,
    call_init: bool,
) -> Result<PreparedDriverExports, DriverError> {
    if exports.is_null() {
        return Err(DriverError::InvalidState);
    }
    if (exports as usize) % core::mem::align_of::<DriverExportsV1>() != 0 {
        log::error!(
            "[DRIVER] DriverExports pointer is unaligned: ptr={:#x}, align={}",
            exports as usize,
            core::mem::align_of::<DriverExportsV1>()
        );
        return Err(DriverError::InvalidState);
    }

    let exports_ref = unsafe { &*exports };
    crate::io::log::early_print("[DRIVER] exports ptr=");
    crate::io::log::early_print_hex(exports as usize as u64);
    crate::io::log::early_print(" abi_ver=");
    crate::io::log::early_print_hex(exports_ref.abi_version as u64);
    crate::io::log::early_print(" abi_size=");
    crate::io::log::early_print_hex(exports_ref.abi_size as u64);
    crate::io::log::early_print("\n");
    crate::io::log::early_print("[DRIVER] exports entry=");
    crate::io::log::early_print_hex(exports_ref.entry as usize as u64);
    crate::io::log::early_print(" init=");
    crate::io::log::early_print_hex(exports_ref.init.map_or(0, |f| f as usize as u64));
    crate::io::log::early_print(" fini=");
    crate::io::log::early_print_hex(exports_ref.fini.map_or(0, |f| f as usize as u64));
    crate::io::log::early_print("\n");

    if exports_ref.abi_version != DRIVER_EXPORTS_ABI_VERSION {
        log::error!(
            "[DRIVER] DriverExports ABI mismatch: expected {}, got {}",
            DRIVER_EXPORTS_ABI_VERSION,
            exports_ref.abi_version
        );
        return Err(DriverError::InvalidState);
    }

    let min_size = core::mem::size_of::<DriverExportsV1>() as u32;
    if exports_ref.abi_size < min_size {
        log::error!(
            "[DRIVER] DriverExports ABI size too small: expected >= {}, got {}",
            min_size,
            exports_ref.abi_size
        );
        return Err(DriverError::InvalidState);
    }

    if call_init {
        if let Some(init) = exports_ref.init {
            crate::io::log::early_print("[DRIVER] prepare_exports: init()\n");
            crate::io::log::early_print("[DRIVER] kernel_api_v1 ptr=");
            crate::io::log::early_print_hex(kernel_api_v2() as *const KernelApiV2 as usize as u64);
            crate::io::log::early_print("\n");
            let init_addr = init as usize;
            let init_virt = crate::mm::virt::higher_half::VirtAddr::new(init_addr as u64);
            #[cfg(any(not(test), feature = "full_mm_tests"))]
            {
                if let Some(pte) = crate::mm::virt::higher_half::get_current_pte(init_virt) {
                    let pte_raw = pte.as_u64();
                    let pte_flags = pte.flags().as_u64();
                    crate::io::log::early_print("[DRIVER] init pte raw=");
                    crate::io::log::early_print_hex(pte_raw);
                    crate::io::log::early_print(" flags=");
                    crate::io::log::early_print_hex(pte_flags);
                    crate::io::log::early_print(" user=");
                    crate::io::log::early_print(
                        if (pte_flags & crate::mm::virt::higher_half::PageFlags::USER) != 0 {
                            "1"
                        } else {
                            "0"
                        },
                    );
                    crate::io::log::early_print(" nx=");
                    crate::io::log::early_print(
                        if (pte_flags & crate::mm::virt::higher_half::PageFlags::NO_EXECUTE) != 0 {
                            "1"
                        } else {
                            "0"
                        },
                    );
                    crate::io::log::early_print("\n");
                } else {
                    crate::io::log::early_print("[DRIVER] init pte lookup failed\n");
                }
            }
            #[cfg(not(any(not(test), feature = "full_mm_tests")))]
            {
                let _ = init_virt;
                crate::io::log::early_print("[DRIVER] init pte lookup skipped in test shim\n");
            }
            let res = init(kernel_api_v2() as *const KernelApiV2);
            crate::io::log::early_print("[DRIVER] prepare_exports: init done\n");
            if !AbiErrorCode::from_raw(res).is_success() {
                log::error!("[DRIVER] DriverExports init failed: code={}", res);
                return Err(DriverError::InvalidState);
            }
        }
    }

    Ok(PreparedDriverExports {
        entry: exports_ref.entry,
        fini: exports_ref.fini,
    })
}
