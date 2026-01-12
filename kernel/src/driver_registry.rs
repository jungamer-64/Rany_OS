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
use kernel_api::driver::{DeviceId, Driver, DriverState, DriverType};
use kernel_api::driver_abi::{
    AbiDriverType, AbiError as AbiErrorCode, DriverCapabilities as AbiDriverCapabilities,
    DriverContext as AbiDriverContext, DriverEntryFn as AbiEntryFn,
    DriverVTable as AbiDriverVTable,
};
use kernel_api::error::{KapiError, KapiResult};

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

/// Register a driver implemented as an ABI vtable
pub fn register_abi_driver(entry: AbiEntryFn) -> Result<DriverHandle, DriverError> {
    // Call the entry to get vtable pointer
    let vtable_ptr = entry();
    if vtable_ptr.is_null() {
        return Err(DriverError::InvalidState);
    }

    let vtable = unsafe { &*vtable_ptr };

    // Validate ABI version
    match vtable.validate() {
        Ok(()) => {}
        Err(_) => return Err(DriverError::InvalidState),
    }

    // Read name
    let name_ptr = (vtable.name)();
    let name_len = (vtable.name_len)();
    let name = if name_ptr.is_null() || name_len == 0 {
        alloc::string::String::from("abi_driver")
    } else {
        let bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
        alloc::string::String::from_utf8_lossy(bytes).into_owned()
    };

    // Build AbiDriver wrapper
    let abi_driver = Box::new(AbiDriver {
        vtable: vtable_ptr,
        name,
        ctx: AbiDriverContext::new(),
    });

    DRIVER_REGISTRY.register(abi_driver)
}

/// Unregister a driver by handle
pub fn unregister_driver(handle: DriverHandle) -> Result<(), DriverError> {
    DRIVER_REGISTRY.unregister(handle)
}

/// Update an existing driver with a new ABI implementation
pub fn update_abi_driver(handle: DriverHandle, entry: AbiEntryFn) -> Result<(), DriverError> {
    // Call the entry to get vtable pointer
    let vtable_ptr = entry();
    if vtable_ptr.is_null() {
        return Err(DriverError::InvalidState);
    }

    let vtable = unsafe { &*vtable_ptr };

    // Validate ABI version
    match vtable.validate() {
        Ok(()) => {}
        Err(_) => return Err(DriverError::InvalidState),
    }

    // Read name
    let name_ptr = (vtable.name)();
    let name_len = (vtable.name_len)();
    let name = if name_ptr.is_null() || name_len == 0 {
        alloc::string::String::from("abi_driver")
    } else {
        let bytes = unsafe { core::slice::from_raw_parts(name_ptr, name_len) };
        alloc::string::String::from_utf8_lossy(bytes).into_owned()
    };

    // Build AbiDriver wrapper
    let abi_driver = Box::new(AbiDriver {
        vtable: vtable_ptr,
        name,
        ctx: AbiDriverContext::new(),
    });

    DRIVER_REGISTRY.replace_driver(handle, abi_driver)
}

// Adapter to delegate trait calls to ABI vtable
struct AbiDriver {
    vtable: *const AbiDriverVTable,
    name: alloc::string::String,
    ctx: AbiDriverContext,
}

// Safety: AbiDriver contains a raw pointer to a statically allocated vtable that
// is anchored in the driver binary memory. We ensure that the pointer remains
// valid during the driver lifetime (loader must hold driver loaded) and so
// it is safe to mark Send/Sync for sharing across kernel threads.
unsafe impl Send for AbiDriver {}
unsafe impl Sync for AbiDriver {}

impl AbiDriver {
    fn vtable(&self) -> &AbiDriverVTable {
        unsafe { &*self.vtable }
    }

    fn map_abi_error(code: i32) -> Result<(), KapiError> {
        let abi = AbiErrorCode::from_raw(code);
        match abi {
            AbiErrorCode::Success => Ok(()),
            AbiErrorCode::DeviceNotFound => Err(KapiError::NotFound),
            AbiErrorCode::OutOfMemory => Err(KapiError::OutOfMemory),
            AbiErrorCode::NotSupported => Err(KapiError::NotSupported),
            // generic fallback
            _ => Err(KapiError::Internal(code)),
        }
    }
}

/// A null driver used to replace unregistered drivers in the registry.
struct NullDriver {
    name: alloc::string::String,
    ty: DriverType,
}

impl NullDriver {
    fn new(name: &str, ty: DriverType) -> Self {
        Self {
            name: alloc::string::String::from(name),
            ty,
        }
    }
}

impl Driver for NullDriver {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> kernel_api::driver::DriverVersion {
        kernel_api::driver::DriverVersion::new(0, 0, 0)
    }

    fn driver_type(&self) -> DriverType {
        self.ty
    }

    fn probe(&mut self) -> KapiResult<()> {
        Err(KapiError::NotSupported)
    }

    fn start(&mut self) -> KapiResult<()> {
        Err(KapiError::NotSupported)
    }

    fn stop(&mut self) -> KapiResult<()> {
        Ok(())
    }

    fn supported_devices(&self) -> &[kernel_api::driver::DeviceId] {
        &[]
    }
}

impl Driver for AbiDriver {
    fn name(&self) -> &str {
        &self.name
    }

    fn version(&self) -> kernel_api::driver::DriverVersion {
        let v = (self.vtable().version)();
        let (major, minor, patch) = kernel_api::driver_abi::unpack_version(v);
        kernel_api::driver::DriverVersion::new(major, minor, patch)
    }

    fn driver_type(&self) -> DriverType {
        let t = (self.vtable().driver_type)();
        match t {
            x if x == AbiDriverType::Pci as u32 => DriverType::Pci,
            x if x == AbiDriverType::Usb as u32 => DriverType::Usb,
            x if x == AbiDriverType::Block as u32 => DriverType::Block,
            x if x == AbiDriverType::Network as u32 => DriverType::Network,
            x if x == AbiDriverType::Hid as u32 => DriverType::Hid,
            x if x == AbiDriverType::Graphics as u32 => DriverType::Graphics,
            x if x == AbiDriverType::Serial as u32 => DriverType::Serial,
            _ => DriverType::Other,
        }
    }

    fn probe(&mut self) -> KapiResult<()> {
        // Request capabilities if present
        if let Some(req) = self.vtable().request_capabilities {
            let mut caps = AbiDriverCapabilities::default();
            req(&mut caps);
            // We ignore capabilities for now; future work: map to kernel capabilities
        }

        let res = (self.vtable().probe)(&mut self.ctx as *mut _);
        match Self::map_abi_error(res) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn start(&mut self) -> KapiResult<()> {
        let res = (self.vtable().start)(&mut self.ctx as *mut _);
        Self::map_abi_error(res)
    }

    fn stop(&mut self) -> KapiResult<()> {
        let res = (self.vtable().stop)(&mut self.ctx as *mut _);
        Self::map_abi_error(res)
    }

    fn remove(&mut self) -> KapiResult<()> {
        let res = (self.vtable().remove)(&mut self.ctx as *mut _);
        Self::map_abi_error(res)
    }

    fn supported_devices(&self) -> &[DeviceId] {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::loader::{unload_cell, with_registry_mut};
    use alloc::string::String;
    use core::sync::atomic::{AtomicBool, Ordering};
    use kernel_api::driver_abi::{
        AbiDriverType, DRIVER_ABI_VERSION, DriverContext, DriverVTable,
    };

    static PROBE_CALLED: AtomicBool = AtomicBool::new(false);
    static REMOVE_CALLED: AtomicBool = AtomicBool::new(false);

    extern "C" fn probe(_ctx: *mut DriverContext) -> i32 {
        PROBE_CALLED.store(true, Ordering::SeqCst);
        0
    }

    extern "C" fn start(_ctx: *mut DriverContext) -> i32 {
        0
    }
    extern "C" fn stop(_ctx: *mut DriverContext) -> i32 {
        0
    }
    extern "C" fn remove(_ctx: *mut DriverContext) -> i32 {
        REMOVE_CALLED.store(true, Ordering::SeqCst);
        0
    }

    static NAME_BYTES: &[u8] = b"test_abi_driver\0";

    extern "C" fn name_fn() -> *const u8 {
        NAME_BYTES.as_ptr()
    }
    extern "C" fn name_len_fn() -> usize {
        NAME_BYTES.len() - 1
    }
    extern "C" fn type_fn() -> u32 {
        AbiDriverType::Block as u32
    }
    extern "C" fn version_fn() -> u64 {
        0
    }

    static VTABLE: DriverVTable = DriverVTable::new(
        DRIVER_ABI_VERSION,
        probe,
        start,
        stop,
        remove,
        name_fn,
        name_len_fn,
        type_fn,
        version_fn,
        None,
        None,
    );

    extern "C" fn entry_fn() -> *const DriverVTable {
        &VTABLE
    }

    #[test_case]
    fn test_register_abi_driver_and_block_unload() {
        // Register driver
        let handle = register_abi_driver(entry_fn).expect("register failed");

        // Probe driver
        let _ = DRIVER_REGISTRY.probe(handle);
        assert!(PROBE_CALLED.load(Ordering::SeqCst));

        // Allocate and register a fake cell
        let cell_id = with_registry_mut(|r| {
            let id = r.allocate_id();
            let entry = crate::loader::CellEntry {
                id,
                name: String::from("test-cell"),
                state: crate::loader::CellState::Loaded,
                load_address: 0, // test: no real allocation
                load_size: 0,
                entry_point: None,
                exports: Vec::new(),
                imports: Vec::new(),
                dependencies: Vec::new(),
                is_safe: true,
                signature_verified: true,
                registered_drivers: alloc::vec![handle],
                pkey: None,
                stats: crate::loader::ModuleStats::default(),
            };
            r.register(entry);
            id
        });

        // Attempt to unload - should fail because driver is registered
        let res = unload_cell(cell_id);
        assert!(res.is_err());

        // Unregister the driver and try again
        let _ = crate::loader::unload_driver(handle).expect("unregister failed");
        assert!(REMOVE_CALLED.load(Ordering::SeqCst));
        let res2 = unload_cell(cell_id);
        assert!(res2.is_ok());
    }

    #[test_case]
    fn test_unregister_running_fails() {
        // Register driver
        let handle = register_abi_driver(entry_fn).expect("register failed");

        // Probe and start driver
        let _ = DRIVER_REGISTRY.probe(handle);
        let _ = DRIVER_REGISTRY.start(handle);

        // Attempt to unload driver while running - should fail
        let res = crate::loader::unload_driver(handle);
        assert!(res.is_err());
    }

    #[test_case]
    fn test_registry_poisoned_readers_return_defaults() {
        use crate::sync::set_panicking;

        let reg = DriverRegistry::new();

        // Poison the registry lock
        set_panicking(true);
        if let Ok(_g) = reg.drivers.lock() {
            // dropping _g while panicking will mark the lock as poisoned
        }
        set_panicking(false);

        assert_eq!(reg.count(), 0);
        assert!(reg.list().is_empty());
        assert_eq!(reg.find_by_type(DriverType::Block).len(), 0);
        assert!(reg.name(DriverHandle(0)).is_none());
    }
}

