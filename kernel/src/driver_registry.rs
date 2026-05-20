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
extern crate alloc;

use crate::sync::PoisonLock;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::AtomicBool;
use kernel_api::abi::driver::{
    AbiBlockDeviceRegistration, AbiDmaSlice, AbiDriverType, AbiError as AbiErrorCode,
    AbiMmioHandle, AbiMsixVectorInfo, AbiNetPortRegistration, AbiNvmeNamespaceRegistration,
    AbiRRefRaw, DRIVER_EXPORTS_ABI_VERSION, DriverCapabilities as AbiDriverCapabilities,
    DriverContext as AbiDriverContext, DriverEntryFn as AbiEntryFn, DriverExportsV1,
    DriverVTable as AbiDriverVTable, KERNEL_API_ABI_VERSION, KernelApiV4, PackedPciLocation,
};
use kernel_api::driver::DriverStateBlob;
use kernel_api::driver::{DeviceId, Driver, DriverState, DriverType};
use kernel_api::error::{KapiError, KapiResult};
use kernel_api::ipc::ChannelHandle;
use kernel_api::provider::ProviderDescriptorV1;
mod registration_api;
pub use registration_api::*;

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
fn cleanup_runtime_resources_for_driver_handle(handle: DriverHandle) {
    crate::resource_registry::cleanup_for_driver_handle(handle);
}

#[cfg(all(
    test,
    not(feature = "full_mm_tests"),
    not(feature = "qemu-test-export")
))]
fn cleanup_runtime_resources_for_driver_handle(_handle: DriverHandle) {}

#[derive(Clone)]
struct IrqBinding {
    owner: crate::domain::DomainId,
    stop: Arc<AtomicBool>,
    cookie: u64,
}

static IRQ_BINDINGS: PoisonLock<BTreeMap<u8, IrqBinding>> = PoisonLock::new(BTreeMap::new());

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
fn resolve_single_driver_handle_for_domain(
    domain: crate::domain::DomainId,
) -> Result<DriverHandle, KapiError> {
    let manager = crate::driver_domain::driver_domain_manager();
    let Some(id) = manager.find_by_domain(domain) else {
        return Err(KapiError::NotSupported);
    };

    let handles = manager
        .with_cell(id, |cell| cell.driver_handles.clone())
        .map_err(|_| KapiError::NotFound)?;
    match handles.as_slice() {
        [handle] => Ok(*handle),
        _ => Err(KapiError::NotSupported),
    }
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
fn resolve_single_driver_handle_for_domain(
    _domain: crate::domain::DomainId,
) -> Result<DriverHandle, KapiError> {
    Err(KapiError::NotSupported)
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
fn force_unbind_irq(vector: u8) -> Option<IrqBinding> {
    let binding = IRQ_BINDINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&vector)?;
    binding
        .stop
        .store(true, core::sync::atomic::Ordering::Release);
    crate::task::interrupt_waker::wake_from_interrupt(
        crate::task::interrupt_waker::InterruptSource::Irq(vector),
    );
    Some(binding)
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
fn force_unbind_irq(vector: u8) -> Option<IrqBinding> {
    IRQ_BINDINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&vector)
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
fn bind_irq_for_current_domain(irq: u32, cookie: u64) -> KapiResult<()> {
    let vector = u8::try_from(irq).map_err(|_| KapiError::InvalidHandle)?;
    let owner = crate::task::context::current_subject().domain;
    let owner_info = crate::io::msix::owner_for_vector(vector).ok_or(KapiError::InvalidHandle)?;
    if owner_info.owner != owner {
        return Err(KapiError::PermissionDenied);
    }

    let handle = resolve_single_driver_handle_for_domain(owner)?;
    if !driver_registry().has_irq_handler(handle) {
        return Err(KapiError::NotSupported);
    }

    let stop = Arc::new(AtomicBool::new(false));
    {
        let mut bindings = IRQ_BINDINGS.lock().unwrap_or_else(|e| e.into_inner());
        if bindings.contains_key(&vector) {
            return Err(KapiError::AlreadyExists);
        }
        bindings.insert(
            vector,
            IrqBinding {
                owner,
                stop: stop.clone(),
                cookie,
            },
        );
    }

    crate::task::spawn_detached_in_domain(
        async move {
            let source = crate::task::interrupt_waker::InterruptSource::Irq(vector);
            // LOOP_PROOF: mode=event; reason=Interrupt forwarder loop exits once the stop flag is observed and otherwise waits for the next IRQ event.;
            loop {
                if stop.load(core::sync::atomic::Ordering::Acquire) {
                    break;
                }

                crate::task::interrupt_waker::wait_for_interrupt(source).await;
                if stop.load(core::sync::atomic::Ordering::Acquire) {
                    break;
                }

                let _ = driver_registry().dispatch_irq(handle, vector as u32);
            }

            crate::task::interrupt_waker::interrupt_waker_registry().unregister(source);
        },
        owner,
    );

    Ok(())
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
fn bind_irq_for_current_domain(_irq: u32, _cookie: u64) -> KapiResult<()> {
    Err(KapiError::NotSupported)
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
fn unbind_irq_for_current_domain(irq: u32) -> KapiResult<()> {
    let vector = u8::try_from(irq).map_err(|_| KapiError::InvalidHandle)?;
    let owner = crate::task::context::current_subject().domain;
    let binding = IRQ_BINDINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&vector)
        .cloned();
    match binding {
        Some(binding) if binding.owner == owner => {
            let _ = binding.cookie;
        }
        Some(_) => return Err(KapiError::PermissionDenied),
        None => return Err(KapiError::NotFound),
    }

    if force_unbind_irq(vector).is_some() {
        Ok(())
    } else {
        Err(KapiError::NotFound)
    }
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
fn unbind_irq_for_current_domain(_irq: u32) -> KapiResult<()> {
    Err(KapiError::NotSupported)
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
pub(crate) fn unbind_irqs_for_owner(owner: crate::domain::DomainId, vectors: &[u8]) {
    for &vector in vectors {
        let should_unbind = IRQ_BINDINGS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&vector)
            .map(|binding| binding.owner == owner)
            .unwrap_or(false);
        if should_unbind {
            let _ = force_unbind_irq(vector);
        }
    }
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
pub(crate) fn unbind_irqs_for_owner(_owner: crate::domain::DomainId, _vectors: &[u8]) {}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
fn cleanup_msix_for_driver_handle(handle: DriverHandle) {
    let manager = crate::driver_domain::driver_domain_manager();
    let Some(id) = manager.find_by_driver_handle(handle) else {
        return;
    };

    let Ok((domain, locator)) = manager.with_cell(id, |cell| {
        (cell.domain_id, cell.abi_driver_context.pci_location())
    }) else {
        return;
    };
    let Some(domain) = domain else {
        return;
    };
    if locator.is_null() {
        return;
    }

    if let Ok(vectors) = crate::io::msix::owned_vectors(domain, locator) {
        unbind_irqs_for_owner(domain, &vectors);
        let _ = crate::io::msix::disable_for_owner(domain, locator);
    }
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
fn cleanup_msix_for_driver_handle(_handle: DriverHandle) {}

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

    #[cfg(test)]
    fn reset_for_tests(&self) {
        let mut drivers = self.drivers.lock().unwrap_or_else(|e| e.into_inner());
        drivers.clear();
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
        let provider_descriptors = {
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
                    entry.driver.provider_descriptors().to_vec()
                }
                Err(e) => {
                    entry.state = DriverState::Error;
                    log::info!("[DRIVER] Start failed: {} - {:?}\n", entry.driver.name(), e);
                    return Err(DriverError::StartFailed);
                }
            }
        };

        if !provider_descriptors.is_empty() {
            crate::provider_registry::provider_registry()
                .register_driver_descriptors(handle, &provider_descriptors);
        }

        Ok(())
    }

    /// Stop a running driver
    pub fn stop(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let result = {
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
        };

        if result.is_ok() {
            cleanup_msix_for_driver_handle(handle);
            cleanup_runtime_resources_for_driver_handle(handle);
            crate::provider_registry::provider_registry().unregister_driver(handle);
        }

        result
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

        cleanup_msix_for_driver_handle(handle);
        cleanup_runtime_resources_for_driver_handle(handle);
        crate::provider_registry::provider_registry().unregister_driver(handle);

        // Try to remove driver resources first
        let _ = entry.driver.remove();

        // Replace the driver with a null implementation and mark removed
        entry.driver = Box::new(NullDriver::new(&old_name, old_ty));
        entry.state = DriverState::Removed;

        log::info!("[DRIVER] Unregistered driver: {}\n", old_name);
        Ok(())
    }

    pub(crate) fn has_irq_handler(&self, handle: DriverHandle) -> bool {
        match self.drivers.lock() {
            Ok(drivers) => drivers
                .get(handle.0)
                .map(|entry| entry.driver.has_irq_handler())
                .unwrap_or(false),
            Err(_) => {
                log::error!("[DRIVER] Registry poisoned (has_irq_handler)");
                false
            }
        }
    }

    pub(crate) fn dispatch_irq(&self, handle: DriverHandle, irq: u32) -> bool {
        match self.drivers.lock() {
            Ok(mut drivers) => {
                let Some(entry) = drivers.get_mut(handle.0) else {
                    return false;
                };
                if entry.state != DriverState::Running {
                    return false;
                }
                entry.driver.handle_irq(irq)
            }
            Err(_) => {
                log::error!("[DRIVER] Registry poisoned (dispatch_irq)");
                false
            }
        }
    }

    pub(crate) fn driver_abi_context(&self, handle: DriverHandle) -> Option<AbiDriverContext> {
        match self.drivers.lock() {
            Ok(drivers) => drivers
                .get(handle.0)
                .and_then(|entry| entry.driver.abi_context()),
            Err(_) => None,
        }
    }

    pub(crate) fn export_live_state(
        &self,
        handle: DriverHandle,
    ) -> Result<Option<DriverStateBlob>, DriverError> {
        let drivers = self.drivers.lock().map_err(|_| DriverError::Poisoned)?;
        let entry = drivers.get(handle.0).ok_or(DriverError::NotFound)?;
        entry
            .driver
            .export_live_state()
            .map_err(|_| DriverError::InvalidState)
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

        cleanup_msix_for_driver_handle(handle);
        cleanup_runtime_resources_for_driver_handle(handle);
        crate::provider_registry::provider_registry().unregister_driver(handle);

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

extern "C" fn kapi_alloc_dma_for_device_raw(
    size: usize,
    device_id: u64,
    align: usize,
    out: *mut AbiDmaSlice,
) -> i32 {
    if out.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }

    unsafe {
        *out = AbiDmaSlice::default();
    }

    if size == 0 || align == 0 || !align.is_power_of_two() {
        return AbiErrorCode::InvalidParam as i32;
    }

    if align > crate::mm::types::PAGE_SIZE_4K {
        return AbiErrorCode::NotSupported as i32;
    }

    match kernel_api::service::kernel::instance()
        .alloc_dma_for_device(size, PackedPciLocation::from_raw(device_id))
    {
        Ok(buffer) => {
            unsafe {
                *out = AbiDmaSlice {
                    dma_handle_id: buffer.dma_handle_id(),
                    device_addr: buffer.device_address(),
                    virt_addr: buffer.as_ptr() as usize as u64,
                    size: buffer.size(),
                };
            }
            core::mem::forget(buffer);
            AbiErrorCode::Success as i32
        }
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_release_dma_raw(dma_handle_id: u64) -> i32 {
    if dma_handle_id == 0 {
        return AbiErrorCode::InvalidParam as i32;
    }

    #[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
    {
        match crate::kapi::memory::release_dma_buffer_checked(dma_handle_id) {
            Ok(()) => return AbiErrorCode::Success as i32,
            Err(err) => return map_kapi_error_to_abi(err),
        }
    }

    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        let _ = dma_handle_id;
        AbiErrorCode::InvalidParam as i32
    }
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

    let virt =
        crate::mm::virt::mapping::phys_to_virt(x86_64::PhysAddr::new_truncate(paddr)).as_u64();
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

extern "C" fn kapi_enable_msix_raw(
    device_id: u64,
    requested_count: u16,
    out_vectors: *mut AbiMsixVectorInfo,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    if written.is_null() || requested_count == 0 {
        return AbiErrorCode::InvalidParam as i32;
    }
    if capacity < requested_count as usize || out_vectors.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }

    unsafe {
        *written = 0;
    }

    match kernel_api::service::kernel::instance()
        .enable_msix(PackedPciLocation::from_raw(device_id), requested_count)
    {
        Ok(vectors) => {
            if vectors.len() != requested_count as usize {
                return AbiErrorCode::IoError as i32;
            }

            for (idx, vector) in vectors.into_iter().enumerate() {
                unsafe {
                    *out_vectors.add(idx) = AbiMsixVectorInfo {
                        vector: vector.vector,
                        table_index: vector.table_index,
                        reserved: 0,
                    };
                }
            }
            unsafe {
                *written = requested_count as usize;
            }
            AbiErrorCode::Success as i32
        }
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_disable_msix_raw(device_id: u64) -> i32 {
    match kernel_api::service::kernel::instance()
        .disable_msix(PackedPciLocation::from_raw(device_id))
    {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_irq_bind(irq: u32, cookie: u64) -> i32 {
    match bind_irq_for_current_domain(irq, cookie) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_irq_unbind(irq: u32) -> i32 {
    match unbind_irq_for_current_domain(irq) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
}

fn map_kapi_error_to_abi(err: KapiError) -> i32 {
    match err {
        KapiError::OutOfMemory => AbiErrorCode::OutOfMemory as i32,
        KapiError::PermissionDenied => AbiErrorCode::PermissionDenied as i32,
        KapiError::NotSupported => AbiErrorCode::NotSupported as i32,
        KapiError::Timeout => AbiErrorCode::Timeout as i32,
        KapiError::NotFound => AbiErrorCode::DeviceNotFound as i32,
        KapiError::AlreadyExists => AbiErrorCode::AlreadyInitialized as i32,
        KapiError::ResourceExhausted => AbiErrorCode::DeviceBusy as i32,
        KapiError::InvalidHandle => AbiErrorCode::InvalidParam as i32,
        _ => AbiErrorCode::IoError as i32,
    }
}

extern "C" fn kapi_register_block_device(
    registration: *const AbiBlockDeviceRegistration,
    out_handle: *mut u64,
) -> i32 {
    if registration.is_null() || out_handle.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let registration = unsafe { &*registration };
    match kernel_api::service::kernel::instance().register_block_device(registration) {
        Ok(handle) => {
            unsafe { *out_handle = handle };
            AbiErrorCode::Success as i32
        }
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_unregister_block_device(handle: u64) -> i32 {
    match kernel_api::service::kernel::instance().unregister_block_device(handle) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_register_nvme_namespace(
    registration: *const AbiNvmeNamespaceRegistration,
    out_handle: *mut u64,
) -> i32 {
    if registration.is_null() || out_handle.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let registration = unsafe { &*registration };
    match kernel_api::service::kernel::instance().register_nvme_namespace(registration) {
        Ok(handle) => {
            unsafe { *out_handle = handle };
            AbiErrorCode::Success as i32
        }
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_unregister_nvme_namespace(handle: u64) -> i32 {
    match kernel_api::service::kernel::instance().unregister_nvme_namespace(handle) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_register_netdev_port(
    registration: *const AbiNetPortRegistration,
    out_handle: *mut u64,
) -> i32 {
    if registration.is_null() || out_handle.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let registration = unsafe { &*registration };
    match kernel_api::service::kernel::instance().register_netdev_port(registration) {
        Ok(handle) => {
            unsafe { *out_handle = handle };
            AbiErrorCode::Success as i32
        }
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_unregister_netdev_port(handle: u64) -> i32 {
    match kernel_api::service::kernel::instance().unregister_netdev_port(handle) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
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

extern "C" fn kapi_current_domain_id() -> u64 {
    #[cfg(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    ))]
    {
        crate::domain::DomainId::KERNEL.as_u64()
    }

    #[cfg(not(all(
        test,
        not(feature = "full_mm_tests"),
        not(feature = "qemu-test-export")
    )))]
    {
        crate::task::context::current_subject().domain.as_u64()
    }
}

extern "C" fn kapi_exchange_alloc_raw(
    size: usize,
    align: usize,
    out_ptr: *mut *mut u8,
    out_owner: *mut u64,
) -> i32 {
    if out_ptr.is_null() || out_owner.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    match kernel_api::service::kernel::instance().exchange_alloc_raw(size, align) {
        Ok((ptr, owner)) => {
            unsafe {
                *out_ptr = ptr.as_ptr();
                *out_owner = owner.as_u64();
            }
            AbiErrorCode::Success as i32
        }
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_exchange_dealloc_raw(
    ptr: *mut u8,
    owner: u64,
    size: usize,
    align: usize,
) -> i32 {
    let Some(ptr) = core::ptr::NonNull::new(ptr) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    match kernel_api::service::kernel::instance().exchange_dealloc_raw(
        ptr,
        kernel_api::ipc::DomainId::new(owner),
        size,
        align,
    ) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_exchange_transfer_raw(ptr: *mut u8, from_owner: u64, to_owner: u64) -> i32 {
    let Some(ptr) = core::ptr::NonNull::new(ptr) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    match kernel_api::service::kernel::instance().exchange_transfer_raw(
        ptr,
        kernel_api::ipc::DomainId::new(from_owner),
        kernel_api::ipc::DomainId::new(to_owner),
    ) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_ipc_create_channel_raw(out_sender: *mut u64, out_receiver: *mut u64) -> i32 {
    if out_sender.is_null() || out_receiver.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    match kernel_api::service::kernel::instance().ipc_create_channel() {
        Ok((sender, receiver)) => {
            unsafe {
                *out_sender = sender.id();
                *out_receiver = receiver.id();
            }
            AbiErrorCode::Success as i32
        }
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_ipc_close_raw(handle: u64) -> i32 {
    match kernel_api::service::kernel::instance().ipc_close(ChannelHandle::new(handle)) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_ipc_send_raw(handle: u64, raw: *const AbiRRefRaw) -> i32 {
    if raw.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let raw = unsafe { *raw };
    match kernel_api::service::kernel::instance().ipc_send_raw(ChannelHandle::new(handle), raw) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => map_kapi_error_to_abi(err),
    }
}

extern "C" fn kapi_ipc_recv_raw(handle: u64, out_raw: *mut AbiRRefRaw) -> i32 {
    if out_raw.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    match kernel_api::service::kernel::instance().ipc_recv_raw(ChannelHandle::new(handle)) {
        Ok(raw) => {
            unsafe {
                *out_raw = raw;
            }
            AbiErrorCode::Success as i32
        }
        Err(err) => map_kapi_error_to_abi(err),
    }
}

#[unsafe(no_mangle)]
pub static __exorust_kernel_api_v4: KernelApiV4 = KernelApiV4 {
    abi_version: KERNEL_API_ABI_VERSION,
    abi_size: core::mem::size_of::<KernelApiV4>() as u64,
    log: kapi_log,
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
    current_domain_id: kapi_current_domain_id,
    exchange_alloc_raw: kapi_exchange_alloc_raw,
    exchange_dealloc_raw: kapi_exchange_dealloc_raw,
    exchange_transfer_raw: kapi_exchange_transfer_raw,
    ipc_create_channel_raw: kapi_ipc_create_channel_raw,
    ipc_close_raw: kapi_ipc_close_raw,
    ipc_send_raw: kapi_ipc_send_raw,
    ipc_recv_raw: kapi_ipc_recv_raw,
    register_block_device: kapi_register_block_device,
    unregister_block_device: kapi_unregister_block_device,
    register_nvme_namespace: kapi_register_nvme_namespace,
    unregister_nvme_namespace: kapi_unregister_nvme_namespace,
    register_netdev_port: kapi_register_netdev_port,
    unregister_netdev_port: kapi_unregister_netdev_port,
    reserved: [0; 2],
    enable_msix_raw: Some(kapi_enable_msix_raw),
    disable_msix_raw: Some(kapi_disable_msix_raw),
};

pub(crate) fn kernel_api_v4() -> &'static KernelApiV4 {
    &__exorust_kernel_api_v4
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

#[cfg(test)]
pub(crate) fn reset_for_tests() {
    DRIVER_REGISTRY.reset_for_tests();
    IRQ_BINDINGS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    crate::provider_registry::reset_for_tests();
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

const MAX_ABI_PROVIDER_DESCRIPTORS: usize = 32;

fn collect_provider_descriptors_from_export(
    export: kernel_api::abi::driver::ProviderDescriptorsFn,
) -> Vec<ProviderDescriptorV1> {
    let mut count = 0usize;
    let descriptors_ptr = export(&mut count as *mut usize);
    if descriptors_ptr.is_null() || count == 0 {
        return Vec::new();
    }

    if count > MAX_ABI_PROVIDER_DESCRIPTORS {
        log::warn!(
            "[DRIVER] Provider descriptor count {} exceeds limit {}, ignoring",
            count,
            MAX_ABI_PROVIDER_DESCRIPTORS
        );
        return Vec::new();
    }

    if (descriptors_ptr as usize) % core::mem::align_of::<ProviderDescriptorV1>() != 0 {
        log::warn!(
            "[DRIVER] Provider descriptor slice is unaligned: ptr={:#x}",
            descriptors_ptr as usize
        );
        return Vec::new();
    }

    let descriptors = unsafe {
        core::slice::from_raw_parts(descriptors_ptr as *const ProviderDescriptorV1, count)
    };

    descriptors
        .iter()
        .copied()
        .filter(|descriptor| descriptor.validate())
        .collect()
}

pub(crate) fn collect_provider_descriptors_from_vtable(
    vtable: &AbiDriverVTable,
) -> Vec<ProviderDescriptorV1> {
    let Some(export) = vtable.provider_descriptors_export() else {
        return Vec::new();
    };

    collect_provider_descriptors_from_export(export)
}

fn build_abi_driver(
    entry: AbiEntryFn,
    exports_fini: Option<extern "C" fn() -> i32>,
    provider_descriptors: Vec<ProviderDescriptorV1>,
    state_hooks: AbiDriverStateHooks,
    ctx: AbiDriverContext,
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
    let provider_descriptors = if provider_descriptors.is_empty() {
        collect_provider_descriptors_from_vtable(vtable)
    } else {
        provider_descriptors
    };

    let abi_driver = Box::new(AbiDriver {
        vtable: vtable_ptr,
        name,
        ctx,
        exports_fini,
        provider_descriptors,
        state_hooks,
    });

    Ok(abi_driver)
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedDriverExports {
    pub entry: AbiEntryFn,
    pub fini: Option<extern "C" fn() -> i32>,
    pub providers: Vec<ProviderDescriptorV1>,
    pub state_hooks: AbiDriverStateHooks,
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

    let min_size = core::mem::size_of::<DriverExportsV1>() as u64;
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
            crate::io::log::early_print_hex(kernel_api_v4() as *const KernelApiV4 as usize as u64);
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
            let res = init(kernel_api_v4() as *const KernelApiV4);
            crate::io::log::early_print("[DRIVER] prepare_exports: init done\n");
            if !AbiErrorCode::from_raw(res).is_success() {
                log::error!("[DRIVER] DriverExports init failed: code={}", res);
                return Err(DriverError::InvalidState);
            }
        }
    }

    let providers = exports_ref
        .providers
        .map(collect_provider_descriptors_from_export)
        .unwrap_or_default();

    Ok(PreparedDriverExports {
        entry: exports_ref.entry,
        fini: exports_ref.fini,
        providers,
        state_hooks: AbiDriverStateHooks {
            export_state: exports_ref.export_state,
            import_state: exports_ref.import_state,
        },
    })
}
