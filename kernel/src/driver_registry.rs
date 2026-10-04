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
use core::ptr::NonNull;
use core::sync::atomic::AtomicBool;
use kernel_api::abi::driver::{
    AbiBlockDeviceRegistration, AbiDmaAllocation, AbiDmaOperation, AbiDmaRequest, AbiDmaResponse,
    AbiDmaStatus, AbiDriverType, AbiError as AbiErrorCode, AbiMsixVectorInfo,
    AbiNetPortRegistration, AbiNvmeNamespaceRegistration, AbiRRefRaw, DRIVER_EXPORTS_ABI_VERSION,
    DriverCapabilities as AbiDriverCapabilities, DriverContext as AbiDriverContext,
    DriverEntryFn as AbiEntryFn, DriverExportsV1, DriverVTable as AbiDriverVTable,
    KERNEL_API_ABI_VERSION, KernelApiV4, PackedPciLocation,
};
use kernel_api::dma::{
    DmaAccessWidth, DmaAllocationRequest, DmaCompletionWitness, DmaDirection, DmaLeaseError,
    DmaLeaseId, DmaLeaseState, DmaQueueIdentity, DmaQuiesceWitness, DmaReconcileWitness,
    DmaResetWitness,
};
use kernel_api::driver::DriverStateBlob;
use kernel_api::driver::{DeviceId, Driver, DriverState, DriverType};
use kernel_api::error::{KapiError, KapiResult};
use kernel_api::ipc::ChannelHandle;
use kernel_api::provider::ProviderDescriptorV1;
mod registration_api;
pub use registration_api::*;

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
fn cleanup_runtime_resources_for_driver_handle(handle: DriverHandle) -> Result<(), DriverError> {
    crate::resource_registry::cleanup_for_driver_handle(handle)
        .map_err(DriverError::ResourceCleanup)
}

#[cfg(all(
    test,
    not(feature = "full_mm_tests"),
    not(feature = "qemu-test-export")
))]
fn cleanup_runtime_resources_for_driver_handle(_handle: DriverHandle) -> Result<(), DriverError> {
    Ok(())
}

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
    let owner = crate::task::current_subject().domain;
    let owner_info = crate::io::msix::owner_for_vector(vector).ok_or(KapiError::InvalidHandle)?;
    if owner_info.owner != owner {
        return Err(KapiError::PermissionDenied);
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

    if crate::task::spawn_in_domain(
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

                let Ok(handle) = resolve_single_driver_handle_for_domain(owner) else {
                    continue;
                };
                let _ = driver_registry().dispatch_irq(handle, vector as u32);
            }
        },
        crate::task::TaskOptions::any(),
        owner,
    )
    .is_err()
    {
        IRQ_BINDINGS
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&vector);
        return Err(KapiError::ResourceExhausted);
    }

    Ok(())
}

#[cfg(not(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export")))]
fn bind_irq_for_current_domain(_irq: u32, _cookie: u64) -> KapiResult<()> {
    Err(KapiError::NotSupported)
}

#[cfg(any(not(test), feature = "full_mm_tests", feature = "qemu-test-export"))]
fn unbind_irq_for_current_domain(irq: u32) -> KapiResult<()> {
    let vector = u8::try_from(irq).map_err(|_| KapiError::InvalidHandle)?;
    let owner = crate::task::current_subject().domain;
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

pub(crate) fn enter_driver_execution_domain(
    owner: crate::domain::DomainId,
) -> Result<Option<crate::cpu::ExecutionContextGuard>, DriverError> {
    if crate::task::current_subject().domain == owner {
        return Ok(None);
    }
    crate::task::enter_domain(owner)
        .map(Some)
        .map_err(|_| DriverError::ExecutionContextUnavailable)
}

/// A driver call owns the instance outside the registry lock. The slot keeps
/// identity, state and code ownership visible throughout a preempted callback.
struct DriverEntry {
    slot: DriverSlot,
    name: String,
    driver_type: DriverType,
    supported_devices: Vec<DeviceId>,
    has_irq_handler: bool,
    abi_context: Option<AbiDriverContext>,
    owner: crate::domain::DomainId,
    code: Option<Arc<crate::loader::code::CodeLease>>,
}

enum DriverSlot {
    Available {
        driver: Box<dyn Driver>,
        state: DriverState,
    },
    Invoking {
        operation: DriverOperation,
        state: DriverState,
    },
    Removed,
}

/// Lifecycle operation whose completion or failure belongs to the driver owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverOperation {
    Probe,
    Start,
    Stop,
    Remove,
    Interrupt,
    ExportState,
    ImportState,
}

impl DriverEntry {
    fn state(&self) -> DriverState {
        match &self.slot {
            DriverSlot::Available { state, .. } | DriverSlot::Invoking { state, .. } => *state,
            DriverSlot::Removed => DriverState::Removed,
        }
    }
}

impl DriverEntry {
    fn prepare(
        owner: crate::domain::DomainId,
        driver: Box<dyn Driver>,
        code: Option<Arc<crate::loader::code::CodeLease>>,
    ) -> Result<Self, DriverError> {
        let mut name = String::new();
        name.try_reserve(driver.name().len())
            .map_err(|_| DriverError::OutOfMemory)?;
        name.push_str(driver.name());
        let mut supported_devices = Vec::new();
        supported_devices
            .try_reserve(driver.supported_devices().len())
            .map_err(|_| DriverError::OutOfMemory)?;
        supported_devices.extend_from_slice(driver.supported_devices());
        Ok(Self {
            driver_type: driver.driver_type(),
            has_irq_handler: driver.has_irq_handler(),
            abi_context: driver.abi_context(),
            name,
            supported_devices,
            owner,
            code,
            slot: DriverSlot::Available {
                driver,
                state: DriverState::Registered,
            },
        })
    }
}

/// Reserves the instance until the callback and its state publication complete.
/// Dropping an unfinished invocation retains the driver as an uncertain failure.
struct DriverInvocation<'a> {
    driver: Option<Box<dyn Driver>>,
    code: Option<Arc<crate::loader::code::CodeLease>>,
    registry: &'a DriverRegistry,
    handle: DriverHandle,
    owner: crate::domain::DomainId,
    previous: DriverState,
    operation: DriverOperation,
}

impl DriverInvocation<'_> {
    fn driver(&mut self) -> &mut dyn Driver {
        self.driver
            .as_deref_mut()
            .expect("the invocation owns its driver until publication")
    }
    fn enter(&self) -> Result<Option<crate::cpu::ExecutionContextGuard>, DriverError> {
        if matches!(
            self.operation,
            DriverOperation::Stop | DriverOperation::Remove
        ) && (self.owner != crate::domain::DomainId::KERNEL || self.code.is_some())
        {
            crate::task::enter_domain_teardown(self.owner, self.code.as_ref())
                .map(Some)
                .map_err(|_| DriverError::ExecutionContextUnavailable)
        } else {
            match &self.code {
                Some(code) => crate::task::enter_cell_domain(self.owner, code.cell())
                    .map(Some)
                    .map_err(|_| DriverError::ExecutionContextUnavailable),
                None => enter_driver_execution_domain(self.owner),
            }
        }
    }
    fn complete(mut self, state: DriverState) {
        let context = self.driver().abi_context();
        let driver = self
            .driver
            .take()
            .expect("completion consumes its reserved driver once");
        let mut entries = self
            .registry
            .drivers
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let entry = entries
            .get_mut(self.handle.0)
            .expect("a reserved slot cannot be removed");
        assert!(
            matches!(entry.slot, DriverSlot::Invoking { operation, .. } if operation == self.operation)
        );
        entry.abi_context = context;
        entry.slot = DriverSlot::Available { driver, state };
    }
    fn removed(mut self) {
        let driver = self
            .driver
            .take()
            .expect("acknowledged removal owns its instance");
        {
            let mut entries = self
                .registry
                .drivers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let entry = entries
                .get_mut(self.handle.0)
                .expect("a reserved slot cannot be removed");
            assert!(matches!(
                entry.slot,
                DriverSlot::Invoking {
                    operation: DriverOperation::Remove,
                    ..
                }
            ));
            entry.slot = DriverSlot::Removed;
            entry.abi_context = None;
            entry.code = None;
        }
        // The invocation still leases code while the driver destructor runs.
        drop(driver);
    }
}

impl Drop for DriverInvocation<'_> {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.take() {
            let mut entries = self
                .registry
                .drivers
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            let entry = entries
                .get_mut(self.handle.0)
                .expect("a reserved slot cannot be removed");
            entry.slot = DriverSlot::Available {
                driver,
                state: DriverState::Error,
            };
        }
    }
}

/// Global driver registry
pub struct DriverRegistry {
    /// All registered drivers
    drivers: PoisonLock<Vec<DriverEntry>>,
}

impl DriverRegistry {
    fn begin(
        &self,
        handle: DriverHandle,
        operation: DriverOperation,
    ) -> Result<DriverInvocation<'_>, DriverError> {
        let mut entries = self.drivers.lock().map_err(|_| DriverError::Poisoned)?;
        let entry = entries.get_mut(handle.0).ok_or(DriverError::NotFound)?;
        if matches!(entry.slot, DriverSlot::Invoking { .. }) {
            return Err(DriverError::Busy { operation });
        }
        let previous = entry.state();
        let valid = match operation {
            DriverOperation::Probe => {
                matches!(previous, DriverState::Registered | DriverState::Probing)
            }
            DriverOperation::Start => matches!(
                previous,
                DriverState::Probed | DriverState::Stopped | DriverState::Starting
            ),
            DriverOperation::Stop => matches!(
                previous,
                DriverState::Registered
                    | DriverState::Probed
                    | DriverState::Running
                    | DriverState::Stopping
                    | DriverState::Finalizing
                    | DriverState::Error
            ),
            DriverOperation::Remove => matches!(
                previous,
                DriverState::Registered
                    | DriverState::Probed
                    | DriverState::Stopped
                    | DriverState::Removing
                    | DriverState::Error
            ),
            DriverOperation::Interrupt => previous == DriverState::Running && entry.has_irq_handler,
            DriverOperation::ExportState => matches!(
                previous,
                DriverState::Running | DriverState::Probed | DriverState::Stopped
            ),
            DriverOperation::ImportState => {
                matches!(previous, DriverState::Probed | DriverState::Importing)
            }
        };
        if !valid {
            if matches!(
                previous,
                DriverState::Probing
                    | DriverState::Importing
                    | DriverState::Starting
                    | DriverState::Stopping
                    | DriverState::Finalizing
                    | DriverState::Removing
            ) {
                return Err(DriverError::Busy { operation });
            }
            return Err(DriverError::InvalidState);
        }
        let state = match operation {
            DriverOperation::Probe => DriverState::Probing,
            DriverOperation::Start => DriverState::Starting,
            DriverOperation::Stop => DriverState::Stopping,
            DriverOperation::Remove => DriverState::Removing,
            DriverOperation::ImportState => DriverState::Importing,
            _ => previous,
        };
        let DriverSlot::Available { driver, .. } =
            core::mem::replace(&mut entry.slot, DriverSlot::Invoking { operation, state })
        else {
            unreachable!("only an available validated instance can enter a callback");
        };
        Ok(DriverInvocation {
            driver: Some(driver),
            code: entry.code.clone(),
            registry: self,
            handle,
            owner: entry.owner,
            previous,
            operation,
        })
    }

    fn operation_result(
        operation: DriverOperation,
        result: KapiResult<()>,
    ) -> Result<(), DriverError> {
        result.map_err(|cause| {
            if cause == KapiError::Busy {
                DriverError::Busy { operation }
            } else {
                DriverError::OperationFailed { operation, cause }
            }
        })
    }

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
        self.register_owned(crate::domain::DomainId::KERNEL, driver)
    }

    pub(crate) fn register_owned(
        &self,
        owner: crate::domain::DomainId,
        driver: Box<dyn Driver>,
    ) -> Result<DriverHandle, DriverError> {
        let code = match crate::cpu::CurrentCpu::acquire().and_then(|cpu| cpu.execution_cell()) {
            Some(cell) => Some(
                Arc::try_new(
                    crate::loader::acquire_code_lease(cell)
                        .ok_or(DriverError::ExecutionContextUnavailable)?,
                )
                .map_err(|_| DriverError::OutOfMemory)?,
            ),
            None => None,
        };
        let entry = DriverEntry::prepare(owner, driver, code)?;
        let mut drivers = self.drivers.lock().map_err(|_| DriverError::Poisoned)?;
        drivers
            .try_reserve(1)
            .map_err(|_| DriverError::OutOfMemory)?;
        let handle = DriverHandle(drivers.len());
        drivers.push(entry);
        Ok(handle)
    }

    /// Probe a specific driver
    pub fn probe(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut call = self.begin(handle, DriverOperation::Probe)?;
        let _scope = call.enter()?;
        let result = call.driver().probe();
        let state = match result {
            Ok(()) => DriverState::Probed,
            Err(KapiError::Busy) => DriverState::Probing,
            Err(_) => DriverState::Error,
        };
        call.complete(state);
        Self::operation_result(DriverOperation::Probe, result)
    }

    /// Start a probed driver
    pub fn start(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut call = self.begin(handle, DriverOperation::Start)?;
        let _scope = call.enter()?;
        let result = call.driver().start();
        if let Err(cause) = result {
            call.complete(if cause == KapiError::Busy {
                DriverState::Starting
            } else {
                DriverState::Error
            });
            return Self::operation_result(DriverOperation::Start, Err(cause));
        }
        let descriptors = call.driver().provider_descriptors();
        if !descriptors.is_empty() {
            crate::provider_registry::provider_registry()
                .register_driver_descriptors(handle, descriptors);
        }
        call.complete(DriverState::Running);
        Ok(())
    }

    /// Stop a running driver
    pub fn stop(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut call = self.begin(handle, DriverOperation::Stop)?;
        let _scope = call.enter()?;
        if call.previous != DriverState::Finalizing {
            let result = call.driver().stop();
            if let Err(cause) = result {
                // Every failed stop retains its cleanup eligibility and driver.
                call.complete(DriverState::Stopping);
                return Self::operation_result(DriverOperation::Stop, Err(cause));
            }
        }
        cleanup_msix_for_driver_handle(handle);
        if let Err(cause) = cleanup_runtime_resources_for_driver_handle(handle) {
            call.complete(DriverState::Finalizing);
            return Err(cause);
        }
        crate::provider_registry::provider_registry().unregister_driver(handle);
        call.complete(DriverState::Stopped);
        Ok(())
    }

    /// Probe and start a driver in one call
    pub fn probe_and_start(&self, handle: DriverHandle) -> Result<(), DriverError> {
        if matches!(
            self.state(handle),
            Some(DriverState::Registered | DriverState::Probing)
        ) {
            self.probe(handle)?;
        }
        match self.state(handle) {
            Some(DriverState::Probed | DriverState::Stopped | DriverState::Starting) => {
                self.start(handle)
            }
            Some(DriverState::Running) => Ok(()),
            None => Err(DriverError::NotFound),
            _ => Err(DriverError::InvalidState),
        }
    }

    /// Get driver state
    pub fn state(&self, handle: DriverHandle) -> Option<DriverState> {
        self.drivers
            .lock()
            .ok()?
            .get(handle.0)
            .map(DriverEntry::state)
    }

    /// Get driver name
    pub fn name(&self, handle: DriverHandle) -> Option<String> {
        self.drivers
            .lock()
            .ok()?
            .get(handle.0)
            .map(|entry| entry.name.clone())
    }

    /// Find drivers by type
    pub fn find_by_type(&self, driver_type: DriverType) -> Vec<DriverHandle> {
        match self.drivers.lock() {
            Ok(entries) => entries
                .iter()
                .enumerate()
                .filter(|(_, entry)| {
                    entry.driver_type == driver_type && entry.state() != DriverState::Removed
                })
                .map(|(index, _)| DriverHandle(index))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Find driver that supports a device
    pub fn find_for_device(&self, device_id: &DeviceId) -> Option<DriverHandle> {
        self.drivers
            .lock()
            .ok()?
            .iter()
            .enumerate()
            .find(|(_, entry)| {
                entry.state() != DriverState::Removed
                    && entry.supported_devices.iter().any(|device| {
                        device.vendor == device_id.vendor && device.device == device_id.device
                    })
            })
            .map(|(index, _)| DriverHandle(index))
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
        self.drivers
            .lock()
            .map(|entries| {
                entries
                    .iter()
                    .filter(|entry| entry.state() == DriverState::Running)
                    .count()
            })
            .unwrap_or(0)
    }

    /// List all drivers with their states
    pub fn list(&self) -> Vec<(DriverHandle, String, DriverType, DriverState)> {
        match self.drivers.lock() {
            Ok(entries) => entries
                .iter()
                .enumerate()
                .map(|(index, entry)| {
                    (
                        DriverHandle(index),
                        entry.name.clone(),
                        entry.driver_type,
                        entry.state(),
                    )
                })
                .collect(),
            Err(_) => Vec::new(),
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

    /// Removal acknowledges device teardown before releasing the instance and code.
    pub fn unregister(&self, handle: DriverHandle) -> Result<(), DriverError> {
        if self.state(handle) == Some(DriverState::Removed) {
            return Ok(());
        }
        let mut call = self.begin(handle, DriverOperation::Remove)?;
        let _scope = call.enter()?;
        cleanup_msix_for_driver_handle(handle);
        if let Err(cause) = cleanup_runtime_resources_for_driver_handle(handle) {
            let previous = call.previous;
            call.complete(previous);
            return Err(cause);
        }
        let result = call.driver().remove();
        if let Err(cause) = result {
            call.complete(DriverState::Removing);
            return Self::operation_result(DriverOperation::Remove, Err(cause));
        }
        crate::provider_registry::provider_registry().unregister_driver(handle);
        call.removed();
        Ok(())
    }

    pub(crate) fn dispatch_irq(&self, handle: DriverHandle, irq: u32) -> bool {
        let Ok(mut call) = self.begin(handle, DriverOperation::Interrupt) else {
            return false;
        };
        let Ok(_scope) = call.enter() else {
            return false;
        };
        let handled = call.driver().handle_irq(irq);
        let previous = call.previous;
        call.complete(previous);
        handled
    }

    pub(crate) fn driver_abi_context(&self, handle: DriverHandle) -> Option<AbiDriverContext> {
        self.drivers
            .lock()
            .ok()?
            .get(handle.0)
            .and_then(|entry| entry.abi_context)
    }

    pub(crate) fn driver_owner(&self, handle: DriverHandle) -> Option<crate::domain::DomainId> {
        self.drivers
            .lock()
            .ok()
            .and_then(|drivers| drivers.get(handle.0).map(|entry| entry.owner))
    }

    pub(crate) fn export_live_state(
        &self,
        handle: DriverHandle,
    ) -> Result<Option<DriverStateBlob>, DriverError> {
        let mut call = self.begin(handle, DriverOperation::ExportState)?;
        let _scope = call.enter()?;
        let result =
            call.driver()
                .export_live_state()
                .map_err(|cause| DriverError::OperationFailed {
                    operation: DriverOperation::ExportState,
                    cause,
                });
        let previous = call.previous;
        call.complete(previous);
        result
    }

    fn import_live_state(
        &self,
        handle: DriverHandle,
        state: &DriverStateBlob,
    ) -> Result<(), DriverError> {
        let mut call = self.begin(handle, DriverOperation::ImportState)?;
        let _scope = call.enter()?;
        let result = call.driver().import_live_state(state);
        call.complete(match result {
            Ok(()) => DriverState::Probed,
            Err(KapiError::Busy) => DriverState::Importing,
            Err(_) => DriverState::Error,
        });
        Self::operation_result(DriverOperation::ImportState, result)
    }
}

/// Owns a prepared instance until publication, then the remaining startup steps.
/// A Busy result preserves this object; retry does not reconstruct the candidate
/// or replay a successful state import. The registry owns a published instance.
pub(crate) struct DriverReplacement {
    handle: DriverHandle,
    candidate: Option<DriverEntry>,
    state: Option<Arc<DriverStateBlob>>,
}

impl DriverReplacement {
    pub(crate) fn published(&self) -> bool {
        self.candidate.is_none()
    }

    pub(crate) fn advance(&mut self, registry: &DriverRegistry) -> Result<(), DriverError> {
        if let Some(candidate) = &self.candidate {
            if matches!(
                registry.state(self.handle),
                Some(
                    DriverState::Running
                        | DriverState::Stopping
                        | DriverState::Finalizing
                        | DriverState::Error
                )
            ) {
                registry.stop(self.handle)?;
            }
            registry.unregister(self.handle)?;
            if let Some(code) = &candidate.code {
                if candidate.owner != crate::domain::DomainId::KERNEL {
                    crate::domain::registry::bind_code_generation(candidate.owner, code.cell())
                        .map_err(|_| DriverError::ExecutionContextUnavailable)?;
                }
            }
            let mut entries = registry.drivers.lock().map_err(|_| DriverError::Poisoned)?;
            let entry = entries
                .get_mut(self.handle.0)
                .ok_or(DriverError::NotFound)?;
            if !matches!(entry.slot, DriverSlot::Removed) {
                return Err(DriverError::Busy {
                    operation: DriverOperation::Remove,
                });
            }
            *entry = self
                .candidate
                .take()
                .expect("publication consumes its prepared instance once");
        }
        if matches!(
            registry.state(self.handle),
            Some(DriverState::Registered | DriverState::Probing)
        ) {
            registry.probe(self.handle)?;
        }
        if let Some(state) = &self.state {
            registry.import_live_state(self.handle, state)?;
            self.state = None;
        }
        registry.probe_and_start(self.handle)
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
    /// An admitted operation or reserved callback has not completed.
    Busy {
        operation: DriverOperation,
    },
    /// The driver retained its resources and a classified operation failure.
    OperationFailed {
        operation: DriverOperation,
        cause: KapiError,
    },
    /// Metadata preparation failed before registration or replacement publication.
    OutOfMemory,
    /// Hardware/DMA resources remain owned after a partial cleanup attempt.
    ResourceCleanup(crate::domain::DomainLifecycleError),
    /// Registry lock is poisoned (previous holder panicked)
    Poisoned,
    /// The current CPU has no execution context for entering the driver owner domain.
    ExecutionContextUnavailable,
    ModuleLifecycle(crate::loader::CellRuntimeError),
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "driver not found"),
            Self::InvalidState => write!(f, "invalid driver state for operation"),
            Self::Busy { operation } => write!(f, "driver {operation:?} incomplete"),
            Self::OperationFailed { operation, cause } => {
                write!(f, "driver {operation:?} failed: {cause}")
            }
            Self::OutOfMemory => write!(f, "driver metadata allocation failed"),
            Self::ResourceCleanup(cause) => cause.fmt(f),
            Self::Poisoned => write!(f, "registry lock poisoned (holder panicked)"),
            Self::ExecutionContextUnavailable => {
                write!(f, "driver execution context unavailable")
            }
            Self::ModuleLifecycle(cause) => cause.fmt(f),
        }
    }
}

// ============================================================================
// Kernel API Table (DriverExportsV1)
// ============================================================================

extern "C" fn kernel_abi_log(level: u32, msg_ptr: *const u8, msg_len: usize) {
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

fn dma_error_status(error: DmaLeaseError) -> i32 {
    AbiDmaStatus::from_result(Err(error)) as i32
}

fn dma_queue(request: AbiDmaRequest) -> Result<DmaQueueIdentity, DmaLeaseError> {
    DmaQueueIdentity::new(
        PackedPciLocation::from_raw(request.device),
        request.queue,
        request.generation,
    )
    .ok_or(DmaLeaseError::QueueMismatch)
}

/// Allocate a registry-owned DMA capability for a driver domain.
///
/// # Safety
/// `out` must be writable and aligned for one `AbiDmaAllocation` for the
/// duration of this synchronous call.
unsafe extern "C" fn kernel_abi_dma_allocate(
    size: usize,
    device: u64,
    direction: u8,
    out: *mut AbiDmaAllocation,
) -> i32 {
    let Some(out) = NonNull::new(out).filter(|pointer| pointer.is_aligned()) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    // SAFETY: pointer validity is the caller's ABI obligation and alignment was
    // checked above. Initialize failure output before any fallible work.
    unsafe { out.as_ptr().write(AbiDmaAllocation::default()) };

    let Some(direction) = DmaDirection::from_abi(direction) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    let Some(request) = DmaAllocationRequest::new(size, direction) else {
        return AbiErrorCode::InvalidSize as i32;
    };
    match kernel_api::service::kernel::instance()
        .alloc_dma_for_device(request, PackedPciLocation::from_raw(device))
    {
        Ok(lease) => {
            let allocation = AbiDmaAllocation::export(lease);
            // SAFETY: the validated output slot remains exclusively borrowed
            // for this function call.
            unsafe { out.as_ptr().write(allocation) };
            AbiErrorCode::Success as i32
        }
        Err(error) => AbiErrorCode::from(error) as i32,
    }
}

/// Dispatch one validated state transition to the authoritative DMA registry.
///
/// # Safety
/// `request` must point to an initialized, aligned request and `out` to writable,
/// aligned response storage. For completion, quiescence, reset, or reconciliation
/// operations, the caller must have established the hardware fact documented by
/// the corresponding Rust witness constructor; numeric fields alone are not proof.
unsafe extern "C" fn kernel_abi_dma_command(
    lease: u64,
    request: *const AbiDmaRequest,
    out: *mut AbiDmaResponse,
) -> i32 {
    let Some(request) = NonNull::new(request.cast_mut()).filter(|pointer| pointer.is_aligned())
    else {
        return dma_error_status(DmaLeaseError::InvalidRange);
    };
    let Some(out) = NonNull::new(out).filter(|pointer| pointer.is_aligned()) else {
        return dma_error_status(DmaLeaseError::InvalidRange);
    };
    // SAFETY: request validity is the ABI caller's obligation; it is copied
    // before output initialization, so overlapping carrier storage is harmless.
    let request = unsafe { request.as_ptr().read() };
    // SAFETY: the caller provided writable aligned response storage.
    unsafe { out.as_ptr().write(AbiDmaResponse::default()) };

    let Some(lease) = DmaLeaseId::from_abi(lease) else {
        return dma_error_status(DmaLeaseError::StaleLease);
    };
    let operation = match AbiDmaOperation::try_from(request.operation) {
        Ok(operation) => operation,
        Err(error) => return dma_error_status(error),
    };
    let command = match operation {
        AbiDmaOperation::Prepare => {
            dma_queue(request).map(crate::resource_registry::dma::DmaRegistryCommand::Prepare)
        }
        AbiDmaOperation::Arm => Ok(crate::resource_registry::dma::DmaRegistryCommand::Arm),
        AbiDmaOperation::Abort => Ok(crate::resource_registry::dma::DmaRegistryCommand::Abort),
        AbiDmaOperation::Complete => dma_queue(request).and_then(|queue| {
            let completed =
                DmaLeaseId::from_abi(request.witness_lease).ok_or(DmaLeaseError::QueueMismatch)?;
            // SAFETY: this unsafe ABI operation requires the driver completion
            // parser to validate exactly this queue entry and allocation.
            let witness =
                unsafe { DmaCompletionWitness::from_validated_queue_entry(queue, completed) };
            Ok(crate::resource_registry::dma::DmaRegistryCommand::Complete(
                witness,
            ))
        }),
        AbiDmaOperation::ReturnToCpu => {
            Ok(crate::resource_registry::dma::DmaRegistryCommand::ReturnToCpu)
        }
        AbiDmaOperation::OutcomeUnknown => {
            Ok(crate::resource_registry::dma::DmaRegistryCommand::OutcomeUnknown)
        }
        AbiDmaOperation::Revoke => {
            // SAFETY: the caller contract requires completed device reset before
            // selecting this operation.
            unsafe {
                DmaResetWitness::after_device_reset(
                    PackedPciLocation::from_raw(request.device),
                    request.generation,
                )
            }
            .map(crate::resource_registry::dma::DmaRegistryCommand::Revoke)
            .ok_or(DmaLeaseError::QueueMismatch)
        }
        AbiDmaOperation::Reconcile => {
            // SAFETY: the caller contract requires reset plus completed IOTLB
            // invalidation before selecting reconciliation.
            let witness = unsafe {
                DmaReconcileWitness::after_iotlb_invalidation(
                    PackedPciLocation::from_raw(request.device),
                    request.generation,
                )
            }
            .ok_or(DmaLeaseError::QueueMismatch);
            witness.map(crate::resource_registry::dma::DmaRegistryCommand::Reconcile)
        }
        AbiDmaOperation::RetryClose => {
            Ok(crate::resource_registry::dma::DmaRegistryCommand::RetryClose)
        }
        AbiDmaOperation::Close => Ok(crate::resource_registry::dma::DmaRegistryCommand::Close),
        AbiDmaOperation::PrepareShared => {
            dma_queue(request).map(crate::resource_registry::dma::DmaRegistryCommand::PrepareShared)
        }
        AbiDmaOperation::ActivateShared => {
            Ok(crate::resource_registry::dma::DmaRegistryCommand::ActivateShared)
        }
        AbiDmaOperation::QuiesceShared => dma_queue(request).and_then(|queue| {
            let shared =
                DmaLeaseId::from_abi(request.witness_lease).ok_or(DmaLeaseError::QueueMismatch)?;
            // SAFETY: the caller contract requires the queue to be stopped and
            // drained for this exact allocation.
            let witness = unsafe { DmaQuiesceWitness::after_queue_quiesced(queue, shared) };
            Ok(crate::resource_registry::dma::DmaRegistryCommand::QuiesceShared(witness))
        }),
        AbiDmaOperation::ReadShared => DmaAccessWidth::from_abi(request.width)
            .map(
                |width| crate::resource_registry::dma::DmaRegistryCommand::ReadShared {
                    offset: request.offset,
                    width,
                },
            )
            .ok_or(DmaLeaseError::InvalidRange),
        AbiDmaOperation::WriteShared => DmaAccessWidth::from_abi(request.width)
            .map(
                |width| crate::resource_registry::dma::DmaRegistryCommand::WriteShared {
                    offset: request.offset,
                    width,
                    value: request.value,
                },
            )
            .ok_or(DmaLeaseError::InvalidRange),
        AbiDmaOperation::PreparedQueue => {
            Ok(crate::resource_registry::dma::DmaRegistryCommand::PreparedQueue)
        }
        AbiDmaOperation::Abandon => DmaLeaseState::from_abi(request.state)
            .map(crate::resource_registry::dma::DmaRegistryCommand::Abandon)
            .ok_or(DmaLeaseError::InvalidState),
    };
    let command = match command {
        Ok(command) => command,
        Err(error) => return dma_error_status(error),
    };
    let owner = crate::task::current_subject().domain;
    match crate::resource_registry::dma::command(lease, owner, command) {
        Ok(response) => {
            let response = match response {
                crate::resource_registry::dma::DmaRegistryResponse::None => {
                    AbiDmaResponse::default()
                }
                crate::resource_registry::dma::DmaRegistryResponse::Scalar(value) => {
                    AbiDmaResponse {
                        value,
                        ..AbiDmaResponse::default()
                    }
                }
                crate::resource_registry::dma::DmaRegistryResponse::Queue(queue) => {
                    AbiDmaResponse {
                        device: queue.device().raw(),
                        queue: queue.index(),
                        generation: queue.generation(),
                        ..AbiDmaResponse::default()
                    }
                }
            };
            // SAFETY: output storage remains exclusively writable for this call.
            unsafe { out.as_ptr().write(response) };
            AbiDmaStatus::Success as i32
        }
        Err(error) => dma_error_status(error),
    }
}

/// Visit CPU-owned DMA bytes without exporting their address as an owner.
///
/// # Safety
/// `visitor` must not retain `bytes`, unwind across the ABI, or use `context`
/// after the synchronous callback returns. Any context pointer it dereferences
/// must remain valid for the call.
unsafe extern "C" fn kernel_abi_dma_read(
    lease: u64,
    context: *mut u8,
    visitor: unsafe extern "C" fn(*mut u8, *const u8, usize),
) -> i32 {
    let Some(lease) = DmaLeaseId::from_abi(lease) else {
        return dma_error_status(DmaLeaseError::StaleLease);
    };
    let owner = crate::task::current_subject().domain;
    let mut visit = |bytes: &[u8]| {
        // SAFETY: the caller supplied this callback under the function's safety
        // contract; the registry pins `bytes` for this invocation only.
        unsafe { visitor(context, bytes.as_ptr(), bytes.len()) };
    };
    AbiDmaStatus::from_result(crate::resource_registry::dma::with_cpu_bytes(
        lease, owner, &mut visit,
    )) as i32
}

/// Mutably visit CPU-owned DMA bytes under registry exclusivity.
///
/// # Safety
/// The same callback/context conditions as `kernel_abi_dma_read` apply. The callback
/// must not create an alias or retain the mutable byte pointer.
unsafe extern "C" fn kernel_abi_dma_write(
    lease: u64,
    context: *mut u8,
    visitor: unsafe extern "C" fn(*mut u8, *mut u8, usize),
) -> i32 {
    let Some(lease) = DmaLeaseId::from_abi(lease) else {
        return dma_error_status(DmaLeaseError::StaleLease);
    };
    let owner = crate::task::current_subject().domain;
    let mut visit = |bytes: &mut [u8]| {
        // SAFETY: the caller supplied this callback under the function's safety
        // contract; the registry grants exclusive access for this invocation.
        unsafe { visitor(context, bytes.as_mut_ptr(), bytes.len()) };
    };
    AbiDmaStatus::from_result(crate::resource_registry::dma::with_cpu_bytes_mut(
        lease, owner, &mut visit,
    )) as i32
}

extern "C" fn kernel_abi_enable_msix_raw(
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
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_disable_msix_raw(device_id: u64) -> i32 {
    match kernel_api::service::kernel::instance()
        .disable_msix(PackedPciLocation::from_raw(device_id))
    {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_irq_bind(irq: u32, cookie: u64) -> i32 {
    match bind_irq_for_current_domain(irq, cookie) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_irq_unbind(irq: u32) -> i32 {
    match unbind_irq_for_current_domain(irq) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_register_block_device(
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
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_unregister_block_device(handle: u64) -> i32 {
    match kernel_api::service::kernel::instance().unregister_block_device(handle) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_register_nvme_namespace(
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
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_unregister_nvme_namespace(handle: u64) -> i32 {
    match kernel_api::service::kernel::instance().unregister_nvme_namespace(handle) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_register_netdev_port(
    registration: *const AbiNetPortRegistration,
    out_handle: *mut u64,
) -> i32 {
    if registration.is_null() || out_handle.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    // SAFETY: the ABI caller provides a writable aligned handle output.
    unsafe { *out_handle = 0 };
    let registration = unsafe { &*registration };
    match kernel_api::service::kernel::instance().register_netdev_port(registration) {
        Ok(handle) => {
            unsafe { *out_handle = handle };
            AbiErrorCode::Success as i32
        }
        Err(kernel_api::error::KapiError::NetRegistrationRetained { handle }) => {
            // SAFETY: the same validated output reports the live partial result.
            unsafe { *out_handle = handle };
            AbiErrorCode::DeviceBusy as i32
        }
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_unregister_netdev_port(handle: u64) -> i32 {
    match kernel_api::service::kernel::instance().unregister_netdev_port(handle) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_heap_alloc(size: usize) -> *mut u8 {
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

extern "C" fn kernel_abi_heap_dealloc(ptr: *mut u8, size: usize) {
    use core::alloc::Layout;

    if ptr.is_null() || size == 0 {
        return;
    }

    let layout = match Layout::from_size_align(size, 8) {
        Ok(l) => l,
        Err(_) => return,
    };

    // SAFETY: ptrは非null検証済み。layoutはkernel_abi_heap_allocと同一のアライメントで構築。
    unsafe { alloc::alloc::dealloc(ptr, layout) }
}

extern "C" fn kernel_abi_panic_abort(msg_ptr: *const u8, msg_len: usize) -> ! {
    if !msg_ptr.is_null() && msg_len > 0 {
        let slice = unsafe { core::slice::from_raw_parts(msg_ptr, msg_len) };
        if let Ok(s) = core::str::from_utf8(slice) {
            log::error!(target: "cell", "Cell panic: {}", s);
        }
    }
    panic!("Cell panic - aborting");
}

extern "C" fn kernel_abi_current_domain_id() -> u64 {
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
        crate::task::current_subject().domain.as_u64()
    }
}

extern "C" fn kernel_abi_exchange_alloc_raw(
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
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_exchange_dealloc_raw(
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
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_exchange_transfer_raw(
    ptr: *mut u8,
    from_owner: u64,
    to_owner: u64,
) -> i32 {
    let Some(ptr) = core::ptr::NonNull::new(ptr) else {
        return AbiErrorCode::InvalidParam as i32;
    };
    match kernel_api::service::kernel::instance().exchange_transfer_raw(
        ptr,
        kernel_api::ipc::DomainId::new(from_owner),
        kernel_api::ipc::DomainId::new(to_owner),
    ) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_ipc_create_channel_raw(
    out_sender: *mut u64,
    out_receiver: *mut u64,
) -> i32 {
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
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_ipc_close_raw(handle: u64) -> i32 {
    match kernel_api::service::kernel::instance().ipc_close(ChannelHandle::new(handle)) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_ipc_send_raw(handle: u64, raw: *const AbiRRefRaw) -> i32 {
    if raw.is_null() {
        return AbiErrorCode::InvalidParam as i32;
    }
    let raw = unsafe { *raw };
    match kernel_api::service::kernel::instance().ipc_send_raw(ChannelHandle::new(handle), raw) {
        Ok(()) => AbiErrorCode::Success as i32,
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

extern "C" fn kernel_abi_ipc_recv_raw(handle: u64, out_raw: *mut AbiRRefRaw) -> i32 {
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
        Err(err) => AbiErrorCode::from(err) as i32,
    }
}

#[unsafe(no_mangle)]
pub static __exorust_kernel_api_v4: KernelApiV4 = KernelApiV4 {
    abi_version: KERNEL_API_ABI_VERSION,
    abi_size: core::mem::size_of::<KernelApiV4>() as u64,
    task_waker_abi: kernel_api::abi::driver::TASK_WAKER_ABI,
    log: kernel_abi_log,
    spawn: kernel_abi_spawn,
    timer_register: kernel_abi_timer_register,
    time_snapshot: kernel_abi_time_snapshot,
    timer_statistics: kernel_abi_timer_statistics,
    current_tick: kernel_abi_current_tick,
    current_task_id: kernel_abi_current_task_id,
    pci_config_read: kernel_abi_pci_config_read,
    mmio_acquire: kernel_abi_mmio_acquire,
    mmio_release: kernel_abi_mmio_release,
    dma_allocate: kernel_abi_dma_allocate,
    dma_command: kernel_abi_dma_command,
    dma_read: kernel_abi_dma_read,
    dma_write: kernel_abi_dma_write,
    irq_bind: kernel_abi_irq_bind,
    irq_unbind: kernel_abi_irq_unbind,
    heap_alloc: Some(kernel_abi_heap_alloc),
    heap_dealloc: Some(kernel_abi_heap_dealloc),
    panic_abort: Some(kernel_abi_panic_abort),
    current_domain_id: kernel_abi_current_domain_id,
    exchange_alloc_raw: kernel_abi_exchange_alloc_raw,
    exchange_dealloc_raw: kernel_abi_exchange_dealloc_raw,
    exchange_transfer_raw: kernel_abi_exchange_transfer_raw,
    ipc_create_channel_raw: kernel_abi_ipc_create_channel_raw,
    ipc_close_raw: kernel_abi_ipc_close_raw,
    ipc_send_raw: kernel_abi_ipc_send_raw,
    ipc_recv_raw: kernel_abi_ipc_recv_raw,
    register_block_device: kernel_abi_register_block_device,
    unregister_block_device: kernel_abi_unregister_block_device,
    register_nvme_namespace: kernel_abi_register_nvme_namespace,
    unregister_nvme_namespace: kernel_abi_unregister_nvme_namespace,
    register_netdev_port: kernel_abi_register_netdev_port,
    unregister_netdev_port: kernel_abi_unregister_netdev_port,
    reserved: [0; 2],
    enable_msix_raw: Some(kernel_abi_enable_msix_raw),
    disable_msix_raw: Some(kernel_abi_disable_msix_raw),
};

/// The importer retains both allocations and originating code throughout the
/// call. A valid input capsule is consumed even when options are rejected.
unsafe extern "C" fn kernel_abi_spawn(
    future: *mut kernel_api::abi::driver::AbiTaskFuture,
    options: *const kernel_api::abi::driver::AbiTaskOptions,
) -> kernel_api::abi::driver::AbiTaskSpawnResult {
    use kernel_api::abi::driver::{AbiTaskFuture, AbiTaskOptions, AbiTaskSpawnResult};
    use kernel_api::resource::task::SpawnError;
    let result = (|| {
        if future.is_null()
            || !future
                .addr()
                .is_multiple_of(core::mem::align_of::<AbiTaskFuture>())
        {
            return Err(SpawnError::InvalidOptions);
        }
        // SAFETY: the importer exclusively borrows an initialized capsule.
        let future = unsafe { (&mut *future).take() }.ok_or(SpawnError::InvalidOptions)?;
        if options.is_null()
            || !options
                .addr()
                .is_multiple_of(core::mem::align_of::<AbiTaskOptions>())
        {
            return Err(SpawnError::InvalidOptions);
        }
        // SAFETY: the importer retains the initialized options for this call.
        let options = unsafe { &*options }.decode()?;
        crate::task::spawn(future, options)
    })();
    AbiTaskSpawnResult::from_result(result)
}

/// The importer retains the aligned schedule until this synchronous call ends.
/// ABI envelope allocation and provider admission both precede publication.
unsafe extern "C" fn kernel_abi_timer_register(
    schedule: *const kernel_api::abi::driver::AbiTimerSchedule,
) -> kernel_api::abi::driver::AbiTimerAdmission {
    use kernel_api::abi::driver::{AbiTimerAdmission, AbiTimerRegistration, AbiTimerSchedule};
    use kernel_api::service::time::TimerError;
    let result = (|| {
        if schedule.is_null()
            || !schedule
                .addr()
                .is_multiple_of(core::mem::align_of::<AbiTimerSchedule>())
        {
            return Err(TimerError::InvalidOptions);
        }
        // SAFETY: the importer borrows initialized schedule storage for the call.
        let schedule = unsafe { &*schedule }.decode()?;
        let service =
            kernel_api::service::time::try_instance().ok_or(TimerError::ServiceUnavailable)?;
        AbiTimerRegistration::register(|| service.register_timer(schedule))
    })();
    AbiTimerAdmission::from_result(result)
}

extern "C" fn kernel_abi_current_task_id() -> u64 {
    crate::task::current_task_id()
}

extern "C" fn kernel_abi_current_tick() -> u64 {
    crate::task::current_tick()
}

extern "C" fn kernel_abi_time_snapshot() -> kernel_api::abi::driver::AbiTimeSnapshot {
    let installed = kernel_api::service::time::try_instance();
    let service = installed.unwrap_or_else(|| crate::drivers::time::concrete_service());
    kernel_api::abi::driver::AbiTimeSnapshot {
        available: u64::from(installed.is_some()),
        tick_ms: service.current_tick_ms(),
        uptime_ns: service.uptime_ns(),
        unix_seconds: service.unix_timestamp(),
        unix_ms: service.unix_timestamp_ms(),
    }
}

extern "C" fn kernel_abi_timer_statistics() -> kernel_api::abi::driver::AbiTimerStatistics {
    let service = kernel_api::service::time::try_instance()
        .unwrap_or_else(|| crate::drivers::time::concrete_service());
    let stats = service.stats();
    kernel_api::abi::driver::AbiTimerStatistics {
        active_timers: u64::try_from(stats.active_timers).unwrap_or(u64::MAX),
        total_fired: stats.total_fired,
        notifications: stats.notifications,
        due_timers: u64::try_from(stats.due_timers).unwrap_or(u64::MAX),
    }
}

unsafe extern "C" fn kernel_abi_pci_config_read(device: u64, out: *mut u8) -> i32 {
    use kernel_api::pci_config::PciConfigReadError;
    if out.is_null() {
        return PciConfigReadError::InvalidResponse.into_abi();
    }
    match kernel_api::service::kernel::instance()
        .read_pci_config(PackedPciLocation::from_raw(device))
    {
        Ok(snapshot) => {
            // SAFETY: the importer provides an exclusive writable 256-byte
            // buffer for this synchronous call. The snapshot is separate storage.
            unsafe { core::ptr::copy_nonoverlapping(snapshot.bytes().as_ptr(), out, 256) };
            0
        }
        Err(cause) => cause.into_abi(),
    }
}

/// The private ABI importer supplies exclusive aligned output storage; numeric
/// request fields are validated before any resource admission or publication.
unsafe extern "C" fn kernel_abi_mmio_acquire(
    device: u64,
    bar: u8,
    aperture: u8,
    offset: usize,
    length: usize,
    out: *mut kernel_api::abi::driver::AbiMmioGrant,
) -> i32 {
    use kernel_api::mmio::{MmioAcquireError, MmioByteRange, MmioRequestError, PciMmioRequest};
    let operation = || {
        if out.is_null()
            || !(out as usize)
                .is_multiple_of(core::mem::align_of::<kernel_api::abi::driver::AbiMmioGrant>())
        {
            return Err(MmioAcquireError::Request(MmioRequestError::InvalidDevice));
        }
        let device = PackedPciLocation::from_raw(device);
        let request = match aperture {
            0 if offset == 0 && length == 0 => PciMmioRequest::whole_bar(device, bar),
            1 => MmioByteRange::new(offset, length)
                .and_then(|range| PciMmioRequest::new(device, bar, range)),
            _ => return Err(MmioAcquireError::Request(MmioRequestError::OutOfBounds)),
        }
        .map_err(MmioAcquireError::Request)?;
        crate::services::authorize_pci_device_for_current_subject(device)
            .map_err(|_| MmioAcquireError::PermissionDenied)?;
        crate::resource_registry::mmio::export(crate::task::current_subject().domain, request)
    };
    match operation() {
        Ok(grant) => {
            // SAFETY: the ABI caller guarantees exclusive writable storage;
            // success transfers this sole grant after all fallible work.
            unsafe {
                out.write(grant);
            }
            0
        }
        Err(error) => error.into_abi(),
    }
}

unsafe extern "C" fn kernel_abi_mmio_release(identity: u64) {
    crate::resource_registry::mmio::release(crate::task::current_subject().domain, identity);
}

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
        provider_descriptors,
        state_hooks,
    });

    Ok(abi_driver)
}

#[derive(Debug, Clone)]
pub(crate) struct PreparedDriverExports {
    pub(crate) code: Option<Arc<crate::loader::code::CodeLease>>,
    pub entry: AbiEntryFn,
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
        let cell = crate::cpu::CurrentCpu::acquire().and_then(|cpu| cpu.execution_cell());
        let owner = crate::task::current_subject().domain;
        crate::loader::cell_runtime::initialize(cell, owner, exports_ref.init, exports_ref.fini)
            .map_err(DriverError::ModuleLifecycle)?;
    }

    let providers = exports_ref
        .providers
        .map(collect_provider_descriptors_from_export)
        .unwrap_or_default();

    Ok(PreparedDriverExports {
        code: None,
        entry: exports_ref.entry,
        providers,
        state_hooks: AbiDriverStateHooks {
            export_state: exports_ref.export_state,
            import_state: exports_ref.import_state,
        },
    })
}
