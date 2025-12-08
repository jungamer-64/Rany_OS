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

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use kernel_api::driver::{Driver, DriverType, DeviceId, DriverState};
use spin::Mutex;

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
    drivers: Mutex<Vec<DriverEntry>>,
}

impl DriverRegistry {
    /// Create a new registry
    pub const fn new() -> Self {
        Self {
            drivers: Mutex::new(Vec::new()),
        }
    }

    /// Register a new driver
    pub fn register(&self, driver: Box<dyn Driver>) -> DriverHandle {
        let mut drivers = self.drivers.lock();
        let id = drivers.len();
        
        crate::log!("[DRIVER] Registering driver: {} (type: {:?})\n", 
                   driver.name(), driver.driver_type());
        
        drivers.push(DriverEntry::new(driver));
        DriverHandle(id)
    }

    /// Probe a specific driver
    pub fn probe(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut drivers = self.drivers.lock();
        let entry = drivers.get_mut(handle.0)
            .ok_or(DriverError::NotFound)?;
        
        if entry.state != DriverState::Registered {
            return Err(DriverError::InvalidState);
        }
        
        crate::log!("[DRIVER] Probing driver: {}\n", entry.driver.name());
        
        match entry.driver.probe() {
            Ok(()) => {
                entry.state = DriverState::Probed;
                crate::log!("[DRIVER] Probe successful: {}\n", entry.driver.name());
                Ok(())
            }
            Err(e) => {
                entry.state = DriverState::Error;
                crate::log!("[DRIVER] Probe failed: {} - {:?}\n", entry.driver.name(), e);
                Err(DriverError::ProbeFailed)
            }
        }
    }

    /// Start a probed driver
    pub fn start(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut drivers = self.drivers.lock();
        let entry = drivers.get_mut(handle.0)
            .ok_or(DriverError::NotFound)?;
        
        if entry.state != DriverState::Probed && entry.state != DriverState::Stopped {
            return Err(DriverError::InvalidState);
        }
        
        crate::log!("[DRIVER] Starting driver: {}\n", entry.driver.name());
        
        match entry.driver.start() {
            Ok(()) => {
                entry.state = DriverState::Running;
                Ok(())
            }
            Err(e) => {
                entry.state = DriverState::Error;
                crate::log!("[DRIVER] Start failed: {} - {:?}\n", entry.driver.name(), e);
                Err(DriverError::StartFailed)
            }
        }
    }

    /// Stop a running driver
    pub fn stop(&self, handle: DriverHandle) -> Result<(), DriverError> {
        let mut drivers = self.drivers.lock();
        let entry = drivers.get_mut(handle.0)
            .ok_or(DriverError::NotFound)?;
        
        if entry.state != DriverState::Running {
            return Err(DriverError::InvalidState);
        }
        
        crate::log!("[DRIVER] Stopping driver: {}\n", entry.driver.name());
        
        match entry.driver.stop() {
            Ok(()) => {
                entry.state = DriverState::Stopped;
                Ok(())
            }
            Err(e) => {
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
        self.drivers.lock()
            .get(handle.0)
            .map(|e| e.state)
    }

    /// Get driver name
    pub fn name(&self, handle: DriverHandle) -> Option<String> {
        self.drivers.lock()
            .get(handle.0)
            .map(|e| String::from(e.driver.name()))
    }

    /// Find drivers by type
    pub fn find_by_type(&self, driver_type: DriverType) -> Vec<DriverHandle> {
        self.drivers.lock()
            .iter()
            .enumerate()
            .filter(|(_, e)| e.driver.driver_type() == driver_type)
            .map(|(i, _)| DriverHandle(i))
            .collect()
    }

    /// Find driver that supports a device
    pub fn find_for_device(&self, device_id: &DeviceId) -> Option<DriverHandle> {
        self.drivers.lock()
            .iter()
            .enumerate()
            .find(|(_, e)| {
                e.driver.supported_devices().iter().any(|d| {
                    d.vendor == device_id.vendor && d.device == device_id.device
                })
            })
            .map(|(i, _)| DriverHandle(i))
    }

    /// Get count of registered drivers
    pub fn count(&self) -> usize {
        self.drivers.lock().len()
    }

    /// Get count of running drivers
    pub fn running_count(&self) -> usize {
        self.drivers.lock()
            .iter()
            .filter(|e| e.state == DriverState::Running)
            .count()
    }

    /// List all drivers with their states
    pub fn list(&self) -> Vec<(DriverHandle, String, DriverType, DriverState)> {
        self.drivers.lock()
            .iter()
            .enumerate()
            .map(|(i, e)| (
                DriverHandle(i),
                String::from(e.driver.name()),
                e.driver.driver_type(),
                e.state,
            ))
            .collect()
    }

    /// Probe all registered drivers
    pub fn probe_all(&self) {
        let count = self.count();
        for i in 0..count {
            let _ = self.probe(DriverHandle(i));
        }
    }

    /// Start all probed drivers
    pub fn start_all(&self) {
        let count = self.count();
        for i in 0..count {
            if self.state(DriverHandle(i)) == Some(DriverState::Probed) {
                let _ = self.start(DriverHandle(i));
            }
        }
    }

    /// Stop all running drivers
    pub fn stop_all(&self) {
        let count = self.count();
        for i in 0..count {
            if self.state(DriverHandle(i)) == Some(DriverState::Running) {
                let _ = self.stop(DriverHandle(i));
            }
        }
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
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "driver not found"),
            Self::InvalidState => write!(f, "invalid driver state for operation"),
            Self::ProbeFailed => write!(f, "driver probe failed"),
            Self::StartFailed => write!(f, "driver start failed"),
            Self::StopFailed => write!(f, "driver stop failed"),
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
pub fn register_driver(driver: Box<dyn Driver>) -> DriverHandle {
    DRIVER_REGISTRY.register(driver)
}
