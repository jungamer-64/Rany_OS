//! Security Integration for ExoRust Kernel
//!
//! Binds security contexts to devices and domains.

extern crate alloc;

use super::device_manager::{DeviceInfo, DeviceManager, DeviceType};
use alloc::vec;
use alloc::vec::Vec;

/// Security context for a device
#[derive(Debug, Clone)]
pub struct DeviceSecurityContext {
    /// Device ID
    pub device_id: u64,
    /// Required capabilities
    pub required_capabilities: Vec<DeviceCapability>,
    /// Security label
    pub security_label: SecurityLabel,
    /// Allowed domains
    pub allowed_domains: Vec<u64>,
}

/// Device-specific capability requirements
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceCapability {
    /// Can perform DMA
    DmaAccess,
    /// Can generate interrupts
    InterruptSource,
    /// Can access raw I/O ports
    RawIo,
    /// Can access PCI configuration space
    PciConfig,
    /// Can access network stack
    NetworkAccess,
    /// Can access storage
    StorageAccess,
    /// Can access display
    DisplayAccess,
}

/// Security label for MAC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityLabel {
    /// Security level
    pub level: u8,
    /// Category bitmap
    pub categories: u64,
}

impl SecurityLabel {
    /// System level (highest)
    pub const SYSTEM: Self = Self {
        level: 3,
        categories: 0xFFFFFFFFFFFFFFFF,
    };
    /// Driver level
    pub const DRIVER: Self = Self {
        level: 2,
        categories: 0,
    };
    /// Application level
    pub const APPLICATION: Self = Self {
        level: 1,
        categories: 0,
    };
    /// Untrusted level (lowest)
    pub const UNTRUSTED: Self = Self {
        level: 0,
        categories: 0,
    };

    /// Check if this label dominates another
    pub fn dominates(&self, other: &Self) -> bool {
        self.level >= other.level && (self.categories & other.categories) == other.categories
    }
}

/// Security integration manager
pub struct SecurityIntegration {
    /// Device security contexts
    device_contexts: Vec<DeviceSecurityContext>,
}

impl SecurityIntegration {
    /// Create a new security integration manager
    pub fn new() -> Self {
        SecurityIntegration {
            device_contexts: Vec::new(),
        }
    }

    /// Bind all devices to security contexts
    pub fn bind_all_devices(&mut self, device_manager: &DeviceManager) {
        self.device_contexts.clear();

        for device in device_manager.all() {
            let context = self.create_context_for_device(device);
            self.device_contexts.push(context);
        }
    }

    /// Create security context for a device
    fn create_context_for_device(&self, device: &DeviceInfo) -> DeviceSecurityContext {
        let (capabilities, label) = match device.device_type {
            DeviceType::Storage => (
                vec![
                    DeviceCapability::DmaAccess,
                    DeviceCapability::InterruptSource,
                    DeviceCapability::StorageAccess,
                ],
                SecurityLabel::DRIVER,
            ),
            DeviceType::Network => (
                vec![
                    DeviceCapability::DmaAccess,
                    DeviceCapability::InterruptSource,
                    DeviceCapability::NetworkAccess,
                ],
                SecurityLabel::DRIVER,
            ),
            DeviceType::Display => (
                vec![DeviceCapability::DmaAccess, DeviceCapability::DisplayAccess],
                SecurityLabel::DRIVER,
            ),
            DeviceType::Usb => (
                vec![
                    DeviceCapability::DmaAccess,
                    DeviceCapability::InterruptSource,
                ],
                SecurityLabel::DRIVER,
            ),
            DeviceType::Bridge => (vec![DeviceCapability::PciConfig], SecurityLabel::SYSTEM),
            _ => (vec![], SecurityLabel::UNTRUSTED),
        };

        DeviceSecurityContext {
            device_id: device.id,
            required_capabilities: capabilities,
            security_label: label,
            allowed_domains: Vec::new(),
        }
    }

    /// Get security context for device
    pub fn get_context(&self, device_id: u64) -> Option<&DeviceSecurityContext> {
        self.device_contexts
            .iter()
            .find(|c| c.device_id == device_id)
    }

    /// Grant domain access to device
    pub fn grant_access(&mut self, device_id: u64, domain_id: u64) {
        if let Some(context) = self
            .device_contexts
            .iter_mut()
            .find(|c| c.device_id == device_id)
        {
            if !context.allowed_domains.contains(&domain_id) {
                context.allowed_domains.push(domain_id);
            }
        }
    }

    /// Revoke domain access from device
    pub fn revoke_access(&mut self, device_id: u64, domain_id: u64) {
        if let Some(context) = self
            .device_contexts
            .iter_mut()
            .find(|c| c.device_id == device_id)
        {
            context.allowed_domains.retain(|&id| id != domain_id);
        }
    }

    /// Check if domain can access device
    pub fn check_access(&self, device_id: u64, domain_id: u64) -> bool {
        if let Some(context) = self.get_context(device_id) {
            // System domains have access to everything
            // For now, kernel (domain 0) always has access
            if domain_id == 0 {
                return true;
            }

            context.allowed_domains.contains(&domain_id)
        } else {
            false
        }
    }

    /// Get all device contexts
    pub fn all_contexts(&self) -> &[DeviceSecurityContext] {
        &self.device_contexts
    }
}

impl Default for SecurityIntegration {
    fn default() -> Self {
        Self::new()
    }
}

/// Capability checker for domain operations
pub struct CapabilityChecker;

impl CapabilityChecker {
    /// Check if operation is allowed
    pub fn check_device_operation(
        device_type: DeviceType,
        operation: DeviceCapability,
        domain_security_level: u8,
    ) -> bool {
        // System level can do anything
        if domain_security_level >= SecurityLabel::SYSTEM.level {
            return true;
        }

        // Driver level can access devices
        if domain_security_level >= SecurityLabel::DRIVER.level {
            match (device_type, operation) {
                // Drivers can use DMA and handle interrupts for their devices
                (_, DeviceCapability::DmaAccess) => true,
                (_, DeviceCapability::InterruptSource) => true,
                // Specific device access
                (DeviceType::Storage, DeviceCapability::StorageAccess) => true,
                (DeviceType::Network, DeviceCapability::NetworkAccess) => true,
                (DeviceType::Display, DeviceCapability::DisplayAccess) => true,
                // PCI config requires system level
                (_, DeviceCapability::PciConfig) => false,
                (_, DeviceCapability::RawIo) => false,
                _ => false,
            }
        } else {
            // Application and untrusted cannot directly access devices
            false
        }
    }
}
