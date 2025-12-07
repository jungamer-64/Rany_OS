//! POSIX-style Capabilities for ExoRust
//!
//! This module implements fine-grained capability-based access control
//! inspired by Linux capabilities.

use alloc::vec::Vec;
use core::fmt;
use spin::Mutex;

extern crate alloc;

/// Capability bit flags
pub type Capability = u64;

// Capability definitions (inspired by Linux capabilities)
/// Network: Bind to privileged ports (< 1024)
pub const CAP_NET_BIND: Capability = 1 << 0;
/// Network: Use raw sockets
pub const CAP_NET_RAW: Capability = 1 << 1;
/// System: General system administration
pub const CAP_SYS_ADMIN: Capability = 1 << 2;
/// System: Reboot the system
pub const CAP_SYS_BOOT: Capability = 1 << 3;
/// System: Set system time
pub const CAP_SYS_TIME: Capability = 1 << 4;
/// System: Trace/debug processes
pub const CAP_SYS_PTRACE: Capability = 1 << 5;
/// File: Override DAC restrictions
pub const CAP_DAC_OVERRIDE: Capability = 1 << 6;
/// Signal: Send signals to any process
pub const CAP_KILL: Capability = 1 << 7;
/// Identity: Change UID
pub const CAP_SETUID: Capability = 1 << 8;
/// Identity: Change GID
pub const CAP_SETGID: Capability = 1 << 9;
/// File: Change file ownership
pub const CAP_CHOWN: Capability = 1 << 10;
/// File: Act as file owner
pub const CAP_FOWNER: Capability = 1 << 11;
/// System: Perform raw I/O
pub const CAP_SYS_RAWIO: Capability = 1 << 12;
/// Memory: Lock memory
pub const CAP_IPC_LOCK: Capability = 1 << 13;
/// Scheduling: Set process priority
pub const CAP_SYS_NICE: Capability = 1 << 14;
/// Network: Configure network interfaces
pub const CAP_NET_ADMIN: Capability = 1 << 15;
/// System: Load/unload modules
pub const CAP_SYS_MODULE: Capability = 1 << 16;
/// System: Access physical memory
pub const CAP_SYS_PHYSMEM: Capability = 1 << 17;
/// DMA: Configure DMA operations
pub const CAP_DMA: Capability = 1 << 18;
/// IOMMU: Configure IOMMU
pub const CAP_IOMMU: Capability = 1 << 19;
/// Interrupt: Register interrupt handlers
pub const CAP_INTERRUPT: Capability = 1 << 20;

/// All capabilities combined
pub const CAP_ALL: Capability = (1 << 21) - 1;

/// No capabilities
pub const CAP_NONE: Capability = 0;

/// Capability set containing permitted, effective, and inheritable sets
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet {
    /// Capabilities that can be used
    pub effective: Capability,
    /// Maximum capabilities that can be acquired
    pub permitted: Capability,
    /// Capabilities inherited across execve
    pub inheritable: Capability,
    /// Capabilities that are always effective when permitted
    pub ambient: Capability,
}

impl CapabilitySet {
    /// Create an empty capability set
    pub const fn empty() -> Self {
        CapabilitySet {
            effective: CAP_NONE,
            permitted: CAP_NONE,
            inheritable: CAP_NONE,
            ambient: CAP_NONE,
        }
    }

    /// Create a capability set with all capabilities
    pub const fn full() -> Self {
        CapabilitySet {
            effective: CAP_ALL,
            permitted: CAP_ALL,
            inheritable: CAP_ALL,
            ambient: CAP_ALL,
        }
    }

    /// Create a new capability set with specific permitted capabilities
    pub const fn with_permitted(permitted: Capability) -> Self {
        CapabilitySet {
            effective: permitted,
            permitted,
            inheritable: CAP_NONE,
            ambient: CAP_NONE,
        }
    }

    /// Check if a capability is effective
    pub fn has_capability(&self, cap: Capability) -> bool {
        (self.effective & cap) == cap
    }

    /// Check if a capability is permitted
    pub fn is_permitted(&self, cap: Capability) -> bool {
        (self.permitted & cap) == cap
    }

    /// Add a capability to the effective set (if permitted)
    pub fn raise(&mut self, cap: Capability) -> Result<(), CapabilityError> {
        if !self.is_permitted(cap) {
            return Err(CapabilityError::NotPermitted);
        }
        self.effective |= cap;
        Ok(())
    }

    /// Remove a capability from the effective set
    pub fn drop(&mut self, cap: Capability) {
        self.effective &= !cap;
    }

    /// Drop a capability from all sets (permanent)
    pub fn drop_permanently(&mut self, cap: Capability) {
        self.effective &= !cap;
        self.permitted &= !cap;
        self.inheritable &= !cap;
        self.ambient &= !cap;
    }

    /// Clear all effective capabilities
    pub fn clear_effective(&mut self) {
        self.effective = CAP_NONE;
    }

    /// Set inheritable capabilities (must be subset of permitted)
    pub fn set_inheritable(&mut self, caps: Capability) -> Result<(), CapabilityError> {
        if (caps & !self.permitted) != 0 {
            return Err(CapabilityError::NotPermitted);
        }
        self.inheritable = caps;
        Ok(())
    }

    /// Calculate new capabilities after exec
    pub fn after_exec(&self, file_permitted: Capability, file_inheritable: Capability) -> Self {
        // P'(permitted) = (P(inheritable) & F(inheritable)) | (F(permitted) & cap_bset)
        let new_permitted = (self.inheritable & file_inheritable) | file_permitted;

        // P'(effective) = F(effective) ? P'(permitted) : 0  (simplified)
        let new_effective = new_permitted;

        // P'(inheritable) = P(inheritable)
        let new_inheritable = self.inheritable;

        CapabilitySet {
            effective: new_effective,
            permitted: new_permitted,
            inheritable: new_inheritable,
            ambient: self.ambient & new_permitted,
        }
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CapabilitySet {{ eff: {:016x}, perm: {:016x}, inh: {:016x} }}",
            self.effective, self.permitted, self.inheritable
        )
    }
}

/// Capability errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    /// Capability not in permitted set
    NotPermitted,
    /// Operation requires capability
    CapabilityRequired,
    /// Invalid capability value
    InvalidCapability,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityError::NotPermitted => write!(f, "capability not permitted"),
            CapabilityError::CapabilityRequired => write!(f, "capability required"),
            CapabilityError::InvalidCapability => write!(f, "invalid capability"),
        }
    }
}

/// Per-domain capability state
struct DomainCapabilities {
    domain_id: u64,
    caps: CapabilitySet,
}

/// Capability manager
pub struct CapabilityManager {
    /// Domain capabilities
    domains: Mutex<Vec<DomainCapabilities>>,
    /// Bounding set (maximum capabilities for any domain)
    bounding_set: Mutex<Capability>,
}

impl CapabilityManager {
    /// Create a new capability manager
    pub const fn new() -> Self {
        CapabilityManager {
            domains: Mutex::new(Vec::new()),
            bounding_set: Mutex::new(CAP_ALL),
        }
    }

    /// Get or create capabilities for a domain
    pub fn get_capabilities(&self, domain_id: u64) -> CapabilitySet {
        let domains = self.domains.lock();
        domains
            .iter()
            .find(|d| d.domain_id == domain_id)
            .map(|d| d.caps)
            .unwrap_or(CapabilitySet::empty())
    }

    /// Set capabilities for a domain
    pub fn set_capabilities(&self, domain_id: u64, caps: CapabilitySet) {
        let mut domains = self.domains.lock();
        let bounding = *self.bounding_set.lock();

        // Apply bounding set
        let bounded_caps = CapabilitySet {
            effective: caps.effective & bounding,
            permitted: caps.permitted & bounding,
            inheritable: caps.inheritable & bounding,
            ambient: caps.ambient & bounding,
        };

        if let Some(domain) = domains.iter_mut().find(|d| d.domain_id == domain_id) {
            domain.caps = bounded_caps;
        } else {
            domains.push(DomainCapabilities {
                domain_id,
                caps: bounded_caps,
            });
        }
    }

    /// Check if domain has a capability
    pub fn has_capability(&self, domain_id: u64, cap: Capability) -> bool {
        self.get_capabilities(domain_id).has_capability(cap)
    }

    /// Require a capability (returns error if not present)
    pub fn require_capability(
        &self,
        domain_id: u64,
        cap: Capability,
    ) -> Result<(), CapabilityError> {
        if self.has_capability(domain_id, cap) {
            Ok(())
        } else {
            Err(CapabilityError::CapabilityRequired)
        }
    }

    /// Drop a capability from the bounding set (permanent)
    pub fn drop_from_bounding(&self, cap: Capability) {
        let mut bounding = self.bounding_set.lock();
        *bounding &= !cap;
    }

    /// Get the bounding set
    pub fn bounding_set(&self) -> Capability {
        *self.bounding_set.lock()
    }

    /// Remove domain
    pub fn remove_domain(&self, domain_id: u64) {
        let mut domains = self.domains.lock();
        domains.retain(|d| d.domain_id != domain_id);
    }
}

/// Global capability manager
static CAPABILITY_MANAGER: CapabilityManager = CapabilityManager::new();

/// Get the global capability manager
pub fn manager() -> &'static CapabilityManager {
    &CAPABILITY_MANAGER
}

/// Initialize capabilities for kernel domain
pub fn init() {
    // Kernel domain gets all capabilities
    CAPABILITY_MANAGER.set_capabilities(0, CapabilitySet::full());
}

/// Get capability name
pub fn capability_name(cap: Capability) -> &'static str {
    match cap {
        CAP_NET_BIND => "CAP_NET_BIND",
        CAP_NET_RAW => "CAP_NET_RAW",
        CAP_SYS_ADMIN => "CAP_SYS_ADMIN",
        CAP_SYS_BOOT => "CAP_SYS_BOOT",
        CAP_SYS_TIME => "CAP_SYS_TIME",
        CAP_SYS_PTRACE => "CAP_SYS_PTRACE",
        CAP_DAC_OVERRIDE => "CAP_DAC_OVERRIDE",
        CAP_KILL => "CAP_KILL",
        CAP_SETUID => "CAP_SETUID",
        CAP_SETGID => "CAP_SETGID",
        CAP_CHOWN => "CAP_CHOWN",
        CAP_FOWNER => "CAP_FOWNER",
        CAP_SYS_RAWIO => "CAP_SYS_RAWIO",
        CAP_IPC_LOCK => "CAP_IPC_LOCK",
        CAP_SYS_NICE => "CAP_SYS_NICE",
        CAP_NET_ADMIN => "CAP_NET_ADMIN",
        CAP_SYS_MODULE => "CAP_SYS_MODULE",
        CAP_SYS_PHYSMEM => "CAP_SYS_PHYSMEM",
        CAP_DMA => "CAP_DMA",
        CAP_IOMMU => "CAP_IOMMU",
        CAP_INTERRUPT => "CAP_INTERRUPT",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_set() {
        let mut caps = CapabilitySet::with_permitted(CAP_NET_BIND | CAP_NET_RAW);

        assert!(caps.has_capability(CAP_NET_BIND));
        assert!(caps.has_capability(CAP_NET_RAW));
        assert!(!caps.has_capability(CAP_SYS_ADMIN));

        caps.drop(CAP_NET_BIND);
        assert!(!caps.has_capability(CAP_NET_BIND));

        // Can raise again since it's still permitted
        assert!(caps.raise(CAP_NET_BIND).is_ok());
        assert!(caps.has_capability(CAP_NET_BIND));
    }

    #[test]
    fn test_raise_not_permitted() {
        let mut caps = CapabilitySet::with_permitted(CAP_NET_BIND);

        assert!(caps.raise(CAP_SYS_ADMIN).is_err());
    }
}
