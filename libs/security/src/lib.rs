#![cfg_attr(not(feature = "std"), no_std)]

//! Minimal Security crate extracted from the kernel for host-friendly unit testing.
//!
//! Provides Capability, CapabilitySet, and CapabilityManager with tests.

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String as KernelString;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::fmt;
use spin::Mutex;

pub type Capability = u64;

pub const CAP_NET_BIND: Capability = 1 << 0;
pub const CAP_NET_RAW: Capability = 1 << 1;
pub const CAP_SYS_ADMIN: Capability = 1 << 2;
pub const CAP_SYS_BOOT: Capability = 1 << 3;
pub const CAP_SYS_TIME: Capability = 1 << 4;
pub const CAP_SYS_PTRACE: Capability = 1 << 5;
pub const CAP_DAC_OVERRIDE: Capability = 1 << 6;
pub const CAP_KILL: Capability = 1 << 7;
pub const CAP_SETUID: Capability = 1 << 8;
pub const CAP_SETGID: Capability = 1 << 9;
pub const CAP_CHOWN: Capability = 1 << 10;
pub const CAP_FOWNER: Capability = 1 << 11;
pub const CAP_SYS_RAWIO: Capability = 1 << 12;
pub const CAP_IPC_LOCK: Capability = 1 << 13;
pub const CAP_SYS_NICE: Capability = 1 << 14;
pub const CAP_NET_ADMIN: Capability = 1 << 15;
pub const CAP_SYS_MODULE: Capability = 1 << 16;
pub const CAP_SYS_PHYSMEM: Capability = 1 << 17;
pub const CAP_DMA: Capability = 1 << 18;
pub const CAP_IOMMU: Capability = 1 << 19;
pub const CAP_INTERRUPT: Capability = 1 << 20;

pub const CAP_ALL: Capability = (1 << 21) - 1;
pub const CAP_NONE: Capability = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilitySet {
    pub effective: Capability,
    pub permitted: Capability,
    pub inheritable: Capability,
    pub ambient: Capability,
}

impl CapabilitySet {
    pub const fn empty() -> Self {
        CapabilitySet {
            effective: CAP_NONE,
            permitted: CAP_NONE,
            inheritable: CAP_NONE,
            ambient: CAP_NONE,
        }
    }

    pub const fn full() -> Self {
        CapabilitySet {
            effective: CAP_ALL,
            permitted: CAP_ALL,
            inheritable: CAP_ALL,
            ambient: CAP_ALL,
        }
    }

    pub const fn with_permitted(permitted: Capability) -> Self {
        CapabilitySet {
            effective: permitted,
            permitted,
            inheritable: CAP_NONE,
            ambient: CAP_NONE,
        }
    }

    #[must_use]
    pub fn has_capability(&self, cap: Capability) -> bool {
        (self.effective & cap) == cap
    }

    #[must_use]
    pub fn is_permitted(&self, cap: Capability) -> bool {
        (self.permitted & cap) == cap
    }

    pub fn raise(&mut self, cap: Capability) -> Result<(), CapabilityError> {
        if !self.is_permitted(cap) {
            return Err(CapabilityError::NotPermitted);
        }
        self.effective |= cap;
        Ok(())
    }

    pub fn drop(&mut self, cap: Capability) {
        self.effective &= !cap;
    }

    pub fn drop_permanently(&mut self, cap: Capability) {
        self.effective &= !cap;
        self.permitted &= !cap;
        self.inheritable &= !cap;
        self.ambient &= !cap;
    }

    pub fn clear_effective(&mut self) {
        self.effective = CAP_NONE;
    }

    pub fn set_inheritable(&mut self, caps: Capability) -> Result<(), CapabilityError> {
        if (caps & !self.permitted) != 0 {
            return Err(CapabilityError::NotPermitted);
        }
        self.inheritable = caps;
        Ok(())
    }

    #[must_use]
    pub fn after_exec(&self, file_permitted: Capability, file_inheritable: Capability) -> Self {
        let new_permitted = (self.inheritable & file_inheritable) | file_permitted;
        let new_effective = new_permitted;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityError {
    NotPermitted,
    CapabilityRequired,
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

struct DomainCapabilities {
    domain_id: u64,
    caps: CapabilitySet,
}

pub struct CapabilityManager {
    domains: Mutex<Vec<DomainCapabilities>>,
    bounding_set: Mutex<Capability>,
}

impl CapabilityManager {
    pub const fn new() -> Self {
        CapabilityManager {
            domains: Mutex::new(Vec::new()),
            bounding_set: Mutex::new(CAP_ALL),
        }
    }

    pub fn get_capabilities(&self, domain_id: u64) -> CapabilitySet {
        let domains = self.domains.lock();
        domains
            .iter()
            .find(|d| d.domain_id == domain_id)
            .map(|d| d.caps)
            .unwrap_or(CapabilitySet::empty())
    }

    pub fn set_capabilities(&self, domain_id: u64, caps: CapabilitySet) {
        let mut domains = self.domains.lock();
        let bounding = *self.bounding_set.lock();
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

    pub fn has_capability(&self, domain_id: u64, cap: Capability) -> bool {
        self.get_capabilities(domain_id).has_capability(cap)
    }

    pub fn grant_capability(
        &self,
        caller_domain: u64,
        target_domain: u64,
        cap: Capability,
    ) -> Result<(), CapabilityError> {
        let caller_caps = self.get_capabilities(caller_domain);
        if !self.has_capability(caller_domain, CAP_SYS_ADMIN) && !caller_caps.is_permitted(cap) {
            return Err(CapabilityError::NotPermitted);
        }
        let mut caps = self.get_capabilities(target_domain);
        caps.permitted |= cap;
        caps.raise(cap)?;
        self.set_capabilities(target_domain, caps);
        Ok(())
    }

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

    pub fn drop_from_bounding(&self, cap: Capability) {
        let mut bounding = self.bounding_set.lock();
        *bounding &= !cap;
    }

    pub fn bounding_set(&self) -> Capability {
        *self.bounding_set.lock()
    }

    pub fn remove_domain(&self, domain_id: u64) {
        let mut domains = self.domains.lock();
        domains.retain(|d| d.domain_id != domain_id);
    }
}

static MANAGER: CapabilityManager = CapabilityManager::new();

pub fn manager() -> &'static CapabilityManager {
    &MANAGER
}

impl Default for CapabilityManager {
    fn default() -> Self {
        Self::new()
    }
}

pub fn init() {
    MANAGER.set_capabilities(0, CapabilitySet::full());
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

        assert!(caps.raise(CAP_NET_BIND).is_ok());
        assert!(caps.has_capability(CAP_NET_BIND));
    }

    #[test]
    fn test_raise_not_permitted() {
        let mut caps = CapabilitySet::with_permitted(CAP_NET_BIND);

        assert!(caps.raise(CAP_SYS_ADMIN).is_err());
    }

    #[test]
    fn test_grant_requires_permissions_manager() {
        let caller: u64 = 1000;
        let target: u64 = 2000;

        manager().set_capabilities(caller, CapabilitySet::empty());

        let res = manager().grant_capability(caller, target, CAP_NET_BIND);
        assert!(res.is_err(), "Expected grant to fail without permissions");
    }

    #[test]
    fn test_grant_with_permitted_manager() {
        let caller: u64 = 1001;
        let target: u64 = 2001;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

        let res = manager().grant_capability(caller, target, CAP_NET_BIND);
        assert!(
            res.is_ok(),
            "Expected grant to succeed when caller is permitted"
        );

        assert!(manager().has_capability(target, CAP_NET_BIND));
    }
}
