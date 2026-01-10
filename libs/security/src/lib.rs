#![allow(clippy::cargo_common_metadata)]
#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::must_use_candidate)] // Capability accessor methods
#![allow(clippy::use_self)] // Explicit type names for clarity
#![allow(clippy::missing_const_for_fn)] // Functions using Mutex
#![allow(clippy::missing_errors_doc)] // Result type documentation
#![allow(clippy::map_unwrap_or)] // map().unwrap_or() pattern is clear

//! Minimal Security crate extracted from the kernel for host-friendly unit testing.
//!
//! Provides [`Capability`], [`CapabilitySet`], and [`CapabilityManager`] with tests.

#[cfg(feature = "std")]
use std::vec::Vec;
#[cfg(feature = "std")]
use std::sync::Once;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::string::String as KernelString;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use core::fmt;
use spin::Mutex;
use core::sync::atomic::{AtomicU64, Ordering};

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
/// Interval (ms) for capability expiry daemon (host)
pub const CAPABILITY_EXPIRY_INTERVAL_MS: u64 = 1000;

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

    /// # Errors
    ///
    /// * `CapabilityError::NotPermitted` - If trying to set a capability not present in permitted set
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
    ReclamationBusy,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CapabilityError::NotPermitted => write!(f, "capability not permitted"),
            CapabilityError::CapabilityRequired => write!(f, "capability required"),
            CapabilityError::InvalidCapability => write!(f, "invalid capability"),
            CapabilityError::ReclamationBusy => write!(f, "token reclamation in progress"),
        }
    }
}

/// Grant token record (for temporally-scoped or delegatable grants)
#[derive(Debug, Clone)]
pub struct GrantToken {
    pub id: u64,
    pub cap: Capability,
    pub target: u64,
    pub issuer: u64,
    pub expires: Option<u64>,
    pub delegatable: bool,
    /// Whether the token has been revoked (pending reclamation)
    pub revoked: bool,
    /// When the token was revoked (tick), if revoked
    pub revoked_at: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclamationStatus {
    Active,
    Revoked { revoked_at: u64 },
}

struct DomainCapabilities {
    domain_id: u64,
    caps: CapabilitySet,
}

pub struct CapabilityManager {
    domains: Mutex<Vec<DomainCapabilities>>,
    bounding_set: Mutex<Capability>,
    grants: Mutex<Vec<GrantToken>>,
    next_grant_id: AtomicU64,
    in_flight: Mutex<Vec<(u64, u64)>>,
}

impl CapabilityManager {
    pub const fn new() -> Self {
        CapabilityManager {
            domains: Mutex::new(Vec::new()),
            bounding_set: Mutex::new(CAP_ALL),
            grants: Mutex::new(Vec::new()),
            next_grant_id: AtomicU64::new(1),
            in_flight: Mutex::new(Vec::new()),
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

    /// Grant with options and return a token id
    pub fn grant_capability_with_opts(
        &self,
        caller_domain: u64,
        target_domain: u64,
        cap: Capability,
        expires: Option<u64>,
        delegatable: bool,
    ) -> Result<u64, CapabilityError> {
        // Clean up expired tokens
        self.expire_grants();

        let caller_caps = self.get_capabilities(caller_domain);
        let mut allowed = false;
        if self.has_capability(caller_domain, CAP_SYS_ADMIN) {
            allowed = true;
        } else if caller_caps.is_permitted(cap) {
            allowed = true;
        } else {
            let grants = self.grants.lock();
            if grants.iter().any(|t| t.target == caller_domain && t.cap == cap && t.delegatable) {
                allowed = true;
            }
        }
        if !allowed {
            return Err(CapabilityError::NotPermitted);
        }

        // Add to permitted and effective
        let mut caps = self.get_capabilities(target_domain);
        caps.permitted |= cap;
        caps.raise(cap)?;
        self.set_capabilities(target_domain, caps);

        // Allocate token
        let token_id = self.next_grant_id.fetch_add(1, Ordering::Relaxed);
        let token = GrantToken {
            id: token_id,
            cap,
            target: target_domain,
            issuer: caller_domain,
            expires,
            delegatable,
            revoked: false,
            revoked_at: None,
        };
        self.grants.lock().push(token);
        // Log for host tests
        log::info!("[SEC] grant token {}: cap {} -> domain {} by {}", token_id, cap, target_domain, caller_domain);
        Ok(token_id)
    }

    /// Revoke a grant by token id
    pub fn revoke_grant(&self, caller_domain: u64, token_id: u64, force: bool) -> Result<(), CapabilityError> {
        self.expire_grants();
        let mut grants = self.grants.lock();
        if let Some(pos) = grants.iter().position(|t| t.id == token_id) {
            // Authorization
            if caller_domain != grants[pos].issuer && !self.has_capability(caller_domain, CAP_SYS_ADMIN) {
                return Err(CapabilityError::NotPermitted);
            }

            #[cfg(test)]
            let now: u64 = 0;
            #[cfg(not(test))]
            let now = 0u64; // host tests don't have timer

            if force {
                let token = grants.remove(pos);
                drop(grants);
                let mut caps = self.get_capabilities(token.target);
                caps.drop_permanently(token.cap);
                self.set_capabilities(token.target, caps);
                log::info!("[SEC] revoke token {}: cap {} from domain {} by {} (force)", token_id, token.cap, token.target, caller_domain);
                Ok(())
            } else {
                grants[pos].revoked = true;
                grants[pos].revoked_at = Some(now);
                let token = grants[pos].clone();
                drop(grants);
                let mut caps = self.get_capabilities(token.target);
                caps.drop_permanently(token.cap);
                self.set_capabilities(token.target, caps);
                log::info!("[SEC] mark token {} revoked: cap {} for domain {} by {}", token_id, token.cap, token.target, caller_domain);
                Ok(())
            }
        } else {
            Err(CapabilityError::InvalidCapability)
        }
    }

    /// List grants targeting domain
    pub fn list_grants(&self, domain_id: u64) -> Vec<GrantToken> {
        self.expire_grants();
        let grants = self.grants.lock();
        grants.iter().filter(|t| t.target == domain_id).cloned().collect()
    }

    fn expire_grants(&self) {
        #[cfg(test)]
        let now: u64 = 0;
        #[cfg(not(test))]
        let now = 0u64; // For host tests we don't have a timer - keep simple

        let mut expired: Vec<GrantToken> = Vec::new();
        {
            let mut grants = self.grants.lock();
            let mut i = 0usize;
            while i < grants.len() {
                if let Some(e) = grants[i].expires {
                    if e <= now {
                        expired.push(grants.remove(i));
                        continue;
                    }
                }
                i += 1;
            }
        }

        for t in expired {
            let mut caps = self.get_capabilities(t.target);
            caps.drop_permanently(t.cap);
            self.set_capabilities(t.target, caps);
            log::info!("[SEC] expired token {} cap {} for domain {}", t.id, t.cap, t.target);
        }
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

    /// Reclamation status for a token
    pub fn reclamation_status(&self, token_id: u64) -> Option<ReclamationStatus> {
        let grants = self.grants.lock();
        grants.iter().find(|t| t.id == token_id).map(|t| {
            if t.revoked {
                ReclamationStatus::Revoked { revoked_at: t.revoked_at.unwrap_or(0) }
            } else {
                ReclamationStatus::Active
            }
        })
    }

    /// Forcefully reclaim a revoked token (physically remove it); returns Err if not revoked or not found
    pub fn reclaim_token(&self, token_id: u64) -> Result<(), CapabilityError> {
        // Can't reclaim while there are in-flight users
        let in_flight = { let m = self.in_flight.lock(); m.iter().find(|(id,_)| *id == token_id).map(|(_,cnt)| *cnt).unwrap_or(0) };
        if in_flight > 0 {
            return Err(CapabilityError::ReclamationBusy);
        }

        let mut grants = self.grants.lock();
        if let Some(pos) = grants.iter().position(|t| t.id == token_id) {
            if !grants[pos].revoked {
                return Err(CapabilityError::InvalidCapability);
            }
            grants.remove(pos);
            let mut m = self.in_flight.lock();
            if let Some(p) = m.iter().position(|(id,_)| *id == token_id) { m.remove(p); }
            Ok(())
        } else {
            Err(CapabilityError::InvalidCapability)
        }
    }

    /// Increment in-flight counter for a token. Fails if token doesn't exist or is revoked.
    pub fn increment_in_flight(&self, token_id: u64) -> Result<(), CapabilityError> {
        {
            let grants = self.grants.lock();
            if let Some(t) = grants.iter().find(|t| t.id == token_id) {
                if t.revoked {
                    return Err(CapabilityError::InvalidCapability);
                }
            } else {
                return Err(CapabilityError::InvalidCapability);
            }
        }

        let mut m = self.in_flight.lock();
        if let Some(pair) = m.iter_mut().find(|(id,_)| *id == token_id) {
            pair.1 += 1;
        } else {
            m.push((token_id, 1));
        }
        Ok(())
    }

    /// Decrement in-flight counter for a token.
    pub fn decrement_in_flight(&self, token_id: u64) -> Result<(), CapabilityError> {
        let mut m = self.in_flight.lock();
        if let Some(pos) = m.iter().position(|(id,_)| *id == token_id) {
            if m[pos].1 == 0 {
                return Err(CapabilityError::InvalidCapability);
            }
            m[pos].1 -= 1;
            if m[pos].1 == 0 {
                m.remove(pos);
            }
            Ok(())
        } else {
            Err(CapabilityError::InvalidCapability)
        }
    }

    /// Current in-flight count
    pub fn in_flight_count(&self, token_id: u64) -> u64 {
        let m = self.in_flight.lock();
        m.iter().find(|(id,_)| *id == token_id).map(|(_,c)| *c).unwrap_or(0)
    }

    /// Reclaim revoked tokens that have no in-flight users
    pub fn reclaim_revoked_now(&self) {
        let mut to_reclaim: Vec<u64> = Vec::new();
        {
            let grants = self.grants.lock();
            let in_flight = self.in_flight.lock();
            for t in grants.iter() {
                if t.revoked {
                    let cnt = in_flight.iter().find(|(id,_)| *id == t.id).map(|(_,c)| *c).unwrap_or(0);
                    if cnt == 0 {
                        to_reclaim.push(t.id);
                    }
                }
            }
        }

        for id in to_reclaim {
            let mut grants = self.grants.lock();
            if let Some(pos) = grants.iter().position(|t| t.id == id && t.revoked) {
                grants.remove(pos);
                let mut m = self.in_flight.lock();
                if let Some(p) = m.iter().position(|(tid,_)| *tid == id) { m.remove(p); }
                log::info!("[SEC] reclaimed token {}", id);
            }
        }
    }
}

#[cfg(feature = "std")]
static EXPIRY_DAEMON: Once = Once::new();

/// Start the expiry daemon (host). Uses std threads in host tests.
#[cfg(feature = "std")]
pub fn spawn_expiry_daemon_task() {
    EXPIRY_DAEMON.call_once(|| {
        std::thread::spawn(|| loop {
            manager().expire_grants();
            std::thread::sleep(std::time::Duration::from_millis(CAPABILITY_EXPIRY_INTERVAL_MS));
        });
    });
}

/// Test / utility: expire now (public wrapper)
pub fn expire_grants_now() {
    manager().expire_grants();
}

#[cfg(feature = "std")]
static RECLAIM_DAEMON: Once = Once::new();

/// Start the reclamation daemon (host). Uses std threads in host tests.
#[cfg(feature = "std")]
pub fn spawn_reclamation_daemon_task() {
    RECLAIM_DAEMON.call_once(|| {
        std::thread::spawn(|| loop {
            manager().reclaim_revoked_now();
            std::thread::sleep(std::time::Duration::from_millis(CAPABILITY_EXPIRY_INTERVAL_MS));
        });
    });
}

/// Test / utility: reclaim now (public wrapper)
pub fn reclaim_revoked_now() {
    manager().reclaim_revoked_now();
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

    #[test]
    fn test_grant_with_options() {
        let caller: u64 = 1001;
        let target: u64 = 2001;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

        let res = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(9999), false);
        assert!(res.is_ok(), "grant_with_opts failed: {:?}", res);
        let token = res.unwrap();

        assert!(manager().has_capability(target, CAP_NET_BIND));

        let grants = manager().list_grants(target);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, token);
        assert_eq!(grants[0].delegatable, false);
        assert_eq!(grants[0].expires, Some(9999));
    }

    #[test]
    fn test_reclaim_token() {
        let caller: u64 = 1200;
        let target: u64 = 2200;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
        let token = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false).unwrap();
        assert!(manager().has_capability(target, CAP_NET_BIND));

        // Revoke (mark revoked)
        assert!(manager().revoke_grant(caller, token, false).is_ok());
        assert!(!manager().has_capability(target, CAP_NET_BIND));

        // Reclamation status should report revoked
        match manager().reclamation_status(token) {
            Some(ReclamationStatus::Revoked { revoked_at: _ }) => {}
            other => panic!("Expected token to be revoked, got {:?}", other),
        }

        // Now reclaim it
        assert!(manager().reclaim_token(token).is_ok());
        // Token should be gone
        assert!(manager().list_grants(target).is_empty());
    }

    #[test]
    fn test_in_flight_blocks_reclaim() {
        let caller: u64 = 3000;
        let target: u64 = 4000;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
        let token = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false).unwrap();

        // increment in-flight
        assert!(manager().increment_in_flight(token).is_ok());

        // revoke
        assert!(manager().revoke_grant(caller, token, false).is_ok());

        // reclaim_now should not remove while in-flight
        reclaim_revoked_now();
        let grants = manager().list_grants(target);
        assert_eq!(grants.len(), 1);

        // reclaim_token should return busy
        match manager().reclaim_token(token) {
            Err(CapabilityError::ReclamationBusy) => {}
            other => panic!("expected ReclamationBusy, got {:?}", other),
        }

        // decrement
        assert!(manager().decrement_in_flight(token).is_ok());

        // now reclaim
        reclaim_revoked_now();
        assert!(manager().list_grants(target).is_empty());
    }

    #[test]
    fn test_spawn_reclamation_daemon_task_idempotent() {
        spawn_reclamation_daemon_task();
        spawn_reclamation_daemon_task();
    }

    #[test]
    fn test_expire_grants_wrapper() {
        let caller: u64 = 1300;
        let target: u64 = 2300;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
        let token = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(0), false).unwrap();
        assert!(manager().has_capability(target, CAP_NET_BIND));

        // Use public wrapper
        expire_grants_now();

        assert!(!manager().has_capability(target, CAP_NET_BIND));
        assert!(manager().list_grants(target).is_empty());
    }

    #[test]
    fn test_spawn_expiry_daemon_task_idempotent() {
        spawn_expiry_daemon_task();
        spawn_expiry_daemon_task();
    }

    #[test]
    fn test_revoke_grant() {
        let caller: u64 = 1010;
        let target: u64 = 2010;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

        let token = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false).unwrap();
        assert!(manager().has_capability(target, CAP_NET_BIND));

        // Revoke by issuer (mark revoked but keep token)
        assert!(manager().revoke_grant(caller, token, false).is_ok());
        assert!(!manager().has_capability(target, CAP_NET_BIND));

        // Token should remain but be marked revoked
        let grants = manager().list_grants(target);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, token);
        assert!(grants[0].revoked);
    }
}
