//! POSIX-style Capabilities for ExoRust
//!
//! This module implements fine-grained capability-based access control
//! inspired by Linux capabilities.

use alloc::collections::BTreeSet;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use spin::Mutex;
use spin::Once;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::security::audit::{AuditEvent, AuditEventType};

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

/// Interval (ms) for capability expiry daemon
pub const CAPABILITY_EXPIRY_INTERVAL_MS: u64 = 1000;

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
    /// Token cannot be reclaimed because it still has in-flight users
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

/// Reclamation status for a token
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclamationStatus {
    Active,
    Revoked { revoked_at: u64 },
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
    /// Active grant tokens
    grants: Mutex<Vec<GrantToken>>,
    /// Next grant token id
    next_grant_id: AtomicU64,
    /// In-flight usage counters for tokens (token_id -> count) - stored as Vec to allow const init
    in_flight: Mutex<Vec<(u64, u64)>>,
    /// Test-only hook: force a failure for the next grant of a particular capability
    #[cfg(test)]
    fail_next_grant_for: Mutex<Option<Capability>>,
}

impl CapabilityManager {
    /// Create a new capability manager
    pub const fn new() -> Self {
        CapabilityManager {
            domains: Mutex::new(Vec::new()),
            bounding_set: Mutex::new(CAP_ALL),
            grants: Mutex::new(Vec::new()),
            next_grant_id: AtomicU64::new(1),
            in_flight: Mutex::new(Vec::new()),
            #[cfg(test)]
            fail_next_grant_for: Mutex::new(None),
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

    /// Grant a capability to a target domain on behalf of caller.
    ///
    /// Permission rule: caller must either have `CAP_SYS_ADMIN` or be
    /// permitted the capability being granted.
    ///
    /// This mirrors the logic used by the ExoShell's `cap.grant` helper and
    /// centralises it so it can be tested without pulling in the full shell
    /// machinery.
    pub fn grant_capability(
        &self,
        caller_domain: u64,
        target_domain: u64,
        cap: Capability,
    ) -> Result<(), CapabilityError> {
        // Check caller permissions
        let caller_caps = self.get_capabilities(caller_domain);
        if !self.has_capability(caller_domain, CAP_SYS_ADMIN) && !caller_caps.is_permitted(cap) {
            return Err(CapabilityError::NotPermitted);
        }

        // Add to permitted and effective (raise) for the target
        let mut caps = self.get_capabilities(target_domain);
        caps.permitted |= cap;
        caps.raise(cap)?;
        self.set_capabilities(target_domain, caps);
        Ok(())
    }

    /// Grant capability with options (expires, delegatable) and return a token id
    pub fn grant_capability_with_opts(
        &self,
        caller_domain: u64,
        target_domain: u64,
        cap: Capability,
        expires: Option<u64>,
        delegatable: bool,
    ) -> Result<u64, CapabilityError> {
        // Clean up expired tokens first
        self.expire_grants();

        // Check caller permissions (same policy as grant_capability) with delegation support.
        let caller_caps = self.get_capabilities(caller_domain);
        let mut allowed = false;
        if self.has_capability(caller_domain, CAP_SYS_ADMIN) {
            allowed = true;
        } else if caller_caps.is_permitted(cap) {
            allowed = true;
        } else {
            // Check if caller has a delegatable grant for this cap
            let grants = self.grants.lock();
            if grants.iter().any(|t| t.target == caller_domain && t.cap == cap && t.delegatable) {
                allowed = true;
            }
        }

        if !allowed {
            return Err(CapabilityError::NotPermitted);
        }

        // Test hook: optionally force a grant failure for a specific cap
        #[cfg(test)]
        {
            let mut f = self.fail_next_grant_for.lock();
            if let Some(fcap) = *f {
                if fcap == cap {
                    *f = None;
                    return Err(CapabilityError::InvalidCapability);
                }
            }
        }

        // Add to permitted and effective (raise) for the target
        let mut caps = self.get_capabilities(target_domain);
        caps.permitted |= cap;
        caps.raise(cap)?;
        self.set_capabilities(target_domain, caps);

        // Allocate token id and record grant
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
        self.grants.lock().push(token.clone());

        // Audit
        crate::security::audit::log_event(
            AuditEvent::new(AuditEventType::CapabilityCheck, caller_domain)
                .message(format!(
                    "grant cap {} -> domain {} (token={})",
                    capability_name(cap), target_domain, token_id
                )),
        );

        Ok(token_id)
    }

    /// Revoke a grant by token id (issuer or CAP_SYS_ADMIN may revoke)
    pub fn revoke_grant(&self, caller_domain: u64, token_id: u64, force: bool) -> Result<(), CapabilityError> {
        // Clean expired first
        self.expire_grants();

        // Find token
        let mut grants = self.grants.lock();
        if let Some(pos) = grants.iter().position(|t| t.id == token_id) {
            // Authorization: issuer or sysadmin
            if caller_domain != grants[pos].issuer && !self.has_capability(caller_domain, CAP_SYS_ADMIN) {
                return Err(CapabilityError::NotPermitted);
            }

            // Acquire 'now'
            #[cfg(not(test))]
            let now = crate::task::timer::current_tick();
            #[cfg(test)]
            let now = 0u64;

            if force {
                // Remove immediately
                let token = grants.remove(pos);
                drop(grants);

                // Remove the capability from the target domain
                let mut caps = self.get_capabilities(token.target);
                caps.drop_permanently(token.cap);
                self.set_capabilities(token.target, caps);

                crate::security::audit::log_event(
                    AuditEvent::new(AuditEventType::CapabilityCheck, caller_domain)
                        .message(format!(
                            "revoke token {} cap {} from domain {} (force)",
                            token_id,
                            capability_name(token.cap),
                            token.target
                        )),
                );

                Ok(())
            } else {
                // Mark as revoked; keep token record for reclamation visibility
                grants[pos].revoked = true;
                grants[pos].revoked_at = Some(now);
                let token = grants[pos].clone();
                drop(grants);

                // Remove capability from target (deny new operations immediately)
                let mut caps = self.get_capabilities(token.target);
                caps.drop_permanently(token.cap);
                self.set_capabilities(token.target, caps);

                crate::security::audit::log_event(
                    AuditEvent::new(AuditEventType::CapabilityCheck, caller_domain)
                        .message(format!(
                            "mark token {} cap {} revoked for domain {}",
                            token_id,
                            capability_name(token.cap),
                            token.target
                        )),
                );

                Ok(())
            }
        } else {
            Err(CapabilityError::InvalidCapability)
        }
    }

    /// List active grants targeting the given domain
    pub fn list_grants(&self, domain_id: u64) -> Vec<GrantToken> {
        self.expire_grants();
        let grants = self.grants.lock();
        grants.iter().filter(|t| t.target == domain_id).cloned().collect()
    }

    /// Expire grants whose expiry <= current tick
    fn expire_grants(&self) {
        // Acquire 'now' in ticks. In tests this is 0.
        #[cfg(not(test))]
        let now = crate::task::timer::current_tick();
        #[cfg(test)]
        let now = 0u64;

        let mut expired: Vec<GrantToken> = Vec::new();
        {
            let mut grants = self.grants.lock();
            let mut i = 0;
            while i < grants.len() {
                if let Some(e) = grants[i].expires {
                    if e <= now {
                        expired.push(grants.remove(i));
                        continue; // don't increment i
                    }
                }
                i += 1;
            }
        }

        for token in expired {
            let mut caps = self.get_capabilities(token.target);
            caps.drop_permanently(token.cap);
            self.set_capabilities(token.target, caps);

            crate::security::audit::log_event(
                AuditEvent::new(AuditEventType::CapabilityCheck, 0)
                    .message(format!(
                        "expired token {} cap {} for domain {}",
                        token.id,
                        capability_name(token.cap),
                        token.target
                    )),
            );
        }
    }

    /// Test helper: force the next grant of `cap` to fail once
    #[cfg(test)]
    pub fn force_fail_next_grant_for(&self, cap: Capability) {
        let mut f = self.fail_next_grant_for.lock();
        *f = Some(cap);
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

    /// Get reclamation status for a token (Active or Revoked with timestamp)
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
            // Clean up any residual in-flight entry
            let mut m = self.in_flight.lock();
            if let Some(p) = m.iter().position(|(id,_)| *id == token_id) { m.remove(p); }
            Ok(())
        } else {
            Err(CapabilityError::InvalidCapability)
        }
    }

    /// Increment the in-flight counter for a token. Fails if token doesn't exist or is revoked.
    pub fn increment_in_flight(&self, token_id: u64) -> Result<(), CapabilityError> {
        // Validate token exists and is not revoked
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

    /// Decrement the in-flight counter for a token. Fails if no in-flight count exists.
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

    /// Current in-flight count for a token
    pub fn in_flight_count(&self, token_id: u64) -> u64 {
        let m = self.in_flight.lock();
        m.iter().find(|(id,_)| *id == token_id).map(|(_,cnt)| *cnt).unwrap_or(0)
    }

    /// Reclaim revoked tokens that have no in-flight users. Safe to call repeatedly.
    pub fn reclaim_revoked_now(&self) {
        // Collect candidates while holding grants + in_flight snapshot
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

                crate::security::audit::log_event(
                    AuditEvent::new(AuditEventType::CapabilityCheck, 0)
                        .message(format!("reclaimed token {}", id)),
                );
            }
        }
    }
    
    /// Validate if a token is valid for a given capability
    pub fn validate_token(&self, _pid: u64, token_id: u64, required_cap: Capability) -> bool {
        // Check if token exists and grants the required capability
        // This is a simplified check. In a real system we'd check if token is assigned to pid or delegation chain.
        let grants = self.grants.lock();
        if let Some(token) = grants.iter().find(|t| t.id == token_id) {
            if token.cap == required_cap && !token.revoked {
                 // Check expiry
                 if let Some(exp) = token.expires {
                     #[cfg(not(test))]
                     let now = crate::task::timer::current_tick();
                     #[cfg(test)]
                     let now = 0;
                     if now >= exp { return false; }
                 }
                 return true;
            }
        }
        false
    }
}

/// Helper: Map resource string to capability bit
pub fn resource_to_capability(resource: &str) -> Capability {
    match resource {
        "/net/bind" => CAP_NET_BIND,
        "/net/raw" => CAP_NET_RAW,
        "/sys/admin" => CAP_SYS_ADMIN,
        "/sys/boot" => CAP_SYS_BOOT,
        "/sys/time" => CAP_SYS_TIME,
        "/sys/module" => CAP_SYS_MODULE,
        "/sys/physmem" => CAP_SYS_PHYSMEM,
        "/sys/dma" => CAP_DMA,
        "/sys/iommu" => CAP_IOMMU,
        "/sys/interrupt" => CAP_INTERRUPT,
        _ => 0,
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

    // Start maintenance daemons
    spawn_expiry_daemon_task();
    spawn_reclamation_daemon_task();
}

/// Expiry daemon (runs periodically to remove expired grants)
static CAP_EXPIRY_TASK: Once<()> = Once::new();

/// Async expiry daemon task
pub async fn expiry_daemon_task() {
    loop {
        manager().expire_grants();
        crate::task::sleep_ms(CAPABILITY_EXPIRY_INTERVAL_MS).await;
    }
}

/// Start the expiry daemon (idempotent)
pub fn spawn_expiry_daemon_task() {
    CAP_EXPIRY_TASK.call_once(|| {
        crate::task::per_core_executor::spawn(expiry_daemon_task());
    });
}

/// Test / utility: expire now (public wrapper)
pub fn expire_grants_now() {
    manager().expire_grants();
}

/// Reclamation daemon (runs periodically to reclaim revoked tokens once drained)
static CAP_RECLAIM_TASK: Once<()> = Once::new();

/// Async reclamation daemon task
pub async fn reclamation_daemon_task() {
    loop {
        manager().reclaim_revoked_now();
        crate::task::sleep_ms(CAPABILITY_EXPIRY_INTERVAL_MS).await;
    }
}

/// Start the reclamation daemon (idempotent)
pub fn spawn_reclamation_daemon_task() {
    CAP_RECLAIM_TASK.call_once(|| {
        crate::task::per_core_executor::spawn(reclamation_daemon_task());
    });
}

/// Test / utility: reclaim now (public wrapper)
pub fn reclaim_revoked_now() {
    manager().reclaim_revoked_now();
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

    #[test]
    fn test_grant_with_options() {
        let caller: u64 = 1001;
        let target: u64 = 2001;

        // Caller has permitted CAP_NET_BIND
        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

        // Grant with expiry and no delegation
        let res = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(9999), false);
        assert!(res.is_ok(), "grant_with_opts failed: {:?}", res);
        let token = res.unwrap();

        // Capability should be present
        assert!(manager().has_capability(target, CAP_NET_BIND));

        let grants = manager().list_grants(target);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, token);
        assert_eq!(grants[0].delegatable, false);
        assert_eq!(grants[0].expires, Some(9999));
    }

    #[test]
    fn test_revoke_grant() {
        let caller: u64 = 1010;
        let target: u64 = 2010;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

        let token = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false).unwrap();
        assert!(manager().has_capability(target, CAP_NET_BIND));

        // Revoke by issuer (mark revoked but keep token for reclamation)
        assert!(manager().revoke_grant(caller, token, false).is_ok());
        assert!(!manager().has_capability(target, CAP_NET_BIND));

        // Token should remain but be marked revoked
        let grants = manager().list_grants(target);
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].id, token);
        assert!(grants[0].revoked);
    }

    #[test]
    fn test_expire_grants() {
        let caller: u64 = 1100;
        let target: u64 = 2100;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

        // Grant with expiry equal to 0 -- in tests 'now' is defined as 0, so this should expire immediately
        let token = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, Some(0), false).unwrap();
        // Immediately expire internal list
        manager().expire_grants();

        // Capability should be removed
        assert!(!manager().has_capability(target, CAP_NET_BIND));
        // Token should be gone
        assert!(manager().list_grants(target).is_empty());
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
    fn test_grant_requires_permissions_manager() {
        // Use numeric domain ids to avoid depending on process_manager here
        let caller: u64 = 1000;
        let target: u64 = 2000;

        // caller has no capabilities
        manager().set_capabilities(caller, CapabilitySet::empty());

        let res = manager().grant_capability(caller, target, CAP_NET_BIND);
        assert!(res.is_err(), "Expected grant to fail without permissions");
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
        let caller: u64 = 1400;
        let target: u64 = 2400;

        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));
        let token = manager().grant_capability_with_opts(caller, target, CAP_NET_BIND, None, false).unwrap();

        // Simulate an in-flight user
        assert!(manager().increment_in_flight(token).is_ok());

        // Revoke (mark revoked)
        assert!(manager().revoke_grant(caller, token, false).is_ok());
        assert!(!manager().has_capability(target, CAP_NET_BIND));

        // reclaim_now should not remove while in-flight
        manager().reclaim_revoked_now();
        let grants = manager().list_grants(target);
        assert_eq!(grants.len(), 1);

        // manual reclaim should fail with busy
        match manager().reclaim_token(token) {
            Err(CapabilityError::ReclamationBusy) => {}
            other => panic!("Expected ReclamationBusy, got {:?}", other),
        }

        // release in-flight
        assert!(manager().decrement_in_flight(token).is_ok());

        // now reclaim
        manager().reclaim_revoked_now();
        assert!(manager().list_grants(target).is_empty());
    }

    #[test]
    fn test_spawn_reclamation_daemon_task_idempotent() {
        spawn_reclamation_daemon_task();
        spawn_reclamation_daemon_task();
    }

    #[test]
    fn test_grant_with_permitted_manager() {
        let caller: u64 = 1001;
        let target: u64 = 2001;

        // give caller permitted CAP_NET_BIND
        manager().set_capabilities(caller, CapabilitySet::with_permitted(CAP_NET_BIND));

        let res = manager().grant_capability(caller, target, CAP_NET_BIND);
        assert!(
            res.is_ok(),
            "Expected grant to succeed when caller is permitted"
        );

        // target should now have effective capability
        assert!(manager().has_capability(target, CAP_NET_BIND));
    }
}
