//! POSIX-style Capabilities for ExoRust
//!
//! This module implements fine-grained capability-based access control
//! inspired by Linux capabilities.
//!
//! # 実装の関係
//!
//! - **正規版**: `libs/security/src/lib.rs` (CapabilityManager, Grant/Revokeシステム, InFlight追跡)
//! - **本ファイル**: カーネル内部の簡略版 (ドメインベースの権限チェックのみ)
//! - **テスト用**: `tools/cap_harness/src/lib.rs` (QEMUテスト用stub)
//!
//! TODO: カーネル版を`libs/security`の正規版へ統合すべき。
//! `spin::Mutex` → `PoisonLock` への移行も必要。

use alloc::format;
use alloc::vec::Vec;
use core::fmt;
use spin::Mutex;
use spin::Once;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::security::audit::{AuditEvent, AuditEventType};

extern crate alloc;

/// Capability bit flags
mod resource_mapping;
pub use resource_mapping::*;
mod manager_impl;
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
