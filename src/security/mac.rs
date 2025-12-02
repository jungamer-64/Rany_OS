//! Mandatory Access Control (MAC) for ExoRust
//!
//! This module implements a Bell-LaPadula style MAC policy
//! with support for security levels and categories.

use core::fmt;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use alloc::string::String;
use spin::Mutex;

extern crate alloc;

/// Security level (hierarchical)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SecurityLevel {
    /// Public - lowest security
    Public = 0,
    /// Internal use
    Internal = 1,
    /// Confidential
    Confidential = 2,
    /// Secret
    Secret = 3,
    /// Top Secret - highest security
    TopSecret = 4,
}

impl SecurityLevel {
    /// Get level name
    pub fn name(&self) -> &'static str {
        match self {
            SecurityLevel::Public => "Public",
            SecurityLevel::Internal => "Internal",
            SecurityLevel::Confidential => "Confidential",
            SecurityLevel::Secret => "Secret",
            SecurityLevel::TopSecret => "Top Secret",
        }
    }
    
    /// Check if this level dominates another
    pub fn dominates(&self, other: SecurityLevel) -> bool {
        (*self as u8) >= (other as u8)
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Public
    }
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Security category (non-hierarchical compartments)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum SecurityCategory {
    /// No special category
    None = 0,
    /// Network operations
    Network = 1,
    /// File system operations
    FileSystem = 2,
    /// Process management
    Process = 3,
    /// Memory management
    Memory = 4,
    /// Hardware access
    Hardware = 5,
    /// Cryptographic operations
    Crypto = 6,
    /// Audit/logging
    Audit = 7,
    /// Inter-process communication
    Ipc = 8,
    /// Custom category 1
    Custom1 = 100,
    /// Custom category 2
    Custom2 = 101,
    /// Custom category 3
    Custom3 = 102,
}

/// Security context combining level and categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityContext {
    /// Security level
    pub level: SecurityLevel,
    /// Categories (compartments)
    pub categories: BTreeSet<SecurityCategory>,
    /// User ID
    pub user_id: u32,
    /// Role ID
    pub role_id: u32,
    /// Type/domain
    pub type_name: String,
}

impl SecurityContext {
    /// Create a new security context
    pub fn new(level: SecurityLevel, user_id: u32, role_id: u32) -> Self {
        SecurityContext {
            level,
            categories: BTreeSet::new(),
            user_id,
            role_id,
            type_name: String::from("unconfined"),
        }
    }
    
    /// Create a minimal (public) context
    pub fn public() -> Self {
        SecurityContext {
            level: SecurityLevel::Public,
            categories: BTreeSet::new(),
            user_id: 0,
            role_id: 0,
            type_name: String::from("public"),
        }
    }
    
    /// Create a kernel context
    pub fn kernel() -> Self {
        let mut categories = BTreeSet::new();
        categories.insert(SecurityCategory::Network);
        categories.insert(SecurityCategory::FileSystem);
        categories.insert(SecurityCategory::Process);
        categories.insert(SecurityCategory::Memory);
        categories.insert(SecurityCategory::Hardware);
        categories.insert(SecurityCategory::Crypto);
        categories.insert(SecurityCategory::Audit);
        categories.insert(SecurityCategory::Ipc);
        
        SecurityContext {
            level: SecurityLevel::TopSecret,
            categories,
            user_id: 0,
            role_id: 0,
            type_name: String::from("kernel"),
        }
    }
    
    /// Add a category
    pub fn add_category(&mut self, category: SecurityCategory) {
        self.categories.insert(category);
    }
    
    /// Remove a category
    pub fn remove_category(&mut self, category: SecurityCategory) {
        self.categories.remove(&category);
    }
    
    /// Check if context has a category
    pub fn has_category(&self, category: SecurityCategory) -> bool {
        self.categories.contains(&category)
    }
    
    /// Check if this context dominates another (Bell-LaPadula)
    /// A dominates B if A.level >= B.level AND A.categories ⊇ B.categories
    pub fn dominates(&self, other: &SecurityContext) -> bool {
        self.level.dominates(other.level) && 
            other.categories.is_subset(&self.categories)
    }
    
    /// Set type/domain name
    pub fn set_type(&mut self, type_name: impl Into<String>) {
        self.type_name = type_name.into();
    }
}

impl Default for SecurityContext {
    fn default() -> Self {
        Self::public()
    }
}

impl fmt::Display for SecurityContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:u{}:r{}:{}", 
               self.level.name(), self.user_id, self.role_id, self.type_name)
    }
}

/// MAC decision
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacDecision {
    /// Access allowed
    Allow,
    /// Access denied
    Deny,
    /// Access requires audit
    AllowWithAudit,
}

/// MAC policy error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MacError {
    /// Access denied by level
    LevelDenied {
        subject_level: SecurityLevel,
        object_level: SecurityLevel,
    },
    /// Access denied by category
    CategoryDenied {
        missing: Vec<SecurityCategory>,
    },
    /// Type transition not allowed
    TypeTransitionDenied {
        from: String,
        to: String,
    },
    /// Policy not loaded
    NoPolicyLoaded,
}

impl fmt::Display for MacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacError::LevelDenied { subject_level, object_level } => {
                write!(f, "Level denied: {} cannot access {}", subject_level, object_level)
            }
            MacError::CategoryDenied { missing } => {
                write!(f, "Category denied: missing {:?}", missing)
            }
            MacError::TypeTransitionDenied { from, to } => {
                write!(f, "Type transition denied: {} -> {}", from, to)
            }
            MacError::NoPolicyLoaded => {
                write!(f, "No MAC policy loaded")
            }
        }
    }
}

/// Access type for MAC checks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    /// Read access
    Read,
    /// Write access
    Write,
    /// Execute access
    Execute,
    /// Append access
    Append,
    /// Create access
    Create,
    /// Delete access
    Delete,
}

/// MAC policy engine
pub struct MacPolicy {
    /// Policy is enabled
    enabled: bool,
    /// Enforce mode (false = permissive/audit only)
    enforcing: bool,
    /// Domain contexts
    domain_contexts: Mutex<Vec<(u64, SecurityContext)>>,
    /// Object contexts (simplified - keyed by object ID)
    object_contexts: Mutex<Vec<(u64, SecurityContext)>>,
}

impl MacPolicy {
    /// Create a new MAC policy
    pub const fn new() -> Self {
        MacPolicy {
            enabled: false,
            enforcing: false,
            domain_contexts: Mutex::new(Vec::new()),
            object_contexts: Mutex::new(Vec::new()),
        }
    }
    
    /// Enable the policy
    pub fn enable(&mut self) {
        self.enabled = true;
    }
    
    /// Disable the policy
    pub fn disable(&mut self) {
        self.enabled = false;
    }
    
    /// Set enforcing mode
    pub fn set_enforcing(&mut self, enforcing: bool) {
        self.enforcing = enforcing;
    }
    
    /// Check if enforcing
    pub fn is_enforcing(&self) -> bool {
        self.enforcing
    }
    
    /// Set context for a domain
    pub fn set_domain_context(&self, domain_id: u64, context: SecurityContext) {
        let mut contexts = self.domain_contexts.lock();
        if let Some(entry) = contexts.iter_mut().find(|(id, _)| *id == domain_id) {
            entry.1 = context;
        } else {
            contexts.push((domain_id, context));
        }
    }
    
    /// Get context for a domain
    pub fn get_domain_context(&self, domain_id: u64) -> Option<SecurityContext> {
        self.domain_contexts.lock()
            .iter()
            .find(|(id, _)| *id == domain_id)
            .map(|(_, ctx)| ctx.clone())
    }
    
    /// Set context for an object
    pub fn set_object_context(&self, object_id: u64, context: SecurityContext) {
        let mut contexts = self.object_contexts.lock();
        if let Some(entry) = contexts.iter_mut().find(|(id, _)| *id == object_id) {
            entry.1 = context;
        } else {
            contexts.push((object_id, context));
        }
    }
    
    /// Get context for an object
    pub fn get_object_context(&self, object_id: u64) -> Option<SecurityContext> {
        self.object_contexts.lock()
            .iter()
            .find(|(id, _)| *id == object_id)
            .map(|(_, ctx)| ctx.clone())
    }
    
    /// Check access (Bell-LaPadula model)
    pub fn check_access(
        &self,
        subject: &SecurityContext,
        object: &SecurityContext,
        access_type: AccessType,
    ) -> Result<MacDecision, MacError> {
        if !self.enabled {
            return Ok(MacDecision::Allow);
        }
        
        match access_type {
            AccessType::Read | AccessType::Execute => {
                // Simple Security Property: No Read Up
                // Subject can read object only if subject dominates object
                if !subject.dominates(object) {
                    if self.enforcing {
                        // Check which constraint failed
                        if !subject.level.dominates(object.level) {
                            return Err(MacError::LevelDenied {
                                subject_level: subject.level,
                                object_level: object.level,
                            });
                        }
                        
                        let missing: Vec<_> = object.categories
                            .difference(&subject.categories)
                            .copied()
                            .collect();
                        return Err(MacError::CategoryDenied { missing });
                    }
                    return Ok(MacDecision::AllowWithAudit);
                }
            }
            AccessType::Write | AccessType::Append | AccessType::Create | AccessType::Delete => {
                // *-Property (Star Property): No Write Down
                // Subject can write to object only if object dominates subject
                // This prevents information leakage to lower levels
                if !object.dominates(subject) {
                    if self.enforcing {
                        if !object.level.dominates(subject.level) {
                            return Err(MacError::LevelDenied {
                                subject_level: subject.level,
                                object_level: object.level,
                            });
                        }
                        
                        let missing: Vec<_> = subject.categories
                            .difference(&object.categories)
                            .copied()
                            .collect();
                        return Err(MacError::CategoryDenied { missing });
                    }
                    return Ok(MacDecision::AllowWithAudit);
                }
            }
        }
        
        Ok(MacDecision::Allow)
    }
    
    /// Check access between domains
    pub fn check_domain_access(
        &self,
        subject_domain: u64,
        object_domain: u64,
        access_type: AccessType,
    ) -> Result<MacDecision, MacError> {
        let subject = self.get_domain_context(subject_domain)
            .unwrap_or(SecurityContext::public());
        let object = self.get_domain_context(object_domain)
            .unwrap_or(SecurityContext::public());
        
        self.check_access(&subject, &object, access_type)
    }
}

impl Default for MacPolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// Global MAC policy
static MAC_POLICY: Mutex<MacPolicy> = Mutex::new(MacPolicy::new());

/// Check access using global policy
pub fn check_access(
    subject: &SecurityContext,
    object: &SecurityContext,
    access_type: AccessType,
) -> Result<MacDecision, MacError> {
    MAC_POLICY.lock().check_access(subject, object, access_type)
}

/// Get current context for a domain
pub fn current_context(domain_id: u64) -> Option<SecurityContext> {
    MAC_POLICY.lock().get_domain_context(domain_id)
}

/// Set context for a domain
pub fn set_context(domain_id: u64, context: SecurityContext) {
    MAC_POLICY.lock().set_domain_context(domain_id, context);
}

/// Initialize MAC subsystem
pub fn init() {
    let mut policy = MAC_POLICY.lock();
    
    // Set kernel context
    policy.set_domain_context(0, SecurityContext::kernel());
    
    // Enable but don't enforce by default
    policy.enable();
    policy.set_enforcing(false);
}

/// Enable enforcement
pub fn set_enforcing(enforcing: bool) {
    MAC_POLICY.lock().set_enforcing(enforcing);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_security_level_dominance() {
        assert!(SecurityLevel::TopSecret.dominates(SecurityLevel::Secret));
        assert!(SecurityLevel::Secret.dominates(SecurityLevel::Confidential));
        assert!(!SecurityLevel::Public.dominates(SecurityLevel::Internal));
    }
    
    #[test]
    fn test_security_context_dominance() {
        let mut high = SecurityContext::new(SecurityLevel::Secret, 0, 0);
        high.add_category(SecurityCategory::Network);
        high.add_category(SecurityCategory::FileSystem);
        
        let mut low = SecurityContext::new(SecurityLevel::Internal, 0, 0);
        low.add_category(SecurityCategory::Network);
        
        assert!(high.dominates(&low));
        assert!(!low.dominates(&high));
    }
    
    #[test]
    fn test_read_up_denied() {
        let mut policy = MacPolicy::new();
        policy.enable();
        policy.set_enforcing(true);
        
        let low = SecurityContext::new(SecurityLevel::Internal, 0, 0);
        let high = SecurityContext::new(SecurityLevel::Secret, 0, 0);
        
        // Low cannot read high (No Read Up)
        assert!(policy.check_access(&low, &high, AccessType::Read).is_err());
        
        // High can read low
        assert!(policy.check_access(&high, &low, AccessType::Read).is_ok());
    }
    
    #[test]
    fn test_write_down_denied() {
        let mut policy = MacPolicy::new();
        policy.enable();
        policy.set_enforcing(true);
        
        let low = SecurityContext::new(SecurityLevel::Internal, 0, 0);
        let high = SecurityContext::new(SecurityLevel::Secret, 0, 0);
        
        // High cannot write to low (No Write Down)
        assert!(policy.check_access(&high, &low, AccessType::Write).is_err());
        
        // Low can write to high
        assert!(policy.check_access(&low, &high, AccessType::Write).is_ok());
    }
}
