//! Security Policy Engine for ExoRust
//!
//! This module implements a flexible rule-based security policy
//! system for controlling access and operations.

use core::fmt;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::BTreeMap;
use spin::RwLock;

extern crate alloc;

/// Policy action to take
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Allow the operation
    Allow,
    /// Deny the operation
    Deny,
    /// Allow with audit logging
    AllowAudit,
    /// Deny with audit logging
    DenyAudit,
}

impl PolicyAction {
    /// Check if action allows the operation
    pub fn is_allow(&self) -> bool {
        matches!(self, PolicyAction::Allow | PolicyAction::AllowAudit)
    }
    
    /// Check if action requires auditing
    pub fn needs_audit(&self) -> bool {
        matches!(self, PolicyAction::AllowAudit | PolicyAction::DenyAudit)
    }
}

impl Default for PolicyAction {
    fn default() -> Self {
        PolicyAction::Deny
    }
}

/// Subject type for policy matching
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PolicySubject {
    /// Any subject
    Any,
    /// Specific domain ID
    Domain(u64),
    /// Domain type/role
    DomainType(String),
    /// User ID
    User(u32),
    /// Group ID
    Group(u32),
}

impl PolicySubject {
    /// Check if this subject matches a domain
    pub fn matches_domain(&self, domain_id: u64, domain_type: &str) -> bool {
        match self {
            PolicySubject::Any => true,
            PolicySubject::Domain(id) => *id == domain_id,
            PolicySubject::DomainType(t) => t == domain_type,
            _ => false,
        }
    }
}

impl Default for PolicySubject {
    fn default() -> Self {
        PolicySubject::Any
    }
}

/// Object type for policy matching
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PolicyObject {
    /// Any object
    Any,
    /// Specific resource ID
    Resource(u64),
    /// Resource type
    ResourceType(String),
    /// File path pattern
    Path(String),
    /// Network address/port
    Network(String),
    /// System call number
    Syscall(u32),
}

impl PolicyObject {
    /// Check if this object matches a resource
    pub fn matches_resource(&self, resource_id: u64, resource_type: &str) -> bool {
        match self {
            PolicyObject::Any => true,
            PolicyObject::Resource(id) => *id == resource_id,
            PolicyObject::ResourceType(t) => t == resource_type,
            _ => false,
        }
    }
    
    /// Check if this object matches a path
    pub fn matches_path(&self, path: &str) -> bool {
        match self {
            PolicyObject::Any => true,
            PolicyObject::Path(pattern) => {
                // Simple glob-style matching
                if pattern.ends_with("/*") {
                    let prefix = &pattern[..pattern.len() - 2];
                    path.starts_with(prefix)
                } else if pattern.ends_with("/**") {
                    let prefix = &pattern[..pattern.len() - 3];
                    path.starts_with(prefix)
                } else {
                    pattern == path
                }
            }
            _ => false,
        }
    }
}

impl Default for PolicyObject {
    fn default() -> Self {
        PolicyObject::Any
    }
}

/// Operation type for policy matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PolicyOperation {
    /// Any operation
    Any,
    /// Read operation
    Read,
    /// Write operation
    Write,
    /// Execute operation
    Execute,
    /// Create operation
    Create,
    /// Delete operation
    Delete,
    /// Send (network)
    Send,
    /// Receive (network)
    Receive,
    /// Map memory
    Map,
    /// IPC send
    IpcSend,
    /// IPC receive
    IpcReceive,
}

impl Default for PolicyOperation {
    fn default() -> Self {
        PolicyOperation::Any
    }
}

/// Policy rule
#[derive(Debug, Clone)]
pub struct PolicyRule {
    /// Rule ID
    pub id: u64,
    /// Rule priority (higher = checked first)
    pub priority: u32,
    /// Subject (who)
    pub subject: PolicySubject,
    /// Object (what)
    pub object: PolicyObject,
    /// Operation (how)
    pub operation: PolicyOperation,
    /// Action to take
    pub action: PolicyAction,
    /// Rule description
    pub description: String,
    /// Is rule enabled
    pub enabled: bool,
}

impl PolicyRule {
    /// Create a new policy rule
    pub fn new(
        subject: PolicySubject,
        object: PolicyObject,
        operation: PolicyOperation,
        action: PolicyAction,
    ) -> Self {
        static NEXT_ID: core::sync::atomic::AtomicU64 = 
            core::sync::atomic::AtomicU64::new(1);
        
        PolicyRule {
            id: NEXT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
            priority: 100,
            subject,
            object,
            operation,
            action,
            description: String::new(),
            enabled: true,
        }
    }
    
    /// Set priority
    pub fn with_priority(mut self, priority: u32) -> Self {
        self.priority = priority;
        self
    }
    
    /// Set description
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
    
    /// Check if rule matches a request
    pub fn matches(
        &self,
        domain_id: u64,
        domain_type: &str,
        resource_id: u64,
        resource_type: &str,
        operation: PolicyOperation,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        
        // Check subject
        if !self.subject.matches_domain(domain_id, domain_type) {
            return false;
        }
        
        // Check object
        if !self.object.matches_resource(resource_id, resource_type) {
            return false;
        }
        
        // Check operation
        if self.operation != PolicyOperation::Any && self.operation != operation {
            return false;
        }
        
        true
    }
    
    /// Check if rule matches a path-based request
    pub fn matches_path(
        &self,
        domain_id: u64,
        domain_type: &str,
        path: &str,
        operation: PolicyOperation,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        
        if !self.subject.matches_domain(domain_id, domain_type) {
            return false;
        }
        
        if !self.object.matches_path(path) {
            return false;
        }
        
        if self.operation != PolicyOperation::Any && self.operation != operation {
            return false;
        }
        
        true
    }
}

impl fmt::Display for PolicyRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Rule {} (pri={}): {:?} -> {:?} on {:?} = {:?}",
               self.id, self.priority, self.subject, self.object,
               self.operation, self.action)
    }
}

/// Policy decision result
#[derive(Debug, Clone)]
pub struct PolicyDecision {
    /// Action to take
    pub action: PolicyAction,
    /// Rule that matched (if any)
    pub matched_rule: Option<u64>,
    /// Audit message
    pub audit_message: Option<String>,
}

impl PolicyDecision {
    /// Create a default deny decision
    pub fn default_deny() -> Self {
        PolicyDecision {
            action: PolicyAction::Deny,
            matched_rule: None,
            audit_message: Some(String::from("No matching rule, default deny")),
        }
    }
    
    /// Create a decision from a rule match
    pub fn from_rule(rule: &PolicyRule) -> Self {
        PolicyDecision {
            action: rule.action,
            matched_rule: Some(rule.id),
            audit_message: if rule.action.needs_audit() {
                Some(rule.description.clone())
            } else {
                None
            },
        }
    }
}

/// Security policy
pub struct SecurityPolicy {
    /// Policy name
    name: String,
    /// Policy version
    version: u32,
    /// Rules (sorted by priority)
    rules: Vec<PolicyRule>,
    /// Default action
    default_action: PolicyAction,
    /// Policy is enabled
    enabled: bool,
    /// Statistics
    stats: PolicyStats,
}

impl SecurityPolicy {
    /// Create a new policy
    pub fn new(name: impl Into<String>) -> Self {
        SecurityPolicy {
            name: name.into(),
            version: 1,
            rules: Vec::new(),
            default_action: PolicyAction::Deny,
            enabled: true,
            stats: PolicyStats::default(),
        }
    }
    
    /// Add a rule
    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        // Sort by priority (descending)
        self.rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    }
    
    /// Remove a rule by ID
    pub fn remove_rule(&mut self, rule_id: u64) -> bool {
        let len = self.rules.len();
        self.rules.retain(|r| r.id != rule_id);
        self.rules.len() < len
    }
    
    /// Get a rule by ID
    pub fn get_rule(&self, rule_id: u64) -> Option<&PolicyRule> {
        self.rules.iter().find(|r| r.id == rule_id)
    }
    
    /// Get all rules
    pub fn rules(&self) -> &[PolicyRule] {
        &self.rules
    }
    
    /// Check policy
    pub fn check(
        &mut self,
        domain_id: u64,
        domain_type: &str,
        resource_id: u64,
        resource_type: &str,
        operation: PolicyOperation,
    ) -> PolicyDecision {
        self.stats.total_checks += 1;
        
        if !self.enabled {
            return PolicyDecision {
                action: PolicyAction::Allow,
                matched_rule: None,
                audit_message: None,
            };
        }
        
        // Find first matching rule
        for rule in &self.rules {
            if rule.matches(domain_id, domain_type, resource_id, resource_type, operation) {
                if rule.action.is_allow() {
                    self.stats.allowed += 1;
                } else {
                    self.stats.denied += 1;
                }
                return PolicyDecision::from_rule(rule);
            }
        }
        
        // No matching rule, use default
        self.stats.denied += 1;
        PolicyDecision::default_deny()
    }
    
    /// Check path-based policy
    pub fn check_path(
        &mut self,
        domain_id: u64,
        domain_type: &str,
        path: &str,
        operation: PolicyOperation,
    ) -> PolicyDecision {
        self.stats.total_checks += 1;
        
        if !self.enabled {
            return PolicyDecision {
                action: PolicyAction::Allow,
                matched_rule: None,
                audit_message: None,
            };
        }
        
        for rule in &self.rules {
            if rule.matches_path(domain_id, domain_type, path, operation) {
                if rule.action.is_allow() {
                    self.stats.allowed += 1;
                } else {
                    self.stats.denied += 1;
                }
                return PolicyDecision::from_rule(rule);
            }
        }
        
        self.stats.denied += 1;
        PolicyDecision::default_deny()
    }
    
    /// Enable/disable policy
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
    
    /// Set default action
    pub fn set_default_action(&mut self, action: PolicyAction) {
        self.default_action = action;
    }
    
    /// Get statistics
    pub fn stats(&self) -> &PolicyStats {
        &self.stats
    }
    
    /// Clear rules
    pub fn clear(&mut self) {
        self.rules.clear();
        self.version += 1;
    }
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self::new("default")
    }
}

/// Policy statistics
#[derive(Debug, Clone, Default)]
pub struct PolicyStats {
    /// Total policy checks
    pub total_checks: u64,
    /// Allowed operations
    pub allowed: u64,
    /// Denied operations
    pub denied: u64,
}

/// Global policy engine
static POLICY: RwLock<SecurityPolicy> = RwLock::new(SecurityPolicy {
    name: String::new(),
    version: 0,
    rules: Vec::new(),
    default_action: PolicyAction::Deny,
    enabled: false,
    stats: PolicyStats {
        total_checks: 0,
        allowed: 0,
        denied: 0,
    },
});

/// Load a policy
pub fn load_policy(policy: SecurityPolicy) {
    *POLICY.write() = policy;
}

/// Check policy
pub fn check_policy(
    domain_id: u64,
    domain_type: &str,
    resource_id: u64,
    resource_type: &str,
    operation: PolicyOperation,
) -> PolicyDecision {
    POLICY.write().check(domain_id, domain_type, resource_id, resource_type, operation)
}

/// Check path-based policy
pub fn check_path_policy(
    domain_id: u64,
    domain_type: &str,
    path: &str,
    operation: PolicyOperation,
) -> PolicyDecision {
    POLICY.write().check_path(domain_id, domain_type, path, operation)
}

/// Add a rule to global policy
pub fn add_rule(rule: PolicyRule) {
    POLICY.write().add_rule(rule);
}

/// Remove a rule from global policy
pub fn remove_rule(rule_id: u64) -> bool {
    POLICY.write().remove_rule(rule_id)
}

/// Initialize policy engine with default rules
pub fn init() {
    let mut policy = SecurityPolicy::new("kernel_policy");
    
    // Default rules
    
    // Kernel domain can do everything
    policy.add_rule(
        PolicyRule::new(
            PolicySubject::Domain(0),
            PolicyObject::Any,
            PolicyOperation::Any,
            PolicyAction::Allow,
        )
        .with_priority(1000)
        .with_description("Kernel unrestricted")
    );
    
    // Default deny
    policy.add_rule(
        PolicyRule::new(
            PolicySubject::Any,
            PolicyObject::Any,
            PolicyOperation::Any,
            PolicyAction::DenyAudit,
        )
        .with_priority(0)
        .with_description("Default deny")
    );
    
    policy.set_enabled(true);
    load_policy(policy);
    
    crate::log!("[POLICY] Policy engine initialized\n");
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_policy_rule() {
        let rule = PolicyRule::new(
            PolicySubject::Domain(1),
            PolicyObject::ResourceType(String::from("file")),
            PolicyOperation::Read,
            PolicyAction::Allow,
        );
        
        assert!(rule.matches(1, "app", 100, "file", PolicyOperation::Read));
        assert!(!rule.matches(2, "app", 100, "file", PolicyOperation::Read));
        assert!(!rule.matches(1, "app", 100, "network", PolicyOperation::Read));
    }
    
    #[test]
    fn test_path_matching() {
        let rule = PolicyRule::new(
            PolicySubject::Any,
            PolicyObject::Path(String::from("/home/*")),
            PolicyOperation::Read,
            PolicyAction::Allow,
        );
        
        assert!(rule.matches_path(1, "app", "/home/user", PolicyOperation::Read));
        assert!(rule.matches_path(1, "app", "/home/test", PolicyOperation::Read));
        assert!(!rule.matches_path(1, "app", "/etc/passwd", PolicyOperation::Read));
    }
    
    #[test]
    fn test_policy() {
        let mut policy = SecurityPolicy::new("test");
        
        policy.add_rule(
            PolicyRule::new(
                PolicySubject::Domain(1),
                PolicyObject::Any,
                PolicyOperation::Read,
                PolicyAction::Allow,
            )
        );
        
        let decision = policy.check(1, "app", 0, "file", PolicyOperation::Read);
        assert!(decision.action.is_allow());
        
        let decision = policy.check(1, "app", 0, "file", PolicyOperation::Write);
        assert!(!decision.action.is_allow());
    }
}
