//! Security Audit Subsystem for ExoRust
//!
//! This module implements comprehensive security auditing for
//! tracking security-relevant events in the kernel.

use core::fmt;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::collections::VecDeque;
use spin::Mutex;
use core::sync::atomic::{AtomicU64, AtomicBool, Ordering};

extern crate alloc;

/// Audit event type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditEventType {
    // Domain events
    /// Domain created
    DomainCreate,
    /// Domain terminated
    DomainTerminate,
    /// Domain context change
    DomainContextChange,
    
    // Access events
    /// File access
    FileAccess,
    /// Network access
    NetworkAccess,
    /// Memory mapping
    MemoryMap,
    /// IPC operation
    IpcOperation,
    
    // Security events
    /// MAC policy decision
    MacDecision,
    /// Capability check
    CapabilityCheck,
    /// Permission denied
    PermissionDenied,
    /// Privilege escalation attempt
    PrivilegeEscalation,
    
    // System events
    /// System call
    Syscall,
    /// Module load
    ModuleLoad,
    /// Configuration change
    ConfigChange,
    
    // Authentication events
    /// Login attempt
    LoginAttempt,
    /// Logout
    Logout,
    /// Authentication failure
    AuthFailure,
}

impl AuditEventType {
    /// Get event type name
    pub fn name(&self) -> &'static str {
        match self {
            AuditEventType::DomainCreate => "DOMAIN_CREATE",
            AuditEventType::DomainTerminate => "DOMAIN_TERMINATE",
            AuditEventType::DomainContextChange => "DOMAIN_CONTEXT_CHANGE",
            AuditEventType::FileAccess => "FILE_ACCESS",
            AuditEventType::NetworkAccess => "NETWORK_ACCESS",
            AuditEventType::MemoryMap => "MEMORY_MAP",
            AuditEventType::IpcOperation => "IPC_OPERATION",
            AuditEventType::MacDecision => "MAC_DECISION",
            AuditEventType::CapabilityCheck => "CAPABILITY_CHECK",
            AuditEventType::PermissionDenied => "PERMISSION_DENIED",
            AuditEventType::PrivilegeEscalation => "PRIVILEGE_ESCALATION",
            AuditEventType::Syscall => "SYSCALL",
            AuditEventType::ModuleLoad => "MODULE_LOAD",
            AuditEventType::ConfigChange => "CONFIG_CHANGE",
            AuditEventType::LoginAttempt => "LOGIN_ATTEMPT",
            AuditEventType::Logout => "LOGOUT",
            AuditEventType::AuthFailure => "AUTH_FAILURE",
        }
    }
    
    /// Check if event type is critical
    pub fn is_critical(&self) -> bool {
        matches!(self,
            AuditEventType::PrivilegeEscalation |
            AuditEventType::PermissionDenied |
            AuditEventType::AuthFailure |
            AuditEventType::ModuleLoad
        )
    }
}

impl fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Audit record
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// Unique record ID
    pub id: u64,
    /// Timestamp (system ticks)
    pub timestamp: u64,
    /// Event type
    pub event_type: AuditEventType,
    /// Domain ID that triggered the event
    pub domain_id: u64,
    /// Result (success/failure)
    pub success: bool,
    /// Additional message
    pub message: String,
    /// Key-value pairs for structured data
    pub fields: Vec<(String, String)>,
}

impl AuditRecord {
    /// Create a new audit record
    pub fn new(event_type: AuditEventType, domain_id: u64, success: bool) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(1);
        
        AuditRecord {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            timestamp: crate::task::timer::current_tick(),
            event_type,
            domain_id,
            success,
            message: String::new(),
            fields: Vec::new(),
        }
    }
    
    /// Set message
    pub fn with_message(mut self, msg: impl Into<String>) -> Self {
        self.message = msg.into();
        self
    }
    
    /// Add a field
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }
    
    /// Format as log line
    pub fn format(&self) -> String {
        use alloc::format;
        
        let mut result = format!(
            "audit({}:{}): type={} domain={} success={}",
            self.timestamp,
            self.id,
            self.event_type.name(),
            self.domain_id,
            if self.success { "yes" } else { "no" }
        );
        
        if !self.message.is_empty() {
            result.push_str(" msg=\"");
            result.push_str(&self.message);
            result.push('"');
        }
        
        for (key, value) in &self.fields {
            result.push(' ');
            result.push_str(key);
            result.push('=');
            result.push_str(value);
        }
        
        result
    }
}

impl fmt::Display for AuditRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.format())
    }
}

/// Audit event (for building records)
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Event type
    pub event_type: AuditEventType,
    /// Domain ID
    pub domain_id: u64,
    /// Success flag
    pub success: bool,
    /// Message
    pub message: Option<String>,
    /// Fields
    pub fields: Vec<(String, String)>,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(event_type: AuditEventType, domain_id: u64) -> Self {
        AuditEvent {
            event_type,
            domain_id,
            success: true,
            message: None,
            fields: Vec::new(),
        }
    }
    
    /// Set success/failure
    pub fn success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }
    
    /// Set message
    pub fn message(mut self, msg: impl Into<String>) -> Self {
        self.message = Some(msg.into());
        self
    }
    
    /// Add field
    pub fn field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((key.into(), value.into()));
        self
    }
    
    /// Convert to record
    pub fn to_record(&self) -> AuditRecord {
        let mut record = AuditRecord::new(self.event_type, self.domain_id, self.success);
        
        if let Some(ref msg) = self.message {
            record.message = msg.clone();
        }
        
        record.fields = self.fields.clone();
        record
    }
}

/// Audit log storage
pub struct AuditLog {
    /// Records buffer
    records: Mutex<VecDeque<AuditRecord>>,
    /// Maximum number of records
    max_records: usize,
    /// Enabled flag
    enabled: AtomicBool,
    /// Total records logged
    total_records: AtomicU64,
    /// Records dropped due to overflow
    dropped_records: AtomicU64,
    /// Log critical events only
    critical_only: AtomicBool,
}

impl AuditLog {
    /// Create a new audit log
    pub const fn new(max_records: usize) -> Self {
        AuditLog {
            records: Mutex::new(VecDeque::new()),
            max_records,
            enabled: AtomicBool::new(true),
            total_records: AtomicU64::new(0),
            dropped_records: AtomicU64::new(0),
            critical_only: AtomicBool::new(false),
        }
    }
    
    /// Log an event
    pub fn log(&self, event: AuditEvent) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        // Filter non-critical events if critical_only mode
        if self.critical_only.load(Ordering::Relaxed) && !event.event_type.is_critical() {
            return;
        }
        
        let record = event.to_record();
        
        // Print critical events immediately
        if event.event_type.is_critical() {
            crate::log!("[AUDIT] {}\n", record.format());
        }
        
        let mut records = self.records.lock();
        
        // Drop oldest if at capacity
        if records.len() >= self.max_records {
            records.pop_front();
            self.dropped_records.fetch_add(1, Ordering::Relaxed);
        }
        
        records.push_back(record);
        self.total_records.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Log a record directly
    pub fn log_record(&self, record: AuditRecord) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        
        if self.critical_only.load(Ordering::Relaxed) && !record.event_type.is_critical() {
            return;
        }
        
        if record.event_type.is_critical() {
            crate::log!("[AUDIT] {}\n", record.format());
        }
        
        let mut records = self.records.lock();
        
        if records.len() >= self.max_records {
            records.pop_front();
            self.dropped_records.fetch_add(1, Ordering::Relaxed);
        }
        
        records.push_back(record);
        self.total_records.fetch_add(1, Ordering::Relaxed);
    }
    
    /// Get all records
    pub fn get_records(&self) -> Vec<AuditRecord> {
        self.records.lock().iter().cloned().collect()
    }
    
    /// Get records by type
    pub fn get_by_type(&self, event_type: AuditEventType) -> Vec<AuditRecord> {
        self.records.lock()
            .iter()
            .filter(|r| r.event_type == event_type)
            .cloned()
            .collect()
    }
    
    /// Get records for a domain
    pub fn get_by_domain(&self, domain_id: u64) -> Vec<AuditRecord> {
        self.records.lock()
            .iter()
            .filter(|r| r.domain_id == domain_id)
            .cloned()
            .collect()
    }
    
    /// Get failed events
    pub fn get_failures(&self) -> Vec<AuditRecord> {
        self.records.lock()
            .iter()
            .filter(|r| !r.success)
            .cloned()
            .collect()
    }
    
    /// Clear the log
    pub fn clear(&self) {
        self.records.lock().clear();
    }
    
    /// Enable/disable logging
    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
    }
    
    /// Set critical-only mode
    pub fn set_critical_only(&self, critical_only: bool) {
        self.critical_only.store(critical_only, Ordering::Relaxed);
    }
    
    /// Get statistics
    pub fn stats(&self) -> AuditStats {
        AuditStats {
            total_records: self.total_records.load(Ordering::Relaxed),
            dropped_records: self.dropped_records.load(Ordering::Relaxed),
            current_records: self.records.lock().len() as u64,
            max_records: self.max_records as u64,
        }
    }
}

/// Audit statistics
#[derive(Debug, Clone, Copy)]
pub struct AuditStats {
    /// Total records ever logged
    pub total_records: u64,
    /// Records dropped due to overflow
    pub dropped_records: u64,
    /// Current number of records
    pub current_records: u64,
    /// Maximum records capacity
    pub max_records: u64,
}

/// Global audit log
static AUDIT_LOG: AuditLog = AuditLog::new(10000);

/// Log an audit event
pub fn log_event(event: AuditEvent) {
    AUDIT_LOG.log(event);
}

/// Log a record directly
pub fn log_record(record: AuditRecord) {
    AUDIT_LOG.log_record(record);
}

/// Flush log (no-op for in-memory log, placeholder for future disk logging)
pub fn flush_log() {
    // Future: write to disk or send to remote
}

/// Get all records
pub fn get_records() -> Vec<AuditRecord> {
    AUDIT_LOG.get_records()
}

/// Get audit statistics
pub fn stats() -> AuditStats {
    AUDIT_LOG.stats()
}

/// Initialize audit subsystem
pub fn init() {
    crate::log!("[AUDIT] Audit subsystem initialized (max {} records)\n", 10000);
}

/// Convenience macro for logging audit events
#[macro_export]
macro_rules! audit {
    ($event_type:expr, $domain_id:expr, $success:expr, $($field:tt)*) => {
        $crate::security::audit::log_event(
            $crate::security::audit::AuditEvent::new($event_type, $domain_id)
                .success($success)
                $($field)*
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_audit_record() {
        let record = AuditRecord::new(AuditEventType::DomainCreate, 42, true)
            .with_message("Test domain created")
            .with_field("name", "test_domain");
        
        assert_eq!(record.domain_id, 42);
        assert!(record.success);
        assert_eq!(record.event_type, AuditEventType::DomainCreate);
    }
    
    #[test]
    fn test_audit_event() {
        let event = AuditEvent::new(AuditEventType::CapabilityCheck, 1)
            .success(false)
            .message("Capability denied")
            .field("capability", "CAP_SYS_ADMIN");
        
        let record = event.to_record();
        assert!(!record.success);
        assert_eq!(record.fields.len(), 1);
    }
    
    #[test]
    fn test_event_type_critical() {
        assert!(AuditEventType::PrivilegeEscalation.is_critical());
        assert!(AuditEventType::AuthFailure.is_critical());
        assert!(!AuditEventType::DomainCreate.is_critical());
    }
}
