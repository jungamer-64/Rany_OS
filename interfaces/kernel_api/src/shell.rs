// ============================================================================
// kernel_api/src/shell.rs - Shell Services API for Cell Separation
// ============================================================================
//!
//! # Shell Services
//!
//! Abstraction layer for ExoShell to access kernel services without
//! direct crate:: dependencies. Enables future Cell separation.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

// ============================================================================
// Memory Information
// ============================================================================

/// Memory statistics
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryStats {
    /// Total system memory in KB
    pub total_kb: usize,
    /// Free memory in KB
    pub free_kb: usize,
    /// Used memory in KB
    pub used_kb: usize,
}

// ============================================================================
// Domain Information
// ============================================================================

/// Domain state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    Initializing,
    Running,
    Suspended,
    Stopped,
    Terminated,
}

/// Domain information
#[derive(Debug, Clone)]
pub struct DomainInfo {
    pub id: u64,
    pub name: String,
    pub state: DomainState,
    pub tasks: usize,
    pub memory_kb: usize,
    pub rrefs: u64,
    pub last_error: Option<String>,
}

// ============================================================================
// System Information
// ============================================================================

/// System information
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub uptime_ticks: u64,
    pub cpu_temperature: Option<f32>,
}

// ============================================================================
// Directory Entry
// ============================================================================

/// File type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Socket,
    Fifo,
    Unknown,
}

/// Directory entry
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub file_type: FileType,
    pub size: u64,
    pub ino: u64,
}

/// File attributes from stat
#[derive(Debug, Clone)]
pub struct FileAttributes {
    pub size: u64,
    pub ino: u64,
    pub nlink: u64,
    pub file_type: FileType,
}

// ============================================================================
// System Monitor Information
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct MonitorInfo {
    pub timestamp: u64,
    pub cpu_usage: u8,
    pub memory: MemoryMonitorInfo,
    pub domains: DomainMonitorInfo,
    pub tasks: TaskMonitorInfo,
    pub network: NetworkMonitorInfo,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryMonitorInfo {
    pub heap_used: usize,
    pub heap_free: usize,
    pub heap_total: usize,
    pub usage_percent: u8,
}

#[derive(Debug, Clone, Default)]
pub struct DomainMonitorInfo {
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
}

#[derive(Debug, Clone, Default)]
pub struct TaskMonitorInfo {
    pub context_switches: u64,
    pub voluntary_yields: u64,
    pub forced_preemptions: u64,
}

#[derive(Debug, Clone, Default)]
pub struct NetworkMonitorInfo {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

// ============================================================================
// Thermal Information
// ============================================================================

#[derive(Debug, Clone)]
pub struct ThermalInfo {
    pub cpu_celsius: Option<f32>,
    pub polling_count: u64,
    pub trip_events: u64,
    pub throttle_policy: String,
    pub throttle_count: u64,
    pub sensors: Vec<ThermalSensorInfo>,
}

#[derive(Debug, Clone)]
pub struct ThermalSensorInfo {
    pub id: usize,
    pub name: String,
    pub current_c: Option<f32>,
    pub is_hot: bool,
    pub is_critical: bool,
}

// ============================================================================
// Watchdog Information
// ============================================================================

#[derive(Debug, Clone, Default)]
pub struct WatchdogInfo {
    pub heartbeats: u64,
    pub timeouts: u64,
    pub checks: u64,
    pub deadlocks_detected: u64,
}

// ============================================================================
// Power Information
// ============================================================================

#[derive(Debug, Clone)]
pub struct PowerInfo {
    pub state: String,
    pub power_button_presses: u64,
    pub sleep_button_presses: u64,
    pub cpu_idle: CpuIdleInfo,
}

#[derive(Debug, Clone, Default)]
pub struct CpuIdleInfo {
    pub c1_count: u64,
    pub c2_count: u64,
    pub c3_count: u64,
}

// ============================================================================
// Shell Services Trait
// ============================================================================

/// Shell services abstraction for Cell separation
///
/// This trait provides kernel access for ExoShell namespaces without
/// requiring direct `crate::` dependencies.
pub trait ShellServices: Send + Sync {
    // --- Memory ---

    /// Get current memory statistics
    fn memory_stats(&self) -> MemoryStats;

    // --- Timer ---

    /// Get current system tick count
    fn current_tick(&self) -> u64;

    // --- Domain ---

    /// List all domains
    fn list_domains(&self) -> Vec<DomainInfo>;

    /// Get domain by ID
    fn get_domain(&self, id: u64) -> Option<DomainInfo>;

    /// Terminate a domain (requires appropriate capability)
    fn terminate_domain(&self, id: u64) -> Result<(), &'static str>;

    /// Stop a domain (requires appropriate capability)
    fn stop_domain(&self, id: u64) -> Result<(), &'static str>;

    /// Resume a domain (requires appropriate capability)
    fn resume_domain(&self, id: u64) -> Result<(), &'static str>;

    /// Get current domain ID
    fn current_domain(&self) -> u64;

    // --- System ---

    /// Get system information
    fn system_info(&self) -> SystemInfo;

    /// Get detailed system monitor snapshot
    fn monitor_info(&self) -> MonitorInfo;

    /// Get thermal information
    fn thermal_info(&self) -> ThermalInfo;

    /// Get watchdog information
    fn watchdog_info(&self) -> WatchdogInfo;

    /// Get power information
    fn power_info(&self) -> PowerInfo;

    /// Get CPU temperature if available
    fn cpu_temperature(&self) -> Option<f32>;

    // --- Power Control ---

    /// Initiate system shutdown
    fn shutdown(&self) -> !;

    /// Initiate system reboot
    fn reboot(&self) -> !;

    // --- Filesystem ---

    /// List directory entries
    fn list_directory(&self, path: &str) -> Result<Vec<DirEntry>, &'static str>;

    /// Read file contents
    fn read_file(&self, path: &str) -> Result<Vec<u8>, &'static str>;

    /// Read file contents with zero-copy semantics
    ///
    /// Returns an Arc-wrapped buffer that can be shared without copying.
    /// This is preferred for large files or when the content will be
    /// passed to multiple consumers.
    fn read_file_zero_copy(&self, path: &str) -> Result<alloc::sync::Arc<Vec<u8>>, &'static str> {
        // Default implementation wraps standard read
        self.read_file(path).map(alloc::sync::Arc::new)
    }

    /// Write file contents
    fn write_file(&self, path: &str, data: &[u8]) -> Result<(), &'static str>;

    /// Get file attributes
    fn stat_file(&self, path: &str) -> Result<FileAttributes, &'static str>;

    /// Create a directory
    fn make_directory(&self, path: &str) -> Result<(), &'static str>;

    /// Remove a file
    fn remove_file(&self, path: &str) -> Result<(), &'static str>;

    /// Remove a directory
    fn remove_directory(&self, path: &str) -> Result<(), &'static str>;
}
