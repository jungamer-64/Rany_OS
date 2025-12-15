// ============================================================================
// src/monitor/mod.rs - System Monitor Dashboard
// Real-time system monitoring with CPU, memory, network stats
// ============================================================================

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

// Note: Individual modules disabled until API stabilization
// pub mod display;
// pub mod collectors;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Monitor refresh rate (in ms)
pub const REFRESH_RATE_MS: u64 = 1000;

/// Monitor state
static RUNNING: AtomicBool = AtomicBool::new(false);

/// System snapshot
#[derive(Debug, Clone)]
pub struct SystemSnapshot {
    /// Timestamp (timer ticks)
    pub timestamp: u64,
    /// CPU usage percentage (0-100)
    pub cpu_usage: u8,
    /// Memory statistics
    pub memory: MemoryStats,
    /// Domain statistics
    pub domains: DomainStats,
    /// Network statistics
    pub network: NetworkStats,
    /// Task statistics
    pub tasks: TaskStats,
    /// I/O statistics
    pub io: IoStats,
}

/// Memory statistics
#[derive(Debug, Clone, Default)]
pub struct MemoryStats {
    /// Heap used bytes
    pub heap_used: usize,
    /// Heap free bytes
    pub heap_free: usize,
    /// Total heap size
    pub heap_total: usize,
    /// Usage percentage
    pub usage_percent: u8,
}

/// Domain statistics
#[derive(Debug, Clone, Default)]
pub struct DomainStats {
    /// Total domains
    pub total: usize,
    /// Running domains
    pub running: usize,
    /// Stopped domains
    pub stopped: usize,
    /// Failed domains
    pub failed: usize,
}

/// Network statistics
#[derive(Debug, Clone, Default)]
pub struct NetworkStats {
    /// Packets received
    pub rx_packets: u64,
    /// Packets transmitted
    pub tx_packets: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Receive errors
    pub rx_errors: u64,
    /// Transmit errors
    pub tx_errors: u64,
}

/// Task statistics
#[derive(Debug, Clone, Default)]
pub struct TaskStats {
    /// Total tasks created
    pub total_created: u64,
    /// Currently active tasks
    pub active: u64,
    /// Context switches
    pub context_switches: u64,
    /// Voluntary yields
    pub voluntary_yields: u64,
    /// Forced preemptions
    pub forced_preemptions: u64,
}

/// I/O statistics
#[derive(Debug, Clone, Default)]
pub struct IoStats {
    /// Disk reads
    pub disk_reads: u64,
    /// Disk writes
    pub disk_writes: u64,
    /// Bytes read
    pub bytes_read: u64,
    /// Bytes written
    pub bytes_written: u64,
}

/// Initialize monitor
pub fn init() {
    log::info!("[MONITOR] System monitor initialized\n");
}

/// Start monitoring
pub fn start() {
    RUNNING.store(true, Ordering::SeqCst);
    log::info!("[MONITOR] Monitoring started\n");
}

/// Stop monitoring
pub fn stop() {
    RUNNING.store(false, Ordering::SeqCst);
    log::info!("[MONITOR] Monitoring stopped\n");
}

/// Check if monitoring is active
pub fn is_running() -> bool {
    RUNNING.load(Ordering::SeqCst)
}

/// Collect current system snapshot
pub fn snapshot() -> SystemSnapshot {
    let (heap_used, heap_free) = crate::memory::heap_stats();
    let heap_total = heap_used + heap_free;
    let usage_percent = if heap_total > 0 {
        ((heap_used * 100) / heap_total) as u8
    } else {
        0
    };

    let domain_stats = crate::domain_system::get_domain_stats();

    let preempt_stats = crate::task::preemption_controller().stats();

    SystemSnapshot {
        timestamp: crate::interrupts::get_timer_ticks(),
        cpu_usage: estimate_cpu_usage(),
        memory: MemoryStats {
            heap_used,
            heap_free,
            heap_total,
            usage_percent,
        },
        domains: DomainStats {
            total: domain_stats.total,
            running: domain_stats.running,
            stopped: domain_stats.stopped,
            failed: 0,
        },
        network: collect_network_stats(),
        tasks: TaskStats {
            total_created: 0,
            active: 0,
            context_switches: 0,
            voluntary_yields: preempt_stats.voluntary_yields,
            forced_preemptions: preempt_stats.forced_preemptions,
        },
        io: IoStats::default(),
    }
}

/// Estimate CPU usage (simplified)
fn estimate_cpu_usage() -> u8 {
    // In a real implementation, this would track idle time
    // For now, return a placeholder
    static LAST_TICK: AtomicU64 = AtomicU64::new(0);

    let current = crate::interrupts::get_timer_ticks();
    let last = LAST_TICK.swap(current, Ordering::Relaxed);

    if last == 0 {
        return 5; // First call
    }

    // Simplified: assume some baseline usage
    10
}

/// Collect network statistics
fn collect_network_stats() -> NetworkStats {
    // Collect from network stack if available
    NetworkStats::default()
}

/// Format snapshot as string
pub fn format_snapshot(snap: &SystemSnapshot) -> String {
    use alloc::fmt::Write;
    let mut s = String::new();

    let _ = writeln!(
        s,
        "\n┌──────────────────────────────────────────────────────────────────────┐"
    );
    let _ = writeln!(
        s,
        "│                    ExoRust System Monitor                            │"
    );
    let _ = writeln!(
        s,
        "├──────────────────────────────────────────────────────────────────────┤"
    );

    // Timestamp and CPU
    let _ = writeln!(
        s,
        "│  Tick: {:>12}  │  CPU: {:>3}%                                   │",
        snap.timestamp, snap.cpu_usage
    );

    let _ = writeln!(
        s,
        "├──────────────────────────────────────────────────────────────────────┤"
    );

    // Memory
    let _ = writeln!(
        s,
        "│  MEMORY                                                              │"
    );
    let _ = writeln!(
        s,
        "│    Used:  {:>10} bytes ({:>2}%)                                  │",
        snap.memory.heap_used, snap.memory.usage_percent
    );
    let _ = writeln!(
        s,
        "│    Free:  {:>10} bytes                                          │",
        snap.memory.heap_free
    );
    let _ = writeln!(
        s,
        "│    Total: {:>10} bytes                                          │",
        snap.memory.heap_total
    );

    // Memory bar
    let bar_width = 40;
    let filled = (snap.memory.usage_percent as usize * bar_width) / 100;
    let _ = write!(s, "│    [");
    for i in 0..bar_width {
        if i < filled {
            let _ = write!(s, "█");
        } else {
            let _ = write!(s, "░");
        }
    }
    let _ = writeln!(s, "]   │");

    let _ = writeln!(
        s,
        "├──────────────────────────────────────────────────────────────────────┤"
    );

    // Domains
    let _ = writeln!(
        s,
        "│  DOMAINS                                                             │"
    );
    let _ = writeln!(
        s,
        "│    Total:   {:>6}  │  Running: {:>6}  │  Stopped: {:>6}         │",
        snap.domains.total, snap.domains.running, snap.domains.stopped
    );

    let _ = writeln!(
        s,
        "├──────────────────────────────────────────────────────────────────────┤"
    );

    // Tasks
    let _ = writeln!(
        s,
        "│  TASKS                                                               │"
    );
    let _ = writeln!(
        s,
        "│    Context Switches: {:>10}                                     │",
        snap.tasks.context_switches
    );
    let _ = writeln!(
        s,
        "│    Voluntary Yields: {:>10}                                     │",
        snap.tasks.voluntary_yields
    );
    let _ = writeln!(
        s,
        "│    Forced Preempts:  {:>10}                                     │",
        snap.tasks.forced_preemptions
    );

    let _ = writeln!(
        s,
        "├──────────────────────────────────────────────────────────────────────┤"
    );

    // Network
    let _ = writeln!(
        s,
        "│  NETWORK                                                             │"
    );
    let _ = writeln!(
        s,
        "│    RX: {:>8} pkts ({:>12} bytes)                            │",
        snap.network.rx_packets, snap.network.rx_bytes
    );
    let _ = writeln!(
        s,
        "│    TX: {:>8} pkts ({:>12} bytes)                            │",
        snap.network.tx_packets, snap.network.tx_bytes
    );

    let _ = writeln!(
        s,
        "└──────────────────────────────────────────────────────────────────────┘"
    );

    s
}

/// Print snapshot to console
pub fn print_snapshot(snap: &SystemSnapshot) {
    let s = format_snapshot(snap);
    log::info!("{}", s);
}

/// Print compact one-line status
pub fn print_status_line(snap: &SystemSnapshot) {
    log::info!(
        "[STATS] T={} CPU={}% MEM={}% DOM={}/{} CTX={}\n",
        snap.timestamp,
        snap.cpu_usage,
        snap.memory.usage_percent,
        snap.domains.running,
        snap.domains.total,
        snap.tasks.context_switches
    );
}

/// Run continuous monitoring (for async task)
pub async fn monitor_loop() {
    log::info!("[MONITOR] Starting monitor loop\n");

    while is_running() {
        let snap = snapshot();
        print_status_line(&snap);

        crate::task::sleep_ms(REFRESH_RATE_MS).await;
    }

    log::info!("[MONITOR] Monitor loop stopped\n");
}

/// Run single snapshot
pub fn run_once() {
    let snap = snapshot();
    print_snapshot(&snap);
}

/// Historical data storage
pub struct MonitorHistory {
    snapshots: Vec<SystemSnapshot>,
    max_size: usize,
}

impl MonitorHistory {
    pub fn new(max_size: usize) -> Self {
        MonitorHistory {
            snapshots: Vec::with_capacity(max_size),
            max_size,
        }
    }

    pub fn add(&mut self, snap: SystemSnapshot) {
        if self.snapshots.len() >= self.max_size {
            self.snapshots.remove(0);
        }
        self.snapshots.push(snap);
    }

    pub fn latest(&self) -> Option<&SystemSnapshot> {
        self.snapshots.last()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SystemSnapshot> {
        self.snapshots.iter()
    }

    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Calculate average CPU usage
    pub fn avg_cpu(&self) -> u8 {
        if self.snapshots.is_empty() {
            return 0;
        }
        let sum: u64 = self.snapshots.iter().map(|s| s.cpu_usage as u64).sum();
        (sum / self.snapshots.len() as u64) as u8
    }

    /// Calculate average memory usage
    pub fn avg_memory(&self) -> u8 {
        if self.snapshots.is_empty() {
            return 0;
        }
        let sum: u64 = self
            .snapshots
            .iter()
            .map(|s| s.memory.usage_percent as u64)
            .sum();
        (sum / self.snapshots.len() as u64) as u8
    }
}
