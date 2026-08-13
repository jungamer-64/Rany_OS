// ============================================================================
// src/monitor/collectors.rs - Data Collectors for System Monitor
// ============================================================================

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

/// CPU statistics collector
pub struct CpuCollector {
    /// Last observed scheduler poll count.
    last_polls: AtomicU64,
    /// Last total ticks
    last_total: AtomicU64,
}

impl CpuCollector {
    pub const fn new() -> Self {
        CpuCollector {
            last_polls: AtomicU64::new(0),
            last_total: AtomicU64::new(0),
        }
    }

    /// Collect CPU usage percentage
    pub fn collect(&self) -> u8 {
        let polls = crate::task::scheduler_snapshot().map_or(0, |state| state.poll_count);

        let total = crate::interrupts::get_timer_ticks();
        let last_total = self.last_total.swap(total, Ordering::Relaxed);
        let last_polls = self.last_polls.swap(polls, Ordering::Relaxed);

        if last_total == 0 || total <= last_total {
            return 5; // Default low usage
        }

        let delta = total - last_total;

        let poll_delta = polls.saturating_sub(last_polls);
        let estimated_usage = ((poll_delta * 100) / delta.max(1)) as u8;

        estimated_usage.min(100)
    }
}

/// Memory statistics collector
pub struct MemoryCollector {
    /// Peak heap usage
    peak_used: AtomicU64,
}

impl MemoryCollector {
    pub const fn new() -> Self {
        MemoryCollector {
            peak_used: AtomicU64::new(0),
        }
    }

    /// Collect memory statistics
    pub fn collect(&self) -> super::MemoryStats {
        let (used, free) = crate::heap::heap_stats();
        let total = used + free;

        // Update peak
        // LOOP_PROOF: mode=event; reason=Loop progress is controlled by explicit break or return on state transitions/events.;
        loop {
            let peak = self.peak_used.load(Ordering::Relaxed);
            if used as u64 > peak {
                if self
                    .peak_used
                    .compare_exchange(peak, used as u64, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    break;
                }
            } else {
                break;
            }
        }

        let usage_percent = if total > 0 {
            ((used * 100) / total) as u8
        } else {
            0
        };

        super::MemoryStats {
            heap_used: used,
            heap_free: free,
            heap_total: total,
            usage_percent,
        }
    }

    /// Get peak usage
    pub fn peak(&self) -> u64 {
        self.peak_used.load(Ordering::Relaxed)
    }

    /// Reset peak
    pub fn reset_peak(&self) {
        self.peak_used.store(0, Ordering::Relaxed);
    }
}

/// Network statistics collector
pub struct NetworkCollector {
    /// Last RX packets
    last_rx_packets: AtomicU64,
    /// Last TX packets
    last_tx_packets: AtomicU64,
    /// Last RX bytes
    last_rx_bytes: AtomicU64,
    /// Last TX bytes
    last_tx_bytes: AtomicU64,
}

impl NetworkCollector {
    pub const fn new() -> Self {
        NetworkCollector {
            last_rx_packets: AtomicU64::new(0),
            last_tx_packets: AtomicU64::new(0),
            last_rx_bytes: AtomicU64::new(0),
            last_tx_bytes: AtomicU64::new(0),
        }
    }

    /// Collect network statistics
    pub fn collect(&self) -> super::NetworkStats {
        // In a real implementation, this would query the network stack
        super::NetworkStats::default()
    }

    /// Calculate packets per second
    pub fn pps(&self, interval_ms: u64) -> (u64, u64) {
        // RX and TX PPS
        (0, 0)
    }

    /// Calculate bytes per second
    pub fn bps(&self, interval_ms: u64) -> (u64, u64) {
        // RX and TX BPS
        (0, 0)
    }
}

/// Task statistics collector
pub struct TaskCollector {
    /// Last scheduler poll count.
    last_polls: AtomicU64,
}

impl TaskCollector {
    pub const fn new() -> Self {
        TaskCollector {
            last_polls: AtomicU64::new(0),
        }
    }

    /// Collect task statistics
    pub fn collect(&self) -> super::TaskStats {
        let scheduler = crate::task::scheduler_snapshot();
        let ready_tasks = scheduler.as_ref().map_or(0, |state| {
            state
                .run_queues
                .iter()
                .map(|queue| queue.ready_tasks as u64)
                .sum()
        });

        super::TaskStats {
            task_count: scheduler
                .as_ref()
                .map_or(0, |state| state.task_count as u64),
            ready_tasks,
            poll_count: scheduler.as_ref().map_or(0, |state| state.poll_count),
        }
    }

    /// Calculate stackless task polls per second.
    pub fn polls_per_sec(&self, interval_ms: u64) -> u64 {
        let current = crate::task::scheduler_snapshot().map_or(0, |state| state.poll_count);
        let last = self.last_polls.swap(current, Ordering::Relaxed);

        if interval_ms == 0 || current < last {
            return 0;
        }

        ((current - last) * 1000) / interval_ms
    }
}

/// Domain statistics collector
pub struct DomainCollector;

impl DomainCollector {
    pub const fn new() -> Self {
        DomainCollector
    }

    /// Collect domain statistics
    pub fn collect(&self) -> super::DomainStats {
        let stats = crate::domain::get_domain_stats();

        super::DomainStats {
            total: stats.total,
            running: stats.running,
            stopped: stats.stopped,
            failed: 0,
        }
    }
}

/// Aggregate collector that gathers all statistics
pub struct AggregateCollector {
    pub cpu: CpuCollector,
    pub memory: MemoryCollector,
    pub network: NetworkCollector,
    pub task: TaskCollector,
    pub domain: DomainCollector,
}

impl AggregateCollector {
    pub const fn new() -> Self {
        AggregateCollector {
            cpu: CpuCollector::new(),
            memory: MemoryCollector::new(),
            network: NetworkCollector::new(),
            task: TaskCollector::new(),
            domain: DomainCollector::new(),
        }
    }

    /// Collect all statistics
    pub fn collect_all(&self) -> super::SystemSnapshot {
        super::SystemSnapshot {
            timestamp: crate::interrupts::get_timer_ticks(),
            cpu_usage: self.cpu.collect(),
            memory: self.memory.collect(),
            domains: self.domain.collect(),
            network: self.network.collect(),
            tasks: self.task.collect(),
            io: super::IoStats::default(),
        }
    }
}

/// Global aggregate collector
static COLLECTOR: AggregateCollector = AggregateCollector::new();

/// Get global collector
pub fn collector() -> &'static AggregateCollector {
    &COLLECTOR
}
