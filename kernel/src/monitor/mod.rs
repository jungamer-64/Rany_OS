// ============================================================================
// src/monitor/mod.rs - System Monitor Dashboard
// ============================================================================
//!
//! # システムモニター・ダッシュボード
//!
//! ## 責務
//! - リアルタイムシステムスナップショット (`SystemSnapshot`)
//! - CPU/メモリ/ネットワーク/IO/タスク/ドメイン統計の集約
//! - ヘルスチェック (`HealthMonitor`)
//! - 定期スナップショット取得 API
//!
//! ## 関連モジュール（可観測性ファミリー）
//! - `diag/` — 低レベル診断（TSC計測、ヒストグラム、トレースポイント、ベンチマーク）
//! - `profiler/` — サンプリングベースCPU/メモリ/I/Oプロファイリング
//!
//! `diag/` が提供する低レベル計測値を集約し、ダッシュボード用のスナップショットとして提供する。

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

// Note: Individual modules disabled until API stabilization
// pub mod display;
// pub mod collectors;

use crate::sync::PoisonLock;
use alloc::string::String;
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
    let (heap_used, heap_free) = crate::heap::heap_stats();
    let heap_total = heap_used + heap_free;
    let usage_percent = if heap_total > 0 {
        ((heap_used * 100) / heap_total) as u8
    } else {
        0
    };

    let domain_stats = crate::domain::get_domain_stats();

    let preempt_stats = crate::task::aggregate_preemption_stats();

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
    static LAST_TICK: AtomicU64 = AtomicU64::new(0);

    let current = crate::interrupts::get_timer_ticks();
    let last = LAST_TICK.swap(current, Ordering::Relaxed);

    if last == 0 {
        return 5;
    }

    10
}

/// Collect network statistics
fn collect_network_stats() -> NetworkStats {
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

    // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
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

// ============================================================================
// ヘルスモニタリング（設計書 §10.4）
// ============================================================================

use core::sync::atomic::AtomicU32;

/// ヘルス状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthStatus {
    /// 正常
    Healthy,
    /// 警告（閾値に近い）
    Warning,
    /// 危険（閾値超過）
    Critical,
    /// 不明（データ不足）
    Unknown,
}

/// ヘルスチェック閾値
#[derive(Debug, Clone)]
pub struct HealthThresholds {
    /// CPU使用率の警告閾値（%）
    pub cpu_warning: u8,
    /// CPU使用率の危険閾値（%）
    pub cpu_critical: u8,
    /// メモリ使用率の警告閾値（%）
    pub memory_warning: u8,
    /// メモリ使用率の危険閾値（%）
    pub memory_critical: u8,
    /// 連続異常判定回数
    pub consecutive_failures: u32,
}

impl Default for HealthThresholds {
    fn default() -> Self {
        Self {
            cpu_warning: 70,
            cpu_critical: 90,
            memory_warning: 80,
            memory_critical: 95,
            consecutive_failures: 3,
        }
    }
}

/// ヘルスメトリクス
#[derive(Debug, Clone, Default)]
pub struct HealthMetrics {
    /// 最新のCPU使用率
    pub cpu_usage: u8,
    /// 最新のメモリ使用率
    pub memory_usage: u8,
    /// 連続警告回数
    pub consecutive_warnings: u32,
    /// 連続危険回数
    pub consecutive_criticals: u32,
    /// 最終チェック時刻（tick）
    pub last_check_tick: u64,
    /// ヘルスチェック総回数
    pub total_checks: u64,
    /// 警告発生総回数
    pub total_warnings: u64,
    /// 危険発生総回数
    pub total_criticals: u64,
}

/// ヘルスモニター
pub struct HealthMonitor {
    thresholds: HealthThresholds,
    metrics: PoisonLock<HealthMetrics>,
    enabled: AtomicBool,
}

impl HealthMonitor {
    /// 新しいヘルスモニターを作成
    pub const fn new() -> Self {
        Self {
            thresholds: HealthThresholds {
                cpu_warning: 70,
                cpu_critical: 90,
                memory_warning: 80,
                memory_critical: 95,
                consecutive_failures: 3,
            },
            metrics: PoisonLock::new(HealthMetrics {
                cpu_usage: 0,
                memory_usage: 0,
                consecutive_warnings: 0,
                consecutive_criticals: 0,
                last_check_tick: 0,
                total_checks: 0,
                total_warnings: 0,
                total_criticals: 0,
            }),
            enabled: AtomicBool::new(false),
        }
    }

    /// ヘルスモニタリングを有効化
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::SeqCst);
    }

    /// ヘルスモニタリングを無効化
    pub fn disable(&self) {
        self.enabled.store(false, Ordering::SeqCst);
    }

    /// 有効状態を取得
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    /// ヘルスチェックを実行
    pub fn check(&self, snap: &SystemSnapshot) -> HealthStatus {
        if !self.is_enabled() {
            return HealthStatus::Unknown;
        }

        let mut metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        metrics.cpu_usage = snap.cpu_usage;
        metrics.memory_usage = snap.memory.usage_percent;
        metrics.last_check_tick = snap.timestamp;
        metrics.total_checks += 1;

        // CPU判定
        let cpu_status = if snap.cpu_usage >= self.thresholds.cpu_critical {
            HealthStatus::Critical
        } else if snap.cpu_usage >= self.thresholds.cpu_warning {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        // メモリ判定
        let mem_status = if snap.memory.usage_percent >= self.thresholds.memory_critical {
            HealthStatus::Critical
        } else if snap.memory.usage_percent >= self.thresholds.memory_warning {
            HealthStatus::Warning
        } else {
            HealthStatus::Healthy
        };

        // 総合判定
        let overall = match (cpu_status, mem_status) {
            (HealthStatus::Critical, _) | (_, HealthStatus::Critical) => {
                metrics.consecutive_criticals += 1;
                metrics.consecutive_warnings = 0;
                metrics.total_criticals += 1;
                HealthStatus::Critical
            }
            (HealthStatus::Warning, _) | (_, HealthStatus::Warning) => {
                metrics.consecutive_warnings += 1;
                metrics.consecutive_criticals = 0;
                metrics.total_warnings += 1;
                HealthStatus::Warning
            }
            _ => {
                metrics.consecutive_warnings = 0;
                metrics.consecutive_criticals = 0;
                HealthStatus::Healthy
            }
        };

        overall
    }

    /// 現在のメトリクスを取得
    pub fn metrics(&self) -> HealthMetrics {
        self.metrics
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// メトリクスをPrometheus形式でエクスポート
    pub fn export_prometheus(&self) -> String {
        use alloc::fmt::Write;
        let metrics = self.metrics.lock().unwrap_or_else(|e| e.into_inner());
        let mut s = String::new();

        let _ = writeln!(s, "# HELP exorust_cpu_usage CPU usage percentage");
        let _ = writeln!(s, "# TYPE exorust_cpu_usage gauge");
        let _ = writeln!(s, "exorust_cpu_usage {}", metrics.cpu_usage);

        let _ = writeln!(s, "# HELP exorust_memory_usage Memory usage percentage");
        let _ = writeln!(s, "# TYPE exorust_memory_usage gauge");
        let _ = writeln!(s, "exorust_memory_usage {}", metrics.memory_usage);

        let _ = writeln!(s, "# HELP exorust_health_checks_total Total health checks");
        let _ = writeln!(s, "# TYPE exorust_health_checks_total counter");
        let _ = writeln!(s, "exorust_health_checks_total {}", metrics.total_checks);

        let _ = writeln!(s, "# HELP exorust_health_warnings_total Total warnings");
        let _ = writeln!(s, "# TYPE exorust_health_warnings_total counter");
        let _ = writeln!(
            s,
            "exorust_health_warnings_total {}",
            metrics.total_warnings
        );

        let _ = writeln!(s, "# HELP exorust_health_criticals_total Total criticals");
        let _ = writeln!(s, "# TYPE exorust_health_criticals_total counter");
        let _ = writeln!(
            s,
            "exorust_health_criticals_total {}",
            metrics.total_criticals
        );

        s
    }
}

/// グローバルヘルスモニター
static HEALTH_MONITOR: HealthMonitor = HealthMonitor::new();

/// グローバルヘルスモニターを取得
pub fn health_monitor() -> &'static HealthMonitor {
    &HEALTH_MONITOR
}

/// ヘルスチェックを実行
pub fn health_check() -> HealthStatus {
    let snap = snapshot();
    HEALTH_MONITOR.check(&snap)
}

/// Prometheusメトリクスをエクスポート
pub fn export_metrics() -> String {
    HEALTH_MONITOR.export_prometheus()
}
