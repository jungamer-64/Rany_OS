// ============================================================================
// src/shell/exoshell/namespaces/sys.rs - System Namespace
// ============================================================================
//!
//! ExoShellのsys名前空間。
//! `system_info` モジュールの raw data API から `ExoValue` を構築する。
//!
//! ## 使用例 (ExoShell)
//! ```text
//! sys.info()       → { os, arch, version, kernel, uptime_ms }
//! sys.memory()     → { total_kb, free_kb, used_kb, usage_percent }
//! sys.cpu()        → { count, vendor, model, cores: [...] }
//! sys.uptime()     → { ticks, seconds, hours, minutes }
//! sys.stat()       → { timer_ticks, context_switches, ... }
//! sys.kernel()     → { hostname, ostype, version }
//! sys.cells()      → [{ id, name, state, tasks, ... }, ...]
//! sys.cell(id)     → { id, name, state, tasks, ... }
//! sys.net()        → { interfaces: [...] }
//! sys.load()       → { avg1, avg5, avg15, running, total }
//! ```

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{BoxFuture, ShellNamespace};
use crate::security::capability::CAP_SYS_BOOT;
use crate::shell::exoshell::types::ExoValue;
use alloc::boxed::Box;

/// システム名前空間
///
/// `system_info` モジュールの raw data アクセサを使い、
/// ExoValue を構築して ExoShell ネームスペースとして公開する。
pub struct SysNamespace;

/// BTreeMapキー生成ヘルパー
#[inline]
fn s(v: &str) -> String {
    String::from(v)
}

impl SysNamespace {
    /// システム情報（バージョン + アップタイム）
    pub fn info() -> ExoValue<'static> {
        use crate::system_info as si;
        let mut map = BTreeMap::new();
        map.insert(s("os"), ExoValue::String(Cow::Borrowed(si::os_name())));
        map.insert(s("arch"), ExoValue::String(Cow::Borrowed(si::arch_name())));
        map.insert(s("version"), ExoValue::String(Cow::Borrowed(si::kernel_version())));
        map.insert(s("kernel"), ExoValue::String(Cow::Borrowed(si::kernel_name())));
        let ticks = kernel_api::services::kernel()
            .shell()
            .map(|sh| sh.current_tick())
            .unwrap_or(0);
        map.insert(s("uptime_ms"), ExoValue::Int(ticks as i64));
        ExoValue::Map(map)
    }

    /// メモリ情報
    pub fn memory() -> ExoValue<'static> {
        use crate::system_info as si;
        let total_kb = si::memory_total_kb();
        let free_kb = si::memory_free_kb();
        let used_kb = total_kb.saturating_sub(free_kb);
        let usage_percent = if total_kb > 0 { (used_kb * 100) / total_kb } else { 0 };

        let mut map = BTreeMap::new();
        map.insert(s("total_kb"), ExoValue::Int(total_kb as i64));
        map.insert(s("free_kb"), ExoValue::Int(free_kb as i64));
        map.insert(s("used_kb"), ExoValue::Int(used_kb as i64));
        map.insert(s("available_kb"), ExoValue::Int((free_kb + free_kb / 4) as i64));
        map.insert(s("usage_percent"), ExoValue::Int(usage_percent as i64));
        ExoValue::Map(map)
    }

    /// 時刻・アップタイム情報
    pub fn time() -> ExoValue<'static> {
        let ticks = crate::system_info::uptime_ticks();
        let seconds = ticks / 1000;
        let mut map = BTreeMap::new();
        map.insert(s("ticks"), ExoValue::Int(ticks as i64));
        map.insert(s("seconds"), ExoValue::Int(seconds as i64));
        map.insert(s("hours"), ExoValue::Int((seconds / 3600) as i64));
        map.insert(s("minutes"), ExoValue::Int(((seconds % 3600) / 60) as i64));
        ExoValue::Map(map)
    }

    /// CPU情報
    pub fn cpu() -> ExoValue<'static> {
        use crate::system_info as si;
        let count = si::cpu_count();
        let vendor = si::cpu_vendor();
        let model = si::cpu_model();

        let mut map = BTreeMap::new();
        map.insert(s("count"), ExoValue::Int(count as i64));
        map.insert(s("vendor"), ExoValue::String(Cow::Borrowed(vendor)));
        map.insert(s("model"), ExoValue::String(Cow::Borrowed(model)));
        map.insert(s("family"), ExoValue::Int(6));
        map.insert(s("mhz"), ExoValue::Float(3000.0));
        map.insert(s("cache_kb"), ExoValue::Int(8192));

        let cores: Vec<ExoValue> = (0..count)
            .map(|id| {
                let mut cpu = BTreeMap::new();
                cpu.insert(s("id"), ExoValue::Int(id as i64));
                cpu.insert(s("core_id"), ExoValue::Int(id as i64));
                cpu.insert(s("vendor"), ExoValue::String(Cow::Borrowed(vendor)));
                cpu.insert(s("model"), ExoValue::String(Cow::Borrowed(model)));
                ExoValue::Map(cpu)
            })
            .collect();
        map.insert(s("cores"), ExoValue::Array(cores));
        ExoValue::Map(map)
    }

    /// システム統計
    pub fn stat() -> ExoValue<'static> {
        use crate::system_info as si;
        let mut map = BTreeMap::new();
        map.insert(s("timer_ticks"), ExoValue::Int(si::timer_ticks() as i64));
        map.insert(s("context_switches"), ExoValue::Int(si::context_switch_count() as i64));
        map.insert(s("boot_time"), ExoValue::Int(si::boot_time_secs() as i64));
        map.insert(s("domains"), ExoValue::Int(si::domain_snapshots().len() as i64));
        map.insert(s("cpu_count"), ExoValue::Int(si::cpu_count() as i64));
        ExoValue::Map(map)
    }

    /// カーネル基本情報
    pub fn kernel() -> ExoValue<'static> {
        use crate::system_info as si;
        let mut map = BTreeMap::new();
        map.insert(s("hostname"), ExoValue::String(Cow::Borrowed("exorust")));
        map.insert(s("ostype"), ExoValue::String(Cow::Borrowed(si::kernel_name())));
        map.insert(s("version"), ExoValue::String(Cow::Borrowed(si::kernel_version())));
        ExoValue::Map(map)
    }

    /// セル（ドメイン）一覧
    pub fn cells() -> ExoValue<'static> {
        let snaps = crate::system_info::domain_snapshots();
        let cells: Vec<ExoValue> = snaps.iter().map(Self::snap_to_value).collect();
        ExoValue::Array(cells)
    }

    /// 指定セルの情報
    pub fn cell(args: &[ExoValue<'static>]) -> ExoValue<'static> {
        let id = match args.first() {
            Some(ExoValue::Int(n)) if *n >= 0 => *n as u64,
            Some(ExoValue::String(s)) => match s.parse::<u64>() {
                Ok(n) => n,
                Err(_) => return ExoValue::Error(String::from("Expected cell id (int)")),
            },
            _ => return ExoValue::Error(String::from("Usage: sys.cell(id)")),
        };
        match crate::system_info::domain_snapshot(id) {
            Some(snap) => Self::snap_to_value(&snap),
            None => ExoValue::Error(format!("Cell {} not found", id)),
        }
    }

    /// ネットワーク概要（スタブ）
    pub fn net() -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        let lo = Self::net_iface("lo", 0, 0, 0, 0);
        let eth0 = Self::net_iface("eth0", 0, 0, 0, 0);
        map.insert(s("interfaces"), ExoValue::Array(alloc::vec![lo, eth0]));
        ExoValue::Map(map)
    }

    /// ロードアベレージ（スタブ）
    pub fn load() -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(s("avg1"), ExoValue::Float(0.0));
        map.insert(s("avg5"), ExoValue::Float(0.0));
        map.insert(s("avg15"), ExoValue::Float(0.0));
        map.insert(s("running"), ExoValue::Int(1));
        map.insert(s("total"), ExoValue::Int(1));
        ExoValue::Map(map)
    }

    // ---- ヘルパー ----

    /// DomainSnapshot → ExoValue::Map
    fn snap_to_value(snap: &crate::domain_system::DomainSnapshot) -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(s("id"), ExoValue::Int(snap.id.as_u64() as i64));
        map.insert(s("name"), ExoValue::String(Cow::Owned(snap.name.clone())));
        map.insert(s("state"), ExoValue::String(Cow::Borrowed(
            crate::system_info::state_str(snap.state),
        )));
        map.insert(s("tasks"), ExoValue::Int(snap.tasks as i64));
        map.insert(s("memory_kb"), ExoValue::Int((snap.memory_bytes / 1024) as i64));
        map.insert(s("memory_bytes"), ExoValue::Int(snap.memory_bytes as i64));
        map.insert(s("rrefs"), ExoValue::Int(snap.rrefs as i64));
        map.insert(s("runtime_ticks"), ExoValue::Int(snap.runtime_ticks as i64));
        map.insert(s("context_switches"), ExoValue::Int(snap.context_switches as i64));
        map.insert(s("created_at"), ExoValue::Int(snap.created_at as i64));
        map.insert(s("numa_node"), snap.numa_node
            .map(|n| ExoValue::Int(n as i64))
            .unwrap_or(ExoValue::Nil));
        if let Some(msg) = &snap.panic_message {
            map.insert(s("panic_message"), ExoValue::String(Cow::Owned(msg.clone())));
        }
        if let Some(err) = &snap.last_error {
            map.insert(s("last_error"), ExoValue::String(Cow::Owned(err.clone())));
        }
        let task_ids: Vec<ExoValue> = snap.task_ids.iter()
            .map(|&id| ExoValue::Int(id as i64)).collect();
        map.insert(s("task_ids"), ExoValue::Array(task_ids));
        let deps: Vec<ExoValue> = snap.dependencies.iter()
            .map(|id| ExoValue::Int(id.as_u64() as i64)).collect();
        map.insert(s("dependencies"), ExoValue::Array(deps));
        let depts: Vec<ExoValue> = snap.dependents.iter()
            .map(|id| ExoValue::Int(id.as_u64() as i64)).collect();
        map.insert(s("dependents"), ExoValue::Array(depts));
        ExoValue::Map(map)
    }

    /// ネットワークインターフェース ExoValue 生成ヘルパー
    fn net_iface(name: &'static str, rx_b: i64, tx_b: i64, rx_p: i64, tx_p: i64) -> ExoValue<'static> {
        let mut m = BTreeMap::new();
        m.insert(s("name"), ExoValue::String(Cow::Borrowed(name)));
        m.insert(s("rx_bytes"), ExoValue::Int(rx_b));
        m.insert(s("tx_bytes"), ExoValue::Int(tx_b));
        m.insert(s("rx_packets"), ExoValue::Int(rx_p));
        m.insert(s("tx_packets"), ExoValue::Int(tx_p));
        ExoValue::Map(m)
    }

    /// システムモニター情報
    pub fn monitor() -> ExoValue<'static> {
        let info = kernel_api::services::kernel()
            .shell()
            .map(|s| s.monitor_info())
            .unwrap_or_default();

        let mut map = BTreeMap::new();

        // Memory
        let mut mem = BTreeMap::new();
        mem.insert(
            String::from("heap_used"),
            ExoValue::Int(info.memory.heap_used as i64),
        );
        mem.insert(
            String::from("heap_free"),
            ExoValue::Int(info.memory.heap_free as i64),
        );
        mem.insert(
            String::from("heap_total"),
            ExoValue::Int(info.memory.heap_total as i64),
        );
        mem.insert(
            String::from("usage_percent"),
            ExoValue::Int(info.memory.usage_percent as i64),
        );
        map.insert(String::from("memory"), ExoValue::Map(mem));

        // Domains
        let mut dom = BTreeMap::new();
        dom.insert(
            String::from("total"),
            ExoValue::Int(info.domains.total as i64),
        );
        dom.insert(
            String::from("running"),
            ExoValue::Int(info.domains.running as i64),
        );
        dom.insert(
            String::from("stopped"),
            ExoValue::Int(info.domains.stopped as i64),
        );
        map.insert(String::from("domains"), ExoValue::Map(dom));

        // Tasks
        let mut tasks = BTreeMap::new();
        tasks.insert(
            String::from("context_switches"),
            ExoValue::Int(info.tasks.context_switches as i64),
        );
        tasks.insert(
            String::from("voluntary_yields"),
            ExoValue::Int(info.tasks.voluntary_yields as i64),
        );
        tasks.insert(
            String::from("forced_preemptions"),
            ExoValue::Int(info.tasks.forced_preemptions as i64),
        );
        map.insert(String::from("tasks"), ExoValue::Map(tasks));

        // Network
        let mut net = BTreeMap::new();
        net.insert(
            String::from("rx_packets"),
            ExoValue::Int(info.network.rx_packets as i64),
        );
        net.insert(
            String::from("tx_packets"),
            ExoValue::Int(info.network.tx_packets as i64),
        );
        net.insert(
            String::from("rx_bytes"),
            ExoValue::Int(info.network.rx_bytes as i64),
        );
        net.insert(
            String::from("tx_bytes"),
            ExoValue::Int(info.network.tx_bytes as i64),
        );
        map.insert(String::from("network"), ExoValue::Map(net));

        ExoValue::Map(map)
    }

    /// モニターダッシュボードを表示
    pub fn monitor_dashboard() -> ExoValue<'static> {
        let info = kernel_api::services::kernel()
            .shell()
            .map(|s| s.monitor_info())
            .unwrap_or_default();

        log::info!("\n");
        log::info!("┌──────────────────────────────────────────────────────────────────────┐\n");
        log::info!("│                    ExoRust System Monitor                            │\n");
        log::info!("├──────────────────────────────────────────────────────────────────────┤\n");
        log::info!("│  Tick: {:>12}  │  CPU: {:>3}%                                   │\n", info.timestamp, info.cpu_usage);
        log::info!("├──────────────────────────────────────────────────────────────────────┤\n");
        log::info!("│  MEMORY                                                              │\n");
        log::info!("│    Used:  {:>10} bytes ({:>2}%)                                  │\n", info.memory.heap_used, info.memory.usage_percent);
        log::info!("│    Free:  {:>10} bytes                                          │\n", info.memory.heap_free);
        log::info!("│    Total: {:>10} bytes                                          │\n", info.memory.heap_total);
        log::info!("├──────────────────────────────────────────────────────────────────────┤\n");
        log::info!("│  DOMAINS                                                             │\n");
        log::info!("│    Total:   {:>6}  │  Running: {:>6}  │  Stopped: {:>6}         │\n", info.domains.total, info.domains.running, info.domains.stopped);
        log::info!("├──────────────────────────────────────────────────────────────────────┤\n");
        log::info!("│  TASKS                                                               │\n");
        log::info!("│    Context Switches: {:>10}                                     │\n", info.tasks.context_switches);
        log::info!("│    Voluntary Yields: {:>10}                                     │\n", info.tasks.voluntary_yields);
        log::info!("│    Forced Preempts:  {:>10}                                     │\n", info.tasks.forced_preemptions);
        log::info!("└──────────────────────────────────────────────────────────────────────┘\n");

        ExoValue::String(Cow::Borrowed("Dashboard displayed"))
    }

    /// 温度情報
    pub fn thermal() -> ExoValue<'static> {
        let info = kernel_api::services::kernel()
            .shell()
            .map(|s| s.thermal_info())
            .unwrap_or(kernel_api::shell::ThermalInfo {
                cpu_celsius: None,
                polling_count: 0,
                trip_events: 0,
                throttle_policy: String::from("Unknown"),
                throttle_count: 0,
                sensors: Vec::new(),
            });

        let mut map = BTreeMap::new();
        
        if let Some(c) = info.cpu_celsius {
            map.insert(String::from("cpu_celsius"), ExoValue::Float(c as f64));
        } else {
            map.insert(
                String::from("cpu_celsius"),
                ExoValue::String(Cow::Borrowed("N/A")),
            );
        }
        
        map.insert(
            String::from("polling_count"),
            ExoValue::Int(info.polling_count as i64),
        );
        map.insert(
            String::from("trip_events"),
            ExoValue::Int(info.trip_events as i64),
        );
        map.insert(
            String::from("throttle_policy"),
            ExoValue::String(Cow::Owned(info.throttle_policy)),
        );
        map.insert(
            String::from("throttle_count"),
            ExoValue::Int(info.throttle_count as i64),
        );

        let sensors: Vec<ExoValue> = info.sensors.into_iter().map(|s| {
            let mut smap = BTreeMap::new();
            smap.insert(String::from("id"), ExoValue::Int(s.id as i64));
            smap.insert(String::from("name"), ExoValue::String(Cow::Owned(s.name)));
            if let Some(temp) = s.current_c {
                smap.insert(String::from("temperature"), ExoValue::Float(temp as f64));
            }
            smap.insert(String::from("is_hot"), ExoValue::Bool(s.is_hot));
            smap.insert(String::from("is_critical"), ExoValue::Bool(s.is_critical));
            ExoValue::Map(smap)
        }).collect();
        
        map.insert(String::from("sensors"), ExoValue::Array(sensors));

        ExoValue::Map(map)
    }

    /// ウォッチドッグ情報
    pub fn watchdog() -> ExoValue<'static> {
        let info = kernel_api::services::kernel()
            .shell()
            .map(|s| s.watchdog_info())
            .unwrap_or_default();

        let mut map = BTreeMap::new();
        map.insert(
            String::from("heartbeats"),
            ExoValue::Int(info.heartbeats as i64),
        );
        map.insert(
            String::from("timeouts"),
            ExoValue::Int(info.timeouts as i64),
        );
        map.insert(
            String::from("checks"),
            ExoValue::Int(info.checks as i64),
        );
        map.insert(
            String::from("deadlocks_detected"),
            ExoValue::Int(info.deadlocks_detected as i64),
        );

        ExoValue::Map(map)
    }

    /// 電源情報
    pub fn power() -> ExoValue<'static> {
        let info = kernel_api::services::kernel()
            .shell()
            .map(|s| s.power_info())
            .unwrap_or(kernel_api::shell::PowerInfo {
                state: String::from("Unknown"),
                power_button_presses: 0,
                sleep_button_presses: 0,
                cpu_idle: kernel_api::shell::CpuIdleInfo::default(),
            });

        let mut map = BTreeMap::new();
        map.insert(
            String::from("state"),
            ExoValue::String(Cow::Owned(info.state)),
        );
        map.insert(
            String::from("power_button"),
            ExoValue::Int(info.power_button_presses as i64),
        );
        map.insert(
            String::from("sleep_button"),
            ExoValue::Int(info.sleep_button_presses as i64),
        );
        
        let mut idle = BTreeMap::new();
        idle.insert(String::from("c1_count"), ExoValue::Int(info.cpu_idle.c1_count as i64));
        idle.insert(String::from("c2_count"), ExoValue::Int(info.cpu_idle.c2_count as i64));
        idle.insert(String::from("c3_count"), ExoValue::Int(info.cpu_idle.c3_count as i64));
        map.insert(String::from("cpu_idle"), ExoValue::Map(idle));

        ExoValue::Map(map)
    }

    /// パニックDMA記録（IOMMUが有効な場合）
    pub fn panic_record() -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        if let Some(info) = crate::io::iommu::api::last_panic_record() {
            map.insert(String::from("available"), ExoValue::Bool(true));
            map.insert(String::from("iova"), ExoValue::Int(info.iova as i64));
            map.insert(
                String::from("phys"),
                ExoValue::Int(info.phys.as_u64() as i64),
            );
            map.insert(String::from("len"), ExoValue::Int(info.len as i64));
            map.insert(String::from("total"), ExoValue::Int(info.total as i64));
            let message = crate::io::iommu::api::last_panic_record_message();
            map.insert(
                String::from("message"),
                ExoValue::String(Cow::Owned(
                    message.map(String::from).unwrap_or_else(|| String::from("<invalid>")),
                )),
            );
        } else {
            map.insert(String::from("available"), ExoValue::Bool(false));
        }

        ExoValue::Map(map)
    }

    /// システムシャットダウン
    /// Requires CAP_SYS_BOOT
    fn shutdown_with_caps(caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_BOOT) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_BOOT required"));
        }

        log::info!("[SYS] Shutdown requested via shell\n");
        
        if let Some(shell) = kernel_api::services::kernel().shell() {
            shell.shutdown();
        }
        
        ExoValue::Nil
    }

    /// システムリブート
    /// Requires CAP_SYS_BOOT
    fn reboot_with_caps(caps: &crate::security::CapabilitySet) -> ExoValue<'static> {
        if !caps.has_capability(CAP_SYS_BOOT) {
            return ExoValue::Error(String::from("Permission denied: CAP_SYS_BOOT required"));
        }

        log::info!("[SYS] Reboot requested via shell\n");
        
        if let Some(shell) = kernel_api::services::kernel().shell() {
            shell.reboot();
        }

        ExoValue::Nil
    }
}

impl ShellNamespace for SysNamespace {
    fn name(&self) -> &str {
        "sys"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        args: &'a [ExoValue<'static>],
        caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "info" => Self::info(),
                "memory" | "mem" => Self::memory(),
                "time" | "uptime" => Self::time(),
                "cpu" | "cpuinfo" => Self::cpu(),
                "stat" | "stats" => Self::stat(),
                "kernel" => Self::kernel(),
                "cells" => Self::cells(),
                "cell" => Self::cell(args),
                "net" | "network" => Self::net(),
                "load" | "loadavg" => Self::load(),
                "monitor" => Self::monitor(),
                "dashboard" => Self::monitor_dashboard(),
                "thermal" | "temp" => Self::thermal(),
                "watchdog" | "wd" => Self::watchdog(),
                "power" => Self::power(),
                "panic_record" => Self::panic_record(),
                "shutdown" => Self::shutdown_with_caps(caps),
                "reboot" => Self::reboot_with_caps(caps),
                _ => ExoValue::Error(format!(
                    "Unknown method 'sys.{}'\nValid methods: info, memory, time, cpu, stat, kernel, cells, cell, net, load, monitor, dashboard, thermal, watchdog, power, panic_record, shutdown, reboot",
                    method
                )),
            }
        })
    }
}
