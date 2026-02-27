// ============================================================================
// src/shell/exoshell/namespaces/sys.rs - System Namespace
// ============================================================================

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
pub struct SysNamespace;

impl SysNamespace {
    /// システム情報
    pub fn info() -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        map.insert(
            String::from("os"),
            ExoValue::String(Cow::Borrowed("RanyOS")),
        );
        map.insert(
            String::from("arch"),
            ExoValue::String(Cow::Borrowed("x86_64")),
        );
        map.insert(
            String::from("version"),
            ExoValue::String(Cow::Borrowed("0.3.0-alpha")),
        );
        map.insert(
            String::from("kernel"),
            ExoValue::String(Cow::Borrowed("ExoRust")),
        );

        let ticks = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_tick())
            .unwrap_or(0);
        map.insert(String::from("uptime_ms"), ExoValue::Int(ticks as i64));

        ExoValue::Map(map)
    }

    /// メモリ情報
    pub fn memory() -> ExoValue<'static> {
        let mut map = BTreeMap::new();
        // 実際のメモリ統計を取得
        let stats = kernel_api::services::kernel()
            .shell()
            .map(|s| s.memory_stats())
            .unwrap_or_default();
        let total = stats.total_kb;
        let free = stats.free_kb;
        let used = stats.used_kb;

        map.insert(String::from("total_kb"), ExoValue::Int(total as i64));
        map.insert(String::from("used_kb"), ExoValue::Int(used as i64));
        map.insert(String::from("free_kb"), ExoValue::Int(free as i64));

        // 使用率をパーセントで計算
        let usage_percent = if total > 0 { (used * 100) / total } else { 0 };
        map.insert(
            String::from("usage_percent"),
            ExoValue::Int(usage_percent as i64),
        );

        ExoValue::Map(map)
    }

    /// 時刻情報
    pub fn time() -> ExoValue<'static> {
        let ticks = kernel_api::services::kernel()
            .shell()
            .map(|s| s.current_tick())
            .unwrap_or(0);
        let seconds = ticks / 1000;
        let mut map = BTreeMap::new();
        map.insert(String::from("ticks"), ExoValue::Int(ticks as i64));
        map.insert(String::from("seconds"), ExoValue::Int(seconds as i64));
        map.insert(
            String::from("hours"),
            ExoValue::Int((seconds / 3600) as i64),
        );
        map.insert(
            String::from("minutes"),
            ExoValue::Int(((seconds % 3600) / 60) as i64),
        );
        ExoValue::Map(map)
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
        if let Some(info) = crate::io::iommu::runtime::panic::last_panic_record() {
            map.insert(String::from("available"), ExoValue::Bool(true));
            map.insert(String::from("iova"), ExoValue::Int(info.iova as i64));
            map.insert(
                String::from("phys"),
                ExoValue::Int(info.phys.as_u64() as i64),
            );
            map.insert(String::from("len"), ExoValue::Int(info.len as i64));
            map.insert(String::from("total"), ExoValue::Int(info.total as i64));
            let message = crate::io::iommu::runtime::panic::last_panic_record_message();
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
        _args: &'a [ExoValue<'static>],
        caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "info" => Self::info(),
                "memory" | "mem" => Self::memory(),
                "time" => Self::time(),
                "monitor" => Self::monitor(),
                "dashboard" => Self::monitor_dashboard(),
                "thermal" | "temp" => Self::thermal(),
                "watchdog" | "wd" => Self::watchdog(),
                "power" => Self::power(),
                "panic_record" => Self::panic_record(),
                "shutdown" => Self::shutdown_with_caps(caps),
                "reboot" => Self::reboot_with_caps(caps),
                _ => ExoValue::Error(format!(
                    "Unknown method 'sys.{}'\nValid methods: info, memory, time, monitor, dashboard, thermal, watchdog, power, panic_record, shutdown, reboot",
                    method
                )),
            }
        })
    }
}
