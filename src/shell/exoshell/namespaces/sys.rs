// ============================================================================
// src/shell/exoshell/namespaces/sys.rs - System Namespace
// ============================================================================

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::shell::exoshell::types::ExoValue;

/// システム名前空間
pub struct SysNamespace;

impl SysNamespace {
    /// システム情報
    pub fn info() -> ExoValue {
        let mut map = BTreeMap::new();
        map.insert(String::from("os"), ExoValue::String(String::from("RanyOS")));
        map.insert(String::from("arch"), ExoValue::String(String::from("x86_64")));
        map.insert(String::from("version"), ExoValue::String(String::from("0.3.0-alpha")));
        map.insert(String::from("kernel"), ExoValue::String(String::from("ExoRust")));
        
        let ticks = crate::task::timer::current_tick();
        map.insert(String::from("uptime_ms"), ExoValue::Int(ticks as i64));
        
        ExoValue::Map(map)
    }

    /// メモリ情報
    pub fn memory() -> ExoValue {
        let mut map = BTreeMap::new();
        // TODO: 実際のメモリ統計を取得
        map.insert(String::from("total_kb"), ExoValue::Int(131072));
        map.insert(String::from("used_kb"), ExoValue::Int(65536));
        map.insert(String::from("free_kb"), ExoValue::Int(65536));
        ExoValue::Map(map)
    }

    /// 時刻情報
    pub fn time() -> ExoValue {
        let ticks = crate::task::timer::current_tick();
        let seconds = ticks / 1000;
        let mut map = BTreeMap::new();
        map.insert(String::from("ticks"), ExoValue::Int(ticks as i64));
        map.insert(String::from("seconds"), ExoValue::Int(seconds as i64));
        map.insert(String::from("hours"), ExoValue::Int((seconds / 3600) as i64));
        map.insert(String::from("minutes"), ExoValue::Int(((seconds % 3600) / 60) as i64));
        ExoValue::Map(map)
    }

    /// システムモニター情報
    pub fn monitor() -> ExoValue {
        let snap = crate::monitor::snapshot();
        let mut map = BTreeMap::new();
        
        // 基本情報
        map.insert(String::from("timestamp"), ExoValue::Int(snap.timestamp as i64));
        map.insert(String::from("cpu_usage"), ExoValue::Int(snap.cpu_usage as i64));
        
        // メモリ情報
        let mut mem = BTreeMap::new();
        mem.insert(String::from("heap_used"), ExoValue::Int(snap.memory.heap_used as i64));
        mem.insert(String::from("heap_free"), ExoValue::Int(snap.memory.heap_free as i64));
        mem.insert(String::from("heap_total"), ExoValue::Int(snap.memory.heap_total as i64));
        mem.insert(String::from("usage_percent"), ExoValue::Int(snap.memory.usage_percent as i64));
        map.insert(String::from("memory"), ExoValue::Map(mem));
        
        // ドメイン情報
        let mut domains = BTreeMap::new();
        domains.insert(String::from("total"), ExoValue::Int(snap.domains.total as i64));
        domains.insert(String::from("running"), ExoValue::Int(snap.domains.running as i64));
        domains.insert(String::from("stopped"), ExoValue::Int(snap.domains.stopped as i64));
        map.insert(String::from("domains"), ExoValue::Map(domains));
        
        // タスク情報
        let mut tasks = BTreeMap::new();
        tasks.insert(String::from("context_switches"), ExoValue::Int(snap.tasks.context_switches as i64));
        tasks.insert(String::from("voluntary_yields"), ExoValue::Int(snap.tasks.voluntary_yields as i64));
        tasks.insert(String::from("forced_preemptions"), ExoValue::Int(snap.tasks.forced_preemptions as i64));
        map.insert(String::from("tasks"), ExoValue::Map(tasks));
        
        // ネットワーク情報
        let mut net = BTreeMap::new();
        net.insert(String::from("rx_packets"), ExoValue::Int(snap.network.rx_packets as i64));
        net.insert(String::from("tx_packets"), ExoValue::Int(snap.network.tx_packets as i64));
        net.insert(String::from("rx_bytes"), ExoValue::Int(snap.network.rx_bytes as i64));
        net.insert(String::from("tx_bytes"), ExoValue::Int(snap.network.tx_bytes as i64));
        map.insert(String::from("network"), ExoValue::Map(net));
        
        ExoValue::Map(map)
    }

    /// モニターダッシュボードを表示
    pub fn monitor_dashboard() -> ExoValue {
        let snap = crate::monitor::snapshot();
        crate::monitor::print_snapshot(&snap);
        ExoValue::String(String::from("Dashboard displayed"))
    }

    /// 温度情報
    pub fn thermal() -> ExoValue {
        let mut map = BTreeMap::new();
        
        // CPU温度を取得
        if let Some(temp) = crate::thermal::cpu_temperature() {
            map.insert(String::from("cpu_celsius"), ExoValue::Int(temp.celsius() as i64));
            map.insert(String::from("cpu_millicelsius"), ExoValue::Int(temp.millicelsius() as i64));
        } else {
            map.insert(String::from("cpu_celsius"), ExoValue::String(String::from("N/A")));
        }
        
        // サーマルマネージャから詳細情報
        let tm = crate::thermal::thermal_manager();
        let (polling_count, trip_events) = tm.stats();
        map.insert(String::from("polling_count"), ExoValue::Int(polling_count as i64));
        map.insert(String::from("trip_events"), ExoValue::Int(trip_events as i64));
        
        // スロットリング情報
        let throttle = tm.throttle_controller();
        let policy = throttle.current_policy();
        map.insert(String::from("throttle_policy"), ExoValue::String(format!("{:?}", policy)));
        map.insert(String::from("throttle_count"), ExoValue::Int(throttle.throttle_count() as i64));
        
        // センサー情報
        let sensors = tm.sensors();
        let mut sensor_list = Vec::new();
        for sensor in sensors.iter() {
            let mut s = BTreeMap::new();
            s.insert(String::from("id"), ExoValue::Int(sensor.id as i64));
            s.insert(String::from("name"), ExoValue::String(sensor.name.clone()));
            if sensor.current.is_valid() {
                s.insert(String::from("current_c"), ExoValue::Int(sensor.current.celsius() as i64));
            }
            s.insert(String::from("is_hot"), ExoValue::Bool(sensor.is_hot()));
            s.insert(String::from("is_critical"), ExoValue::Bool(sensor.is_critical()));
            sensor_list.push(ExoValue::Map(s));
        }
        map.insert(String::from("sensors"), ExoValue::Array(sensor_list));
        
        ExoValue::Map(map)
    }

    /// ウォッチドッグ情報
    pub fn watchdog() -> ExoValue {
        let mut map = BTreeMap::new();
        
        let wm = crate::watchdog::watchdog_manager();
        let sw = wm.software();
        let (heartbeats, timeouts, checks) = sw.stats();
        
        map.insert(String::from("heartbeats"), ExoValue::Int(heartbeats as i64));
        map.insert(String::from("timeouts"), ExoValue::Int(timeouts as i64));
        map.insert(String::from("checks"), ExoValue::Int(checks as i64));
        
        // デッドロック検出情報
        let dd = wm.deadlock_detector();
        map.insert(String::from("deadlocks_detected"), ExoValue::Int(dd.deadlocks_detected() as i64));
        
        ExoValue::Map(map)
    }

    /// 電源情報
    pub fn power() -> ExoValue {
        let mut map = BTreeMap::new();
        
        let pm = crate::power::power_manager();
        let state = pm.current_state();
        map.insert(String::from("state"), ExoValue::String(format!("{:?}", state)));
        
        let stats = pm.stats();
        map.insert(String::from("power_button_presses"), 
            ExoValue::Int(stats.power_button_presses.load(core::sync::atomic::Ordering::Relaxed) as i64));
        map.insert(String::from("sleep_button_presses"), 
            ExoValue::Int(stats.sleep_button_presses.load(core::sync::atomic::Ordering::Relaxed) as i64));
        
        // CPUアイドル統計
        let idle = crate::power::cpu_idle();
        let (c1, c2, c3) = idle.stats();
        let mut idle_stats = BTreeMap::new();
        idle_stats.insert(String::from("c1_count"), ExoValue::Int(c1 as i64));
        idle_stats.insert(String::from("c2_count"), ExoValue::Int(c2 as i64));
        idle_stats.insert(String::from("c3_count"), ExoValue::Int(c3 as i64));
        map.insert(String::from("cpu_idle"), ExoValue::Map(idle_stats));
        
        ExoValue::Map(map)
    }

    /// システムシャットダウン
    pub fn shutdown() -> ExoValue {
        crate::log!("[SYS] Shutdown requested via shell\n");
        // 実際のシャットダウンは危険なのでメッセージのみ
        ExoValue::String(String::from("Shutdown command received. Use Ctrl+Alt+Del or power button to actually shutdown."))
    }

    /// システムリブート
    pub fn reboot() -> ExoValue {
        crate::log!("[SYS] Reboot requested via shell\n");
        // 実際のリブートは危険なのでメッセージのみ
        ExoValue::String(String::from("Reboot command received. Use Ctrl+Alt+Del to actually reboot."))
    }
}
