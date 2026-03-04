// ============================================================================
// src/shell/exoshell/namespaces/task.rs - Task Management Namespace
// ============================================================================
//!
//! ExoShell の task 名前空間。
//! タスク・エグゼキュータの状態観測を提供する。
//!
//! ## 使用例 (ExoShell)
//! ```text
//! task.stats()        → { wake_queue_len, wake_queue_capacity, fuel_remaining, ... }
//! task.fuel()         → { remaining, is_active }
//! task.preemption()   → { yields_requested, timer_ticks, ... }
//! task.tick()         → 現在のティック値
//! task.yield()        → 手動yield
//! ```

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::boxed::Box;

use super::{BoxFuture, ShellNamespace};
use crate::shell::exoshell::types::ExoValue;

/// タスク管理名前空間
pub struct TaskNamespace;

/// BTreeMapキー生成ヘルパー
#[inline]
fn s(v: &str) -> String {
    String::from(v)
}

impl TaskNamespace {
    /// タスクシステムの統計情報
    pub fn stats() -> ExoValue<'static> {
        let (wake_len, wake_cap) = crate::task::waker::wake_queue_stats();
        let (timer_len, timer_cap) = crate::task::timer::pending_waker_stats();
        let fuel_remaining = crate::task::fuel::Fuel::remaining();
        let fuel_active = crate::task::fuel::Fuel::is_active();
        let current_tick = crate::task::timer::current_tick();

        let mut map = BTreeMap::new();
        map.insert(s("wake_queue_len"), ExoValue::Int(wake_len as i64));
        map.insert(s("wake_queue_capacity"), ExoValue::Int(wake_cap as i64));
        map.insert(s("timer_pending"), ExoValue::Int(timer_len as i64));
        map.insert(s("timer_capacity"), ExoValue::Int(timer_cap as i64));
        map.insert(s("fuel_remaining"), ExoValue::Int(fuel_remaining as i64));
        map.insert(s("fuel_active"), ExoValue::Bool(fuel_active));
        map.insert(s("current_tick"), ExoValue::Int(current_tick as i64));
        ExoValue::Map(map)
    }

    /// Fuel（実行予算）の情報
    pub fn fuel() -> ExoValue<'static> {
        let remaining = crate::task::fuel::Fuel::remaining();
        let active = crate::task::fuel::Fuel::is_active();

        let mut map = BTreeMap::new();
        map.insert(s("remaining"), ExoValue::Int(remaining as i64));
        map.insert(s("is_active"), ExoValue::Bool(active));
        ExoValue::Map(map)
    }

    /// プリエンプション統計
    pub fn preemption() -> ExoValue<'static> {
        let stats = crate::task::preemption::preemption_controller().stats();
        let mut map = BTreeMap::new();
        map.insert(s("forced_preemptions"), ExoValue::Int(stats.forced_preemptions as i64));
        map.insert(s("voluntary_yields"), ExoValue::Int(stats.voluntary_yields as i64));
        map.insert(s("current_time_slice"), ExoValue::Int(stats.current_time_slice as i64));
        map.insert(s("enabled"), ExoValue::Bool(stats.enabled));
        ExoValue::Map(map)
    }

    /// 現在のティック値
    pub fn tick() -> ExoValue<'static> {
        ExoValue::Int(crate::task::timer::current_tick() as i64)
    }

    /// 手動yield
    pub async fn do_yield() -> ExoValue<'static> {
        crate::task::yield_now().await;
        ExoValue::Bool(true)
    }
}

impl ShellNamespace for TaskNamespace {
    fn name(&self) -> &str {
        "task"
    }

    fn call<'a>(
        &'a self,
        method: &'a str,
        _args: &'a [ExoValue<'static>],
        _caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "stats" => Self::stats(),
                "fuel" => Self::fuel(),
                "preemption" => Self::preemption(),
                "tick" => Self::tick(),
                "yield" => Self::do_yield().await,
                _ => ExoValue::Error(format!(
                    "Unknown method 'task.{}'\nValid methods: stats, fuel, preemption, tick, yield",
                    method
                )),
            }
        })
    }
}
