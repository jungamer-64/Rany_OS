// ============================================================================
// src/shell/exoshell/namespaces/task.rs - Task Management Namespace
// ============================================================================
//!
//! ExoShell の task 名前空間。
//! タスク・エグゼキュータの状態観測を提供する。
//!
//! ## 使用例 (ExoShell)
//! ```text
//! task.stats()        → { task_count, forced_switches, runtime_ns, quota_waiting, ... }
//! task.fuel()         → { remaining, is_active }
//! task.tick()         → 現在のティック値
//! task.yield()        → 手動yield
//! ```

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;

use super::{BoxFuture, ShellNamespace};
use crate::security::CapabilitySet;
use crate::security::capability::CAP_SYS_ADMIN;
use crate::shell::exoshell::types::ExoValue;

/// タスク管理名前空間
pub struct TaskNamespace;

/// BTreeMapキー生成ヘルパー
#[inline]
fn s(v: &str) -> String {
    String::from(v)
}

impl TaskNamespace {
    fn require_sys_admin(caps: &CapabilitySet, op_name: &str) -> Result<(), ExoValue<'static>> {
        if caps.has_capability(CAP_SYS_ADMIN) {
            Ok(())
        } else {
            Err(ExoValue::Error(format!(
                "Permission denied: {} requires CAP_SYS_ADMIN",
                op_name
            )))
        }
    }

    /// タスクシステムの統計情報
    pub fn stats(caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_sys_admin(caps, "task.stats") {
            return e;
        }
        let scheduler = crate::task::scheduler_snapshot();
        let timer_stats = crate::task::timer_stats();
        let fuel_remaining = crate::task::fuel::Fuel::remaining();
        let fuel_active = crate::task::fuel::Fuel::is_active();
        let current_tick = crate::task::current_tick();

        let mut map = BTreeMap::new();
        map.insert(
            s("pending_wakes"),
            ExoValue::Int(scheduler.as_ref().map_or(0, |state| state.pending_wakes) as i64),
        );
        let task_count = scheduler.as_ref().map_or(0, |state| state.task_count);
        let poll_count = scheduler.as_ref().map_or(0, |state| state.poll_count);
        let ready_tasks = scheduler.as_ref().map_or(0, |state| {
            state.run_queues.iter().map(|queue| queue.ready_tasks).sum()
        });
        let online_queues = scheduler.as_ref().map_or(0, |state| state.run_queues.len());
        map.insert(s("task_count"), ExoValue::Int(task_count as i64));
        map.insert(s("task_polls"), ExoValue::Int(poll_count as i64));
        map.insert(s("ready_tasks"), ExoValue::Int(ready_tasks as i64));
        map.insert(s("online_queues"), ExoValue::Int(online_queues as i64));
        map.insert(
            s("timer_registered"),
            ExoValue::Int(timer_stats.active_timers as i64),
        );
        map.insert(s("timer_due"), ExoValue::Int(timer_stats.due_timers as i64));
        map.insert(
            s("timer_fired"),
            ExoValue::Int(timer_stats.total_fired as i64),
        );
        map.insert(
            s("timer_notifications"),
            ExoValue::Int(timer_stats.notifications as i64),
        );
        map.insert(
            s("forced_switches"),
            ExoValue::Int(scheduler.as_ref().map_or(0, |state| state.forced_switches) as i64),
        );
        map.insert(
            s("runtime_ns"),
            ExoValue::Int(scheduler.as_ref().map_or(0, |state| state.runtime_ns) as i64),
        );
        map.insert(
            s("quota_waiting"),
            ExoValue::Int(scheduler.as_ref().map_or(0, |state| state.quota_waiting) as i64),
        );
        map.insert(
            s("interrupted_polls"),
            ExoValue::Int(
                scheduler
                    .as_ref()
                    .map_or(0, |state| state.interrupted_polls) as i64,
            ),
        );
        map.insert(s("fuel_remaining"), ExoValue::Int(fuel_remaining as i64));
        map.insert(s("fuel_active"), ExoValue::Bool(fuel_active));
        map.insert(s("current_tick"), ExoValue::Int(current_tick as i64));
        ExoValue::Map(map)
    }

    /// Fuel（実行予算）の情報
    pub fn fuel(caps: &CapabilitySet) -> ExoValue<'static> {
        if let Err(e) = Self::require_sys_admin(caps, "task.fuel") {
            return e;
        }
        let remaining = crate::task::fuel::Fuel::remaining();
        let active = crate::task::fuel::Fuel::is_active();

        let mut map = BTreeMap::new();
        map.insert(s("remaining"), ExoValue::Int(remaining as i64));
        map.insert(s("is_active"), ExoValue::Bool(active));
        ExoValue::Map(map)
    }

    /// 現在のティック値
    pub fn tick() -> ExoValue<'static> {
        ExoValue::Int(crate::task::current_tick() as i64)
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
        caps: &'a crate::security::CapabilitySet,
    ) -> BoxFuture<'a, ExoValue<'static>> {
        Box::pin(async move {
            match method {
                "stats" => Self::stats(caps),
                "fuel" => Self::fuel(caps),
                "tick" => Self::tick(),
                "yield" => Self::do_yield().await,
                _ => ExoValue::Error(format!(
                    "Unknown method 'task.{}'\nValid methods: stats, fuel, tick, yield",
                    method
                )),
            }
        })
    }
}
