// ============================================================================
// kernel/src/system_info.rs - System Information Provider
// ============================================================================
//!
//! # システム情報プロバイダー
//!
//! カーネル各サブシステムの情報を集約し、構造化データAPIを提供する。
//!
//! ## 構造化データAPI（ExoShellネームスペース: `SysNamespace` が使用）
//! 生データアクセス関数群。`SysNamespace` がこれらを `ExoValue` に変換する。
//!
//! ## 設計原則
//! - `ExoValue` への依存を持たない（shellモジュール非依存）
//! - 上位層（SysNamespace）がExoValueラッピングを担当

use crate::domain_system::{DomainId, DomainState, get_domain_snapshot, list_domain_snapshots};
use alloc::vec::Vec;

mod cpuinfo_gen;
use cpuinfo_gen::*;

// ============================================================================
// Primary API: Raw data accessors (SysNamespace が ExoValue に変換する)
// ============================================================================

/// OS名
pub fn os_name() -> &'static str {
    "RanyOS"
}

/// アーキテクチャ名
pub fn arch_name() -> &'static str {
    "x86_64"
}

/// カーネルバージョン
pub fn kernel_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// カーネル名
pub fn kernel_name() -> &'static str {
    "ExoRust"
}

/// 合計メモリ (KB)
pub fn memory_total_kb() -> u64 {
    crate::memory::total_memory_kb()
}

/// 空きメモリ (KB)
pub fn memory_free_kb() -> u64 {
    crate::memory::free_memory_kb()
}

/// アップタイム (tick単位、1tick = 1ms)
pub fn uptime_ticks() -> u64 {
    crate::time::current_tick()
}

/// CPU数
pub fn cpu_count() -> usize {
    crate::smp::cpu_count() as usize
}

/// CPUベンダー文字列
pub fn cpu_vendor() -> &'static str {
    get_cpu_vendor()
}

/// CPUモデル名
pub fn cpu_model() -> &'static str {
    get_cpu_model_name()
}

/// タイマー割り込み回数
pub fn timer_ticks() -> u64 {
    crate::interrupts::get_timer_ticks()
}

/// コンテキストスイッチ回数
pub fn context_switch_count() -> u64 {
    crate::task::context::CONTEXT_SWITCH_COUNT.load(core::sync::atomic::Ordering::Relaxed)
}

/// ブート時刻 (秒)
pub fn boot_time_secs() -> u64 {
    crate::time::now().saturating_sub(crate::time::current_tick() / 1000)
}

/// ドメインスナップショット一覧
pub fn domain_snapshots() -> Vec<crate::domain_system::DomainSnapshot> {
    let mut snaps = list_domain_snapshots();
    snaps.sort_by_key(|s| s.id.as_u64());
    snaps
}

/// 指定ドメインのスナップショット
pub fn domain_snapshot(id: u64) -> Option<crate::domain_system::DomainSnapshot> {
    get_domain_snapshot(DomainId::new(id))
}

/// ドメイン状態を文字列に変換
pub fn state_str(state: DomainState) -> &'static str {
    state_to_str(state)
}

// ============================================================================
// Internal helpers
// ============================================================================

fn state_to_str(state: DomainState) -> &'static str {
    match state {
        DomainState::Initializing => "initializing",
        DomainState::Running => "running",
        DomainState::Suspended => "suspended",
        DomainState::Stopped => "stopped",
        DomainState::Terminated => "terminated",
    }
}
