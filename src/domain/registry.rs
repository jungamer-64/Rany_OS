// ============================================================================
// src/domain/registry.rs - Domain Registry
// 設計書 3.1: セル（ドメイン）の管理とライフサイクル
// 
// P3完了: domain_system.rs の統合されたDomain/DomainStateを使用
// このモジュールはdomain_system.rsへの薄いラッパーとして機能
// ============================================================================

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

// domain_system.rs から統合された型を再エクスポート（重複定義の排除）
pub use crate::domain_system::{Domain, DomainId, DomainState};

use alloc::string::String;
use spin::Mutex;

// ============================================================================
// 公開API - domain_system.rs への委譲
// domain/lifecycle.rs などから使用される互換レイヤー
// ============================================================================

/// カーネルドメインを初期化
/// 内部的に domain_system::init() を呼び出す
pub fn init_kernel_domain() {
    crate::domain_system::init();
}

/// 新しいドメインを登録
/// 内部的に domain_system::create_domain() を呼び出す
pub fn register_domain(name: String) -> DomainId {
    crate::domain_system::create_domain(name)
}

/// ドメインを取得（読み取り用）
/// 内部的に domain_system::with_domain() を呼び出す
pub fn get_domain<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&Domain) -> R,
{
    crate::domain_system::with_domain(id, f)
}

/// ドメインを更新
/// 内部的に domain_system::with_domain_mut() を呼び出す
pub fn update_domain<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&mut Domain) -> R,
{
    crate::domain_system::with_domain_mut(id, f)
}

/// ドメインの状態を変更
/// 内部的に domain_system::set_domain_state() を呼び出す
pub fn set_domain_state(id: DomainId, state: DomainState) {
    crate::domain_system::set_domain_state(id, state);
}

/// ドメインにタスクを追加
pub fn add_task_to_domain(domain_id: DomainId, task_id: u64) {
    update_domain(domain_id, |domain| {
        domain.add_task(task_id);
    });
}

/// ドメインからタスクを削除
pub fn remove_task_from_domain(domain_id: DomainId, task_id: u64) {
    update_domain(domain_id, |domain| {
        domain.remove_task(task_id);
    });
}

/// 全ドメインの統計を取得
pub fn get_domain_stats() -> DomainStats {
    crate::domain_system::get_stats()
}

/// ドメイン統計（domain_system::DomainStatsの再エクスポート）
pub use crate::domain_system::DomainStats;
