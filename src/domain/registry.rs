// ============================================================================
// src/domain/registry.rs - Domain Registry
// 設計書 3.1: セル（ドメイン）の管理とライフサイクル
// ============================================================================

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]

use crate::ipc::rref::DomainId;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

/// ドメインの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// 初期化中
    Initializing,
    /// 実行中
    Running,
    /// 一時停止
    Suspended,
    /// 停止中（パニック後）
    Stopped,
    /// 終了済み
    Terminated,
}

/// ドメイン（セル）の情報
/// 設計書 3.1: セルはRustのクレートに相当するソフトウェアの構成単位
pub struct Domain {
    /// ドメインID
    pub id: DomainId,
    /// ドメイン名
    pub name: String,
    /// ドメインの状態
    pub state: DomainState,
    /// 所有するタスクのID一覧
    pub tasks: Vec<u64>,
    /// 依存するドメインのID一覧
    pub dependencies: Vec<DomainId>,
    /// このドメインに依存するドメインのID一覧
    pub dependents: Vec<DomainId>,
    /// 統計: 作成されたRRefの数
    pub rref_count: u64,
    /// 統計: 実行時間（ティック）
    pub runtime_ticks: u64,
    /// パニックメッセージ（Stopped状態の場合）
    pub panic_message: Option<String>,
}

impl Domain {
    /// 新しいドメインを作成
    pub fn new(id: DomainId, name: String) -> Self {
        Self {
            id,
            name,
            state: DomainState::Initializing,
            tasks: Vec::new(),
            dependencies: Vec::new(),
            dependents: Vec::new(),
            rref_count: 0,
            runtime_ticks: 0,
            panic_message: None,
        }
    }

    /// タスクを追加
    pub fn add_task(&mut self, task_id: u64) {
        self.tasks.push(task_id);
    }

    /// タスクを削除
    pub fn remove_task(&mut self, task_id: u64) {
        self.tasks.retain(|&id| id != task_id);
    }

    /// 依存関係を追加
    pub fn add_dependency(&mut self, dep_id: DomainId) {
        if !self.dependencies.contains(&dep_id) {
            self.dependencies.push(dep_id);
        }
    }

    /// 被依存関係を追加（他のドメインがこのドメインに依存）
    pub fn add_dependent(&mut self, dep_id: DomainId) {
        if !self.dependents.contains(&dep_id) {
            self.dependents.push(dep_id);
        }
    }

    /// ドメインが実行可能かどうか
    pub fn is_runnable(&self) -> bool {
        matches!(self.state, DomainState::Running | DomainState::Initializing)
    }
}

/// ドメインレジストリ
/// システム上の全ドメインを管理
pub struct DomainRegistry {
    /// ドメインID -> ドメインのマッピング
    domains: BTreeMap<DomainId, Domain>,
    /// 次のドメインID
    next_id: AtomicU64,
}

impl DomainRegistry {
    /// 新しいレジストリを作成
    pub const fn new() -> Self {
        Self {
            domains: BTreeMap::new(),
            next_id: AtomicU64::new(1), // 0はカーネル用に予約
        }
    }

    /// 新しいドメインIDを生成
    pub fn generate_id(&self) -> DomainId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        DomainId::new(id)
    }

    /// ドメインを登録
    pub fn register(&mut self, domain: Domain) {
        self.domains.insert(domain.id, domain);
    }

    /// ドメインを取得
    pub fn get(&self, id: DomainId) -> Option<&Domain> {
        self.domains.get(&id)
    }

    /// ドメインを可変で取得
    pub fn get_mut(&mut self, id: DomainId) -> Option<&mut Domain> {
        self.domains.get_mut(&id)
    }

    /// ドメインを削除
    pub fn remove(&mut self, id: DomainId) -> Option<Domain> {
        self.domains.remove(&id)
    }

    /// 全ドメインを列挙
    pub fn all_domains(&self) -> impl Iterator<Item = &Domain> {
        self.domains.values()
    }

    /// 特定の状態のドメインを列挙
    pub fn domains_by_state(&self, state: DomainState) -> impl Iterator<Item = &Domain> {
        self.domains.values().filter(move |d| d.state == state)
    }

    /// ドメイン数を取得
    pub fn count(&self) -> usize {
        self.domains.len()
    }
}

/// グローバルなドメインレジストリ
static DOMAIN_REGISTRY: Mutex<DomainRegistry> = Mutex::new(DomainRegistry::new());

/// カーネルドメインを初期化
pub fn init_kernel_domain() {
    let mut registry = DOMAIN_REGISTRY.lock();
    let mut kernel = Domain::new(DomainId::KERNEL, "kernel".into());
    kernel.state = DomainState::Running;
    registry.domains.insert(DomainId::KERNEL, kernel);
}

/// 新しいドメインを登録
pub fn register_domain(name: String) -> DomainId {
    let mut registry = DOMAIN_REGISTRY.lock();
    let id = registry.generate_id();
    let domain = Domain::new(id, name);
    registry.register(domain);
    id
}

/// ドメインを取得（読み取り用）
pub fn get_domain<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&Domain) -> R,
{
    let registry = DOMAIN_REGISTRY.lock();
    registry.get(id).map(f)
}

/// ドメインを更新
pub fn update_domain<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&mut Domain) -> R,
{
    let mut registry = DOMAIN_REGISTRY.lock();
    registry.get_mut(id).map(f)
}

/// ドメインの状態を変更
pub fn set_domain_state(id: DomainId, state: DomainState) {
    update_domain(id, |domain| {
        domain.state = state;
    });
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
    let registry = DOMAIN_REGISTRY.lock();
    DomainStats {
        total: registry.count(),
        running: registry.domains_by_state(DomainState::Running).count(),
        stopped: registry.domains_by_state(DomainState::Stopped).count(),
    }
}

/// ドメイン統計
#[derive(Debug, Clone)]
pub struct DomainStats {
    pub total: usize,
    pub running: usize,
    pub stopped: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_registry() {
        let mut registry = DomainRegistry::new();

        // ドメイン作成
        let id1 = registry.generate_id();
        let domain1 = Domain::new(id1, "test1".into());
        registry.register(domain1);

        // 取得
        let domain = registry.get(id1);
        assert!(domain.is_some());
        assert_eq!(domain.unwrap().name, "test1");

        // 状態変更
        registry.get_mut(id1).unwrap().state = DomainState::Running;
        assert_eq!(registry.get(id1).unwrap().state, DomainState::Running);
    }
}
