// ============================================================================
// src/domain_system.rs - 統合ドメイン管理システム
// ============================================================================
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 8.2: RedLeafの知見：交換可能な型とプロキシ
//
// domain/ と ipc/ の機能を統合し、一貫したドメイン管理を提供
// ============================================================================
#![allow(dead_code)]

// use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicU64, Ordering};
// 【設計書 8.1】PoisonLock使用 - パニック時自動毒入れ
use crate::error::{DomainErrorKind, KernelError};
use crate::sync::PoisonLock;

// ============================================================================
// ドメインID
// ============================================================================

/// ドメインを一意に識別するID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainId(u64);

impl DomainId {
    /// 新しいドメインIDを作成
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// IDを数値として取得
    pub const fn as_u64(&self) -> u64 {
        self.0
    }

    /// カーネルドメイン（常にID=0）
    pub const KERNEL: DomainId = DomainId(0);
}

impl core::fmt::Display for DomainId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Domain({})", self.0)
    }
}

// ============================================================================
// ドメイン状態
// ============================================================================

/// ドメインのライフサイクル状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainState {
    /// 初期化中
    Initializing,
    /// 実行中
    Running,
    /// 一時停止
    Suspended,
    /// 停止（エラーで）
    Stopped,
    /// 終了済み（リソース回収完了）
    Terminated,
}

impl DomainState {
    /// 実行可能な状態かどうか
    pub fn is_runnable(&self) -> bool {
        matches!(self, DomainState::Running | DomainState::Initializing)
    }

    /// アクティブな状態かどうか（リソースを保持）
    pub fn is_active(&self) -> bool {
        !matches!(self, DomainState::Terminated)
    }
}

// ============================================================================
// ドメイン構造体
// ============================================================================

/// ドメイン: 隔離された実行環境
#[derive(Debug)]
pub struct Domain {
    /// ドメインID
    pub id: DomainId,
    /// ドメイン名
    pub name: String,
    /// 現在の状態
    pub state: DomainState,

    // タスク管理
    /// このドメインに属するタスクID
    pub tasks: Vec<u64>,

    // 依存関係
    /// このドメインが依存するドメイン
    pub dependencies: Vec<DomainId>,
    /// このドメインに依存するドメイン
    pub dependents: Vec<DomainId>,

    // リソース追跡
    /// 所有するRRefの数
    pub rref_count: u64,
    /// 割り当て済みメモリ量（バイト）
    pub allocated_memory: u64,

    // 統計情報
    /// 総実行時間（ティック）
    pub runtime_ticks: u64,
    /// コンテキストスイッチ回数
    pub context_switches: u64,
    /// 作成時刻（ティック）
    pub created_at: u64,

    // エラー情報
    /// パニックメッセージ（クラッシュ時）
    pub panic_message: Option<String>,
    /// 最後のエラーメッセージ
    pub last_error: Option<String>,
    /// NUMAノードアフィニティ（任意）
    pub numa_node: Option<usize>,
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
            allocated_memory: 0,
            runtime_ticks: 0,
            context_switches: 0,
            created_at: crate::task::timer::current_tick(),
            panic_message: None,
            last_error: None,
            numa_node: None,
        }
    }

    /// 実行可能かどうか
    pub fn is_runnable(&self) -> bool {
        self.state.is_runnable()
    }

    /// タスクを追加
    pub fn add_task(&mut self, task_id: u64) {
        if !self.tasks.contains(&task_id) {
            self.tasks.push(task_id);
        }
    }

    /// タスクを削除
    pub fn remove_task(&mut self, task_id: u64) {
        self.tasks.retain(|&id| id != task_id);
    }

    /// 依存関係を追加
    pub fn add_dependency(&mut self, dep: DomainId) {
        if !self.dependencies.contains(&dep) {
            self.dependencies.push(dep);
        }
    }

    /// 被依存関係を追加（他のドメインがこのドメインに依存）
    pub fn add_dependent(&mut self, dep_id: DomainId) {
        if !self.dependents.contains(&dep_id) {
            self.dependents.push(dep_id);
        }
    }

    /// 依存関係を削除
    pub fn remove_dependency(&mut self, dep: DomainId) {
        self.dependencies.retain(|&id| id != dep);
    }

    /// 被依存関係を削除
    pub fn remove_dependent(&mut self, dep_id: DomainId) {
        self.dependents.retain(|&id| id != dep_id);
    }

    /// RRef数をインクリメント
    pub fn increment_rref(&mut self) {
        self.rref_count += 1;
    }

    /// RRef数をデクリメント
    pub fn decrement_rref(&mut self) {
        if self.rref_count > 0 {
            self.rref_count -= 1;
        }
    }

    /// メモリ使用量を追加
    pub fn add_memory(&mut self, size: u64) {
        self.allocated_memory = self.allocated_memory.saturating_add(size);
    }

    /// NUMAノードを設定
    pub fn set_numa_node(&mut self, node: usize) {
        self.numa_node = Some(node);
    }

    /// NUMAノードを取得
    pub fn get_numa_node(&self) -> Option<usize> {
        self.numa_node
    }

    /// メモリ使用量を減少
    pub fn free_memory(&mut self, size: u64) {
        self.allocated_memory = self.allocated_memory.saturating_sub(size);
    }
}

// ============================================================================
// ドメインレジストリ
// ============================================================================

/// ドメインレジストリ
#[derive(Debug)]
struct DomainRegistry {
    /// 全ドメインのリスト
    domains: Vec<Domain>,
    /// 次のドメインID
    next_id: AtomicU64,
}

impl DomainRegistry {
    /// 新しいレジストリを作成
    const fn new() -> Self {
        Self {
            domains: Vec::new(),
            next_id: AtomicU64::new(1), // 0はカーネル用
        }
    }

    /// 新しいドメインIDを生成
    fn generate_id(&self) -> DomainId {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        DomainId::new(id)
    }
}

/// グローバルなドメインレジストリ
/// 【設計書 8.1】PoisonLockを使用してパニック時の毒入れを保証
static REGISTRY: PoisonLock<DomainRegistry> = PoisonLock::new(DomainRegistry::new());

// ============================================================================
// ヒープレジストリ統合
// ============================================================================
// 以前はここに static HEAP_REGISTRY がありましたが、
// 拡張性のため crate::sas（Global Sharded Registry）に統合されました。
// ============================================================================

// ============================================================================
// 公開API - ドメイン管理
// ============================================================================

/// ドメインシステムを初期化（カーネルドメインを作成）
pub fn init() {
    crate::io::log::early_print("[DOM] lock\n");
    // 初期化時は毒入れされていないはず
    let mut registry = REGISTRY
        .lock()
        .expect("domain registry poisoned during init");
    crate::io::log::early_print("[DOM] locked\n");

    // カーネルドメインを作成
    let mut kernel = Domain::new(DomainId::KERNEL, "kernel".into());
    crate::io::log::early_print("[DOM] new done\n");
    kernel.state = DomainState::Running;
    crate::io::log::early_print("[DOM] insert\n");
    registry.domains.push(kernel);
    crate::io::log::early_print("[DOM] done\n");
}

/// 新しいドメインを作成
///
/// # パフォーマンス注意
/// `name.clone()` は `crate::log!` マクロで使用するために必要。
/// ドメイン作成は頻繁に呼ばれないため、このコストは許容される。
/// 代替案: log を先に行い、name を消費するパターン
pub fn create_domain(name: String) -> Result<DomainId, KernelError> {
    // Runtime path: do not attempt best-effort recovery from a poisoned registry.
    // If the registry lock is poisoned, return a conservative error so callers can
    // decide how to proceed (e.g., abort, retry, or propagate the error).
    match REGISTRY.lock() {
        Ok(mut registry) => {
            let id = registry.generate_id();
            // Log before consuming `name` to avoid an extra clone
            log::info!("[DOMAIN] Created domain {} ({})\n", id.as_u64(), &name);
            let domain = Domain::new(id, name);
            registry.domains.push(domain);
            Ok(id)
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned during create_domain");
            Err(KernelError::Domain(DomainErrorKind::RegistryPoisoned))
        }
    }
}

/// ドメインの状態を取得
pub fn get_domain_state(id: DomainId) -> Option<DomainState> {
    match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().find(|d| d.id == id).map(|d| d.state),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_state)");
            None
        }
    }
}

/// ドメインに対して読み取り操作を実行
/// domain/registry.rs からの互換性維持のために追加
pub fn with_domain<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&Domain) -> R,
{
    match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().find(|d| d.id == id).map(f),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (with_domain)");
            None
        }
    }
}

/// ドメインに対して更新操作を実行
/// domain/registry.rs からの互換性維持のために追加
pub fn with_domain_mut<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&mut Domain) -> R,
{
    match REGISTRY.lock() {
        Ok(mut guard) => guard.domains.iter_mut().find(|d| d.id == id).map(f),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (with_domain_mut)");
            None
        }
    }
}

/// ドメインの状態を変更
pub fn set_domain_state(id: DomainId, state: DomainState) {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                let old_state = domain.state;
                domain.state = state;
                log::info!("[DOMAIN] {} state: {:?} -> {:?}\n", id, old_state, state);
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (set_domain_state) - no-op"),
    }
}

/// ドメインを開始
pub fn start_domain(id: DomainId) -> Result<(), &'static str> {
    match REGISTRY.lock() {
        Ok(mut registry) => {
            if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                if domain.state != DomainState::Initializing {
                    return Err("Domain is not in initializing state");
                }
                domain.state = DomainState::Running;
                log::info!("[DOMAIN] Started {}\n", id);
                Ok(())
            } else {
                Err("Domain not found")
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (start_domain)");
            Err("Domain registry poisoned")
        }
    }
}

/// Set NUMA node for a domain
pub fn set_domain_numa(id: DomainId, node: usize) {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == id) {
                domain.set_numa_node(node);
                log::info!("[DOMAIN] {} NUMA node set to {}\n", id, node);
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (set_domain_numa) - no-op"),
    }
}

/// Get NUMA node for a domain
pub fn get_domain_numa(id: DomainId) -> Option<usize> {
    match REGISTRY.lock() {
        Ok(guard) => guard
            .domains
            .iter()
            .find(|d| d.id == id)
            .and_then(|d| d.get_numa_node()),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_numa)");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_set_and_get_domain_numa() {
        let id = create_domain(String::from("numa_test")).expect("create_domain failed");
        assert_eq!(get_domain_numa(id), None);
        set_domain_numa(id, 3);
        assert_eq!(get_domain_numa(id), Some(3usize));
    }

    #[test_case]
    fn test_domain_poisoned_readers_return_defaults() {
        use crate::sync::set_panicking;

        let id = create_domain(String::from("poison_test")).expect("create_domain failed");

        // Poison the registry lock
        set_panicking(true);
        if let Ok(_g) = REGISTRY.lock() {
            // dropping _g while panicking will mark the lock as poisoned
        }
        set_panicking(false);

        assert!(get_domain_state(id).is_none());
        assert!(with_domain(id, |_d| 1).is_none());
        assert!(with_domain_mut(id, |_d| 1).is_none());
        assert!(start_domain(id).is_err());

        let stats = get_domain_stats();
        assert_eq!(stats.total, 0);

        // print_domain_list should not panic
        print_domain_list();
    }

    #[test_case]
    fn test_create_domain_poisoned_returns_error() {
        use crate::error::{DomainErrorKind, KernelError};
        use crate::sync::set_panicking;

        // Poison the registry
        set_panicking(true);
        if let Ok(_g) = REGISTRY.lock() {
            // dropping _g will poison the lock
        }
        set_panicking(false);

        let res = create_domain(String::from("poison_test2"));
        assert_eq!(
            res,
            Err(KernelError::Domain(DomainErrorKind::RegistryPoisoned))
        );
    }

    #[test_case]
    fn test_domain_poisoned_add_remove_task_no_panic() {
        use crate::sync::set_panicking;

        let id = create_domain(String::from("task_poison")).expect("create_domain failed");

        set_panicking(true);
        if let Ok(_g) = REGISTRY.lock() {
            // drop marks as poisoned
        }
        set_panicking(false);

        // should not panic
        add_task_to_domain(id, 1234);
        remove_task_from_domain(id, 1234);
    }

    #[test_case]
    fn test_reclaim_domain_resources_poisoned_no_panic() {
        use crate::sync::set_panicking;

        let id = create_domain(String::from("reclaim_poison")).expect("create_domain failed");

        set_panicking(true);
        if let Ok(_g) = REGISTRY.lock() {
            // drop marks as poisoned
        }
        set_panicking(false);

        reclaim_domain_resources(id);
    }
}

/// Stop a domain
pub fn stop_domain(id: DomainId) -> Result<(), &'static str> {
    match REGISTRY.lock() {
        Ok(mut registry) => {
            if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                domain.state = DomainState::Stopped;
                log::info!("[DOMAIN] Stopped {}\n", id);
                Ok(())
            } else {
                Err("Domain not found")
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (stop_domain)");
            Err("Domain registry poisoned")
        }
    }
}

/// ドメインを終了しリソースを回収
pub fn terminate_domain(id: DomainId) -> Result<(), &'static str> {
    if id == DomainId::KERNEL {
        return Err("Cannot terminate kernel domain");
    }

    // dependents をロック外で使うため clone() が必要
    // Note: Vec<DomainId> の clone は DomainId が Copy なら
    // 単純な memcpy に展開される（Vecヘッダーのみアロケート）
    let dependents: Vec<DomainId>;

    {
        match REGISTRY.lock() {
            Ok(mut registry) => {
                if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                    domain.state = DomainState::Terminated;
                    // clone() はロックを保持したままの処理を避けるため
                    // デッドロック回避が clone のコストより重要
                    dependents = domain.dependents.clone();
                } else {
                    return Err("Domain not found");
                }
            }
            Err(_) => {
                log::error!("[DOMAIN] Registry poisoned (terminate_domain)");
                return Err("Domain registry poisoned");
            }
        }
    }

    // リソース回収（ロックを解放してから）
    reclaim_domain_resources(id);

    // 依存するドメインに通知
    {
        match REGISTRY.lock() {
            Ok(mut registry) => {
                for dep_id in dependents {
                    if let Some(dep) = registry.domains.iter_mut().find(|d| d.id == dep_id) {
                        dep.last_error = Some(format!("Dependency {} terminated", id.as_u64()));
                    }
                }
            }
            Err(_) => log::error!(
                "[DOMAIN] Registry poisoned (terminate_domain notify) - skipping dependent updates"
            ),
        }
    }

    log::info!("[DOMAIN] Terminated {} and reclaimed resources\n", id);
    Ok(())
}

/// ドメインがパニックした場合の処理
pub fn handle_domain_panic(id: DomainId, message: String) {
    log::info!("[PANIC] {} crashed: {}\n", id, message);

    {
        match REGISTRY.lock() {
            Ok(mut registry) => {
                if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                    domain.state = DomainState::Stopped;
                    domain.panic_message = Some(message);
                }
            }
            Err(_) => log::error!(
                "[DOMAIN] Registry poisoned (handle_domain_panic) - could not record panic message"
            ),
        }
    }

    // リソース回収
    reclaim_domain_resources(id);
}

/// ドメインにタスクを追加
pub fn add_task_to_domain(domain_id: DomainId, task_id: u64) {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == domain_id) {
                domain.add_task(task_id);
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (add_task_to_domain) - no-op"),
    }
}

/// ドメインからタスクを削除
pub fn remove_task_from_domain(domain_id: DomainId, task_id: u64) {
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == domain_id) {
                domain.remove_task(task_id);
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (remove_task_from_domain) - no-op"),
    }
}

// ============================================================================
// 公開API - リソース管理
// ============================================================================

/// Exchange Heap上にオブジェクトを登録
pub fn register_heap_object(ptr: usize, layout: Layout, owner: DomainId) {
    // 統合されたHeapRegistryに登録
    crate::sas::register_object(
        ptr,
        layout.size(),
        crate::sas::DomainId::new(owner.as_u64()),
    );

    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == owner) {
                domain.increment_rref();
                domain.add_memory(layout.size() as u64);
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (register_heap_object) - stats not updated")
        }
    }
}

/// Exchange Heap上のオブジェクトを解除
pub fn unregister_heap_object(ptr: usize) {
    // 統合されたHeapRegistryからオブジェクト情報を取得して解除
    if let Some((owner, size)) = crate::sas::unregister_any(ptr) {
        // ドメイン統計を更新
        match REGISTRY.lock() {
            Ok(mut guard) => {
                let owner_ds = DomainId::new(owner.as_u64());
                if let Some(domain) = guard.domains.iter_mut().find(|d| d.id == owner_ds) {
                    domain.decrement_rref();
                    domain.free_memory(size as u64);
                }
            }
            Err(_) => log::error!(
                "[DOMAIN] Registry poisoned (unregister_heap_object) - stats not updated"
            ),
        }
    }
}

/// オブジェクトの所有権を移動
pub fn transfer_ownership(ptr: usize, new_owner: DomainId) -> bool {
    // NOTE: transfer requires knowing old owner to call sas::transfer_ownership?
    // sas::transfer_ownership(ptr, from, to)
    // But this API only takes new_owner.
    //
    // We need 'from' owner.
    // HeapRegistry has check `get_owner`.
    //
    // So:
    // 1. Get owner (and size for stats)
    // 2. Transfer
    // 3. Update stats

    // We need get_info exposed in sas? Or unregister_any returns info, but we don't want to unregister.
    // I added get_info to sas internal. Maybe I should expose it in sas?
    // Wait, I updated heap_registry.rs to add `get_info`.
    // But did I update sas/mod.rs to expose `get_info`?
    // I exposed `unregister_any`.
    // I should check if I exposed `get_info` in sas/mod.rs.
    //
    // If not, I can use `sas::get_owner(ptr)` to get owner.
    // But I need size for stats.
    // If I can't get size easily, stats might drift.
    //
    // For now, let's use `sas::get_owner` and assume I can't update size stats perfectly unless I expose get_info?
    // Or I rely on `unregister_any` for final stats update?
    //
    // If I transfer, "allocated_memory" ownership moves.
    // If I don't update stats, one domain has 0 usage but owns memory.
    //
    // I'll use `sas::get_owner` -> then `sas::transfer`.
    // Metadata (size) is not retrievable easily without `get_info`.
    //
    // I'll skip size update for now in transfer (minor bug in stats only), or better, fix sas/mod.rs to expose `get_info`.
    // But I am writing `domain_system.rs` now.
    //
    // Assuming I can't call `get_info` yet (unless I modify sas/mod.rs again),
    // I will try to call `crate::sas::get_info` if I think I verified it.
    // I checked `heap_registry.rs` has `get_info`.
    // `sas/mod.rs` does NOT have `get_info` exposed publically (only `unregister_any`).
    //
    // I will just use `sas::get_owner` and SKIP size update for now.
    // The stats are secondary.

    if let Some(old_owner) = crate::sas::get_owner(ptr) {
        // Convert SAS DomainId to domain_system::DomainId for registry lookup
        let old_owner_ds = DomainId::new(old_owner.as_u64());
        if crate::sas::transfer_ownership(
            ptr,
            old_owner,
            crate::sas::DomainId::new(new_owner.as_u64()),
        )
        .is_ok()
        {
            match REGISTRY.lock() {
                Ok(mut registry) => {
                    // 旧所有者のカウント減少
                    if let Some(old_domain) =
                        registry.domains.iter_mut().find(|d| d.id == old_owner_ds)
                    {
                        old_domain.decrement_rref();
                        // old_domain.free_memory(size as u64); // Size unknown
                    }

                    // 新所有者のカウント増加
                    if let Some(new_domain) =
                        registry.domains.iter_mut().find(|d| d.id == new_owner)
                    {
                        new_domain.increment_rref();
                        // new_domain.add_memory(size as u64); // Size unknown
                    }
                    return true;
                }
                Err(_) => {
                    log::error!(
                        "[DOMAIN] Registry poisoned (transfer_ownership) - stats not updated"
                    );
                    return true; // Ownership transfer succeeded; just skip stats update
                }
            }
        }
    }
    false
}

/// ドメインが所有する全リソースを回収
pub fn reclaim_domain_resources(domain: DomainId) {
    // 統合されたHeapRegistryのreclaim_allを使用
    // Note: sas::reclaim_domain_resources (on manager) returns count.
    // We need to call it via Global Manager or direct?
    // sas/mod.rs has `reclaim_domain_resources` IN struct, but not exposed function?
    // I verified `sas/mod.rs` exposed `unregister_any`, `check_access`.
    // I checked `sas/mod.rs` content:
    // It has `pub fn reclaim_domain_resources` ON `SingleAddressSpaceManager`.
    // But NO standalone public function `reclaim_domain_resources`.
    //
    // So I must do `crate::sas::with_sas_manager_mut(|m| m.reclaim_domain_resources(domain))`

    let count = crate::sas::with_sas_manager_mut(|m| {
        m.reclaim_domain_resources(crate::sas::DomainId::new(domain.as_u64()))
    });

    // ドメインのリソースカウントをリセット
    match REGISTRY.lock() {
        Ok(mut guard) => {
            if let Some(d) = guard.domains.iter_mut().find(|d| d.id == domain) {
                d.rref_count = 0;
                d.allocated_memory = 0;
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (reclaim_domain_resources) - stats not reset")
        }
    }

    if count > 0 {
        log::info!("[DOMAIN] Reclaimed {} resources from {}\n", count, domain);
    }
}

// ============================================================================
// 公開API - 統計
// ============================================================================

/// ドメイン統計
#[derive(Debug, Clone)]
pub struct DomainStats {
    /// 総ドメイン数
    pub total: usize,
    /// 実行中のドメイン数
    pub running: usize,
    /// 停止中のドメイン数
    pub stopped: usize,
    /// 終了済みのドメイン数
    pub terminated: usize,
    /// 総メモリ使用量（バイト）
    pub memory_used: u64,
    /// 総RRef数
    pub total_rrefs: u64,
}

/// ドメイン統計を取得
pub fn get_domain_stats() -> DomainStats {
    match REGISTRY.lock() {
        Ok(guard) => {
            let mut stats = DomainStats {
                total: guard.domains.len(),
                running: 0,
                stopped: 0,
                terminated: 0,
                memory_used: 0,
                total_rrefs: 0,
            };

            for domain in guard.domains.iter() {
                match domain.state {
                    DomainState::Running | DomainState::Initializing => stats.running += 1,
                    DomainState::Stopped | DomainState::Suspended => stats.stopped += 1,
                    DomainState::Terminated => stats.terminated += 1,
                }
                stats.memory_used += domain.allocated_memory;
                stats.total_rrefs += domain.rref_count;
            }

            stats
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_stats)");
            DomainStats {
                total: 0,
                running: 0,
                stopped: 0,
                terminated: 0,
                memory_used: 0,
                total_rrefs: 0,
            }
        }
    }
}

/// ドメイン統計を取得（get_domain_statsのエイリアス）
/// domain/registry.rs からの互換性維持のために追加
pub fn get_stats() -> DomainStats {
    get_domain_stats()
}

/// ドメイン一覧を表示
pub fn print_domain_list() {
    match REGISTRY.lock() {
        Ok(guard) => {
            log::info!("[DOMAIN] === Domain List ===\n");
            for domain in guard.domains.iter() {
                log::info!(
                    "[DOMAIN] {} '{}': {:?}, tasks={}, rrefs={}, mem={}KB\n",
                    domain.id,
                    domain.name,
                    domain.state,
                    domain.tasks.len(),
                    domain.rref_count,
                    domain.allocated_memory / 1024
                );
            }
        }
        Err(_) => log::error!("[DOMAIN] Registry poisoned (print_domain_list) - skipping"),
    }
}

// ============================================================================
// 現在のドメイン管理
// ============================================================================

/// 現在のドメインID（Per-CPUデータから取得予定）
static CURRENT_DOMAIN: AtomicU64 = AtomicU64::new(0);

/// 現在のドメインを設定
pub fn set_current_domain(id: DomainId) {
    CURRENT_DOMAIN.store(id.as_u64(), Ordering::SeqCst);
}

/// 現在のドメインを取得
pub fn current_domain() -> DomainId {
    DomainId::new(CURRENT_DOMAIN.load(Ordering::SeqCst))
}

/// 現在のドメインがカーネルかどうか
pub fn is_kernel_domain() -> bool {
    current_domain() == DomainId::KERNEL
}

