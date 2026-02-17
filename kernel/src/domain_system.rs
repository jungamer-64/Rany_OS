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
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::sync::atomic::{AtomicU64, Ordering};
// 【設計書 8.1】PoisonLock使用 - パニック時自動毒入れ
use crate::error::{DomainErrorKind, KernelError};
use crate::security::CapabilitySet;
use crate::sync::PoisonLock;
use spin::Once;

// ============================================================================
// ドメインID
// ============================================================================

/// ドメインを一意に識別するID
mod _split_1;
use _split_1::*;
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
// ドメインセキュリティ
// ============================================================================

/// ドメイン主体の資格情報
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainCredentials {
    pub uid: u32,
    pub gid: u32,
}

impl DomainCredentials {
    pub const ROOT: Self = Self { uid: 0, gid: 0 };

    pub const fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

/// ドメイン主体の権限情報
#[derive(Debug, Clone)]
pub struct DomainSecurity {
    pub credentials: DomainCredentials,
    pub caps: CapabilitySet,
}

impl DomainSecurity {
    pub fn kernel() -> Self {
        Self {
            credentials: DomainCredentials::ROOT,
            caps: CapabilitySet::full(),
        }
    }
}

impl Default for DomainSecurity {
    fn default() -> Self {
        Self {
            credentials: DomainCredentials::ROOT,
            caps: CapabilitySet::empty(),
        }
    }
}

fn kernel_security_handle() -> Arc<DomainSecurity> {
    static KERNEL_SECURITY: Once<Arc<DomainSecurity>> = Once::new();
    KERNEL_SECURITY
        .call_once(|| Arc::new(DomainSecurity::kernel()))
        .clone()
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
    /// セキュリティ主体（資格情報/ケイパビリティ）
    pub security: Arc<DomainSecurity>,

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

/// Domain summary snapshot for external queries
#[derive(Debug, Clone)]
pub struct DomainSnapshot {
    pub id: DomainId,
    pub name: String,
    pub state: DomainState,
    pub tasks: usize,
    pub task_ids: Vec<u64>,
    pub memory_bytes: u64,
    pub rrefs: u64,
    pub runtime_ticks: u64,
    pub context_switches: u64,
    pub created_at: u64,
    pub dependencies: Vec<DomainId>,
    pub dependents: Vec<DomainId>,
    pub numa_node: Option<usize>,
    pub panic_message: Option<String>,
    pub last_error: Option<String>,
}

impl Domain {
    /// 新しいドメインを作成
    pub fn new(id: DomainId, name: String) -> Self {
        let security = if id == DomainId::KERNEL {
            kernel_security_handle()
        } else {
            Arc::new(DomainSecurity::default())
        };

        Self {
            id,
            name,
            state: DomainState::Initializing,
            security,
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

/// ドメインのセキュリティハンドルを取得
pub fn domain_security_handle(id: DomainId) -> Arc<DomainSecurity> {
    match REGISTRY.lock() {
        Ok(guard) => guard
            .domains
            .iter()
            .find(|d| d.id == id)
            .map(|d| d.security.clone())
            .unwrap_or_else(kernel_security_handle),
        Err(_) => kernel_security_handle(),
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

/// Create a lightweight snapshot of a domain for external queries.
fn to_snapshot(domain: &Domain) -> DomainSnapshot {
    DomainSnapshot {
        id: domain.id,
        name: domain.name.clone(),
        state: domain.state,
        tasks: domain.tasks.len(),
        task_ids: domain.tasks.clone(),
        memory_bytes: domain.allocated_memory,
        rrefs: domain.rref_count,
        runtime_ticks: domain.runtime_ticks,
        context_switches: domain.context_switches,
        created_at: domain.created_at,
        dependencies: domain.dependencies.clone(),
        dependents: domain.dependents.clone(),
        numa_node: domain.numa_node,
        panic_message: domain.panic_message.clone(),
        last_error: domain.last_error.clone(),
    }
}

/// List all domain snapshots.
pub fn list_domain_snapshots() -> Vec<DomainSnapshot> {
    match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().map(to_snapshot).collect(),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (list_domain_snapshots)");
            Vec::new()
        }
    }
}

/// Get a single domain snapshot by ID.
pub fn get_domain_snapshot(id: DomainId) -> Option<DomainSnapshot> {
    match REGISTRY.lock() {
        Ok(guard) => guard.domains.iter().find(|d| d.id == id).map(to_snapshot),
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (get_domain_snapshot)");
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
mod tests;

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

/// Resume a stopped or suspended domain
pub fn resume_domain(id: DomainId) -> Result<(), &'static str> {
    match REGISTRY.lock() {
        Ok(mut registry) => {
            if let Some(domain) = registry.domains.iter_mut().find(|d| d.id == id) {
                match domain.state {
                    DomainState::Stopped | DomainState::Suspended => {
                        domain.state = DomainState::Running;
                        log::info!("[DOMAIN] Resumed {}\n", id);
                        Ok(())
                    }
                    DomainState::Running | DomainState::Initializing => Ok(()),
                    DomainState::Terminated => Err("Domain is terminated"),
                }
            } else {
                Err("Domain not found")
            }
        }
        Err(_) => {
            log::error!("[DOMAIN] Registry poisoned (resume_domain)");
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
