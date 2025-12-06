// ============================================================================
// src/domain_system.rs - 統合ドメイン管理システム
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 8.2: RedLeafの知見：交換可能な型とプロキシ
//
// domain/ と ipc/ の機能を統合し、一貫したドメイン管理を提供
// ============================================================================
#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::alloc::Layout;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

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
            created_at: crate::task::current_tick(),
            panic_message: None,
            last_error: None,
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

    /// メモリ使用量を減少
    pub fn free_memory(&mut self, size: u64) {
        self.allocated_memory = self.allocated_memory.saturating_sub(size);
    }
}

// ============================================================================
// ドメインレジストリ
// ============================================================================

/// ドメインレジストリ
struct DomainRegistry {
    /// 全ドメインのマップ
    domains: BTreeMap<DomainId, Domain>,
    /// 次のドメインID
    next_id: AtomicU64,
}

impl DomainRegistry {
    /// 新しいレジストリを作成
    const fn new() -> Self {
        Self {
            domains: BTreeMap::new(),
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
static REGISTRY: Mutex<DomainRegistry> = Mutex::new(DomainRegistry::new());

// ============================================================================
// ヒープレジストリ（RRef追跡）
// P3完了: sas::heap_registry::HeapRegistry を統合実装として使用
// 
// 役割分担:
// - sas::heap_registry::HeapRegistry: 完全な所有権追跡（型安全、世代管理、参照カウント）
// - domain_system.rs: ドメインレベルの統計情報（メモリ量・RRef数）のみ管理
// ============================================================================

use crate::sas::heap_registry::HeapRegistry as SasHeapRegistry;

/// グローバルなヒープレジストリ
/// sas::heap_registry::HeapRegistry の完全実装を使用
static HEAP_REGISTRY: Mutex<SasHeapRegistry> = Mutex::new(SasHeapRegistry::new());

// ============================================================================
// 公開API - ドメイン管理
// ============================================================================

/// ドメインシステムを初期化（カーネルドメインを作成）
pub fn init() {
    crate::vga::early_serial_str("[DOM] lock\n");
    let mut registry = REGISTRY.lock();
    crate::vga::early_serial_str("[DOM] locked\n");

    // カーネルドメインを作成
    let mut kernel = Domain::new(DomainId::KERNEL, "kernel".into());
    crate::vga::early_serial_str("[DOM] new done\n");
    kernel.state = DomainState::Running;
    crate::vga::early_serial_str("[DOM] insert\n");
    registry.domains.insert(DomainId::KERNEL, kernel);
    crate::vga::early_serial_str("[DOM] done\n");
}

/// 新しいドメインを作成
///
/// # パフォーマンス注意
/// `name.clone()` は `crate::log!` マクロで使用するために必要。
/// ドメイン作成は頻繁に呼ばれないため、このコストは許容される。
/// 代替案: log を先に行い、name を消費するパターン
pub fn create_domain(name: String) -> DomainId {
    let mut registry = REGISTRY.lock();
    let id = registry.generate_id();

    // name をログで先に使用し、その後 Domain::new に渡す
    // これにより clone() を回避
    crate::log!("[DOMAIN] Created domain {} ({})\n", id.as_u64(), &name);

    let domain = Domain::new(id, name);
    registry.domains.insert(id, domain);

    id
}

/// ドメインの状態を取得
pub fn get_domain_state(id: DomainId) -> Option<DomainState> {
    REGISTRY.lock().domains.get(&id).map(|d| d.state)
}

/// ドメインに対して読み取り操作を実行
/// domain/registry.rs からの互換性維持のために追加
pub fn with_domain<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&Domain) -> R,
{
    REGISTRY.lock().domains.get(&id).map(f)
}

/// ドメインに対して更新操作を実行
/// domain/registry.rs からの互換性維持のために追加
pub fn with_domain_mut<F, R>(id: DomainId, f: F) -> Option<R>
where
    F: FnOnce(&mut Domain) -> R,
{
    REGISTRY.lock().domains.get_mut(&id).map(f)
}

/// ドメインの状態を変更
pub fn set_domain_state(id: DomainId, state: DomainState) {
    if let Some(domain) = REGISTRY.lock().domains.get_mut(&id) {
        let old_state = domain.state;
        domain.state = state;
        crate::log!("[DOMAIN] {} state: {:?} -> {:?}\n", id, old_state, state);
    }
}

/// ドメインを開始
pub fn start_domain(id: DomainId) -> Result<(), &'static str> {
    let mut registry = REGISTRY.lock();

    if let Some(domain) = registry.domains.get_mut(&id) {
        if domain.state != DomainState::Initializing {
            return Err("Domain is not in initializing state");
        }
        domain.state = DomainState::Running;
        crate::log!("[DOMAIN] Started {}\n", id);
        Ok(())
    } else {
        Err("Domain not found")
    }
}

/// ドメインを停止
pub fn stop_domain(id: DomainId) -> Result<(), &'static str> {
    if id == DomainId::KERNEL {
        return Err("Cannot stop kernel domain");
    }

    let mut registry = REGISTRY.lock();

    if let Some(domain) = registry.domains.get_mut(&id) {
        domain.state = DomainState::Stopped;
        crate::log!("[DOMAIN] Stopped {}\n", id);
        Ok(())
    } else {
        Err("Domain not found")
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
        let mut registry = REGISTRY.lock();

        if let Some(domain) = registry.domains.get_mut(&id) {
            domain.state = DomainState::Terminated;
            // clone() はロックを保持したままの処理を避けるため
            // デッドロック回避が clone のコストより重要
            dependents = domain.dependents.clone();
        } else {
            return Err("Domain not found");
        }
    }

    // リソース回収（ロックを解放してから）
    reclaim_domain_resources(id);

    // 依存するドメインに通知
    {
        let mut registry = REGISTRY.lock();
        for dep_id in dependents {
            if let Some(dep) = registry.domains.get_mut(&dep_id) {
                dep.last_error = Some(format!("Dependency {} terminated", id.as_u64()));
            }
        }
    }

    crate::log!("[DOMAIN] Terminated {} and reclaimed resources\n", id);
    Ok(())
}

/// ドメインがパニックした場合の処理
pub fn handle_domain_panic(id: DomainId, message: String) {
    crate::log!("[PANIC] {} crashed: {}\n", id, message);

    {
        let mut registry = REGISTRY.lock();

        if let Some(domain) = registry.domains.get_mut(&id) {
            domain.state = DomainState::Stopped;
            domain.panic_message = Some(message);
        }
    }

    // リソース回収
    reclaim_domain_resources(id);
}

/// ドメインにタスクを追加
pub fn add_task_to_domain(domain_id: DomainId, task_id: u64) {
    if let Some(domain) = REGISTRY.lock().domains.get_mut(&domain_id) {
        domain.add_task(task_id);
    }
}

/// ドメインからタスクを削除
pub fn remove_task_from_domain(domain_id: DomainId, task_id: u64) {
    if let Some(domain) = REGISTRY.lock().domains.get_mut(&domain_id) {
        domain.remove_task(task_id);
    }
}

// ============================================================================
// 公開API - リソース管理
// ============================================================================

/// Exchange Heap上にオブジェクトを登録
pub fn register_heap_object(ptr: usize, layout: Layout, owner: DomainId) {
    // 統合されたHeapRegistryに登録（簡易版APIを使用）
    HEAP_REGISTRY.lock().register_simple(ptr, layout.size(), owner);

    if let Some(domain) = REGISTRY.lock().domains.get_mut(&owner) {
        domain.increment_rref();
        domain.add_memory(layout.size() as u64);
    }
}

/// Exchange Heap上のオブジェクトを解除
pub fn unregister_heap_object(ptr: usize) {
    // 統合されたHeapRegistryからオブジェクト情報を取得
    let mut heap_registry = HEAP_REGISTRY.lock();
    if let Some(obj) = heap_registry.get_object(ptr) {
        let owner = obj.owner;
        let size = obj.size;
        
        // 登録解除（簡易版APIを使用）
        heap_registry.unregister_simple(ptr);
        drop(heap_registry); // ロックを解放
        
        // ドメイン統計を更新
        if let Some(domain) = REGISTRY.lock().domains.get_mut(&owner) {
            domain.decrement_rref();
            domain.free_memory(size as u64);
        }
    }
}

/// オブジェクトの所有権を移動
pub fn transfer_ownership(ptr: usize, new_owner: DomainId) -> bool {
    // 統合されたHeapRegistryからオブジェクト情報を取得
    let mut heap_registry = HEAP_REGISTRY.lock();
    let entry_opt = heap_registry.get_object(ptr).map(|obj| (obj.owner, obj.size));

    if let Some((old_owner, size)) = entry_opt {
        // 所有者変更（統合されたAPIを使用）
        let _ = heap_registry.change_owner(ptr, old_owner, new_owner);
        drop(heap_registry); // ロックを解放

        let mut registry = REGISTRY.lock();

        // 旧所有者のカウント減少
        if let Some(old_domain) = registry.domains.get_mut(&old_owner) {
            old_domain.decrement_rref();
            old_domain.free_memory(size as u64);
        }

        // 新所有者のカウント増加
        if let Some(new_domain) = registry.domains.get_mut(&new_owner) {
            new_domain.increment_rref();
            new_domain.add_memory(size as u64);
        }

        true
    } else {
        drop(heap_registry); // ロックを解放
        false
    }
}

/// ドメインが所有する全リソースを回収
pub fn reclaim_domain_resources(domain: DomainId) {
    // 統合されたHeapRegistryのreclaim_allを使用
    let mut heap_registry = HEAP_REGISTRY.lock();
    
    // ドメインのオブジェクトアドレスを取得
    let addrs: Vec<usize> = heap_registry
        .get_domain_objects(domain)
        .map(|v| v.clone())
        .unwrap_or_default();
    let count = addrs.len();
    
    // 各オブジェクトを回収
    for addr in &addrs {
        if let Some(obj) = heap_registry.get_object(*addr) {
            let size = obj.size;
            // Exchange Heapから解放
            unsafe {
                let layout = Layout::from_size_align_unchecked(size, 8);
                crate::mm::exchange_heap::deallocate_raw(
                    NonNull::new_unchecked(*addr as *mut u8),
                    layout,
                );
            }
        }
    }
    
    // HeapRegistryから一括削除
    let _ = heap_registry.reclaim_all(domain);
    drop(heap_registry); // ロックを解放

    // ドメインのリソースカウントをリセット
    if let Some(domain) = REGISTRY.lock().domains.get_mut(&domain) {
        domain.rref_count = 0;
        domain.allocated_memory = 0;
    }

    if count > 0 {
        crate::log!("[DOMAIN] Reclaimed {} resources from {}\n", count, domain);
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
    let registry = REGISTRY.lock();

    let mut stats = DomainStats {
        total: registry.domains.len(),
        running: 0,
        stopped: 0,
        terminated: 0,
        memory_used: 0,
        total_rrefs: 0,
    };

    for domain in registry.domains.values() {
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

/// ドメイン統計を取得（get_domain_statsのエイリアス）
/// domain/registry.rs からの互換性維持のために追加
pub fn get_stats() -> DomainStats {
    get_domain_stats()
}

/// ドメイン一覧を表示
pub fn print_domain_list() {
    let registry = REGISTRY.lock();

    crate::log!("[DOMAIN] === Domain List ===\n");
    for domain in registry.domains.values() {
        crate::log!(
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
