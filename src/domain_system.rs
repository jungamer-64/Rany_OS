// ============================================================================
// src/domain_system.rs - 統合ドメイン管理システム
// 設計書 3.1: 「セル (Cell)」モデルによるモジュール化
// 設計書 8.2: RedLeafの知見：交換可能な型とプロキシ
//
// domain/ と ipc/ の機能を統合し、一貫したドメイン管理を提供
// ============================================================================
#![allow(dead_code)]

use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use alloc::format;
use core::sync::atomic::{AtomicU64, Ordering};
use core::ptr::NonNull;
use core::alloc::Layout;
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
// ヒープレジストリ（RRef追跡）- sas/heap_registryの統合版を使用
// ============================================================================

// NOTE: domain_systemレベルのHeapEntryは簡易追跡用
// 完全版はsas/heap_registryを使用

/// ヒープエントリ（簡易版）
#[derive(Debug, Clone, Copy)]
struct HeapEntry {
    ptr: usize,
    layout: Layout,
    owner: DomainId,
}

/// ドメインレベルのヒープ追跡（簡易版）
/// 注: より高度な追跡（型安全、世代管理、参照カウント）は
/// sas::heap_registry::HeapRegistry を使用すること
struct HeapRegistry {
    entries: BTreeMap<usize, HeapEntry>,
}

impl HeapRegistry {
    const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }
    
    /// エントリを登録
    fn register(&mut self, ptr: usize, layout: Layout, owner: DomainId) {
        self.entries.insert(ptr, HeapEntry { ptr, layout, owner });
    }
    
    /// エントリを削除
    fn unregister(&mut self, ptr: usize) -> Option<HeapEntry> {
        self.entries.remove(&ptr)
    }
    
    /// 所有者を変更
    fn change_owner(&mut self, ptr: usize, new_owner: DomainId) -> bool {
        if let Some(entry) = self.entries.get_mut(&ptr) {
            entry.owner = new_owner;
            true
        } else {
            false
        }
    }
    
    /// 特定ドメインの全エントリを取得
    fn get_owned_by(&self, domain: DomainId) -> Vec<HeapEntry> {
        self.entries
            .values()
            .filter(|e| e.owner == domain)
            .cloned()
            .collect()
    }
}

/// グローバルなヒープレジストリ
static HEAP_REGISTRY: Mutex<HeapRegistry> = Mutex::new(HeapRegistry::new());

// ============================================================================
// 公開API - ドメイン管理
// ============================================================================

/// ドメインシステムを初期化（カーネルドメインを作成）
pub fn init() {
    let mut registry = REGISTRY.lock();
    
    // カーネルドメインを作成
    let mut kernel = Domain::new(DomainId::KERNEL, "kernel".into());
    kernel.state = DomainState::Running;
    registry.domains.insert(DomainId::KERNEL, kernel);
    
    crate::log!("[DOMAIN] Domain system initialized (kernel domain created)\n");
}

/// 新しいドメインを作成
pub fn create_domain(name: String) -> DomainId {
    let mut registry = REGISTRY.lock();
    let id = registry.generate_id();
    let domain = Domain::new(id, name.clone());
    registry.domains.insert(id, domain);
    
    crate::log!("[DOMAIN] Created domain {} ({})\n", id.as_u64(), name);
    id
}

/// ドメインの状態を取得
pub fn get_domain_state(id: DomainId) -> Option<DomainState> {
    REGISTRY.lock().domains.get(&id).map(|d| d.state)
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
    
    let dependents: Vec<DomainId>;
    
    {
        let mut registry = REGISTRY.lock();
        
        if let Some(domain) = registry.domains.get_mut(&id) {
            domain.state = DomainState::Terminated;
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
    HEAP_REGISTRY.lock().register(ptr, layout, owner);
    
    if let Some(domain) = REGISTRY.lock().domains.get_mut(&owner) {
        domain.increment_rref();
        domain.add_memory(layout.size() as u64);
    }
}

/// Exchange Heap上のオブジェクトを解除
pub fn unregister_heap_object(ptr: usize) {
    if let Some(entry) = HEAP_REGISTRY.lock().unregister(ptr) {
        if let Some(domain) = REGISTRY.lock().domains.get_mut(&entry.owner) {
            domain.decrement_rref();
            domain.free_memory(entry.layout.size() as u64);
        }
    }
}

/// オブジェクトの所有権を移動
pub fn transfer_ownership(ptr: usize, new_owner: DomainId) -> bool {
    let entry_opt = {
        let heap_registry = HEAP_REGISTRY.lock();
        heap_registry.entries.get(&ptr).map(|e| (e.owner, e.layout))
    };
    
    if let Some((old_owner, layout)) = entry_opt {
        // 所有者変更
        HEAP_REGISTRY.lock().change_owner(ptr, new_owner);
        
        let mut registry = REGISTRY.lock();
        
        // 旧所有者のカウント減少
        if let Some(old_domain) = registry.domains.get_mut(&old_owner) {
            old_domain.decrement_rref();
            old_domain.free_memory(layout.size() as u64);
        }
        
        // 新所有者のカウント増加
        if let Some(new_domain) = registry.domains.get_mut(&new_owner) {
            new_domain.increment_rref();
            new_domain.add_memory(layout.size() as u64);
        }
        
        true
    } else {
        false
    }
}

/// ドメインが所有する全リソースを回収
pub fn reclaim_domain_resources(domain: DomainId) {
    let entries = HEAP_REGISTRY.lock().get_owned_by(domain);
    let count = entries.len();
    
    for entry in entries {
        // Exchange Heapから解放
        unsafe {
            crate::mm::exchange_heap::deallocate_raw(
                NonNull::new_unchecked(entry.ptr as *mut u8),
                entry.layout,
            );
        }
        HEAP_REGISTRY.lock().unregister(entry.ptr);
    }
    
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

/// ドメイン一覧を表示
pub fn print_domain_list() {
    let registry = REGISTRY.lock();
    
    crate::log!("[DOMAIN] === Domain List ===\n");
    for domain in registry.domains.values() {
        crate::log!("[DOMAIN] {} '{}': {:?}, tasks={}, rrefs={}, mem={}KB\n",
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
