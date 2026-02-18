// ============================================================================
// Memory Cgroup (memcg) Support
// メモリリソース制限とアカウンティングの基盤
// ============================================================================
//!
//! # Memory Cgroup Architecture
//!
//! ## 概要
//! Memory Cgroupは、プロセスグループごとにメモリ使用量を制限し追跡する機構。
//! ExoRustではドメイン単位でのリソース制限に活用。
//!
//! ## 機能
//! - メモリ使用量の追跡（RSS, Cache, Swap）
//! - ハード/ソフト制限
//! - OOMキラー優先度制御
//! - 階層的なリソース管理
//!
//! ## 階層構造
//! ```text
//! root_memcg
//!   ├── system (カーネル予約)
//!   ├── drivers (ドライバ群)
//!   └── apps (アプリケーション)
//!       ├── app1
//!       └── app2
//! ```

#![allow(dead_code)]
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

use super::types::FrameIndex;
use super::PAGE_SIZE_4K;

/// Cgroup ID型
mod _split_1;
pub use _split_1::*;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MemcgId(u64);

impl MemcgId {
    pub const ROOT: Self = Self(0);
    
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
    
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// メモリ使用量カウンタ
#[derive(Debug)]
pub struct MemcgCounter {
    /// 現在値（ページ数）
    current: AtomicU64,
    /// ピーク値
    peak: AtomicU64,
    /// フェイルカウント（制限超過回数）
    failcnt: AtomicU64,
}

impl MemcgCounter {
    pub const fn new() -> Self {
        Self {
            current: AtomicU64::new(0),
            peak: AtomicU64::new(0),
            failcnt: AtomicU64::new(0),
        }
    }
    
    /// 値を加算
    pub fn add(&self, pages: u64) {
        let new = self.current.fetch_add(pages, Ordering::Relaxed) + pages;
        // ピーク更新
        let mut peak = self.peak.load(Ordering::Relaxed);
        while new > peak {
            match self.peak.compare_exchange_weak(
                peak,
                new,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
    }
    
    /// 値を減算
    pub fn sub(&self, pages: u64) {
        self.current.fetch_sub(pages.min(self.current.load(Ordering::Relaxed)), Ordering::Relaxed);
    }
    
    /// 現在値を取得
    pub fn current(&self) -> u64 {
        self.current.load(Ordering::Relaxed)
    }
    
    /// ピーク値を取得
    pub fn peak(&self) -> u64 {
        self.peak.load(Ordering::Relaxed)
    }
    
    /// フェイルカウントを取得
    pub fn failcnt(&self) -> u64 {
        self.failcnt.load(Ordering::Relaxed)
    }
    
    /// フェイルカウントをインクリメント
    pub fn inc_failcnt(&self) {
        self.failcnt.fetch_add(1, Ordering::Relaxed);
    }
    
    /// ピークをリセット
    pub fn reset_peak(&self) {
        self.peak.store(self.current.load(Ordering::Relaxed), Ordering::Relaxed);
    }
}

/// メモリ制限設定
#[derive(Debug, Clone)]
pub struct MemcgLimit {
    /// ハード制限（ページ数、超過不可）
    pub hard_limit: u64,
    /// ソフト制限（ページ数、回収優先度に影響）
    pub soft_limit: u64,
    /// スワップ制限（ページ数）
    pub swap_limit: u64,
    /// メモリ+スワップ合計制限
    pub memsw_limit: u64,
}

impl Default for MemcgLimit {
    fn default() -> Self {
        Self {
            hard_limit: u64::MAX,
            soft_limit: u64::MAX,
            swap_limit: u64::MAX,
            memsw_limit: u64::MAX,
        }
    }
}

/// OOM制御設定
#[derive(Debug, Clone)]
pub struct OomControl {
    /// OOMキラーを無効化（OOM時にタスクを停止）
    pub oom_kill_disable: bool,
    /// OOM発生カウント
    pub oom_count: u64,
    /// 現在OOM状態か
    pub under_oom: bool,
}

impl Default for OomControl {
    fn default() -> Self {
        Self {
            oom_kill_disable: false,
            oom_count: 0,
            under_oom: false,
        }
    }
}

/// Memory Cgroup
pub struct MemCgroup {
    /// Cgroup ID
    pub id: MemcgId,
    /// 名前
    pub name: String,
    /// 親Cgroup ID（Noneならroot）
    pub parent_id: Option<MemcgId>,
    /// 子Cgroup一覧
    children: RwLock<Vec<MemcgId>>,
    /// メモリ使用量（anonymous）
    anon_counter: MemcgCounter,
    /// メモリ使用量（file cache）
    cache_counter: MemcgCounter,
    /// スワップ使用量
    swap_counter: MemcgCounter,
    /// カーネルメモリ使用量
    kmem_counter: MemcgCounter,
    /// 制限設定
    limits: RwLock<MemcgLimit>,
    /// OOM制御
    oom_control: Mutex<OomControl>,
    /// 有効フラグ
    enabled: AtomicU8,
    /// 作成タイムスタンプ
    created_tsc: u64,
}

impl MemCgroup {
    /// 新しいMemCgroupを作成
    pub fn new(id: MemcgId, name: String, parent_id: Option<MemcgId>) -> Self {
        Self {
            id,
            name,
            parent_id,
            children: RwLock::new(Vec::new()),
            anon_counter: MemcgCounter::new(),
            cache_counter: MemcgCounter::new(),
            swap_counter: MemcgCounter::new(),
            kmem_counter: MemcgCounter::new(),
            limits: RwLock::new(MemcgLimit::default()),
            oom_control: Mutex::new(OomControl::default()),
            enabled: AtomicU8::new(1),
            created_tsc: read_tsc(),
        }
    }
    
    /// 有効か確認
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Acquire) != 0
    }
    
    /// 無効化
    pub fn disable(&self) {
        self.enabled.store(0, Ordering::Release);
    }
    
    /// メモリ使用量を取得（ページ数）
    pub fn memory_usage(&self) -> u64 {
        self.anon_counter.current() + self.cache_counter.current()
    }
    
    /// 合計使用量（メモリ+スワップ）
    pub fn memsw_usage(&self) -> u64 {
        self.memory_usage() + self.swap_counter.current()
    }
    
    /// 制限内でページを割り当て可能か確認
    pub fn can_charge(&self, pages: u64, is_swap: bool) -> bool {
        let limits = self.limits.read();
        
        if is_swap {
            let new_swap = self.swap_counter.current() + pages;
            if new_swap > limits.swap_limit {
                return false;
            }
        } else {
            let new_mem = self.memory_usage() + pages;
            if new_mem > limits.hard_limit {
                return false;
            }
        }
        
        let new_memsw = self.memsw_usage() + pages;
        new_memsw <= limits.memsw_limit
    }
    
    /// ページをチャージ（使用量加算）
    pub fn charge(&self, pages: u64, charge_type: ChargeType) -> Result<(), MemcgError> {
        if !self.can_charge(pages, matches!(charge_type, ChargeType::Swap)) {
            match charge_type {
                ChargeType::Anon => self.anon_counter.inc_failcnt(),
                ChargeType::Cache => self.cache_counter.inc_failcnt(),
                ChargeType::Swap => self.swap_counter.inc_failcnt(),
                ChargeType::Kmem => self.kmem_counter.inc_failcnt(),
            }
            return Err(MemcgError::LimitExceeded);
        }
        
        match charge_type {
            ChargeType::Anon => self.anon_counter.add(pages),
            ChargeType::Cache => self.cache_counter.add(pages),
            ChargeType::Swap => self.swap_counter.add(pages),
            ChargeType::Kmem => self.kmem_counter.add(pages),
        }
        
        Ok(())
    }
    
    /// ページをアンチャージ（使用量減算）
    pub fn uncharge(&self, pages: u64, charge_type: ChargeType) {
        match charge_type {
            ChargeType::Anon => self.anon_counter.sub(pages),
            ChargeType::Cache => self.cache_counter.sub(pages),
            ChargeType::Swap => self.swap_counter.sub(pages),
            ChargeType::Kmem => self.kmem_counter.sub(pages),
        }
    }
    
    /// 制限を設定
    pub fn set_limit(&self, limit_type: LimitType, pages: u64) {
        let mut limits = self.limits.write();
        match limit_type {
            LimitType::Hard => limits.hard_limit = pages,
            LimitType::Soft => limits.soft_limit = pages,
            LimitType::Swap => limits.swap_limit = pages,
            LimitType::MemSw => limits.memsw_limit = pages,
        }
    }
    
    /// 制限を取得
    pub fn get_limit(&self, limit_type: LimitType) -> u64 {
        let limits = self.limits.read();
        match limit_type {
            LimitType::Hard => limits.hard_limit,
            LimitType::Soft => limits.soft_limit,
            LimitType::Swap => limits.swap_limit,
            LimitType::MemSw => limits.memsw_limit,
        }
    }
    
    /// ソフト制限を超過しているか
    pub fn over_soft_limit(&self) -> bool {
        let limits = self.limits.read();
        self.memory_usage() > limits.soft_limit
    }
    
    /// 統計情報を取得
    pub fn stats(&self) -> MemcgStats {
        let limits = self.limits.read();
        MemcgStats {
            id: self.id,
            anon_pages: self.anon_counter.current(),
            cache_pages: self.cache_counter.current(),
            swap_pages: self.swap_counter.current(),
            kmem_pages: self.kmem_counter.current(),
            anon_peak: self.anon_counter.peak(),
            cache_peak: self.cache_counter.peak(),
            hard_limit: limits.hard_limit,
            soft_limit: limits.soft_limit,
            failcnt: self.anon_counter.failcnt() + self.cache_counter.failcnt(),
        }
    }
    
    /// 子Cgroupを追加
    pub fn add_child(&self, child_id: MemcgId) {
        let mut children = self.children.write();
        if !children.contains(&child_id) {
            children.push(child_id);
        }
    }
    
    /// 子Cgroupを削除
    pub fn remove_child(&self, child_id: MemcgId) {
        let mut children = self.children.write();
        children.retain(|&id| id != child_id);
    }
    
    /// 子Cgroup一覧を取得
    pub fn children(&self) -> Vec<MemcgId> {
        self.children.read().clone()
    }
}

/// チャージタイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeType {
    /// Anonymous memory
    Anon,
    /// File cache
    Cache,
    /// Swap
    Swap,
    /// Kernel memory
    Kmem,
}

/// 制限タイプ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitType {
    /// ハード制限
    Hard,
    /// ソフト制限
    Soft,
    /// スワップ制限
    Swap,
    /// メモリ+スワップ制限
    MemSw,
}

/// Cgroup統計
#[derive(Debug, Clone)]
pub struct MemcgStats {
    pub id: MemcgId,
    pub anon_pages: u64,
    pub cache_pages: u64,
    pub swap_pages: u64,
    pub kmem_pages: u64,
    pub anon_peak: u64,
    pub cache_peak: u64,
    pub hard_limit: u64,
    pub soft_limit: u64,
    pub failcnt: u64,
}

impl MemcgStats {
    /// 総メモリ使用量（バイト）
    pub fn memory_bytes(&self) -> u64 {
        (self.anon_pages + self.cache_pages) * PAGE_SIZE_4K as u64
    }
    
    /// 使用率（0.0 - 1.0）
    pub fn usage_ratio(&self) -> f64 {
        if self.hard_limit == u64::MAX {
            0.0
        } else {
            (self.anon_pages + self.cache_pages) as f64 / self.hard_limit as f64
        }
    }
}

/// Memcgエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemcgError {
    /// 制限超過
    LimitExceeded,
    /// Cgroupが見つからない
    NotFound,
    /// 既に存在
    AlreadyExists,
    /// 無効な操作
    InvalidOperation,
    /// 子が存在（削除不可）
    HasChildren,
}

/// Memory Cgroup Manager
pub struct MemcgManager {
    /// Cgroup一覧（ID -> MemCgroup）
    cgroups: RwLock<BTreeMap<MemcgId, MemCgroup>>,
    /// 次のCgroup ID
    next_id: AtomicU64,
    /// 有効フラグ
    enabled: AtomicU8,
}

impl MemcgManager {
    /// 新しいManagerを作成
    pub const fn new() -> Self {
        Self {
            cgroups: RwLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1), // 0はroot予約
            enabled: AtomicU8::new(0),
        }
    }
    
    /// 初期化
    pub fn init(&self) {
        if self.enabled.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            // rootを作成
            let root = MemCgroup::new(
                MemcgId::ROOT,
                String::from("root"),
                None,
            );
            
            let mut cgroups = self.cgroups.write();
            cgroups.insert(MemcgId::ROOT, root);
            
            log::info!("[Memcg] Memory cgroup manager initialized");
        }
    }
    
    /// 新しいCgroupを作成
    pub fn create(
        &self,
        name: String,
        parent_id: MemcgId,
    ) -> Result<MemcgId, MemcgError> {
        // 親の存在確認
        {
            let cgroups = self.cgroups.read();
            if !cgroups.contains_key(&parent_id) {
                return Err(MemcgError::NotFound);
            }
        }
        
        let new_id = MemcgId::new(self.next_id.fetch_add(1, Ordering::Relaxed));
        let cgroup = MemCgroup::new(new_id, name.clone(), Some(parent_id));
        
        let mut cgroups = self.cgroups.write();
        
        // 親に子を追加
        if let Some(parent) = cgroups.get(&parent_id) {
            parent.add_child(new_id);
        }
        
        cgroups.insert(new_id, cgroup);
        
        log::debug!("[Memcg] Created cgroup '{}' (id={}) under parent {}", 
            name, new_id.as_u64(), parent_id.as_u64());
        
        Ok(new_id)
    }
    
    /// Cgroupを削除
    pub fn remove(&self, id: MemcgId) -> Result<(), MemcgError> {
        if id == MemcgId::ROOT {
            return Err(MemcgError::InvalidOperation);
        }
        
        let mut cgroups = self.cgroups.write();
        
        // 子がいないか確認
        if let Some(cg) = cgroups.get(&id) {
            if !cg.children().is_empty() {
                return Err(MemcgError::HasChildren);
            }
            
            // 親から削除
            if let Some(parent_id) = cg.parent_id {
                if let Some(parent) = cgroups.get(&parent_id) {
                    parent.remove_child(id);
                }
            }
        }
        
        cgroups.remove(&id);
        
        log::debug!("[Memcg] Removed cgroup id={}", id.as_u64());
        
        Ok(())
    }
    
    /// ページをチャージ
    pub fn charge(
        &self,
        id: MemcgId,
        pages: u64,
        charge_type: ChargeType,
    ) -> Result<(), MemcgError> {
        let cgroups = self.cgroups.read();
        
        // 階層的にチャージ（子→親の順）
        let mut current_id = Some(id);
        let mut charged_ids = Vec::new();
        
        while let Some(cid) = current_id {
            if let Some(cg) = cgroups.get(&cid) {
                if let Err(e) = cg.charge(pages, charge_type) {
                    // ロールバック
                    for rollback_id in charged_ids {
                        if let Some(rcg) = cgroups.get(&rollback_id) {
                            rcg.uncharge(pages, charge_type);
                        }
                    }
                    return Err(e);
                }
                charged_ids.push(cid);
                current_id = cg.parent_id;
            } else {
                break;
            }
        }
        
        Ok(())
    }
    
    /// ページをアンチャージ
    pub fn uncharge(&self, id: MemcgId, pages: u64, charge_type: ChargeType) {
        let cgroups = self.cgroups.read();
        
        // 階層的にアンチャージ
        let mut current_id = Some(id);
        
        while let Some(cid) = current_id {
            if let Some(cg) = cgroups.get(&cid) {
                cg.uncharge(pages, charge_type);
                current_id = cg.parent_id;
            } else {
                break;
            }
        }
    }
    
    /// 制限を設定
    pub fn set_limit(
        &self,
        id: MemcgId,
        limit_type: LimitType,
        pages: u64,
    ) -> Result<(), MemcgError> {
        let cgroups = self.cgroups.read();
        let cg = cgroups.get(&id).ok_or(MemcgError::NotFound)?;
        cg.set_limit(limit_type, pages);
        Ok(())
    }
    
    /// 統計を取得
    pub fn stats(&self, id: MemcgId) -> Option<MemcgStats> {
        let cgroups = self.cgroups.read();
        cgroups.get(&id).map(|cg| cg.stats())
    }
    
    /// ソフト制限超過Cgroup一覧を取得
    pub fn over_soft_limit_cgroups(&self) -> Vec<MemcgId> {
        let cgroups = self.cgroups.read();
        cgroups.iter()
            .filter(|(_, cg)| cg.over_soft_limit())
            .map(|(&id, _)| id)
            .collect()
    }
    
    /// 全Cgroup一覧を取得
    pub fn list_all(&self) -> Vec<MemcgId> {
        let cgroups = self.cgroups.read();
        cgroups.keys().copied().collect()
    }
    
    /// 階層構造を取得
    pub fn get_hierarchy(&self, id: MemcgId) -> Vec<MemcgId> {
        let cgroups = self.cgroups.read();
        let mut result = Vec::new();
        let mut current_id = Some(id);
        
        while let Some(cid) = current_id {
            result.push(cid);
            current_id = cgroups.get(&cid).and_then(|cg| cg.parent_id);
        }
        
        result.reverse();
        result
    }
}

/// TSC読み取り
#[inline]
fn read_tsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

// グローバルマネージャ
static MEMCG_MANAGER: MemcgManager = MemcgManager::new();

// ============================================================================
// Public API
// ============================================================================

/// Memcg機能を初期化
pub fn init_memcg() {
    MEMCG_MANAGER.init();
}

/// Cgroupを作成
pub fn memcg_create(name: String, parent_id: MemcgId) -> Result<MemcgId, MemcgError> {
    MEMCG_MANAGER.create(name, parent_id)
}

/// Cgroupを削除
pub fn memcg_remove(id: MemcgId) -> Result<(), MemcgError> {
    MEMCG_MANAGER.remove(id)
}

/// ページをチャージ
pub fn memcg_charge(id: MemcgId, pages: u64, charge_type: ChargeType) -> Result<(), MemcgError> {
    MEMCG_MANAGER.charge(id, pages, charge_type)
}

/// ページをアンチャージ
pub fn memcg_uncharge(id: MemcgId, pages: u64, charge_type: ChargeType) {
    MEMCG_MANAGER.uncharge(id, pages, charge_type)
}

/// 制限を設定
pub fn memcg_set_limit(id: MemcgId, limit_type: LimitType, pages: u64) -> Result<(), MemcgError> {
    MEMCG_MANAGER.set_limit(id, limit_type, pages)
}

/// 統計を取得
pub fn memcg_stats(id: MemcgId) -> Option<MemcgStats> {
    MEMCG_MANAGER.stats(id)
}

/// ソフト制限超過Cgroup一覧
pub fn memcg_over_soft_limit() -> Vec<MemcgId> {
    MEMCG_MANAGER.over_soft_limit_cgroups()
}

/// 全Cgroup一覧
pub fn memcg_list_all() -> Vec<MemcgId> {
    MEMCG_MANAGER.list_all()
}

/// Root CgroupのID
pub fn memcg_root() -> MemcgId {
    MemcgId::ROOT
}

// ============================================================================
// Per-Page Tracking (Optional)
// ============================================================================

/// ページごとのCgroup追跡情報
#[derive(Debug, Clone, Copy)]
pub struct PageMemcgInfo {
    /// 所属Cgroup ID
    pub memcg_id: MemcgId,
    /// チャージタイプ
    pub charge_type: ChargeType,
}

/// ページ→Cgroup マッピング（オプショナル機能）
pub struct PageMemcgTracker {
    /// ページ→Cgroup マッピング
    mapping: RwLock<BTreeMap<FrameIndex, PageMemcgInfo>>,
}
