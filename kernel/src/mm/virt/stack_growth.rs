// ============================================================================
// src/mm/stack_growth.rs - Automatic Stack Growth
//
// ## 概要
//
// 自動スタック拡張の実装。ユーザースタックがガードページに到達した際に、
// 自動的にスタックを拡張してスタックオーバーフローを防止する。
//
// ## 設計
//
// 1. **ガードページ**: スタック下限にマッピングなしのページを配置
// 2. **フォルト検出**: ガードページへのアクセスでページフォルト発生
// 3. **スタック拡張**: 新しいページを割り当ててスタックを拡張
// 4. **制限管理**: スタックサイズ上限を超える拡張を防止
//
// ## セキュリティ
//
// - スタック領域外へのアクセスは即座にSIGSEGV
// - ulimit相当のスタックサイズ制限
// - ガードページギャップ（複数ページ）でバッファオーバーランを検出
//
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use alloc::collections::BTreeMap;
use spin::RwLock;

use super::higher_half::{PageFlags, MapError, VirtAddr};
use crate::mm::meta::memcg::ChargeType; // for memcg page charges
use crate::mm::reclaim::page_reclaim::PageType as LruPageType;
use super::fault_handler::PageSetup;

// ============================================================================
// Constants
// ============================================================================

/// デフォルトスタックサイズ（8MB）
pub const DEFAULT_STACK_SIZE: u64 = 8 * 1024 * 1024;

/// 最小スタックサイズ（64KB）
pub const MIN_STACK_SIZE: u64 = 64 * 1024;

/// 最大スタックサイズ（128MB）
pub const MAX_STACK_SIZE: u64 = 128 * 1024 * 1024;

/// ガードページ数（スタック下限のアンマップページ数）
pub const GUARD_PAGE_COUNT: u64 = 4;

/// ガードページサイズ
pub const GUARD_SIZE: u64 = GUARD_PAGE_COUNT * 4096;

/// スタック拡張時の追加ページ数
pub const GROWTH_PAGES: u64 = 16;

// ============================================================================
// Stack Region
// ============================================================================

/// スタック領域情報
#[derive(Debug, Clone)]
pub struct StackRegion {
    /// スタックトップ（最高アドレス、固定）
    pub stack_top: VirtAddr,
    /// 現在のスタックボトム（マッピング済み最低アドレス）
    pub current_bottom: VirtAddr,
    /// スタックサイズ上限
    pub max_size: u64,
    /// ガードページ下限（絶対的な限界）
    pub guard_bottom: VirtAddr,
    /// 使用中のページ数
    pub pages_used: u64,
    /// 最大拡張回数
    pub growth_count: u64,
}

impl StackRegion {
    /// 新しいスタック領域を作成
    pub fn new(stack_top: VirtAddr, initial_size: u64, max_size: u64) -> Self {
        let stack_top_aligned = VirtAddr::new(stack_top.as_u64() & !0xFFF);
        let initial_bottom = VirtAddr::new(stack_top_aligned.as_u64() - initial_size);
        let guard_bottom = VirtAddr::new(stack_top_aligned.as_u64() - max_size - GUARD_SIZE);
        
        Self {
            stack_top: stack_top_aligned,
            current_bottom: initial_bottom,
            max_size,
            guard_bottom,
            pages_used: initial_size / 4096,
            growth_count: 0,
        }
    }
    
    /// アドレスがスタック領域内か
    #[inline]
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.current_bottom && addr < self.stack_top
    }
    
    /// アドレスがガードページ領域か
    #[inline]
    pub fn is_in_guard(&self, addr: VirtAddr) -> bool {
        addr >= self.guard_bottom && addr < self.current_bottom
    }
    
    /// アドレスがスタック拡張可能な領域か
    #[inline]
    pub fn can_grow_to(&self, addr: VirtAddr) -> bool {
        // ガードページより下は拡張不可
        if addr < self.guard_bottom {
            return false;
        }
        
        // 現在のボトムより下（かつガードより上）なら拡張可能
        addr < self.current_bottom
    }
    
    /// 現在のスタックサイズ
    #[inline]
    pub fn current_size(&self) -> u64 {
        self.stack_top.as_u64() - self.current_bottom.as_u64()
    }
    
    /// 残り拡張可能サイズ
    #[inline]
    pub fn remaining_growth(&self) -> u64 {
        self.current_bottom.as_u64().saturating_sub(self.guard_bottom.as_u64() + GUARD_SIZE)
    }
}

// ============================================================================
// Stack Manager
// ============================================================================

/// スタック管理マネージャ
pub struct StackManager {
    /// タスクID → スタック領域
    stacks: BTreeMap<u64, StackRegion>,
}

impl StackManager {
    pub const fn new() -> Self {
        Self {
            stacks: BTreeMap::new(),
        }
    }
    
    /// スタック領域を登録
    pub fn register(&mut self, task_id: u64, stack: StackRegion) {
        self.stacks.insert(task_id, stack);
        STACK_STATS.stacks_registered.fetch_add(1, Ordering::Relaxed);
    }
    
    /// スタック領域を取得
    pub fn get(&self, task_id: u64) -> Option<&StackRegion> {
        self.stacks.get(&task_id)
    }
    
    /// スタック領域を取得（可変）
    pub fn get_mut(&mut self, task_id: u64) -> Option<&mut StackRegion> {
        self.stacks.get_mut(&task_id)
    }
    
    /// スタック領域を削除
    pub fn remove(&mut self, task_id: u64) -> Option<StackRegion> {
        STACK_STATS.stacks_removed.fetch_add(1, Ordering::Relaxed);
        self.stacks.remove(&task_id)
    }
    
    /// アドレスに対応するスタックを検索
    pub fn find_for_addr(&self, addr: VirtAddr) -> Option<(u64, &StackRegion)> {
        for (task_id, stack) in &self.stacks {
            if stack.contains(addr) || stack.can_grow_to(addr) {
                return Some((*task_id, stack));
            }
        }
        None
    }
}

static STACK_MANAGER: RwLock<StackManager> = RwLock::new(StackManager::new());

// ============================================================================
// Statistics
// ============================================================================

/// スタック管理統計
pub struct StackStats {
    /// 登録されたスタック数
    pub stacks_registered: AtomicU64,
    /// 削除されたスタック数
    pub stacks_removed: AtomicU64,
    /// スタック拡張回数
    pub growths: AtomicU64,
    /// 拡張されたページ数
    pub pages_grown: AtomicU64,
    /// スタックオーバーフロー回数
    pub overflows: AtomicU64,
    /// ガードページヒット回数
    pub guard_hits: AtomicU64,
}

impl StackStats {
    pub const fn new() -> Self {
        Self {
            stacks_registered: AtomicU64::new(0),
            stacks_removed: AtomicU64::new(0),
            growths: AtomicU64::new(0),
            pages_grown: AtomicU64::new(0),
            overflows: AtomicU64::new(0),
            guard_hits: AtomicU64::new(0),
        }
    }
}

static STACK_STATS: StackStats = StackStats::new();

// ============================================================================
// Stack Growth Result
// ============================================================================

/// スタック拡張の結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StackResult {
    /// 成功
    Ok,
    /// スタックオーバーフロー（上限超過）
    Overflow,
    /// ガードページ違反
    GuardViolation,
    /// スタックが見つからない
    NotFound,
    /// メモリ不足
    OutOfMemory,
    /// アドレスがスタック領域外
    OutOfRange,
}

// ============================================================================
// Core Stack Growth Functions
// ============================================================================

/// スタック拡張フォルト処理
///
/// ページフォルトハンドラから呼び出される。
/// フォルトアドレスがスタック拡張可能な範囲であれば、スタックを拡張する。
pub fn handle_stack_fault(task_id: u64, fault_addr: VirtAddr) -> StackResult {
    let page_addr = VirtAddr::new(fault_addr.as_u64() & !0xFFF);
    
    let mut manager = STACK_MANAGER.write();
    let stack = match manager.get_mut(task_id) {
        Some(s) => s,
        None => return StackResult::NotFound,
    };
    
    // 既にスタック範囲内ならDemand Paging
    if stack.contains(page_addr) {
        return grow_single_page(page_addr);
    }
    
    // ガードページへのアクセス
    if stack.is_in_guard(page_addr) {
        STACK_STATS.guard_hits.fetch_add(1, Ordering::Relaxed);
        
        // ガードより上なら拡張を試みる
        if stack.can_grow_to(page_addr) {
            return grow_stack_to(stack, page_addr);
        }
        
        // ガード最下部への直接アクセスはオーバーフロー
        STACK_STATS.overflows.fetch_add(1, Ordering::Relaxed);
        return StackResult::Overflow;
    }
    
    // スタック拡張可能領域へのアクセス
    if stack.can_grow_to(page_addr) {
        return grow_stack_to(stack, page_addr);
    }
    
    StackResult::OutOfRange
}

/// スタックを指定アドレスまで拡張
fn grow_stack_to(stack: &mut StackRegion, target_addr: VirtAddr) -> StackResult {
    let target_page = VirtAddr::new(target_addr.as_u64() & !0xFFF);
    
    // 現在のボトムからターゲットまでのページ数を計算
    let pages_needed = (stack.current_bottom.as_u64() - target_page.as_u64()) / 4096;
    
    // 追加で余裕を持って拡張
    let pages_to_grow = pages_needed.max(GROWTH_PAGES);
    let new_bottom = VirtAddr::new(stack.current_bottom.as_u64() - pages_to_grow * 4096);
    
    // ガード領域を侵害しないようにクリップ
    let new_bottom = if new_bottom < VirtAddr::new(stack.guard_bottom.as_u64() + GUARD_SIZE) {
        VirtAddr::new(stack.guard_bottom.as_u64() + GUARD_SIZE)
    } else {
        new_bottom
    };
    
    // 各ページを割り当て
    let mut addr = stack.current_bottom.as_u64() - 4096;
    let mut pages_grown = 0u64;
    
    while addr >= new_bottom.as_u64() {
        let result = grow_single_page(VirtAddr::new(addr));
        match result {
            StackResult::Ok => {
                pages_grown += 1;
            }
            StackResult::OutOfMemory => {
                // 一部でも成功していれば続行
                if pages_grown > 0 {
                    break;
                }
                return StackResult::OutOfMemory;
            }
            _ => break,
        }
        addr -= 4096;
    }
    
    // スタック情報を更新
    stack.current_bottom = VirtAddr::new(stack.current_bottom.as_u64() - pages_grown * 4096);
    stack.pages_used += pages_grown;
    stack.growth_count += 1;
    
    STACK_STATS.growths.fetch_add(1, Ordering::Relaxed);
    STACK_STATS.pages_grown.fetch_add(pages_grown, Ordering::Relaxed);
    
    // ターゲットアドレスがカバーされているか確認
    if target_page >= stack.current_bottom {
        StackResult::Ok
    } else {
        // まだ足りない場合はオーバーフロー
        STACK_STATS.overflows.fetch_add(1, Ordering::Relaxed);
        StackResult::Overflow
    }
}

/// 単一ページを割り当て
fn grow_single_page(page_addr: VirtAddr) -> StackResult {
    let memcg_id = crate::task::process::get_current_process_memcg_id();

    let setup = match PageSetup::allocate(Some(memcg_id), ChargeType::Anon) {
        Some(s) => s,
        None => return StackResult::OutOfMemory,
    };

    let flags = PageFlags::new(PageFlags::PRESENT | PageFlags::WRITABLE | PageFlags::USER);

    match unsafe { setup.map_and_track(page_addr, flags, LruPageType::Anonymous) } {
        Ok(()) => StackResult::Ok,
        Err(MapError::AlreadyMapped) => StackResult::Ok,
        Err(_) => StackResult::OutOfMemory,
    }
}

// ============================================================================
// Stack Management API
// ============================================================================

/// スタックを作成・登録
pub fn create_stack(task_id: u64, stack_top: VirtAddr, initial_size: u64, max_size: u64) -> StackResult {
    let max_size = max_size.clamp(MIN_STACK_SIZE, MAX_STACK_SIZE);
    let initial_size = initial_size.clamp(MIN_STACK_SIZE, max_size);
    
    let stack = StackRegion::new(stack_top, initial_size, max_size);
    
    // 初期ページをマッピング
    let mut addr = stack.current_bottom.as_u64();
    while addr < stack.stack_top.as_u64() {
        let result = grow_single_page(VirtAddr::new(addr));
        if result != StackResult::Ok {
            // クリーンアップ
            // TODO: 既にマッピングしたページをアンマップ
            return result;
        }
        addr += 4096;
    }
    
    STACK_MANAGER.write().register(task_id, stack);
    
    StackResult::Ok
}

/// スタックサイズ上限を変更
pub fn set_stack_limit(task_id: u64, new_limit: u64) -> StackResult {
    let new_limit = new_limit.clamp(MIN_STACK_SIZE, MAX_STACK_SIZE);
    
    let mut manager = STACK_MANAGER.write();
    if let Some(stack) = manager.get_mut(task_id) {
        // 現在のサイズより小さくはできない
        if new_limit < stack.current_size() {
            return StackResult::Overflow;
        }
        
        stack.max_size = new_limit;
        stack.guard_bottom = VirtAddr::new(stack.stack_top.as_u64() - new_limit - GUARD_SIZE);
        
        StackResult::Ok
    } else {
        StackResult::NotFound
    }
}

/// スタック情報を取得
pub fn get_stack_info(task_id: u64) -> Option<StackInfo> {
    let manager = STACK_MANAGER.read();
    manager.get(task_id).map(|s| StackInfo {
        stack_top: s.stack_top,
        current_bottom: s.current_bottom,
        guard_bottom: s.guard_bottom,
        current_size: s.current_size(),
        max_size: s.max_size,
        pages_used: s.pages_used,
        growth_count: s.growth_count,
        remaining_growth: s.remaining_growth(),
    })
}

/// スタック情報
#[derive(Debug, Clone, Copy)]
pub struct StackInfo {
    pub stack_top: VirtAddr,
    pub current_bottom: VirtAddr,
    pub guard_bottom: VirtAddr,
    pub current_size: u64,
    pub max_size: u64,
    pub pages_used: u64,
    pub growth_count: u64,
    pub remaining_growth: u64,
}

/// スタックを削除
pub fn remove_stack(task_id: u64) -> Option<StackRegion> {
    STACK_MANAGER.write().remove(task_id)
}

// ============================================================================
// Stack Pointer Validation
// ============================================================================

/// スタックポインタが有効な範囲内か検証
pub fn validate_stack_pointer(task_id: u64, sp: VirtAddr) -> bool {
    let manager = STACK_MANAGER.read();
    if let Some(stack) = manager.get(task_id) {
        // スタック範囲内または拡張可能範囲内
        stack.contains(sp) || stack.can_grow_to(sp)
    } else {
        false
    }
}

/// 現在のスタック使用量を取得
pub fn get_stack_usage(task_id: u64, current_sp: VirtAddr) -> Option<u64> {
    let manager = STACK_MANAGER.read();
    manager.get(task_id).map(|stack| {
        stack.stack_top.as_u64().saturating_sub(current_sp.as_u64())
    })
}

// ============================================================================
// Statistics API
// ============================================================================

/// 統計スナップショット
#[derive(Debug, Clone, Copy)]
pub struct StackStatSnapshot {
    pub stacks_registered: u64,
    pub stacks_removed: u64,
    pub growths: u64,
    pub pages_grown: u64,
    pub overflows: u64,
    pub guard_hits: u64,
}

/// 統計を取得
pub fn stack_stats() -> StackStatSnapshot {
    StackStatSnapshot {
        stacks_registered: STACK_STATS.stacks_registered.load(Ordering::Relaxed),
        stacks_removed: STACK_STATS.stacks_removed.load(Ordering::Relaxed),
        growths: STACK_STATS.growths.load(Ordering::Relaxed),
        pages_grown: STACK_STATS.pages_grown.load(Ordering::Relaxed),
        overflows: STACK_STATS.overflows.load(Ordering::Relaxed),
        guard_hits: STACK_STATS.guard_hits.load(Ordering::Relaxed),
    }
}

// ============================================================================
// Debug
// ============================================================================

/// デバッグ情報を出力
pub fn stack_debug_info(task_id: u64) {
    if let Some(info) = get_stack_info(task_id) {
        log::info!("=== Stack Debug Info (Task {}) ===", task_id);
        log::info!("  Stack top: {:#x}", info.stack_top.as_u64());
        log::info!("  Current bottom: {:#x}", info.current_bottom.as_u64());
        log::info!("  Guard bottom: {:#x}", info.guard_bottom.as_u64());
        log::info!("  Current size: {} KB", info.current_size / 1024);
        log::info!("  Max size: {} KB", info.max_size / 1024);
        log::info!("  Pages used: {}", info.pages_used);
        log::info!("  Growth count: {}", info.growth_count);
        log::info!("  Remaining growth: {} KB", info.remaining_growth / 1024);
    } else {
        log::info!("Stack not found for task {}", task_id);
    }
}

/// グローバル統計を出力
pub fn stack_global_stats() {
    let stats = stack_stats();
    
    log::info!("=== Stack Global Stats ===");
    log::info!("  Stacks registered: {}", stats.stacks_registered);
    log::info!("  Stacks removed: {}", stats.stacks_removed);
    log::info!("  Growths: {}", stats.growths);
    log::info!("  Pages grown: {}", stats.pages_grown);
    log::info!("  Overflows: {}", stats.overflows);
    log::info!("  Guard hits: {}", stats.guard_hits);
}

// ============================================================================
// Initialization
// ============================================================================

/// スタック管理サブシステムを初期化
pub fn init_stack_growth() {
    log::info!("[mm] Stack growth initialized (default: {}MB, max: {}MB)",
        DEFAULT_STACK_SIZE / (1024 * 1024),
        MAX_STACK_SIZE / (1024 * 1024));
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test_case]
    fn test_stack_region_new() {
        let stack = StackRegion::new(
            VirtAddr::new(0x8000_0000),
            64 * 1024,
            8 * 1024 * 1024,
        );
        
        assert_eq!(stack.stack_top.as_u64(), 0x8000_0000);
        assert_eq!(stack.current_size(), 64 * 1024);
    }
    
    #[test_case]
    fn test_stack_region_contains() {
        let stack = StackRegion::new(
            VirtAddr::new(0x8000_0000),
            64 * 1024,
            8 * 1024 * 1024,
        );
        
        // スタック範囲内
        assert!(stack.contains(VirtAddr::new(0x7FFF_F000)));
        
        // スタック外
        assert!(!stack.contains(VirtAddr::new(0x8000_0000)));
    }
    
    #[test_case]
    fn test_stack_can_grow() {
        let stack = StackRegion::new(
            VirtAddr::new(0x8000_0000),
            64 * 1024,
            8 * 1024 * 1024,
        );
        
        // 現在のボトムより下は拡張可能
        assert!(stack.can_grow_to(VirtAddr::new(stack.current_bottom.as_u64() - 0x1000)));
        
        // ガードより下は拡張不可
        assert!(!stack.can_grow_to(VirtAddr::new(stack.guard_bottom.as_u64() - 0x1000)));
    }
}

