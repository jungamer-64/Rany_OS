// ============================================================================
// src/mm/huge_pages.rs - 1GB Huge Page Support (Legacy Compatibility Layer)
// 設計書 11.1.1: 初期ページテーブル設定 (1GB Huge Page)
// ============================================================================
//!
//! # 1GB Huge Page サポート（互換レイヤー）
//!
//! このモジュールは後方互換性のために維持されています。
//! 新規コードは `huge_page` モジュールを直接使用してください。
//!
//! ## 機能
//!
//! - CPU機能検出（1GBページサポート）
//! - ブートストラップ用シンプルアロケータ
//! - リニアマッピング設定ヘルパー
//!
//! ## 移行ガイド
//!
//! | 旧API (huge_pages) | 新API (huge_page) |
//! |-------------------|-------------------|
//! | `detect_1g_page_support()` | `huge_page::detect_1g_page_support()` |
//! | `is_1g_page_supported()` | `huge_page::is_1g_page_supported()` |
//! | `alloc_huge_page_1g()` | `huge_page::allocate_huge_page_1gb()` |
//! | `HugePageAllocator` | `huge_page::HugePageAllocator` (拡張版) |

#![allow(dead_code)]

use crate::sync::PoisonLock;
use x86_64::PhysAddr;

// huge_page モジュールから主要機能を再エクスポート
pub use super::huge_page::{
    // CPU検出
    detect_1g_page_support,
    is_1g_page_supported,
};

// types.rs から追加の定数

// ============================================================================
// Legacy Constants (互換性のため維持)
// ============================================================================

/// 1GBページサイズ (HUGE_PAGE_SIZE_1GB と同義)
pub const HUGE_PAGE_SIZE_1G: usize = super::types::HUGE_PAGE_SIZE_1GB;

/// 2MBページサイズ (HUGE_PAGE_SIZE_2MB と同義)
pub const HUGE_PAGE_SIZE_2M: usize = super::types::HUGE_PAGE_SIZE_2MB;

// ============================================================================
// Bootstrap Huge Page Allocator (ブートストラップ専用)
// ============================================================================

/// 1GBページアロケータ（ブートストラップ用シンプル版）
///
/// 物理メモリの連続した1GB領域を管理する。
/// ブートストラップ時に使用可能なメモリ領域を設定する。
///
/// **注意**: ランタイムでは `huge_page::HugePageAllocator` を使用してください。
#[derive(Debug)]
pub struct HugePageAllocator {
    /// 利用可能な1GBページのビットマップ
    /// 最大64GB (64 pages) を管理
    available: u64,
    /// 割り当て済み1GBページのビットマップ
    allocated: u64,
    /// ベースアドレス
    base_address: PhysAddr,
}

impl HugePageAllocator {
    /// 新しい1GBページアロケータを作成
    pub const fn new() -> Self {
        Self {
            available: 0,
            allocated: 0,
            base_address: PhysAddr::zero(),
        }
    }

    /// アロケータを初期化
    ///
    /// # Arguments
    /// - `base`: 管理する物理メモリ領域の開始アドレス（1GB境界）
    /// - `count`: 利用可能な1GBページの数（最大64）
    pub fn init(&mut self, base: PhysAddr, count: usize) {
        assert!(
            base.as_u64() % HUGE_PAGE_SIZE_1G as u64 == 0,
            "Base must be 1GB aligned"
        );
        assert!(count <= 64, "Maximum 64 huge pages supported");

        self.base_address = base;
        self.available = (1u64 << count) - 1;
        self.allocated = 0;

        log::info!(
            "[HUGE_PAGE] Bootstrap allocator initialized: base=0x{:X}, count={}",
            base.as_u64(),
            count
        );
    }

    /// 1GBページを割り当て
    pub fn allocate(&mut self) -> Option<PhysAddr> {
        let free = self.available & !self.allocated;
        if free == 0 {
            return None;
        }

        // 最初の空きビットを見つける
        let index = free.trailing_zeros() as usize;
        self.allocated |= 1 << index;

        let addr =
            PhysAddr::new(self.base_address.as_u64() + (index as u64 * HUGE_PAGE_SIZE_1G as u64));
        Some(addr)
    }

    /// 1GBページを解放
    pub fn deallocate(&mut self, addr: PhysAddr) {
        assert!(addr.as_u64() >= self.base_address.as_u64());
        let offset = addr.as_u64() - self.base_address.as_u64();
        assert!(offset % HUGE_PAGE_SIZE_1G as u64 == 0);

        let index = (offset / HUGE_PAGE_SIZE_1G as u64) as usize;
        assert!(index < 64);
        assert!(self.allocated & (1 << index) != 0, "Page not allocated");

        self.allocated &= !(1 << index);
    }

    /// 統計を取得
    pub fn stats(&self) -> HugePageStats {
        let total = self.available.count_ones() as usize;
        let used = self.allocated.count_ones() as usize;

        HugePageStats {
            total_pages_1g: total,
            used_pages_1g: used,
            free_pages_1g: total - used,
            total_memory_gb: total,
            used_memory_gb: used,
        }
    }
}

impl Default for HugePageAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Huge Page統計
#[derive(Debug, Clone, Copy)]
pub struct HugePageStats {
    /// 総1GBページ数
    pub total_pages_1g: usize,
    /// 使用中1GBページ数
    pub used_pages_1g: usize,
    /// 空き1GBページ数
    pub free_pages_1g: usize,
    /// 総メモリ (GB)
    pub total_memory_gb: usize,
    /// 使用メモリ (GB)
    pub used_memory_gb: usize,
}

// ============================================================================
// Linear Mapping Helpers
// ============================================================================

/// 1GBページを使用したリニアマッピングを設定
///
/// # Safety
/// - ページテーブルの設定を直接操作するため unsafe
/// - ブートストラップ初期段階で呼び出すこと
#[cfg(target_arch = "x86_64")]
pub unsafe fn setup_linear_mapping_1g(total_memory: usize) -> usize {
    if !is_1g_page_supported() {
        log::info!("[HUGE_PAGE] Falling back to 2MB pages for linear mapping");
        return setup_linear_mapping_2m(total_memory);
    }

    let pages_needed = (total_memory + HUGE_PAGE_SIZE_1G - 1) / HUGE_PAGE_SIZE_1G;
    log::info!(
        "[HUGE_PAGE] Setting up linear mapping with {} 1GB pages for {} bytes",
        pages_needed,
        total_memory
    );

    // ページテーブル設定は higher_half モジュールに委譲
    pages_needed
}

/// 2MBページを使用したリニアマッピング（フォールバック）
#[cfg(target_arch = "x86_64")]
pub unsafe fn setup_linear_mapping_2m(total_memory: usize) -> usize {
    let pages_needed = (total_memory + HUGE_PAGE_SIZE_2M - 1) / HUGE_PAGE_SIZE_2M;
    log::info!(
        "[HUGE_PAGE] Setting up linear mapping with {} 2MB pages for {} bytes",
        pages_needed,
        total_memory
    );
    pages_needed
}

/// 非x86_64アーキテクチャ用スタブ
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn setup_linear_mapping_1g(_total_memory: usize) -> usize {
    0
}

#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn setup_linear_mapping_2m(_total_memory: usize) -> usize {
    0
}

// ============================================================================
// Global Instance & Initialization
// ============================================================================

/// グローバル1GBページアロケータ（ブートストラップ用）
static HUGE_PAGE_ALLOCATOR: PoisonLock<HugePageAllocator> =
    PoisonLock::new(HugePageAllocator::new());

/// Huge Pageアロケータに安全にアクセス
pub fn with_huge_page_allocator<F, R>(f: F) -> Option<R>
where
    F: FnOnce(&mut HugePageAllocator) -> R,
{
    match HUGE_PAGE_ALLOCATOR.lock() {
        Ok(mut guard) => Some(f(&mut guard)),
        Err(_) => {
            log::error!("[MM] Huge Page Allocator poisoned - refusing to access");
            None
        }
    }
}

/// 1GBページを割り当て（グローバルAPI）
pub fn alloc_huge_page_1g() -> Option<PhysAddr> {
    match HUGE_PAGE_ALLOCATOR.lock() {
        Ok(mut guard) => guard.allocate(),
        Err(_) => {
            log::error!("[MM] Huge Page Allocator poisoned - allocation failed");
            None
        }
    }
}

/// 1GBページを解放（グローバルAPI）
pub fn dealloc_huge_page_1g(addr: PhysAddr) {
    match HUGE_PAGE_ALLOCATOR.lock() {
        Ok(mut guard) => guard.deallocate(addr),
        Err(_) => log::error!("[MM] Huge Page Allocator poisoned - deallocate ignored"),
    }
}

/// Huge Page統計を取得
pub fn huge_page_stats() -> HugePageStats {
    match HUGE_PAGE_ALLOCATOR.lock() {
        Ok(guard) => guard.stats(),
        Err(_) => {
            log::error!("[MM] Huge Page Allocator poisoned - returning zero stats");
            HugePageStats {
                total_pages_1g: 0,
                used_pages_1g: 0,
                free_pages_1g: 0,
                total_memory_gb: 0,
                used_memory_gb: 0,
            }
        }
    }
}

/// Huge Pageサブシステムを初期化
pub fn init() {
    detect_1g_page_support();
}

/// Huge Pageアロケータを初期化（メモリレイアウト確定後）
pub fn init_allocator(base: PhysAddr, count: usize) {
    let mut guard = HUGE_PAGE_ALLOCATOR.lock_for_init("[MM] Huge Page Allocator init");
    guard.init(base, count);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_huge_page_allocator() {
        let mut alloc = HugePageAllocator::new();
        alloc.init(PhysAddr::new(0x40000000), 4); // 4GB from 1GB base

        // 4ページ割り当て可能
        let p1 = alloc.allocate().unwrap();
        let p2 = alloc.allocate().unwrap();
        let p3 = alloc.allocate().unwrap();
        let p4 = alloc.allocate().unwrap();

        assert_eq!(p1.as_u64(), 0x40000000);
        assert_eq!(p2.as_u64(), 0x80000000);
        assert_eq!(p3.as_u64(), 0xC0000000);
        assert_eq!(p4.as_u64(), 0x100000000);

        // 5ページ目は割り当て不可
        assert!(alloc.allocate().is_none());

        // 解放して再割り当て
        alloc.deallocate(p2);
        let p5 = alloc.allocate().unwrap();
        assert_eq!(p5.as_u64(), 0x80000000);
    }

    #[test]
    fn test_huge_page_stats() {
        let mut alloc = HugePageAllocator::new();
        alloc.init(PhysAddr::new(0), 8);

        let stats = alloc.stats();
        assert_eq!(stats.total_pages_1g, 8);
        assert_eq!(stats.used_pages_1g, 0);
        assert_eq!(stats.free_pages_1g, 8);

        alloc.allocate();
        alloc.allocate();
        let stats = alloc.stats();
        assert_eq!(stats.used_pages_1g, 2);
        assert_eq!(stats.free_pages_1g, 6);
    }
}
