// ============================================================================
// src/mm/demand_paging.rs - Demand Paging Implementation
//
// ## 概要
//
// Demand Paging（遅延ページ割り当て）の実装。map_region/brkで確保された
// 仮想アドレス空間に対して、実際のアクセスが発生するまで物理ページの
// 割り当てを遅延させる。
//
// ## 設計
//
// 1. **Lazy Allocation**: VMA作成時は物理ページを割り当てない
// 2. **Zero Fill**: 匿名マッピングの初回アクセスでゼロクリアページを提供
// 3. **File Backed**: ファイルマッピングの初回アクセスでファイルから読み込み
// 4. **CoW Zero Page**: ゼロページへのCoWで初期化コストを削減
//
// ## パフォーマンス
//
// - 未使用ページのメモリ消費ゼロ
// - fork()後の子プロセス起動が高速
// - 大量のmmap()呼び出しが軽量
//
// ============================================================================
#![allow(dead_code)]

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::RwLock;

use super::cow::{CowResult, cow_map_zero_page, zero_page_phys};
use super::fault_handler::PageSetup;
use super::higher_half::{MapError, PageFlags, PhysAddr, VirtAddr, global_map_page};
use crate::mm::meta::memcg::{ChargeType, MemcgId, memcg_charge, memcg_track_page, memcg_uncharge};
use crate::mm::phys::frame_allocator::alloc_frame;
use crate::mm::reclaim::page_reclaim::{PageType as LruPageType, lru_add_page};
use crate::mm::types::FrameIndex;

// ============================================================================
// Demand Paging Configuration
// ============================================================================

/// Demand Pagingの設定
#[derive(Debug, Clone, Copy)]
pub struct DemandPagingConfig {
    /// ゼロページCoW最適化を有効にするか
    pub use_zero_page_cow: bool,
    /// プリフォルト（先読み）ページ数
    pub prefault_pages: usize,
    /// 最大プリフォルトサイズ（バイト）
    pub max_prefault_size: usize,
    /// Memcgチャージを有効にするか
    pub memcg_enabled: bool,
}

impl Default for DemandPagingConfig {
    fn default() -> Self {
        Self {
            use_zero_page_cow: true,
            prefault_pages: 4,
            max_prefault_size: 64 * 1024, // 64KB
            memcg_enabled: true,
        }
    }
}

static CONFIG: RwLock<DemandPagingConfig> = RwLock::new(DemandPagingConfig {
    use_zero_page_cow: true,
    prefault_pages: 4,
    max_prefault_size: 64 * 1024,
    memcg_enabled: true,
});

/// 設定を更新
pub fn set_config(config: DemandPagingConfig) {
    *CONFIG.write() = config;
}

/// 現在の設定を取得
pub fn get_config() -> DemandPagingConfig {
    *CONFIG.read()
}

// ============================================================================
// Virtual Memory Region Types
// ============================================================================

/// 仮想メモリ領域の種類
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmRegionType {
    /// 匿名マッピング（ヒープ、スタック等）
    Anonymous,
    /// ファイルマッピング（Private）
    FilePrivate,
    /// ファイルマッピング（Shared）
    FileShared,
    /// デバイスマッピング
    Device,
    /// 特殊領域（vDSO等）
    Special,
}

/// 仮想メモリ領域
#[derive(Debug, Clone)]
pub struct VmRegion {
    /// 開始アドレス
    pub start: VirtAddr,
    /// 終了アドレス（exclusive）
    pub end: VirtAddr,
    /// 領域タイプ
    pub region_type: VmRegionType,
    /// 保護フラグ
    pub prot: ProtFlags,
    /// バッキングファイル情報（ファイルマッピングの場合）
    pub file_info: Option<FileBackingInfo>,
    /// 既に物理ページが割り当てられたページのビットマップインデックス
    populated_pages: Vec<bool>,
}

/// 保護フラグ
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtFlags(pub u32);

impl ProtFlags {
    pub const NONE: ProtFlags = ProtFlags(0);
    pub const READ: ProtFlags = ProtFlags(1);
    pub const WRITE: ProtFlags = ProtFlags(2);
    pub const EXEC: ProtFlags = ProtFlags(4);

    #[inline]
    pub fn readable(&self) -> bool {
        self.0 & Self::READ.0 != 0
    }

    #[inline]
    pub fn writable(&self) -> bool {
        self.0 & Self::WRITE.0 != 0
    }

    #[inline]
    pub fn executable(&self) -> bool {
        self.0 & Self::EXEC.0 != 0
    }

    /// PageFlagsに変換
    pub fn to_page_flags(&self) -> PageFlags {
        let mut base_flags = PageFlags::PRESENT | PageFlags::USER;
        if self.writable() {
            base_flags |= PageFlags::WRITABLE;
        }
        if !self.executable() {
            base_flags |= PageFlags::NO_EXECUTE;
        }
        PageFlags::new(base_flags)
    }
}

impl core::ops::BitOr for ProtFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self::Output {
        ProtFlags(self.0 | rhs.0)
    }
}

/// ファイルバッキング情報
#[derive(Debug, Clone)]
pub struct FileBackingInfo {
    /// inode番号
    pub inode: u64,
    /// ファイル内オフセット
    pub offset: u64,
    /// ファイルサイズ
    pub file_size: u64,
}

impl VmRegion {
    /// 新しい匿名領域を作成
    pub fn new_anonymous(start: VirtAddr, end: VirtAddr, prot: ProtFlags) -> Self {
        let page_count = ((end.as_u64() - start.as_u64()) / 4096) as usize;

        Self {
            start,
            end,
            region_type: VmRegionType::Anonymous,
            prot,
            file_info: None,
            populated_pages: alloc::vec![false; page_count],
        }
    }

    /// 新しいファイルマッピング領域を作成
    pub fn new_file(
        start: VirtAddr,
        end: VirtAddr,
        prot: ProtFlags,
        shared: bool,
        file_info: FileBackingInfo,
    ) -> Self {
        let page_count = ((end.as_u64() - start.as_u64()) / 4096) as usize;

        Self {
            start,
            end,
            region_type: if shared {
                VmRegionType::FileShared
            } else {
                VmRegionType::FilePrivate
            },
            prot,
            file_info: Some(file_info),
            populated_pages: alloc::vec![false; page_count],
        }
    }

    /// アドレスがこの領域に含まれるか
    #[inline]
    pub fn contains(&self, addr: VirtAddr) -> bool {
        addr >= self.start && addr < self.end
    }

    /// ページインデックスを取得
    #[inline]
    fn page_index(&self, addr: VirtAddr) -> usize {
        ((addr.as_u64() - self.start.as_u64()) / 4096) as usize
    }

    /// ページが既に割り当て済みか
    pub fn is_populated(&self, addr: VirtAddr) -> bool {
        let idx = self.page_index(addr);
        if idx < self.populated_pages.len() {
            self.populated_pages[idx]
        } else {
            false
        }
    }

    /// ページを割り当て済みとしてマーク
    pub fn mark_populated(&mut self, addr: VirtAddr) {
        let idx = self.page_index(addr);
        if idx < self.populated_pages.len() {
            self.populated_pages[idx] = true;
        }
    }
}

// ============================================================================
// Demand Paging Manager
// ============================================================================

/// Demand Pagingマネージャ
pub struct DemandPagingManager {
    /// タスクID → VmRegionリスト
    regions: BTreeMap<u64, Vec<VmRegion>>,
}

impl DemandPagingManager {
    pub const fn new() -> Self {
        Self {
            regions: BTreeMap::new(),
        }
    }

    /// 領域を登録
    pub fn register_region(&mut self, task_id: u64, region: VmRegion) {
        self.regions
            .entry(task_id)
            .or_insert_with(Vec::new)
            .push(region);

        DEMAND_STATS
            .regions_registered
            .fetch_add(1, Ordering::Relaxed);
    }

    /// アドレスに対応する領域を検索
    pub fn find_region(&self, task_id: u64, addr: VirtAddr) -> Option<&VmRegion> {
        self.regions
            .get(&task_id)
            .and_then(|regions| regions.iter().find(|r| r.contains(addr)))
    }

    /// アドレスに対応する領域を検索（可変）
    pub fn find_region_mut(&mut self, task_id: u64, addr: VirtAddr) -> Option<&mut VmRegion> {
        self.regions
            .get_mut(&task_id)
            .and_then(|regions| regions.iter_mut().find(|r| r.contains(addr)))
    }

    /// 領域を削除
    pub fn remove_region(&mut self, task_id: u64, start: VirtAddr) -> Option<VmRegion> {
        if let Some(regions) = self.regions.get_mut(&task_id) {
            if let Some(idx) = regions.iter().position(|r| r.start == start) {
                DEMAND_STATS.regions_removed.fetch_add(1, Ordering::Relaxed);
                return Some(regions.remove(idx));
            }
        }
        None
    }

    /// タスクの全領域を削除
    pub fn remove_all_regions(&mut self, task_id: u64) -> Vec<VmRegion> {
        self.regions.remove(&task_id).unwrap_or_default()
    }
}

static DEMAND_MANAGER: RwLock<DemandPagingManager> = RwLock::new(DemandPagingManager::new());

// ============================================================================
// Statistics
// ============================================================================

/// Demand Paging統計
pub struct DemandStats {
    /// 登録された領域数
    pub regions_registered: AtomicU64,
    /// 削除された領域数
    pub regions_removed: AtomicU64,
    /// ゼロフィルページ数
    pub zero_fill_pages: AtomicU64,
    /// ファイル読み込みページ数
    pub file_read_pages: AtomicU64,
    /// ゼロページCoW使用数
    pub zero_page_cow: AtomicU64,
    /// プリフォルトページ数
    pub prefault_pages: AtomicU64,
    /// フォルト解決失敗数
    pub fault_failures: AtomicU64,
}

impl DemandStats {
    pub const fn new() -> Self {
        Self {
            regions_registered: AtomicU64::new(0),
            regions_removed: AtomicU64::new(0),
            zero_fill_pages: AtomicU64::new(0),
            file_read_pages: AtomicU64::new(0),
            zero_page_cow: AtomicU64::new(0),
            prefault_pages: AtomicU64::new(0),
            fault_failures: AtomicU64::new(0),
        }
    }
}

static DEMAND_STATS: DemandStats = DemandStats::new();

// ============================================================================
// Demand Paging Result
// ============================================================================

/// Demand Paging操作の結果
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DemandResult {
    /// 成功
    Ok,
    /// 領域が見つからない
    RegionNotFound,
    /// 権限違反
    PermissionDenied,
    /// メモリ不足
    OutOfMemory,
    /// ファイルI/Oエラー
    IoError,
    /// 既にマッピング済み
    AlreadyMapped,
}

// ============================================================================
// Core Demand Paging Functions
// ============================================================================

/// Demand Pagingフォルト処理
///
/// ページフォルトハンドラから呼び出される。
/// 該当アドレスの領域タイプに応じて適切なページを割り当てる。
pub fn handle_demand_fault(task_id: u64, fault_addr: VirtAddr, is_write: bool) -> DemandResult {
    let page_addr = VirtAddr::new(fault_addr.as_u64() & !0xFFF);
    let config = get_config();

    // 領域を検索
    let mut manager = DEMAND_MANAGER.write();
    let region = match manager.find_region_mut(task_id, page_addr) {
        Some(r) => r,
        None => return DemandResult::RegionNotFound,
    };

    // 権限チェック
    if is_write && !region.prot.writable() {
        return DemandResult::PermissionDenied;
    }

    // 既にマッピング済みか
    if region.is_populated(page_addr) {
        return DemandResult::AlreadyMapped;
    }

    // 領域タイプに応じた処理
    let result = match region.region_type {
        VmRegionType::Anonymous => populate_anonymous_page(page_addr, &region.prot, &config),
        VmRegionType::FilePrivate | VmRegionType::FileShared => {
            populate_file_page(page_addr, region)
        }
        VmRegionType::Device => {
            // デバイスマッピングはDemand Pagingしない
            DemandResult::AlreadyMapped
        }
        VmRegionType::Special => {
            // 特殊領域はDemand Pagingしない
            DemandResult::AlreadyMapped
        }
    };

    if result == DemandResult::Ok {
        region.mark_populated(page_addr);
    } else {
        DEMAND_STATS.fault_failures.fetch_add(1, Ordering::Relaxed);
    }

    result
}

/// 匿名ページの割り当て
fn populate_anonymous_page(
    page_addr: VirtAddr,
    prot: &ProtFlags,
    config: &DemandPagingConfig,
) -> DemandResult {
    // ゼロページCoW最適化
    if config.use_zero_page_cow && !prot.writable() && zero_page_phys().is_some() {
        match cow_map_zero_page(page_addr) {
            CowResult::Ok => {
                DEMAND_STATS.zero_page_cow.fetch_add(1, Ordering::Relaxed);
                return DemandResult::Ok;
            }
            _ => {
                // フォールバック: 実ページを割り当て
            }
        }
    }

    // memcg ID（条件付き）
    let memcg_id = if config.memcg_enabled {
        Some(crate::mm::meta::memcg::current_memcg_id())
    } else {
        None
    };

    let setup = match PageSetup::allocate(memcg_id, ChargeType::Anon) {
        Some(s) => s,
        None => return DemandResult::OutOfMemory,
    };

    let flags = prot.to_page_flags();
    match unsafe { setup.map_and_track(page_addr, flags, LruPageType::Anonymous) } {
        Ok(()) => {
            DEMAND_STATS.zero_fill_pages.fetch_add(1, Ordering::Relaxed);
            DemandResult::Ok
        }
        Err(MapError::AlreadyMapped) => DemandResult::AlreadyMapped,
        Err(_) => DemandResult::OutOfMemory,
    }
}

/// ファイル読み込みとmemcgチャージを実行
fn prepare_file_page_data(
    frame_phys: PhysAddr,
    file_info: &FileBackingInfo,
    file_offset: u64,
) -> Result<(bool, MemcgId), DemandResult> {
    zero_page(frame_phys);
    let remaining = file_info.file_size.saturating_sub(file_offset);
    let to_read = remaining.min(crate::mm::types::PAGE_SIZE_4K as u64) as usize;
    if to_read > 0 {
        let virt = super::mapping::phys_to_virt(x86_64::PhysAddr::new(frame_phys.as_u64()));
        let buf = unsafe { core::slice::from_raw_parts_mut(virt.as_u64() as *mut u8, to_read) };
        if crate::fs::fs_abstraction::read_inode_by_number(
            file_info.inode as crate::fs::InodeNum,
            file_offset,
            buf,
        )
        .is_err()
        {
            return Err(DemandResult::IoError);
        }
    }
    let frame_idx = FrameIndex::from_phys_addr(frame_phys.as_u64());
    let page_num = (file_offset / crate::mm::types::PAGE_SIZE_4K as u64) as u64;
    crate::mm::meta::frame_backing::track_frame_backing(
        frame_idx,
        file_info.inode as crate::fs::InodeNum,
        page_num,
    );

    let mut memcg_charged = false;
    let mut memcg_id = MemcgId::ROOT;
    if CONFIG.read().memcg_enabled {
        memcg_id = crate::mm::meta::memcg::current_memcg_id();
        if memcg_charge(memcg_id, 1, ChargeType::Cache).is_err() {
            return Err(DemandResult::OutOfMemory);
        }
        memcg_charged = true;
    }
    Ok((memcg_charged, memcg_id))
}

/// ファイルバックページの割り当て
fn populate_file_page(page_addr: VirtAddr, region: &VmRegion) -> DemandResult {
    let _file_info = match &region.file_info {
        Some(info) => info,
        None => return DemandResult::IoError,
    };

    // 新しいフレームを割り当て
    let frame = match alloc_frame() {
        Some(f) => f,
        None => return DemandResult::OutOfMemory,
    };

    let frame_phys = PhysAddr::new(frame.start_address().as_u64());
    let file_offset = _file_info.offset + (page_addr.as_u64() - region.start.as_u64());

    let (memcg_charged, memcg_id) =
        match prepare_file_page_data(frame_phys, _file_info, file_offset) {
            Ok(v) => v,
            Err(result) => {
                crate::mm::phys::frame_allocator::dealloc_frame(frame);
                return result;
            }
        };

    // ページマッピング
    let flags = region.prot.to_page_flags();
    match unsafe { global_map_page(page_addr, frame_phys, flags) } {
        Ok(()) => {}
        Err(MapError::AlreadyMapped) => {
            if memcg_charged {
                memcg_uncharge(memcg_id, 1, ChargeType::Cache);
            }
            crate::mm::phys::frame_allocator::dealloc_frame(frame);
            return DemandResult::AlreadyMapped;
        }
        Err(_) => {
            if memcg_charged {
                memcg_uncharge(memcg_id, 1, ChargeType::Cache);
            }
            crate::mm::phys::frame_allocator::dealloc_frame(frame);
            return DemandResult::OutOfMemory;
        }
    }

    // LRUに追加
    lru_add_page(frame, LruPageType::FileBacked);

    // ページとmemcgを追跡
    if memcg_charged {
        let frame_idx = FrameIndex::from_phys_addr(frame_phys.as_u64());
        memcg_track_page(frame_idx, memcg_id, ChargeType::Cache);
    }

    DEMAND_STATS.file_read_pages.fetch_add(1, Ordering::Relaxed);

    DemandResult::Ok
}

/// ページをゼロクリア
fn zero_page(phys_addr: PhysAddr) {
    let x86_phys = x86_64::PhysAddr::new(phys_addr.as_u64());
    let virt = super::mapping::phys_to_virt(x86_phys);
    unsafe {
        core::ptr::write_bytes(virt.as_u64() as *mut u8, 0, 4096);
    }
}

// ============================================================================
// Prefaulting
// ============================================================================

/// プリフォルト（先読みページ割り当て）
///
/// フォルト発生アドレスの周辺ページを先に割り当てることで、
/// 連続的なアクセスパターンでのフォルト回数を削減する。
pub fn prefault_pages(task_id: u64, center_addr: VirtAddr, count: usize) -> usize {
    let config = get_config();
    let max_pages = config.prefault_pages.min(count);
    let mut populated = 0;

    let mut manager = DEMAND_MANAGER.write();

    // 中心アドレスの前後にプリフォルト
    for i in 0..max_pages {
        let offset = (i as i64 - (max_pages as i64 / 2)) * 4096;
        let addr = match center_addr.as_u64().checked_add_signed(offset) {
            Some(a) => VirtAddr::new(a),
            None => continue,
        };

        // 領域を検索
        let region = match manager.find_region_mut(task_id, addr) {
            Some(r) => r,
            None => continue,
        };

        // 既にマッピング済みならスキップ
        if region.is_populated(addr) {
            continue;
        }

        // ページを割り当て
        let result = match region.region_type {
            VmRegionType::Anonymous => populate_anonymous_page(addr, &region.prot, &config),
            _ => continue, // ファイルマッピングはプリフォルトしない
        };

        if result == DemandResult::Ok {
            region.mark_populated(addr);
            populated += 1;
            DEMAND_STATS.prefault_pages.fetch_add(1, Ordering::Relaxed);
        }
    }

    populated
}

// ============================================================================
// Region Management API
// ============================================================================

/// 匿名領域を登録
pub fn register_anonymous(task_id: u64, start: VirtAddr, size: u64, prot: ProtFlags) {
    let end = VirtAddr::new(start.as_u64() + size);
    let region = VmRegion::new_anonymous(start, end, prot);

    DEMAND_MANAGER.write().register_region(task_id, region);
}

/// ファイルマッピング領域を登録
pub fn register_file_mapping(
    task_id: u64,
    start: VirtAddr,
    size: u64,
    prot: ProtFlags,
    shared: bool,
    inode: u64,
    offset: u64,
    file_size: u64,
) {
    let end = VirtAddr::new(start.as_u64() + size);
    let file_info = FileBackingInfo {
        inode,
        offset,
        file_size,
    };
    let region = VmRegion::new_file(start, end, prot, shared, file_info);

    DEMAND_MANAGER.write().register_region(task_id, region);
}

/// 領域を削除
pub fn unregister_region(task_id: u64, start: VirtAddr) -> Option<VmRegion> {
    DEMAND_MANAGER.write().remove_region(task_id, start)
}

/// タスクの全領域を削除
pub fn cleanup_task(task_id: u64) -> Vec<VmRegion> {
    DEMAND_MANAGER.write().remove_all_regions(task_id)
}

// ============================================================================
// Statistics API
// ============================================================================

/// 統計スナップショット
#[derive(Debug, Clone, Copy)]
pub struct DemandStatSnapshot {
    pub regions_registered: u64,
    pub regions_removed: u64,
    pub zero_fill_pages: u64,
    pub file_read_pages: u64,
    pub zero_page_cow: u64,
    pub prefault_pages: u64,
    pub fault_failures: u64,
}

/// 統計を取得
pub fn demand_stats() -> DemandStatSnapshot {
    DemandStatSnapshot {
        regions_registered: DEMAND_STATS.regions_registered.load(Ordering::Relaxed),
        regions_removed: DEMAND_STATS.regions_removed.load(Ordering::Relaxed),
        zero_fill_pages: DEMAND_STATS.zero_fill_pages.load(Ordering::Relaxed),
        file_read_pages: DEMAND_STATS.file_read_pages.load(Ordering::Relaxed),
        zero_page_cow: DEMAND_STATS.zero_page_cow.load(Ordering::Relaxed),
        prefault_pages: DEMAND_STATS.prefault_pages.load(Ordering::Relaxed),
        fault_failures: DEMAND_STATS.fault_failures.load(Ordering::Relaxed),
    }
}

/// 統計をリセット
pub fn reset_stats() {
    DEMAND_STATS.regions_registered.store(0, Ordering::Relaxed);
    DEMAND_STATS.regions_removed.store(0, Ordering::Relaxed);
    DEMAND_STATS.zero_fill_pages.store(0, Ordering::Relaxed);
    DEMAND_STATS.file_read_pages.store(0, Ordering::Relaxed);
    DEMAND_STATS.zero_page_cow.store(0, Ordering::Relaxed);
    DEMAND_STATS.prefault_pages.store(0, Ordering::Relaxed);
    DEMAND_STATS.fault_failures.store(0, Ordering::Relaxed);
}

// ============================================================================
// Initialization
// ============================================================================

/// Demand Pagingサブシステムを初期化
pub fn init_demand_paging() {
    // ゼロページを初期化
    super::cow::init_zero_page();

    log::info!("[mm] Demand paging initialized");
}

// ============================================================================
// Debug
// ============================================================================

/// デバッグ情報を出力
pub fn demand_debug_info() {
    let stats = demand_stats();
    let config = get_config();

    log::info!("=== Demand Paging Debug Info ===");
    log::info!("Config:");
    log::info!("  Zero page CoW: {}", config.use_zero_page_cow);
    log::info!("  Prefault pages: {}", config.prefault_pages);
    log::info!("  Max prefault size: {} bytes", config.max_prefault_size);
    log::info!("Statistics:");
    log::info!(
        "  Regions: {} registered, {} removed",
        stats.regions_registered,
        stats.regions_removed
    );
    log::info!("  Zero fill pages: {}", stats.zero_fill_pages);
    log::info!("  File read pages: {}", stats.file_read_pages);
    log::info!("  Zero page CoW: {}", stats.zero_page_cow);
    log::info!("  Prefault pages: {}", stats.prefault_pages);
    log::info!("  Fault failures: {}", stats.fault_failures);
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests;
