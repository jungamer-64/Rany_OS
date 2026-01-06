// ============================================================================
// Shrinker Framework
// メモリ回収時のキャッシュ縮小機構
// ============================================================================
//!
//! # Shrinker Architecture
//!
//! ## 概要
//! Shrinkerは、メモリ圧迫時に各サブシステムのキャッシュを縮小する統一フレームワーク。
//! 登録された各shrinkerは、回収可能なオブジェクト数を報告し、要求に応じて縮小する。
//!
//! ## 使用例
//! - Slabキャッシュの縮小
//! - ページキャッシュの回収
//! - dentryキャッシュの縮小
//! - inodeキャッシュの縮小
//!
//! ## 優先度
//! 1. 低優先度キャッシュ（dentry, inode）
//! 2. 中優先度キャッシュ（page cache）
//! 3. 高優先度キャッシュ（重要なカーネルキャッシュ）

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

use super::types::NumaNodeId;

/// Shrinker ID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct ShrinkerId(u64);

impl ShrinkerId {
    pub const fn new(id: u64) -> Self {
        Self(id)
    }
    
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

/// 縮小優先度
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ShrinkerPriority {
    /// 最低優先度（積極的に縮小）
    Lowest = 0,
    /// 低優先度
    Low = 1,
    /// 通常
    Normal = 2,
    /// 高優先度（最後に縮小）
    High = 3,
    /// 最高優先度（緊急時のみ）
    Critical = 4,
}

impl Default for ShrinkerPriority {
    fn default() -> Self {
        Self::Normal
    }
}

/// 縮小制御フラグ
#[derive(Debug, Clone, Copy)]
pub struct ShrinkControl {
    /// 縮小対象NUMAノード（Noneなら全ノード）
    pub numa_node: Option<NumaNodeId>,
    /// 要求する縮小オブジェクト数
    pub nr_to_scan: usize,
    /// GFP風フラグ（将来拡張用）
    pub gfp_flags: u32,
    /// 緊急縮小フラグ
    pub urgent: bool,
}

impl Default for ShrinkControl {
    fn default() -> Self {
        Self {
            numa_node: None,
            nr_to_scan: 128,
            gfp_flags: 0,
            urgent: false,
        }
    }
}

/// Shrinkerトレイト
pub trait Shrinker: Send + Sync {
    /// 縮小可能なオブジェクト数を報告
    fn count_objects(&self, sc: &ShrinkControl) -> usize;
    
    /// オブジェクトを縮小し、実際に縮小した数を返す
    fn scan_objects(&self, sc: &ShrinkControl) -> usize;
    
    /// Shrinker名を取得
    fn name(&self) -> &str;
    
    /// 優先度を取得
    fn priority(&self) -> ShrinkerPriority {
        ShrinkerPriority::Normal
    }
    
    /// 縮小可能か確認
    fn can_shrink(&self) -> bool {
        true
    }
}

/// Shrinker登録情報
struct ShrinkerEntry {
    /// Shrinker実装
    shrinker: &'static dyn Shrinker,
    /// 優先度
    priority: ShrinkerPriority,
    /// 登録タイムスタンプ
    registered_tsc: u64,
    /// 呼び出し回数
    call_count: AtomicU64,
    /// 縮小したオブジェクト総数
    total_freed: AtomicU64,
}

/// Shrinker統計
#[derive(Debug, Clone)]
pub struct ShrinkerStats {
    pub id: ShrinkerId,
    pub name: String,
    pub priority: ShrinkerPriority,
    pub countable_objects: usize,
    pub call_count: u64,
    pub total_freed: u64,
}

/// グローバル縮小統計
#[derive(Debug, Default, Clone)]
pub struct GlobalShrinkStats {
    /// 縮小サイクル実行回数
    pub shrink_cycles: u64,
    /// 縮小したオブジェクト総数
    pub total_objects_freed: u64,
    /// 緊急縮小回数
    pub urgent_shrinks: u64,
    /// 縮小失敗回数（0オブジェクト）
    pub failed_shrinks: u64,
    /// 最後の縮小タイムスタンプ
    pub last_shrink_tsc: u64,
}

/// Shrinker Manager
pub struct ShrinkerManager {
    /// 登録されたshrinker（ID -> エントリ）
    shrinkers: RwLock<BTreeMap<ShrinkerId, ShrinkerEntry>>,
    /// 次のID
    next_id: AtomicU64,
    /// グローバル統計
    global_stats: Mutex<GlobalShrinkStats>,
    /// 初期化済み
    initialized: AtomicU8,
}

impl ShrinkerManager {
    /// 新しいManagerを作成
    pub const fn new() -> Self {
        Self {
            shrinkers: RwLock::new(BTreeMap::new()),
            next_id: AtomicU64::new(1),
            global_stats: Mutex::new(GlobalShrinkStats {
                shrink_cycles: 0,
                total_objects_freed: 0,
                urgent_shrinks: 0,
                failed_shrinks: 0,
                last_shrink_tsc: 0,
            }),
            initialized: AtomicU8::new(0),
        }
    }
    
    /// 初期化
    pub fn init(&self) {
        if self.initialized.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            log::info!("[Shrinker] Shrinker manager initialized");
        }
    }
    
    /// Shrinkerを登録
    pub fn register(&self, shrinker: &'static dyn Shrinker) -> ShrinkerId {
        let id = ShrinkerId::new(self.next_id.fetch_add(1, Ordering::Relaxed));
        
        let entry = ShrinkerEntry {
            shrinker,
            priority: shrinker.priority(),
            registered_tsc: read_tsc(),
            call_count: AtomicU64::new(0),
            total_freed: AtomicU64::new(0),
        };
        
        let mut shrinkers = self.shrinkers.write();
        shrinkers.insert(id, entry);
        
        log::debug!("[Shrinker] Registered '{}' with id={}", shrinker.name(), id.as_u64());
        
        id
    }
    
    /// Shrinkerを登録解除
    pub fn unregister(&self, id: ShrinkerId) {
        let mut shrinkers = self.shrinkers.write();
        if let Some(entry) = shrinkers.remove(&id) {
            log::debug!("[Shrinker] Unregistered '{}' (id={})", entry.shrinker.name(), id.as_u64());
        }
    }
    
    /// 全shrinkerの縮小可能オブジェクト数を取得
    pub fn count_all(&self, sc: &ShrinkControl) -> usize {
        let shrinkers = self.shrinkers.read();
        shrinkers.values()
            .filter(|e| e.shrinker.can_shrink())
            .map(|e| e.shrinker.count_objects(sc))
            .sum()
    }
    
    /// 縮小を実行（優先度順）
    pub fn shrink(&self, sc: &ShrinkControl) -> usize {
        let tsc = read_tsc();
        let shrinkers = self.shrinkers.read();
        
        // 優先度でソート（低優先度から先に縮小）
        let mut entries: Vec<_> = shrinkers.iter().collect();
        entries.sort_by_key(|(_, e)| e.priority);
        
        let mut total_freed = 0;
        let mut remaining = sc.nr_to_scan;
        
        for (id, entry) in entries {
            if remaining == 0 {
                break;
            }
            
            if !entry.shrinker.can_shrink() {
                continue;
            }
            
            let mut local_sc = *sc;
            local_sc.nr_to_scan = remaining;
            
            let freed = entry.shrinker.scan_objects(&local_sc);
            
            entry.call_count.fetch_add(1, Ordering::Relaxed);
            entry.total_freed.fetch_add(freed as u64, Ordering::Relaxed);
            
            total_freed += freed;
            remaining = remaining.saturating_sub(freed);
            
            log::trace!(
                "[Shrinker] {} (id={}) freed {} objects",
                entry.shrinker.name(),
                id.as_u64(),
                freed
            );
        }
        
        // グローバル統計更新
        {
            let mut stats = self.global_stats.lock();
            stats.shrink_cycles += 1;
            stats.total_objects_freed += total_freed as u64;
            stats.last_shrink_tsc = tsc;
            
            if sc.urgent {
                stats.urgent_shrinks += 1;
            }
            if total_freed == 0 {
                stats.failed_shrinks += 1;
            }
        }
        
        log::debug!("[Shrinker] Shrink cycle completed: freed {} objects", total_freed);
        
        total_freed
    }
    
    /// 特定のshrinkerのみ縮小
    pub fn shrink_one(&self, id: ShrinkerId, sc: &ShrinkControl) -> usize {
        let shrinkers = self.shrinkers.read();
        
        if let Some(entry) = shrinkers.get(&id) {
            if entry.shrinker.can_shrink() {
                let freed = entry.shrinker.scan_objects(sc);
                entry.call_count.fetch_add(1, Ordering::Relaxed);
                entry.total_freed.fetch_add(freed as u64, Ordering::Relaxed);
                return freed;
            }
        }
        
        0
    }
    
    /// 各shrinkerの統計を取得
    pub fn stats(&self) -> Vec<ShrinkerStats> {
        let sc = ShrinkControl::default();
        let shrinkers = self.shrinkers.read();
        
        shrinkers.iter().map(|(&id, entry)| {
            ShrinkerStats {
                id,
                name: String::from(entry.shrinker.name()),
                priority: entry.priority,
                countable_objects: entry.shrinker.count_objects(&sc),
                call_count: entry.call_count.load(Ordering::Relaxed),
                total_freed: entry.total_freed.load(Ordering::Relaxed),
            }
        }).collect()
    }
    
    /// グローバル統計を取得
    pub fn global_stats(&self) -> GlobalShrinkStats {
        self.global_stats.lock().clone()
    }
    
    /// 登録数を取得
    pub fn count(&self) -> usize {
        self.shrinkers.read().len()
    }
}

/// TSC読み取り
#[inline]
fn read_tsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

// グローバルマネージャ
static SHRINKER_MANAGER: ShrinkerManager = ShrinkerManager::new();

// ============================================================================
// Public API
// ============================================================================

/// Shrinker機能を初期化
pub fn init_shrinker() {
    SHRINKER_MANAGER.init();
}

/// Shrinkerを登録
pub fn shrinker_register(shrinker: &'static dyn Shrinker) -> ShrinkerId {
    SHRINKER_MANAGER.register(shrinker)
}

/// Shrinkerを登録解除
pub fn shrinker_unregister(id: ShrinkerId) {
    SHRINKER_MANAGER.unregister(id)
}

/// 縮小を実行
pub fn shrinker_shrink(sc: &ShrinkControl) -> usize {
    SHRINKER_MANAGER.shrink(sc)
}

/// 縮小可能オブジェクト数を取得
pub fn shrinker_count_all() -> usize {
    SHRINKER_MANAGER.count_all(&ShrinkControl::default())
}

/// 各shrinkerの統計を取得
pub fn shrinker_stats() -> Vec<ShrinkerStats> {
    SHRINKER_MANAGER.stats()
}

/// グローバル統計を取得
pub fn shrinker_global_stats() -> GlobalShrinkStats {
    SHRINKER_MANAGER.global_stats()
}

// ============================================================================
// Memory Pressure Notification
// ============================================================================

/// メモリ圧力レベル
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum MemoryPressureLevel {
    /// 正常
    None = 0,
    /// 低圧力（予防的回収推奨）
    Low = 1,
    /// 中圧力（積極的回収）
    Medium = 2,
    /// 高圧力（緊急回収）
    High = 3,
    /// クリティカル（OOM間近）
    Critical = 4,
}

/// メモリ圧力イベント
#[derive(Debug, Clone, Copy)]
pub struct MemoryPressureEvent {
    /// 圧力レベル
    pub level: MemoryPressureLevel,
    /// 空きメモリ（ページ数）
    pub free_pages: u64,
    /// 利用可能メモリ（ページ数）
    pub available_pages: u64,
    /// イベントタイムスタンプ
    pub timestamp: u64,
}

/// メモリ圧力コールバック
pub trait MemoryPressureCallback: Send + Sync {
    /// 圧力変化通知
    fn on_pressure_change(&self, event: MemoryPressureEvent);
    
    /// 即座に反応する最低レベル
    fn min_level(&self) -> MemoryPressureLevel {
        MemoryPressureLevel::Low
    }
}

/// Memory Pressure Monitor
pub struct MemoryPressureMonitor {
    /// 現在の圧力レベル
    current_level: AtomicU8,
    /// コールバック一覧
    callbacks: RwLock<Vec<&'static dyn MemoryPressureCallback>>,
    /// 閾値設定（空きページ数）
    thresholds: RwLock<PressureThresholds>,
    /// 最後のチェック時刻
    last_check_tsc: AtomicU64,
    /// 初期化済み
    initialized: AtomicU8,
}

/// 圧力閾値設定
#[derive(Debug, Clone)]
pub struct PressureThresholds {
    /// 低圧力閾値（空きページがこれ以下で低圧力）
    pub low_threshold: u64,
    /// 中圧力閾値
    pub medium_threshold: u64,
    /// 高圧力閾値
    pub high_threshold: u64,
    /// クリティカル閾値
    pub critical_threshold: u64,
}

impl Default for PressureThresholds {
    fn default() -> Self {
        // デフォルト: 256MB, 128MB, 64MB, 32MB
        Self {
            low_threshold: 65536,     // 256MB
            medium_threshold: 32768,  // 128MB
            high_threshold: 16384,    // 64MB
            critical_threshold: 8192, // 32MB
        }
    }
}

impl MemoryPressureMonitor {
    pub const fn new() -> Self {
        Self {
            current_level: AtomicU8::new(MemoryPressureLevel::None as u8),
            callbacks: RwLock::new(Vec::new()),
            thresholds: RwLock::new(PressureThresholds {
                low_threshold: 65536,
                medium_threshold: 32768,
                high_threshold: 16384,
                critical_threshold: 8192,
            }),
            last_check_tsc: AtomicU64::new(0),
            initialized: AtomicU8::new(0),
        }
    }
    
    /// 初期化
    pub fn init(&self) {
        if self.initialized.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            log::info!("[MemPressure] Memory pressure monitor initialized");
        }
    }
    
    /// 閾値を設定
    pub fn set_thresholds(&self, thresholds: PressureThresholds) {
        let mut t = self.thresholds.write();
        *t = thresholds;
    }
    
    /// コールバックを登録
    pub fn register_callback(&self, callback: &'static dyn MemoryPressureCallback) {
        let mut callbacks = self.callbacks.write();
        callbacks.push(callback);
    }
    
    /// 現在の圧力レベルを取得
    pub fn current_level(&self) -> MemoryPressureLevel {
        match self.current_level.load(Ordering::Acquire) {
            0 => MemoryPressureLevel::None,
            1 => MemoryPressureLevel::Low,
            2 => MemoryPressureLevel::Medium,
            3 => MemoryPressureLevel::High,
            _ => MemoryPressureLevel::Critical,
        }
    }
    
    /// メモリ状態を更新（定期的に呼び出し）
    pub fn update(&self, free_pages: u64, available_pages: u64) {
        let thresholds = self.thresholds.read();
        
        let new_level = if free_pages <= thresholds.critical_threshold {
            MemoryPressureLevel::Critical
        } else if free_pages <= thresholds.high_threshold {
            MemoryPressureLevel::High
        } else if free_pages <= thresholds.medium_threshold {
            MemoryPressureLevel::Medium
        } else if free_pages <= thresholds.low_threshold {
            MemoryPressureLevel::Low
        } else {
            MemoryPressureLevel::None
        };
        
        drop(thresholds);
        
        let old_level = self.current_level();
        
        if new_level != old_level {
            self.current_level.store(new_level as u8, Ordering::Release);
            
            let event = MemoryPressureEvent {
                level: new_level,
                free_pages,
                available_pages,
                timestamp: read_tsc(),
            };
            
            // コールバック通知
            let callbacks = self.callbacks.read();
            for cb in callbacks.iter() {
                if new_level >= cb.min_level() {
                    cb.on_pressure_change(event);
                }
            }
            
            log::debug!(
                "[MemPressure] Level changed: {:?} -> {:?} (free={} pages)",
                old_level, new_level, free_pages
            );
            
            // 圧力が高い場合は自動的にshrinkerを呼び出し
            if new_level >= MemoryPressureLevel::Medium {
                let mut sc = ShrinkControl::default();
                sc.urgent = new_level >= MemoryPressureLevel::High;
                sc.nr_to_scan = match new_level {
                    MemoryPressureLevel::Medium => 256,
                    MemoryPressureLevel::High => 512,
                    MemoryPressureLevel::Critical => 1024,
                    _ => 128,
                };
                
                let freed = shrinker_shrink(&sc);
                log::debug!("[MemPressure] Auto-shrink freed {} objects", freed);
            }
        }
        
        self.last_check_tsc.store(read_tsc(), Ordering::Release);
    }
    
    /// 圧力レベルを数値で取得（0-100）
    pub fn pressure_percent(&self) -> u8 {
        match self.current_level() {
            MemoryPressureLevel::None => 0,
            MemoryPressureLevel::Low => 25,
            MemoryPressureLevel::Medium => 50,
            MemoryPressureLevel::High => 75,
            MemoryPressureLevel::Critical => 100,
        }
    }
}

// グローバルモニター
static PRESSURE_MONITOR: MemoryPressureMonitor = MemoryPressureMonitor::new();

// ============================================================================
// Pressure Public API
// ============================================================================

/// メモリ圧力モニターを初期化
pub fn init_pressure_monitor() {
    PRESSURE_MONITOR.init();
}

/// 圧力閾値を設定
pub fn pressure_set_thresholds(thresholds: PressureThresholds) {
    PRESSURE_MONITOR.set_thresholds(thresholds);
}

/// コールバックを登録
pub fn pressure_register_callback(callback: &'static dyn MemoryPressureCallback) {
    PRESSURE_MONITOR.register_callback(callback);
}

/// 現在の圧力レベルを取得
pub fn pressure_current_level() -> MemoryPressureLevel {
    PRESSURE_MONITOR.current_level()
}

/// メモリ状態を更新
pub fn pressure_update(free_pages: u64, available_pages: u64) {
    PRESSURE_MONITOR.update(free_pages, available_pages);
}

/// 圧力をパーセントで取得
pub fn pressure_percent() -> u8 {
    PRESSURE_MONITOR.pressure_percent()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_priority_ordering() {
        assert!(ShrinkerPriority::Lowest < ShrinkerPriority::Low);
        assert!(ShrinkerPriority::Low < ShrinkerPriority::Normal);
        assert!(ShrinkerPriority::Normal < ShrinkerPriority::High);
    }
    
    #[test]
    fn test_pressure_levels() {
        assert!(MemoryPressureLevel::None < MemoryPressureLevel::Low);
        assert!(MemoryPressureLevel::High < MemoryPressureLevel::Critical);
    }
}
