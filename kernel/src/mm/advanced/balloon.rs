// ============================================================================
// Memory Ballooning Support
// 仮想環境でのメモリ動的調整機構
// ============================================================================
//!
//! # Memory Ballooning Architecture
//!
//! ## 概要
//! バルーニングは仮想環境でゲストOSからホストOSにメモリを返却（または取得）する機構。
//! バルーンドライバがページを「膨らませる」（inflate）とそのメモリはホストに返却され、
//! 「しぼませる」（deflate）とゲストに返却される。
//!
//! ## 設計原則
//! - 段階的な膨張/収縮: 一度に大量のメモリを操作しない
//! - 優先度ベース: 低優先度のページから回収
//! - キャンセル可能: メモリ圧迫時は膨張を停止
//!
//! ## 状態
//! ```text
//! IDLE -> INFLATING -> IDLE
//!          ↓
//!       (圧力検出)
//!          ↓
//!       DEFLATING
//! ```

#![allow(dead_code)]
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

use crate::mm::types::{FrameIndex, NumaNodeId};
use crate::mm::types::PAGE_SIZE_4K;

/// バルーン状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BalloonState {
    /// アイドル状態
    Idle = 0,
    /// 膨張中（メモリをホストに返却中）
    Inflating = 1,
    /// 収縮中（メモリをゲストに取得中）
    Deflating = 2,
    /// 一時停止
    Suspended = 3,
}

impl From<u8> for BalloonState {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Idle,
            1 => Self::Inflating,
            2 => Self::Deflating,
            3 => Self::Suspended,
            _ => Self::Idle,
        }
    }
}

/// バルーン設定
#[derive(Debug, Clone)]
pub struct BalloonConfig {
    /// 目標サイズ（ページ数）
    pub target_pages: usize,
    /// 最小保持ページ数（これ以下には縮小しない）
    pub min_pages: usize,
    /// 最大サイズ（ページ数）
    pub max_pages: usize,
    /// 1回の膨張/収縮で操作するページ数
    pub batch_size: usize,
    /// 膨張間隔（ミリ秒）
    pub inflate_interval_ms: u64,
    /// メモリ圧力閾値（これを超えると収縮）
    pub pressure_threshold: f64,
    /// 自動調整有効
    pub auto_adjust: bool,
}

impl Default for BalloonConfig {
    fn default() -> Self {
        Self {
            target_pages: 0,
            min_pages: 1024,       // 最低4MB保持
            max_pages: 256 * 1024, // 最大1GB
            batch_size: 256,       // 1MBずつ
            inflate_interval_ms: 100,
            pressure_threshold: 0.8, // 80%使用率で収縮開始
            auto_adjust: false,
        }
    }
}

/// バルーン統計
#[derive(Debug, Default, Clone)]
pub struct BalloonStats {
    /// 現在のバルーンサイズ（ページ数）
    pub current_pages: usize,
    /// 膨張回数
    pub inflate_count: u64,
    /// 収縮回数
    pub deflate_count: u64,
    /// 膨張で返却したページ総数
    pub total_inflated: u64,
    /// 収縮で取得したページ総数
    pub total_deflated: u64,
    /// メモリ圧力による強制収縮回数
    pub pressure_deflates: u64,
    /// 最後の操作タイムスタンプ
    pub last_operation_tsc: u64,
}

/// バルーンページエントリ
#[derive(Debug, Clone, Copy)]
struct BalloonPage {
    /// フレームインデックス
    frame: FrameIndex,
    /// 所属NUMAノード
    numa_node: NumaNodeId,
    /// 追加タイムスタンプ
    added_tsc: u64,
}

/// バルーンイベント
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalloonEvent {
    /// 目標サイズ変更
    TargetChanged { old: usize, new: usize },
    /// 膨張完了
    InflateComplete { pages: usize },
    /// 収縮完了
    DeflateComplete { pages: usize },
    /// メモリ圧力検出
    PressureDetected { level: u8 },
    /// 操作キャンセル
    OperationCancelled,
}

/// バルーンコールバック trait
pub trait BalloonCallback: Send + Sync {
    /// イベント通知
    fn on_balloon_event(&self, event: BalloonEvent);
    
    /// メモリ圧力レベルを取得（0-100）
    fn get_memory_pressure(&self) -> u8;
}

/// Memory Balloon Manager
pub struct BalloonManager {
    /// バルーン内のページ一覧
    pages: RwLock<Vec<BalloonPage>>,
    /// 設定
    config: RwLock<BalloonConfig>,
    /// 状態
    state: AtomicU8,
    /// 統計
    stats: Mutex<BalloonStats>,
    /// コールバック
    callback: RwLock<Option<&'static dyn BalloonCallback>>,
    /// 初期化済み
    initialized: AtomicU8,
    /// 操作カウンタ
    operation_counter: AtomicU64,
}

impl BalloonManager {
    /// 新しいBalloonManagerを作成
    pub const fn new() -> Self {
        Self {
            pages: RwLock::new(Vec::new()),
            config: RwLock::new(BalloonConfig {
                target_pages: 0,
                min_pages: 1024,
                max_pages: 256 * 1024,
                batch_size: 256,
                inflate_interval_ms: 100,
                pressure_threshold: 0.8,
                auto_adjust: false,
            }),
            state: AtomicU8::new(BalloonState::Idle as u8),
            stats: Mutex::new(BalloonStats {
                current_pages: 0,
                inflate_count: 0,
                deflate_count: 0,
                total_inflated: 0,
                total_deflated: 0,
                pressure_deflates: 0,
                last_operation_tsc: 0,
            }),
            callback: RwLock::new(None),
            initialized: AtomicU8::new(0),
            operation_counter: AtomicU64::new(0),
        }
    }
    
    /// 初期化
    pub fn init(&self) {
        if self.initialized.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            log::info!("[Balloon] Memory balloon manager initialized");
        }
    }
    
    /// コールバックを設定
    pub fn set_callback(&self, callback: &'static dyn BalloonCallback) {
        let mut cb = self.callback.write();
        *cb = Some(callback);
    }
    
    /// 設定を更新
    pub fn update_config(&self, config: BalloonConfig) {
        let mut cfg = self.config.write();
        *cfg = config;
    }
    
    /// 目標サイズを設定
    pub fn set_target(&self, target_pages: usize) -> Result<(), BalloonError> {
        let mut config = self.config.write();
        let old = config.target_pages;
        
        if target_pages > config.max_pages {
            return Err(BalloonError::TargetTooLarge);
        }
        
        config.target_pages = target_pages;
        
        // コールバック通知
        if let Some(cb) = self.callback.read().as_ref() {
            cb.on_balloon_event(BalloonEvent::TargetChanged {
                old,
                new: target_pages,
            });
        }
        
        log::debug!("[Balloon] Target changed: {} -> {} pages", old, target_pages);
        
        Ok(())
    }
    
    /// 状態を取得
    pub fn state(&self) -> BalloonState {
        BalloonState::from(self.state.load(Ordering::Acquire))
    }
    
    /// 現在のサイズを取得（ページ数）
    pub fn current_size(&self) -> usize {
        self.pages.read().len()
    }
    
    /// バルーンを膨張（メモリをホストに返却）
    pub fn inflate(&self, num_pages: usize) -> Result<usize, BalloonError> {
        // 状態チェック
        if self.state() != BalloonState::Idle {
            return Err(BalloonError::Busy);
        }
        
        // メモリ圧力チェック
        if let Some(cb) = self.callback.read().as_ref() {
            let pressure = cb.get_memory_pressure();
            let config = self.config.read();
            if (pressure as f64 / 100.0) > config.pressure_threshold {
                log::warn!("[Balloon] Inflate aborted due to memory pressure: {}%", pressure);
                return Err(BalloonError::MemoryPressure);
            }
        }
        
        // 状態を膨張中に
        self.state.store(BalloonState::Inflating as u8, Ordering::Release);
        
        let config = self.config.read();
        let actual_pages = num_pages.min(config.batch_size);
        let max_allowed = config.max_pages.saturating_sub(self.current_size());
        let pages_to_inflate = actual_pages.min(max_allowed);
        
        drop(config);
        
        let mut inflated = 0;
        let tsc = read_tsc();
        
        for _ in 0..pages_to_inflate {
            // フレームアロケータからページを取得
            match self.alloc_balloon_page() {
                Some((frame, numa_node)) => {
                    let entry = BalloonPage {
                        frame,
                        numa_node,
                        added_tsc: tsc,
                    };
                    
                    let mut pages = self.pages.write();
                    pages.push(entry);
                    inflated += 1;
                }
                None => {
                    // メモリ不足
                    break;
                }
            }
        }
        
        // 統計更新
        {
            let mut stats = self.stats.lock();
            stats.current_pages = self.pages.read().len();
            stats.inflate_count += 1;
            stats.total_inflated += inflated as u64;
            stats.last_operation_tsc = tsc;
        }
        
        // 状態をアイドルに戻す
        self.state.store(BalloonState::Idle as u8, Ordering::Release);
        
        // コールバック通知
        if let Some(cb) = self.callback.read().as_ref() {
            cb.on_balloon_event(BalloonEvent::InflateComplete { pages: inflated });
        }
        
        log::debug!("[Balloon] Inflated {} pages (total: {})", inflated, self.current_size());
        
        Ok(inflated)
    }
    
    /// バルーンを収縮（メモリをゲストに取得）
    pub fn deflate(&self, num_pages: usize) -> Result<usize, BalloonError> {
        // 状態チェック
        if self.state() != BalloonState::Idle {
            return Err(BalloonError::Busy);
        }
        
        // 状態を収縮中に
        self.state.store(BalloonState::Deflating as u8, Ordering::Release);
        
        let config = self.config.read();
        let actual_pages = num_pages.min(config.batch_size);
        let current = self.current_size();
        let min_pages = config.min_pages;
        let pages_to_deflate = actual_pages.min(current.saturating_sub(min_pages));
        
        drop(config);
        
        let mut deflated = 0;
        let tsc = read_tsc();
        
        for _ in 0..pages_to_deflate {
            let mut pages = self.pages.write();
            if let Some(entry) = pages.pop() {
                drop(pages);
                
                // フレームアロケータにページを返却
                self.free_balloon_page(entry.frame);
                deflated += 1;
            } else {
                break;
            }
        }
        
        // 統計更新
        {
            let mut stats = self.stats.lock();
            stats.current_pages = self.pages.read().len();
            stats.deflate_count += 1;
            stats.total_deflated += deflated as u64;
            stats.last_operation_tsc = tsc;
        }
        
        // 状態をアイドルに戻す
        self.state.store(BalloonState::Idle as u8, Ordering::Release);
        
        // コールバック通知
        if let Some(cb) = self.callback.read().as_ref() {
            cb.on_balloon_event(BalloonEvent::DeflateComplete { pages: deflated });
        }
        
        log::debug!("[Balloon] Deflated {} pages (total: {})", deflated, self.current_size());
        
        Ok(deflated)
    }
    
    /// 目標に向けて調整
    pub fn adjust_to_target(&self) -> Result<i64, BalloonError> {
        let target = self.config.read().target_pages;
        let current = self.current_size();
        
        if current < target {
            // 膨張が必要
            let needed = target - current;
            let inflated = self.inflate(needed)?;
            Ok(inflated as i64)
        } else if current > target {
            // 収縮が必要
            let excess = current - target;
            let deflated = self.deflate(excess)?;
            Ok(-(deflated as i64))
        } else {
            Ok(0)
        }
    }
    
    /// メモリ圧力に応じた自動調整（定期的に呼び出し）
    pub fn auto_adjust_tick(&self) {
        let config = self.config.read();
        if !config.auto_adjust {
            return;
        }
        
        let threshold = config.pressure_threshold;
        drop(config);
        
        // メモリ圧力を取得
        if let Some(cb) = self.callback.read().as_ref() {
            let pressure = cb.get_memory_pressure() as f64 / 100.0;
            
            if pressure > threshold && self.current_size() > 0 {
                // 圧力が高い: 収縮
                let batch = self.config.read().batch_size;
                if let Ok(deflated) = self.deflate(batch) {
                    if deflated > 0 {
                        let mut stats = self.stats.lock();
                        stats.pressure_deflates += 1;
                        
                        cb.on_balloon_event(BalloonEvent::PressureDetected {
                            level: (pressure * 100.0) as u8,
                        });
                    }
                }
            }
        }
    }
    
    /// バルーン用にページを割り当て
    fn alloc_balloon_page(&self) -> Option<(FrameIndex, NumaNodeId)> {
        // 実際のフレームアロケータと連携
        // ここではスタブ実装
        // 
        // 実際の実装:
        // match crate::mm::phys::frame_allocator::alloc_frame() {
        //     Some(frame) => Some((frame, NumaNodeId::NODE_0)),
        //     None => None,
        // }
        
        // スタブ: 常に失敗（実際のPMMと連携時に実装）
        None
    }
    
    /// バルーンページを解放
    fn free_balloon_page(&self, _frame: FrameIndex) {
        // 実際のフレームアロケータと連携
        // crate::mm::phys::frame_allocator::dealloc_frame(frame);
    }
    
    /// 統計を取得
    pub fn stats(&self) -> BalloonStats {
        self.stats.lock().clone()
    }
    
    /// NUMA別のバルーンページ数を取得
    pub fn pages_per_numa(&self) -> [usize; 16] {
        let mut counts = [0usize; 16];
        let pages = self.pages.read();
        
        for page in pages.iter() {
            let idx = page.numa_node.as_usize();
            if idx < 16 {
                counts[idx] += 1;
            }
        }
        
        counts
    }
    
    /// バルーンを一時停止
    pub fn suspend(&self) {
        self.state.store(BalloonState::Suspended as u8, Ordering::Release);
        log::info!("[Balloon] Suspended");
    }
    
    /// バルーンを再開
    pub fn resume(&self) {
        if self.state() == BalloonState::Suspended {
            self.state.store(BalloonState::Idle as u8, Ordering::Release);
            log::info!("[Balloon] Resumed");
        }
    }
    
    /// バルーンをリセット（全ページ解放）
    pub fn reset(&self) -> Result<usize, BalloonError> {
        if self.state() != BalloonState::Idle && self.state() != BalloonState::Suspended {
            return Err(BalloonError::Busy);
        }
        
        let mut pages = self.pages.write();
        let count = pages.len();
        
        // 全ページを解放
        for page in pages.drain(..) {
            self.free_balloon_page(page.frame);
        }
        
        // 統計リセット
        {
            let mut stats = self.stats.lock();
            stats.current_pages = 0;
        }
        
        log::info!("[Balloon] Reset: released {} pages", count);
        
        Ok(count)
    }
}

/// TSC読み取り
#[inline]
fn read_tsc() -> u64 {
    unsafe {
        core::arch::x86_64::_rdtsc()
    }
}

/// バルーンエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BalloonError {
    /// 目標サイズが大きすぎる
    TargetTooLarge,
    /// 操作中
    Busy,
    /// メモリ圧力が高い
    MemoryPressure,
    /// 最小サイズ制限
    MinimumReached,
    /// 内部エラー
    InternalError,
}

// グローバルマネージャ
static BALLOON_MANAGER: BalloonManager = BalloonManager::new();

// ============================================================================
// Public API
// ============================================================================

/// バルーン機能を初期化
pub fn init_balloon() {
    BALLOON_MANAGER.init();
}

/// バルーン設定を更新
pub fn balloon_update_config(config: BalloonConfig) {
    BALLOON_MANAGER.update_config(config);
}

/// バルーン目標サイズを設定
pub fn balloon_set_target(target_pages: usize) -> Result<(), BalloonError> {
    BALLOON_MANAGER.set_target(target_pages)
}

/// バルーンを膨張
pub fn balloon_inflate(pages: usize) -> Result<usize, BalloonError> {
    BALLOON_MANAGER.inflate(pages)
}

/// バルーンを収縮
pub fn balloon_deflate(pages: usize) -> Result<usize, BalloonError> {
    BALLOON_MANAGER.deflate(pages)
}

/// 目標に向けて調整
pub fn balloon_adjust() -> Result<i64, BalloonError> {
    BALLOON_MANAGER.adjust_to_target()
}

/// 自動調整ティック
pub fn balloon_auto_tick() {
    BALLOON_MANAGER.auto_adjust_tick();
}

/// バルーン状態を取得
pub fn balloon_state() -> BalloonState {
    BALLOON_MANAGER.state()
}

/// バルーンサイズを取得（ページ数）
pub fn balloon_size() -> usize {
    BALLOON_MANAGER.current_size()
}

/// バルーン統計を取得
pub fn balloon_stats() -> BalloonStats {
    BALLOON_MANAGER.stats()
}

/// コールバックを設定
pub fn balloon_set_callback(callback: &'static dyn BalloonCallback) {
    BALLOON_MANAGER.set_callback(callback);
}

/// バルーンを一時停止
pub fn balloon_suspend() {
    BALLOON_MANAGER.suspend();
}

/// バルーンを再開
pub fn balloon_resume() {
    BALLOON_MANAGER.resume();
}

/// バルーンをリセット
pub fn balloon_reset() -> Result<usize, BalloonError> {
    BALLOON_MANAGER.reset()
}

/// NUMA別バルーンページ数を取得
pub fn balloon_pages_per_numa() -> [usize; 16] {
    BALLOON_MANAGER.pages_per_numa()
}

// ============================================================================
// VirtIO Balloon Integration
// ============================================================================

/// VirtIO Balloonとの連携用trait
pub trait VirtioBalloonBackend: Send + Sync {
    /// ホストからの目標サイズ通知
    fn notify_target(&self, target_mb: u32);
    
    /// 現在のサイズをホストに報告
    fn report_size(&self, current_mb: u32);
    
    /// Free Page Hinting
    fn hint_free_pages(&self, pages: &[FrameIndex]);
}

/// VirtIO Balloon統合（将来の拡張用）
pub struct VirtioBalloonIntegration {
    backend: RwLock<Option<&'static dyn VirtioBalloonBackend>>,
}

impl VirtioBalloonIntegration {
    pub const fn new() -> Self {
        Self {
            backend: RwLock::new(None),
        }
    }
    
    pub fn set_backend(&self, backend: &'static dyn VirtioBalloonBackend) {
        let mut b = self.backend.write();
        *b = Some(backend);
    }
    
    /// ホストからの目標変更を処理
    pub fn handle_target_change(&self, target_mb: u32) {
        let target_pages = (target_mb as usize * 1024 * 1024) / PAGE_SIZE_4K;
        let _ = balloon_set_target(target_pages);
    }
    
    /// 現在のサイズをホストに報告
    pub fn report_current_size(&self) {
        let current_pages = balloon_size();
        let current_mb = (current_pages * PAGE_SIZE_4K) / (1024 * 1024);
        
        if let Some(backend) = self.backend.read().as_ref() {
            backend.report_size(current_mb as u32);
        }
    }
}

static VIRTIO_INTEGRATION: VirtioBalloonIntegration = VirtioBalloonIntegration::new();

/// VirtIOバックエンドを設定
pub fn balloon_set_virtio_backend(backend: &'static dyn VirtioBalloonBackend) {
    VIRTIO_INTEGRATION.set_backend(backend);
}

/// VirtIO目標変更を処理
pub fn balloon_handle_virtio_target(target_mb: u32) {
    VIRTIO_INTEGRATION.handle_target_change(target_mb);
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test_case]
    fn test_balloon_config() {
        let config = BalloonConfig::default();
        assert_eq!(config.min_pages, 1024);
        assert_eq!(config.batch_size, 256);
    }
    
    #[test_case]
    fn test_balloon_state() {
        assert_eq!(BalloonState::from(0), BalloonState::Idle);
        assert_eq!(BalloonState::from(1), BalloonState::Inflating);
        assert_eq!(BalloonState::from(2), BalloonState::Deflating);
    }
}

