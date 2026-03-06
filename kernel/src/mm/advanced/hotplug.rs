// ============================================================================
// Memory Hotplug Support
// 動的メモリ追加/削除のための基盤
// ============================================================================
//!
//! # Memory Hotplug Architecture
//!
//! ## 設計原則
//! - メモリブロック単位での追加/削除（通常128MB単位）
//! - NUMA対応: 追加メモリは適切なノードに配置
//! - 段階的なオフライン: ページマイグレーションを用いた安全な削除
//!
//! ## 状態遷移
//! ```text
//! OFFLINE -> GOING_ONLINE -> ONLINE -> GOING_OFFLINE -> OFFLINE
//!               ↓                           ↓
//!          (初期化)                    (マイグレーション)
//! ```

#![allow(dead_code)]
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use spin::RwLock;

use crate::mm::types::PAGE_SIZE_4K;
use crate::mm::types::{FrameIndex, NumaNodeId};

/// メモリブロックサイズ（128MB = デフォルトのhotplug単位）
pub const MEMORY_BLOCK_SIZE: usize = 128 * 1024 * 1024;

/// メモリブロックあたりのページ数
pub const PAGES_PER_BLOCK: usize = MEMORY_BLOCK_SIZE / PAGE_SIZE_4K;

/// メモリブロック状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MemoryBlockState {
    /// オフライン（未初期化または削除済み）
    Offline = 0,
    /// オンライン化進行中
    GoingOnline = 1,
    /// オンライン（使用可能）
    Online = 2,
    /// オフライン化進行中
    GoingOffline = 3,
    /// オフライン失敗（リトライ可能）
    OfflineFailed = 4,
}

impl From<u8> for MemoryBlockState {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Offline,
            1 => Self::GoingOnline,
            2 => Self::Online,
            3 => Self::GoingOffline,
            4 => Self::OfflineFailed,
            _ => Self::Offline,
        }
    }
}

/// メモリブロック情報
#[derive(Debug)]
pub struct MemoryBlock {
    /// ブロックID
    pub block_id: u64,
    /// 開始物理アドレス
    pub start_addr: u64,
    /// サイズ（バイト）
    pub size: usize,
    /// 所属NUMAノード
    pub numa_node: NumaNodeId,
    /// 現在の状態
    state: AtomicU8,
    /// ブロック内のページ数
    pub total_pages: usize,
    /// 使用中のページ数
    used_pages: AtomicU64,
    /// オンライン完了タイムスタンプ（TSC）
    online_timestamp: AtomicU64,
}

impl MemoryBlock {
    /// 新しいメモリブロックを作成
    pub fn new(block_id: u64, start_addr: u64, size: usize, numa_node: NumaNodeId) -> Self {
        let total_pages = size / PAGE_SIZE_4K;
        Self {
            block_id,
            start_addr,
            size,
            numa_node,
            state: AtomicU8::new(MemoryBlockState::Offline as u8),
            total_pages,
            used_pages: AtomicU64::new(0),
            online_timestamp: AtomicU64::new(0),
        }
    }

    /// 状態を取得
    pub fn state(&self) -> MemoryBlockState {
        MemoryBlockState::from(self.state.load(Ordering::Acquire))
    }

    /// 状態をセット
    fn set_state(&self, state: MemoryBlockState) {
        self.state.store(state as u8, Ordering::Release);
    }

    /// 使用中ページ数を取得
    pub fn used_pages(&self) -> u64 {
        self.used_pages.load(Ordering::Relaxed)
    }

    /// 空きページ率を取得（0.0 - 1.0）
    pub fn free_ratio(&self) -> f64 {
        let used = self.used_pages() as f64;
        let total = self.total_pages as f64;
        1.0 - (used / total)
    }

    /// このブロックがオフライン可能か
    pub fn can_offline(&self) -> bool {
        self.state() == MemoryBlockState::Online
    }

    /// ブロック内のフレーム範囲を取得
    pub fn frame_range(&self) -> (FrameIndex, FrameIndex) {
        let start = FrameIndex::new(self.start_addr as usize / PAGE_SIZE_4K);
        let end = FrameIndex::new((self.start_addr as usize + self.size) / PAGE_SIZE_4K);
        (start, end)
    }
}

/// Hotplugイベント種別
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugEvent {
    /// メモリ追加通知
    MemoryAdded { block_id: u64 },
    /// メモリ削除予定通知
    MemoryGoingOffline { block_id: u64 },
    /// メモリ削除完了通知
    MemoryRemoved { block_id: u64 },
    /// オフライン失敗
    OfflineFailed {
        block_id: u64,
        reason: OfflineFailReason,
    },
}

/// オフライン失敗理由
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineFailReason {
    /// 固定メモリ（mlockされた領域等）
    PinnedMemory,
    /// カーネル使用中
    KernelReserved,
    /// DMAバッファ使用中
    DmaInUse,
    /// マイグレーション失敗
    MigrationFailed,
    /// タイムアウト
    Timeout,
}

/// Hotplugコールバック trait
pub trait HotplugCallback: Send + Sync {
    /// イベント通知
    fn on_hotplug_event(&self, event: HotplugEvent);

    /// オフライン可否の確認（falseを返すとオフライン拒否）
    fn can_offline(&self, block_id: u64) -> bool;
}

/// Hotplug統計情報
#[derive(Debug, Default, Clone)]
pub struct HotplugStats {
    /// オンラインブロック数
    pub online_blocks: usize,
    /// オフラインブロック数
    pub offline_blocks: usize,
    /// 総オンラインメモリ（バイト）
    pub total_online_memory: u64,
    /// 追加成功回数
    pub add_success_count: u64,
    /// 削除成功回数
    pub remove_success_count: u64,
    /// 削除失敗回数
    pub remove_fail_count: u64,
    /// 進行中の操作
    pub pending_operations: usize,
}

/// Memory Hotplug Manager
pub struct HotplugManager {
    /// ブロック一覧（ブロックID -> メモリブロック）
    blocks: RwLock<BTreeMap<u64, MemoryBlock>>,
    /// コールバック一覧
    callbacks: RwLock<Vec<&'static dyn HotplugCallback>>,
    /// 統計情報
    stats: RwLock<HotplugStats>,
    /// 次のブロックID
    next_block_id: AtomicU64,
    /// 初期化済みフラグ
    initialized: AtomicU8,
}

impl HotplugManager {
    /// 新しいHotplugManagerを作成
    pub const fn new() -> Self {
        Self {
            blocks: RwLock::new(BTreeMap::new()),
            callbacks: RwLock::new(Vec::new()),
            stats: RwLock::new(HotplugStats {
                online_blocks: 0,
                offline_blocks: 0,
                total_online_memory: 0,
                add_success_count: 0,
                remove_success_count: 0,
                remove_fail_count: 0,
                pending_operations: 0,
            }),
            next_block_id: AtomicU64::new(0),
            initialized: AtomicU8::new(0),
        }
    }

    /// 初期化
    pub fn init(&self) {
        if self
            .initialized
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            log::info!("[Hotplug] Memory hotplug manager initialized");
        }
    }

    /// コールバックを登録
    pub fn register_callback(&self, callback: &'static dyn HotplugCallback) {
        let mut callbacks = self.callbacks.write();
        callbacks.push(callback);
    }

    /// メモリブロックを追加（オンライン化）
    pub fn add_memory_block(
        &self,
        start_addr: u64,
        size: usize,
        numa_node: NumaNodeId,
    ) -> Result<u64, HotplugError> {
        // アドレスアライメントチェック
        if start_addr as usize % MEMORY_BLOCK_SIZE != 0 {
            return Err(HotplugError::InvalidAlignment);
        }

        // サイズチェック
        if size < MEMORY_BLOCK_SIZE {
            return Err(HotplugError::InvalidSize);
        }

        // 重複チェック
        {
            let blocks = self.blocks.read();
            for block in blocks.values() {
                let block_end = block.start_addr + block.size as u64;
                let new_end = start_addr + size as u64;

                if start_addr < block_end && new_end > block.start_addr {
                    return Err(HotplugError::OverlappingRegion);
                }
            }
        }

        let block_id = self.next_block_id.fetch_add(1, Ordering::Relaxed);
        let block = MemoryBlock::new(block_id, start_addr, size, numa_node);

        // 状態をGOING_ONLINEに変更
        block.set_state(MemoryBlockState::GoingOnline);

        // ブロック追加
        {
            let mut blocks = self.blocks.write();
            blocks.insert(block_id, block);
        }

        // 統計更新
        {
            let mut stats = self.stats.write();
            stats.pending_operations += 1;
        }

        // PMM（Physical Memory Manager）に通知してフレームを登録
        // この部分は実際のPMM実装と連携する
        self.online_block_internal(block_id)?;

        // コールバック通知
        let callbacks = self.callbacks.read();
        for cb in callbacks.iter() {
            cb.on_hotplug_event(HotplugEvent::MemoryAdded { block_id });
        }

        // 統計更新
        {
            let mut stats = self.stats.write();
            stats.online_blocks += 1;
            stats.total_online_memory += size as u64;
            stats.add_success_count += 1;
            stats.pending_operations = stats.pending_operations.saturating_sub(1);
        }

        log::info!(
            "[Hotplug] Memory block {} added: addr=0x{:x}, size={}MB, node={}",
            block_id,
            start_addr,
            size / (1024 * 1024),
            numa_node.as_u8()
        );

        Ok(block_id)
    }

    /// ブロック内部のオンライン処理
    fn online_block_internal(&self, block_id: u64) -> Result<(), HotplugError> {
        let blocks = self.blocks.read();
        let block = blocks.get(&block_id).ok_or(HotplugError::BlockNotFound)?;

        // ゼロクリアを非同期でスケジュール
        // 実際はフレームアロケータへの登録を行う
        let (_start_frame, _end_frame) = block.frame_range();

        // ここでbuddy_register_numa_regionを呼び出す
        // 今回は基盤のみなのでTODOとして残す

        // 状態をONLINEに変更
        block.set_state(MemoryBlockState::Online);
        block.online_timestamp.store(read_tsc(), Ordering::Release);

        Ok(())
    }

    /// メモリブロックを削除（オフライン化）
    fn handle_offline_success(&self, block_id: u64) {
        let size = {
            let mut blocks = self.blocks.write();
            blocks.remove(&block_id).map(|b| b.size).unwrap_or(0)
        };

        {
            let mut stats = self.stats.write();
            stats.online_blocks = stats.online_blocks.saturating_sub(1);
            stats.offline_blocks += 1;
            stats.total_online_memory = stats.total_online_memory.saturating_sub(size as u64);
            stats.remove_success_count += 1;
            stats.pending_operations = stats.pending_operations.saturating_sub(1);
        }

        let callbacks = self.callbacks.read();
        for cb in callbacks.iter() {
            cb.on_hotplug_event(HotplugEvent::MemoryRemoved { block_id });
        }

        log::info!("[Hotplug] Memory block {} removed", block_id);
    }

    fn handle_offline_failure(&self, block_id: u64, e: &HotplugError) {
        {
            let blocks = self.blocks.read();
            if let Some(block) = blocks.get(&block_id) {
                block.set_state(MemoryBlockState::OfflineFailed);
            }
        }

        {
            let mut stats = self.stats.write();
            stats.remove_fail_count += 1;
            stats.pending_operations = stats.pending_operations.saturating_sub(1);
        }

        let callbacks = self.callbacks.read();
        let reason = match e {
            HotplugError::PinnedPages => OfflineFailReason::PinnedMemory,
            HotplugError::MigrationFailed => OfflineFailReason::MigrationFailed,
            _ => OfflineFailReason::KernelReserved,
        };
        for cb in callbacks.iter() {
            cb.on_hotplug_event(HotplugEvent::OfflineFailed { block_id, reason });
        }

        log::warn!(
            "[Hotplug] Memory block {} offline failed: {:?}",
            block_id,
            e
        );
    }

    pub fn remove_memory_block(&self, block_id: u64) -> Result<(), HotplugError> {
        // ブロック存在チェック
        {
            let blocks = self.blocks.read();
            let block = blocks.get(&block_id).ok_or(HotplugError::BlockNotFound)?;

            if !block.can_offline() {
                return Err(HotplugError::BlockBusy);
            }
        }

        // コールバックでオフライン可否を確認
        {
            let callbacks = self.callbacks.read();
            for cb in callbacks.iter() {
                if !cb.can_offline(block_id) {
                    return Err(HotplugError::OfflineRejected);
                }
            }
        }

        // 状態をGOING_OFFLINEに変更
        {
            let blocks = self.blocks.read();
            if let Some(block) = blocks.get(&block_id) {
                block.set_state(MemoryBlockState::GoingOffline);
            }
        }

        // 統計更新
        {
            let mut stats = self.stats.write();
            stats.pending_operations += 1;
        }

        // コールバック通知
        {
            let callbacks = self.callbacks.read();
            for cb in callbacks.iter() {
                cb.on_hotplug_event(HotplugEvent::MemoryGoingOffline { block_id });
            }
        }

        // オフライン処理を実行
        match self.offline_block_internal(block_id) {
            Ok(()) => {
                self.handle_offline_success(block_id);
                Ok(())
            }
            Err(e) => {
                self.handle_offline_failure(block_id, &e);
                Err(e)
            }
        }
    }

    /// ブロック内部のオフライン処理
    fn offline_block_internal(&self, block_id: u64) -> Result<(), HotplugError> {
        let blocks = self.blocks.read();
        let block = blocks.get(&block_id).ok_or(HotplugError::BlockNotFound)?;

        let (start_frame, end_frame) = block.frame_range();

        // ページマイグレーション試行
        // 各ページを他のメモリブロックに移動する
        for frame_idx in start_frame.as_usize()..end_frame.as_usize() {
            let frame = FrameIndex::new(frame_idx);

            // ページが使用中かチェック
            if self.is_frame_in_use(frame) {
                // マイグレーション試行
                if !self.try_migrate_frame(frame, block.numa_node) {
                    // マイグレーション失敗
                    return Err(HotplugError::MigrationFailed);
                }
            }
        }

        // PMM（Physical Memory Manager）からフレームを登録解除
        // この部分は実際のPMM実装と連携する

        Ok(())
    }

    /// フレームが使用中かチェック
    fn is_frame_in_use(&self, _frame: FrameIndex) -> bool {
        // TODO: 実際のPMM実装と連携
        // 現在は常にfalse（未使用）を返す
        false
    }

    /// フレームのマイグレーション試行
    fn try_migrate_frame(&self, _frame: FrameIndex, _numa_node: NumaNodeId) -> bool {
        // TODO: autonuma::migrate_numa_page と連携
        // 現在は常にtrue（成功）を返す
        true
    }

    /// ブロック情報を取得
    pub fn get_block_info(&self, block_id: u64) -> Option<MemoryBlockInfo> {
        let blocks = self.blocks.read();
        blocks.get(&block_id).map(|b| MemoryBlockInfo {
            block_id: b.block_id,
            start_addr: b.start_addr,
            size: b.size,
            numa_node: b.numa_node,
            state: b.state(),
            total_pages: b.total_pages,
            used_pages: b.used_pages(),
            free_ratio: b.free_ratio(),
        })
    }

    /// 全ブロックの一覧を取得
    pub fn list_blocks(&self) -> Vec<MemoryBlockInfo> {
        let blocks = self.blocks.read();
        blocks
            .values()
            .map(|b| MemoryBlockInfo {
                block_id: b.block_id,
                start_addr: b.start_addr,
                size: b.size,
                numa_node: b.numa_node,
                state: b.state(),
                total_pages: b.total_pages,
                used_pages: b.used_pages(),
                free_ratio: b.free_ratio(),
            })
            .collect()
    }

    /// 統計情報を取得
    pub fn stats(&self) -> HotplugStats {
        self.stats.read().clone()
    }

    /// 特定NUMAノードのオンラインメモリ合計を取得
    pub fn online_memory_on_node(&self, numa_node: NumaNodeId) -> u64 {
        let blocks = self.blocks.read();
        blocks
            .values()
            .filter(|b| b.numa_node == numa_node && b.state() == MemoryBlockState::Online)
            .map(|b| b.size as u64)
            .sum()
    }

    /// オフライン失敗したブロックをリトライ
    pub fn retry_failed_offline(&self, block_id: u64) -> Result<(), HotplugError> {
        // 状態チェック
        {
            let blocks = self.blocks.read();
            let block = blocks.get(&block_id).ok_or(HotplugError::BlockNotFound)?;

            if block.state() != MemoryBlockState::OfflineFailed {
                return Err(HotplugError::InvalidState);
            }

            // 状態をONLINEに戻す
            block.set_state(MemoryBlockState::Online);
        }

        // 再度オフライン試行
        self.remove_memory_block(block_id)
    }
}

/// ブロック情報（読み取り用）
#[derive(Debug, Clone)]
pub struct MemoryBlockInfo {
    pub block_id: u64,
    pub start_addr: u64,
    pub size: usize,
    pub numa_node: NumaNodeId,
    pub state: MemoryBlockState,
    pub total_pages: usize,
    pub used_pages: u64,
    pub free_ratio: f64,
}

/// Hotplugエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugError {
    /// アドレスアライメントエラー
    InvalidAlignment,
    /// サイズエラー
    InvalidSize,
    /// ブロックが見つからない
    BlockNotFound,
    /// ブロックがビジー
    BlockBusy,
    /// 領域が重複
    OverlappingRegion,
    /// オフラインが拒否された
    OfflineRejected,
    /// マイグレーション失敗
    MigrationFailed,
    /// 固定ページあり
    PinnedPages,
    /// 不正な状態
    InvalidState,
    /// 内部エラー
    InternalError,
}

// グローバルマネージャ
static HOTPLUG_MANAGER: HotplugManager = HotplugManager::new();

/// TSC読み取り
#[inline]
fn read_tsc() -> u64 {
    crate::time::rdtsc_unserialized()
}

// ============================================================================
// Public API
// ============================================================================

/// Hotplug機能を初期化
pub fn init_hotplug() {
    HOTPLUG_MANAGER.init();
}

/// メモリブロックを追加
pub fn hotplug_add_memory(
    start_addr: u64,
    size: usize,
    numa_node: NumaNodeId,
) -> Result<u64, HotplugError> {
    HOTPLUG_MANAGER.add_memory_block(start_addr, size, numa_node)
}

/// メモリブロックを削除
pub fn hotplug_remove_memory(block_id: u64) -> Result<(), HotplugError> {
    HOTPLUG_MANAGER.remove_memory_block(block_id)
}

/// ブロック情報を取得
pub fn hotplug_block_info(block_id: u64) -> Option<MemoryBlockInfo> {
    HOTPLUG_MANAGER.get_block_info(block_id)
}

/// 全ブロック一覧を取得
pub fn hotplug_list_blocks() -> Vec<MemoryBlockInfo> {
    HOTPLUG_MANAGER.list_blocks()
}

/// Hotplug統計を取得
pub fn hotplug_stats() -> HotplugStats {
    HOTPLUG_MANAGER.stats()
}

/// コールバックを登録
pub fn hotplug_register_callback(callback: &'static dyn HotplugCallback) {
    HOTPLUG_MANAGER.register_callback(callback);
}

/// 特定NUMAノードのオンラインメモリを取得
pub fn hotplug_online_memory_on_node(numa_node: NumaNodeId) -> u64 {
    HOTPLUG_MANAGER.online_memory_on_node(numa_node)
}

/// オフライン失敗ブロックをリトライ
pub fn hotplug_retry_offline(block_id: u64) -> Result<(), HotplugError> {
    HOTPLUG_MANAGER.retry_failed_offline(block_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_memory_block_state() {
        let block = MemoryBlock::new(0, 0, MEMORY_BLOCK_SIZE, NumaNodeId::new(0));
        assert_eq!(block.state(), MemoryBlockState::Offline);

        block.set_state(MemoryBlockState::Online);
        assert_eq!(block.state(), MemoryBlockState::Online);
    }

    #[test_case]
    fn test_frame_range() {
        let block = MemoryBlock::new(0, 0x1000_0000, MEMORY_BLOCK_SIZE, NumaNodeId::new(0));
        let (start, end) = block.frame_range();

        assert_eq!(start.as_usize(), 0x1000_0000 / PAGE_SIZE_4K);
        assert_eq!(
            end.as_usize(),
            (0x1000_0000 + MEMORY_BLOCK_SIZE) / PAGE_SIZE_4K
        );
    }
}
