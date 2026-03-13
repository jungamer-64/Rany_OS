// ============================================================================
// Memory Hotplug Support
// 動的メモリ追加/削除のための基盤
// ============================================================================
#![allow(dead_code)]
use crate::sync::PoisonRwLock;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

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
    Offline = 0,
    GoingOnline = 1,
    Online = 2,
    GoingOffline = 3,
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
    pub block_id: u64,
    pub start_addr: u64,
    pub size: usize,
    pub numa_node: NumaNodeId,
    state: AtomicU8,
    pub total_pages: usize,
    used_pages: AtomicU64,
    pub(crate) online_timestamp: AtomicU64,
}

impl MemoryBlock {
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

    pub fn state(&self) -> MemoryBlockState {
        MemoryBlockState::from(self.state.load(Ordering::Acquire))
    }

    fn set_state(&self, state: MemoryBlockState) {
        self.state.store(state as u8, Ordering::Release);
    }

    pub fn used_pages(&self) -> u64 {
        self.used_pages.load(Ordering::Relaxed)
    }

    pub fn free_ratio(&self) -> f64 {
        let used = self.used_pages() as f64;
        let total = self.total_pages as f64;
        1.0 - (used / total)
    }

    pub fn can_offline(&self) -> bool {
        self.state() == MemoryBlockState::Online
    }

    pub fn frame_range(&self) -> (FrameIndex, FrameIndex) {
        let start = FrameIndex::new(self.start_addr as usize / PAGE_SIZE_4K);
        let end = FrameIndex::new((self.start_addr as usize + self.size) / PAGE_SIZE_4K);
        (start, end)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugEvent {
    MemoryAdded {
        block_id: u64,
    },
    MemoryGoingOffline {
        block_id: u64,
    },
    MemoryRemoved {
        block_id: u64,
    },
    OfflineFailed {
        block_id: u64,
        reason: OfflineFailReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OfflineFailReason {
    PinnedMemory,
    KernelReserved,
    DmaInUse,
    MigrationFailed,
    Timeout,
}

pub trait HotplugCallback: Send + Sync {
    fn on_hotplug_event(&self, event: HotplugEvent);
    fn can_offline(&self, block_id: u64) -> bool;
}

#[derive(Debug, Default, Clone)]
pub struct HotplugStats {
    pub online_blocks: usize,
    pub offline_blocks: usize,
    pub total_online_memory: u64,
    pub add_success_count: u64,
    pub remove_success_count: u64,
    pub remove_fail_count: u64,
    pub pending_operations: usize,
}

pub struct HotplugManager {
    blocks: PoisonRwLock<BTreeMap<u64, MemoryBlock>>,
    callbacks: PoisonRwLock<Vec<&'static dyn HotplugCallback>>,
    stats: PoisonRwLock<HotplugStats>,
    next_block_id: AtomicU64,
    initialized: AtomicU8,
}

impl HotplugManager {
    pub const fn new() -> Self {
        Self {
            blocks: PoisonRwLock::new(BTreeMap::new()),
            callbacks: PoisonRwLock::new(Vec::new()),
            stats: PoisonRwLock::new(HotplugStats {
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

    pub fn init(&self) {
        if self
            .initialized
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            log::info!("[Hotplug] Memory hotplug manager initialized");
        }
    }

    pub fn register_callback(&self, callback: &'static dyn HotplugCallback) {
        let mut callbacks = self.callbacks.write().unwrap_or_else(|e| e.into_inner());
        callbacks.push(callback);
    }

    pub fn add_memory_block(
        &self,
        start_addr: u64,
        size: usize,
        numa_node: NumaNodeId,
    ) -> Result<u64, HotplugError> {
        if start_addr as usize % MEMORY_BLOCK_SIZE != 0 {
            return Err(HotplugError::InvalidAlignment);
        }
        if size < MEMORY_BLOCK_SIZE {
            return Err(HotplugError::InvalidSize);
        }
        {
            let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
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
        block.set_state(MemoryBlockState::GoingOnline);

        {
            let mut blocks = self.blocks.write().unwrap_or_else(|e| e.into_inner());
            blocks.insert(block_id, block);
        }
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.pending_operations += 1;
        }

        self.online_block_internal(block_id)?;

        let callbacks = self.callbacks.read().unwrap_or_else(|e| e.into_inner());
        for cb in callbacks.iter() {
            cb.on_hotplug_event(HotplugEvent::MemoryAdded { block_id });
        }

        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
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

    fn online_block_internal(&self, block_id: u64) -> Result<(), HotplugError> {
        let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
        let block = blocks.get(&block_id).ok_or(HotplugError::BlockNotFound)?;
        block.set_state(MemoryBlockState::Online);
        block.online_timestamp.store(read_tsc(), Ordering::Release);
        Ok(())
    }

    fn handle_offline_success(&self, block_id: u64) {
        let size = {
            let mut blocks = self.blocks.write().unwrap_or_else(|e| e.into_inner());
            blocks.remove(&block_id).map(|b| b.size).unwrap_or(0)
        };
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.online_blocks = stats.online_blocks.saturating_sub(1);
            stats.offline_blocks += 1;
            stats.total_online_memory = stats.total_online_memory.saturating_sub(size as u64);
            stats.remove_success_count += 1;
            stats.pending_operations = stats.pending_operations.saturating_sub(1);
        }
        let callbacks = self.callbacks.read().unwrap_or_else(|e| e.into_inner());
        for cb in callbacks.iter() {
            cb.on_hotplug_event(HotplugEvent::MemoryRemoved { block_id });
        }
        log::info!("[Hotplug] Memory block {} removed", block_id);
    }

    fn handle_offline_failure(&self, block_id: u64, e: &HotplugError) {
        {
            let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
            if let Some(block) = blocks.get(&block_id) {
                block.set_state(MemoryBlockState::OfflineFailed);
            }
        }
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.remove_fail_count += 1;
            stats.pending_operations = stats.pending_operations.saturating_sub(1);
        }
        let callbacks = self.callbacks.read().unwrap_or_else(|e| e.into_inner());
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
        {
            let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
            let block = blocks.get(&block_id).ok_or(HotplugError::BlockNotFound)?;
            if !block.can_offline() {
                return Err(HotplugError::BlockBusy);
            }
        }
        {
            let callbacks = self.callbacks.read().unwrap_or_else(|e| e.into_inner());
            for cb in callbacks.iter() {
                if !cb.can_offline(block_id) {
                    return Err(HotplugError::OfflineRejected);
                }
            }
        }
        {
            let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
            if let Some(block) = blocks.get(&block_id) {
                block.set_state(MemoryBlockState::GoingOffline);
            }
        }
        {
            let mut stats = self.stats.write().unwrap_or_else(|e| e.into_inner());
            stats.pending_operations += 1;
        }
        {
            let callbacks = self.callbacks.read().unwrap_or_else(|e| e.into_inner());
            for cb in callbacks.iter() {
                cb.on_hotplug_event(HotplugEvent::MemoryGoingOffline { block_id });
            }
        }
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

    fn offline_block_internal(&self, block_id: u64) -> Result<(), HotplugError> {
        let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
        let block = blocks.get(&block_id).ok_or(HotplugError::BlockNotFound)?;
        let (start_frame, end_frame) = block.frame_range();
        for frame_idx in start_frame.as_usize()..end_frame.as_usize() {
            let frame = FrameIndex::new(frame_idx);
            if self.is_frame_in_use(frame) {
                if !self.try_migrate_frame(frame, block.numa_node) {
                    return Err(HotplugError::MigrationFailed);
                }
            }
        }
        Ok(())
    }

    fn is_frame_in_use(&self, _frame: FrameIndex) -> bool {
        false
    }
    fn try_migrate_frame(&self, _frame: FrameIndex, _numa_node: NumaNodeId) -> bool {
        true
    }

    pub fn get_block_info(&self, block_id: u64) -> Option<MemoryBlockInfo> {
        let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
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

    pub fn list_blocks(&self) -> Vec<MemoryBlockInfo> {
        let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
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

    pub fn stats(&self) -> HotplugStats {
        self.stats.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn online_memory_on_node(&self, numa_node: NumaNodeId) -> u64 {
        let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
        blocks
            .values()
            .filter(|b| b.numa_node == numa_node && b.state() == MemoryBlockState::Online)
            .map(|b| b.size as u64)
            .sum()
    }

    pub fn retry_failed_offline(&self, block_id: u64) -> Result<(), HotplugError> {
        {
            let blocks = self.blocks.read().unwrap_or_else(|e| e.into_inner());
            let block = blocks.get(&block_id).ok_or(HotplugError::BlockNotFound)?;
            if block.state() != MemoryBlockState::OfflineFailed {
                return Err(HotplugError::InvalidState);
            }
            block.set_state(MemoryBlockState::Online);
        }
        self.remove_memory_block(block_id)
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HotplugError {
    InvalidAlignment,
    InvalidSize,
    BlockNotFound,
    BlockBusy,
    OverlappingRegion,
    OfflineRejected,
    MigrationFailed,
    PinnedPages,
    InvalidState,
    InternalError,
}

static HOTPLUG_MANAGER: HotplugManager = HotplugManager::new();

#[inline]
fn read_tsc() -> u64 {
    crate::time::rdtsc_unserialized()
}

pub fn init_hotplug() {
    HOTPLUG_MANAGER.init();
}

pub fn hotplug_add_memory(
    start_addr: u64,
    size: usize,
    numa_node: NumaNodeId,
) -> Result<u64, HotplugError> {
    HOTPLUG_MANAGER.add_memory_block(start_addr, size, numa_node)
}

pub fn hotplug_remove_memory(block_id: u64) -> Result<(), HotplugError> {
    HOTPLUG_MANAGER.remove_memory_block(block_id)
}

pub fn hotplug_block_info(block_id: u64) -> Option<MemoryBlockInfo> {
    HOTPLUG_MANAGER.get_block_info(block_id)
}

pub fn hotplug_list_blocks() -> Vec<MemoryBlockInfo> {
    HOTPLUG_MANAGER.list_blocks()
}

pub fn hotplug_stats() -> HotplugStats {
    HOTPLUG_MANAGER.stats()
}

pub fn hotplug_register_callback(callback: &'static dyn HotplugCallback) {
    HOTPLUG_MANAGER.register_callback(callback);
}

pub fn hotplug_online_memory_on_node(numa_node: NumaNodeId) -> u64 {
    HOTPLUG_MANAGER.online_memory_on_node(numa_node)
}

pub fn hotplug_retry_offline(block_id: u64) -> Result<(), HotplugError> {
    HOTPLUG_MANAGER.retry_failed_offline(block_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
    fn test_memory_block_state() {
        let block = MemoryBlock::new(0, 0, MEMORY_BLOCK_SIZE, NumaNodeId::new(0));
        assert_eq!(block.state(), MemoryBlockState::Offline);
        block.set_state(MemoryBlockState::Online);
        assert_eq!(block.state(), MemoryBlockState::Online);
    }
    #[cfg_attr(all(test, any(feature = "std", target_os = "linux")), test)]
    #[cfg_attr(all(test, not(any(feature = "std", target_os = "linux"))), test_case)]
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
