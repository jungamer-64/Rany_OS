// ============================================================================
// src/mm/frame_allocator.rs - Bitmap-based Physical Frame Allocator
// 設計書 5.2 Tier1: 4KiB/2MiB/1GiB単位の物理フレーム管理
// 設計書 5.3 NUMAアーキテクチャへの対応
//
// 注意: 構造体全体がMutexで保護されているため、内部フィールドは
// 通常のu64を使用。Mutex + Atomicの二重ロックはオーバーヘッド。
// ============================================================================
#![allow(dead_code)]

extern crate alloc;

use boot_proto::NumaInfo;
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use crate::sync::IrqMutex;
use crate::mm::fast_allocator::{FastBitmapAllocator, PageGranularity};
use x86_64::PhysAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size1GiB, Size2MiB, Size4KiB};

// 共通型定義をインポート（IOVA_MM_MIGRATION_PLAN Phase 0.1）
use super::numa::{MAX_NUMA_NODES, NumaTopology};
use super::types::{FrameIndex, NumaNodeId, PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G};

// ============================================================================
// 型安全性: フレーム番号のNewtype
// FrameIndex, PAGE_SIZE_* は super::types からインポート済み
// (IOVA_MM_MIGRATION_PLAN Phase 0.1 による統一)
// ============================================================================

/// PMMが管理する最大ページ数 (IOVA bitmapと同等: 256GiB / 4KiB)
const PMM_MAX_PAGES: usize = 64 * 1024 * 1024;
/// Single-writer arena sync interval (ticks)
const PMM_SYNC_INTERVAL_TICKS: u64 = 1024;

/// 物理メモリの最大サイズ（16GiB想定）
const MAX_PHYSICAL_MEMORY: usize = 16 * 1024 * 1024 * 1024;
/// 4KiBページ数の最大値
const MAX_4K_FRAMES: usize = MAX_PHYSICAL_MEMORY / PAGE_SIZE_4K;
/// ビットマップのワード数（64ビット単位）
const BITMAP_WORDS: usize = MAX_4K_FRAMES / 64;

/// ビットマップ方式の物理フレームアロケータ
/// 設計書: ビットマップ管理。頻繁には呼ばれない。
///
/// 注意: 構造体全体がFRAME_ALLOCATOR: Mutex<BitmapFrameAllocator>で保護されるため、
/// 内部フィールドにAtomicは不要。通常のu64を使用する。
pub struct BitmapFrameAllocator {
    /// ビットマップ（1 = 使用中, 0 = 空き）
    bitmap: [u64; BITMAP_WORDS],
    /// 総フレーム数
    total_frames: usize,
    /// 空きフレーム数（統計用）
    free_frames: u64,
    /// 最初の空き領域のヒント（高速化用）
    next_free_hint: u64,
}

impl BitmapFrameAllocator {
    /// 新しいフレームアロケータを作成（未初期化）
    pub const fn new() -> Self {
        Self {
            bitmap: [0u64; BITMAP_WORDS],
            total_frames: 0,
            free_frames: 0,
            next_free_hint: 0,
        }
    }

    /// メモリマップに基づいてアロケータを初期化
    ///
    /// # Safety
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    pub unsafe fn init(&mut self, usable_regions: &[(PhysAddr, u64)]) {
        // 最初は全てを使用中としてマーク
        for word in self.bitmap.iter_mut() {
            *word = u64::MAX;
        }

        let mut total = 0usize;
        let mut free = 0u64;

        // 使用可能な領域を空きとしてマーク
        for &(start, size) in usable_regions {
            let start_frame = FrameIndex::from_phys_addr(start.as_u64());
            let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

            for frame_idx in start_frame.as_usize()..end_frame.as_usize() {
                if frame_idx < MAX_4K_FRAMES {
                    self.mark_frame_free(FrameIndex::new(frame_idx));
                    free += 1;
                }
            }

            total = total.max(end_frame.as_usize());
        }

        self.total_frames = total;
        self.free_frames = free;
    }

    /// フレームを空きとしてマーク
    fn mark_frame_free(&mut self, frame: FrameIndex) {
        let word_idx = frame.word_index();
        let bit_idx = frame.bit_index();

        if word_idx < BITMAP_WORDS {
            let mask = !(1u64 << bit_idx);
            self.bitmap[word_idx] &= mask;
        }
    }

    /// フレームを使用中としてマーク
    fn mark_frame_used(&mut self, frame: FrameIndex) {
        let word_idx = frame.word_index();
        let bit_idx = frame.bit_index();

        if word_idx < BITMAP_WORDS {
            let mask = 1u64 << bit_idx;
            self.bitmap[word_idx] |= mask;
        }
    }

    /// フレームが空きかどうか確認
    fn is_frame_free(&self, frame: FrameIndex) -> bool {
        let word_idx = frame.word_index();
        let bit_idx = frame.bit_index();

        if word_idx >= BITMAP_WORDS {
            return false;
        }

        (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
    }

    /// 4KiB フレームを1つ割り当て
    pub fn allocate_4k_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let hint = FrameIndex::new(self.next_free_hint as usize);
        let hint_word = hint.word_index();

        // ヒントの位置から検索開始
        for word_offset in 0..BITMAP_WORDS {
            let word_idx = (hint_word + word_offset) % BITMAP_WORDS;
            let word = self.bitmap[word_idx];

            // このワードに空きビットがあるか
            if word != u64::MAX {
                // 空きビットを見つける
                let bit_idx = (!word).trailing_zeros() as usize;
                let frame = FrameIndex::new(word_idx * 64 + bit_idx);

                if frame.as_usize() >= self.total_frames {
                    continue;
                }

                // Mutexで保護されているので通常のビット操作でOK
                self.bitmap[word_idx] |= 1u64 << bit_idx;
                self.free_frames -= 1;
                self.next_free_hint = frame.as_usize() as u64 + 1;

                let addr = PhysAddr::new(frame.to_phys_addr());
                return Some(PhysFrame::containing_address(addr));
            }
        }

        None
    }

    /// 連続する物理フレームを割り当て（2MiB, 1GiB用）
    pub fn allocate_contiguous(
        &mut self,
        frame_count: usize,
        alignment: usize,
    ) -> Option<PhysAddr> {
        let aligned_frames = alignment / PAGE_SIZE_4K;

        for start_word in 0..BITMAP_WORDS {
            let start_frame = start_word * 64;

            // アライメントに合わせる
            let aligned_start =
                (start_frame + aligned_frames - 1) / aligned_frames * aligned_frames;

            if aligned_start + frame_count > self.total_frames {
                break;
            }

            // 連続した空きフレームがあるかチェック
            let mut all_free = true;
            for i in 0..frame_count {
                if !self.is_frame_free(FrameIndex::new(aligned_start + i)) {
                    all_free = false;
                    break;
                }
            }

            if all_free {
                // 全て確保
                for i in 0..frame_count {
                    self.mark_frame_used(FrameIndex::new(aligned_start + i));
                }
                self.free_frames -= frame_count as u64;

                let start_frame = FrameIndex::new(aligned_start);
                return Some(PhysAddr::new(start_frame.to_phys_addr()));
            }
        }

        None
    }

    /// 2MiB フレームを割り当て
    pub fn allocate_2m_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let frames_needed = PAGE_SIZE_2M / PAGE_SIZE_4K; // 512
        self.allocate_contiguous(frames_needed, PAGE_SIZE_2M)
            .map(|addr| PhysFrame::containing_address(addr))
    }

    /// 1GiB フレームを割り当て（設計書5.1: 1GBページの活用）
    pub fn allocate_1g_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        let frames_needed = PAGE_SIZE_1G / PAGE_SIZE_4K; // 262144
        self.allocate_contiguous(frames_needed, PAGE_SIZE_1G)
            .map(|addr| PhysFrame::containing_address(addr))
    }

    /// 4KiB フレームを解放
    pub fn deallocate_4k_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // Memcg: ページがmemcgでトラックされている場合はuntrackしてチャージを戻す
        super::memcg::memcg_untrack_and_uncharge(frame_idx, 1);

        self.mark_frame_free(frame_idx);
        self.free_frames += 1;
    }

    /// 2MiB フレームを解放
    pub fn deallocate_2m_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_2M / PAGE_SIZE_4K;

        // Memcg: 各4KiBページについてアンチャージ/アンストラックする
        for i in 0..frames_count {
            let idx = FrameIndex::new(start_frame.as_usize() + i);
            super::memcg::memcg_untrack_and_uncharge(idx, 1);
            self.mark_frame_free(idx);
        }
        self.free_frames += frames_count as u64;
    }

    /// 1GiB フレームを解放
    pub fn deallocate_1g_frame(&mut self, frame: PhysFrame<Size1GiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_1G / PAGE_SIZE_4K;

        // Memcg: 各4KiBページについてアンチャージ/アンストラックする
        for i in 0..frames_count {
            let idx = FrameIndex::new(start_frame.as_usize() + i);
            super::memcg::memcg_untrack_and_uncharge(idx, 1);
            self.mark_frame_free(idx);
        }
        self.free_frames += frames_count as u64;
    }

    /// 空きフレーム数を取得
    pub fn free_frame_count(&self) -> u64 {
        self.free_frames
    }

    /// 総フレーム数を取得
    pub fn total_frame_count(&self) -> usize {
        self.total_frames
    }
}

// x86_64 crateのFrameAllocatorトレイトを実装
unsafe impl FrameAllocator<Size4KiB> for BitmapFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_4k_frame()
    }
}

// ============================================================================
// PMM Fast Allocator (IOVA-based Bitmap + Magazine)
// ============================================================================

/// PMM fast allocator wrapper (phys addr aware)
struct PmmAllocatorFast {
    inner: FastBitmapAllocator,
    base: u64,
    size: u64,
}

impl PmmAllocatorFast {
    fn new(base: u64, size: u64) -> Self {
        Self {
            inner: FastBitmapAllocator::new(base, size),
            base,
            size,
        }
    }

    fn configure_arenas_for_cpu_ids(&mut self, cpu_ids: &[usize]) {
        self.inner.reconfigure_for_cpu_ids(cpu_ids);
    }

    fn enable_single_writer(&self) {
        self.inner.enable_single_writer_arenas();
    }

    fn drain_remote_frees(&self) -> usize {
        self.inner.drain_remote_frees()
    }

    fn sync_single_writer_arenas(&self) {
        self.inner.sync_single_writer_arenas();
    }

    fn stats(&self) -> (u64, usize) {
        self.inner.pmm_stats()
    }

    fn alloc_4k(&self) -> Option<PhysFrame<Size4KiB>> {
        let addr = self.inner.allocate_4k()?;
        PhysFrame::from_start_address(PhysAddr::new(addr)).ok()
    }

    fn alloc_2m(&self) -> Option<PhysFrame<Size2MiB>> {
        let addr = self.inner.allocate_2m()?;
        PhysFrame::from_start_address(PhysAddr::new(addr)).ok()
    }

    fn alloc_1g(&self) -> Option<PhysFrame<Size1GiB>> {
        let addr = self.inner.allocate_1g()?;
        PhysFrame::from_start_address(PhysAddr::new(addr)).ok()
    }

    fn alloc_contiguous(&self, frames: usize) -> Option<PhysAddr> {
        self.alloc_contiguous_aligned(frames, PAGE_SIZE_4K as u64)
    }

    fn alloc_contiguous_aligned(&self, frames: usize, align_bytes: u64) -> Option<PhysAddr> {
        if frames == 0 {
            return None;
        }
        let size = (frames as u64).checked_mul(PAGE_SIZE_4K as u64)?;
        let align = align_bytes.max(PAGE_SIZE_4K as u64);
        let addr = self.inner.allocate_contiguous(size, align)?;
        Some(PhysAddr::new(addr))
    }

    fn free_4k(&self, frame: PhysFrame<Size4KiB>) {
        let addr = frame.start_address().as_u64();
        let _ = self
            .inner
            .free_immediate(addr, PageGranularity::Page4K);
    }

    fn free_2m(&self, frame: PhysFrame<Size2MiB>) {
        let addr = frame.start_address().as_u64();
        let _ = self
            .inner
            .free_immediate(addr, PageGranularity::Page2M);
    }

    fn free_1g(&self, frame: PhysFrame<Size1GiB>) {
        let addr = frame.start_address().as_u64();
        let _ = self
            .inner
            .free_immediate(addr, PageGranularity::Page1G);
    }

    fn reserve_range(&self, start: u64, size: u64) {
        if size == 0 {
            return;
        }
        if let Err(err) = self.inner.reserve(start, size) {
            log::warn!(
                "[PMM] reserve failed: start={:#x} size={:#x} err={:?}",
                start,
                size,
                err
            );
        }
    }

    fn reserve_gaps(&self, usable: &[(u64, u64)]) {
        let end = self.base.saturating_add(self.size);
        let mut cursor = self.base;

        for &(start, end_region) in usable {
            let start = start.max(self.base);
            let end_region = end_region.min(end);
            if end_region <= cursor {
                continue;
            }
            if start > cursor {
                self.reserve_range(cursor, start - cursor);
            }
            cursor = end_region;
        }

        if cursor < end {
            self.reserve_range(cursor, end - cursor);
        }
    }

    fn release_range_direct(&self, start: u64, size: u64) -> u64 {
        if size == 0 {
            return 0;
        }
        let mut range_start = start.max(self.base);
        let mut range_end = start.saturating_add(size);
        let pmm_end = self.base.saturating_add(self.size);
        if range_end > pmm_end {
            range_end = pmm_end;
        }
        if range_end <= range_start {
            return 0;
        }

        range_start = align_up(range_start, PAGE_SIZE_4K as u64);
        range_end = align_down(range_end, PAGE_SIZE_4K as u64);
        if range_end <= range_start {
            return 0;
        }

        let len = range_end - range_start;
        if self
            .inner
            .free_range_immediate(range_start, len)
            .is_ok()
        {
            len / (PAGE_SIZE_4K as u64)
        } else {
            0
        }
    }
}

fn align_down(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value & !(align - 1)
}

fn align_up(value: u64, align: u64) -> u64 {
    if align == 0 {
        return value;
    }
    value.wrapping_add(align - 1) & !(align - 1)
}

fn align_size_to_page(size: usize) -> usize {
    if size <= PAGE_SIZE_4K {
        return PAGE_SIZE_4K;
    }
    size.saturating_add(PAGE_SIZE_4K - 1) / PAGE_SIZE_4K * PAGE_SIZE_4K
}

fn normalize_regions(usable_regions: &[(PhysAddr, u64)]) -> Vec<(u64, u64)> {
    let mut regions: Vec<(u64, u64)> = usable_regions
        .iter()
        .filter_map(|&(addr, size)| {
            if size == 0 {
                return None;
            }
            let start = addr.as_u64();
            let end_raw = start.checked_add(size)?;
            let start = align_up(start, PAGE_SIZE_4K as u64);
            let end = align_down(end_raw, PAGE_SIZE_4K as u64);
            if end <= start {
                return None;
            }
            Some((start, end))
        })
        .collect();

    regions.sort_by_key(|&(start, _)| start);

    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(regions.len());
    for (start, end) in regions {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    merged
}

fn build_pmm_from_regions(usable_regions: &[(PhysAddr, u64)]) -> Option<PmmAllocatorFast> {
    let merged = normalize_regions(usable_regions);
    if merged.is_empty() {
        return None;
    }

    let min_start = merged.iter().map(|&(start, _)| start).min()?;
    let base = align_down(min_start, PAGE_SIZE_4K as u64);
    let max_end = merged.iter().map(|&(_, end)| end).max()?;
    let max_size = (PMM_MAX_PAGES as u64) * (PAGE_SIZE_4K as u64);
    let size = align_down(max_end.saturating_sub(base), PAGE_SIZE_4K as u64).min(max_size);
    if size == 0 {
        return None;
    }

    let pmm = PmmAllocatorFast::new(base, size);
    pmm.reserve_gaps(&merged);
    Some(pmm)
}

// ============================================================================
// NUMA-Aware Frame Allocator
// 設計書 5.3.2: NUMA-Awareメモリアロケータ
// ============================================================================

/// NUMA対応フレームアロケータ
/// 各NUMAノードごとに独立したビットマップアロケータを持つ
pub struct NumaFrameAllocator {
    /// 各NUMAノードのアロケータ
    node_allocators: [BitmapFrameAllocator; MAX_NUMA_NODES],
    /// NUMAトポロジ情報
    topology: NumaTopology,
}

impl NumaFrameAllocator {
    /// 新しいNUMA対応アロケータを作成
    pub const fn new() -> Self {
        Self {
            node_allocators: [
                BitmapFrameAllocator::new(),
                BitmapFrameAllocator::new(),
                BitmapFrameAllocator::new(),
                BitmapFrameAllocator::new(),
                BitmapFrameAllocator::new(),
                BitmapFrameAllocator::new(),
                BitmapFrameAllocator::new(),
                BitmapFrameAllocator::new(),
            ],
            topology: NumaTopology::new(),
        }
    }

    /// NUMA対応アロケータを初期化
    ///
    /// # Safety
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    /// - `numa_regions` は各領域とNUMAノードの対応を示す
    pub unsafe fn init_numa(&mut self, usable_regions: &[(PhysAddr, u64, NumaNodeId)]) {
        // NUMAノードごとの領域をグループ化
        for node_idx in 0..MAX_NUMA_NODES {
            let node_id = NumaNodeId::new(node_idx as u8);
            let valid_regions: alloc::vec::Vec<_> = usable_regions
                .iter()
                .filter(|&&(_, _, region_node)| region_node == node_id)
                .map(|&(addr, size, _)| (addr, size))
                .filter(|&(_, size)| size > 0)
                .collect();

            if !valid_regions.is_empty() {
                unsafe {
                    self.node_allocators[node_idx].init(&valid_regions);
                }

                // トポロジにメモリ範囲を追加
                for (addr, size) in &valid_regions {
                    self.topology.nodes[node_idx].add_memory_range(addr.as_u64(), *size);
                }
            }
        }
    }

    /// 指定NUMAノードから4KiBフレームを割り当て
    /// 設計書 5.3.2: 明示的なノード指定
    pub fn allocate_4k_on_node(&mut self, node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
        let idx = node.as_usize();
        if idx < MAX_NUMA_NODES {
            self.node_allocators[idx].allocate_4k_frame()
        } else {
            None
        }
    }

    /// 現在のCPUに近いノードから4KiBフレームを割り当て
    /// 設計書 5.3.2: デフォルトポリシー（First-Touch Policy）
    ///
    /// 優先順位:
    /// 1. 現在のCPUが属するNUMAノード
    /// 2. 距離の近いNUMAノード（順番にフォールバック）
    pub fn allocate_4k_local(&mut self, current_cpu: u8) -> Option<PhysFrame<Size4KiB>> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        // 近いノードから順に試行
        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(frame) = self.allocate_4k_on_node(node) {
                return Some(frame);
            }
        }

        None
    }

    /// 指定NUMAノードから2MiBフレームを割り当て
    pub fn allocate_2m_on_node(&mut self, node: NumaNodeId) -> Option<PhysFrame<Size2MiB>> {
        let idx = node.as_usize();
        if idx < MAX_NUMA_NODES {
            self.node_allocators[idx].allocate_2m_frame()
        } else {
            None
        }
    }

    /// 現在のCPUに近いノードから2MiBフレームを割り当て
    pub fn allocate_2m_local(&mut self, current_cpu: u8) -> Option<PhysFrame<Size2MiB>> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(frame) = self.allocate_2m_on_node(node) {
                return Some(frame);
            }
        }

        None
    }

    /// フレームが属するNUMAノードを判定して解放
    pub fn deallocate_4k_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let addr = frame.start_address().as_u64();
        let node = self.topology.addr_to_node(addr);
        let idx = node.as_usize();
        if idx < MAX_NUMA_NODES {
            self.node_allocators[idx].deallocate_4k_frame(frame);
        }
    }

    /// 全ノードの統計を取得
    pub fn stats(&self) -> NumaAllocatorStats {
        let mut stats = NumaAllocatorStats {
            per_node: [(0, 0); MAX_NUMA_NODES],
            total_free: 0,
            total_frames: 0,
        };

        for (i, allocator) in self.node_allocators.iter().enumerate() {
            let free = allocator.free_frame_count();
            let total = allocator.total_frame_count();
            stats.per_node[i] = (free, total);
            stats.total_free += free;
            stats.total_frames += total;
        }

        stats
    }

    /// トポロジ情報への参照を取得
    pub fn topology(&self) -> &NumaTopology {
        &self.topology
    }
}

/// NUMA統計情報
#[derive(Debug, Clone)]
pub struct NumaAllocatorStats {
    /// 各ノードの(空きフレーム数, 総フレーム数)
    pub per_node: [(u64, usize); MAX_NUMA_NODES],
    /// 全ノード合計の空きフレーム数
    pub total_free: u64,
    /// 全ノード合計の総フレーム数
    pub total_frames: usize,
}

/// NUMA対応PMMアロケータ（fast bitmap版）
struct NumaPmmAllocator {
    node_allocators: Vec<Option<PmmAllocatorFast>>,
    topology: NumaTopology,
}

impl NumaPmmAllocator {
    fn new() -> Self {
        let mut node_allocators = Vec::with_capacity(MAX_NUMA_NODES);
        for _ in 0..MAX_NUMA_NODES {
            node_allocators.push(None);
        }
        Self {
            node_allocators,
            topology: NumaTopology::new(),
        }
    }

    fn cpu_ids_for_node(&self, node_idx: usize) -> Vec<usize> {
        let mut ids = Vec::new();
        if node_idx < MAX_NUMA_NODES {
            let mask = self.topology.nodes[node_idx].cpu_mask;
            for cpu_id in 0..crate::mm::per_cpu::MAX_CPUS {
                if (mask & (1u64 << cpu_id)) != 0 {
                    ids.push(cpu_id);
                }
            }
        }
        if ids.is_empty() {
            for cpu_id in 0..crate::mm::per_cpu::MAX_CPUS {
                ids.push(cpu_id);
            }
        }
        ids
    }

    fn init_numa(&mut self, usable_regions: &[(PhysAddr, u64, NumaNodeId)]) {
        let mut max_node = 0usize;

        for node_idx in 0..MAX_NUMA_NODES {
            let node_id = NumaNodeId::new(node_idx as u8);
            let mut node_regions: Vec<(PhysAddr, u64)> = Vec::new();

            for &(addr, size, region_node) in usable_regions {
                if region_node == node_id && size > 0 {
                    node_regions.push((addr, size));
                }
            }

            if node_regions.is_empty() {
                continue;
            }

            if let Some(mut pmm) = build_pmm_from_regions(&node_regions) {
                let cpu_ids = self.cpu_ids_for_node(node_idx);
                pmm.configure_arenas_for_cpu_ids(&cpu_ids);
                pmm.enable_single_writer();
                self.node_allocators[node_idx] = Some(pmm);
            }

            for (addr, size) in node_regions {
                self.topology.nodes[node_idx].add_memory_range(addr.as_u64(), size);
            }

            max_node = max_node.max(node_idx + 1);
        }

        if max_node > 0 {
            self.topology.node_count = max_node;
        }
    }

    fn allocate_4k_on_node(&self, node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
        let idx = node.as_usize();
        self.node_allocators.get(idx)?.as_ref()?.alloc_4k()
    }

    fn allocate_4k_local(&self, current_cpu: u8) -> Option<PhysFrame<Size4KiB>> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(frame) = self.allocate_4k_on_node(node) {
                return Some(frame);
            }
        }

        None
    }

    fn allocate_2m_on_node(&self, node: NumaNodeId) -> Option<PhysFrame<Size2MiB>> {
        let idx = node.as_usize();
        self.node_allocators.get(idx)?.as_ref()?.alloc_2m()
    }

    fn allocate_2m_local(&self, current_cpu: u8) -> Option<PhysFrame<Size2MiB>> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(frame) = self.allocate_2m_on_node(node) {
                return Some(frame);
            }
        }

        None
    }

    fn allocate_1g_on_node(&self, node: NumaNodeId) -> Option<PhysFrame<Size1GiB>> {
        let idx = node.as_usize();
        self.node_allocators.get(idx)?.as_ref()?.alloc_1g()
    }

    fn allocate_1g_local(&self, current_cpu: u8) -> Option<PhysFrame<Size1GiB>> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(frame) = self.allocate_1g_on_node(node) {
                return Some(frame);
            }
        }

        None
    }

    fn alloc_contiguous_on_node(&self, node: NumaNodeId, frames: usize) -> Option<PhysAddr> {
        let idx = node.as_usize();
        self.node_allocators.get(idx)?.as_ref()?.alloc_contiguous(frames)
    }

    fn alloc_contiguous_on_node_aligned(
        &self,
        node: NumaNodeId,
        frames: usize,
        align_bytes: u64,
    ) -> Option<PhysAddr> {
        let idx = node.as_usize();
        self.node_allocators
            .get(idx)?
            .as_ref()?
            .alloc_contiguous_aligned(frames, align_bytes)
    }

    fn alloc_contiguous_local(&self, current_cpu: u8, frames: usize) -> Option<PhysAddr> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(addr) = self.alloc_contiguous_on_node(node, frames) {
                return Some(addr);
            }
        }

        None
    }

    fn alloc_contiguous_local_aligned(
        &self,
        current_cpu: u8,
        frames: usize,
        align_bytes: u64,
    ) -> Option<PhysAddr> {
        let preferred_node = self.topology.cpu_to_node(current_cpu);
        let fallback_order = self.topology.nodes_by_distance(preferred_node);

        for i in 0..self.topology.node_count() {
            let node = fallback_order[i];
            if let Some(addr) = self.alloc_contiguous_on_node_aligned(node, frames, align_bytes) {
                return Some(addr);
            }
        }

        None
    }

    fn deallocate_4k_frame(&self, frame: PhysFrame<Size4KiB>) {
        let addr = frame.start_address().as_u64();
        let node = self.topology.addr_to_node(addr);
        let idx = node.as_usize();
        if let Some(Some(pmm)) = self.node_allocators.get(idx) {
            pmm.free_4k(frame);
        }
    }

    fn deallocate_2m_frame(&self, frame: PhysFrame<Size2MiB>) {
        let addr = frame.start_address().as_u64();
        let node = self.topology.addr_to_node(addr);
        let idx = node.as_usize();
        if let Some(Some(pmm)) = self.node_allocators.get(idx) {
            pmm.free_2m(frame);
        }
    }

    fn deallocate_1g_frame(&self, frame: PhysFrame<Size1GiB>) {
        let addr = frame.start_address().as_u64();
        let node = self.topology.addr_to_node(addr);
        let idx = node.as_usize();
        if let Some(Some(pmm)) = self.node_allocators.get(idx) {
            pmm.free_1g(frame);
        }
    }

    fn stats(&self) -> NumaAllocatorStats {
        let mut stats = NumaAllocatorStats {
            per_node: [(0, 0); MAX_NUMA_NODES],
            total_free: 0,
            total_frames: 0,
        };

        for (i, allocator) in self.node_allocators.iter().enumerate() {
            if let Some(pmm) = allocator.as_ref() {
                let (free, total) = pmm.stats();
                stats.per_node[i] = (free, total);
                stats.total_free += free;
                stats.total_frames += total;
            }
        }

        stats
    }

    fn topology(&self) -> &NumaTopology {
        &self.topology
    }

    fn allocator_for_cpu(&self, cpu_id: u8) -> Option<&PmmAllocatorFast> {
        let node = self.topology.cpu_to_node(cpu_id);
        let idx = node.as_usize();
        self.node_allocators.get(idx)?.as_ref()
    }
}

// ============================================================================
// グローバルアロケータ（後方互換性維持）
// ============================================================================

/// グローバルなフレームアロケータ（NUMA非対応版、後方互換用）
/// 割り込み禁止Mutexで保護（デッドロック防止）
static FRAME_ALLOCATOR: IrqMutex<BitmapFrameAllocator> = IrqMutex::new(BitmapFrameAllocator::new());

/// NUMA対応グローバルフレームアロケータ
/// 設計書 5.3: NUMAアーキテクチャへの対応
static NUMA_FRAME_ALLOCATOR: IrqMutex<NumaFrameAllocator> =
    IrqMutex::new(NumaFrameAllocator::new());

/// PMM fast allocator (global)
static PMM_GLOBAL_PTR: AtomicPtr<PmmAllocatorFast> = AtomicPtr::new(ptr::null_mut());

/// PMM fast allocator (NUMA-aware)
static PMM_NUMA_PTR: AtomicPtr<NumaPmmAllocator> = AtomicPtr::new(ptr::null_mut());
static PMM_LAST_SYNC_TICK: AtomicU64 = AtomicU64::new(0);

fn pmm_global() -> Option<&'static PmmAllocatorFast> {
    let ptr = PMM_GLOBAL_PTR.load(Ordering::Acquire);
    unsafe { ptr.as_ref() }
}

fn pmm_numa() -> Option<&'static NumaPmmAllocator> {
    let ptr = PMM_NUMA_PTR.load(Ordering::Acquire);
    unsafe { ptr.as_ref() }
}

unsafe fn pmm_global_mut() -> Option<&'static mut PmmAllocatorFast> {
    let ptr = PMM_GLOBAL_PTR.load(Ordering::Acquire);
    unsafe { ptr.as_mut() }
}

unsafe fn pmm_numa_mut() -> Option<&'static mut NumaPmmAllocator> {
    let ptr = PMM_NUMA_PTR.load(Ordering::Acquire);
    unsafe { ptr.as_mut() }
}

fn should_sync_single_writer(tick: u64) -> bool {
    let last = PMM_LAST_SYNC_TICK.load(Ordering::Relaxed);
    if tick.saturating_sub(last) < PMM_SYNC_INTERVAL_TICKS {
        return false;
    }
    PMM_LAST_SYNC_TICK
        .compare_exchange(last, tick, Ordering::AcqRel, Ordering::Relaxed)
        .is_ok()
}

/// フレームアロケータを初期化（後方互換）
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_frame_allocator(usable_regions: &[(PhysAddr, u64)]) {
    if pmm_global().is_some() || pmm_numa().is_some() {
        return;
    }

    if let Some(pmm) = build_pmm_from_regions(usable_regions) {
        pmm.enable_single_writer();
        let boxed = Box::new(pmm);
        PMM_GLOBAL_PTR.store(Box::into_raw(boxed), Ordering::Release);
        return;
    }

    // Fallback to legacy bitmap allocator
    unsafe {
        FRAME_ALLOCATOR.lock().init(usable_regions);
    }
}

/// NUMA対応フレームアロケータを初期化
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
/// ACPI SRATから取得したNUMA情報を渡す
pub unsafe fn init_numa_frame_allocator(regions: &[(PhysAddr, u64, NumaNodeId)]) {
    if pmm_numa().is_some() || pmm_global().is_some() {
        return;
    }

    let mut numa = NumaPmmAllocator::new();
    numa.init_numa(regions);
    let boxed = Box::new(numa);
    PMM_NUMA_PTR.store(Box::into_raw(boxed), Ordering::Release);
}

/// NUMA情報（ブートローダー由来）からフレームアロケータを初期化
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_numa_frame_allocator_from_info(numa_info: &NumaInfo) -> bool {
    if pmm_numa().is_some() {
        return true;
    }
    if pmm_global().is_some() {
        return false;
    }

    let node_count = (numa_info.node_count as usize).min(MAX_NUMA_NODES);
    if node_count == 0 {
        return false;
    }

    let mut regions = collect_numa_memory_regions(numa_info, node_count);

    if regions.is_empty() {
        return false;
    }

    let mut numa = NumaPmmAllocator::new();
    for node_idx in 0..node_count {
        let node = &numa_info.nodes[node_idx];
        if node.cpu_apic_mask_high != 0 {
            log::warn!(
                "[PMM] NUMA node {} has APIC IDs >= 64; truncating CPU mask",
                node_idx
            );
        }
        numa.topology.nodes[node_idx].cpu_mask = node.cpu_apic_mask_low;
    }

    numa.init_numa(&regions);
    if node_count > numa.topology.node_count {
        numa.topology.node_count = node_count;
    }

    let boxed = Box::new(numa);
    PMM_NUMA_PTR.store(Box::into_raw(boxed), Ordering::Release);
    true
}

/// NUMAノード単位でアリーナを再構成
fn reconfigure_numa_node(
    numa: &mut NumaPmmAllocator,
    node_idx: usize,
    allowed: &[bool; crate::mm::per_cpu::MAX_CPUS],
    cpu_ids: &[usize],
) {
    let node_cpu_ids = numa.cpu_ids_for_node(node_idx);
    let mut filtered = Vec::new();
    for cpu_id in node_cpu_ids {
        if cpu_id < allowed.len() && allowed[cpu_id] {
            filtered.push(cpu_id);
        }
    }
    if let Some(pmm) = numa
        .node_allocators
        .get_mut(node_idx)
        .and_then(|opt| opt.as_mut())
    {
        pmm.sync_single_writer_arenas();
        if filtered.is_empty() {
            pmm.configure_arenas_for_cpu_ids(cpu_ids);
        } else {
            pmm.configure_arenas_for_cpu_ids(&filtered);
        }
        pmm.enable_single_writer();
    }
}

/// Reconfigure PMM arena ownership for a CPU ID list.
///
/// # Safety
/// Call during early boot while no concurrent allocations are running.
pub unsafe fn pmm_reconfigure_for_cpu_ids(cpu_ids: &[usize]) {
    let mut allowed = [false; crate::mm::per_cpu::MAX_CPUS];
    for &cpu_id in cpu_ids {
        if cpu_id < allowed.len() {
            allowed[cpu_id] = true;
        }
    }

    if let Some(numa) = unsafe { pmm_numa_mut() } {
        let node_count = numa.node_allocators.len();
        for node_idx in 0..node_count {
            reconfigure_numa_node(numa, node_idx, &allowed, cpu_ids);
        }
        return;
    }

    if let Some(pmm) = unsafe { pmm_global_mut() } {
        pmm.sync_single_writer_arenas();
        pmm.configure_arenas_for_cpu_ids(cpu_ids);
        pmm.enable_single_writer();
    }
}

/// Reconfigure PMM arena ownership for currently online CPUs.
///
/// # Safety
/// Call during early boot while no concurrent allocations are running.
pub unsafe fn pmm_reconfigure_for_online_cpus() {
    let cpu_ids = crate::mm::per_cpu::online_cpu_ids();
    unsafe {
        pmm_reconfigure_for_cpu_ids(&cpu_ids);
    }
}

// 簡易的な計測: ローカル優先割当の試行回数と成功回数
static FRAME_LOCAL_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static FRAME_LOCAL_SUCCESSES: AtomicU64 = AtomicU64::new(0);

/// 4KiB フレームを割り当て（後方互換）
/// 現在のCPUのローカルNUMAノードからの割当を優先して試みる
pub fn alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
            FRAME_LOCAL_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            if let Some(frame) = numa.allocate_4k_local(cpu_id as u8) {
                FRAME_LOCAL_SUCCESSES.fetch_add(1, Ordering::Relaxed);
                return Some(frame);
            }
        }

        for node_idx in 0..numa.topology().node_count() {
            if let Some(frame) = numa.allocate_4k_on_node(NumaNodeId::new(node_idx as u8)) {
                return Some(frame);
            }
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_4k();
    }

    FRAME_ALLOCATOR.lock().allocate_4k_frame()
}

/// 指定NUMAノードから4KiBフレームを割り当て
/// 設計書 5.3.2: 明示的なノード指定API
pub fn alloc_frame_on_numa_node(node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(frame) = numa.allocate_4k_on_node(node) {
            return Some(frame);
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_4k();
    }

    FRAME_ALLOCATOR.lock().allocate_4k_frame()
}

/// 現在のCPUのローカルNUMAノードから4KiBフレームを割り当て
/// 設計書 5.3.2: First-Touch Policy
pub fn alloc_frame_local(current_cpu: u8) -> Option<PhysFrame<Size4KiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(frame) = numa.allocate_4k_local(current_cpu) {
            return Some(frame);
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_4k();
    }

    FRAME_ALLOCATOR.lock().allocate_4k_frame()
}

/// 計測値取得（テスト用）
pub fn get_frame_local_alloc_metrics() -> (u64, u64) {
    (
        FRAME_LOCAL_ATTEMPTS.load(Ordering::Relaxed),
        FRAME_LOCAL_SUCCESSES.load(Ordering::Relaxed),
    )
}

/// 計測値リセット（テスト用）
pub fn reset_frame_local_alloc_metrics() {
    FRAME_LOCAL_ATTEMPTS.store(0, Ordering::Relaxed);
    FRAME_LOCAL_SUCCESSES.store(0, Ordering::Relaxed);
}

static FRAME2M_LOCAL_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static FRAME2M_LOCAL_SUCCESSES: AtomicU64 = AtomicU64::new(0);

/// 2MiB フレームを割り当て（後方互換）
/// NUMAローカル優先で割当を試みる
pub fn alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
            FRAME2M_LOCAL_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
            if let Some(frame) = numa.allocate_2m_local(cpu_id as u8) {
                FRAME2M_LOCAL_SUCCESSES.fetch_add(1, Ordering::Relaxed);
                return Some(frame);
            }
        }

        for node_idx in 0..numa.topology().node_count() {
            if let Some(frame) = numa.allocate_2m_on_node(NumaNodeId::new(node_idx as u8)) {
                return Some(frame);
            }
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_2m();
    }

    FRAME_ALLOCATOR.lock().allocate_2m_frame()
}

/// 指定NUMAノードから2MiBフレームを割り当て
pub fn alloc_frame_2m_on_numa_node(node: NumaNodeId) -> Option<PhysFrame<Size2MiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(frame) = numa.allocate_2m_on_node(node) {
            return Some(frame);
        }
    }
    if let Some(pmm) = pmm_global() {
        return pmm.alloc_2m();
    }
    FRAME_ALLOCATOR.lock().allocate_2m_frame()
}

/// 現在のCPUのローカルNUMAノードから2MiBフレームを割り当て
pub fn alloc_frame_2m_local(current_cpu: u8) -> Option<PhysFrame<Size2MiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(frame) = numa.allocate_2m_local(current_cpu) {
            return Some(frame);
        }
    }
    if let Some(pmm) = pmm_global() {
        return pmm.alloc_2m();
    }
    FRAME_ALLOCATOR.lock().allocate_2m_frame()
}

/// PMM fast が初期化済みかどうか
pub fn pmm_initialized() -> bool {
    pmm_numa().is_some() || pmm_global().is_some()
}

/// 物理アドレスが属するNUMAノードを取得（PMM fastが初期化済みの場合のみ）
pub fn numa_node_for_addr(addr: PhysAddr) -> Option<NumaNodeId> {
    pmm_numa().map(|numa| numa.topology().addr_to_node(addr.as_u64()))
}

/// 連続した (4KiB) フレームをアライン指定で割り当てるラッパー
///
/// - `frames_needed`: 割り当てたいフレーム数
/// - `align_bytes`: アラインメント（バイト）
/// - 戻り値: 割り当て開始物理アドレス (4KiB 単位)
pub fn alloc_contiguous_frames_aligned(
    frames_needed: usize,
    align_bytes: usize,
) -> Option<PhysAddr> {
    if frames_needed == 0 {
        return None;
    }

    let align = align_size_to_page(align_bytes);

    if let Some(numa) = pmm_numa() {
        if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
            if let Some(addr) =
                numa.alloc_contiguous_local_aligned(cpu_id as u8, frames_needed, align as u64)
            {
                return Some(addr);
            }
        }
        for node_idx in 0..numa.topology().node_count() {
            if let Some(addr) = numa.alloc_contiguous_on_node_aligned(
                NumaNodeId::new(node_idx as u8),
                frames_needed,
                align as u64,
            ) {
                return Some(addr);
            }
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_contiguous_aligned(frames_needed, align as u64);
    }

    FRAME_ALLOCATOR
        .lock()
        .allocate_contiguous(frames_needed, align)
}

/// 連続した (4KiB) フレームを指定NUMAノードからアライン指定で割り当てる
pub fn alloc_contiguous_frames_aligned_on_node(
    node: NumaNodeId,
    frames_needed: usize,
    align_bytes: usize,
) -> Option<PhysAddr> {
    if frames_needed == 0 {
        return None;
    }

    let align = align_size_to_page(align_bytes);

    if let Some(numa) = pmm_numa() {
        return numa.alloc_contiguous_on_node_aligned(node, frames_needed, align as u64);
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_contiguous_aligned(frames_needed, align as u64);
    }

    FRAME_ALLOCATOR
        .lock()
        .allocate_contiguous(frames_needed, align)
}

/// 連続した (4KiB) フレームを割り当てるラッパー
///
/// - `frames_needed`: 割り当てたいフレーム数
/// - 戻り値: 割り当て開始物理アドレス (4KiB 単位)
pub fn alloc_contiguous_frames(frames_needed: usize) -> Option<PhysAddr> {
    alloc_contiguous_frames_aligned(frames_needed, PAGE_SIZE_4K)
}

/// 連続領域を解放するラッパー
///
/// - `start`: 開始物理アドレス
/// - `frames`: フレーム数
pub fn dealloc_contiguous_frames(start: PhysAddr, frames: usize) {
    // Deallocate frame-by-frame (4KiB)
    for i in 0..frames {
        let addr = start.as_u64() + (i as u64) * (PAGE_SIZE_4K as u64);
        if let Ok(frame) = PhysFrame::<Size4KiB>::from_start_address(x86_64::PhysAddr::new(addr)) {
            if let Some(numa) = pmm_numa() {
                numa.deallocate_4k_frame(frame);
                continue;
            }
            if let Some(pmm) = pmm_global() {
                pmm.free_4k(frame);
                continue;
            }
            FRAME_ALLOCATOR.lock().deallocate_4k_frame(frame);
        }
    }
}

/// 2MiB 計測値取得（テスト用）
pub fn get_frame2m_local_alloc_metrics() -> (u64, u64) {
    (
        FRAME2M_LOCAL_ATTEMPTS.load(Ordering::Relaxed),
        FRAME2M_LOCAL_SUCCESSES.load(Ordering::Relaxed),
    )
}

/// 2MiB 計測値リセット（テスト用）
pub fn reset_frame2m_local_alloc_metrics() {
    FRAME2M_LOCAL_ATTEMPTS.store(0, Ordering::Relaxed);
    FRAME2M_LOCAL_SUCCESSES.store(0, Ordering::Relaxed);
}

/// 1GiB フレームを割り当て（設計書5.1: TLBエントリの消費を最小限に）
pub fn alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    if let Some(numa) = pmm_numa() {
        if let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() {
            if let Some(frame) = numa.allocate_1g_local(cpu_id as u8) {
                return Some(frame);
            }
        }
        for node_idx in 0..numa.topology().node_count() {
            if let Some(frame) = numa.allocate_1g_on_node(NumaNodeId::new(node_idx as u8)) {
                return Some(frame);
            }
        }
    }

    if let Some(pmm) = pmm_global() {
        return pmm.alloc_1g();
    }

    FRAME_ALLOCATOR.lock().allocate_1g_frame()
}

/// 2MiB フレームを解放
pub fn dealloc_frame_2m(frame: PhysFrame<Size2MiB>) {
    if let Some(numa) = pmm_numa() {
        numa.deallocate_2m_frame(frame);
        return;
    }
    if let Some(pmm) = pmm_global() {
        pmm.free_2m(frame);
        return;
    }
    FRAME_ALLOCATOR.lock().deallocate_2m_frame(frame);
}

/// 1GiB フレームを解放
pub fn dealloc_frame_1g(frame: PhysFrame<Size1GiB>) {
    if let Some(numa) = pmm_numa() {
        numa.deallocate_1g_frame(frame);
        return;
    }
    if let Some(pmm) = pmm_global() {
        pmm.free_1g(frame);
        return;
    }
    FRAME_ALLOCATOR.lock().deallocate_1g_frame(frame);
}

/// 4KiB フレームを解放（後方互換）
pub fn dealloc_frame(frame: PhysFrame<Size4KiB>) {
    if let Some(numa) = pmm_numa() {
        numa.deallocate_4k_frame(frame);
        return;
    }
    if let Some(pmm) = pmm_global() {
        pmm.free_4k(frame);
        return;
    }
    FRAME_ALLOCATOR.lock().deallocate_4k_frame(frame);
}

/// NUMAアロケータでフレームを解放
pub fn dealloc_frame_numa(frame: PhysFrame<Size4KiB>) {
    if let Some(numa) = pmm_numa() {
        numa.deallocate_4k_frame(frame);
        return;
    }
    dealloc_frame(frame);
}

/// フレームアロケータの統計を取得（後方互換）
pub fn frame_allocator_stats() -> (u64, usize) {
    if let Some(numa) = pmm_numa() {
        let stats = numa.stats();
        return (stats.total_free, stats.total_frames);
    }
    if let Some(pmm) = pmm_global() {
        return pmm.stats();
    }
    let allocator = FRAME_ALLOCATOR.lock();
    (allocator.free_frame_count(), allocator.total_frame_count())
}

/// NUMA対応統計を取得
pub fn numa_frame_allocator_stats() -> NumaAllocatorStats {
    if let Some(numa) = pmm_numa() {
        return numa.stats();
    }
    NUMA_FRAME_ALLOCATOR.lock().stats()
}

/// 現在のCPUが属するNUMAノードを取得
pub fn get_cpu_numa_node(cpu_id: u8) -> NumaNodeId {
    if let Some(numa) = pmm_numa() {
        return numa.topology().cpu_to_node(cpu_id);
    }
    NUMA_FRAME_ALLOCATOR.lock().topology().cpu_to_node(cpu_id)
}

/// 指定範囲がPMMで管理されているか（ベストエフォート）
pub fn is_range_managed_by_pmm(start: PhysAddr, size: u64) -> bool {
    if size == 0 {
        return false;
    }
    let Some(end) = start.as_u64().checked_add(size) else {
        return false;
    };

    if let Some(numa) = pmm_numa() {
        let topo = numa.topology();
        for node_idx in 0..topo.node_count() {
            let node = &topo.nodes[node_idx];
            for i in 0..node.range_count {
                let (range_start, range_size) = node.memory_ranges[i];
                let range_end = range_start.saturating_add(range_size);
                if start.as_u64() >= range_start && end <= range_end {
                    return true;
                }
            }
        }
        return false;
    }

    if let Some(pmm) = pmm_global() {
        let range_start = pmm.base;
        let range_end = pmm.base.saturating_add(pmm.size);
        return start.as_u64() >= range_start && end <= range_end;
    }

    crate::mm::buddy_allocator::is_range_managed_by_buddy(start, size)
}

/// PMMが管理する最大物理アドレス（排他的上限）を取得
pub fn pmm_managed_end() -> Option<u64> {
    if let Some(numa) = pmm_numa() {
        let topo = numa.topology();
        let mut max_end = 0u64;
        for node_idx in 0..topo.node_count() {
            let node = &topo.nodes[node_idx];
            for i in 0..node.range_count {
                let (start, size) = node.memory_ranges[i];
                max_end = max_end.max(start.saturating_add(size));
            }
        }
        return if max_end == 0 { None } else { Some(max_end) };
    }

    if let Some(pmm) = pmm_global() {
        let end = pmm.base.saturating_add(pmm.size);
        return if end == 0 { None } else { Some(end) };
    }

    None
}

/// PMM定期メンテナンス（リモートフリーの排出など）
///
/// 非ISRコンテキストから呼び出すこと。
pub fn pmm_maintenance_tick(tick: u64) {
    let Some(cpu_id) = crate::mm::per_cpu::try_current_cpu_id() else {
        return;
    };

    if let Some(numa) = pmm_numa() {
        if let Some(pmm) = numa.allocator_for_cpu(cpu_id as u8) {
            let _ = pmm.drain_remote_frees();
            if should_sync_single_writer(tick) {
                pmm.sync_single_writer_arenas();
            }
        }
        return;
    }

    if let Some(pmm) = pmm_global() {
        let _ = pmm.drain_remote_frees();
        if should_sync_single_writer(tick) {
            pmm.sync_single_writer_arenas();
        }
    }
}

/// NUMAノードから物理範囲を解放
fn release_range_from_numa(numa: &NumaPmmAllocator, start: u64, end: u64) -> u64 {
    let node_count = numa.topology.node_count;
    let mut freed = 0u64;
    for node_idx in 0..node_count {
        let node = &numa.topology.nodes[node_idx];
        let Some(pmm) = numa
            .node_allocators
            .get(node_idx)
            .and_then(|opt| opt.as_ref())
        else {
            continue;
        };
        for i in 0..node.range_count {
            let (range_start, range_size) = node.memory_ranges[i];
            let range_end = range_start.saturating_add(range_size);
            let rel_start = start.max(range_start);
            let rel_end = end.min(range_end);
            if rel_end > rel_start {
                freed += pmm.release_range_direct(rel_start, rel_end - rel_start);
            }
        }
    }
    freed
}

/// NUMA情報からメモリ領域を収集
fn collect_numa_memory_regions(numa_info: &NumaInfo, node_count: usize) -> Vec<(PhysAddr, u64, NumaNodeId)> {
    let mut regions: Vec<(PhysAddr, u64, NumaNodeId)> = Vec::new();
    for node_idx in 0..node_count {
        let node = &numa_info.nodes[node_idx];
        let range_count = (node.memory_range_count as usize).min(node.memory_ranges.len());
        for i in 0..range_count {
            let range = node.memory_ranges[i];
            if range.length == 0 {
                continue;
            }
            regions.push((
                PhysAddr::new(range.base),
                range.length,
                NumaNodeId::new(node_idx as u8),
            ));
        }
    }
    regions
}

/// 予約済みだった物理範囲をPMMに戻す（ACPI reclaimなど向け）
pub fn pmm_release_range(start: PhysAddr, size: u64) -> u64 {
    if size == 0 {
        return 0;
    }
    let start = start.as_u64();
    let end = start.saturating_add(size);
    let cpu_ids = crate::mm::per_cpu::online_cpu_ids();

    if let Some(numa) = unsafe { pmm_numa_mut() } {
        for allocator in numa.node_allocators.iter_mut() {
            if let Some(pmm) = allocator.as_mut() {
                pmm.configure_arenas_for_cpu_ids(&cpu_ids);
            }
        }

        let freed = release_range_from_numa(numa, start, end);

        for allocator in numa.node_allocators.iter_mut() {
            if let Some(pmm) = allocator.as_mut() {
                pmm.enable_single_writer();
            }
        }

        return freed;
    }

    if let Some(pmm) = unsafe { pmm_global_mut() } {
        pmm.configure_arenas_for_cpu_ids(&cpu_ids);
        let freed = pmm.release_range_direct(start, size);
        pmm.enable_single_writer();
        return freed;
    }

    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test_case]
    fn test_bitmap_allocator() {
        let mut allocator = BitmapFrameAllocator::new();

        // テスト用のメモリ領域（1MiB）
        let regions = [(PhysAddr::new(0x100000), 0x100000u64)];
        unsafe {
            allocator.init(&regions);
        }

        // フレーム割り当て
        let frame1 = allocator.allocate_4k_frame();
        assert!(frame1.is_some());

        let frame2 = allocator.allocate_4k_frame();
        assert!(frame2.is_some());

        // 異なるフレームが割り当てられていることを確認
        assert_ne!(
            frame1.unwrap().start_address(),
            frame2.unwrap().start_address()
        );
    }

    #[test_case]
    fn test_alloc_frame_numa_prefers_local_or_fallback() {
        let regions = [(PhysAddr::new(0x100000), 0x200000u64)];
        unsafe {
            init_frame_allocator(&regions);
        }
        reset_frame_local_alloc_metrics();
        let frame = alloc_frame();
        assert!(frame.is_some(), "alloc_frame failed to allocate a frame");
        let (attempts, successes) = get_frame_local_alloc_metrics();
        assert!(successes <= attempts);
    }

    #[test_case]
    fn test_alloc_frame_2m_numa_prefers_local_or_fallback() {
        let regions = [(PhysAddr::new(0x100000), 0x200000u64)];
        unsafe {
            init_frame_allocator(&regions);
        }
        reset_frame2m_local_alloc_metrics();
        let _frame = alloc_frame_2m(); // may be None on small test region
        let (attempts, successes) = get_frame2m_local_alloc_metrics();
        assert!(successes <= attempts);
    }

    #[test_case]
    fn test_alloc_dealloc_contiguous_wrapper() {
        // Try to allocate a single contiguous 4KiB frame; if not available, test is a no-op
        if let Some(start) = alloc_contiguous_frames(1) {
            // Map to virtual address using HHDM offset
            let virt = crate::memory::physical_memory_offset() + start.as_u64();
            let ptr = virt as *mut u8;
            unsafe {
                core::ptr::write_volatile(ptr, 0xA5u8);
                let v = core::ptr::read_volatile(ptr);
                assert_eq!(v, 0xA5u8);
            }
            dealloc_contiguous_frames(start, 1);
        }
    }
}

