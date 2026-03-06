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

use crate::mm::phys::fast_allocator::{FastBitmapAllocator, PageGranularity};
use crate::sync::IrqPoisonLock;
use alloc::boxed::Box;
use alloc::vec::Vec;
use boot_proto::NumaInfo;
use core::ptr;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use x86_64::PhysAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size1GiB, Size2MiB, Size4KiB};

// 共通型定義をインポート（IOVA_MM_MIGRATION_PLAN Phase 0.1）
use crate::loader::type_id::{SemVer, TypeHash, TypeIdHash, const_hash};
use crate::mm::numa::topology::{MAX_NUMA_NODES, NumaTopology};
use crate::mm::types::{FrameIndex, NumaNodeId, PAGE_SIZE_1G, PAGE_SIZE_2M, PAGE_SIZE_4K};

// ============================================================================
// 型安全性: フレーム番号のNewtype
// FrameIndex, PAGE_SIZE_* は crate::mm::types からインポート済み
// (IOVA_MM_MIGRATION_PLAN Phase 0.1 による統一)
// ============================================================================

/// PMMが管理する最大ページ数 (IOVA bitmapと同等: 256GiB / 4KiB)
mod numa;
pub use numa::*;
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
#[derive(Debug)]
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
            // 脆弱性修正: ページ境界にアライン。開始は切り上げ、終了は切り下げ。
            // これにより、部分的に予約されているページが空きとしてマークされるのを防ぐ。
            let start_addr =
                (start.as_u64() + PAGE_SIZE_4K as u64 - 1) & !(PAGE_SIZE_4K as u64 - 1);
            let end_addr = (start.as_u64() + size) & !(PAGE_SIZE_4K as u64 - 1);

            if start_addr >= end_addr {
                continue;
            }

            let start_frame = FrameIndex::from_phys_addr(start_addr);
            let end_frame = FrameIndex::from_phys_addr(end_addr);

            for frame_idx in start_frame.as_usize()..end_frame.as_usize() {
                if frame_idx < MAX_4K_FRAMES {
                    self.mark_frame_free(FrameIndex::new(frame_idx));
                    free = free.saturating_add(1);
                }
            }

            total = total.max(end_frame.as_usize());
        }

        self.total_frames = total.min(MAX_4K_FRAMES);
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
                self.free_frames = self.free_frames.saturating_sub(1);
                self.next_free_hint = (frame.as_usize() as u64).saturating_add(1);

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
        if frame_count == 0 {
            return None;
        }
        // 脆弱性修正: alignmentが0の場合の除算ゼロを防止
        let alignment = alignment.max(PAGE_SIZE_4K);
        let aligned_frames = alignment / PAGE_SIZE_4K;

        if aligned_frames == 0 {
            return None;
        }

        for start_word in 0..BITMAP_WORDS {
            let start_frame = start_word * 64;

            // アライメントに合わせる (Checked arithmetic to avoid overflow)
            let aligned_start = (start_frame.checked_add(aligned_frames)?.saturating_sub(1)
                / aligned_frames)
                * aligned_frames;

            if aligned_start.saturating_add(frame_count) > self.total_frames {
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
                self.free_frames = self.free_frames.saturating_sub(frame_count as u64);

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

        // 脆弱性修正: 二重解放の防止
        if self.is_frame_free(frame_idx) {
            log::warn!(
                "[PMM] Double free detected for 4KiB frame {:#x}",
                frame.start_address().as_u64()
            );
            return;
        }

        // Memcg: ページがmemcgでトラックされている場合はuntrackしてチャージを戻す
        crate::mm::meta::memcg::memcg_untrack_and_uncharge(frame_idx, 1);

        self.mark_frame_free(frame_idx);
        self.free_frames += 1;
    }

    /// 2MiB フレームを解放
    pub fn deallocate_2m_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_2M / PAGE_SIZE_4K;

        // 脆弱性修正: 二重解放の防止（先頭ページで代表チェック）
        if self.is_frame_free(start_frame) {
            log::warn!(
                "[PMM] Double free detected for 2MiB frame {:#x}",
                frame.start_address().as_u64()
            );
            return;
        }

        // Memcg: 各4KiBページについてアンチャージ/アンストラックする
        for i in 0..frames_count {
            let idx = FrameIndex::new(start_frame.as_usize() + i);
            crate::mm::meta::memcg::memcg_untrack_and_uncharge(idx, 1);
            self.mark_frame_free(idx);
        }
        self.free_frames += frames_count as u64;
    }

    /// 1GiB フレームを解放
    pub fn deallocate_1g_frame(&mut self, frame: PhysFrame<Size1GiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_1G / PAGE_SIZE_4K;

        // 脆弱性修正: 二重解放の防止（先頭ページで代表チェック）
        if self.is_frame_free(start_frame) {
            log::warn!(
                "[PMM] Double free detected for 1GiB frame {:#x}",
                frame.start_address().as_u64()
            );
            return;
        }

        // Memcg: 各4KiBページについてアンチャージ/アンストラックする
        for i in 0..frames_count {
            let idx = FrameIndex::new(start_frame.as_usize() + i);
            crate::mm::meta::memcg::memcg_untrack_and_uncharge(idx, 1);
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

impl TypeIdHash for BitmapFrameAllocator {
    fn type_id_hash() -> TypeHash {
        const_hash(b"BitmapFrameAllocator:v1:total_frames,free_frames")
    }

    fn type_name() -> &'static str {
        "BitmapFrameAllocator"
    }

    fn type_version() -> SemVer {
        SemVer::new(1, 0, 0)
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
pub(crate) struct PmmAllocatorFast {
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
        let _ = self.inner.free_immediate(addr, PageGranularity::Page4K);
    }

    fn free_2m(&self, frame: PhysFrame<Size2MiB>) {
        let addr = frame.start_address().as_u64();
        let _ = self.inner.free_immediate(addr, PageGranularity::Page2M);
    }

    fn free_1g(&self, frame: PhysFrame<Size1GiB>) {
        let addr = frame.start_address().as_u64();
        let _ = self.inner.free_immediate(addr, PageGranularity::Page1G);
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
        if self.inner.free_range_immediate(range_start, len).is_ok() {
            len / (PAGE_SIZE_4K as u64)
        } else {
            0
        }
    }
}

use crate::util::{align_down_u64 as align_down, align_up_u64 as align_up};

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
#[derive(Debug)]
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

impl TypeIdHash for NumaFrameAllocator {
    fn type_id_hash() -> TypeHash {
        const_hash(b"NumaFrameAllocator:v1:node_allocators,topology")
    }

    fn type_name() -> &'static str {
        "NumaFrameAllocator"
    }

    fn type_version() -> SemVer {
        SemVer::new(1, 0, 0)
    }
}
