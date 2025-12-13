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

use crate::sync::IrqMutex;
use x86_64::PhysAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size1GiB, Size2MiB, Size4KiB};

// ============================================================================
// NUMA対応（設計書 5.3: NUMA-Awareメモリアロケータ）
// ============================================================================

/// 最大NUMAノード数
pub const MAX_NUMA_NODES: usize = 8;

/// NUMAノードID
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct NumaNodeId(pub u8);

impl NumaNodeId {
    /// ノードIDを作成
    #[inline]
    pub const fn new(id: u8) -> Self {
        Self(id)
    }

    /// 生の値を取得
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// usizeとして取得
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }
}

/// NUMAノード情報
/// 設計書 5.3.1: NUMAドメインの抽象化
#[derive(Debug, Clone)]
pub struct NumaNode {
    /// ノードID
    pub id: NumaNodeId,
    /// このノードのメモリ範囲（開始アドレス、サイズ）
    pub memory_ranges: [(u64, u64); 4], // 最大4つの不連続範囲をサポート
    /// 有効なメモリ範囲数
    pub range_count: usize,
    /// このノードに属するCPUコアのビットマスク
    pub cpu_mask: u64,
    /// 総メモリサイズ（バイト）
    pub total_memory: u64,
}

impl NumaNode {
    /// 空のNUMAノードを作成
    pub const fn empty(id: NumaNodeId) -> Self {
        Self {
            id,
            memory_ranges: [(0, 0); 4],
            range_count: 0,
            cpu_mask: 0,
            total_memory: 0,
        }
    }

    /// メモリ範囲を追加
    pub fn add_memory_range(&mut self, start: u64, size: u64) {
        if self.range_count < 4 {
            self.memory_ranges[self.range_count] = (start, size);
            self.range_count += 1;
            self.total_memory += size;
        }
    }

    /// CPUコアを追加
    pub fn add_cpu(&mut self, cpu_id: u8) {
        if cpu_id < 64 {
            self.cpu_mask |= 1u64 << cpu_id;
        }
    }

    /// 指定アドレスがこのノードに属するか判定
    pub fn contains_address(&self, addr: u64) -> bool {
        for i in 0..self.range_count {
            let (start, size) = self.memory_ranges[i];
            if addr >= start && addr < start + size {
                return true;
            }
        }
        false
    }
}

/// NUMAトポロジ情報
/// 設計書 5.3.1: 起動時にACPI SRATから検出
pub struct NumaTopology {
    /// 各NUMAノードの情報
    nodes: [NumaNode; MAX_NUMA_NODES],
    /// 有効なノード数
    node_count: usize,
    /// ノード間距離行列（キャッシュライン考慮）
    /// 値が大きいほど遠い（レイテンシが高い）
    distance_matrix: [[u8; MAX_NUMA_NODES]; MAX_NUMA_NODES],
}

impl NumaTopology {
    /// 空のトポロジを作成（シングルノードとして初期化）
    pub const fn new() -> Self {
        let nodes = [
            NumaNode::empty(NumaNodeId::new(0)),
            NumaNode::empty(NumaNodeId::new(1)),
            NumaNode::empty(NumaNodeId::new(2)),
            NumaNode::empty(NumaNodeId::new(3)),
            NumaNode::empty(NumaNodeId::new(4)),
            NumaNode::empty(NumaNodeId::new(5)),
            NumaNode::empty(NumaNodeId::new(6)),
            NumaNode::empty(NumaNodeId::new(7)),
        ];

        // デフォルトの距離行列（ローカル=10、リモート=20）
        let distance_matrix = [
            [10, 20, 20, 20, 20, 20, 20, 20],
            [20, 10, 20, 20, 20, 20, 20, 20],
            [20, 20, 10, 20, 20, 20, 20, 20],
            [20, 20, 20, 10, 20, 20, 20, 20],
            [20, 20, 20, 20, 10, 20, 20, 20],
            [20, 20, 20, 20, 20, 10, 20, 20],
            [20, 20, 20, 20, 20, 20, 10, 20],
            [20, 20, 20, 20, 20, 20, 20, 10],
        ];

        Self {
            nodes,
            node_count: 1, // デフォルトは1ノード
            distance_matrix,
        }
    }

    /// ノード数を取得
    #[inline]
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// ノード情報を取得
    pub fn get_node(&self, id: NumaNodeId) -> Option<&NumaNode> {
        let idx = id.as_usize();
        if idx < self.node_count {
            Some(&self.nodes[idx])
        } else {
            None
        }
    }

    /// CPUコアが属するNUMAノードを取得
    pub fn cpu_to_node(&self, cpu_id: u8) -> NumaNodeId {
        for i in 0..self.node_count {
            if (self.nodes[i].cpu_mask & (1u64 << cpu_id)) != 0 {
                return NumaNodeId::new(i as u8);
            }
        }
        // 見つからない場合はノード0
        NumaNodeId::new(0)
    }

    /// 物理アドレスが属するNUMAノードを取得
    pub fn addr_to_node(&self, addr: u64) -> NumaNodeId {
        for i in 0..self.node_count {
            if self.nodes[i].contains_address(addr) {
                return NumaNodeId::new(i as u8);
            }
        }
        NumaNodeId::new(0)
    }

    /// ノード間の距離を取得
    #[inline]
    pub fn distance(&self, from: NumaNodeId, to: NumaNodeId) -> u8 {
        self.distance_matrix[from.as_usize()][to.as_usize()]
    }

    /// 指定ノードからの優先順位でノードをソート
    /// 近いノードが先頭に来る
    pub fn nodes_by_distance(&self, from: NumaNodeId) -> [NumaNodeId; MAX_NUMA_NODES] {
        let mut result = [NumaNodeId::new(0); MAX_NUMA_NODES];
        let mut indices: [usize; MAX_NUMA_NODES] = [0, 1, 2, 3, 4, 5, 6, 7];

        // 距離でソート（バブルソート）
        for i in 0..self.node_count {
            for j in (i + 1)..self.node_count {
                let dist_i = self.distance(from, NumaNodeId::new(indices[i] as u8));
                let dist_j = self.distance(from, NumaNodeId::new(indices[j] as u8));
                if dist_i > dist_j {
                    indices.swap(i, j);
                }
            }
        }

        for (i, &idx) in indices.iter().enumerate() {
            result[i] = NumaNodeId::new(idx as u8);
        }
        result
    }
}

// ============================================================================
// 型安全性: フレーム番号のNewtype
// 物理アドレスとフレームインデックスの取り違えをコンパイル時に防ぐ
// ============================================================================

/// フレーム番号（物理アドレス / PAGE_SIZE_4K）
///
/// 型安全性のためのNewTypeパターン。
/// `usize` や `PhysAddr` との取り違えをコンパイル時に検出。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FrameIndex(usize);

impl FrameIndex {
    /// フレーム番号から作成
    #[inline]
    pub const fn new(index: usize) -> Self {
        Self(index)
    }

    /// 物理アドレスからフレーム番号を計算
    #[inline]
    pub const fn from_phys_addr(addr: u64) -> Self {
        Self((addr as usize) / PAGE_SIZE_4K)
    }

    /// フレーム番号を物理アドレスに変換
    #[inline]
    pub const fn to_phys_addr(self) -> u64 {
        (self.0 * PAGE_SIZE_4K) as u64
    }

    /// 生の値を取得
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// ビットマップのワードインデックスを取得
    #[inline]
    pub const fn word_index(self) -> usize {
        self.0 / 64
    }

    /// ビットマップ内のビット位置を取得
    #[inline]
    pub const fn bit_index(self) -> usize {
        self.0 % 64
    }
}

/// 4KiB ページサイズ
pub const PAGE_SIZE_4K: usize = 4096;
/// 2MiB ページサイズ
pub const PAGE_SIZE_2M: usize = 2 * 1024 * 1024;
/// 1GiB ページサイズ
pub const PAGE_SIZE_1G: usize = 1024 * 1024 * 1024;

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
        self.mark_frame_free(frame_idx);
        self.free_frames += 1;
    }

    /// 2MiB フレームを解放
    pub fn deallocate_2m_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_2M / PAGE_SIZE_4K;

        for i in 0..frames_count {
            self.mark_frame_free(FrameIndex::new(start_frame.as_usize() + i));
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
            let node_regions: [(PhysAddr, u64); 16] = {
                let mut regions = [(PhysAddr::zero(), 0u64); 16];
                let mut count = 0;
                for &(addr, size, region_node) in usable_regions {
                    if region_node == node_id && count < 16 {
                        regions[count] = (addr, size);
                        count += 1;
                    }
                }
                regions
            };

            // このノードに領域があれば初期化
            let mut has_regions = false;
            for &(_, size) in &node_regions {
                if size > 0 {
                    has_regions = true;
                    break;
                }
            }

            if has_regions {
                let valid_regions: alloc::vec::Vec<_> = node_regions
                    .iter()
                    .filter(|&&(_, size)| size > 0)
                    .copied()
                    .collect();

                unsafe {
                    self.node_allocators[node_idx].init(&valid_regions);
                }

                // トポロジにメモリ範囲を追加
                for (addr, size) in valid_regions {
                    self.topology.nodes[node_idx].add_memory_range(addr.as_u64(), size);
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

/// フレームアロケータを初期化（後方互換）
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_frame_allocator(usable_regions: &[(PhysAddr, u64)]) {
    // SAFETY: 呼び出し元がusable_regionsの正当性を保証
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
    // SAFETY: 呼び出し元がregionsの正当性を保証
    unsafe {
        NUMA_FRAME_ALLOCATOR.lock().init_numa(regions);
    }
}

/// 4KiB フレームを割り当て（後方互換）
pub fn alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    FRAME_ALLOCATOR.lock().allocate_4k_frame()
}

/// 指定NUMAノードから4KiBフレームを割り当て
/// 設計書 5.3.2: 明示的なノード指定API
pub fn alloc_frame_on_numa_node(node: NumaNodeId) -> Option<PhysFrame<Size4KiB>> {
    NUMA_FRAME_ALLOCATOR.lock().allocate_4k_on_node(node)
}

/// 現在のCPUのローカルNUMAノードから4KiBフレームを割り当て
/// 設計書 5.3.2: First-Touch Policy
pub fn alloc_frame_local(current_cpu: u8) -> Option<PhysFrame<Size4KiB>> {
    NUMA_FRAME_ALLOCATOR.lock().allocate_4k_local(current_cpu)
}

/// 2MiB フレームを割り当て（後方互換）
pub fn alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    FRAME_ALLOCATOR.lock().allocate_2m_frame()
}

/// 指定NUMAノードから2MiBフレームを割り当て
pub fn alloc_frame_2m_on_numa_node(node: NumaNodeId) -> Option<PhysFrame<Size2MiB>> {
    NUMA_FRAME_ALLOCATOR.lock().allocate_2m_on_node(node)
}

/// 現在のCPUのローカルNUMAノードから2MiBフレームを割り当て
pub fn alloc_frame_2m_local(current_cpu: u8) -> Option<PhysFrame<Size2MiB>> {
    NUMA_FRAME_ALLOCATOR.lock().allocate_2m_local(current_cpu)
}

/// 1GiB フレームを割り当て（設計書5.1: TLBエントリの消費を最小限に）
pub fn alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    FRAME_ALLOCATOR.lock().allocate_1g_frame()
}

/// 4KiB フレームを解放（後方互換）
pub fn dealloc_frame(frame: PhysFrame<Size4KiB>) {
    FRAME_ALLOCATOR.lock().deallocate_4k_frame(frame);
}

/// NUMAアロケータでフレームを解放
pub fn dealloc_frame_numa(frame: PhysFrame<Size4KiB>) {
    NUMA_FRAME_ALLOCATOR.lock().deallocate_4k_frame(frame);
}

/// フレームアロケータの統計を取得（後方互換）
pub fn frame_allocator_stats() -> (u64, usize) {
    let allocator = FRAME_ALLOCATOR.lock();
    (allocator.free_frame_count(), allocator.total_frame_count())
}

/// NUMA対応統計を取得
pub fn numa_frame_allocator_stats() -> NumaAllocatorStats {
    NUMA_FRAME_ALLOCATOR.lock().stats()
}

/// 現在のCPUが属するNUMAノードを取得
pub fn get_cpu_numa_node(cpu_id: u8) -> NumaNodeId {
    NUMA_FRAME_ALLOCATOR.lock().topology().cpu_to_node(cpu_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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
}
