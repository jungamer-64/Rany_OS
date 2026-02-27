// ============================================================================
// src/mm/buddy_allocator.rs - Buddy Allocator for Physical Frames
// 設計書 5.2 Tier1改良: O(log n) 物理フレーム管理
//
// ビットマップFirst-fitの問題点:
// - 連続フレーム検索が O(n)
// - フラグメンテーション発生時に性能劣化
//
// Buddy Allocatorの利点:
// - 割り当て/解放が O(log n)
// - 連続領域の確保が効率的
// - 2のべき乗サイズの自然なサポート
//
// ## 最適化
//
// - TZCNT命令活用: ビットスキャンを O(64) → O(1) に高速化
// ============================================================================
#![allow(dead_code)]

use crate::sync::IrqPoisonLock;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::PhysAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size1GiB, Size2MiB, Size4KiB};

// 共通型定義をインポート（IOVA_MM_MIGRATION_PLAN Phase 0.1）
use crate::mm::types::{FrameIndex, NumaNodeId, PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G};

// ============================================================================
// TZCNT (Trailing Zero Count) 高速化
// ============================================================================

/// x86_64 TZCNT命令を使用した高速trailing zero count
/// 
/// TZCNT命令はBMI1拡張で利用可能。利用不可の場合はBSF命令にフォールバック。
/// 両方ともO(1)で実行される。
/// 
/// # Performance
/// 
/// - TZCNT: 3サイクル（Haswell以降）
/// - trailing_zeros(): コンパイラ最適化次第（通常はTZCNT/BSFにコンパイルされる）
mod core_alloc;
pub use core_alloc::*;
#[inline(always)]
fn fast_tzcnt_u64(word: u64) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        // 安全なintrinsicsを使用（Rustコンパイラが適切な命令を選択）
        word.trailing_zeros()
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        word.trailing_zeros()
    }
}

// ============================================================================
// Phase 1 最適化: SIMD Bitmap Scan (AVX2/SSE4.2)
// ============================================================================

/// SIMD機能の利用可能フラグ
mod simd_support {
    use core::sync::atomic::{AtomicBool, Ordering};
    
    /// AVX2が利用可能か
    pub static AVX2_AVAILABLE: AtomicBool = AtomicBool::new(false);
    /// SSE4.2が利用可能か
    pub static SSE42_AVAILABLE: AtomicBool = AtomicBool::new(false);
    /// SIMD初期化済みフラグ
    pub static SIMD_INITIALIZED: AtomicBool = AtomicBool::new(false);
    
    /// SIMD機能を初期化（CPUIDでチェック）
    pub fn init_simd_features() {
        if SIMD_INITIALIZED.load(Ordering::Acquire) {
            return;
        }
        
        #[cfg(target_arch = "x86_64")]
        {
            // CPUID.01H:ECX.SSE4_2[bit 20]
            let cpuid1 = core::arch::x86_64::__cpuid(1);
            let sse42 = (cpuid1.ecx >> 20) & 1 != 0;
            SSE42_AVAILABLE.store(sse42, Ordering::Release);
            
            // CPUID.07H:EBX.AVX2[bit 5]
            let cpuid7 = core::arch::x86_64::__cpuid_count(7, 0);
            let avx2 = (cpuid7.ebx >> 5) & 1 != 0;
            AVX2_AVAILABLE.store(avx2, Ordering::Release);
        }
        
        SIMD_INITIALIZED.store(true, Ordering::Release);
    }
    
    #[inline]
    pub fn has_avx2() -> bool {
        AVX2_AVAILABLE.load(Ordering::Relaxed)
    }
    
    #[inline]
    pub fn has_sse42() -> bool {
        SSE42_AVAILABLE.load(Ordering::Relaxed)
    }
}

/// SIMD Bitmap Scan統計
pub struct SimdScanStats {
    /// SIMDスキャン回数
    pub simd_scans: core::sync::atomic::AtomicU64,
    /// スカラースキャン回数（フォールバック）
    pub scalar_scans: core::sync::atomic::AtomicU64,
    /// SIMDで見つかった空きブロック数
    pub simd_found: core::sync::atomic::AtomicU64,
}

impl SimdScanStats {
    pub const fn new() -> Self {
        Self {
            simd_scans: core::sync::atomic::AtomicU64::new(0),
            scalar_scans: core::sync::atomic::AtomicU64::new(0),
            simd_found: core::sync::atomic::AtomicU64::new(0),
        }
    }
}

/// グローバルSIMDスキャン統計
pub static SIMD_SCAN_STATS: SimdScanStats = SimdScanStats::new();

/// ビットマップスライスから最初のセットビット（空きブロック）を検索
/// 
/// ## アルゴリズム
/// 
/// 1. AVX2/SSE利用可能ならSIMD並列スキャン
/// 2. 利用不可ならスカラー版（TZCNT）にフォールバック
/// 
/// ## SIMD戦略
/// 
/// - AVX2: 256ビット（4 x u64）を一度に比較
/// - SSE4.2: 128ビット（2 x u64）を一度に比較
/// - スカラー: u64ごとにTZCNT
/// 
/// ## 戻り値
/// 
/// - `Some(bit_index)`: 空きブロックのビットインデックス
/// - `None`: 空きブロックなし
#[inline]
pub fn find_first_set_bit_simd(bitmap: &[u64]) -> Option<usize> {
    if bitmap.is_empty() {
        return None;
    }
    
    // SIMD初期化チェック
    if !simd_support::SIMD_INITIALIZED.load(core::sync::atomic::Ordering::Acquire) {
        simd_support::init_simd_features();
    }
    
    #[cfg(target_arch = "x86_64")]
    {
        // AVX2版: 4 x u64を並列スキャン
        if simd_support::has_avx2() && bitmap.len() >= 4 {
            if let Some(idx) = find_first_set_bit_avx2(bitmap) {
                SIMD_SCAN_STATS.simd_scans.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                SIMD_SCAN_STATS.simd_found.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
                return Some(idx);
            }
        }
    }
    
    // スカラーフォールバック
    SIMD_SCAN_STATS.scalar_scans.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    find_first_set_bit_scalar(bitmap)
}

/// AVX2によるビットマップスキャン（4 x u64並列）
/// 
/// This function is only available when AVX2 is enabled at compile time.
/// Runtime AVX2 detection is done in find_first_set_bit_simd before calling.
#[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
#[inline]
fn find_first_set_bit_avx2(bitmap: &[u64]) -> Option<usize> {
    use core::arch::x86_64::*;
    
    let chunks = bitmap.len() / 4;
    
    for chunk_idx in 0..chunks {
        let base = chunk_idx * 4;
        
        unsafe {
            // 4つのu64をロード
            let ptr = bitmap.as_ptr().add(base) as *const __m256i;
            let vec = _mm256_loadu_si256(ptr);
            
            // ゼロと比較（非ゼロ = 空きブロックあり）
            let zero = _mm256_setzero_si256();
            let cmp = _mm256_cmpeq_epi64(vec, zero);
            
            // マスクを取得（各64ビット要素の符号ビット）
            let mask = _mm256_movemask_pd(_mm256_castsi256_pd(cmp));
            
            // mask == 0xF なら全てゼロ（空きなし）
            if mask != 0xF {
                // 非ゼロの要素がある → 詳細スキャン
                for i in 0..4 {
                    let word = bitmap[base + i];
                    if word != 0 {
                        let bit_in_word = fast_tzcnt_u64(word) as usize;
                        return Some((base + i) * 64 + bit_in_word);
                    }
                }
            }
        }
    }
    
    // 残りをスカラーでスキャン
    let remainder_start = chunks * 4;
    for (i, &word) in bitmap[remainder_start..].iter().enumerate() {
        if word != 0 {
            let bit_in_word = fast_tzcnt_u64(word) as usize;
            return Some((remainder_start + i) * 64 + bit_in_word);
        }
    }
    
    None
}

/// Fallback for targets without AVX2 at compile time - just use scalar
#[cfg(not(all(target_arch = "x86_64", target_feature = "avx2")))]
#[inline]
fn find_first_set_bit_avx2(_bitmap: &[u64]) -> Option<usize> {
    // This function should not be called on non-AVX2 targets
    // The caller (find_first_set_bit_simd) checks has_avx2() at runtime
    // which would never return true on a soft-float target
    None
}

/// スカラー版ビットマップスキャン（フォールバック）
#[inline]
fn find_first_set_bit_scalar(bitmap: &[u64]) -> Option<usize> {
    for (word_idx, &word) in bitmap.iter().enumerate() {
        if word != 0 {
            let bit_in_word = fast_tzcnt_u64(word) as usize;
            return Some(word_idx * 64 + bit_in_word);
        }
    }
    None
}

/// 指定位置からの循環スキャン（Round-Robin対応）
/// 
/// カーソル位置から開始し、ビットマップを循環的にスキャン。
/// メモリ領域の均等使用を促進。
#[inline]
pub fn find_first_set_bit_from(bitmap: &[u64], start_word: usize) -> Option<usize> {
    if bitmap.is_empty() {
        return None;
    }
    
    let len = bitmap.len();
    let start = start_word % len;
    
    // start から末尾まで
    for word_idx in start..len {
        if bitmap[word_idx] != 0 {
            let bit_in_word = fast_tzcnt_u64(bitmap[word_idx]) as usize;
            return Some(word_idx * 64 + bit_in_word);
        }
    }
    
    // 先頭から start まで（循環）
    for word_idx in 0..start {
        if bitmap[word_idx] != 0 {
            let bit_in_word = fast_tzcnt_u64(bitmap[word_idx]) as usize;
            return Some(word_idx * 64 + bit_in_word);
        }
    }
    
    None
}

/// 複数ビット連続空き領域を検索（大ブロック割り当て向け）
/// 
/// 連続したnビットのセット（空き）を検索。
/// 2MBや1GBページの割り当てに使用。
#[inline]
/// Scan bitmap words for a contiguous run of set bits with the given length.
fn scan_contiguous_run(bitmap: &[u64], count: usize) -> Option<usize> {
    let mut run_start = None;
    let mut run_len = 0;

    for word_idx in 0..bitmap.len() {
        let word = bitmap[word_idx];

        for bit in 0..64 {
            let bit_idx = word_idx * 64 + bit;
            if (word >> bit) & 1 != 0 {
                if run_start.is_none() {
                    run_start = Some(bit_idx);
                    run_len = 0;
                }
                run_len += 1;
                if run_len >= count {
                    return run_start;
                }
            } else {
                run_start = None;
                run_len = 0;
            }
        }
    }

    None
}

pub fn find_contiguous_set_bits(bitmap: &[u64], count: usize) -> Option<usize> {
    if count == 0 || bitmap.is_empty() {
        return None;
    }

    if count == 1 {
        return find_first_set_bit_simd(bitmap);
    }

    scan_contiguous_run(bitmap, count)
}

/// 最大オーダー（2^MAX_ORDER * 4KiB = 最大ブロックサイズ）
/// MAX_ORDER = 10 → 4MiB ブロック
/// MAX_ORDER = 18 → 1GiB ブロック（1GiBページ対応）
pub const MAX_ORDER: usize = 18;

/// PMMから借りる最小オーダー（小さな要求でもまとめて確保）
const BUDDY_BORROW_MIN_ORDER: usize = 9; // 2MiB

/// 物理メモリの最大サイズ（16GiB想定）
const MAX_PHYSICAL_MEMORY: usize = 16 * 1024 * 1024 * 1024;

/// 4KiBページ数の最大値
const MAX_4K_FRAMES: usize = MAX_PHYSICAL_MEMORY / PAGE_SIZE_4K;

/// 全オーダーの空きビット数の合計（完全二分木）
const TOTAL_BLOCKS: usize = MAX_4K_FRAMES * 2 - 1;

/// 空きビットの総ワード数（u64）
/// 空きビットの総ワード数（u64）
const TOTAL_DETAIL_WORDS: usize = total_detail_words();

const fn total_detail_words() -> usize {
    let mut total = 0usize;
    let mut order = 0usize;
    while order <= MAX_ORDER {
        let blocks = MAX_4K_FRAMES >> order;
        let detail_words = (blocks + 63) / 64;
        total += detail_words;
        order += 1;
    }
    total
}

/// 各オーダーのサマリービットの総ワード数（u64）
const TOTAL_SUMMARY_WORDS: usize = total_summary_words();

const fn total_summary_words() -> usize {
    let mut total = 0usize;
    let mut order = 0usize;
    while order <= MAX_ORDER {
        let blocks = MAX_4K_FRAMES >> order;
        let detail_words = (blocks + 63) / 64;
        let summary_words = (detail_words + 63) / 64;
        total += summary_words;
        order += 1;
    }
    total
}

// FrameIndexはcrate::mm::types::FrameIndexを使用
// (IOVA_MM_MIGRATION_PLAN Phase 0.1 による統一)
// buddy(), align_down() メソッドも types.rs に含まれている

// (FreeList removed: order-local free bitsets are used instead.)

// ============================================================================
// Coalesce Policy with Hysteresis (v0.6.0)
// ============================================================================
//
// 単純な閾値ベースの遅延結合では、閾値付近で結合と分割が繰り返される
// 「チャタリング」が発生する可能性がある。
//
// Hysteresisパターン:
// - low watermark以下 → 結合を積極的に実行
// - high watermark以上 → 結合をスキップ（十分な空きあり）
// - 間 → 前回の状態を維持
//
// これにより、安定した動作と不要なCPUサイクル消費を防ぐ。
// ============================================================================

/// Coalesceポリシーの状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CoalesceState {
    /// 結合を積極的に実行する状態
    Coalescing = 0,
    /// 結合をスキップする状態（十分な空きあり）
    Deferring = 1,
}

/// Hysteresisベースの結合ポリシー
#[derive(Debug, Clone, Copy)]
pub struct CoalescePolicy {
    /// Low watermark: この空きブロック数以下で結合開始
    pub low_watermark: usize,
    /// High watermark: この空きブロック数以上で結合抑制
    pub high_watermark: usize,
    /// 現在の状態
    state: CoalesceState,
    /// 統計: 結合遅延回数
    deferrals: u64,
    /// 統計: 強制結合回数
    forced_coalesces: u64,
}

impl CoalescePolicy {
    /// 新しいポリシーを作成
    /// 
    /// デフォルト: low=32, high=128 のブロック数
    pub const fn new() -> Self {
        Self {
            low_watermark: 32,
            high_watermark: 128,
            state: CoalesceState::Deferring,
            deferrals: 0,
            forced_coalesces: 0,
        }
    }
    
    /// watermarkを設定
    pub fn set_watermarks(&mut self, low: usize, high: usize) {
        self.low_watermark = low;
        self.high_watermark = high.max(low + 1);
    }
    
    /// 現在の空きブロック数に基づいて結合すべきか判定
    /// 
    /// Hysteresisロジック:
    /// - free <= low → Coalescing状態へ遷移、trueを返す
    /// - free >= high → Deferring状態へ遷移、falseを返す
    /// - 間 → 前回の状態を維持
    #[inline]
    pub fn should_coalesce(&mut self, free_blocks: usize) -> bool {
        if free_blocks <= self.low_watermark {
            if self.state == CoalesceState::Deferring {
                self.forced_coalesces += 1;
            }
            self.state = CoalesceState::Coalescing;
            true
        } else if free_blocks >= self.high_watermark {
            if self.state == CoalesceState::Coalescing {
                self.deferrals += 1;
            }
            self.state = CoalesceState::Deferring;
            false
        } else {
            // Hysteresis: 前回の状態を維持
            self.state == CoalesceState::Coalescing
        }
    }
    
    /// 強制的に結合状態にする（メモリ圧迫時）
    #[inline]
    pub fn force_coalesce(&mut self) {
        self.state = CoalesceState::Coalescing;
        self.forced_coalesces += 1;
    }
    
    /// 統計情報を取得
    pub fn stats(&self) -> CoalescePolicyStats {
        CoalescePolicyStats {
            state: self.state,
            deferrals: self.deferrals,
            forced_coalesces: self.forced_coalesces,
        }
    }
}

impl Default for CoalescePolicy {
    fn default() -> Self {
        Self::new()
    }
}

/// CoalescePolicy統計
#[derive(Debug, Clone, Copy)]
pub struct CoalescePolicyStats {
    pub state: CoalesceState,
    pub deferrals: u64,
    pub forced_coalesces: u64,
}

// ============================================================================
// Memory Compaction - Proactive Defragmentation (v0.6.0)
// ============================================================================
//
// フラグメンテーションを削減するためのプロアクティブなメモリ圧縮機構。
//
// ## 目的
//
// - 高次オーダーの連続領域を確保しやすくする
// - 大きなブロック（2MB, 1GB）の割り当て成功率を向上
// - バックグラウンドで徐々に圧縮して突発的なレイテンシを回避
//
// ## 戦略
//
// 1. フラグメンテーション率を監視
// 2. 閾値を超えたらバックグラウンド圧縮を開始
// 3. 低次オーダーのブロックを移動して高次オーダーに結合
//
// ============================================================================

/// 圧縮状態
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompactionState {
    /// アイドル（圧縮不要）
    Idle = 0,
    /// 圧縮中（バックグラウンドで実行中）
    Compacting = 1,
    /// 完了（圧縮終了、次回チェックまで待機）
    Done = 2,
}

/// 圧縮統計
#[derive(Debug, Clone, Copy)]
pub struct CompactionStats {
    /// 圧縮サイクル数
    pub cycles: u64,
    /// 移動したページ数
    pub pages_moved: u64,
    /// 作成された高次ブロック数
    pub blocks_created: u64,
    /// 圧縮による空きブロック増加数
    pub freed_blocks: u64,
}

// ============================================================================
// Fragmentation Index - Detailed Fragmentation Metrics (Phase 2.1)
// ============================================================================
//
// より詳細なフラグメンテーション分析を提供。
// 外部/内部フラグメンテーションを分離して計算することで、
// 適切な対処法（コンパクション vs 結合）を選択できる。
//
// ## 指標
//
// - external: 空き領域が散在している度合い (0.0-1.0)
//   高い値 → コンパクションが有効
// - internal: 大きなブロックが小さく分割されている度合い (0.0-1.0)
//   高い値 → 結合 (coalescing) が有効
// - unusable: 要求オーダーに対して使用不能な空き領域の割合
//
// ============================================================================

/// 詳細なフラグメンテーション指標
/// 
/// 単純なパーセンテージではなく、フラグメンテーションの種類と
/// 深刻度を分離して表現する。
#[derive(Debug, Clone, Copy, Default)]
pub struct FragmentationIndex {
    /// 外部フラグメンテーション (0.0 = 断片化なし, 1.0 = 完全断片化)
    /// 
    /// 空き領域が多数の小さなブロックに分散している度合い。
    /// 高い値は物理的に連続した大きな領域の確保が困難なことを示す。
    pub external: f32,
    
    /// 内部フラグメンテーション (0.0 = 最適, 1.0 = 最悪)
    /// 
    /// 低次オーダーに空きが偏っている度合い。
    /// 高い値は過度な分割により大きなブロックが失われていることを示す。
    pub internal: f32,
    
    /// 使用不能率 (特定オーダー用)
    /// 
    /// 特定のオーダーの割り当てに使用できない空き領域の割合。
    pub unusable_ratio: f32,
    
    /// 推奨アクション
    pub recommended_action: FragmentationAction,
    
    /// 緊急度 (0-100)
    /// 
    /// Compaction/Coalesceを実行すべき緊急度。
    pub urgency: u8,
}

/// 推奨されるフラグメンテーション対策
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum FragmentationAction {
    /// 特に対処不要
    #[default]
    None = 0,
    /// 遅延結合を実行すべき
    Coalesce = 1,
    /// バックグラウンドコンパクションを開始すべき
    CompactBackground = 2,
    /// 緊急コンパクションが必要
    CompactUrgent = 3,
}

impl FragmentationIndex {
    /// フラグメンテーション指標を計算
    /// 
    /// # Arguments
    /// * `free_counts` - 各オーダーの空きブロック数
    /// * `total_frames` - 総フレーム数
    /// * `target_order` - (オプション) 特定オーダーの使用不能率を計算
    pub fn calculate(
        free_counts: &[usize; MAX_ORDER + 1],
        total_frames: usize,
        target_order: Option<usize>,
    ) -> Self {
        let total_free: usize = free_counts.iter().sum();
        if total_free == 0 || total_frames == 0 {
            return Self::default();
        }
        
        // External fragmentation: 空きブロック数 vs 最大可能ブロック数
        // 理想: 全ての空きが1つの最大オーダーブロックに
        // 現実: 多数の小さなブロックに分散
        let total_free_pages: usize = free_counts.iter()
            .enumerate()
            .map(|(order, &count)| count * (1usize << order))
            .sum();
        
        // 理想的な場合の最大オーダーブロック数
        let ideal_max_order = total_free_pages.checked_ilog2().unwrap_or(0) as usize;
        let ideal_block_count = if ideal_max_order > 0 { 1 } else { 0 };
        
        let external = if ideal_block_count > 0 && total_free > ideal_block_count {
            // 実際のブロック数が理想より多い → 断片化
            let excess = (total_free - ideal_block_count) as f32;
            (excess / total_free as f32).min(1.0)
        } else {
            0.0
        };
        
        // Internal fragmentation: 低次オーダーへの偏り
        // オーダー0-3 (4KB-32KB) に偏っているほど内部断片化が高い
        let low_order_free: usize = free_counts[..4.min(MAX_ORDER + 1)].iter().sum();
        let _high_order_free: usize = free_counts[4.min(MAX_ORDER + 1)..].iter().sum();
        
        let internal = if total_free > 0 {
            (low_order_free as f32 / total_free as f32).min(1.0)
        } else {
            0.0
        };
        
        // Unusable ratio for target order
        let unusable_ratio = if let Some(order) = target_order {
            // target_order より小さいブロックは使用不能
            let unusable: usize = free_counts[..order.min(MAX_ORDER + 1)].iter().sum();
            (unusable as f32 / total_free as f32).min(1.0)
        } else {
            0.0
        };
        
        // 緊急度と推奨アクションを決定
        let (urgency, action) = Self::determine_action(external, internal, free_counts, total_frames);
        
        Self {
            external,
            internal,
            unusable_ratio,
            recommended_action: action,
            urgency,
        }
    }
    
    /// 緊急度と推奨アクションを決定
    fn determine_action(
        external: f32,
        internal: f32,
        free_counts: &[usize; MAX_ORDER + 1],
        total_frames: usize,
    ) -> (u8, FragmentationAction) {
        // Calculate total free pages
        let total_free_pages: usize = free_counts.iter()
            .enumerate()
            .map(|(order, &count)| count * (1usize << order))
            .sum();
        
        let free_ratio = total_free_pages as f32 / total_frames as f32;
        
        // 空きが少ない + 高断片化 → 緊急
        if free_ratio < 0.05 && (external > 0.7 || internal > 0.8) {
            return (90, FragmentationAction::CompactUrgent);
        }
        
        // 高い外部断片化 → コンパクション
        if external > 0.6 {
            let urgency = ((external - 0.3) * 100.0).clamp(0.0, 80.0) as u8;
            return (urgency, FragmentationAction::CompactBackground);
        }
        
        // 高い内部断片化 → 結合
        if internal > 0.7 {
            let urgency = ((internal - 0.4) * 80.0).clamp(0.0, 60.0) as u8;
            return (urgency, FragmentationAction::Coalesce);
        }
        
        (0, FragmentationAction::None)
    }
    
    /// コンパクションが必要かどうか
    pub fn needs_compaction(&self) -> bool {
        matches!(
            self.recommended_action,
            FragmentationAction::CompactBackground | FragmentationAction::CompactUrgent
        )
    }
    
    /// 結合が必要かどうか
    pub fn needs_coalesce(&self) -> bool {
        matches!(self.recommended_action, FragmentationAction::Coalesce)
    }
    
    /// 緊急対応が必要かどうか
    pub fn is_urgent(&self) -> bool {
        self.urgency >= 70
    }
}

/// 圧縮コントローラ
/// 
/// フラグメンテーション率を監視し、必要に応じて圧縮を実行。
pub struct CompactionController {
    /// 現在の状態
    pub state: CompactionState,
    /// フラグメンテーション閾値（パーセント）
    /// この値を超えたら圧縮開始
    pub fragmentation_threshold: usize,
    /// 1サイクルあたりの最大移動ページ数
    pub max_pages_per_cycle: usize,
    /// 圧縮対象の最小オーダー
    pub min_compact_order: usize,
    /// 圧縮対象の最大オーダー
    pub max_compact_order: usize,
    /// 統計
    pub stats: CompactionStats,
    /// 最後の圧縮時刻（TSC）
    last_compaction_time: u64,
    /// 圧縮間隔（TSCサイクル）
    compaction_interval: u64,
}

impl CompactionController {
    /// 新しいコントローラを作成
    pub const fn new() -> Self {
        Self {
            state: CompactionState::Idle,
            fragmentation_threshold: 30, // 30%以上でトリガー
            max_pages_per_cycle: 64,
            min_compact_order: 0,
            max_compact_order: 8, // 最大256ページ（1MB）ブロックまで
            stats: CompactionStats {
                cycles: 0,
                pages_moved: 0,
                blocks_created: 0,
                freed_blocks: 0,
            },
            last_compaction_time: 0,
            compaction_interval: 10_000_000_000, // 約3秒@3GHz
        }
    }
    
    /// フラグメンテーション率を計算
    /// 
    /// (空きブロック数 - 理想的な空きブロック数) / 理想的な空きブロック数
    pub fn calculate_fragmentation(&self, free_counts: &[usize; 19]) -> usize {
        // 低次オーダーに空きが偏っているほどフラグメンテーションが高い
        let total_free: usize = free_counts.iter().sum();
        if total_free == 0 {
            return 0;
        }
        
        // 低次オーダー（0-3）の空きブロック比率
        let low_order_free: usize = free_counts[..4].iter().sum();
        (low_order_free * 100) / total_free
    }
    
    /// 圧縮が必要か判定
    pub fn should_compact(&self, fragmentation_percent: usize) -> bool {
        self.state == CompactionState::Idle 
            && fragmentation_percent >= self.fragmentation_threshold
    }
    
    /// 圧縮を開始
    pub fn start_compaction(&mut self) {
        self.state = CompactionState::Compacting;
    }
    
    /// 圧縮完了
    pub fn finish_compaction(&mut self, pages_moved: usize, blocks_created: usize) {
        self.state = CompactionState::Done;
        self.stats.cycles += 1;
        self.stats.pages_moved += pages_moved as u64;
        self.stats.blocks_created += blocks_created as u64;
    }
    
    /// アイドルにリセット
    pub fn reset_to_idle(&mut self) {
        self.state = CompactionState::Idle;
    }
    
    /// 圧縮候補のブロックを検索
    /// 
    /// 低次オーダーのブロックで、Buddyと結合可能なものを特定
    pub fn find_compaction_candidates(
        &self,
        free_counts: &[usize; 19],
        max_candidates: usize,
    ) -> CompactionCandidates {
        let mut candidates = CompactionCandidates::new();
        
        // 低次オーダーから検索
        for order in self.min_compact_order..self.max_compact_order {
            if candidates.count >= max_candidates {
                break;
            }
            
            if free_counts[order] >= 2 {
                // このオーダーにBuddy結合可能なペアがありそう
                candidates.add(order, free_counts[order].min(max_candidates - candidates.count));
            }
        }
        
        candidates
    }
}

impl Default for CompactionController {
    fn default() -> Self {
        Self::new()
    }
}

/// 圧縮候補リスト
#[derive(Debug)]
pub struct CompactionCandidates {
    /// 各オーダーの候補数
    pub by_order: [usize; 19],
    /// 合計候補数
    pub count: usize,
}
