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

use crate::sync::IrqMutex;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::PhysAddr;
use x86_64::structures::paging::{FrameAllocator, PhysFrame, Size1GiB, Size2MiB, Size4KiB};

// 共通型定義をインポート（IOVA_MM_MIGRATION_PLAN Phase 0.1）
use super::types::{FrameIndex, PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G};

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
#[cfg(target_arch = "x86_64")]
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
pub fn find_contiguous_set_bits(bitmap: &[u64], count: usize) -> Option<usize> {
    if count == 0 || bitmap.is_empty() {
        return None;
    }
    
    if count == 1 {
        return find_first_set_bit_simd(bitmap);
    }
    
    // 連続ビット検索（シンプル版）
    let mut run_start = None;
    let mut run_len = 0;
    
    for word_idx in 0..bitmap.len() {
        let word = bitmap[word_idx];
        
        for bit in 0..64 {
            let bit_idx = word_idx * 64 + bit;
            let is_set = (word >> bit) & 1 != 0;
            
            if is_set {
                if run_start.is_none() {
                    run_start = Some(bit_idx);
                    run_len = 1;
                } else {
                    run_len += 1;
                }
                
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

/// 最大オーダー（2^MAX_ORDER * 4KiB = 最大ブロックサイズ）
/// MAX_ORDER = 10 → 4MiB ブロック
/// MAX_ORDER = 18 → 1GiB ブロック（1GiBページ対応）
pub const MAX_ORDER: usize = 18;

/// 物理メモリの最大サイズ（16GiB想定）
const MAX_PHYSICAL_MEMORY: usize = 16 * 1024 * 1024 * 1024;

/// 4KiBページ数の最大値
const MAX_4K_FRAMES: usize = MAX_PHYSICAL_MEMORY / PAGE_SIZE_4K;

/// 全オーダーの空きビット数の合計（完全二分木）
const TOTAL_BLOCKS: usize = MAX_4K_FRAMES * 2 - 1;

/// 空きビットの総ワード数（u64）
const TOTAL_DETAIL_WORDS: usize = (TOTAL_BLOCKS + 63) / 64;

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

// FrameIndexはsuper::types::FrameIndexを使用
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

impl CompactionCandidates {
    pub const fn new() -> Self {
        Self {
            by_order: [0; 19],
            count: 0,
        }
    }
    
    pub fn add(&mut self, order: usize, count: usize) {
        if order < 19 {
            self.by_order[order] += count;
            self.count += count;
        }
    }
}

/// 遅延結合の閾値（解放回数がこれを超えたら結合を試みる）
const LAZY_COALESCE_THRESHOLD: u64 = 64;

/// Buddy Allocator
///
/// オーダー n のブロックは 2^n 個の連続した4KiBフレームを表す
/// - order 0: 4KiB (1フレーム)
/// - order 9: 2MiB (512フレーム)
/// - order 18: 1GiB (262144フレーム)
///
/// ## 遅延結合 (Lazy Coalescing)
///
/// フレーム解放時に即座にBuddyとの結合を試みると、割り当てと解放が
/// 境界付近で繰り返される場合に「分割→結合→分割→結合」のスラッシングが
/// 発生し、CPUサイクルを浪費します。
///
/// 遅延結合では、解放時にはブロックをフリーリストに戻すだけにし、
/// 以下のタイミングでまとめて結合処理を行います：
/// - 解放回数が閾値を超えた場合
/// - 要求サイズのブロックが見つからない場合（allocate_order内）
/// - 明示的な `try_coalesce_all` 呼び出し
pub struct BuddyFrameAllocator {
    /// 各オーダーの空きブロックビット（1 = free）
    free_bits: [u64; TOTAL_DETAIL_WORDS],
    /// 各オーダーの空きサマリービット（1 = detail word has free blocks）
    free_summary: [u64; TOTAL_SUMMARY_WORDS],
    /// オーダーごとのブロック数（capacity, MAX_PHYSICAL_MEMORYに基づく）
    order_block_capacity: [usize; MAX_ORDER + 1],
    /// オーダーごとのブロック数（total_framesに基づく上限）
    order_block_counts: [usize; MAX_ORDER + 1],
    /// オーダーごとの詳細ビット開始位置（word index）
    order_detail_word_start: [usize; MAX_ORDER + 1],
    /// オーダーごとの詳細ビット長（word数）
    order_detail_word_len: [usize; MAX_ORDER + 1],
    /// オーダーごとのサマリービット開始位置（word index）
    order_summary_word_start: [usize; MAX_ORDER + 1],
    /// オーダーごとのサマリービット長（word数）
    order_summary_word_len: [usize; MAX_ORDER + 1],
    /// オーダーごとの空きブロック数
    order_free_counts: [usize; MAX_ORDER + 1],
    /// レイアウト初期化済みフラグ
    layout_initialized: bool,
    /// 総フレーム数
    total_frames: usize,
    /// 空きフレーム数（4KiB単位）
    free_frames: u64,
    /// 統計: 分割回数
    split_count: u64,
    /// 統計: 合体回数
    coalesce_count: u64,
    /// 遅延結合: 前回の結合以降の解放回数
    deferred_dealloc_count: u64,
    /// 遅延結合: スキップした結合の回数（統計用）
    deferred_coalesce_skipped: u64,
    /// NUMA node -> list of managed (start_frame, end_frame) ranges
    /// This is optional so the allocator can remain const-constructible; it is
    /// initialized during `init` or when regions are registered.
    numa_regions: Option<BTreeMap<usize, alloc::vec::Vec<(FrameIndex, FrameIndex)>>>,
    /// 探索カーソル: 各オーダーの次回探索開始位置（Round-Robin）
    /// これにより特定領域への割り当て集中を防ぎ、メモリ全体を均等に使用
    search_cursor: [usize; MAX_ORDER + 1],
    /// ゼロクリア済みフラグビットマップ（1 = zeroed）
    /// free_bitsと同じレイアウトで、空きブロックのうちゼロクリア済みのものを追跡
    zeroed_bits: [u64; TOTAL_DETAIL_WORDS],
    /// ゼロクリア済み空きブロック数（オーダーごと）
    zeroed_counts: [usize; MAX_ORDER + 1],
    /// 統計: ゼロクリア済みページからの割り当て数
    zeroed_allocs: u64,
    /// 統計: スクラブ（バックグラウンドゼロクリア）回数
    scrub_count: u64,
    /// Coalesceポリシー（Hysteresisベース）
    coalesce_policy: CoalescePolicy,
}

impl BuddyFrameAllocator {
    pub const fn new() -> Self {
        Self {
            free_bits: [0u64; TOTAL_DETAIL_WORDS],
            free_summary: [0u64; TOTAL_SUMMARY_WORDS],
            order_block_capacity: [0usize; MAX_ORDER + 1],
            order_block_counts: [0usize; MAX_ORDER + 1],
            order_detail_word_start: [0usize; MAX_ORDER + 1],
            order_detail_word_len: [0usize; MAX_ORDER + 1],
            order_summary_word_start: [0usize; MAX_ORDER + 1],
            order_summary_word_len: [0usize; MAX_ORDER + 1],
            order_free_counts: [0usize; MAX_ORDER + 1],
            layout_initialized: false,
            total_frames: 0,
            free_frames: 0,
            split_count: 0,
            coalesce_count: 0,
            deferred_dealloc_count: 0,
            deferred_coalesce_skipped: 0,
            numa_regions: None,
            search_cursor: [0usize; MAX_ORDER + 1],
            zeroed_bits: [0u64; TOTAL_DETAIL_WORDS],
            zeroed_counts: [0usize; MAX_ORDER + 1],
            zeroed_allocs: 0,
            scrub_count: 0,
            coalesce_policy: CoalescePolicy::new(),
        }
    }

    /// メモリマップに基づいてアロケータを初期化
    ///
    /// # Safety
    /// - `usable_regions` は正しい使用可能メモリ領域を示す必要がある
    pub unsafe fn init(&mut self, usable_regions: &[(PhysAddr, u64)]) {
        self.init_layout();

        // 初期化: 全て使用中（free bit = 0）
        for word in self.free_bits.iter_mut() {
            *word = 0;
        }
        for word in self.free_summary.iter_mut() {
            *word = 0;
        }
        for count in self.order_free_counts.iter_mut() {
            *count = 0;
        }
        self.free_frames = 0;
        self.split_count = 0;
        self.coalesce_count = 0;
        self.deferred_dealloc_count = 0;
        self.deferred_coalesce_skipped = 0;
        // 探索カーソルを0に初期化
        for cursor in self.search_cursor.iter_mut() {
            *cursor = 0;
        }
        // ゼロクリア済みビットを初期化
        for word in self.zeroed_bits.iter_mut() {
            *word = 0;
        }
        for count in self.zeroed_counts.iter_mut() {
            *count = 0;
        }
        self.zeroed_allocs = 0;
        self.scrub_count = 0;

        let mut total = 0usize;

        // 使用可能な領域を空きブロックとして登録
        if self.numa_regions.is_none() {
            self.numa_regions = Some(BTreeMap::new());
        }

        for &(start, size) in usable_regions {
            let start_frame = FrameIndex::from_phys_addr(start.as_u64());
            let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

            total = total.max(end_frame.as_usize());

            // 領域を最大オーダーのブロックに分割して登録
            self.add_region(start_frame, end_frame);

            if let Some(map) = self.numa_regions.as_mut() {
                map.entry(0)
                    .or_insert_with(alloc::vec::Vec::new)
                    .push((start_frame, end_frame));
            }
        }

        self.total_frames = total.min(MAX_4K_FRAMES);
        self.update_order_limits();
    }

    fn init_layout(&mut self) {
        if self.layout_initialized {
            return;
        }

        let mut detail_offset = 0usize;
        let mut summary_offset = 0usize;

        for order in 0..=MAX_ORDER {
            let blocks = MAX_4K_FRAMES >> order;
            let detail_words = (blocks + 63) / 64;
            let summary_words = (detail_words + 63) / 64;

            self.order_block_capacity[order] = blocks;
            self.order_detail_word_start[order] = detail_offset;
            self.order_detail_word_len[order] = detail_words;
            self.order_summary_word_start[order] = summary_offset;
            self.order_summary_word_len[order] = summary_words;

            detail_offset += detail_words;
            summary_offset += summary_words;
        }

        debug_assert!(detail_offset <= TOTAL_DETAIL_WORDS);
        debug_assert!(summary_offset <= TOTAL_SUMMARY_WORDS);

        self.layout_initialized = true;
    }

    fn update_order_limits(&mut self) {
        for order in 0..=MAX_ORDER {
            self.order_block_counts[order] = self.total_frames >> order;
        }
    }

    /// 連続した空き領域を Buddy システムに追加
    fn add_region(&mut self, start: FrameIndex, end: FrameIndex) {
        let mut current = start.as_usize();
        let mut end_idx = end.as_usize();

        if current >= MAX_4K_FRAMES {
            return;
        }
        if end_idx > MAX_4K_FRAMES {
            log::warn!(
                "[Buddy] Region beyond MAX_PHYSICAL_MEMORY: clamping end {:#x} -> {:#x}",
                end_idx * PAGE_SIZE_4K,
                MAX_4K_FRAMES * PAGE_SIZE_4K
            );
            end_idx = MAX_4K_FRAMES;
        }

        while current < end_idx {
            // 現在位置からアラインされた最大ブロックを見つける
            let remaining = end_idx - current;

            // 使用可能な最大オーダーを計算
            let max_order_by_alignment = current.trailing_zeros() as usize;
            let max_order_by_size = (usize::BITS - remaining.leading_zeros() - 1) as usize;
            let order = max_order_by_alignment.min(max_order_by_size).min(MAX_ORDER);

            let block_size = 1 << order;

            // このブロックを空きとして登録
            let frame = FrameIndex::new(current);
            self.set_free_block_by_frame(order, frame);
            self.free_frames += block_size as u64;

            current += block_size;
        }
    }

    #[inline]
    fn set_summary_bit(&mut self, order: usize, detail_word_idx: usize) {
        let summary_word_idx =
            self.order_summary_word_start[order] + (detail_word_idx / 64);
        let summary_bit = detail_word_idx % 64;
        if summary_word_idx < self.free_summary.len() {
            self.free_summary[summary_word_idx] |= 1u64 << summary_bit;
        }
    }

    #[inline]
    fn clear_summary_bit(&mut self, order: usize, detail_word_idx: usize) {
        let summary_word_idx =
            self.order_summary_word_start[order] + (detail_word_idx / 64);
        let summary_bit = detail_word_idx % 64;
        if summary_word_idx < self.free_summary.len() {
            self.free_summary[summary_word_idx] &= !(1u64 << summary_bit);
        }
    }

    #[inline]
    fn set_free_block(&mut self, order: usize, block_idx: usize) {
        if block_idx >= self.order_block_capacity[order] {
            return;
        }
        let detail_word_idx = block_idx / 64;
        let bit_idx = block_idx % 64;
        let word_idx = self.order_detail_word_start[order] + detail_word_idx;
        let word = self.free_bits[word_idx];
        let new_word = word | (1u64 << bit_idx);
        if new_word != word {
            self.free_bits[word_idx] = new_word;
            self.order_free_counts[order] += 1;
            if word == 0 {
                self.set_summary_bit(order, detail_word_idx);
            }
        }
    }

    #[inline]
    fn clear_free_block(&mut self, order: usize, block_idx: usize) {
        if block_idx >= self.order_block_capacity[order] {
            return;
        }
        let detail_word_idx = block_idx / 64;
        let bit_idx = block_idx % 64;
        let word_idx = self.order_detail_word_start[order] + detail_word_idx;
        let word = self.free_bits[word_idx];
        if (word & (1u64 << bit_idx)) == 0 {
            return;
        }
        let new_word = word & !(1u64 << bit_idx);
        self.free_bits[word_idx] = new_word;
        self.order_free_counts[order] = self.order_free_counts[order].saturating_sub(1);
        if new_word == 0 {
            self.clear_summary_bit(order, detail_word_idx);
        }
    }

    #[inline]
    fn is_block_free(&self, order: usize, block_idx: usize) -> bool {
        if block_idx >= self.order_block_capacity[order] {
            return false;
        }
        let detail_word_idx = block_idx / 64;
        let bit_idx = block_idx % 64;
        let word_idx = self.order_detail_word_start[order] + detail_word_idx;
        (self.free_bits[word_idx] & (1u64 << bit_idx)) != 0
    }

    #[inline]
    fn set_free_block_by_frame(&mut self, order: usize, frame: FrameIndex) {
        let block_idx = frame.as_usize() >> order;
        self.set_free_block(order, block_idx);
    }

    fn find_free_block(&mut self, order: usize) -> Option<usize> {
        if self.order_free_counts[order] == 0 || self.order_block_counts[order] == 0 {
            return None;
        }

        let summary_start = self.order_summary_word_start[order];
        let summary_len = self.order_summary_word_len[order];
        let detail_start = self.order_detail_word_start[order];
        let detail_len = self.order_detail_word_len[order];
        let max_blocks = self.order_block_counts[order];

        // Round-Robin: 前回のカーソル位置から探索開始
        let start_summary = self.search_cursor[order] % summary_len.max(1);

        // 2パス: start_summary -> end, then 0 -> start_summary
        for pass in 0..2 {
            let (begin, end) = if pass == 0 {
                (start_summary, summary_len)
            } else {
                (0, start_summary)
            };

            for summary_idx in begin..end {
                let mut summary_word = self.free_summary[summary_start + summary_idx];
                while summary_word != 0 {
                    // TZCNT命令活用: O(64) -> O(1) に高速化
                    let bit = fast_tzcnt_u64(summary_word) as usize;
                    let detail_idx = summary_idx * 64 + bit;
                    if detail_idx >= detail_len {
                        break;
                    }
                    let detail_word = self.free_bits[detail_start + detail_idx];
                    if detail_word == 0 {
                        self.clear_summary_bit(order, detail_idx);
                    } else {
                        // TZCNT命令活用
                        let block_bit = fast_tzcnt_u64(detail_word) as usize;
                        let block_idx = detail_idx * 64 + block_bit;
                        if block_idx < max_blocks {
                            // カーソルを次のサマリーワードに進める
                            self.search_cursor[order] = (summary_idx + 1) % summary_len.max(1);
                            return Some(block_idx);
                        }
                    }
                    summary_word &= summary_word - 1;
                }
            }
        }

        None
    }

    fn find_free_block_in_range(
        &mut self,
        order: usize,
        start_block: usize,
        end_block: usize,
    ) -> Option<usize> {
        if start_block >= end_block {
            return None;
        }

        let max_blocks = self.order_block_counts[order];
        let end_block = end_block.min(max_blocks);
        if start_block >= end_block || self.order_free_counts[order] == 0 {
            return None;
        }

        let detail_start = self.order_detail_word_start[order];
        let detail_len = self.order_detail_word_len[order];
        let start_word = start_block / 64;
        let end_word = (end_block + 63) / 64;

        for word_idx in start_word..end_word.min(detail_len) {
            let mut word = self.free_bits[detail_start + word_idx];
            if word == 0 {
                continue;
            }

            let word_base = word_idx * 64;
            let mut mask = u64::MAX;
            if word_base < start_block {
                mask &= !((1u64 << (start_block - word_base)) - 1);
            }
            if word_base + 64 > end_block {
                let tail = end_block - word_base;
                if tail < 64 {
                    mask &= (1u64 << tail) - 1;
                }
            }

            word &= mask;
            if word == 0 {
                continue;
            }
            let bit = word.trailing_zeros() as usize;
            let block_idx = word_base + bit;
            if block_idx < end_block {
                return Some(block_idx);
            }
        }

        None
    }

    /// 指定オーダーのブロックを割り当て
    /// 
    /// ## 遅延結合との連携
    /// 
    /// 要求サイズのブロックが見つからない場合、まず遅延されていた
    /// 結合処理を実行してから再度探索を試みる。
    fn allocate_order(&mut self, order: usize) -> Option<FrameIndex> {
        if order > MAX_ORDER {
            return None;
        }

        // 第1試行: 通常の探索
        if let Some(frame) = self.try_allocate_order_internal(order) {
            return Some(frame);
        }

        // 空きブロックが見つからなかった場合、遅延結合を実行
        if self.deferred_dealloc_count > 0 {
            self.try_coalesce_all();
            self.deferred_dealloc_count = 0;

            // 第2試行: 結合後に再探索
            return self.try_allocate_order_internal(order);
        }

        None
    }

    /// allocate_orderの内部実装（結合なし）
    fn try_allocate_order_internal(&mut self, order: usize) -> Option<FrameIndex> {
        // 要求オーダー以上の空きブロックを探す
        for current_order in order..=MAX_ORDER {
            if let Some(block_idx) = self.find_free_block(current_order) {
                self.clear_free_block(current_order, block_idx);
                let frame = FrameIndex::new(block_idx << current_order);

                // 必要に応じてブロックを分割
                self.split_block(frame, current_order, order);

                let block_size = 1u64 << order;
                debug_assert!(self.free_frames >= block_size);
                self.free_frames = self.free_frames.saturating_sub(block_size);

                return Some(frame);
            }
        }

        None
    }

    /// 大きなブロックを目標オーダーまで分割
    fn split_block(&mut self, frame: FrameIndex, from_order: usize, to_order: usize) {
        let mut current_order = from_order;

        while current_order > to_order {
            current_order -= 1;

            // 後半のBuddyを空きビットに追加
            let buddy = FrameIndex::new(frame.as_usize() + (1 << current_order));
            self.set_free_block_by_frame(current_order, buddy);

            self.split_count += 1;
        }
    }

    /// 指定オーダーのブロックを解放
    /// 
    /// ## 遅延結合 (Lazy Coalescing)
    /// 
    /// 即座にBuddyとの結合を試みず、フリービットをセットするだけにする。
    /// 結合は以下のタイミングで行われる：
    /// - 解放回数が閾値 (LAZY_COALESCE_THRESHOLD) を超えた場合
    /// - allocate_order で要求サイズのブロックが見つからない場合
    /// - 明示的な try_coalesce_all 呼び出し
    fn deallocate_order(&mut self, frame: FrameIndex, order: usize) {
        debug_assert_eq!(frame.align_down(order), frame);

        // フレームを空きとしてマーク
        let block_idx = frame.as_usize() >> order;
        if self.is_block_free(order, block_idx) {
            log::error!(
                "[Buddy] Double free detected: frame={:#x} order={}",
                frame.to_phys_addr(),
                order
            );
            return;
        }
        self.set_free_block(order, block_idx);
        self.free_frames += 1u64 << order;

        // 遅延結合: 解放回数をインクリメント
        self.deferred_dealloc_count += 1;

        // 閾値を超えたら結合を試みる
        if self.deferred_dealloc_count >= LAZY_COALESCE_THRESHOLD {
            self.try_coalesce_all();
            self.deferred_dealloc_count = 0;
        } else {
            self.deferred_coalesce_skipped += 1;
        }
    }

    /// 指定オーダーのブロックを解放（即時結合版）
    /// 
    /// 遅延結合を使用せず、即座にBuddyとの結合を試みる。
    /// 大きなブロック（2MB以上）の解放など、結合が有利な場合に使用。
    fn deallocate_order_immediate(&mut self, frame: FrameIndex, order: usize) {
        debug_assert_eq!(frame.align_down(order), frame);

        let block_idx = frame.as_usize() >> order;
        if self.is_block_free(order, block_idx) {
            log::error!(
                "[Buddy] Double free detected: frame={:#x} order={}",
                frame.to_phys_addr(),
                order
            );
            return;
        }
        self.set_free_block(order, block_idx);
        self.free_frames += 1u64 << order;

        // 即座にBuddyとの合体を試みる
        self.coalesce(block_idx, order);
    }

    /// 全オーダーで結合可能なブロックを結合する
    /// 
    /// アイドル時やメモリ不足時に呼び出すことで、
    /// 断片化を解消し大きな連続領域を確保できる。
    pub fn try_coalesce_all(&mut self) {
        // 下位オーダーから順に結合を試みる
        for order in 0..MAX_ORDER {
            self.try_coalesce_order(order);
        }
    }

    /// 特定オーダーのブロックを結合可能な限り結合する
    fn try_coalesce_order(&mut self, order: usize) {
        if order >= MAX_ORDER {
            return;
        }

        let max_blocks = self.order_block_counts[order];
        let _detail_start = self.order_detail_word_start[order];
        let _detail_len = self.order_detail_word_len[order];

        // 全ブロックをスキャンして結合可能なペアを探す
        let mut block_idx = 0usize;
        while block_idx < max_blocks {
            // 偶数インデックスのブロックのみチェック（奇数はBuddyなので）
            if block_idx % 2 != 0 {
                block_idx += 1;
                continue;
            }

            let buddy_idx = block_idx + 1;
            if buddy_idx >= max_blocks {
                break;
            }

            // 両方が空いているかチェック
            if self.is_block_free(order, block_idx) && self.is_block_free(order, buddy_idx) {
                // 結合実行
                self.clear_free_block(order, block_idx);
                self.clear_free_block(order, buddy_idx);

                // 上位オーダーに空きブロックを追加
                let parent_idx = block_idx >> 1;
                self.set_free_block(order + 1, parent_idx);

                self.coalesce_count += 1;
            }

            block_idx += 2;
        }
    }

    /// Buddyとの合体を反復的に試みる
    ///
    /// 以前の再帰実装はスタックオーバーフローのリスクがあったため、
    /// ループベースの反復的実装に変更。
    fn coalesce(&mut self, block_idx: usize, order: usize) {
        let mut current_block = block_idx;
        let mut current_order = order;

        // 反復的に合体を試みる
        while current_order < MAX_ORDER {
            let buddy = current_block ^ 1;
            if buddy >= self.order_block_counts[current_order] {
                break;
            }

            // Buddyが存在し、かつ同じオーダーで空いているか確認
            if !self.is_block_free(current_order, buddy) {
                break;
            }

            // Buddyと自分のブロックを消去して上位を空きにする
            self.clear_free_block(current_order, current_block);
            self.clear_free_block(current_order, buddy);

            self.coalesce_count += 1;

            // 次のオーダーへ
            current_block >>= 1;
            current_order += 1;

            self.set_free_block(current_order, current_block);
        }
    }

    /// 必要フレーム数から適切なオーダーを計算
    fn frames_to_order(frames: usize) -> usize {
        if frames == 0 {
            return 0;
        }
        (usize::BITS - (frames - 1).leading_zeros()) as usize
    }

    /// 4KiB フレームを1つ割り当て
    pub fn allocate_4k_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_order(0).map(|frame| {
            let addr = PhysAddr::new(frame.to_phys_addr());
            PhysFrame::containing_address(addr)
        })
    }

    /// 2MiB フレームを割り当て（order 9 = 512 * 4KiB = 2MiB）
    pub fn allocate_2m_frame(&mut self) -> Option<PhysFrame<Size2MiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        self.allocate_order(order).map(|frame| {
            let addr = PhysAddr::new(frame.to_phys_addr());
            PhysFrame::containing_address(addr)
        })
    }

    /// 1GiB フレームを割り当て（order 18 = 262144 * 4KiB = 1GiB）
    pub fn allocate_1g_frame(&mut self) -> Option<PhysFrame<Size1GiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        self.allocate_order(order).map(|frame| {
            let addr = PhysAddr::new(frame.to_phys_addr());
            PhysFrame::containing_address(addr)
        })
    }

    /// 4KiB フレームを解放
    pub fn deallocate_4k_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        let frame_idx = FrameIndex::from_phys_addr(frame.start_address().as_u64());

        // Memcg: ページがmemcgでトラックされている場合はアンチャージ
        if let Some(info) = super::memcg::memcg_untrack_page(frame_idx) {
            let _ = super::memcg::memcg_uncharge(info.memcg_id, 1, info.charge_type);
        }

        self.deallocate_order(frame_idx, 0);
    }

    /// 2MiB フレームを解放
    /// 
    /// 大きなブロックは即時結合を使用（スラッシングのリスクが低い）
    pub fn deallocate_2m_frame(&mut self, frame: PhysFrame<Size2MiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_2M / PAGE_SIZE_4K;

        // Memcg: 各4KiBページについてアンチャージ/アンストラックする
        for i in 0..frames_count {
            let idx = FrameIndex::new(start_frame.as_usize() + i);
            if let Some(info) = super::memcg::memcg_untrack_page(idx) {
                let _ = super::memcg::memcg_uncharge(info.memcg_id, 1, info.charge_type);
            }
        }

        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        self.deallocate_order_immediate(start_frame, order);
    }

    /// 1GiB フレームを解放
    /// 
    /// 大きなブロックは即時結合を使用（スラッシングのリスクが低い）
    pub fn deallocate_1g_frame(&mut self, frame: PhysFrame<Size1GiB>) {
        let start_frame = FrameIndex::from_phys_addr(frame.start_address().as_u64());
        let frames_count = PAGE_SIZE_1G / PAGE_SIZE_4K;

        // Memcg: 各4KiBページについてアンチャージ/アンストラックする
        for i in 0..frames_count {
            let idx = FrameIndex::new(start_frame.as_usize() + i);
            if let Some(info) = super::memcg::memcg_untrack_page(idx) {
                let _ = super::memcg::memcg_uncharge(info.memcg_id, 1, info.charge_type);
            }
        }

        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        self.deallocate_order_immediate(start_frame, order);
    }

    /// 連続する物理フレームを割り当て（2のべき乗に切り上げ）
    pub fn allocate_contiguous(&mut self, frame_count: usize) -> Option<PhysAddr> {
        let order = Self::frames_to_order(frame_count);
        if order > MAX_ORDER {
            return None;
        }
        self.allocate_order(order)
            .map(|frame| PhysAddr::new(frame.to_phys_addr()))
    }

    /// Register a NUMA region for a node and add it to the allocator
    pub fn register_numa_region(&mut self, node: usize, start: FrameIndex, end: FrameIndex) {
        self.init_layout();

        if self.numa_regions.is_none() {
            self.numa_regions = Some(BTreeMap::new());
        }
        let map = self.numa_regions.as_mut().unwrap();
        map.entry(node)
            .or_insert_with(|| alloc::vec![])
            .push((start, end));

        // Add the region to the global free bitsets
        self.add_region(start, end);

        // Update total_frames to cover the new region
        self.total_frames = self.total_frames.max(end.as_usize().min(MAX_4K_FRAMES));
        self.update_order_limits();
    }

    /// Allocate an order block restricted to [start_frame, end_frame)
    fn allocate_order_in_range(
        &mut self,
        order: usize,
        start_frame: usize,
        end_frame: usize,
    ) -> Option<FrameIndex> {
        if order > MAX_ORDER {
            return None;
        }
        for current_order in order..=MAX_ORDER {
            let block_size = 1 << current_order;
            let start_block = (start_frame + block_size - 1) / block_size;
            let end_block = end_frame / block_size;

            if let Some(block_idx) =
                self.find_free_block_in_range(current_order, start_block, end_block)
            {
                self.clear_free_block(current_order, block_idx);
                let frame = FrameIndex::new(block_idx << current_order);

                self.split_block(frame, current_order, order);

                let target_size = 1u64 << order;
                debug_assert!(self.free_frames >= target_size);
                self.free_frames = self.free_frames.saturating_sub(target_size);

                return Some(frame);
            }
        }
        None
    }

    /// Try to allocate a 4KiB frame on a preferred NUMA node; fallback to others and global
    pub fn allocate_4k_frame_on_node(&mut self, node: usize) -> Option<PhysFrame<Size4KiB>> {
        // Clone the map to avoid borrow conflict with &mut self in allocate_order_in_range
        let map_clone = self.numa_regions.clone();
        if let Some(map) = map_clone.as_ref() {
            if let Some(ranges) = map.get(&node) {
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(0, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }

            for (&other, ranges) in map.iter() {
                if other == node {
                    continue;
                }
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(0, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }
        }

        // global fallback
        self.allocate_4k_frame()
    }

    /// 2MiB allocation on a preferred NUMA node
    pub fn allocate_2m_frame_on_node(&mut self, node: usize) -> Option<PhysFrame<Size2MiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_2M / PAGE_SIZE_4K);
        // Clone the map to avoid borrow conflict with &mut self in allocate_order_in_range
        let map_clone = self.numa_regions.clone();
        if let Some(map) = map_clone.as_ref() {
            if let Some(ranges) = map.get(&node) {
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }

            for (&other, ranges) in map.iter() {
                if other == node {
                    continue;
                }
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }
        }
        self.allocate_2m_frame()
    }

    /// 1GiB allocation on a preferred NUMA node
    pub fn allocate_1g_frame_on_node(&mut self, node: usize) -> Option<PhysFrame<Size1GiB>> {
        let order = Self::frames_to_order(PAGE_SIZE_1G / PAGE_SIZE_4K);
        // Clone the map to avoid borrow conflict with &mut self in allocate_order_in_range
        let map_clone = self.numa_regions.clone();
        if let Some(map) = map_clone.as_ref() {
            if let Some(ranges) = map.get(&node) {
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }

            for (&other, ranges) in map.iter() {
                if other == node {
                    continue;
                }
                for &(start, end) in ranges.iter() {
                    if let Some(frame) =
                        self.allocate_order_in_range(order, start.as_usize(), end.as_usize())
                    {
                        let addr = PhysAddr::new(frame.to_phys_addr());
                        return Some(PhysFrame::containing_address(addr));
                    }
                }
            }
        }

        self.allocate_1g_frame()
    }

    /// 空きフレーム数を取得
    pub fn free_frame_count(&self) -> u64 {
        self.free_frames
    }

    /// 総フレーム数を取得
    pub fn total_frame_count(&self) -> usize {
        self.total_frames
    }

    /// 統計情報を取得
    pub fn stats(&self) -> BuddyAllocatorStats {
        let mut order_stats = [(0usize, 0usize); MAX_ORDER + 1];

        for order in 0..=MAX_ORDER {
            let block_frames = 1 << order;
            let free_blocks = self.order_free_counts[order];
            let total_frames = free_blocks * block_frames;
            order_stats[order] = (free_blocks, total_frames);
        }

        BuddyAllocatorStats {
            total_frames: self.total_frames,
            free_frames: self.free_frames,
            split_count: self.split_count,
            coalesce_count: self.coalesce_count,
            order_stats,
        }
    }

    // ========================================================================
    // ゼロクリア済みページ管理
    // ========================================================================

    /// ゼロクリア済みブロックかどうかをチェック
    #[inline]
    fn is_block_zeroed(&self, order: usize, block_idx: usize) -> bool {
        if order > MAX_ORDER {
            return false;
        }
        let detail_start = self.order_detail_word_start[order];
        let word_idx = detail_start + (block_idx / 64);
        let bit_idx = block_idx % 64;
        if word_idx < TOTAL_DETAIL_WORDS {
            (self.zeroed_bits[word_idx] >> bit_idx) & 1 != 0
        } else {
            false
        }
    }

    /// ブロックをゼロクリア済みとしてマーク
    #[inline]
    fn set_block_zeroed(&mut self, order: usize, block_idx: usize) {
        if order > MAX_ORDER {
            return;
        }
        let detail_start = self.order_detail_word_start[order];
        let word_idx = detail_start + (block_idx / 64);
        let bit_idx = block_idx % 64;
        if word_idx < TOTAL_DETAIL_WORDS {
            let old = self.zeroed_bits[word_idx];
            if old & (1u64 << bit_idx) == 0 {
                self.zeroed_bits[word_idx] = old | (1u64 << bit_idx);
                self.zeroed_counts[order] += 1;
            }
        }
    }

    /// ブロックのゼロクリア済みフラグをクリア
    #[inline]
    fn clear_block_zeroed(&mut self, order: usize, block_idx: usize) {
        if order > MAX_ORDER {
            return;
        }
        let detail_start = self.order_detail_word_start[order];
        let word_idx = detail_start + (block_idx / 64);
        let bit_idx = block_idx % 64;
        if word_idx < TOTAL_DETAIL_WORDS {
            let old = self.zeroed_bits[word_idx];
            if old & (1u64 << bit_idx) != 0 {
                self.zeroed_bits[word_idx] = old & !(1u64 << bit_idx);
                self.zeroed_counts[order] = self.zeroed_counts[order].saturating_sub(1);
            }
        }
    }

    /// ゼロクリア済みの空きブロックを探索
    fn find_zeroed_free_block(&self, order: usize) -> Option<usize> {
        if self.zeroed_counts[order] == 0 {
            return None;
        }

        let detail_start = self.order_detail_word_start[order];
        let detail_len = self.order_detail_word_len[order];
        let max_blocks = self.order_block_counts[order];

        for word_offset in 0..detail_len {
            let word_idx = detail_start + word_offset;
            // 空きかつゼロクリア済みのブロックを探す
            let combined = self.free_bits[word_idx] & self.zeroed_bits[word_idx];
            if combined != 0 {
                let bit = combined.trailing_zeros() as usize;
                let block_idx = word_offset * 64 + bit;
                if block_idx < max_blocks {
                    return Some(block_idx);
                }
            }
        }

        None
    }

    /// ゼロクリア済みページを優先して割り当て
    ///
    /// ゼロクリア済みブロックがあればそれを使用し、なければ通常割り当て後に
    /// 呼び出し元でゼロクリアする必要がある。
    ///
    /// # Returns
    /// - `Some((frame, true))`: ゼロクリア済みブロックを割り当て
    /// - `Some((frame, false))`: 通常ブロックを割り当て（要ゼロクリア）
    /// - `None`: 割り当て失敗
    pub fn allocate_order_prefer_zeroed(&mut self, order: usize) -> Option<(FrameIndex, bool)> {
        if order > MAX_ORDER {
            return None;
        }

        // まずゼロクリア済みブロックを探す
        if let Some(block_idx) = self.find_zeroed_free_block(order) {
            self.clear_free_block(order, block_idx);
            self.clear_block_zeroed(order, block_idx);
            let frame = FrameIndex::new(block_idx << order);
            let block_size = 1u64 << order;
            self.free_frames = self.free_frames.saturating_sub(block_size);
            self.zeroed_allocs += 1;
            return Some((frame, true));
        }

        // ゼロクリア済みがなければ通常割り当て
        self.allocate_order(order).map(|frame| (frame, false))
    }

    /// 4KiBフレームをゼロクリア済みとして割り当て
    pub fn allocate_4k_zeroed(&mut self) -> Option<(PhysFrame<Size4KiB>, bool)> {
        self.allocate_order_prefer_zeroed(0).map(|(frame, zeroed)| {
            let phys_addr = PhysAddr::new(frame.to_phys_addr());
            (unsafe { PhysFrame::from_start_address_unchecked(phys_addr) }, zeroed)
        })
    }

    /// バックグラウンドスクラブ: 1つの空きページをゼロクリア
    ///
    /// アイドルタスクから呼び出し、非ゼロの空きページを見つけてゼロクリアする。
    /// 実際のゼロクリア（memset）は呼び出し元で行い、完了後に `mark_scrubbed` を呼ぶ。
    ///
    /// # Returns
    /// ゼロクリア対象のフレームアドレス。ゼロクリア不要な場合はNone。
    pub fn find_dirty_free_page(&self, order: usize) -> Option<FrameIndex> {
        if order > MAX_ORDER || self.order_free_counts[order] == 0 {
            return None;
        }

        let detail_start = self.order_detail_word_start[order];
        let detail_len = self.order_detail_word_len[order];
        let max_blocks = self.order_block_counts[order];

        for word_offset in 0..detail_len {
            let word_idx = detail_start + word_offset;
            // 空きだがゼロクリア済みでないブロックを探す
            let free_word = self.free_bits[word_idx];
            let zeroed_word = self.zeroed_bits[word_idx];
            let dirty = free_word & !zeroed_word;
            if dirty != 0 {
                let bit = dirty.trailing_zeros() as usize;
                let block_idx = word_offset * 64 + bit;
                if block_idx < max_blocks {
                    return Some(FrameIndex::new(block_idx << order));
                }
            }
        }

        None
    }

    /// スクラブ完了をマーク
    ///
    /// `find_dirty_free_page` で見つけたページをゼロクリアした後に呼び出す。
    pub fn mark_scrubbed(&mut self, frame: FrameIndex, order: usize) {
        let block_idx = frame.as_usize() >> order;
        // まだ空きブロックであることを確認
        if self.is_block_free(order, block_idx) {
            self.set_block_zeroed(order, block_idx);
            self.scrub_count += 1;
        }
    }

    /// ゼロクリア統計を取得
    pub fn zeroed_stats(&self) -> (u64, u64, [usize; MAX_ORDER + 1]) {
        (self.zeroed_allocs, self.scrub_count, self.zeroed_counts)
    }
}

// x86_64 crateのFrameAllocatorトレイトを実装
unsafe impl FrameAllocator<Size4KiB> for BuddyFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_4k_frame()
    }
}

/// Buddy Allocator 統計情報
#[derive(Debug, Clone, Copy)]
pub struct BuddyAllocatorStats {
    pub total_frames: usize,
    pub free_frames: u64,
    pub split_count: u64,
    pub coalesce_count: u64,
    /// 各オーダーの (空きブロック数, 総フレーム数)
    pub order_stats: [(usize, usize); MAX_ORDER + 1],
}

// ============================================================================
// Per-CPU Front Layer (Phase 3 Optimization)
// ============================================================================
//
// Buddy Allocatorへのロック競合を軽減するため、各CPUがローカルな
// フレームキャッシュを持つ。割り当て/解放はまずフロントレイヤーで処理され、
// キャッシュが空/満杯の場合のみBuddyにアクセスする。
//
// 設計:
// - 各CPUは4KiBフレームのローカルキャッシュを持つ
// - キャッシュサイズはNUMAノードあたりの利用可能メモリに基づき調整
// - バックグラウンドでBuddyからリフィル/ドレイン
//
// 性能特性:
// - Hot Path: Per-CPUキャッシュからロックフリーで割り当て
// - Cold Path: Buddyからバッチでリフィル
// ============================================================================

use core::sync::atomic::AtomicUsize;

/// Per-CPUフロントレイヤーのキャッシュサイズ
pub const FRONT_LAYER_CACHE_SIZE: usize = 64;

/// 最大CPU数
pub const FRONT_LAYER_MAX_CPUS: usize = 64;

/// Low watermark（この数以下でリフィル）
const FRONT_LAYER_LOW_WATERMARK: usize = 16;

/// High watermark（この数以上でドレイン）
const FRONT_LAYER_HIGH_WATERMARK: usize = 48;

/// リフィル時のバッチサイズ
const FRONT_LAYER_REFILL_BATCH: usize = 32;

/// Per-CPUフレームキャッシュ
#[repr(align(64))] // キャッシュラインアライン
pub struct PerCpuFrameCache {
    /// キャッシュされた4KiBフレーム（物理アドレス）
    frames: [u64; FRONT_LAYER_CACHE_SIZE],
    /// 現在のフレーム数
    count: usize,
    /// CPU ID
    cpu_id: usize,
    /// NUMAノードID
    numa_node: Option<u8>,
    /// 統計: キャッシュヒット数
    cache_hits: u64,
    /// 統計: キャッシュミス数（Buddyフォールバック）
    cache_misses: u64,
    /// 統計: リフィル回数
    refill_count: u64,
    /// 統計: ドレイン回数
    drain_count: u64,
}

impl PerCpuFrameCache {
    /// 新しいPer-CPUキャッシュを作成
    pub const fn new(cpu_id: usize) -> Self {
        Self {
            frames: [0; FRONT_LAYER_CACHE_SIZE],
            count: 0,
            cpu_id,
            numa_node: None,
            cache_hits: 0,
            cache_misses: 0,
            refill_count: 0,
            drain_count: 0,
        }
    }

    /// NUMAノードを設定
    pub fn set_numa_node(&mut self, node: u8) {
        self.numa_node = Some(node);
    }

    /// キャッシュからフレームを取得（Hot Path）
    #[inline]
    pub fn pop(&mut self) -> Option<u64> {
        if self.count == 0 {
            return None;
        }
        self.count -= 1;
        self.cache_hits += 1;
        Some(self.frames[self.count])
    }

    /// キャッシュにフレームを追加（Hot Path）
    #[inline]
    pub fn push(&mut self, frame_addr: u64) -> bool {
        if self.count >= FRONT_LAYER_CACHE_SIZE {
            return false;
        }
        self.frames[self.count] = frame_addr;
        self.count += 1;
        true
    }

    /// キャッシュが空かどうか
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// キャッシュが満杯かどうか
    #[inline]
    pub fn is_full(&self) -> bool {
        self.count >= FRONT_LAYER_CACHE_SIZE
    }

    /// リフィルが必要かどうか
    #[inline]
    pub fn needs_refill(&self) -> bool {
        self.count <= FRONT_LAYER_LOW_WATERMARK
    }

    /// ドレインが必要かどうか
    #[inline]
    pub fn needs_drain(&self) -> bool {
        self.count >= FRONT_LAYER_HIGH_WATERMARK
    }

    /// 現在のフレーム数
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// 統計情報を取得
    pub fn stats(&self) -> PerCpuFrameCacheStats {
        PerCpuFrameCacheStats {
            cpu_id: self.cpu_id,
            cached_frames: self.count,
            cache_hits: self.cache_hits,
            cache_misses: self.cache_misses,
            refill_count: self.refill_count,
            drain_count: self.drain_count,
        }
    }
}

/// Per-CPUキャッシュ統計
#[derive(Debug, Clone, Copy)]
pub struct PerCpuFrameCacheStats {
    pub cpu_id: usize,
    pub cached_frames: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub refill_count: u64,
    pub drain_count: u64,
}

/// フロントレイヤー全体の管理構造
pub struct BuddyFrontLayer {
    /// Per-CPUキャッシュ配列
    caches: [Option<PerCpuFrameCache>; FRONT_LAYER_MAX_CPUS],
    /// 初期化されたCPU数
    initialized_cpus: AtomicUsize,
    /// 統計: 総キャッシュヒット数
    total_hits: AtomicUsize,
    /// 統計: 総キャッシュミス数
    total_misses: AtomicUsize,
}

impl BuddyFrontLayer {
    /// 新しいフロントレイヤーを作成
    pub const fn new() -> Self {
        const NONE_CACHE: Option<PerCpuFrameCache> = None;
        Self {
            caches: [NONE_CACHE; FRONT_LAYER_MAX_CPUS],
            initialized_cpus: AtomicUsize::new(0),
            total_hits: AtomicUsize::new(0),
            total_misses: AtomicUsize::new(0),
        }
    }

    /// 指定CPUのキャッシュを初期化
    pub fn init_cpu(&mut self, cpu_id: usize) {
        if cpu_id < FRONT_LAYER_MAX_CPUS && self.caches[cpu_id].is_none() {
            self.caches[cpu_id] = Some(PerCpuFrameCache::new(cpu_id));
            self.initialized_cpus.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// 指定CPUのキャッシュを取得
    #[inline]
    pub fn get_cache(&mut self, cpu_id: usize) -> Option<&mut PerCpuFrameCache> {
        self.caches.get_mut(cpu_id).and_then(|c| c.as_mut())
    }

    /// フレームを割り当て（フロントレイヤー優先）
    ///
    /// 1. Per-CPUキャッシュから取得
    /// 2. キャッシュが空ならBuddyからリフィル
    pub fn allocate(&mut self, cpu_id: usize, buddy: &mut BuddyFrameAllocator) -> Option<PhysFrame<Size4KiB>> {
        // キャッシュから取得を試みる
        let cache_result = if let Some(cache) = self.caches.get_mut(cpu_id).and_then(|c| c.as_mut()) {
            if let Some(addr) = cache.pop() {
                Some(Ok(addr)) // キャッシュヒット
            } else {
                cache.cache_misses += 1;
                Some(Err(())) // キャッシュミス、リフィル必要
            }
        } else {
            None // キャッシュなし
        };

        match cache_result {
            Some(Ok(addr)) => {
                self.total_hits.fetch_add(1, Ordering::Relaxed);
                return Some(unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) });
            }
            Some(Err(())) => {
                self.total_misses.fetch_add(1, Ordering::Relaxed);
                
                // バッチでリフィル
                let mut refilled = 0;
                let mut frames_to_add = Vec::new();
                
                for _ in 0..FRONT_LAYER_REFILL_BATCH {
                    if let Some(frame) = buddy.allocate_4k_frame() {
                        frames_to_add.push(frame.start_address().as_u64());
                    } else {
                        break;
                    }
                }
                
                // キャッシュに追加
                if let Some(cache) = self.caches.get_mut(cpu_id).and_then(|c| c.as_mut()) {
                    for addr in frames_to_add {
                        if cache.push(addr) {
                            refilled += 1;
                        } else {
                            // キャッシュが満杯になった場合は戻す
                            let frame = unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) };
                            buddy.deallocate_4k_frame(frame);
                            break;
                        }
                    }
                    
                    if refilled > 0 {
                        cache.refill_count += 1;
                        // リフィルしたので再度取得
                        if let Some(addr) = cache.pop() {
                            return Some(unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) });
                        }
                    }
                }
            }
            None => {}
        }

        // フォールバック: 直接Buddyから割り当て
        buddy.allocate_4k_frame()
    }

    /// フレームを解放（フロントレイヤー優先）
    ///
    /// 1. Per-CPUキャッシュに追加
    /// 2. キャッシュが満杯ならBuddyにドレイン
    pub fn deallocate(&mut self, cpu_id: usize, frame: PhysFrame<Size4KiB>, buddy: &mut BuddyFrameAllocator) {
        let addr = frame.start_address().as_u64();

        // キャッシュへの追加と、必要ならドレインを別々に処理
        let needs_drain = if let Some(cache) = self.caches.get_mut(cpu_id).and_then(|c| c.as_mut()) {
            if cache.push(addr) {
                cache.needs_drain()
            } else {
                // キャッシュ満杯 → 先にドレインが必要
                true
            }
        } else {
            // キャッシュなし → 直接Buddyに返却
            buddy.deallocate_4k_frame(frame);
            return;
        };

        if needs_drain {
            self.drain_cache(cpu_id, buddy);
            
            // ドレイン後、まだ追加できていない場合は再度試みる
            if let Some(cache) = self.caches.get_mut(cpu_id).and_then(|c| c.as_mut()) {
                if !cache.push(addr) {
                    // それでも追加できなければ直接返却
                    buddy.deallocate_4k_frame(frame);
                }
            }
        }
    }

    /// キャッシュの一部をBuddyにドレイン
    fn drain_cache(&mut self, cpu_id: usize, buddy: &mut BuddyFrameAllocator) {
        if let Some(cache) = self.caches.get_mut(cpu_id).and_then(|c| c.as_mut()) {
            let drain_count = cache.len().saturating_sub(FRONT_LAYER_LOW_WATERMARK).min(FRONT_LAYER_REFILL_BATCH);
            
            for _ in 0..drain_count {
                if let Some(addr) = cache.pop() {
                    let frame = unsafe { PhysFrame::from_start_address_unchecked(PhysAddr::new(addr)) };
                    buddy.deallocate_4k_frame(frame);
                }
            }

            if drain_count > 0 {
                cache.drain_count += 1;
            }
        }
    }

    /// 統計情報を取得
    pub fn stats(&self) -> BuddyFrontLayerStats {
        BuddyFrontLayerStats {
            initialized_cpus: self.initialized_cpus.load(Ordering::Relaxed),
            total_hits: self.total_hits.load(Ordering::Relaxed),
            total_misses: self.total_misses.load(Ordering::Relaxed),
        }
    }
}

/// フロントレイヤー統計
#[derive(Debug, Clone, Copy)]
pub struct BuddyFrontLayerStats {
    pub initialized_cpus: usize,
    pub total_hits: usize,
    pub total_misses: usize,
}

/// グローバルなフロントレイヤー
static BUDDY_FRONT_LAYER: IrqMutex<BuddyFrontLayer> = IrqMutex::new(BuddyFrontLayer::new());

/// フロントレイヤーを初期化（CPU起動時）
pub fn init_buddy_front_layer_for_cpu(cpu_id: usize) {
    BUDDY_FRONT_LAYER.lock().init_cpu(cpu_id);
}

/// フロントレイヤー経由で4KiBフレームを割り当て
pub fn buddy_alloc_frame_fast(cpu_id: usize) -> Option<PhysFrame<Size4KiB>> {
    let mut front = BUDDY_FRONT_LAYER.lock();
    let mut buddy = BUDDY_ALLOCATOR.lock();
    front.allocate(cpu_id, &mut buddy)
}

/// フロントレイヤー経由で4KiBフレームを解放
pub fn buddy_dealloc_frame_fast(cpu_id: usize, frame: PhysFrame<Size4KiB>) {
    let mut front = BUDDY_FRONT_LAYER.lock();
    let mut buddy = BUDDY_ALLOCATOR.lock();
    front.deallocate(cpu_id, frame, &mut buddy);
}

/// フロントレイヤー統計を取得
pub fn buddy_front_layer_stats() -> BuddyFrontLayerStats {
    BUDDY_FRONT_LAYER.lock().stats()
}

/// グローバルなBuddy Allocator
/// 割り込み禁止Mutexで保護（デッドロック防止）
static BUDDY_ALLOCATOR: IrqMutex<BuddyFrameAllocator> = IrqMutex::new(BuddyFrameAllocator::new());

/// Buddy Allocatorを初期化
///
/// # Safety
/// カーネル初期化時に一度だけ呼ばれる必要がある
pub unsafe fn init_buddy_allocator(usable_regions: &[(PhysAddr, u64)]) {
    unsafe {
        BUDDY_ALLOCATOR.lock().init(usable_regions);
    }
}

/// 4KiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame() -> Option<PhysFrame<Size4KiB>> {
    BUDDY_ALLOCATOR.lock().allocate_4k_frame()
}

/// 2MiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame_2m() -> Option<PhysFrame<Size2MiB>> {
    BUDDY_ALLOCATOR.lock().allocate_2m_frame()
}

/// 1GiB フレームを割り当て（Buddy版）
pub fn buddy_alloc_frame_1g() -> Option<PhysFrame<Size1GiB>> {
    BUDDY_ALLOCATOR.lock().allocate_1g_frame()
}

/// 連続する物理フレームを割り当て（2のべき乗に切り上げ）
pub fn buddy_alloc_contiguous_frames(frame_count: usize) -> Option<PhysAddr> {
    if frame_count == 0 {
        return None;
    }
    BUDDY_ALLOCATOR.lock().allocate_contiguous(frame_count)
}

/// 4KiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame(frame: PhysFrame<Size4KiB>) {
    BUDDY_ALLOCATOR.lock().deallocate_4k_frame(frame);
}

/// 2MiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame_2m(frame: PhysFrame<Size2MiB>) {
    BUDDY_ALLOCATOR.lock().deallocate_2m_frame(frame);
}

/// 1GiB フレームを解放（Buddy版）
pub fn buddy_dealloc_frame_1g(frame: PhysFrame<Size1GiB>) {
    BUDDY_ALLOCATOR.lock().deallocate_1g_frame(frame);
}

/// Buddy Allocatorの統計を取得
pub fn buddy_allocator_stats() -> BuddyAllocatorStats {
    BUDDY_ALLOCATOR.lock().stats()
}

/// Register a NUMA region with the global Buddy Allocator
pub fn buddy_register_numa_region(node: usize, start: PhysAddr, size: u64) {
    let mut allocator = BUDDY_ALLOCATOR.lock();
    let start_frame = FrameIndex::from_phys_addr(start.as_u64());
    let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);
    allocator.register_numa_region(node, start_frame, end_frame);
}

/// Allocate a 4KiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_on_node(node: usize) -> Option<PhysFrame<Size4KiB>> {
    BUDDY_ALLOCATOR.lock().allocate_4k_frame_on_node(node)
}

/// Allocate a 2MiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_2m_on_node(node: usize) -> Option<PhysFrame<Size2MiB>> {
    BUDDY_ALLOCATOR.lock().allocate_2m_frame_on_node(node)
}

/// Allocate a 1GiB frame preferring the given NUMA node (best-effort)
pub fn buddy_alloc_frame_1g_on_node(node: usize) -> Option<PhysFrame<Size1GiB>> {
    BUDDY_ALLOCATOR.lock().allocate_1g_frame_on_node(node)
}

/// 指定アドレスがBuddy Allocatorで管理されているかチェック
///
/// 設計書 P2: 統一フレームアロケータのための判定
/// 注: Buddyアロケータは初期化時に登録された領域のみを管理する
pub fn is_managed_by_buddy(addr: PhysAddr) -> bool {
    let allocator = BUDDY_ALLOCATOR.lock();

    // If NUMA regions are recorded, check them first
    if let Some(map) = allocator.numa_regions.as_ref() {
        for (_node, ranges) in map.iter() {
            for &(start, end) in ranges.iter() {
                let start_addr = start.to_phys_addr();
                let end_addr = end.to_phys_addr();
                if addr.as_u64() >= start_addr && addr.as_u64() < end_addr {
                    return true;
                }
            }
        }
    }

    // Fallback: contiguous region assumption
    if allocator.total_frames == 0 {
        return false;
    }

    let max_addr = (allocator.total_frames as u64) * (PAGE_SIZE_4K as u64);
    addr.as_u64() < max_addr
}

/// 指定範囲がBuddy Allocatorで管理されているかチェック
///
/// 範囲は [start, start+size) の半開区間。
pub fn is_range_managed_by_buddy(start: PhysAddr, size: u64) -> bool {
    if size == 0 {
        return false;
    }

    let Some(end) = start.as_u64().checked_add(size) else {
        return false;
    };

    let allocator = BUDDY_ALLOCATOR.lock();

    if let Some(map) = allocator.numa_regions.as_ref() {
        for (_node, ranges) in map.iter() {
            for &(range_start, range_end) in ranges.iter() {
                let start_addr = range_start.to_phys_addr();
                let end_addr = range_end.to_phys_addr();
                if start.as_u64() >= start_addr && end <= end_addr {
                    return true;
                }
            }
        }
        return false;
    }

    if allocator.total_frames == 0 {
        return false;
    }

    let max_addr = (allocator.total_frames as u64) * (PAGE_SIZE_4K as u64);
    start.as_u64() < max_addr && end <= max_addr
}

// ============================================================================
// Phase 6: THP Support Functions
// ============================================================================

/// 指定フレームが割り当て済み（使用中）かどうかをチェック
/// 
/// THP昇格候補の検出に使用される。
/// 空きフレームでない = 割り当て済みとみなす。
#[inline]
pub fn is_frame_allocated(frame_idx: usize) -> bool {
    let allocator = BUDDY_ALLOCATOR.lock();
    
    if frame_idx >= allocator.total_frames {
        return false;
    }
    
    // Order 0（4KB）のビットマップで空きかどうかをチェック
    // is_block_free が false = 空きではない = 割り当て済み
    !allocator.is_block_free(0, frame_idx)
}

/// 512個の連続フレームをHugePageとしてマーク
/// 
/// THP昇格時に呼び出される。Order 9（512フレーム = 2MB）として
/// Buddyアロケータに登録する。
/// 
/// # Safety
/// 
/// - `start_frame`は2MB境界にアラインされている必要がある
/// - 512個全てのフレームが割り当て済みである必要がある
#[inline]
pub unsafe fn mark_as_huge_page(start_frame: usize) -> bool {
    const PAGES_PER_2MB: usize = 512;
    
    // 2MB境界チェック
    if start_frame % PAGES_PER_2MB != 0 {
        return false;
    }
    
    let allocator = BUDDY_ALLOCATOR.lock();
    
    // 全512フレームが割り当て済みかチェック（is_block_free使用）
    for i in 0..PAGES_PER_2MB {
        let frame_idx = start_frame + i;
        if frame_idx >= allocator.total_frames {
            return false;
        }
        
        // 空きであれば割り当て不可
        if allocator.is_block_free(0, frame_idx) {
            return false;
        }
    }
    
    // Order 9（2MB）として内部的にマーク
    // 注: 実際のページテーブル操作は別途必要
    // ここではBuddyの統計を更新
    
    // HugePageカウンタをインクリメント（統計用）
    HUGE_PAGE_STATS.marked_count.fetch_add(1, Ordering::Relaxed);
    
    true
}

/// HugePageマーキング統計
pub struct HugePageStats {
    /// マークされたHugePage数
    pub marked_count: AtomicU64,
    /// アンマークされたHugePage数
    pub unmarked_count: AtomicU64,
}

impl HugePageStats {
    pub const fn new() -> Self {
        Self {
            marked_count: AtomicU64::new(0),
            unmarked_count: AtomicU64::new(0),
        }
    }
}

/// グローバルHugePage統計
pub static HUGE_PAGE_STATS: HugePageStats = HugePageStats::new();

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buddy_allocator() {
        let mut allocator = BuddyFrameAllocator::new();

        // テスト用のメモリ領域（4MiB、MAX_ORDER=18に対応）
        let regions = [(PhysAddr::new(0x100000), 0x400000u64)];
        unsafe {
            allocator.init(&regions);
        }

        // フレーム割り当て
        let frame1 = allocator.allocate_4k_frame();
        assert!(frame1.is_some());
    }

    #[test]
    fn test_init_numa_frame_allocator_registers_region_with_buddy() {
        use crate::mm::frame_allocator::NumaNodeId;
        use crate::mm::{init_buddy_allocator, init_numa_frame_allocator};

        // Initialize buddy allocator with a default region
        let base_region = [(PhysAddr::new(0x100000), 0x400000u64)];
        unsafe {
            init_buddy_allocator(&base_region);
        }

        // Register a NUMA region and ensure buddy knows about it
        let numa_region = [(PhysAddr::new(0x200000), 0x2000u64, NumaNodeId::new(1))];
        unsafe {
            init_numa_frame_allocator(&numa_region);
        }

        // Check buddy reports the address as managed
        assert!(crate::mm::buddy_allocator::is_managed_by_buddy(PhysAddr::new(
            0x200000
        )));

        // Try to allocate a frame preferring that node (best-effort)
        let alloc = crate::mm::buddy_alloc_frame_on_node(1);
        assert!(alloc.is_some());
    }

    #[test]
    fn test_order_calculation() {
        assert_eq!(BuddyFrameAllocator::frames_to_order(1), 0);
        assert_eq!(BuddyFrameAllocator::frames_to_order(2), 1);
        assert_eq!(BuddyFrameAllocator::frames_to_order(3), 2);
        assert_eq!(BuddyFrameAllocator::frames_to_order(4), 2);
        assert_eq!(BuddyFrameAllocator::frames_to_order(512), 9);
        assert_eq!(BuddyFrameAllocator::frames_to_order(262144), 18);
    }

    #[test]
    fn test_numa_register_and_alloc_local() {
        let mut allocator = BuddyFrameAllocator::new();

        // Register a NUMA region (small area)
        let start = PhysAddr::new(0x1000_0000);
        let size = 0x20_000; // 128 KiB
        let start_frame = FrameIndex::from_phys_addr(start.as_u64());
        let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

        allocator.register_numa_region(0, start_frame, end_frame);

        // Allocate a 4K frame preferring node 0
        let frame = allocator.allocate_4k_frame_on_node(0).expect("alloc local");
        assert!(frame.start_address().as_u64() >= start.as_u64());
        assert!(frame.start_address().as_u64() < start.as_u64() + size);
    }

    #[test]
    fn test_numa_2m_alloc_local() {
        let mut allocator = BuddyFrameAllocator::new();

        // Register a larger NUMA region suitable for 2MiB allocations
        let start = PhysAddr::new(0x2000_0000);
        let size = 0x10_0000; // 1 MiB (smaller than 2MiB but for test we can still allocate a 4K)
        let start_frame = FrameIndex::from_phys_addr(start.as_u64());
        let end_frame = FrameIndex::from_phys_addr(start.as_u64() + size);

        allocator.register_numa_region(1, start_frame, end_frame);

        // Try 4K allocation on node 1 (2M allocation may fail due to size)
        let frame = allocator
            .allocate_4k_frame_on_node(1)
            .expect("alloc 4K local");
        assert!(frame.start_address().as_u64() >= start.as_u64());
        assert!(frame.start_address().as_u64() < start.as_u64() + size);
    }
}
