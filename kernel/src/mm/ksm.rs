// ============================================================================
// src/mm/ksm.rs - Kernel Same-page Merging (KSM)
//
// 重複したページ内容を検出し、単一の物理ページに統合することで
// メモリ使用量を削減する機構。
//
// ## 設計概要
//
// 1. **スキャン**: メモリ領域をスキャンしてページのハッシュを計算
// 2. **比較**: ハッシュが一致するページを詳細比較
// 3. **マージ**: 同一内容のページを単一の読み取り専用ページに統合
// 4. **CoW (Copy-on-Write)**: 書き込み時に新しいページを割り当て
//
// ## ユースケース
//
// - 仮想化環境での同一OSイメージのメモリ共有
// - フォークしたプロセス間のページ共有
// - 同じデータを持つ複数プロセスのメモリ削減
//
// ## 制限事項
//
// - CPUオーバーヘッド（スキャンとハッシュ計算）
// - 書き込み時のCoWオーバーヘッド
// - サイドチャネル攻撃のリスク（タイミング攻撃）
// ============================================================================
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, Ordering};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::sync::IrqMutex;
use super::types::{FrameIndex, PAGE_SIZE_4K};
use super::mapping::PHYSICAL_MEMORY_OFFSET;

// ============================================================================
// Configuration
// ============================================================================

/// 一度のスキャンで処理する最大ページ数
const KSM_SCAN_BATCH_SIZE: usize = 256;

/// スキャン間隔（ミリ秒）
const KSM_SCAN_PERIOD_MS: u64 = 2000;

/// マージ候補として保持する最大ページ数
const KSM_MAX_CANDIDATES: usize = 1024;

/// ハッシュバケットサイズ
const KSM_HASH_BUCKETS: usize = 256;

// ============================================================================
// Page Hash
// ============================================================================

/// ページのハッシュ値
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PageHash(pub u64);

impl PageHash {
    /// ページ内容からハッシュを計算（xxHash風の高速ハッシュ）
    pub fn compute(page_data: &[u8; PAGE_SIZE_4K]) -> Self {
        // FNV-1a ハッシュ（高速で衝突が少ない）
        const FNV_PRIME: u64 = 0x00000100000001B3;
        const FNV_OFFSET: u64 = 0xcbf29ce484222325;
        
        let mut hash = FNV_OFFSET;
        
        // 64バイトごとに処理して高速化
        let ptr = page_data.as_ptr() as *const u64;
        for i in 0..(PAGE_SIZE_4K / 8) {
            let word = unsafe { ptr.add(i).read_unaligned() };
            hash ^= word;
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        
        PageHash(hash)
    }
    
    /// バケットインデックスを取得
    #[inline]
    pub fn bucket_index(&self) -> usize {
        (self.0 as usize) % KSM_HASH_BUCKETS
    }
}

// ============================================================================
// Stable Page Entry
// ============================================================================

/// マージ済みの安定ページエントリ
#[derive(Debug, Clone)]
pub struct StablePage {
    /// 物理フレーム
    pub frame: FrameIndex,
    /// ハッシュ値
    pub hash: PageHash,
    /// 参照カウント（このページを共有しているPTE数）
    pub ref_count: u32,
    /// 作成時刻
    pub created_at: u64,
}

/// マージ候補ページエントリ
#[derive(Debug, Clone)]
pub struct UnstablePage {
    /// 物理フレーム
    pub frame: FrameIndex,
    /// ハッシュ値
    pub hash: PageHash,
    /// 最後にスキャンした時刻
    pub last_scan: u64,
    /// スキャン回数
    pub scan_count: u32,
}

// ============================================================================
// KSM Statistics
// ============================================================================

/// KSM統計
#[derive(Debug, Clone, Copy, Default)]
pub struct KsmStats {
    /// スキャンしたページ数
    pub pages_scanned: u64,
    /// マージに成功したページ数
    pub pages_merged: u64,
    /// マージにより削減したバイト数
    pub bytes_saved: u64,
    /// CoWにより分離したページ数
    pub pages_unmerged: u64,
    /// 現在のマージ済みページ数
    pub current_merged: u64,
    /// 安定ページテーブルのエントリ数
    pub stable_pages: u64,
    /// 不安定ページテーブルのエントリ数
    pub unstable_pages: u64,
}

// ============================================================================
// KSM Manager
// ============================================================================

/// KSMマネージャ
pub struct KsmManager {
    /// 安定ページテーブル（ハッシュ -> ページ情報）
    stable_tree: BTreeMap<PageHash, StablePage>,
    
    /// 不安定ページテーブル（マージ候補）
    unstable_tree: BTreeMap<PageHash, Vec<UnstablePage>>,
    
    /// スキャン位置
    scan_position: FrameIndex,
    
    /// 最大フレーム番号
    max_frame: FrameIndex,
    
    /// 統計情報
    stats: KsmStats,
    
    /// 有効化フラグ
    enabled: bool,
    
    /// スキャン実行中フラグ
    scanning: AtomicBool,
}

impl KsmManager {
    /// 新しいKSMマネージャを作成
    pub const fn new() -> Self {
        Self {
            stable_tree: BTreeMap::new(),
            unstable_tree: BTreeMap::new(),
            scan_position: FrameIndex::new(0),
            max_frame: FrameIndex::new(0),
            stats: KsmStats {
                pages_scanned: 0,
                pages_merged: 0,
                bytes_saved: 0,
                pages_unmerged: 0,
                current_merged: 0,
                stable_pages: 0,
                unstable_pages: 0,
            },
            enabled: false,
            scanning: AtomicBool::new(false),
        }
    }
    
    /// 初期化
    pub fn init(&mut self, max_frame: FrameIndex) {
        self.max_frame = max_frame;
        self.scan_position = FrameIndex::new(0);
        self.stable_tree.clear();
        self.unstable_tree.clear();
        self.enabled = true;
    }
    
    /// 有効化/無効化
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
    
    /// ページをスキャンしてマージ候補を検出
    pub fn scan_pages(&mut self, current_time: u64) -> usize {
        if !self.enabled {
            return 0;
        }
        
        // 再入防止
        if self.scanning.swap(true, Ordering::SeqCst) {
            return 0;
        }
        
        let mut scanned = 0;
        let start = self.scan_position.as_usize();
        let end = (start + KSM_SCAN_BATCH_SIZE).min(self.max_frame.as_usize());
        
        for frame_idx in start..end {
            if self.try_merge_page(FrameIndex::new(frame_idx), current_time) {
                self.stats.pages_merged += 1;
            }
            scanned += 1;
        }
        
        // スキャン位置を更新
        self.scan_position = if end >= self.max_frame.as_usize() {
            FrameIndex::new(0)
        } else {
            FrameIndex::new(end)
        };
        
        self.stats.pages_scanned += scanned as u64;
        self.scanning.store(false, Ordering::SeqCst);
        
        scanned
    }
    
    /// 単一ページのマージを試行
    fn try_merge_page(&mut self, frame: FrameIndex, current_time: u64) -> bool {
        // ページデータを読み取り
        let page_data = match self.read_page_data(frame) {
            Some(data) => data,
            None => return false,
        };
        
        // ハッシュを計算
        let hash = PageHash::compute(&page_data);
        
        // 1. 安定ツリーで完全一致を検索
        if let Some(stable) = self.stable_tree.get(&hash) {
            let stable_frame = stable.frame;
            // 内容を詳細比較（selfの借用を避けるために静的関数を使用）
            if Self::pages_equal_static(frame, stable_frame) {
                // マージ成功: 参照カウントを増加
                if let Some(stable_mut) = self.stable_tree.get_mut(&hash) {
                    stable_mut.ref_count += 1;
                }
                self.stats.current_merged += 1;
                self.stats.bytes_saved += PAGE_SIZE_4K as u64;
                return true;
            }
        }
        
        // 2. 不安定ツリーで候補を検索
        // まず候補フレームのみを抽出
        let candidate_frames: Vec<FrameIndex> = self.unstable_tree
            .get(&hash)
            .map(|entries| entries.iter().map(|e| e.frame).collect())
            .unwrap_or_default();
        
        // 候補と比較
        for candidate_frame in candidate_frames {
            if Self::pages_equal_static(frame, candidate_frame) {
                // 新しい安定ページとして登録
                let stable = StablePage {
                    frame: candidate_frame,
                    hash,
                    ref_count: 2,  // 元のページ + 新しいページ
                    created_at: current_time,
                };
                self.stable_tree.insert(hash, stable);
                self.stats.stable_pages += 1;
                self.stats.current_merged += 2;
                self.stats.bytes_saved += PAGE_SIZE_4K as u64;
                return true;
            }
        }
        
        // 3. 不安定ツリーに追加
        let unstable_entry = self.unstable_tree
            .entry(hash)
            .or_insert_with(Vec::new);
        
        if unstable_entry.len() < 16 {  // 同一ハッシュの上限
            unstable_entry.push(UnstablePage {
                frame,
                hash,
                last_scan: current_time,
                scan_count: 1,
            });
            self.stats.unstable_pages += 1;
        }
        
        false
    }
    
    /// ページデータを読み取り
    fn read_page_data(&self, frame: FrameIndex) -> Option<[u8; PAGE_SIZE_4K]> {
        let phys_addr = (frame.as_usize() * PAGE_SIZE_4K) as u64;
        let virt_addr = phys_addr + PHYSICAL_MEMORY_OFFSET;
        
        let mut data = [0u8; PAGE_SIZE_4K];
        unsafe {
            core::ptr::copy_nonoverlapping(
                virt_addr as *const u8,
                data.as_mut_ptr(),
                PAGE_SIZE_4K,
            );
        }
        Some(data)
    }
    
    /// 2つのページが完全に一致するか比較（静的版）
    fn pages_equal_static(frame1: FrameIndex, frame2: FrameIndex) -> bool {
        if frame1 == frame2 {
            return true;
        }
        
        let phys1 = (frame1.as_usize() * PAGE_SIZE_4K) as u64;
        let phys2 = (frame2.as_usize() * PAGE_SIZE_4K) as u64;
        
        let virt1 = (phys1 + PHYSICAL_MEMORY_OFFSET) as *const u64;
        let virt2 = (phys2 + PHYSICAL_MEMORY_OFFSET) as *const u64;
        
        // 64ビットごとに比較（高速化）
        for i in 0..(PAGE_SIZE_4K / 8) {
            unsafe {
                if virt1.add(i).read_volatile() != virt2.add(i).read_volatile() {
                    return false;
                }
            }
        }
        
        true
    }
    
    /// ページのマージを解除（CoW時に呼び出し）
    pub fn unmerge_page(&mut self, hash: PageHash) -> bool {
        if let Some(stable) = self.stable_tree.get_mut(&hash) {
            stable.ref_count -= 1;
            self.stats.current_merged -= 1;
            self.stats.pages_unmerged += 1;
            
            // 参照がなくなったら安定ツリーから削除
            if stable.ref_count == 0 {
                self.stable_tree.remove(&hash);
                self.stats.stable_pages -= 1;
            }
            return true;
        }
        false
    }
    
    /// 古い不安定エントリを削除
    pub fn cleanup_unstable(&mut self, max_age: u64, current_time: u64) {
        for (_hash, entries) in self.unstable_tree.iter_mut() {
            entries.retain(|e| {
                let keep = current_time.saturating_sub(e.last_scan) < max_age;
                if !keep {
                    self.stats.unstable_pages -= 1;
                }
                keep
            });
        }
        
        // 空のバケットを削除
        self.unstable_tree.retain(|_, v| !v.is_empty());
    }
    
    /// 統計情報を取得
    pub fn stats(&self) -> KsmStats {
        self.stats
    }
    
    /// 統計をリセット
    pub fn reset_stats(&mut self) {
        self.stats = KsmStats::default();
    }
}

// ============================================================================
// Global KSM Manager
// ============================================================================

/// グローバルKSMマネージャ
static KSM_MANAGER: IrqMutex<KsmManager> = IrqMutex::new(KsmManager::new());

/// KSMを初期化
pub fn init_ksm(max_frame: FrameIndex) {
    KSM_MANAGER.lock().init(max_frame);
}

/// KSMを有効化
pub fn enable_ksm() {
    KSM_MANAGER.lock().set_enabled(true);
}

/// KSMを無効化
pub fn disable_ksm() {
    KSM_MANAGER.lock().set_enabled(false);
}

/// ページスキャンを実行
pub fn ksm_scan(current_time: u64) -> usize {
    KSM_MANAGER.lock().scan_pages(current_time)
}

/// KSM統計を取得
pub fn ksm_stats() -> KsmStats {
    KSM_MANAGER.lock().stats()
}

/// アイドル時のKSM処理
/// 
/// スキャンと古いエントリのクリーンアップを実行
pub fn ksm_idle_work(current_time: u64) -> usize {
    let mut manager = KSM_MANAGER.lock();
    
    // 古いエントリをクリーンアップ（60秒以上古いもの）
    manager.cleanup_unstable(60000, current_time);
    
    // スキャンを実行
    manager.scan_pages(current_time)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_page_hash_compute() {
        let mut data1 = [0u8; PAGE_SIZE_4K];
        let mut data2 = [0u8; PAGE_SIZE_4K];
        let mut data3 = [0u8; PAGE_SIZE_4K];
        
        data1[0] = 1;
        data2[0] = 1;
        data3[0] = 2;
        
        let hash1 = PageHash::compute(&data1);
        let hash2 = PageHash::compute(&data2);
        let hash3 = PageHash::compute(&data3);
        
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_page_hash_bucket() {
        let data = [0u8; PAGE_SIZE_4K];
        let hash = PageHash::compute(&data);
        let bucket = hash.bucket_index();
        
        assert!(bucket < KSM_HASH_BUCKETS);
    }
}
