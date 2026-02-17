// ============================================================================
// ZSWAP - Compressed Swap Cache
// スワップ前のメモリ圧縮キャッシュ
// ============================================================================
//!
//! # ZSWAP Architecture
#![allow(dead_code)]
//!
//! ## 概要
//! ZSWAPは、ページがスワップアウトされる前に圧縮してRAM上に保持する機構。
//! ディスクI/Oを削減し、メモリ圧縮によるパフォーマンス向上を実現。
//!
//! ## フロー
//! ```text
//! ページ回収要求
//!     ↓
//! ZSWAP圧縮試行
//!     ↓ (成功)
//! 圧縮データをzpoolに格納
//!     ↓ (圧縮率が悪い/プール満杯)
//! 通常スワップ/回収
//! ```
//!
//! ## 圧縮アルゴリズム
//! - LZ4: 高速、中程度の圧縮率
//! - ZSTD: 低速、高い圧縮率（オプション）

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use spin::{Mutex, RwLock};

use super::{PAGE_SIZE_4K, PAGE_SIZE_2M, PAGE_SIZE_1G};

/// 圧縮アルゴリズム
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionAlgo {
    /// LZ4（デフォルト、高速）
    Lz4 = 0,
    /// ZSTD（高圧縮率）
    Zstd = 1,
    /// 無圧縮（デバッグ用）
    None = 2,
}

impl Default for CompressionAlgo {
    fn default() -> Self {
        Self::Lz4
    }
}

/// ZSWAPエントリ
struct ZswapEntry {
    /// 圧縮データ
    data: Vec<u8>,
    /// 元のページサイズ（通常4096）
    original_size: usize,
    /// 圧縮後サイズ
    compressed_size: usize,
    /// 圧縮アルゴリズム
    algo: CompressionAlgo,
    /// 作成タイムスタンプ
    created_tsc: u64,
    /// アクセスカウント
    access_count: u32,
}

impl ZswapEntry {
    /// 圧縮率を取得（0.0 - 1.0、低いほど良い）
    fn compression_ratio(&self) -> f64 {
        self.compressed_size as f64 / self.original_size as f64
    }
}

/// ZSWAP統計
#[derive(Debug, Default, Clone)]
pub struct ZswapStats {
    /// 格納中のエントリ数
    pub stored_pages: u64,
    /// 2MiBページとして格納されたエントリ数
    pub stored_pages_2m: u64,
    /// 1GiBページとして格納されたエントリ数
    pub stored_pages_1g: u64,
    /// 格納前の合計サイズ（バイト）
    pub orig_data_size: u64,
    /// 圧縮後の合計サイズ（バイト）
    pub compr_data_size: u64,
    /// 圧縮成功回数
    pub compress_success: u64,
    /// 圧縮失敗回数（圧縮率が悪い等）
    pub compress_fail: u64,
    /// 展開成功回数
    pub decompress_success: u64,
    /// プール満杯によるリジェクト
    pub pool_full_reject: u64,
    /// 書き戻し回数（プールからスワップへ）
    pub writeback_count: u64,
    /// 重複検出回数
    pub duplicate_count: u64,
}

impl ZswapStats {
    /// 平均圧縮率を取得
    pub fn avg_compression_ratio(&self) -> f64 {
        if self.orig_data_size == 0 {
            1.0
        } else {
            self.compr_data_size as f64 / self.orig_data_size as f64
        }
    }
    
    /// 節約バイト数
    pub fn saved_bytes(&self) -> u64 {
        self.orig_data_size.saturating_sub(self.compr_data_size)
    }
}

/// ZSWAP設定
#[derive(Debug, Clone)]
pub struct ZswapConfig {
    /// 有効フラグ
    pub enabled: bool,
    /// 圧縮アルゴリズム
    pub compressor: CompressionAlgo,
    /// 最大プールサイズ（バイト）
    pub max_pool_size: usize,
    /// 許容最大圧縮率（これより大きいと拒否）
    pub max_compression_ratio: f64,
    /// 同一ページ最適化
    pub same_filled_pages_enabled: bool,
    /// LRU書き戻し閾値
    pub writeback_threshold: f64,
}

impl Default for ZswapConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            compressor: CompressionAlgo::Lz4,
            max_pool_size: 256 * 1024 * 1024, // 256MB
            max_compression_ratio: 0.9, // 90%以上は拒否
            same_filled_pages_enabled: true,
            writeback_threshold: 0.8, // 80%使用で書き戻し開始
        }
    }
}

/// Zpool（圧縮データプール）
pub struct Zpool {
    /// エントリ一覧（スワップオフセット -> エントリ）
    entries: RwLock<BTreeMap<u64, ZswapEntry>>,
    /// 現在の使用サイズ（バイト）
    current_size: AtomicU64,
    /// 最大サイズ
    max_size: AtomicU64,
    /// 統計
    stats: Mutex<ZswapStats>,
    /// 設定
    config: RwLock<ZswapConfig>,
    /// 初期化済み
    initialized: AtomicU8,
}

impl Zpool {
    /// 新しいZpoolを作成
    pub const fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
            current_size: AtomicU64::new(0),
            max_size: AtomicU64::new(256 * 1024 * 1024),
            stats: Mutex::new(ZswapStats {
                stored_pages: 0,                stored_pages_2m: 0,
                stored_pages_1g: 0,                orig_data_size: 0,
                compr_data_size: 0,
                compress_success: 0,
                compress_fail: 0,
                decompress_success: 0,
                pool_full_reject: 0,
                writeback_count: 0,
                duplicate_count: 0,
            }),
            config: RwLock::new(ZswapConfig {
                enabled: true,
                compressor: CompressionAlgo::Lz4,
                max_pool_size: 256 * 1024 * 1024,
                max_compression_ratio: 0.9,
                same_filled_pages_enabled: true,
                writeback_threshold: 0.8,
            }),
            initialized: AtomicU8::new(0),
        }
    }
    
    /// 初期化
    pub fn init(&self) {
        if self.initialized.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            log::info!("[ZSWAP] Initialized with max pool size: {}MB", 
                self.max_size.load(Ordering::Relaxed) / (1024 * 1024));
        }
    }
    
    /// 設定を更新
    pub fn update_config(&self, config: ZswapConfig) {
        self.max_size.store(config.max_pool_size as u64, Ordering::Relaxed);
        let mut cfg = self.config.write();
        *cfg = config;
    }
    
    /// 有効か確認
    pub fn is_enabled(&self) -> bool {
        self.config.read().enabled
    }
    
    /// 同一値ページ検出を試み、成功すれば格納して結果を返す
    fn try_store_same_filled(&self, swap_offset: u64, page_data: &[u8]) -> Option<Result<(), ZswapError>> {
        let config = self.config.read();
        if config.same_filled_pages_enabled {
            if let Some(fill_value) = self.detect_same_filled(page_data) {
                return Some(self.store_same_filled(swap_offset, fill_value, page_data.len()));
            }
        }
        None
    }

    /// 格納成功後の統計更新
    fn update_store_stats(&self, page_size: usize, compressed_len: usize) {
        let mut stats = self.stats.lock();
        stats.stored_pages += 1;
        stats.orig_data_size += page_size as u64;
        stats.compr_data_size += compressed_len as u64;
        stats.compress_success += 1;
        if page_size == PAGE_SIZE_2M { stats.stored_pages_2m += 1; }
        if page_size == PAGE_SIZE_1G { stats.stored_pages_1g += 1; }
    }

    /// ページを圧縮して格納
    pub fn store(&self, swap_offset: u64, page_data: &[u8]) -> Result<(), ZswapError> {
        if !self.is_enabled() {
            return Err(ZswapError::Disabled);
        }

        // Accept 4KiB / 2MiB / 1GiB
        let page_size = page_data.len();
        if page_size != PAGE_SIZE_4K && page_size != PAGE_SIZE_2M && page_size != PAGE_SIZE_1G {
            return Err(ZswapError::InvalidSize);
        }

        // 同一値ページ検出（任意サイズ対応）
        if let Some(result) = self.try_store_same_filled(swap_offset, page_data) {
            return result;
        }

        // 圧縮（ページ全体を圧縮）
        let config = self.config.read();
        let compressed = self.compress(page_data, config.compressor)?;
        let compression_ratio = compressed.len() as f64 / page_size as f64;

        // 圧縮率チェック
        if compression_ratio > config.max_compression_ratio {
            let mut stats = self.stats.lock();
            stats.compress_fail += 1;
            return Err(ZswapError::PoorCompression);
        }
        
        drop(config);
        
        // プールサイズチェック
        let new_size = self.current_size.load(Ordering::Relaxed) + compressed.len() as u64;
        if new_size > self.max_size.load(Ordering::Relaxed) {
            let mut stats = self.stats.lock();
            stats.pool_full_reject += 1;
            return Err(ZswapError::PoolFull);
        }
        
        let entry = ZswapEntry {
            data: compressed.clone(),
            original_size: page_size,
            compressed_size: compressed.len(),
            algo: self.config.read().compressor,
            created_tsc: read_tsc(),
            access_count: 0,
        };

        // 格納
        {
            let mut entries = self.entries.write();

            // 既存エントリがあれば削除
            if let Some(old) = entries.remove(&swap_offset) {
                self.current_size.fetch_sub(old.compressed_size as u64, Ordering::Relaxed);
                let mut stats = self.stats.lock();
                stats.stored_pages -= 1;
                stats.orig_data_size -= old.original_size as u64;
                stats.compr_data_size -= old.compressed_size as u64;
                stats.duplicate_count += 1;
            }

            entries.insert(swap_offset, entry);
        }

        // 統計更新
        self.current_size.fetch_add(compressed.len() as u64, Ordering::Relaxed);
        self.update_store_stats(page_size, compressed.len());

        Ok(())
    }
    
    /// ページを展開して取得
    pub fn load(&self, swap_offset: u64, out_buffer: &mut [u8]) -> Result<(), ZswapError> {
        let entries = self.entries.read();
        let entry = entries.get(&swap_offset).ok_or(ZswapError::NotFound)?;

        if out_buffer.len() != entry.original_size {
            return Err(ZswapError::InvalidSize);
        }

        // 展開
        self.decompress(&entry.data, entry.algo, out_buffer)?;

        // 統計更新
        {
            let mut stats = self.stats.lock();
            stats.decompress_success += 1;
        }

        Ok(())
    }
    
    /// エントリを削除
    pub fn invalidate(&self, swap_offset: u64) -> bool {
        let mut entries = self.entries.write();
        
        if let Some(entry) = entries.remove(&swap_offset) {
            self.current_size.fetch_sub(entry.compressed_size as u64, Ordering::Relaxed);
            
            let mut stats = self.stats.lock();
            stats.stored_pages -= 1;
            stats.orig_data_size -= entry.original_size as u64;
            stats.compr_data_size -= entry.compressed_size as u64;
            
            true
        } else {
            false
        }
    }
    
    /// 圧縮処理
    fn compress(&self, data: &[u8], algo: CompressionAlgo) -> Result<Vec<u8>, ZswapError> {
        match algo {
            CompressionAlgo::Lz4 => self.compress_lz4(data),
            CompressionAlgo::Zstd => self.compress_zstd(data),
            CompressionAlgo::None => Ok(data.to_vec()),
        }
    }
    
    /// LZ4圧縮（簡易実装）
    fn compress_lz4(&self, data: &[u8]) -> Result<Vec<u8>, ZswapError> {
        // 実際のLZ4実装ではなく、簡易的なRLE圧縮
        // 本番環境では lz4_flex クレートなどを使用
        let mut compressed = Vec::with_capacity(data.len());
        let mut i = 0;
        
        while i < data.len() {
            let byte = data[i];
            let mut run_len = 1u8;
            
            while (i + run_len as usize) < data.len() 
                && data[i + run_len as usize] == byte 
                && run_len < 255 
            {
                run_len += 1;
            }
            
            if run_len >= 4 {
                // RLEエンコード: [0xFF, byte, length]
                compressed.push(0xFF);
                compressed.push(byte);
                compressed.push(run_len);
                i += run_len as usize;
            } else {
                // そのまま
                if byte == 0xFF {
                    compressed.push(0xFF);
                    compressed.push(0xFF);
                    compressed.push(1);
                } else {
                    compressed.push(byte);
                }
                i += 1;
            }
        }
        
        Ok(compressed)
    }
    
    /// ZSTD圧縮（スタブ）
    fn compress_zstd(&self, data: &[u8]) -> Result<Vec<u8>, ZswapError> {
        // 実際のZSTD実装ではなく、LZ4にフォールバック
        self.compress_lz4(data)
    }
    
    /// 展開処理
    fn decompress(&self, data: &[u8], algo: CompressionAlgo, out: &mut [u8]) -> Result<(), ZswapError> {
        match algo {
            CompressionAlgo::Lz4 => self.decompress_lz4(data, out),
            CompressionAlgo::Zstd => self.decompress_zstd(data, out),
            CompressionAlgo::None => {
                out.copy_from_slice(data);
                Ok(())
            }
        }
    }
    
    /// LZ4展開
    fn decompress_lz4(&self, data: &[u8], out: &mut [u8]) -> Result<(), ZswapError> {
        let mut out_idx = 0;
        let mut in_idx = 0;
        
        while in_idx < data.len() && out_idx < out.len() {
            let byte = data[in_idx];
            in_idx += 1;
            
            if byte == 0xFF && in_idx + 1 < data.len() {
                let value = data[in_idx];
                let count = data[in_idx + 1] as usize;
                in_idx += 2;
                
                if value == 0xFF && count == 1 {
                    // エスケープされた0xFF
                    if out_idx < out.len() {
                        out[out_idx] = 0xFF;
                        out_idx += 1;
                    }
                } else {
                    // RLEデコード
                    for _ in 0..count {
                        if out_idx < out.len() {
                            out[out_idx] = value;
                            out_idx += 1;
                        }
                    }
                }
            } else {
                out[out_idx] = byte;
                out_idx += 1;
            }
        }
        
        // 残りをゼロ埋め
        while out_idx < out.len() {
            out[out_idx] = 0;
            out_idx += 1;
        }
        
        Ok(())
    }
    
    /// ZSTD展開
    fn decompress_zstd(&self, data: &[u8], out: &mut [u8]) -> Result<(), ZswapError> {
        self.decompress_lz4(data, out)
    }
    
    /// 同一値ページの検出
    fn detect_same_filled(&self, data: &[u8]) -> Option<u8> {
        if data.is_empty() {
            return None;
        }
        
        let first = data[0];
        if data.iter().all(|&b| b == first) {
            Some(first)
        } else {
            None
        }
    }
    
    /// 同一値ページを格納（1バイトで表現）
    fn store_same_filled(&self, swap_offset: u64, fill_value: u8, original_size: usize) -> Result<(), ZswapError> {
        let entry = ZswapEntry {
            data: vec![fill_value],
            original_size,
            compressed_size: 1,
            algo: CompressionAlgo::None, // 特殊マーカー
            created_tsc: read_tsc(),
            access_count: 0,
        };

        {
            let mut entries = self.entries.write();
            entries.insert(swap_offset, entry);
        }

        self.current_size.fetch_add(1, Ordering::Relaxed);

        let mut stats = self.stats.lock();
        stats.stored_pages += 1;
        stats.orig_data_size += original_size as u64;
        stats.compr_data_size += 1;
        stats.compress_success += 1;
        if original_size == PAGE_SIZE_2M { stats.stored_pages_2m += 1; }
        if original_size == PAGE_SIZE_1G { stats.stored_pages_1g += 1; }

        Ok(())
    }
    
    /// 統計を取得
    pub fn stats(&self) -> ZswapStats {
        self.stats.lock().clone()
    }
    
    /// 現在のプール使用率
    pub fn pool_usage(&self) -> f64 {
        let current = self.current_size.load(Ordering::Relaxed);
        let max = self.max_size.load(Ordering::Relaxed);
        if max == 0 {
            0.0
        } else {
            current as f64 / max as f64
        }
    }
    
    /// 書き戻しが必要か
    pub fn needs_writeback(&self) -> bool {
        let threshold = self.config.read().writeback_threshold;
        self.pool_usage() > threshold
    }
    
    /// LRUで最も古いエントリを取得
    pub fn get_oldest_entries(&self, count: usize) -> Vec<u64> {
        let entries = self.entries.read();
        let mut items: Vec<_> = entries.iter()
            .map(|(&offset, entry)| (offset, entry.created_tsc))
            .collect();
        
        items.sort_by_key(|&(_, tsc)| tsc);
        items.into_iter().take(count).map(|(offset, _)| offset).collect()
    }
    
    /// エントリ数を取得
    pub fn entry_count(&self) -> usize {
        self.entries.read().len()
    }
}

/// TSC読み取り
#[inline]
fn read_tsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// ZSWAPエラー
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZswapError {
    /// 無効
    Disabled,
    /// サイズ不正
    InvalidSize,
    /// 圧縮率が悪い
    PoorCompression,
    /// プール満杯
    PoolFull,
    /// エントリなし
    NotFound,
    /// 圧縮エラー
    CompressionError,
    /// 展開エラー
    DecompressionError,
}

// グローバルプール
static ZSWAP_POOL: Zpool = Zpool::new();

// ============================================================================
// Public API
// ============================================================================

/// ZSWAPを初期化
pub fn init_zswap() {
    ZSWAP_POOL.init();
}

/// ZSWAPが有効か確認
pub fn zswap_is_enabled() -> bool {
    ZSWAP_POOL.is_enabled()
}

/// ZSWAPを有効化/無効化
pub fn zswap_set_enabled(enabled: bool) {
    let mut config = ZSWAP_POOL.config.write();
    config.enabled = enabled;
}

/// 設定を更新
pub fn zswap_update_config(config: ZswapConfig) {
    ZSWAP_POOL.update_config(config);
}

/// ページを格納
pub fn zswap_store(swap_offset: u64, page_data: &[u8]) -> Result<(), ZswapError> {
    ZSWAP_POOL.store(swap_offset, page_data)
}

// Automatic swap-id allocator for callers that don't need a persistent swap offset.
static SWAP_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn zswap_store_auto(page_data: &[u8]) -> Result<u64, ZswapError> {
    let id = SWAP_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    ZSWAP_POOL.store(id, page_data)?;
    Ok(id)
}

/// ページを取得
pub fn zswap_load(swap_offset: u64, out_buffer: &mut [u8]) -> Result<(), ZswapError> {
    ZSWAP_POOL.load(swap_offset, out_buffer)
}

/// エントリを無効化
pub fn zswap_invalidate(swap_offset: u64) -> bool {
    ZSWAP_POOL.invalidate(swap_offset)
}

/// 統計を取得
pub fn zswap_stats() -> ZswapStats {
    ZSWAP_POOL.stats()
}

/// プール使用率を取得
pub fn zswap_pool_usage() -> f64 {
    ZSWAP_POOL.pool_usage()
}

/// 書き戻しが必要か
pub fn zswap_needs_writeback() -> bool {
    ZSWAP_POOL.needs_writeback()
}

/// 最も古いエントリを取得（書き戻し用）
pub fn zswap_get_writeback_candidates(count: usize) -> Vec<u64> {
    ZSWAP_POOL.get_oldest_entries(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test_case]
    fn test_same_filled_detection() {
        let pool = Zpool::new();
        
        let zeros = [0u8; PAGE_SIZE_4K];
        assert_eq!(pool.detect_same_filled(&zeros), Some(0));
        
        let ones = [1u8; PAGE_SIZE_4K];
        assert_eq!(pool.detect_same_filled(&ones), Some(1));
        
        let mut mixed = [0u8; PAGE_SIZE_4K];
        mixed[100] = 1;
        assert_eq!(pool.detect_same_filled(&mixed), None);
    }
    
    #[test_case]
    fn test_compression_ratio() {
        let entry = ZswapEntry {
            data: vec![0; 1000],
            original_size: 4096,
            compressed_size: 1000,
            algo: CompressionAlgo::Lz4,
            created_tsc: 0,
            access_count: 0,
        };
        
        let ratio = entry.compression_ratio();
        assert!(ratio > 0.24 && ratio < 0.25);
    }

    #[test_case]
    fn test_zswap_store_load_2m() {
        // Ensure pool is initialized and sized
        ZSWAP_POOL.init();
        ZSWAP_POOL.update_config(ZswapConfig {
            enabled: true,
            compressor: CompressionAlgo::Lz4,
            max_pool_size: PAGE_SIZE_2M * 4,
            max_compression_ratio: 1.0,
            same_filled_pages_enabled: false,
            writeback_threshold: 0.8,
        });

        // Prepare a 2MiB page
        let data = alloc::vec![0x5u8; PAGE_SIZE_2M];
        let id = zswap_store_auto(&data).expect("store ok");

        let mut out = alloc::vec![0u8; PAGE_SIZE_2M];
        zswap_load(id, &mut out).expect("load ok");
        assert_eq!(out, data);
    }
}


