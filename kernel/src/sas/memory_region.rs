// ============================================================================
// src/sas/memory_region.rs - メモリ領域管理
// ============================================================================
#![allow(dead_code)]

use bitflags::bitflags;

/// メモリ領域
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// 開始アドレス
    pub start: usize,
    /// サイズ
    pub size: usize,
    /// パーミッション
    pub permissions: RegionPermissions,
}

impl MemoryRegion {
    /// 新しいメモリ領域を作成
    pub const fn new(start: usize, size: usize, permissions: RegionPermissions) -> Self {
        Self {
            start,
            size,
            permissions,
        }
    }

    /// 終端アドレスを取得
    pub const fn end(&self) -> usize {
        self.start + self.size
    }

    /// アドレスが領域内かチェック
    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.start && addr < self.end()
    }

    /// 範囲が領域内かチェック
    pub fn contains_range(&self, start: usize, size: usize) -> bool {
        start >= self.start && start + size <= self.end()
    }

    /// 領域が重なるかチェック
    pub fn overlaps(&self, other: &MemoryRegion) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

bitflags! {
    /// 領域パーミッション
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct RegionPermissions: u32 {
        /// 読み取り可能
        const READ = 1 << 0;
        /// 書き込み可能
        const WRITE = 1 << 1;
        /// 実行可能
        const EXECUTE = 1 << 2;
        /// ユーザーアクセス可能
        const USER = 1 << 3;
        /// 共有領域
        const SHARED = 1 << 4;
        /// DMA対象領域
        const DMA = 1 << 5;

        /// 読み書き
        const RW = Self::READ.bits() | Self::WRITE.bits();
        /// 読み取り実行
        const RX = Self::READ.bits() | Self::EXECUTE.bits();
        /// 全権限
        const RWX = Self::READ.bits() | Self::WRITE.bits() | Self::EXECUTE.bits();
        /// カーネル領域
        const KERNEL = Self::RWX.bits();
        /// ユーザーデータ
        const USER_DATA = Self::RW.bits() | Self::USER.bits();
        /// ユーザーコード
        const USER_CODE = Self::RX.bits() | Self::USER.bits();
    }
}

impl Default for RegionPermissions {
    fn default() -> Self {
        Self::READ
    }
}
