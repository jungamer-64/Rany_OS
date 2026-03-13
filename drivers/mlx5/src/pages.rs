// ============================================================================
// drivers/mlx5/src/pages.rs - Firmware Page Management
// ============================================================================
//! FW ページ管理 (MANAGE_PAGES)
//!
//! ConnectX ファミリのファームウェアは初期化フェーズで物理ページを要求する。
//! ドライバはこれらのページを割り当てて MANAGE_PAGES コマンドで提供する。
//!
//! ## フロー
//! 1. PAGE_REQUEST EQE を受信
//! 2. QUERY_PAGES で必要ページ数を取得
//! 3. DMA対応ページを割り当て
//! 4. MANAGE_PAGES (give_pages) で提供
//! 5. シャットダウン時に MANAGE_PAGES (reclaim_pages) で回収

extern crate alloc;

use crate::cmd::CmdMailbox;
use crate::defs::MLX5_CMD_MBOX_SIZE;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use kernel_api::dma::{CpuOwned, DmaSlice};

/// ページ管理操作タイプ
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagePagesOp {
    /// ページ提供（FWへ）
    GivePages = 0x01,
    /// ページ回収（FWから）
    ReclaimPages = 0x02,
}

/// FWに提供したページのトラッキング情報
#[derive(Debug, Clone, Copy)]
pub struct PageAllocation {
    /// 物理アドレス
    pub phys_addr: u64,
    /// 仮想アドレス（解放時に使用）
    pub virt_addr: u64,
    /// 関数ID
    pub function_id: u16,
}

/// ページマネージャ
///
/// FWに提供したページの追跡と回収を行う。
pub struct PageManager {
    /// 提供済みページの一覧
    allocated_pages: Vec<PageAllocation>,
    /// 既知ページの高速インデックス
    allocated_page_index: BTreeSet<u64>,
    /// ドライバが追加確保した FW ページの所有権
    owned_pages: Vec<OwnedPageBuffer>,
    /// 合計提供ページ数
    total_given: u32,
}

struct OwnedPageBuffer {
    dma_addr: u64,
    _buffer: DmaSlice<CpuOwned>,
}

// SAFETY: OwnedPageBuffer keeps exclusive ownership of the DMA buffer inside the
// mlx5 driver's internal state. Safe APIs never hand out shared references to
// the underlying memory, so sharing the holder across threads is acceptable.
unsafe impl Sync for OwnedPageBuffer {}

impl PageManager {
    /// 新しいページマネージャを作成
    pub fn new() -> Self {
        Self {
            allocated_pages: Vec::new(),
            allocated_page_index: BTreeSet::new(),
            owned_pages: Vec::new(),
            total_given: 0,
        }
    }

    /// 提供済みページ数を取得
    pub fn total_given_pages(&self) -> u32 {
        self.total_given
    }

    /// ページ割り当て記録を追加
    pub fn record_allocation(&mut self, alloc: PageAllocation) {
        if !self.allocated_page_index.insert(alloc.phys_addr) {
            return;
        }
        self.allocated_pages.push(alloc);
        self.total_given = self.allocated_pages.len() as u32;
    }

    /// ドライバが追加確保した DMA ページを記録し、所有権を保持する。
    pub fn record_owned_dma_page(&mut self, buffer: DmaSlice<CpuOwned>, function_id: u16) -> u64 {
        let dma_addr = buffer.device_address();
        let virt_addr = buffer.as_ptr() as u64;
        self.record_allocation(PageAllocation {
            phys_addr: dma_addr,
            virt_addr,
            function_id,
        });
        self.owned_pages.push(OwnedPageBuffer {
            dma_addr,
            _buffer: buffer,
        });
        dma_addr
    }

    /// 指定関数IDに関連するページを回収用にリストアップ
    pub fn pages_for_function(&self, function_id: u16) -> Vec<u64> {
        self.allocated_pages
            .iter()
            .filter(|p| p.function_id == function_id)
            .map(|p| p.phys_addr)
            .collect()
    }

    /// 回収されたページを記録から削除
    pub fn remove_pages(&mut self, phys_addrs: &[u64]) {
        for &phys in phys_addrs {
            self.allocated_page_index.remove(&phys);
        }
        self.allocated_pages
            .retain(|p| !phys_addrs.contains(&p.phys_addr));
        self.owned_pages
            .retain(|page| !phys_addrs.contains(&page.dma_addr));
        self.total_given = self.allocated_pages.len() as u32;
    }

    /// 全ページのリスト（シャットダウン時の一括解放用）
    pub fn all_pages(&self) -> &[PageAllocation] {
        &self.allocated_pages
    }
}

impl Default for PageManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Command Helpers for Page Management
// ============================================================================

// These have been moved to crate::cmd::hca

/// FWページ要求に対応するページ数の上限
///
/// メールボックスサイズの制約によって1回のMANAGE_PAGESで送れるPA数が制限される。
/// PA開始オフセット = 0x10, 各PA = 8バイト → (512 - 16) / 8 = 62 エントリ/メールボックス
pub const MAX_PAS_PER_MBOX: usize = (MLX5_CMD_MBOX_SIZE - 0x10) / 8;

/// ページアドレスリストをメールボックスに格納
///
/// 62エントリ/メールボックスの制限を超える場合はバッチ発行が必要。
pub fn fill_manage_pages_pas(in_mbox: &mut CmdMailbox, pas: &[u64], batch_offset: usize) {
    for (i, &pa) in pas.iter().enumerate() {
        let off = 0x10 + (batch_offset + i) * 8;
        if off + 8 <= MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be64(off, pa);
        }
    }
}

/// MANAGE_PAGES (reclaim) 出力からPAリストを解析
pub fn parse_reclaim_pages_output(out_mbox: &CmdMailbox, num_pages: u32) -> Vec<u64> {
    let mut pas = Vec::new();
    for i in 0..num_pages as usize {
        let off = 0x10 + i * 8;
        if off + 8 <= MLX5_CMD_MBOX_SIZE {
            pas.push(out_mbox.read_be64(off));
        }
    }
    pas
}
