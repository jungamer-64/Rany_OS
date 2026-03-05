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
use alloc::vec::Vec;

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
    /// 合計提供ページ数
    total_given: u32,
}

impl PageManager {
    /// 新しいページマネージャを作成
    pub fn new() -> Self {
        Self {
            allocated_pages: Vec::new(),
            total_given: 0,
        }
    }

    /// 提供済みページ数を取得
    pub fn total_given_pages(&self) -> u32 {
        self.total_given
    }

    /// ページ割り当て記録を追加
    pub fn record_allocation(&mut self, alloc: PageAllocation) {
        self.allocated_pages.push(alloc);
        self.total_given += 1;
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
        self.allocated_pages
            .retain(|p| !phys_addrs.contains(&p.phys_addr));
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

/// QUERY_PAGES 出力の解析
///
/// # Returns
/// (function_id, num_pages) — 要求元の関数IDと必要ページ数
pub fn parse_query_pages_output(out_mbox: &CmdMailbox) -> (u16, i32) {
    let func_id = out_mbox.read_be16(0x04);
    let num_pages = out_mbox.read_be32(0x0C) as i32;
    (func_id, num_pages)
}

/// QUERY_PAGES コマンド入力の構築
///
/// `op_mod`: 0x01 = boot pages, 0x02 = init pages, 0x03 = regular pages
pub fn build_query_pages_input(in_mbox: &mut CmdMailbox, op_mod: u16) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be16(0x02, op_mod);
}

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
