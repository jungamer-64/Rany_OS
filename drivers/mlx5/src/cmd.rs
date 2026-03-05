// ============================================================================
// drivers/mlx5/src/cmd.rs - Command Interface
// ============================================================================
//! mlx5 コマンドインタフェース
//!
//! HCAファームウェアとのメールボックスベースのコマンド送受信。
//! コマンドキュー(CMDQ)を通じて初期化コマンドやリソース作成コマンドを発行する。

use crate::defs::{CmdOpcode, CmdStatus, MLX5_CMD_MBOX_SIZE};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::regs::cmd_entry;

/// コマンドメールボックス (512 bytes aligned)
///
/// 入出力データを格納するバッファ。物理的に連続したDMAメモリ上に配置される。
#[repr(C, align(4096))]
pub struct CmdMailbox {
    /// メールボックスデータ
    pub data: [u8; MLX5_CMD_MBOX_SIZE],
}

impl CmdMailbox {
    /// ゼロ初期化されたメールボックスを作成
    pub const fn zeroed() -> Self {
        Self {
            data: [0u8; MLX5_CMD_MBOX_SIZE],
        }
    }

    /// 指定オフセットにu32を書き込む（ビッグエンディアン）
    pub fn write_be32(&mut self, offset: usize, value: u32) {
        let bytes = value.to_be_bytes();
        self.data[offset..offset + 4].copy_from_slice(&bytes);
    }

    /// 指定オフセットからu32を読み取る（ビッグエンディアン）
    pub fn read_be32(&self, offset: usize) -> u32 {
        let bytes: [u8; 4] = [
            self.data[offset],
            self.data[offset + 1],
            self.data[offset + 2],
            self.data[offset + 3],
        ];
        u32::from_be_bytes(bytes)
    }

    /// 指定オフセットにu16を書き込む（ビッグエンディアン）
    pub fn write_be16(&mut self, offset: usize, value: u16) {
        let bytes = value.to_be_bytes();
        self.data[offset..offset + 2].copy_from_slice(&bytes);
    }

    /// 指定オフセットからu16を読み取る（ビッグエンディアン）
    pub fn read_be16(&self, offset: usize) -> u16 {
        let bytes: [u8; 2] = [self.data[offset], self.data[offset + 1]];
        u16::from_be_bytes(bytes)
    }

    /// 指定オフセットにu64を書き込む（ビッグエンディアン）
    pub fn write_be64(&mut self, offset: usize, value: u64) {
        let bytes = value.to_be_bytes();
        self.data[offset..offset + 8].copy_from_slice(&bytes);
    }

    /// 指定オフセットからu64を読み取る（ビッグエンディアン）
    pub fn read_be64(&self, offset: usize) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.data[offset..offset + 8]);
        u64::from_be_bytes(bytes)
    }
}

// ============================================================================
// Command Entry (in command queue)
// ============================================================================

/// コマンドキューエントリ (64 bytes)
///
/// コマンドキューの各スロットに配置される。
/// メールボックスポインタを通じて入出力データを参照する。
#[repr(C, align(64))]
pub struct CmdEntry {
    pub raw: [u8; cmd_entry::ENTRY_SIZE],
}

impl CmdEntry {
    /// ゼロ初期化エントリ
    pub const fn zeroed() -> Self {
        Self {
            raw: [0u8; cmd_entry::ENTRY_SIZE],
        }
    }

    /// 入力メールボックス物理アドレスを設定
    pub fn set_input_mailbox(&mut self, phys_addr: u64) {
        let h = (phys_addr >> 32) as u32;
        let l = phys_addr as u32;
        self.write_be32(cmd_entry::IN_MBOX_PTR_H, h);
        self.write_be32(cmd_entry::IN_MBOX_PTR_L, l);
    }

    /// 出力メールボックス物理アドレスを設定
    pub fn set_output_mailbox(&mut self, phys_addr: u64) {
        let h = (phys_addr >> 32) as u32;
        let l = phys_addr as u32;
        self.write_be32(cmd_entry::OUT_MBOX_PTR_H, h);
        self.write_be32(cmd_entry::OUT_MBOX_PTR_L, l);
    }

    /// 入力データ長を設定
    pub fn set_input_length(&mut self, len: u32) {
        self.write_be32(cmd_entry::IN_LENGTH, len);
    }

    /// 出力データ長を設定
    pub fn set_output_length(&mut self, len: u32) {
        self.write_be32(cmd_entry::OUT_LENGTH, len);
    }

    /// オペコードとトークンを設定してオーナービットをHWに引き渡す
    pub fn submit(&mut self, opcode: CmdOpcode, token: u8) {
        // TOKEN_SIG: byte layout = [token, signature, rsvd, rsvd]
        self.write_be32(cmd_entry::TOKEN_SIG, (token as u32) << 24);

        // STATUS_OWN: bit0 = owner (1=HW), bits[23:8] = opcode
        let val = ((opcode as u32) << 8) | 0x01; // owner=HW
        self.write_be32(cmd_entry::STATUS_OWN, val);
    }

    /// オーナービットをチェック（0=SW=完了, 1=HW=進行中）
    pub fn is_owned_by_hw(&self) -> bool {
        let val = self.read_be32(cmd_entry::STATUS_OWN);
        (val & 0x01) != 0
    }

    /// ステータスを取得
    pub fn status(&self) -> CmdStatus {
        let val = self.read_be32(cmd_entry::STATUS_OWN);
        CmdStatus::from_u8(((val >> 24) & 0xFF) as u8)
    }

    fn write_be32(&mut self, offset: usize, value: u32) {
        let bytes = value.to_be_bytes();
        self.raw[offset..offset + 4].copy_from_slice(&bytes);
    }

    fn read_be32(&self, offset: usize) -> u32 {
        let bytes: [u8; 4] = [
            self.raw[offset],
            self.raw[offset + 1],
            self.raw[offset + 2],
            self.raw[offset + 3],
        ];
        u32::from_be_bytes(bytes)
    }
}

// ============================================================================
// Command Interface Abstraction
// ============================================================================

/// コマンドインタフェース
///
/// コマンドキューのベースアドレスとログサイズを保持し、
/// コマンドの発行とポーリング完了を管理する。
pub struct CmdInterface {
    /// コマンドキューDMA物理アドレス
    cmdq_phys: u64,
    /// コマンドキューの仮想アドレス（MMIOマップ済み）
    cmdq_virt: u64,
    /// ログ2コマンドキューサイズ（エントリ数）
    log_cmdq_size: u8,
    /// BAR0ベース仮想アドレス
    bar0_base: u64,
    /// 次のトークン値
    next_token: u8,
}

impl CmdInterface {
    /// コマンドインタフェースを作成
    ///
    /// # Arguments
    /// - `bar0_base`: BAR0ベース仮想アドレス
    /// - `cmdq_phys`: コマンドキューDMA物理アドレス
    /// - `cmdq_virt`: コマンドキュー仮想アドレス
    /// - `log_cmdq_size`: ログ2キューサイズ
    pub fn new(bar0_base: u64, cmdq_phys: u64, cmdq_virt: u64, log_cmdq_size: u8) -> Self {
        Self {
            cmdq_phys,
            cmdq_virt,
            log_cmdq_size,
            bar0_base,
            next_token: 1,
        }
    }

    /// コマンドキューのエントリ数
    pub fn queue_size(&self) -> usize {
        1 << self.log_cmdq_size
    }

    /// 指定スロットのエントリへの可変参照を返す
    ///
    /// # Safety
    /// - `slot < queue_size()` であること
    /// - cmdq_virt が有効なマッピングであること
    unsafe fn entry_mut(&self, slot: usize) -> &mut CmdEntry {
        let ptr = (self.cmdq_virt as usize + slot * cmd_entry::ENTRY_SIZE) as *mut CmdEntry;
        &mut *ptr
    }

    /// 指定スロットのエントリへの参照を返す
    ///
    /// # Safety
    /// - `slot < queue_size()` であること
    unsafe fn entry(&self, slot: usize) -> &CmdEntry {
        let ptr = (self.cmdq_virt as usize + slot * cmd_entry::ENTRY_SIZE) as *const CmdEntry;
        &*ptr
    }

    /// コマンドキューの物理アドレスとログサイズをBAR0に書き込む
    ///
    /// # Safety
    /// - bar0_base が有効なMMIOマッピングであること
    pub unsafe fn setup_cmdq_in_bar0(&self) {
        use crate::regs::init_seg;

        let addr_h = (self.cmdq_phys >> 32) as u32;
        let addr_l_sz = ((self.cmdq_phys & 0xFFFF_F000) as u32) | (self.log_cmdq_size as u32);

        hal::mmio::mmio_write_u32(self.bar0_base as usize + init_seg::CMDQ_ADDR_H, addr_h);
        hal::mmio::mmio_write_u32(
            self.bar0_base as usize + init_seg::CMDQ_ADDR_L_SZ,
            addr_l_sz,
        );
    }

    /// コマンドドアベルをリングする
    ///
    /// # Safety
    /// - bar0_base が有効なMMIOマッピングであること
    pub unsafe fn ring_doorbell(&self) {
        use crate::regs::init_seg;
        hal::mmio::mmio_write_u32(self.bar0_base as usize + init_seg::CMDQ_DOORBELL, 0x01);
    }

    /// コマンドを同期的に発行して完了を待つ
    ///
    /// # Arguments
    /// - `opcode`: コマンドオペコード
    /// - `in_mbox_phys`: 入力メールボックス物理アドレス（0ならメールボックスなし）
    /// - `in_len`: 入力データ長
    /// - `out_mbox_phys`: 出力メールボックス物理アドレス
    /// - `out_len`: 出力データ長
    ///
    /// # Safety
    /// - メールボックスポインタが有効なDMAメモリであること
    pub unsafe fn execute(
        &mut self,
        opcode: CmdOpcode,
        in_mbox_phys: u64,
        in_len: u32,
        out_mbox_phys: u64,
        out_len: u32,
    ) -> Mlx5Result<()> {
        // スロット0を使用（シンプルな同期実行）
        let slot = 0;

        // トークン発行
        let token = self.next_token;
        self.next_token = self.next_token.wrapping_add(1);
        if self.next_token == 0 {
            self.next_token = 1;
        }

        let entry = self.entry_mut(slot);
        *entry = CmdEntry::zeroed();

        // メールボックスアドレス設定
        if in_mbox_phys != 0 {
            entry.set_input_mailbox(in_mbox_phys);
        }
        entry.set_input_length(in_len);

        if out_mbox_phys != 0 {
            entry.set_output_mailbox(out_mbox_phys);
        }
        entry.set_output_length(out_len);

        // オーナービットをHWに引き渡し
        entry.submit(opcode, token);

        // ドアベルリング
        self.ring_doorbell();

        // ポーリングで完了を待つ（タイムアウト付き）
        self.poll_completion(slot)
    }

    /// ポーリングでコマンド完了を待つ
    ///
    /// # Safety
    /// - cmdq_virt が有効であること
    unsafe fn poll_completion(&self, slot: usize) -> Mlx5Result<()> {
        // 簡易ポーリング: spin待ち
        // 実プロダクション環境ではタイマーベースのタイムアウトを使用
        let max_iters = 10_000_000u64;

        for _ in 0..max_iters {
            let entry = self.entry(slot);
            if !entry.is_owned_by_hw() {
                // 完了チェック
                let status = entry.status();
                if status == CmdStatus::Ok {
                    return Ok(());
                } else {
                    return Err(Mlx5Error::CommandFailed(status as u8));
                }
            }
            // ビジーウェイト（短いスピン）
            core::hint::spin_loop();
        }

        Err(Mlx5Error::CommandTimeout)
    }
}

// ============================================================================
// High-Level Command Helpers
// ============================================================================

/// QUERY_ISSI コマンド出力の解析
pub fn parse_query_issi(out_mbox: &CmdMailbox) -> u32 {
    // Current ISSI version (offset 0x00 in output)
    out_mbox.read_be32(0x00)
}

/// ENABLE_HCA コマンド入力の構築
pub fn build_enable_hca_input(in_mbox: &mut CmdMailbox, function_id: u16) {
    *in_mbox = CmdMailbox::zeroed();
    // function_id at offset 0x04 (bits 31:16)
    in_mbox.write_be32(0x04, (function_id as u32) << 16);
}

/// QUERY_HCA_CAP コマンド入力の構築
///
/// `cap_type`: キャパビリティタイプ
///   0x0 = General Capabilities
///   0x1 = Ethernet Offloads
///   0x2 = Atomic Capabilities
pub fn build_query_hca_cap_input(in_mbox: &mut CmdMailbox, cap_type: u16) {
    *in_mbox = CmdMailbox::zeroed();
    // opcode modifier contains cap_type
    in_mbox.write_be16(0x02, cap_type);
}

/// INIT_HCA コマンド入力の構築
pub fn build_init_hca_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
    // INIT_HCA は基本パラメータなし
}

/// NOP コマンド入力の構築
pub fn build_nop_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
}

/// TEARDOWN_HCA コマンド入力の構築
///
/// `graceful`: trueならグレースフル停止
pub fn build_teardown_hca_input(in_mbox: &mut CmdMailbox, graceful: bool) {
    *in_mbox = CmdMailbox::zeroed();
    // profile: 0x0 = graceful, 0x1 = force
    let profile: u16 = if graceful { 0x0 } else { 0x1 };
    in_mbox.write_be16(0x02, profile);
}

/// MANAGE_PAGES コマンド入力の構築
///
/// `op`: 0x01 = give pages, 0x02 = reclaim pages
/// `function_id`: 対象関数ID
/// `num_pages`: ページ数
/// `pas`: 物理アドレスリスト
pub fn build_manage_pages_input(
    in_mbox: &mut CmdMailbox,
    op: u8,
    function_id: u16,
    num_pages: u32,
    pas: &[u64],
) {
    *in_mbox = CmdMailbox::zeroed();
    // op at offset 0x00 bits[27:24]
    in_mbox.write_be32(0x00, (op as u32) << 24);
    // function_id at offset 0x04
    in_mbox.write_be32(0x04, (function_id as u32) << 16);
    // num_pages at offset 0x08
    in_mbox.write_be32(0x08, num_pages);
    // PAs start at offset 0x10, each 8 bytes
    for (i, &pa) in pas.iter().enumerate() {
        let off = 0x10 + i * 8;
        if off + 8 <= MLX5_CMD_MBOX_SIZE {
            in_mbox.write_be64(off, pa);
        }
    }
}

/// CREATE_EQ コマンド入力の構築
pub fn build_create_eq_input(
    in_mbox: &mut CmdMailbox,
    log_eq_size: u8,
    eqc_pa: u64,
    uar_page: u32,
    event_bitmask: u64,
) {
    *in_mbox = CmdMailbox::zeroed();
    // EQ Context (EQC) at offset 0x10
    // log_eq_size at EQC offset 0x00 bits[4:0]
    let eqc_base = 0x10;
    in_mbox.write_be32(eqc_base, log_eq_size as u32);
    // UAR page at EQC offset 0x08
    in_mbox.write_be32(eqc_base + 0x08, uar_page);
    // Page address at EQC offset 0x20
    in_mbox.write_be64(eqc_base + 0x20, eqc_pa);
    // Event bitmask at offset 0x0C
    in_mbox.write_be64(0x0C, event_bitmask);
}

/// QUERY_NIC_VPORT_CONTEXT コマンド入力の構築
pub fn build_query_nic_vport_input(in_mbox: &mut CmdMailbox, vport_number: u16) {
    *in_mbox = CmdMailbox::zeroed();
    // Other vport bit at offset 0x00 bit 16, vport_number at offset 0x04
    in_mbox.write_be16(0x04, vport_number);
}

/// QUERY_NIC_VPORT_CONTEXT 出力からMACアドレスを取得
pub fn parse_vport_mac(out_mbox: &CmdMailbox) -> [u8; 6] {
    // MAC is at vport context offset 0x70-0x75 in output (8-byte field, upper 2 reserved)
    let mac_h = out_mbox.read_be16(0x70 + 0x10); // 上位2バイト
    let mac_l = out_mbox.read_be32(0x72 + 0x10); // 下位4バイト
    [
        (mac_h >> 8) as u8,
        mac_h as u8,
        (mac_l >> 24) as u8,
        (mac_l >> 16) as u8,
        (mac_l >> 8) as u8,
        mac_l as u8,
    ]
}
