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
use core::sync::atomic::{fence, Ordering};

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

    /// 指定オフセットから24bit値を読み取る（ビッグエンディアン）
    pub fn read_be24(&self, offset: usize) -> u32 {
        ((self.data[offset] as u32) << 16)
            | ((self.data[offset + 1] as u32) << 8)
            | (self.data[offset + 2] as u32)
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
    const PCI_CMD_XPORT: u8 = 7;

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

    /// 入力インライン領域（16 bytes）を設定
    pub fn set_input_inline(&mut self, first_16: &[u8]) {
        let mut buf = [0u8; 16];
        let copy_len = first_16.len().min(16);
        buf[..copy_len].copy_from_slice(&first_16[..copy_len]);
        self.raw[cmd_entry::IN_INLINE..cmd_entry::IN_INLINE + 16].copy_from_slice(&buf);
    }

    /// 出力インライン領域（16 bytes）を取得
    pub fn output_inline(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.raw[cmd_entry::OUT_INLINE..cmd_entry::OUT_INLINE + 16]);
        out
    }

    /// トークンを設定
    pub fn set_token(&mut self, token: u8) {
        self.raw[cmd_entry::TOKEN] = token;
    }

    /// 記述子シグネチャを更新
    pub fn update_signature(&mut self) {
        self.raw[cmd_entry::SIG] = 0;
        let mut sum = 0u8;
        for b in &self.raw {
            sum ^= *b;
        }
        self.raw[cmd_entry::SIG] = !sum;
    }

    /// 記述子タイプ/トークンを設定してオーナービットをHWに引き渡す
    pub fn submit(&mut self, token: u8) {
        self.raw[cmd_entry::TYPE] = Self::PCI_CMD_XPORT;
        self.set_token(token);
        self.raw[cmd_entry::STATUS_OWN] = 0x01; // owner=HW
        self.update_signature();
    }

    /// オーナービットをチェック（0=SW=完了, 1=HW=進行中）
    pub fn is_owned_by_hw(&self) -> bool {
        (self.raw[cmd_entry::STATUS_OWN] & 0x01) != 0
    }

    /// ステータスを取得
    pub fn status(&self) -> CmdStatus {
        CmdStatus::from_u8(self.raw[cmd_entry::STATUS_OWN] >> 1)
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

/// コマンド転送抽象（CMDQ, 将来の別経路対応）
pub trait CommandTransport {
    /// コマンドを同期的に発行して完了を待つ
    ///
    /// # Safety
    /// - メールボックスポインタが有効なDMAメモリであること
    unsafe fn execute(
        &mut self,
        opcode: CmdOpcode,
        in_mbox_phys: u64,
        in_len: u32,
        out_mbox_phys: u64,
        out_len: u32,
    ) -> Mlx5Result<()>;

    /// コマンドヘッダに設定するUIDを更新する
    fn set_uid(&mut self, _uid: u16) {}

    /// 現在のコマンドUIDを取得する
    fn uid(&self) -> u16 {
        0
    }
}

/// CMDQベースのコマンドインタフェース
///
/// コマンドキューのベースアドレスとログサイズを保持し、
/// コマンドの発行とポーリング完了を管理する。
pub struct CmdQueueTransport {
    /// コマンドキューDMA物理アドレス
    cmdq_phys: u64,
    /// コマンドキューの仮想アドレス（MMIOマップ済み）
    cmdq_virt: u64,
    /// ログ2コマンドキューサイズ（エントリ数）
    log_cmdq_size: u8,
    /// ログ2コマンドエントリstride（bytes）
    log_cmd_stride: u8,
    /// BAR0ベース仮想アドレス
    bar0_base: u64,
    /// コマンド入力メールボックス仮想アドレス（4KB DMAスロット先頭）
    in_mbox_virt: u64,
    /// コマンド出力メールボックス仮想アドレス（4KB DMAスロット先頭）
    out_mbox_virt: u64,
    /// 次のトークン値
    next_token: u8,
    /// コマンド入力ヘッダ UID (mlx5_ifc command_in.uid)
    uid: u16,
}

#[repr(C)]
struct CmdProtBlock {
    data: [u8; MLX5_CMD_MBOX_SIZE],
    rsvd0: [u8; 48],
    next: u64,
    block_num: u32,
    rsvd1: u8,
    token: u8,
    ctrl_sig: u8,
    sig: u8,
}

impl CmdQueueTransport {
    /// ハードウェアが公開する `cmdq_addr_l_sz` から CMDQ パラメータを抽出
    pub fn parse_hw_cmdq_layout(cmdq_addr_l_sz: u32) -> (u8, u8, bool) {
        let low = cmdq_addr_l_sz & 0xFF;
        let log_cmdq_size = ((low >> 4) & 0x0F) as u8;
        let log_cmd_stride = (low & 0x0F) as u8;
        let nic_if_supported =
            (cmdq_addr_l_sz & crate::regs::fw_state::NIC_INTERFACE_SUPPORTED_BIT) != 0;
        (log_cmdq_size, log_cmd_stride, nic_if_supported)
    }

    fn validate_hw_cmdq_layout(log_cmdq_size: u8, log_cmd_stride: u8) -> Mlx5Result<()> {
        if log_cmdq_size == 0 {
            return Err(Mlx5Error::NotSupported);
        }
        let entry_size = 1usize
            .checked_shl(log_cmd_stride as u32)
            .ok_or(Mlx5Error::NotSupported)?;
        if entry_size != cmd_entry::ENTRY_SIZE {
            return Err(Mlx5Error::NotSupported);
        }
        Ok(())
    }

    /// CMDQ転送インタフェースを作成
    ///
    /// # Arguments
    /// - `bar0_base`: BAR0ベース仮想アドレス
    /// - `cmdq_phys`: コマンドキューDMA物理アドレス
    /// - `cmdq_virt`: コマンドキュー仮想アドレス
    /// - `log_cmdq_size`: ログ2キューサイズ
    /// - `log_cmd_stride`: ログ2エントリstride
    pub fn new(
        bar0_base: u64,
        cmdq_phys: u64,
        cmdq_virt: u64,
        in_mbox_virt: u64,
        out_mbox_virt: u64,
        log_cmdq_size: u8,
        log_cmd_stride: u8,
    ) -> Mlx5Result<Self> {
        Self::validate_hw_cmdq_layout(log_cmdq_size, log_cmd_stride)?;
        Ok(Self {
            cmdq_phys,
            cmdq_virt,
            log_cmdq_size,
            log_cmd_stride,
            bar0_base,
            in_mbox_virt,
            out_mbox_virt,
            next_token: 1,
            uid: 0,
        })
    }

    /// コマンドヘッダ UID を設定
    pub fn set_uid(&mut self, uid: u16) {
        self.uid = uid;
    }

    /// コマンドヘッダ UID を取得
    pub fn uid(&self) -> u16 {
        self.uid
    }

    fn xor8(buf: &[u8]) -> u8 {
        let mut sum = 0u8;
        for b in buf {
            sum ^= *b;
        }
        sum
    }

    unsafe fn prepare_in_block(&self, token: u8, in_len: usize) -> [u8; 16] {
        let block = &mut *(self.in_mbox_virt as *mut CmdProtBlock);
        let mut in_inline = [0u8; 16];
        let inline_len = in_len.min(16);
        in_inline[..inline_len].copy_from_slice(&block.data[..inline_len]);

        if in_len > 16 {
            let payload_len = (in_len - 16).min(MLX5_CMD_MBOX_SIZE);
            let mut tmp = [0u8; MLX5_CMD_MBOX_SIZE];
            tmp[..payload_len].copy_from_slice(&block.data[16..16 + payload_len]);
            block.data.fill(0);
            block.data[..payload_len].copy_from_slice(&tmp[..payload_len]);
        } else {
            block.data.fill(0);
        }

        block.rsvd0 = [0u8; 48];
        block.next = 0;
        block.block_num = 0;
        block.rsvd1 = 0;
        block.token = token;
        block.ctrl_sig = 0;
        block.sig = 0;

        let raw = core::slice::from_raw_parts_mut(block as *mut CmdProtBlock as *mut u8, 576);
        // ctrl_sig: XOR over trailer area excluding ctrl_sig/sig.
        let ctrl_xor = Self::xor8(&raw[512..574]);
        block.ctrl_sig = !ctrl_xor;
        raw[574] = block.ctrl_sig;
        // sig: XOR over entire block excluding sig itself.
        let sig_xor = Self::xor8(&raw[..575]);
        block.sig = !sig_xor;

        in_inline
    }

    unsafe fn prepare_out_block(&self, token: u8) {
        let block = &mut *(self.out_mbox_virt as *mut CmdProtBlock);
        block.data.fill(0);
        block.rsvd0 = [0u8; 48];
        block.next = 0;
        block.block_num = 0;
        block.rsvd1 = 0;
        block.token = token;
        block.ctrl_sig = 0;
        block.sig = 0;

        let raw = core::slice::from_raw_parts_mut(block as *mut CmdProtBlock as *mut u8, 576);
        let ctrl_xor = Self::xor8(&raw[512..574]);
        block.ctrl_sig = !ctrl_xor;
        raw[574] = block.ctrl_sig;
        let sig_xor = Self::xor8(&raw[..575]);
        block.sig = !sig_xor;
    }

    unsafe fn collect_out_data(&self, out_len: usize, inline_out: [u8; 16]) {
        let block = &mut *(self.out_mbox_virt as *mut CmdProtBlock);
        if out_len > 16 {
            let payload_len = (out_len - 16).min(MLX5_CMD_MBOX_SIZE);
            let mut tmp = [0u8; MLX5_CMD_MBOX_SIZE];
            tmp[..payload_len].copy_from_slice(&block.data[..payload_len]);
            let inline_len = out_len.min(16);
            block.data[..inline_len].copy_from_slice(&inline_out[..inline_len]);
            block.data[16..16 + payload_len].copy_from_slice(&tmp[..payload_len]);
        } else {
            let inline_len = out_len.min(16);
            block.data[..inline_len].copy_from_slice(&inline_out[..inline_len]);
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
        let layout_low =
            (((self.log_cmdq_size as u32) & 0x0F) << 4) | ((self.log_cmd_stride as u32) & 0x0F);
        let addr_l_sz = ((self.cmdq_phys & 0xFFFF_F000) as u32) | layout_low;

        crate::mmio_write_be32(self.bar0_base as usize + init_seg::CMDQ_ADDR_H, addr_h);
        crate::mmio_write_be32(
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
        crate::mmio_write_be32(self.bar0_base as usize + init_seg::CMDQ_DOORBELL, 0x01);
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

        let in_len_usize = in_len as usize;
        let out_len_usize = out_len as usize;

        let in_mbox = &mut *(self.in_mbox_virt as *mut CmdMailbox);
        // opcode[15:0] is at command input offset 0x00.
        in_mbox.write_be16(0x00, opcode as u16);
        // uid[15:0] is at command input offset 0x02.
        in_mbox.write_be16(0x02, self.uid);
        let in_inline = self.prepare_in_block(token, in_len_usize);
        if out_len_usize > 16 {
            self.prepare_out_block(token);
        }

        let entry = self.entry_mut(slot);
        *entry = CmdEntry::zeroed();
        entry.set_input_inline(&in_inline);

        // メールボックスアドレス設定
        if in_mbox_phys != 0 && in_len_usize > 16 {
            entry.set_input_mailbox(in_mbox_phys);
        }
        entry.set_input_length(in_len);

        if out_mbox_phys != 0 && out_len_usize > 16 {
            entry.set_output_mailbox(out_mbox_phys);
        }
        entry.set_output_length(out_len);

        // オーナービットをHWに引き渡し
        entry.submit(token);

        // ドアベルリング
        self.ring_doorbell();

        // ポーリングで完了を待つ（タイムアウト付き）
        match self.poll_completion(slot) {
            Ok(()) => {
                // Ensure DMA/descriptor writes are visible after ownership handoff.
                fence(Ordering::Acquire);
                let completed = self.entry(slot);
                self.collect_out_data(out_len_usize, completed.output_inline());

                if out_len_usize > 0 {
                    let out_mbox = &*(self.out_mbox_virt as *const CmdMailbox);
                    let fw_status = out_mbox.data[0];
                    if fw_status != 0 {
                        let syndrome = if out_len_usize >= 8 {
                            out_mbox.read_be32(0x04)
                        } else {
                            0
                        };
                        log::error!(
                            target: "mlx5",
                            "CMD {:?} FW status error: status={:#x} syndrome={:#x}",
                            opcode,
                            fw_status,
                            syndrome
                        );
                        return Err(Mlx5Error::CommandFailed(fw_status));
                    }
                }
                Ok(())
            }
            Err(err) => {
                log::error!(
                    target: "mlx5",
                    "CMD {:?} failed: {:?} (token={} in_iova={:#x} out_iova={:#x})",
                    opcode,
                    err,
                    token,
                    in_mbox_phys,
                    out_mbox_phys
                );
                Err(err)
            }
        }
    }

    /// ポーリングでコマンド完了を待つ
    ///
    /// # Safety
    /// - cmdq_virt が有効であること
    unsafe fn poll_completion(&self, slot: usize) -> Mlx5Result<()> {
        // 簡易ポーリング: spin待ち
        // 実プロダクション環境ではタイマーベースのタイムアウトを使用
        // IMPORTANT:
        //   This path may run on the kernel async executor thread.
        //   Keep timeout bounded, but allow enough budget for VF + vIOMMU paths where
        //   command completion latency is noticeably higher than pure PF bring-up.
        // VF + vIOMMU 環境では完了までの待ちが長引くため、十分な上限を確保する。
        let max_iters = 200_000_000u64;

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

impl CommandTransport for CmdQueueTransport {
    unsafe fn execute(
        &mut self,
        opcode: CmdOpcode,
        in_mbox_phys: u64,
        in_len: u32,
        out_mbox_phys: u64,
        out_len: u32,
    ) -> Mlx5Result<()> {
        CmdQueueTransport::execute(self, opcode, in_mbox_phys, in_len, out_mbox_phys, out_len)
    }

    fn set_uid(&mut self, uid: u16) {
        CmdQueueTransport::set_uid(self, uid);
    }

    fn uid(&self) -> u16 {
        CmdQueueTransport::uid(self)
    }
}

// ============================================================================
// High-Level Command Helpers
// ============================================================================

/// QUERY_ISSI コマンド出力の解析
pub fn parse_query_issi(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_query_issi_out_bits:
    // current_issi is at bit offset 0x50 => byte offset 0x0A.
    out_mbox.read_be16(0x0A) as u32
}

/// ENABLE_HCA コマンド入力の構築
pub fn build_enable_hca_input(in_mbox: &mut CmdMailbox, function_id: u16) {
    *in_mbox = CmdMailbox::zeroed();
    // mlx5_ifc_enable_hca_in_bits: function_id at bit 0x50 => byte 0x0A.
    in_mbox.write_be16(0x0A, function_id);
}

/// SET_ISSI コマンド入力の構築
pub fn build_set_issi_input(in_mbox: &mut CmdMailbox, current_issi: u16) {
    *in_mbox = CmdMailbox::zeroed();
    // mlx5_ifc_set_issi_in_bits: current_issi at bit 0x50 => byte 0x0A.
    in_mbox.write_be16(0x0A, current_issi);
}

/// QUERY_HCA_CAP コマンド入力の構築
///
/// `cap_type`: キャパビリティタイプ
///   0x0 = General Capabilities
///   0x1 = Ethernet Offloads
///   0x2 = Atomic Capabilities
pub fn build_query_hca_cap_input(in_mbox: &mut CmdMailbox, cap_type: u16) {
    *in_mbox = CmdMailbox::zeroed();
    // mlx5_ifc_query_hca_cap_in_bits: op_mod at byte 0x06.
    in_mbox.write_be16(0x06, cap_type);
}

/// SET_HCA_CAP コマンド入力の構築
///
/// - `cap_type`: capability type (0x0 = General)
/// - `capability_payload`: capability union bytes copied from QUERY_HCA_CAP out[0x10..]
pub fn build_set_hca_cap_input(
    in_mbox: &mut CmdMailbox,
    cap_type: u16,
    capability_payload: &[u8],
) {
    *in_mbox = CmdMailbox::zeroed();
    // mlx5_ifc_set_hca_cap_in_bits: op_mod at byte 0x06.
    in_mbox.write_be16(0x06, cap_type);
    // capability union starts at byte 0x10.
    let copy_len = capability_payload.len().min(MLX5_CMD_MBOX_SIZE - 0x10);
    in_mbox.data[0x10..0x10 + copy_len].copy_from_slice(&capability_payload[..copy_len]);
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
    // mlx5_ifc_teardown_hca_in_bits: profile at byte 0x0A.
    in_mbox.write_be16(0x0A, profile);
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
    // mlx5_ifc_manage_pages_in_bits:
    // op_mod at byte 0x06, function_id at byte 0x0A, input_num_entries at byte 0x0C.
    in_mbox.write_be16(0x06, op as u16);
    in_mbox.write_be16(0x0A, function_id);
    in_mbox.write_be32(0x0C, num_pages);
    // PAS list starts at byte 0x10.
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
    build_query_nic_vport_input_ex(in_mbox, vport_number, false, None);
}

/// QUERY_NIC_VPORT_CONTEXT コマンド入力の構築（拡張）
///
/// - `other_vport`: query_nic_vport_context_in.other_vport
/// - `allowed_list_type`: query_nic_vport_context_in.allowed_list_type
pub fn build_query_nic_vport_input_ex(
    in_mbox: &mut CmdMailbox,
    vport_number: u16,
    other_vport: bool,
    allowed_list_type: Option<u8>,
) {
    *in_mbox = CmdMailbox::zeroed();
    // mlx5_ifc_query_nic_vport_context_in_bits:
    // vport_number is at bit offset 0x50 => byte offset 0x0A.
    in_mbox.write_be16(0x0A, vport_number);

    // other_vport is bit 0x40 (byte 0x08, MSB).
    if other_vport {
        in_mbox.data[0x08] |= 0x80;
    }

    // allowed_list_type is at bits [2:0] of byte 0x0C.
    if let Some(list_type) = allowed_list_type {
        in_mbox.data[0x0C] = (in_mbox.data[0x0C] & 0xF8) | (list_type & 0x07);
    }
}

/// QUERY_NIC_VPORT_CONTEXT 出力からMACアドレスを取得
pub fn parse_vport_mac(out_mbox: &CmdMailbox) -> [u8; 6] {
    // mlx5_ifc_query_nic_vport_context_out_bits:
    // - nic_vport_context starts at byte 0x10
    // - permanent_address (mac layout) at bit 0x7a0 inside context => +0xF4 bytes
    // - current_uc_mac_address[0] at bit 0x7e0 inside context => +0xFC bytes
    // mac_address_layout:
    //   reserved_at_0[16], mac_addr_47_32[16], mac_addr_31_0[32]
    const NIC_VPORT_CTX_BASE: usize = 0x10;
    const PERM_MAC_LAYOUT: usize = NIC_VPORT_CTX_BASE + 0xF4;
    const CURR_UC0_MAC_LAYOUT: usize = NIC_VPORT_CTX_BASE + 0xFC;

    fn read_mac_layout(mbox: &CmdMailbox, base: usize) -> [u8; 6] {
        let mac_h = mbox.read_be16(base + 0x02);
        let mac_l = mbox.read_be32(base + 0x04);
        [
            (mac_h >> 8) as u8,
            mac_h as u8,
            (mac_l >> 24) as u8,
            (mac_l >> 16) as u8,
            (mac_l >> 8) as u8,
            mac_l as u8,
        ]
    }

    let perm = read_mac_layout(out_mbox, PERM_MAC_LAYOUT);
    if perm != [0; 6] {
        return perm;
    }

    let current = read_mac_layout(out_mbox, CURR_UC0_MAC_LAYOUT);
    if current != [0; 6] {
        return current;
    }

    [0; 6]
}

/// QUERY_SPECIAL_CONTEXTS コマンド入力の構築
pub fn build_query_special_contexts_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
}

/// QUERY_SPECIAL_CONTEXTS 出力から reserved lkey を取得
pub fn parse_query_special_contexts_resd_lkey(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_query_special_contexts_out_bits: resd_lkey at byte offset 0x0C.
    out_mbox.read_be32(0x0C)
}

// ============================================================================
// Resource Allocation Commands
// ============================================================================

/// ALLOC_UAR コマンド入力の構築
pub fn build_alloc_uar_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
    // ALLOC_UAR は追加パラメータ不要
}

/// ALLOC_UAR 出力からUARページ番号を解析
pub fn parse_alloc_uar_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_alloc_uar_out_bits: uar[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// DEALLOC_UAR コマンド入力の構築
pub fn build_dealloc_uar_input(in_mbox: &mut CmdMailbox, uar_number: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, uar_number & 0x00FF_FFFF);
}

/// ALLOC_PD コマンド入力の構築
pub fn build_alloc_pd_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
}

/// ALLOC_PD 出力からPD番号を解析
pub fn parse_alloc_pd_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_alloc_pd_out_bits: pd[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// DEALLOC_PD コマンド入力の構築
pub fn build_dealloc_pd_input(in_mbox: &mut CmdMailbox, pd: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, pd & 0x00FF_FFFF);
}

/// ALLOC_TRANSPORT_DOMAIN コマンド入力の構築
pub fn build_alloc_td_input(in_mbox: &mut CmdMailbox) {
    *in_mbox = CmdMailbox::zeroed();
}

/// ALLOC_TRANSPORT_DOMAIN 出力からTD番号を解析
pub fn parse_alloc_td_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_alloc_transport_domain_out_bits: transport_domain[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// DEALLOC_TRANSPORT_DOMAIN コマンド入力の構築
pub fn build_dealloc_td_input(in_mbox: &mut CmdMailbox, td: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, td & 0x00FF_FFFF);
}

// ============================================================================
// Queue Creation / Modification Commands
// ============================================================================

/// CREATE_CQ コマンド入力の構築
///
/// # Arguments
/// - `log_cq_size`: ログ2 CQサイズ
/// - `cq_buf_pa`: CQバッファの物理アドレス
/// - `db_pa`: CQドアベルレコードの物理アドレス
/// - `uar_page`: UARページ番号
/// - `eqn`: 紐づくEQ番号
/// - `cqe_comp`: CQE圧縮の有効/無効
pub fn build_create_cq_input(
    in_mbox: &mut CmdMailbox,
    log_cq_size: u8,
    cq_buf_pa: u64,
    db_pa: u64,
    uar_page: u32,
    eqn: u32,
    cqe_comp: bool,
) {
    *in_mbox = CmdMailbox::zeroed();
    // CQ Context at offset 0x10
    let ctx = 0x10;
    // log_cq_size at bits [4:0] | cqe_sz at bits [6:5] (0 = 64-byte CQE)
    let cqe_sz: u32 = 0; // 64-byte CQE
    let flags: u32 = if cqe_comp { 0x01 << 8 } else { 0 }; // cqe_compression
    in_mbox.write_be32(ctx, (cqe_sz << 5) | (log_cq_size as u32) | flags);
    // UAR page at offset +0x04
    in_mbox.write_be32(ctx + 0x04, uar_page & 0x00FF_FFFF);
    // EQ番号 at offset +0x08
    in_mbox.write_be32(ctx + 0x08, eqn & 0x00FF_FFFF);
    // CQ buffer PA at offset +0x10 (PAS list, first entry)
    in_mbox.write_be64(ctx + 0x10, cq_buf_pa);
    // Doorbell record PA at offset +0x18
    in_mbox.write_be64(ctx + 0x18, db_pa);
}

/// CREATE_CQ 出力からCQ番号を解析
pub fn parse_create_cq_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_cq_out_bits: cqn[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// DESTROY_CQ コマンド入力の構築
pub fn build_destroy_cq_input(in_mbox: &mut CmdMailbox, cqn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, cqn & 0x00FF_FFFF);
}

/// CREATE_SQ コマンド入力の構築
///
/// # Arguments
/// - `log_sq_size`: ログ2 SQサイズ
/// - `sq_buf_pa`: SQバッファ物理アドレス
/// - `db_pa`: SQドアベルレコード物理アドレス
/// - `cqn`: 紐づくCQ番号
/// - `tisn`: 紐づくTIS番号
/// - `uar_page`: UARページ番号
/// - `mkey`: メモリキー
pub fn build_create_sq_input(
    in_mbox: &mut CmdMailbox,
    log_sq_size: u8,
    sq_buf_pa: u64,
    db_pa: u64,
    cqn: u32,
    tisn: u32,
    uar_page: u32,
    _mkey: u32,
) {
    *in_mbox = CmdMailbox::zeroed();
    // SQ Context at offset 0x10
    let ctx = 0x10;
    // flags + state (RESET=0x00) at offset +0x00
    // flush_in_error: bit 28
    in_mbox.write_be32(ctx, 0x1 << 28); // flush_in_error = 1
                                        // CQN at offset +0x04
    in_mbox.write_be32(ctx + 0x04, cqn & 0x00FF_FFFF);
    // TISN at offset +0x08
    in_mbox.write_be32(ctx + 0x08, tisn & 0x00FF_FFFF);
    // UAR page at offset +0x0C
    in_mbox.write_be32(ctx + 0x0C, uar_page & 0x00FF_FFFF);
    // WQ Context at offset 0x30
    let wq_ctx = 0x30;
    // wq_type (0x01 = cyclic) + log_wq_stride (6 = 64-byte WQEs) + log_wq_sz
    let wq_type: u32 = 0x01; // cyclic
    let log_wq_stride: u32 = 6; // 64-byte WQE stride (2^6 = 64)
    in_mbox.write_be32(
        wq_ctx,
        (wq_type << 28) | (log_wq_stride << 16) | (log_sq_size as u32),
    );
    // PD at offset +0x04
    // (PD is set globally, not per-queue in this simplified model)
    // Buffer PA at offset +0x10
    in_mbox.write_be64(wq_ctx + 0x10, sq_buf_pa);
    // Doorbell PA at offset +0x18
    in_mbox.write_be64(wq_ctx + 0x18, db_pa);
}

/// CREATE_SQ 出力からSQ番号を解析
pub fn parse_create_sq_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_sq_out_bits: sqn[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// DESTROY_SQ コマンド入力の構築
pub fn build_destroy_sq_input(in_mbox: &mut CmdMailbox, sqn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, sqn & 0x00FF_FFFF);
}

/// MODIFY_SQ コマンド入力の構築（状態遷移用）
///
/// # Arguments
/// - `sqn`: SQ番号
/// - `current_state`: 現在の状態
/// - `next_state`: 遷移先の状態
pub fn build_modify_sq_input(
    in_mbox: &mut CmdMailbox,
    sqn: u32,
    current_state: u8,
    next_state: u8,
) {
    *in_mbox = CmdMailbox::zeroed();
    // SQN at offset 0x04
    in_mbox.write_be32(0x04, sqn & 0x00FF_FFFF);
    // SQ Context at offset 0x10
    let ctx = 0x10;
    // sq_state (current) at bits [7:4], next_state at bits [3:0]
    let state_val = ((current_state as u32) << 4) | (next_state as u32);
    in_mbox.write_be32(ctx, state_val);
}

/// CREATE_RQ コマンド入力の構築
///
/// # Arguments
/// - `log_rq_size`: ログ2 RQサイズ
/// - `rq_buf_pa`: RQバッファ物理アドレス
/// - `db_pa`: RQドアベルレコード物理アドレス
/// - `cqn`: 紐づくCQ番号
/// - `uar_page`: UARページ番号
/// - `mkey`: メモリキー
pub fn build_create_rq_input(
    in_mbox: &mut CmdMailbox,
    log_rq_size: u8,
    rq_buf_pa: u64,
    db_pa: u64,
    cqn: u32,
    _uar_page: u32,
    _mkey: u32,
) {
    *in_mbox = CmdMailbox::zeroed();
    // RQ Context at offset 0x10
    let ctx = 0x10;
    // flags + state (RESET=0x00) at offset +0x00
    // flush_in_error: bit 28
    in_mbox.write_be32(ctx, 0x1 << 28);
    // CQN at offset +0x04
    in_mbox.write_be32(ctx + 0x04, cqn & 0x00FF_FFFF);
    // WQ Context at offset 0x30
    let wq_ctx = 0x30;
    // wq_type (0x01 = cyclic) + log_wq_stride (4 = 16-byte scatter) + log_wq_sz
    let wq_type: u32 = 0x01; // cyclic
    let log_wq_stride: u32 = 4; // 16-byte WQE stride for RQ (single scatter entry)
    in_mbox.write_be32(
        wq_ctx,
        (wq_type << 28) | (log_wq_stride << 16) | (log_rq_size as u32),
    );
    // Buffer PA at offset +0x10
    in_mbox.write_be64(wq_ctx + 0x10, rq_buf_pa);
    // Doorbell PA at offset +0x18
    in_mbox.write_be64(wq_ctx + 0x18, db_pa);
}

/// CREATE_RQ 出力からRQ番号を解析
pub fn parse_create_rq_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_rq_out_bits: rqn[23:0] at byte offset 0x09.
    out_mbox.read_be24(0x09)
}

/// DESTROY_RQ コマンド入力の構築
pub fn build_destroy_rq_input(in_mbox: &mut CmdMailbox, rqn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, rqn & 0x00FF_FFFF);
}

/// MODIFY_RQ コマンド入力の構築（状態遷移用）
pub fn build_modify_rq_input(
    in_mbox: &mut CmdMailbox,
    rqn: u32,
    current_state: u8,
    next_state: u8,
) {
    *in_mbox = CmdMailbox::zeroed();
    // RQN at offset 0x04
    in_mbox.write_be32(0x04, rqn & 0x00FF_FFFF);
    // RQ Context at offset 0x10
    let ctx = 0x10;
    let state_val = ((current_state as u32) << 4) | (next_state as u32);
    in_mbox.write_be32(ctx, state_val);
}

/// DESTROY_EQ コマンド入力の構築
pub fn build_destroy_eq_input(in_mbox: &mut CmdMailbox, eqn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, eqn & 0x00FF_FFFF);
}

/// CREATE_EQ 出力からEQ番号を解析
pub fn parse_create_eq_output(out_mbox: &CmdMailbox) -> u32 {
    // mlx5_ifc_create_eq_out_bits: eq_number[7:0] at byte offset 0x0B.
    out_mbox.data[0x0B] as u32
}

// ============================================================================
// Port & Statistics Commands
// ============================================================================

/// QUERY_VPORT_STATE コマンド入力の構築
pub fn build_query_vport_state_input(in_mbox: &mut CmdMailbox, vport_number: u16) {
    *in_mbox = CmdMailbox::zeroed();
    // mlx5_ifc_query_vport_state_in_bits: vport_number at bit offset 0x50 => byte 0x0A.
    in_mbox.write_be16(0x0A, vport_number);
}

/// QUERY_VPORT_STATE 出力からリンク状態を解析
///
/// # Returns
/// (admin_state, link_state) — 各2ビットフィールド
pub fn parse_query_vport_state_output(out_mbox: &CmdMailbox) -> (u8, u8) {
    // mlx5_ifc_query_vport_state_out_bits:
    // reserved_at_60[24], admin_state[4], state[4] => dword at byte 0x08.
    let val = out_mbox.read_be32(0x08);
    let admin_state = ((val >> 4) & 0x0F) as u8;
    let oper_state = (val & 0x0F) as u8;
    (admin_state, oper_state)
}

/// QUERY_VPORT_COUNTER コマンド入力の構築
pub fn build_query_vport_counter_input(in_mbox: &mut CmdMailbox, port: u8, clear_on_read: bool) {
    *in_mbox = CmdMailbox::zeroed();
    // other_vport = 0, port_num at byte 0x09
    in_mbox.data[0x09] = port;
    // clear on read at bit 0 of byte 0x02
    if clear_on_read {
        in_mbox.data[0x02] = 0x01;
    }
}

/// QUERY_VPORT_COUNTER 出力を解析
pub fn parse_query_vport_counter_output(out_mbox: &CmdMailbox) -> crate::defs::VportCounters {
    use crate::defs::VportCounters;
    // Counter offsets in output mailbox (simplified layout)
    let base = 0x10;
    VportCounters {
        rx_unicast_packets: out_mbox.read_be64(base + 0x00),
        rx_unicast_bytes: out_mbox.read_be64(base + 0x08),
        rx_multicast_packets: out_mbox.read_be64(base + 0x10),
        rx_multicast_bytes: out_mbox.read_be64(base + 0x18),
        rx_broadcast_packets: out_mbox.read_be64(base + 0x20),
        rx_broadcast_bytes: out_mbox.read_be64(base + 0x28),
        tx_unicast_packets: out_mbox.read_be64(base + 0x30),
        tx_unicast_bytes: out_mbox.read_be64(base + 0x38),
        tx_multicast_packets: out_mbox.read_be64(base + 0x40),
        tx_multicast_bytes: out_mbox.read_be64(base + 0x48),
        tx_broadcast_packets: out_mbox.read_be64(base + 0x50),
        tx_broadcast_bytes: out_mbox.read_be64(base + 0x58),
        rx_error_packets: out_mbox.read_be64(base + 0x60),
        tx_error_packets: out_mbox.read_be64(base + 0x68),
        rx_dropped: out_mbox.read_be64(base + 0x70),
        tx_dropped: out_mbox.read_be64(base + 0x78),
    }
}

/// MODIFY_NIC_VPORT_CONTEXT コマンド入力の構築（プロミスキャスモード）
pub fn build_modify_nic_vport_promisc_input(
    in_mbox: &mut CmdMailbox,
    uc_promisc: bool,
    mc_promisc: bool,
    all_promisc: bool,
) {
    *in_mbox = CmdMailbox::zeroed();
    // Modify field select at offset 0x00: bit 0 = promisc
    in_mbox.write_be32(0x00, 0x01); // promisc field selected
                                    // NIC VPORT context at offset 0x10
    let ctx = 0x10;
    let mut promisc_flags: u32 = 0;
    if uc_promisc {
        promisc_flags |= 0x01;
    }
    if mc_promisc {
        promisc_flags |= 0x02;
    }
    if all_promisc {
        promisc_flags |= 0x04;
    }
    in_mbox.write_be32(ctx + 0x00, promisc_flags);
}

/// SET_DRIVER_VERSION コマンド入力の構築
pub fn build_set_driver_version_input(in_mbox: &mut CmdMailbox, version_str: &[u8]) {
    *in_mbox = CmdMailbox::zeroed();
    // Driver version string at offset 0x10 (max 64 bytes)
    let copy_len = version_str.len().min(64);
    in_mbox.data[0x10..0x10 + copy_len].copy_from_slice(&version_str[..copy_len]);
}

/// MODIFY_CQ コマンド入力の構築（CQモデレーション設定）
///
/// # Arguments
/// - `cqn`: CQ番号
/// - `max_count`: 割り込み結合の最大パケット数
/// - `max_period_us`: 割り込み結合の最大遅延（マイクロ秒）
pub fn build_modify_cq_moderation_input(
    in_mbox: &mut CmdMailbox,
    cqn: u32,
    max_count: u16,
    max_period_us: u16,
) {
    *in_mbox = CmdMailbox::zeroed();
    // CQN at offset 0x04
    in_mbox.write_be32(0x04, cqn & 0x00FF_FFFF);
    // CQ Context (modify fields) at offset 0x10
    let ctx = 0x10;
    // Modify field select: bit 0 = moderation
    in_mbox.write_be32(0x00, 0x01);
    // cq_max_count at offset +0x00 (upper 16 bits)
    // cq_period at offset +0x00 (lower 16 bits)
    let moderation = ((max_count as u32) << 16) | (max_period_us as u32);
    in_mbox.write_be32(ctx, moderation);
}

/// DESTROY_RQT コマンド入力の構築
pub fn build_destroy_rqt_input(in_mbox: &mut CmdMailbox, rqtn: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, rqtn & 0x00FF_FFFF);
}

/// DESTROY_FLOW_TABLE コマンド入力の構築
pub fn build_destroy_flow_table_input(in_mbox: &mut CmdMailbox, table_id: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
}

/// DESTROY_FLOW_GROUP コマンド入力の構築
pub fn build_destroy_flow_group_input(in_mbox: &mut CmdMailbox, table_id: u32, group_id: u32) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
    in_mbox.write_be32(0x08, group_id & 0x00FF_FFFF);
}

/// DELETE_FLOW_TABLE_ENTRY コマンド入力の構築
pub fn build_delete_flow_table_entry_input(
    in_mbox: &mut CmdMailbox,
    table_id: u32,
    flow_index: u32,
) {
    *in_mbox = CmdMailbox::zeroed();
    in_mbox.write_be32(0x04, table_id & 0x00FF_FFFF);
    in_mbox.write_be32(0x08, flow_index);
}
