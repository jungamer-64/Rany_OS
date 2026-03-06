// ============================================================================
// drivers/mlx5/src/cmd/mod.rs - Command Interface Base
// ============================================================================
//! mlx5 コマンドインタフェースの基盤
//!
//! HCAファームウェアとのメールボックスベースのコマンド送受信を管理する。

use crate::defs::{CmdOpcode, CmdStatus, MLX5_CMD_DATA_BLOCK_SIZE, MLX5_CMD_MBOX_SIZE};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::regs::cmd_entry;
use core::sync::atomic::{fence, Ordering};

pub mod hca;
pub mod res;
pub mod queues;
pub mod flow;

/// コマンドメールボックス (Page aligned)
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

/// コマンドキューエントリ (64 bytes)
#[repr(C, align(64))]
pub struct CmdEntry {
    pub raw: [u8; cmd_entry::ENTRY_SIZE],
}

impl CmdEntry {
    const PCI_CMD_XPORT: u8 = 7;

    pub const fn zeroed() -> Self {
        Self {
            raw: [0u8; cmd_entry::ENTRY_SIZE],
        }
    }

    pub fn set_input_mailbox(&mut self, phys_addr: u64) {
        let h = (phys_addr >> 32) as u32;
        let l = phys_addr as u32;
        self.write_be32(cmd_entry::IN_MBOX_PTR_H, h);
        self.write_be32(cmd_entry::IN_MBOX_PTR_L, l);
    }

    pub fn set_output_mailbox(&mut self, phys_addr: u64) {
        let h = (phys_addr >> 32) as u32;
        let l = phys_addr as u32;
        self.write_be32(cmd_entry::OUT_MBOX_PTR_H, h);
        self.write_be32(cmd_entry::OUT_MBOX_PTR_L, l);
    }

    pub fn set_input_length(&mut self, len: u32) {
        self.write_be32(cmd_entry::IN_LENGTH, len);
    }

    pub fn set_output_length(&mut self, len: u32) {
        self.write_be32(cmd_entry::OUT_LENGTH, len);
    }

    pub fn set_input_inline(&mut self, first_16: &[u8]) {
        let mut buf = [0u8; 16];
        let copy_len = first_16.len().min(16);
        buf[..copy_len].copy_from_slice(&first_16[..copy_len]);
        self.raw[cmd_entry::IN_INLINE..cmd_entry::IN_INLINE + 16].copy_from_slice(&buf);
    }

    pub fn output_inline(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.raw[cmd_entry::OUT_INLINE..cmd_entry::OUT_INLINE + 16]);
        out
    }

    pub fn set_token(&mut self, token: u8) {
        self.raw[cmd_entry::TOKEN] = token;
    }

    pub fn update_signature(&mut self) {
        self.raw[cmd_entry::SIG] = 0;
        let mut sum = 0u8;
        for b in &self.raw {
            sum ^= *b;
        }
        self.raw[cmd_entry::SIG] = !sum;
    }

    pub fn submit(&mut self, token: u8) {
        self.raw[cmd_entry::TYPE] = Self::PCI_CMD_XPORT;
        self.set_token(token);
        self.raw[cmd_entry::STATUS_OWN] = 0x01; // owner=HW
        self.update_signature();
    }

    pub fn is_owned_by_hw(&self) -> bool {
        (self.raw[cmd_entry::STATUS_OWN] & 0x01) != 0
    }

    pub fn status(&self) -> CmdStatus {
        CmdStatus::from_u8(self.raw[cmd_entry::STATUS_OWN] >> 1)
    }

    fn write_be32(&mut self, offset: usize, value: u32) {
        let bytes = value.to_be_bytes();
        self.raw[offset..offset + 4].copy_from_slice(&bytes);
    }
}

/// コマンド転送抽象
pub trait CommandTransport {
    /// Safety: メールボックスポインタが有効なDMAメモリであること
    unsafe fn execute(
        &mut self,
        opcode: CmdOpcode,
        in_mbox_phys: u64,
        in_len: u32,
        out_mbox_phys: u64,
        out_len: u32,
    ) -> Mlx5Result<()>;

    fn set_uid(&mut self, _uid: u16) {}
    fn uid(&self) -> u16 { 0 }
}

/// CMDQベースのコマンドインタフェース
pub struct CmdQueueTransport {
    cmdq_phys: u64,
    cmdq_virt: u64,
    log_cmdq_size: u8,
    log_cmd_stride: u8,
    bar0_base: u64,
    in_mbox_virt: u64,
    out_mbox_virt: u64,
    next_token: u8,
    uid: u16,
}

#[repr(C)]
struct CmdProtBlock {
    data: [u8; MLX5_CMD_DATA_BLOCK_SIZE],
    rsvd0: [u8; 48],
    next: u64,
    block_num: u32,
    rsvd1: u8,
    token: u8,
    ctrl_sig: u8,
    sig: u8,
}

pub type CmdQueue = CmdQueueTransport;

impl CmdQueueTransport {
    pub fn opcode_uses_uid(opcode: CmdOpcode) -> bool {
        matches!(
            opcode,
            CmdOpcode::AllocUar | CmdOpcode::DeallocUar | CmdOpcode::AllocPd | CmdOpcode::DeallocPd
            | CmdOpcode::AllocTransportDomain | CmdOpcode::DeallocTransportDomain
            | CmdOpcode::CreateEq | CmdOpcode::CreateCq | CmdOpcode::DestroyCq | CmdOpcode::ModifyCq
            | CmdOpcode::CreateSq | CmdOpcode::DestroySq | CmdOpcode::ModifySq
            | CmdOpcode::CreateRq | CmdOpcode::DestroyRq | CmdOpcode::ModifyRq
            | CmdOpcode::CreateTis | CmdOpcode::ModifyTis | CmdOpcode::DestroyTis
            | CmdOpcode::CreateTir | CmdOpcode::ModifyTir | CmdOpcode::DestroyTir
            | CmdOpcode::CreateMkey | CmdOpcode::DestroyMkey
            | CmdOpcode::CreateRqt | CmdOpcode::ModifyRqt | CmdOpcode::DestroyRqt
            | CmdOpcode::CreateFlowTable
        )
    }

    pub fn parse_hw_cmdq_layout(cmdq_addr_l_sz: u32) -> (u8, u8, bool) {
        let low = cmdq_addr_l_sz & 0xFF;
        let log_cmdq_size = ((low >> 4) & 0x0F) as u8;
        let log_cmd_stride = (low & 0x0F) as u8;
        let nic_if_supported = (cmdq_addr_l_sz & crate::regs::fw_state::NIC_INTERFACE_SUPPORTED_BIT) != 0;
        (log_cmdq_size, log_cmd_stride, nic_if_supported)
    }

    fn validate_hw_cmdq_layout(log_cmdq_size: u8, log_cmd_stride: u8) -> Mlx5Result<()> {
        if log_cmdq_size == 0 { return Err(Mlx5Error::NotSupported); }
        let entry_size = 1usize.checked_shl(log_cmd_stride as u32).ok_or(Mlx5Error::NotSupported)?;
        if entry_size != cmd_entry::ENTRY_SIZE { return Err(Mlx5Error::NotSupported); }
        Ok(())
    }

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

    pub fn set_uid(&mut self, uid: u16) { self.uid = uid; }
    pub fn uid(&self) -> u16 { self.uid }

    fn xor8(buf: &[u8]) -> u8 {
        let mut sum = 0u8;
        for b in buf { sum ^= *b; }
        sum
    }

    unsafe fn prepare_in_block(&self, token: u8, in_len: usize, _in_mbox_phys: u64) -> [u8; 16] {
        let mut in_inline = [0u8; 16];
        if in_len == 0 { return in_inline; }
        let src = core::slice::from_raw_parts(self.in_mbox_virt as *const u8, in_len.min(16));
        in_inline[..src.len()].copy_from_slice(src);

        if in_len > 16 {
            let total_payload = in_len - 16;
            let num_blocks = (total_payload + MLX5_CMD_DATA_BLOCK_SIZE - 1) / MLX5_CMD_DATA_BLOCK_SIZE;
            if num_blocks * 512 > MLX5_CMD_MBOX_SIZE {
                log::error!(target: "mlx5", "Input mailbox overflow: {} blocks requested", num_blocks);
                return in_inline;
            }
            let mut tmp_payload = [0u8; MLX5_CMD_MBOX_SIZE];
            let copy_len = total_payload.min(MLX5_CMD_MBOX_SIZE);
            core::ptr::copy_nonoverlapping((self.in_mbox_virt as *const u8).add(16), tmp_payload.as_mut_ptr(), copy_len);

            for i in 0..num_blocks {
                let block_ptr = (self.in_mbox_virt as *mut CmdProtBlock).add(i);
                let block = &mut *block_ptr;
                let offset = i * MLX5_CMD_DATA_BLOCK_SIZE;
                let payload_len = (total_payload - offset).min(MLX5_CMD_DATA_BLOCK_SIZE);
                block.data.fill(0);
                block.data[..payload_len].copy_from_slice(&tmp_payload[offset..offset + payload_len]);
                block.token = token;
                block.block_num = i as u32;
                block.next = if i + 1 < num_blocks { _in_mbox_phys + ((i + 1) * 512) as u64 } else { 0 };
                block.ctrl_sig = 0;
                block.sig = 0;
                let block_bytes = core::slice::from_raw_parts(block_ptr as *const u8, 512);
                block.sig = !Self::xor8(block_bytes);
            }
        }
        in_inline
    }

    pub fn setup_cmdq_in_bar0(&mut self) {
        let h = (self.cmdq_phys >> 32) as u32;
        // combine physical address low32 bits with command queue layout fields
        let l = (self.cmdq_phys as u32)
            | ((self.log_cmdq_size as u32) << 4)
            | (self.log_cmd_stride as u32);
        crate::mmio_write_be32(self.bar0_base as usize + crate::regs::init_seg::CMDQ_ADDR_H, h);
        fence(Ordering::Release);
        crate::mmio_write_be32(self.bar0_base as usize + crate::regs::init_seg::CMDQ_ADDR_L_SZ, l);
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
        let token = self.next_token;
        self.next_token = if self.next_token == 0xFF { 1 } else { self.next_token + 1 };

        if Self::opcode_uses_uid(opcode) {
            let in_mbox = &mut *(self.in_mbox_virt as *mut CmdMailbox);
            in_mbox.write_be16(0x0c, self.uid);
        }

        let in_inline = self.prepare_in_block(token, in_len as usize, in_mbox_phys);
        let entry_ptr = self.cmdq_virt as *mut CmdEntry;
        let entry = &mut *entry_ptr;

        while entry.is_owned_by_hw() { core::hint::spin_loop(); }

        *entry = CmdEntry::zeroed();
        entry.write_be32(cmd_entry::OPCODE, (opcode as u32) << 16);
        entry.set_input_mailbox(in_mbox_phys);
        entry.set_input_length(in_len);
        entry.set_output_mailbox(out_mbox_phys);
        entry.set_output_length(out_len);
        entry.set_input_inline(&in_inline);
        fence(Ordering::Release);
        entry.submit(token);

        let doorbell = self.bar0_base as usize + crate::regs::init_seg::CMDQ_DOORBELL;
        crate::mmio_write_be32(doorbell, 1 << 31);

        let start_ms = kernel_api::services::kernel().current_tick();
        while entry.is_owned_by_hw() {
            if kernel_api::services::kernel().current_tick() - start_ms > 5000 {
                log::error!(target: "mlx5", "Command timeout: opcode={:?}", opcode);
                return Err(Mlx5Error::CommandTimeout);
            }
            core::hint::spin_loop();
        }
        fence(Ordering::Acquire);

        let status = entry.status();
        if status != CmdStatus::Ok {
            let out_mbox = &*(self.out_mbox_virt as *const CmdMailbox);
            let syndrome = out_mbox.read_be32(0x04);
            log::error!(target: "mlx5", "Command failed: opcode={:?} status={:?} syndrome={:#x}", opcode, status, syndrome);
            // syndrome is currently a 32-bit value returned by the HW;
            // the error enum only stores an 8‑bit code so truncate.
            return Err(Mlx5Error::CommandFailed(syndrome as u8));
        }

        if out_len > 16 {
            let total_payload = out_len as usize - 16;
            let num_blocks = (total_payload + MLX5_CMD_DATA_BLOCK_SIZE - 1) / MLX5_CMD_DATA_BLOCK_SIZE;
            let mut out_payload = [0u8; MLX5_CMD_MBOX_SIZE];
            for i in 0..num_blocks {
                let block = &*(self.out_mbox_virt as *const CmdProtBlock).add(i);
                let offset = i * MLX5_CMD_DATA_BLOCK_SIZE;
                let payload_len = (total_payload - offset).min(MLX5_CMD_DATA_BLOCK_SIZE);
                out_payload[offset..offset + payload_len].copy_from_slice(&block.data[..payload_len]);
            }
            let dest = (self.out_mbox_virt as *mut u8).add(16);
            core::ptr::copy_nonoverlapping(out_payload.as_ptr(), dest, total_payload.min(MLX5_CMD_MBOX_SIZE - 16));
        }
        let out_inline = entry.output_inline();
        core::ptr::copy_nonoverlapping(out_inline.as_ptr(), self.out_mbox_virt as *mut u8, 16);

        Ok(())
    }

    fn set_uid(&mut self, uid: u16) { self.uid = uid; }
    fn uid(&self) -> u16 { self.uid }
}
