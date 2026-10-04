// ============================================================================
// drivers/mlx5/src/cmd/mod.rs - Command Interface Base
// ============================================================================
//! mlx5 コマンドインタフェースの基盤
//!
//! HCAファームウェアとのメールボックスベースのコマンド送受信を管理する。

use crate::defs::{CmdDeliveryStatus, MLX5_CMD_MBOX_SIZE};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::regs::cmd_entry;

pub mod flow;
pub mod hca;
pub mod queues;
pub mod res;

mod memory;
mod transport;
mod wire;
pub use transport::CmdQueue;

/// CPU-owned logical command data. This storage is never exposed to firmware;
/// the command transport separately encodes its retained DMA blocks.
pub struct CmdMailbox {
    /// メールボックスデータ
    pub data: [u8; MLX5_CMD_MBOX_SIZE],
}

impl CmdMailbox {
    /// Allocate staging before any command hardware publication.
    #[expect(
        unsafe_code,
        reason = "CmdMailbox contains only bytes, so a zeroed allocation is initialized"
    )]
    pub(crate) fn allocate() -> Mlx5Result<alloc::boxed::Box<Self>> {
        let mailbox =
            alloc::boxed::Box::<Self>::try_new_zeroed().map_err(|_| Mlx5Error::OutOfMemory)?;
        // SAFETY: every field is a byte array; all-zero is a valid mailbox value.
        Ok(unsafe { mailbox.assume_init() })
    }

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

    pub fn delivery_status_raw(&self) -> u8 {
        self.raw[cmd_entry::STATUS_OWN] >> 1
    }

    pub fn delivery_status(&self) -> CmdDeliveryStatus {
        CmdDeliveryStatus::from_u8(self.delivery_status_raw())
    }

    fn write_be32(&mut self, offset: usize, value: u32) {
        let bytes = value.to_be_bytes();
        self.raw[offset..offset + 4].copy_from_slice(&bytes);
    }
}
