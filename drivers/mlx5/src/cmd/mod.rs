// ============================================================================
// drivers/mlx5/src/cmd/mod.rs - Command Interface Base
// ============================================================================
//! mlx5 コマンドインタフェースの基盤
//!
//! HCAファームウェアとのメールボックスベースのコマンド送受信を管理する。

use crate::defs::{
    CmdDeliveryStatus, CmdOpcode, MLX5_CMD_DATA_BLOCK_SIZE, MLX5_CMD_INLINE_SIZE,
    MLX5_CMD_MBOX_BACKING_SIZE, MLX5_CMD_MBOX_SIZE, MLX5_CMD_PROT_BLOCK_ALIGN,
};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::regs::cmd_entry;
use core::mem::size_of;
use core::sync::atomic::{Ordering, fence};

pub mod flow;
pub mod hca;
pub mod queues;
pub mod res;

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

    /// Snapshot the logical command input before a UID retry loop starts.
    /// Default no-op for transports that don't rewrite input buffers.
    unsafe fn snapshot_input(&mut self, _in_len: u32) -> Mlx5Result<()> {
        Ok(())
    }

    /// Restore the logical command input before each UID retry attempt.
    /// Default no-op for transports that don't rewrite input buffers.
    unsafe fn restore_input(&mut self) -> Mlx5Result<()> {
        Ok(())
    }

    fn set_uid(&mut self, _uid: u16) {}
    fn uid(&self) -> u16 {
        0
    }
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
    in_snapshot: [u8; MLX5_CMD_MBOX_SIZE],
    in_snapshot_len: usize,
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

const CMD_BLOCK_SIZE: usize = size_of::<CmdProtBlock>();

pub type CmdQueue = CmdQueueTransport;

impl CmdQueueTransport {
    pub fn opcode_uses_uid(opcode: CmdOpcode) -> bool {
        !matches!(
            opcode,
            CmdOpcode::QueryHcaCap
                | CmdOpcode::QueryAdapter
                | CmdOpcode::InitHca
                | CmdOpcode::TeardownHca
                | CmdOpcode::EnableHca
                | CmdOpcode::DisableHca
                | CmdOpcode::QueryPages
                | CmdOpcode::ManagePages
                | CmdOpcode::SetHcaCap
                | CmdOpcode::QueryIssi
                | CmdOpcode::SetIssi
                | CmdOpcode::QueryNicVportContext
                | CmdOpcode::ModifyNicVportContext
                | CmdOpcode::QueryVportState
                | CmdOpcode::ModifyVportState
                | CmdOpcode::QueryVportCounter
                | CmdOpcode::QueryVnicEnv
                | CmdOpcode::QueryVhcaState
                | CmdOpcode::ModifyVhcaState
                | CmdOpcode::QuerySpecialContexts
                | CmdOpcode::SetDriverVersion
                | CmdOpcode::DestroyFlowTable
                | CmdOpcode::CreateFlowGroup
                | CmdOpcode::DestroyFlowGroup
                | CmdOpcode::SetFlowTableEntry
                | CmdOpcode::DeleteFlowTableEntry
                | CmdOpcode::AccessRegister
                | CmdOpcode::Nop
        )
    }

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
        let cmdq_entries = 1usize
            .checked_shl(log_cmdq_size as u32)
            .ok_or(Mlx5Error::NotSupported)?;
        let cmdq_bytes = cmdq_entries
            .checked_mul(cmd_entry::ENTRY_SIZE)
            .ok_or(Mlx5Error::NotSupported)?;
        unsafe {
            // Fresh DMA buffers may retain stale owner bits from prior use. Clear the
            // command queue and mailboxes before exposing them to the device.
            core::ptr::write_bytes(cmdq_virt as *mut u8, 0, cmdq_bytes);
            core::ptr::write_bytes(in_mbox_virt as *mut u8, 0, MLX5_CMD_MBOX_BACKING_SIZE);
            core::ptr::write_bytes(out_mbox_virt as *mut u8, 0, MLX5_CMD_MBOX_BACKING_SIZE);
        }
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
            in_snapshot: [0u8; MLX5_CMD_MBOX_SIZE],
            in_snapshot_len: 0,
        })
    }

    pub fn set_uid(&mut self, uid: u16) {
        self.uid = uid;
    }
    pub fn uid(&self) -> u16 {
        self.uid
    }

    fn write_transport_header(&self, opcode: CmdOpcode, in_mbox: &mut CmdMailbox) {
        in_mbox.write_be16(0x00, opcode as u16);
        if Self::opcode_uses_uid(opcode) {
            in_mbox.write_be16(0x02, self.uid);
        }
    }

    fn xor8(buf: &[u8]) -> u8 {
        let mut sum = 0u8;
        for b in buf {
            sum ^= *b;
        }
        sum
    }

    fn chained_block_count(len: usize) -> usize {
        if len <= MLX5_CMD_INLINE_SIZE {
            0
        } else {
            (len - MLX5_CMD_INLINE_SIZE + MLX5_CMD_DATA_BLOCK_SIZE - 1) / MLX5_CMD_DATA_BLOCK_SIZE
        }
    }

    fn validate_mailbox_len(dir: &str, len: usize) -> Mlx5Result<()> {
        if len > MLX5_CMD_MBOX_SIZE {
            log::error!(
                target: "mlx5",
                "{} mailbox length {} exceeds logical mailbox size {}",
                dir,
                len,
                MLX5_CMD_MBOX_SIZE
            );
            return Err(Mlx5Error::InvalidParameter);
        }
        let num_blocks = Self::chained_block_count(len);
        let storage = num_blocks
            .checked_mul(MLX5_CMD_PROT_BLOCK_ALIGN)
            .ok_or(Mlx5Error::InvalidParameter)?;
        if storage > MLX5_CMD_MBOX_BACKING_SIZE {
            log::error!(
                target: "mlx5",
                "{} mailbox backing overflow: len={} blocks={} storage={}",
                dir,
                len,
                num_blocks,
                storage
            );
            return Err(Mlx5Error::InvalidParameter);
        }
        Ok(())
    }

    fn block_phys(base_phys: u64, index: usize) -> u64 {
        base_phys + (index * MLX5_CMD_PROT_BLOCK_ALIGN) as u64
    }

    unsafe fn block_ptr(base_virt: u64, index: usize) -> *mut CmdProtBlock {
        (base_virt as *mut u8).add(index * MLX5_CMD_PROT_BLOCK_ALIGN) as *mut CmdProtBlock
    }

    unsafe fn finalize_block(block_ptr: *mut CmdProtBlock, token: u8, block_num: u32, next: u64) {
        let block = &mut *block_ptr;
        block.next = next.to_be();
        block.block_num = block_num.to_be();
        block.rsvd1 = 0;
        block.token = token;
        block.ctrl_sig = 0;
        block.sig = 0;

        let block_bytes = core::slice::from_raw_parts(block_ptr as *const u8, CMD_BLOCK_SIZE);
        block.ctrl_sig =
            !Self::xor8(&block_bytes[MLX5_CMD_DATA_BLOCK_SIZE..MLX5_CMD_DATA_BLOCK_SIZE + 62]);
        block.sig = !Self::xor8(&block_bytes[..CMD_BLOCK_SIZE - 1]);
    }

    unsafe fn prepare_in_block(
        &self,
        token: u8,
        in_len: usize,
        in_mbox_phys: u64,
    ) -> Mlx5Result<[u8; MLX5_CMD_INLINE_SIZE]> {
        Self::validate_mailbox_len("input", in_len)?;
        let mut in_inline = [0u8; MLX5_CMD_INLINE_SIZE];
        if in_len == 0 {
            return Ok(in_inline);
        }
        let src = core::slice::from_raw_parts(
            self.in_mbox_virt as *const u8,
            in_len.min(MLX5_CMD_INLINE_SIZE),
        );
        in_inline[..src.len()].copy_from_slice(src);

        if in_len > MLX5_CMD_INLINE_SIZE {
            let total_payload = in_len - MLX5_CMD_INLINE_SIZE;
            let num_blocks = Self::chained_block_count(in_len);
            for i in (0..num_blocks).rev() {
                let block_ptr = Self::block_ptr(self.in_mbox_virt, i);
                let offset = i * MLX5_CMD_DATA_BLOCK_SIZE;
                let payload_len = (total_payload - offset).min(MLX5_CMD_DATA_BLOCK_SIZE);
                let mut payload = [0u8; MLX5_CMD_DATA_BLOCK_SIZE];
                core::ptr::copy_nonoverlapping(
                    (self.in_mbox_virt as *const u8).add(MLX5_CMD_INLINE_SIZE + offset),
                    payload.as_mut_ptr(),
                    payload_len,
                );
                core::ptr::write_bytes(block_ptr as *mut u8, 0, CMD_BLOCK_SIZE);
                let block = &mut *block_ptr;
                block.data[..payload_len].copy_from_slice(&payload[..payload_len]);
                let next = if i + 1 < num_blocks {
                    Self::block_phys(in_mbox_phys, i + 1)
                } else {
                    0
                };
                Self::finalize_block(block_ptr, token, i as u32, next);
            }
        }
        Ok(in_inline)
    }

    unsafe fn prepare_out_block(
        &self,
        token: u8,
        out_len: usize,
        out_mbox_phys: u64,
    ) -> Mlx5Result<()> {
        Self::validate_mailbox_len("output", out_len)?;
        if out_len <= MLX5_CMD_INLINE_SIZE {
            return Ok(());
        }

        let num_blocks = Self::chained_block_count(out_len);
        for i in 0..num_blocks {
            let block_ptr = Self::block_ptr(self.out_mbox_virt, i);
            core::ptr::write_bytes(block_ptr as *mut u8, 0, CMD_BLOCK_SIZE);
            let next = if i + 1 < num_blocks {
                Self::block_phys(out_mbox_phys, i + 1)
            } else {
                0
            };
            Self::finalize_block(block_ptr, token, i as u32, next);
        }
        Ok(())
    }

    pub fn setup_cmdq_in_bar0(&mut self) {
        let h = (self.cmdq_phys >> 32) as u32;
        if (self.cmdq_phys & 0x0fff) != 0 {
            log::error!(
                target: "mlx5",
                "CMDQ physical address is not 4K-aligned: {:#x}",
                self.cmdq_phys
            );
        }

        // Firmware publishes the command queue layout in this register. The
        // driver only programs the aligned DMA base address back into BAR0.
        let l = self.cmdq_phys as u32;
        crate::mmio_write_be32(
            self.bar0_base as usize + crate::regs::init_seg::CMDQ_ADDR_H,
            h,
        );
        fence(Ordering::Release);
        crate::mmio_write_be32(
            self.bar0_base as usize + crate::regs::init_seg::CMDQ_ADDR_L_SZ,
            l,
        );
    }
}

impl CommandTransport for CmdQueueTransport {
    unsafe fn snapshot_input(&mut self, in_len: u32) -> Mlx5Result<()> {
        let len = (in_len as usize).min(MLX5_CMD_MBOX_SIZE);
        if len == 0 {
            self.in_snapshot_len = 0;
            return Ok(());
        }
        core::ptr::copy_nonoverlapping(
            self.in_mbox_virt as *const u8,
            self.in_snapshot.as_mut_ptr(),
            len,
        );
        self.in_snapshot_len = len;
        Ok(())
    }

    unsafe fn restore_input(&mut self) -> Mlx5Result<()> {
        if self.in_snapshot_len == 0 {
            return Ok(());
        }
        core::ptr::copy_nonoverlapping(
            self.in_snapshot.as_ptr(),
            self.in_mbox_virt as *mut u8,
            self.in_snapshot_len,
        );
        Ok(())
    }

    unsafe fn execute(
        &mut self,
        opcode: CmdOpcode,
        in_mbox_phys: u64,
        in_len: u32,
        out_mbox_phys: u64,
        out_len: u32,
    ) -> Mlx5Result<()> {
        crate::boot_trace_cmd(opcode, "exec_enter", self.uid);
        let token = self.next_token;
        self.next_token = if self.next_token == 0xFF {
            1
        } else {
            self.next_token + 1
        };

        let in_mbox = &mut *(self.in_mbox_virt as *mut CmdMailbox);
        self.write_transport_header(opcode, in_mbox);

        let in_inline = self.prepare_in_block(token, in_len as usize, in_mbox_phys)?;
        self.prepare_out_block(token, out_len as usize, out_mbox_phys)?;
        let entry_ptr = self.cmdq_virt as *mut CmdEntry;
        let entry = &mut *entry_ptr;

        crate::boot_trace_cmd(opcode, "wait_slot", self.uid);
        let queue_wait_start = kernel_api::service::kernel::instance().current_tick();
        let mut queue_wait_spins = 0u64;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while entry.is_owned_by_hw() {
            queue_wait_spins = queue_wait_spins.wrapping_add(1);
            if queue_wait_spins == 10_000_000 {
                crate::boot_trace_cmd(opcode, "slot_still_busy", self.uid);
            }
            if kernel_api::service::kernel::instance().current_tick() - queue_wait_start > 5000 {
                crate::boot_trace_cmd(opcode, "slot_timeout", self.uid);
                log::error!(
                    target: "mlx5",
                    "Command queue busy before submit: opcode={:?} token={} uid={:#x}",
                    opcode,
                    token,
                    self.uid
                );
                return Err(Mlx5Error::CommandTimeout);
            }
            core::hint::spin_loop();
        }
        crate::boot_trace_cmd(opcode, "slot_ready", self.uid);

        *entry = CmdEntry::zeroed();
        if in_len as usize > MLX5_CMD_INLINE_SIZE {
            entry.set_input_mailbox(in_mbox_phys);
        }
        entry.set_input_length(in_len);
        if out_len as usize > MLX5_CMD_INLINE_SIZE {
            entry.set_output_mailbox(out_mbox_phys);
        }
        entry.set_output_length(out_len);
        entry.set_input_inline(&in_inline);
        fence(Ordering::Release);
        entry.submit(token);

        crate::boot_trace_cmd(opcode, "doorbell", self.uid);
        let doorbell = self.bar0_base as usize + crate::regs::init_seg::CMDQ_DOORBELL;
        // This transport submits synchronously through slot 0 only, so ring the
        // doorbell for descriptor bit 0. The register itself is big-endian;
        // shifting into bit 31 prevents firmware from seeing the command.
        crate::mmio_write_be32(doorbell, 1);

        crate::boot_trace_cmd(opcode, "wait_hw", self.uid);
        let start_ms = kernel_api::service::kernel::instance().current_tick();
        let mut hw_wait_spins = 0u64;
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while entry.is_owned_by_hw() {
            hw_wait_spins = hw_wait_spins.wrapping_add(1);
            if hw_wait_spins == 10_000_000 {
                crate::boot_trace_cmd(opcode, "hw_still_owned", self.uid);
            }
            if kernel_api::service::kernel::instance().current_tick() - start_ms > 5000 {
                crate::boot_trace_cmd(opcode, "hw_timeout", self.uid);
                log::error!(target: "mlx5", "Command timeout: opcode={:?}", opcode);
                return Err(Mlx5Error::CommandTimeout);
            }
            core::hint::spin_loop();
        }
        crate::boot_trace_cmd(opcode, "hw_done", self.uid);
        fence(Ordering::Acquire);

        let out_inline = entry.output_inline();
        let delivery_status_raw = entry.delivery_status_raw();
        let delivery_status = entry.delivery_status();
        if delivery_status != CmdDeliveryStatus::Ok {
            let syndrome =
                u32::from_be_bytes([out_inline[4], out_inline[5], out_inline[6], out_inline[7]]);
            crate::boot_trace_cmd(opcode, "status_err", self.uid);
            log::error!(
                target: "mlx5",
                "Command delivery failed: opcode={:?} delivery={:?} raw={:#x} syndrome={:#x}",
                opcode,
                delivery_status,
                delivery_status_raw,
                syndrome
            );
            return Err(Mlx5Error::CommandFailed(delivery_status_raw));
        }

        core::ptr::copy_nonoverlapping(
            out_inline.as_ptr(),
            self.out_mbox_virt as *mut u8,
            MLX5_CMD_INLINE_SIZE,
        );
        if out_len as usize > MLX5_CMD_INLINE_SIZE {
            let total_payload = out_len as usize - MLX5_CMD_INLINE_SIZE;
            let num_blocks = Self::chained_block_count(out_len as usize);
            for i in 0..num_blocks {
                let block = &*Self::block_ptr(self.out_mbox_virt, i);
                let offset = i * MLX5_CMD_DATA_BLOCK_SIZE;
                let payload_len = (total_payload - offset).min(MLX5_CMD_DATA_BLOCK_SIZE);
                let mut payload = [0u8; MLX5_CMD_DATA_BLOCK_SIZE];
                payload[..payload_len].copy_from_slice(&block.data[..payload_len]);
                core::ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    (self.out_mbox_virt as *mut u8).add(MLX5_CMD_INLINE_SIZE + offset),
                    payload_len,
                );
            }
        }

        let fw_status = out_inline[0];
        if fw_status != 0 {
            let syndrome =
                u32::from_be_bytes([out_inline[4], out_inline[5], out_inline[6], out_inline[7]]);
            crate::boot_trace_cmd(opcode, "status_err", self.uid);
            log::error!(
                target: "mlx5",
                "Command failed: opcode={:?} fw_status={:#x} syndrome={:#x}",
                opcode,
                fw_status,
                syndrome
            );
            return Err(Mlx5Error::CommandFailed(fw_status));
        }

        crate::boot_trace_cmd(opcode, "done", self.uid);
        Ok(())
    }

    fn set_uid(&mut self, uid: u16) {
        self.uid = uid;
    }
    fn uid(&self) -> u16 {
        self.uid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_transport_header_only_injects_uid_for_uid_opcodes() {
        let transport = CmdQueueTransport {
            cmdq_phys: 0,
            cmdq_virt: 0,
            log_cmdq_size: 5,
            log_cmd_stride: 6,
            bar0_base: 0,
            in_mbox_virt: 0,
            out_mbox_virt: 0,
            next_token: 1,
            uid: 0x1234,
            in_snapshot: [0u8; MLX5_CMD_MBOX_SIZE],
            in_snapshot_len: 0,
        };

        let mut with_uid = CmdMailbox::zeroed();
        transport.write_transport_header(CmdOpcode::CreateSq, &mut with_uid);
        assert_eq!(with_uid.read_be16(0x00), CmdOpcode::CreateSq as u16);
        assert_eq!(with_uid.read_be16(0x02), 0x1234);

        let mut flow_table_uid = CmdMailbox::zeroed();
        transport.write_transport_header(CmdOpcode::CreateFlowTable, &mut flow_table_uid);
        assert_eq!(
            flow_table_uid.read_be16(0x00),
            CmdOpcode::CreateFlowTable as u16
        );
        assert_eq!(flow_table_uid.read_be16(0x02), 0x1234);

        let mut reserved_uid = CmdMailbox::zeroed();
        reserved_uid.write_be16(0x02, 0x55aa);
        transport.write_transport_header(CmdOpcode::QueryHcaCap, &mut reserved_uid);
        assert_eq!(reserved_uid.read_be16(0x00), CmdOpcode::QueryHcaCap as u16);
        assert_eq!(reserved_uid.read_be16(0x02), 0x55aa);

        let mut flow_no_uid = CmdMailbox::zeroed();
        flow_no_uid.write_be16(0x02, 0xbeef);
        transport.write_transport_header(CmdOpcode::CreateFlowGroup, &mut flow_no_uid);
        assert_eq!(
            flow_no_uid.read_be16(0x00),
            CmdOpcode::CreateFlowGroup as u16
        );
        assert_eq!(flow_no_uid.read_be16(0x02), 0xbeef);

        let mut rebuilt_uid = CmdMailbox::zeroed();
        rebuilt_uid.write_be16(0x02, 0xabcd);
        transport.write_transport_header(CmdOpcode::QueryVhcaState, &mut rebuilt_uid);
        assert_eq!(
            rebuilt_uid.read_be16(0x00),
            CmdOpcode::QueryVhcaState as u16
        );
        assert_eq!(rebuilt_uid.read_be16(0x02), 0xabcd);
    }

    #[test]
    fn prepare_in_block_preserves_input_payload_when_backing_overlaps_mailbox() {
        let in_len = 0x118usize;
        let payload_len = in_len - MLX5_CMD_INLINE_SIZE;
        let mut in_backing = [0u8; MLX5_CMD_MBOX_BACKING_SIZE];
        for (i, byte) in in_backing[..in_len].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
        }

        let mut expected_inline = [0u8; MLX5_CMD_INLINE_SIZE];
        expected_inline.copy_from_slice(&in_backing[..MLX5_CMD_INLINE_SIZE]);
        let mut expected_payload = [0u8; MLX5_CMD_DATA_BLOCK_SIZE];
        expected_payload[..payload_len].copy_from_slice(&in_backing[MLX5_CMD_INLINE_SIZE..in_len]);

        let transport = CmdQueueTransport {
            cmdq_phys: 0,
            cmdq_virt: 0,
            log_cmdq_size: 5,
            log_cmd_stride: 6,
            bar0_base: 0,
            in_mbox_virt: in_backing.as_mut_ptr() as u64,
            out_mbox_virt: 0,
            next_token: 1,
            uid: 0,
            in_snapshot: [0u8; MLX5_CMD_MBOX_SIZE],
            in_snapshot_len: 0,
        };

        let in_inline = unsafe {
            transport
                .prepare_in_block(0x5a, in_len, 0x2000)
                .expect("prepare_in_block")
        };
        assert_eq!(in_inline, expected_inline);

        let block = unsafe { &*CmdQueueTransport::block_ptr(transport.in_mbox_virt, 0) };
        assert_eq!(&block.data[..payload_len], &expected_payload[..payload_len]);
        assert_eq!(u64::from_be(block.next), 0);
    }

    #[test]
    fn restore_input_recovers_logical_mailbox_after_block_preparation() {
        let in_len = 0x118usize;
        let mut in_backing = [0u8; MLX5_CMD_MBOX_BACKING_SIZE];
        for (i, byte) in in_backing[..in_len].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(11).wrapping_add(5);
        }
        let mut expected = [0u8; MLX5_CMD_MBOX_SIZE];
        expected[..in_len].copy_from_slice(&in_backing[..in_len]);

        let mut transport = CmdQueueTransport {
            cmdq_phys: 0,
            cmdq_virt: 0,
            log_cmdq_size: 5,
            log_cmd_stride: 6,
            bar0_base: 0,
            in_mbox_virt: in_backing.as_mut_ptr() as u64,
            out_mbox_virt: 0,
            next_token: 1,
            uid: 0,
            in_snapshot: [0u8; MLX5_CMD_MBOX_SIZE],
            in_snapshot_len: 0,
        };

        unsafe {
            CommandTransport::snapshot_input(&mut transport, in_len as u32)
                .expect("snapshot_input");
            let _ = transport
                .prepare_in_block(0x33, in_len, 0x2000)
                .expect("prepare_in_block");
            CommandTransport::restore_input(&mut transport).expect("restore_input");
        }

        assert_eq!(&in_backing[..in_len], &expected[..in_len]);
    }
}
