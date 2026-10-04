//! One synchronous command slot. Mailbox staging is ordinary CPU memory;
//! descriptor accesses use retained shared leases and scalar registry visits.

#![deny(unsafe_code)]

use super::{CmdEntry, CmdMailbox, memory::CommandMemory, wire};
use crate::defs::{
    CmdOpcode, MLX5_CMD_DATA_BLOCK_SIZE, MLX5_CMD_INLINE_SIZE, MLX5_CMD_PROT_BLOCK_ALIGN,
};
use crate::error::{CommandFailure, Mlx5Error, Mlx5Result};
use crate::regs::cmd_entry;
use core::sync::atomic::{Ordering, fence};
use kernel_api::dma::{CpuDmaLease, DmaQueueIdentity};

#[derive(Clone, Copy, PartialEq, Eq)]
enum CommandState {
    Unpublished,
    Idle,
    /// Registry/descriptor failure before this command's owner publication.
    StagingFailed,
    Pending {
        token: u8,
    },
    OutcomeUnknown {
        token: u8,
    },
    Released,
}

/// Owns command RAM through preparation, publication, completion and uncertain
/// outcome. CPU mailbox references never point into these allocations.
pub struct CmdQueue {
    registers: crate::registers::CommandRegisters,
    memory: CommandMemory,
    state: CommandState,
    next_token: u8,
    uid: u16,
}

impl CmdQueue {
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
                | CmdOpcode::QueryMkey
                | CmdOpcode::QuerySpecialContexts
                | CmdOpcode::QuerySq
                | CmdOpcode::QueryRq
                | CmdOpcode::QueryTis
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

    pub(crate) fn new(
        registers: crate::registers::CommandRegisters,
        identity: DmaQueueIdentity,
        leases: [CpuDmaLease; 3],
    ) -> Self {
        Self {
            registers,
            memory: CommandMemory::new(identity, leases),
            state: CommandState::Unpublished,
            next_token: 1,
            uid: 0,
        }
    }

    /// Store this owner in the device before calling initialize: any preparation
    /// failure then remains available for explicit unpublished retirement.
    pub(crate) fn initialize(&mut self, log_size: u8, log_stride: u8) -> Mlx5Result<()> {
        if self.state != CommandState::Unpublished || log_size == 0 || log_stride != 6 {
            return Err(Mlx5Error::InvalidParameter);
        }
        let bytes = 1usize
            .checked_shl(u32::from(log_size))
            .and_then(|entries| entries.checked_mul(cmd_entry::ENTRY_SIZE))
            .ok_or(Mlx5Error::NotSupported)?;
        self.memory.prepare(bytes)?;
        let address = self.memory.address(0)?.get();
        // Publication cannot fail after preparation. Change the state before
        // either external write; no recovery path can claim "unpublished".
        self.state = CommandState::Idle;
        self.registers
            .program_address((address >> 32) as u32, address as u32);
        Ok(())
    }

    /// # Errors
    /// Published or uncertain command RAM requires device stop/reset evidence.
    /// A failed unmap keeps its quarantine owner in this transport.
    #[expect(
        unsafe_code,
        reason = "only the unpublished state authorizes pre-publication RAM retirement"
    )]
    pub(crate) fn close_unpublished(&mut self) -> Mlx5Result<()> {
        match self.state {
            CommandState::Released => return Ok(()),
            CommandState::Unpublished => {}
            _ => return Err(Mlx5Error::CommandTransportBusy),
        }
        // SAFETY: Unpublished is consumed before the first command address write;
        // this owner never exposes its descriptors to another protocol owner.
        unsafe { self.memory.close_unpublished() }?;
        self.state = CommandState::Released;
        Ok(())
    }

    pub(crate) fn is_idle(&self) -> bool {
        self.state == CommandState::Idle
    }

    pub fn set_uid(&mut self, uid: u16) {
        self.uid = uid;
    }
    pub fn uid(&self) -> u16 {
        self.uid
    }

    pub fn parse_hw_cmdq_layout(value: u32) -> (u8, u8, bool) {
        (
            ((value >> 4) & 0xf) as u8,
            (value & 0xf) as u8,
            value & crate::regs::fw_state::NIC_INTERFACE_SUPPORTED_BIT != 0,
        )
    }

    fn next_block(&self, region: usize, index: usize, count: usize) -> Mlx5Result<u64> {
        if index + 1 == count {
            return Ok(0);
        }
        self.memory
            .address(region)?
            .checked_add((index + 1) * MLX5_CMD_PROT_BLOCK_ALIGN)
            .map(|address| address.get())
            .ok_or(Mlx5Error::InvalidParameter)
    }

    fn prepare_mailboxes(
        &mut self,
        opcode: CmdOpcode,
        input: &CmdMailbox,
        in_len: usize,
        out_len: usize,
        token: u8,
    ) -> Mlx5Result<[u8; MLX5_CMD_INLINE_SIZE]> {
        let mut inline = [0; MLX5_CMD_INLINE_SIZE];
        let inline_len = in_len.min(MLX5_CMD_INLINE_SIZE);
        inline[..inline_len].copy_from_slice(&input.data[..inline_len]);
        inline[..2].copy_from_slice(&(opcode as u16).to_be_bytes());
        if Self::opcode_uses_uid(opcode) {
            inline[2..4].copy_from_slice(&self.uid.to_be_bytes());
        }
        let count = wire::block_count(in_len);
        for index in 0..count {
            let offset = MLX5_CMD_INLINE_SIZE + index * MLX5_CMD_DATA_BLOCK_SIZE;
            let end = (offset + MLX5_CMD_DATA_BLOCK_SIZE).min(in_len);
            let block = wire::input_block(
                &input.data[offset..end],
                self.next_block(1, index, count)?,
                index as u32,
                token,
            )?;
            self.memory
                .write(1, index * MLX5_CMD_PROT_BLOCK_ALIGN, &block)?;
        }
        let count = wire::block_count(out_len);
        for index in 0..count {
            let block = wire::output_block(self.next_block(2, index, count)?, index as u32, token);
            self.memory
                .write(2, index * MLX5_CMD_PROT_BLOCK_ALIGN, &block)?;
        }
        Ok(inline)
    }

    fn finish_output(
        &mut self,
        entry: &CmdEntry,
        output: &mut CmdMailbox,
        length: usize,
        token: u8,
    ) -> Mlx5Result<()> {
        output.data.fill(0);
        let inline = length.min(MLX5_CMD_INLINE_SIZE);
        output.data[..inline]
            .copy_from_slice(&entry.raw[cmd_entry::OUT_INLINE..cmd_entry::OUT_INLINE + inline]);
        let count = wire::block_count(length);
        for index in 0..count {
            let block = self
                .memory
                .read::<{ wire::BLOCK_BYTES }>(2, index * MLX5_CMD_PROT_BLOCK_ALIGN)?;
            if !wire::valid_output(
                &block,
                self.next_block(2, index, count)?,
                index as u32,
                token,
            ) {
                return Err(Mlx5Error::InvalidResponse);
            }
            let offset = MLX5_CMD_INLINE_SIZE + index * MLX5_CMD_DATA_BLOCK_SIZE;
            let bytes = (length - offset).min(MLX5_CMD_DATA_BLOCK_SIZE);
            output.data[offset..offset + bytes].copy_from_slice(&block[..bytes]);
        }
        Ok(())
    }

    /// Execute one command against CPU-owned logical mailboxes. Completion
    /// requires a cleared ownership bit and the current token. Timeout, RAM
    /// access failure, or malformed completion closes further admission and
    /// keeps every DMA capability; it cannot be retried as a UID rejection.
    ///
    /// # Errors
    /// Rejects an occupied slot, unsupported lengths, registry access failure,
    /// timeout, delivery failure, or firmware status. Output is meaningful only
    /// after a token-validated response; callers must check this result first.
    pub fn execute(
        &mut self,
        opcode: CmdOpcode,
        input: &CmdMailbox,
        in_len: u32,
        output: &mut CmdMailbox,
        out_len: u32,
    ) -> Result<(), CommandFailure> {
        if !self.is_idle() {
            return Err(CommandFailure::NotPublished(Mlx5Error::DeviceNotReady));
        }
        let in_bytes = wire::checked_length(in_len).map_err(CommandFailure::NotPublished)?;
        let out_bytes = wire::checked_length(out_len).map_err(CommandFailure::NotPublished)?;
        let token = self.next_token;
        self.next_token = if token == u8::MAX { 1 } else { token + 1 };
        let owner = match self.memory.read_byte(0, cmd_entry::STATUS_OWN) {
            Ok(owner) => owner,
            Err(cause) => {
                self.state = CommandState::StagingFailed;
                return Err(CommandFailure::NotPublished(cause));
            }
        };
        if owner & 1 != 0 {
            self.state = CommandState::OutcomeUnknown { token };
            return Err(CommandFailure::NotPublished(Mlx5Error::DeviceNotReady));
        }
        // Registry failures during staging close admission but do not claim
        // that this command reached the hardware. A new owner byte is the
        // separate publication boundary below.
        self.state = CommandState::StagingFailed;
        let inline = self
            .prepare_mailboxes(opcode, input, in_bytes, out_bytes, token)
            .map_err(CommandFailure::NotPublished)?;
        let mut entry = CmdEntry::zeroed();
        if in_bytes > MLX5_CMD_INLINE_SIZE {
            entry.set_input_mailbox(
                self.memory
                    .address(1)
                    .map_err(CommandFailure::NotPublished)?
                    .get(),
            );
        }
        if out_bytes > MLX5_CMD_INLINE_SIZE {
            entry.set_output_mailbox(
                self.memory
                    .address(2)
                    .map_err(CommandFailure::NotPublished)?
                    .get(),
            );
        }
        entry.set_input_length(in_len);
        entry.set_output_length(out_len);
        entry.set_input_inline(&inline);
        entry.submit(token);
        // The owner byte is the publication point. All other fields and the
        // signature computed for owner=1 precede it. Even a failing write at
        // that point retains Pending/OutcomeUnknown, never Idle.
        self.memory
            .write(0, 0, &entry.raw[..cmd_entry::STATUS_OWN])
            .map_err(CommandFailure::NotPublished)?;
        self.state = CommandState::Pending { token };
        let result = self.publish_and_wait(opcode, output, out_bytes, token);
        match result {
            Ok(()) | Err(Mlx5Error::CommandFailed(_)) => self.state = CommandState::Idle,
            Err(_) => self.state = CommandState::OutcomeUnknown { token },
        }
        match result {
            Ok(()) => Ok(()),
            Err(Mlx5Error::CommandFailed(status)) => Err(CommandFailure::Rejected(status)),
            Err(cause) => Err(CommandFailure::OutcomeUnknown(cause)),
        }
    }

    fn publish_and_wait(
        &mut self,
        opcode: CmdOpcode,
        output: &mut CmdMailbox,
        out_bytes: usize,
        token: u8,
    ) -> Mlx5Result<()> {
        fence(Ordering::Release);
        self.memory.write_byte(0, cmd_entry::STATUS_OWN, 1)?;
        fence(Ordering::Release);
        self.registers.submit_slot_zero();
        let start = kernel_api::service::kernel::instance().current_tick();
        // LOOP_PROOF: mode=condition; reason=The finite read budget also terminates before clock initialization; a current cleared owner exits normally and timeout retains all command RAM;
        for _ in 0..50_000_000u32 {
            if self.memory.read_byte(0, cmd_entry::STATUS_OWN)? & 1 == 0 {
                fence(Ordering::Acquire);
                let entry = CmdEntry {
                    raw: self.memory.read(0, 0)?,
                };
                if entry.is_owned_by_hw() || entry.raw[cmd_entry::TOKEN] != token {
                    return Err(Mlx5Error::InvalidResponse);
                }
                if entry.delivery_status_raw() != 0 {
                    return Err(Mlx5Error::CommandDelivery(entry.delivery_status_raw()));
                }
                self.finish_output(&entry, output, out_bytes, token)?;
                if output.data[0] != 0 {
                    crate::boot_trace_cmd_error(
                        opcode,
                        self.uid,
                        output.data[0],
                        output.read_be32(4),
                    );
                    return Err(Mlx5Error::CommandFailed(output.data[0]));
                }
                return Ok(());
            }
            if kernel_api::service::kernel::instance()
                .current_tick()
                .saturating_sub(start)
                >= 5_000
            {
                return Err(Mlx5Error::CommandTimeout);
            }
            core::hint::spin_loop();
        }
        Err(Mlx5Error::CommandTimeout)
    }
}
