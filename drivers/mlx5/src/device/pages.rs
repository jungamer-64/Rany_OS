//! Device protocol boundary for owned firmware page leases.

#![deny(unsafe_code)]

use crate::cmd::CmdMailbox;
use crate::cmd::hca::{
    build_manage_pages_input, build_query_pages_input, parse_query_pages_output,
};
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, MLX5_PAGE_SIZE};
use crate::device::Mlx5Device;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::pages::{MAX_RETURNED_PAGES, ReturnedPages};
use kernel_api::dma::{DmaAllocationRequest, DmaDirection};

impl Mlx5Device {
    /// Every page source uses device-scoped registry allocation. The page arena
    /// retains partial supply and uncertain publication; supply is one-shot and
    /// never passes through UID retry. CPU mailbox data stays on this stack.
    pub(crate) fn supply_fw_pages(&mut self, function: u16, count: u32) -> Mlx5Result<()> {
        let device = self.packed_device_id();
        let command = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        if !command.is_idle() {
            return Err(Mlx5Error::DeviceNotReady);
        }
        let pages = self
            .firmware_pages
            .as_mut()
            .ok_or(Mlx5Error::DeviceNotReady)?;
        let request = DmaAllocationRequest::new(MLX5_PAGE_SIZE, DmaDirection::Bidirectional)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let mut input = CmdMailbox::zeroed();
        let output = &mut *self.cmd_output;
        pages.supply(
            function,
            count,
            || kernel_api::service::kernel::instance().alloc_dma_for_device(request, device),
            |addresses| {
                build_manage_pages_input(
                    &mut input,
                    1,
                    function,
                    addresses.len() as u32,
                    addresses,
                );
                command
                    .execute(
                        CmdOpcode::ManagePages,
                        &input,
                        (16 + addresses.len() * 8) as u32,
                        output,
                        16,
                    )
                    .map_err(crate::error::CommandFailure::cause)
            },
        )?;
        Ok(())
    }

    pub(crate) fn query_required_pages(&mut self, op_mod: u16) -> Mlx5Result<(u16, i32)> {
        let mut input = CmdMailbox::zeroed();
        build_query_pages_input(&mut input, op_mod);
        self.execute_command(CmdOpcode::QueryPages, &input, 16, 64)?;
        Ok(parse_query_pages_output(&self.cmd_output))
    }

    /// A negative request returns pages. Every successful response advances by
    /// its validated count; failure keeps the arena's remaining capabilities.
    pub(crate) fn satisfy_fw_page_request(&mut self, function: u16, count: i32) -> Mlx5Result<()> {
        if count > 0 {
            return self.supply_fw_pages(function, count as u32);
        }
        let mut remaining = count.unsigned_abs();
        // LOOP_PROOF: mode=bounded; reason=Each response subtracts a positive validated count bounded by remaining, while zero progress or any failure exits;
        while remaining > 0 {
            let returned = self.return_fw_pages(function, remaining)?;
            if returned == 0 {
                return Err(Mlx5Error::DeviceNotReady);
            }
            remaining -= returned as u32;
        }
        Ok(())
    }

    /// PAGE_REQUEST is a recommendation, acknowledged by one MANAGE_PAGES.
    /// Supplying a bounded prefix arms the next event for any remaining demand.
    pub(crate) fn service_fw_page_event(&mut self, function: u16, count: i32) -> Mlx5Result<()> {
        if count > 0 {
            return self.supply_fw_pages(function, (count as u32).min(MAX_RETURNED_PAGES as u32));
        }
        if count < 0 {
            self.return_fw_pages(function, count.unsigned_abs())?;
            return Ok(());
        }
        let mut input = CmdMailbox::zeroed();
        build_manage_pages_input(&mut input, 1, function, 0, &[]);
        self.cmd
            .as_mut()
            .ok_or(Mlx5Error::DeviceNotReady)?
            .execute(CmdOpcode::ManagePages, &input, 16, &mut self.cmd_output, 16)?;
        Ok(())
    }

    /// Malformed/foreign returns release no prefix. A short successful return is
    /// progress, not proof that the entire requested count has been returned.
    #[expect(
        unsafe_code,
        reason = "the current one-shot firmware response is the evidence for a page return receipt"
    )]
    pub(crate) fn return_fw_pages(&mut self, function: u16, count: u32) -> Mlx5Result<usize> {
        let requested = count.min(MAX_RETURNED_PAGES as u32) as usize;
        if requested == 0 {
            return Ok(0);
        }
        let command = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut input = CmdMailbox::zeroed();
        build_manage_pages_input(&mut input, 2, function, requested as u32, &[]);
        command.execute(
            CmdOpcode::ManagePages,
            &input,
            16,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let returned = ReturnedPages::parse(&self.cmd_output.data, requested)
            .map_err(|_| Mlx5Error::InvalidResponse)?;
        let pages = self
            .firmware_pages
            .as_mut()
            .ok_or(Mlx5Error::DeviceNotReady)?;
        // SAFETY: the retained transport observed this one-shot command's
        // current token and completed ownership transfer. The arena validates
        // the complete list against this function's active leases before release.
        unsafe { pages.accept_return(function, returned) }
    }

    /// Stops at lack of progress, failed return, unknown supply or failed unmap.
    /// The arena and every remaining capability remain owned by this device.
    pub(crate) fn finish_fw_pages(&mut self) -> Mlx5Result<()> {
        // LOOP_PROOF: mode=event; reason=Each successful return removes active pages, and zero progress or any firmware/finalization failure exits;
        loop {
            let next = self
                .firmware_pages
                .as_ref()
                .and_then(|pages| pages.next_reclaim());
            let Some((function, count)) = next else { break };
            if self.return_fw_pages(function, count)? == 0 {
                return Err(Mlx5Error::DeviceNotReady);
            }
        }
        if let Some(pages) = self.firmware_pages.as_mut() {
            pages.finish()?;
        }
        Ok(())
    }
}
