//! Device protocol boundary for owned firmware page leases.

#![deny(unsafe_code)]

use crate::cmd::hca::{
    build_manage_pages_input, build_query_pages_input, parse_query_pages_output,
};
use crate::cmd::{CmdMailbox, CommandTransport};
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, MLX5_PAGE_SIZE};
use crate::device::{DeviceState, Mlx5Device};
use crate::error::{Mlx5Error, Mlx5Result};
use crate::pages::{MAX_RETURNED_PAGES, ReturnedPages};
use kernel_api::dma::{DmaAllocationRequest, DmaDirection};

impl Mlx5Device {
    /// All firmware page sources, including boot/init, use registry allocation
    /// and the same consumed lease protocol. No raw PAS input is accepted.
    ///
    /// # Safety
    /// The command interface must retain its live DMA mailboxes and BAR mapping;
    /// caller serializes command execution through this exclusive device borrow.
    ///
    /// # Errors
    /// The firmware-page owner retains partial supply and unknown outcome.
    #[expect(
        unsafe_code,
        reason = "command mailbox DMA ownership is currently established by the device startup boundary"
    )]
    pub(crate) unsafe fn supply_fw_pages(&mut self, function: u16, count: u32) -> Mlx5Result<()> {
        let device = self.packed_device_id();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        if !cmd.is_idle() {
            return Err(Mlx5Error::DeviceNotReady);
        }
        let pages = self
            .firmware_pages
            .as_mut()
            .ok_or(Mlx5Error::DeviceNotReady)?;
        let request = DmaAllocationRequest::new(MLX5_PAGE_SIZE, DmaDirection::Bidirectional)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let in_ptr = self.cmd_in_mbox_virt as *mut CmdMailbox;
        let input_address = self.cmd_in_mbox_device;
        let output_address = self.cmd_out_mbox_device;
        pages.supply(
            function,
            count,
            || kernel_api::service::kernel::instance().alloc_dma_for_device(request, device),
            |addresses| {
                // SAFETY: startup retained the mailbox; the exclusive device/command
                // borrow serializes access. Page addresses come only from descriptors
                // of armed registry leases, not caller-supplied memory authority.
                let input = unsafe { &mut *in_ptr };
                build_manage_pages_input(input, 1, function, addresses.len() as u32, addresses);
                // SAFETY: the same startup mailbox contract, bounded input length,
                // and retained page capabilities cover this one publication. Never
                // repeat MANAGE_PAGES through a UID-candidate retry loop.
                unsafe {
                    cmd.execute(
                        CmdOpcode::ManagePages,
                        input_address,
                        (16 + addresses.len() * 8) as u32,
                        output_address,
                        16,
                    )
                }
            },
        )?;
        self.state = DeviceState::PagesProvided;
        Ok(())
    }

    /// # Safety
    /// Startup retains both mailboxes and the live command queue; this exclusive
    /// borrow serializes all command accesses.
    ///
    /// # Errors
    /// Propagates the command failure; no page ownership is transferred.
    #[expect(
        unsafe_code,
        reason = "the device command boundary retains and serializes DMA mailboxes"
    )]
    pub(crate) unsafe fn query_required_pages(&mut self, op_mod: u16) -> Mlx5Result<(u16, i32)> {
        if !self
            .cmd
            .as_ref()
            .ok_or(Mlx5Error::DeviceNotReady)?
            .is_idle()
        {
            return Err(Mlx5Error::DeviceNotReady);
        }
        // SAFETY: startup mailbox lifetime/extent and exclusive borrow as above.
        let input = unsafe { &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox) };
        build_query_pages_input(input, op_mod);
        // SAFETY: retained mailbox ranges match this command's bounded lengths.
        unsafe {
            self.execute_cmd_with_uid_candidates(
                CmdOpcode::QueryPages,
                self.cmd_in_mbox_device,
                16,
                self.cmd_out_mbox_device,
                64,
            )
        }?;
        // SAFETY: successful current command completion precedes this CPU read.
        let output = unsafe { &*(self.cmd_out_mbox_virt as *const CmdMailbox) };
        Ok(parse_query_pages_output(output))
    }

    /// # Safety
    /// The startup command/mailbox contract remains live and exclusively owned.
    ///
    /// # Errors
    /// Preserves partial supplied/returned pages in the owned arena. A negative
    /// request is a return request, not an unsigned allocation count.
    #[expect(
        unsafe_code,
        reason = "dispatches device-specific firmware commands under exclusive ownership"
    )]
    pub(crate) unsafe fn satisfy_fw_page_request(
        &mut self,
        function: u16,
        count: i32,
    ) -> Mlx5Result<()> {
        if count > 0 {
            // SAFETY: forwarded live command/mailbox contract.
            unsafe { self.supply_fw_pages(function, count as u32) }
        } else if count < 0 {
            let mut remaining = count.unsigned_abs();
            // LOOP_PROOF: mode=bounded; reason=Each successful response subtracts a positive validated count no larger than remaining, zero progress or any failure exits;
            while remaining > 0 {
                // SAFETY: forwarded live command/mailbox contract. The response
                // decoder bounds the returned count by this actual request.
                let returned = unsafe { self.return_fw_pages(function, remaining) }?;
                if returned == 0 {
                    return Err(Mlx5Error::DeviceNotReady);
                }
                remaining -= returned as u32;
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    /// # Safety
    /// Startup retains the current command queue and mailbox allocations.
    /// The command transport validates current token and ownership before
    /// exposing the ordered response; command queue replacement is prohibited
    /// while this firmware-page owner exists.
    ///
    /// # Errors
    /// Malformed/foreign returns release no prefix. A short successful return is
    /// progress, not proof that the whole requested count was returned.
    #[expect(
        unsafe_code,
        reason = "firmware return completion must be interpreted at the device protocol boundary"
    )]
    pub(crate) unsafe fn return_fw_pages(
        &mut self,
        function: u16,
        count: u32,
    ) -> Mlx5Result<usize> {
        let requested = count.min(MAX_RETURNED_PAGES as u32) as usize;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        if !cmd.is_idle() {
            return Err(Mlx5Error::DeviceNotReady);
        }
        // SAFETY: startup mailbox extent/lifetime and exclusive command access.
        let input = unsafe { &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox) };
        build_manage_pages_input(input, 2, function, requested as u32, &[]);
        // SAFETY: retained live command/mailboxes; output fits the mailbox. This
        // is one command, never an unknown-outcome retry across UID candidates.
        unsafe {
            cmd.execute(
                CmdOpcode::ManagePages,
                self.cmd_in_mbox_device,
                16,
                self.cmd_out_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
            )
        }?;
        // SAFETY: transport observed ordered, successful current completion.
        let output = unsafe { &*(self.cmd_out_mbox_virt as *const CmdMailbox) };
        let returned = ReturnedPages::parse(&output.data, requested)
            .map_err(|_| Mlx5Error::InvalidResponse)?;
        let pages = self
            .firmware_pages
            .as_mut()
            .ok_or(Mlx5Error::DeviceNotReady)?;
        // SAFETY: successful one-shot current MANAGE_PAGES command returned this
        // function's pages. The arena additionally validates the complete list
        // against its exact active leases before consuming any receipt.
        unsafe { pages.accept_return(function, returned) }
    }

    /// # Safety
    /// The current command/mailbox contract remains live until all returned
    /// pages have passed their explicit fallible close boundary.
    ///
    /// # Errors
    /// Stops on lack of progress, failed return, unknown supply or failed unmap.
    /// The arena and every remaining capability stay owned by this device.
    #[expect(
        unsafe_code,
        reason = "device-specific return commands precede registry-owned finalization"
    )]
    pub(crate) unsafe fn finish_fw_pages(&mut self) -> Mlx5Result<()> {
        // LOOP_PROOF: mode=event; reason=Each successful return removes active pages, a zero return or any firmware/finalization failure exits;
        loop {
            let next = self
                .firmware_pages
                .as_ref()
                .and_then(|pages| pages.next_reclaim());
            let Some((function, count)) = next else { break };
            // SAFETY: retained current command/mailboxes as above.
            if unsafe { self.return_fw_pages(function, count) }? == 0 {
                return Err(Mlx5Error::DeviceNotReady);
            }
        }
        if let Some(pages) = self.firmware_pages.as_mut() {
            pages.finish()?;
        }
        Ok(())
    }
}
