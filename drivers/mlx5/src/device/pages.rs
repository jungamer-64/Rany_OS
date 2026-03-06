// ============================================================================
// drivers/mlx5/src/device/pages.rs - FW Page Management
// ============================================================================

extern crate alloc;
use crate::cmd::CmdMailbox;
use crate::cmd::hca::*;
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE};
use crate::device::Mlx5Device;
use crate::error::{Mlx5Error, Mlx5Result};
use alloc::vec::Vec; // manage/query page commands

impl Mlx5Device {
    /// FW ページを提供
    pub unsafe fn provide_pages(&mut self, function_id: u16, pas: &[u64]) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        log::info!(target: "mlx5", "Providing {} pages to function {}", pas.len(), function_id);

        build_manage_pages_input(
            in_mbox,
            crate::pages::ManagePagesOp::GivePages as u8,
            function_id,
            pas.len() as u32,
            pas,
        );

        let in_len = (0x10 + (pas.len().min(crate::pages::MAX_PAS_PER_MBOX)) * 8) as u32;
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::ManagePages,
            self.cmd_in_mbox_device,
            in_len,
            self.cmd_out_mbox_device,
            16,
        )?;

        log::info!(target: "mlx5", "Pages provided successfully");
        Ok(())
    }

    /// QUERY_PAGES で必要ページ数を確認し、要求に応じて提供/回収を行う
    pub unsafe fn handle_page_requests(&mut self, op_mod: u16) -> Mlx5Result<()> {
        let (func_id, num_pages) = self.query_required_pages(op_mod)?;
        if num_pages == 0 {
            return Ok(());
        }

        if num_pages > 0 {
            let mut page_pas = Vec::with_capacity(num_pages as usize);
            for _ in 0..num_pages {
                let buf = kernel_api::service::kernel::instance()
                    .alloc_dma(4096)
                    .map_err(|_| Mlx5Error::DmaAllocFailed)?;

                let pa = buf.device_address();
                let va = buf.as_ptr() as u64;

                self.page_manager
                    .record_allocation(crate::pages::PageAllocation {
                        phys_addr: pa,
                        virt_addr: va,
                        function_id: func_id,
                    });
                page_pas.push(pa);
            }

            self.give_pages_internal(func_id, &page_pas)?;
        } else {
            self.reclaim_pages(func_id, num_pages.unsigned_abs())?;
        }

        Ok(())
    }

    unsafe fn give_pages_internal(&mut self, function_id: u16, pas: &[u64]) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        build_manage_pages_input(
            in_mbox,
            crate::pages::ManagePagesOp::GivePages as u8,
            function_id,
            pas.len() as u32,
            pas,
        );

        let in_len = (0x10 + pas.len() * 8) as u32;
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::ManagePages,
            self.cmd_in_mbox_device,
            in_len,
            self.cmd_out_mbox_device,
            16,
        )?;
        Ok(())
    }

    pub unsafe fn query_required_pages(&mut self, op_mod: u16) -> Mlx5Result<(u16, i32)> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_pages_input(in_mbox, op_mod);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::QueryPages,
            self.cmd_in_mbox_device,
            16,
            self.cmd_out_mbox_device,
            64,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let res = parse_query_pages_output(out_mbox);
        log::info!(target: "mlx5", "QUERY_PAGES(op={:#x}): func_id={:#x} num_pages={}", op_mod, res.0, res.1);
        Ok(res)
    }

    pub unsafe fn reclaim_pages(&mut self, function_id: u16, num_pages: u32) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;

        log::info!(
            target: "mlx5",
            "Reclaiming {} pages from FW (function_id={})",
            num_pages, function_id
        );

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_manage_pages_input(
            in_mbox,
            crate::pages::ManagePagesOp::ReclaimPages as u8,
            function_id,
            num_pages,
            &[],
        );

        self.execute_cmd_with_uid_candidates(
            CmdOpcode::ManagePages,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        log::info!(target: "mlx5", "Reclaimed pages from FW");
        Ok(())
    }
}
