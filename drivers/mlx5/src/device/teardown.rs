// ============================================================================
// drivers/mlx5/src/device/teardown.rs - MLX5 Device Teardown
// ============================================================================

extern crate alloc;
use crate::cmd::CmdMailbox;
use crate::cmd::CommandTransport;
use crate::cmd::flow::*; // flow-related command builders
use crate::cmd::hca::*; // HCA lifecycle commands
use crate::cmd::queues::*; // queue-related command builders
use crate::cmd::res::*; // resource-management commands (dealloc etc)
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE};
use crate::device::{DeviceState, Mlx5Device};
use crate::error::Mlx5Result;
use alloc::vec::Vec; // bring execute() method into scope

impl Mlx5Device {
    pub unsafe fn teardown_full(&mut self) -> Mlx5Result<()> {
        log::info!(target: "mlx5", "=== Starting full teardown sequence ===");

        // 1. パケット送受信の停止
        let sqns: Vec<u32> = self.sqs.iter().map(|sq| sq.sqn).collect();
        for sqn in sqns {
            let _ = self.transition_sq_to_error(sqn);
        }
        let rqns: Vec<u32> = self.rqs.iter().map(|rq| rq.rqn).collect();
        for rqn in rqns {
            let _ = self.transition_rq_to_error(rqn);
        }

        // 2. フローテーブルの破棄
        let entries = core::mem::take(&mut self.flow_entries);
        for entry in entries {
            let _ = self.delete_flow_table_entry_hw(entry.table_id, entry.index);
        }
        let groups = core::mem::take(&mut self.flow_groups);
        for group in groups {
            let _ = self.destroy_flow_group_hw(group.table_id, group.group_id);
        }
        let tables = core::mem::take(&mut self.flow_tables);
        for table in tables {
            let _ = self.destroy_flow_table_hw(table.table_id);
        }

        // 3. TIR / TIS / RQT の破棄
        let tir_list = core::mem::take(&mut self.tir_list);
        for tir in tir_list {
            let _ = self.destroy_tir_hw(tir.tirn);
        }
        let tis_list = core::mem::take(&mut self.tis_list);
        for tis in tis_list {
            let _ = self.destroy_tis_hw(tis.tisn);
        }
        let rq_tables = core::mem::take(&mut self.rq_tables);
        for rqt in rq_tables {
            let _ = self.destroy_rqt_hw(rqt.rqtn);
        }

        // 4. SQ / RQ / CQ / EQ の破棄
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(sq) = self.sqs.pop() {
            let _ = self.destroy_sq_hw(sq.sqn);
        }
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(rq) = self.rqs.pop() {
            let _ = self.destroy_rq_hw(rq.rqn);
        }
        while let Some(rmpn) = self.rmp_list.pop() {
            let _ = self.destroy_rmp_hw(rmpn);
        }
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(cq) = self.cqs.pop() {
            let _ = self.destroy_cq_hw(cq.cqn);
        }
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(eq) = self.eqs.pop() {
            let _ = self.destroy_eq_hw(eq.eqn);
        }
        self.tx_cq_by_sq.clear();
        self.rx_cq_by_rq.clear();

        // 5. MKEY & PD / TD / UAR
        if let Some(info) = self.mkey_info.take() {
            let _ = self.destroy_mkey_hw(info.mkey_index);
        }
        if self.pd != 0 {
            let _ = self.dealloc_pd_hw(self.pd);
            self.pd = 0;
        }
        if self.td != 0 {
            let _ = self.dealloc_td_hw(self.td);
            self.td = 0;
        }
        // LOOP_PROOF: mode=condition; reason=Loop termination is governed by the while condition and exits when it becomes false.;
        while let Some(uar) = self.allocated_uars.pop() {
            let _ = self.dealloc_uar_hw(uar);
        }

        // 6. HCA Teardown & Disable
        let _ = self.teardown_hca_hw(true);
        let _ = self.disable_hca_hw();

        // 7. FW ページの回収
        let total_pages = self.page_manager.total_given_pages();
        if total_pages > 0 {
            let _ = self.reclaim_pages(self.fw_function_id, total_pages as u32);
        }

        self.state = DeviceState::Uninitialized;
        self.resources_allocated = false;
        Ok(())
    }

    pub unsafe fn destroy_sq_hw(&mut self, sqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_destroy_sq_input(in_mbox, sqn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroySq,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    // ... added more destroy helpers as needed
    pub unsafe fn destroy_rq_hw(&mut self, rqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_destroy_rq_input(in_mbox, rqn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyRq,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn destroy_rmp_hw(&mut self, rmpn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_destroy_rmp_input(in_mbox, rmpn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyRmp,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn destroy_cq_hw(&mut self, cqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_destroy_cq_input(in_mbox, cqn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyCq,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn destroy_eq_hw(&mut self, eqn: u32) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_destroy_eq_input(in_mbox, eqn);
        cmd.execute(
            CmdOpcode::DestroyEq,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn destroy_tir_hw(&mut self, tirn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be32(0x04, tirn & 0x00FF_FFFF);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyTir,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn destroy_tis_hw(&mut self, tisn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be32(0x04, tisn & 0x00FF_FFFF);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyTis,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn destroy_rqt_hw(&mut self, rqtn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_destroy_rqt_input(in_mbox, rqtn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyRqt,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn destroy_flow_table_hw(&mut self, table_id: u32) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_destroy_flow_table_input(in_mbox, table_id);
        cmd.execute(
            CmdOpcode::DestroyFlowTable,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn destroy_flow_group_hw(&mut self, table_id: u32, group_id: u32) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_destroy_flow_group_input(in_mbox, table_id, group_id);
        cmd.execute(
            CmdOpcode::DestroyFlowGroup,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn delete_flow_table_entry_hw(
        &mut self,
        table_id: u32,
        flow_index: u32,
    ) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_delete_flow_table_entry_input(in_mbox, table_id, flow_index);
        cmd.execute(
            CmdOpcode::DeleteFlowTableEntry,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn destroy_mkey_hw(&mut self, mkey_index: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be32(0x04, mkey_index & 0x00FF_FFFF);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyMkey,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn dealloc_pd_hw(&mut self, pd: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_dealloc_pd_input(in_mbox, pd);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DeallocPd,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn dealloc_td_hw(&mut self, td: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_dealloc_td_input(in_mbox, td);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DeallocTransportDomain,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn dealloc_uar_hw(&mut self, uar_page: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_dealloc_uar_input(in_mbox, uar_page);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DeallocUar,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn teardown_hca_hw(&mut self, graceful: bool) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_teardown_hca_input(in_mbox, graceful);
        cmd.execute(
            CmdOpcode::TeardownHca,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn disable_hca_hw(&mut self) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        *in_mbox = CmdMailbox::zeroed();
        cmd.execute(
            CmdOpcode::DisableHca,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn transition_sq_to_error(&mut self, sqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_modify_sq_input(
            in_mbox,
            sqn,
            crate::defs::WqState::Ready as u8,
            crate::defs::WqState::Error as u8,
        );
        self.execute_uid_sensitive_cmd(
            CmdOpcode::ModifySq,
            0x110,
            0x10,
        )?;
        Ok(())
    }

    pub unsafe fn transition_rq_to_error(&mut self, rqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_modify_rq_input(
            in_mbox,
            rqn,
            crate::defs::WqState::Ready as u8,
            crate::defs::WqState::Error as u8,
        );
        self.execute_uid_sensitive_cmd(
            CmdOpcode::ModifyRq,
            0x110,
            0x10,
        )?;
        Ok(())
    }
}
