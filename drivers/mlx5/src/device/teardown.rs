// ============================================================================
// drivers/mlx5/src/device/teardown.rs - MLX5 Device Teardown
// ============================================================================

extern crate alloc;
use crate::cmd::CmdMailbox;
use crate::cmd::flow::*; // flow-related command builders
use crate::cmd::hca::*; // HCA lifecycle commands
use crate::cmd::queues::*; // queue-related command builders
use crate::cmd::res::*; // resource-management commands (dealloc etc)
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE};
use crate::device::{DeviceState, Mlx5Device};
use crate::error::Mlx5Result;

impl Mlx5Device {
    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    /// Completed releases remove their inventory entry; any failure retains
    /// the entire unreleased suffix. An unknown command outcome blocks a new
    /// attempt before mailbox mutation. Reset/reconciliation remains separate.
    ///
    /// # Safety
    /// The device's command and queue DMA must remain retained throughout this
    /// finalization, including its error return. The caller must exclude every
    /// TX/RX/interrupt entry before starting, and may reclaim backing only after
    /// its separate lease close/quiescence protocol succeeds.
    #[deny(unsafe_op_in_unsafe_fn)]
    pub unsafe fn teardown_full(&mut self) -> Mlx5Result<()> {
        if self.firmware_pages.is_none() {
            // Failed command construction has no hardware consumer. Retire the
            // actual preparation prefix before dropping its retained MMIO owner.
            if let Some(command) = self.cmd.as_mut() {
                command.close_unpublished()?;
            }
            self.cmd = None;
            self.state = DeviceState::Uninitialized;
            return Ok(());
        }
        let command = self
            .cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        if !command.is_idle() {
            return Err(crate::error::Mlx5Error::DeviceNotReady);
        }
        self.tx_path_enabled = false;
        for index in 0..self.sqs.len() {
            let number = self.sqs[index].sqn;
            // SAFETY: the caller retains SQ backing and excludes all queue users
            // as required by this finalizer's contract, including on failure.
            unsafe { self.transition_sq_to_error(number) }?;
        }
        for index in 0..self.rqs.len() {
            let number = self.rqs[index].rqn;
            // SAFETY: the caller retains RQ backing and excludes all queue users
            // as required by this finalizer's contract, including on failure.
            unsafe { self.transition_rq_to_error(number) }?;
        }

        // LOOP_PROOF: mode=condition; reason=Each successful hardware release removes exactly one owned entry, failure returns with the remainder retained.;
        while let Some(entry) = self.flow_entries.last() {
            let (table, index) = (entry.table_id, entry.index);
            // SAFETY: this device still owns the entry and its parent table.
            unsafe { self.delete_flow_table_entry_hw(table, index) }?;
            self.flow_entries.pop();
        }
        // LOOP_PROOF: mode=condition; reason=Success removes one group, failure retains the unreleased suffix.;
        while let Some(group) = self.flow_groups.last() {
            let (table, group) = (group.table_id, group.group_id);
            // SAFETY: all owned entries were removed before their parent group.
            unsafe { self.destroy_flow_group_hw(table, group) }?;
            self.flow_groups.pop();
        }
        // LOOP_PROOF: mode=condition; reason=Success removes one table, failure retains the unreleased suffix.;
        while let Some(table) = self.flow_tables.last() {
            let table = table.table_id;
            // SAFETY: the table's owned groups and entries were released first.
            unsafe { self.destroy_flow_table_hw(table) }?;
            self.flow_tables.pop();
        }
        // LOOP_PROOF: mode=condition; reason=Success removes one TIR, failure retains its ownership entry.;
        while let Some(tir) = self.tir_list.last() {
            let number = tir.tirn;
            // SAFETY: flows were released before the owned TIR.
            unsafe { self.destroy_tir_hw(number) }?;
            self.tir_list.pop();
        }
        // LOOP_PROOF: mode=condition; reason=An owned TIS is removed only after release, borrowed TIS entries surrender no hardware ownership.;
        while let Some(tis) = self.tis_list.last() {
            let (number, owned) = (tis.tisn, tis.destroy_on_teardown());
            if owned {
                // SAFETY: only an owned firmware grant is destroyed.
                unsafe { self.destroy_tis_hw(number) }?;
            }
            self.tis_list.pop();
        }
        // LOOP_PROOF: mode=condition; reason=Success removes one RQT, failure retains the unreleased suffix.;
        while let Some(table) = self.rq_tables.last() {
            let number = table.rqtn;
            // SAFETY: TIR references were removed before this owned RQT.
            unsafe { self.destroy_rqt_hw(number) }?;
            self.rq_tables.pop();
        }
        // LOOP_PROOF: mode=condition; reason=Success destroys one SQ before dropping its retained doorbell, failure retains both.;
        while let Some(sq) = self.sqs.last() {
            let number = sq.sqn;
            // SAFETY: the SQ backing and UAR grant remain retained until this completion.
            unsafe { self.destroy_sq_hw(number) }?;
            self.sqs.pop();
        }
        // LOOP_PROOF: mode=condition; reason=Success destroys one RQ before removing its entry, failure retains it.;
        while let Some(rq) = self.rqs.last() {
            let number = rq.rqn;
            // SAFETY: the RQ backing remains retained until this completion.
            unsafe { self.destroy_rq_hw(number) }?;
            self.rqs.pop();
        }
        // LOOP_PROOF: mode=condition; reason=Success destroys one RMP before removing its entry, failure retains it.;
        while let Some(&number) = self.rmp_list.last() {
            // SAFETY: all RQ consumers were destroyed before the owned RMP.
            unsafe { self.destroy_rmp_hw(number) }?;
            self.rmp_list.pop();
        }
        // LOOP_PROOF: mode=condition; reason=Success destroys one CQ before dropping its retained doorbell, failure retains both.;
        while let Some(cq) = self.cqs.last() {
            let number = cq.cqn;
            // SAFETY: SQ/RQ consumers were destroyed and CQ DMA/UAR are still retained.
            unsafe { self.destroy_cq_hw(number) }?;
            self.cqs.pop();
        }
        // LOOP_PROOF: mode=condition; reason=Success destroys one EQ before dropping its retained doorbell, failure retains both.;
        while let Some(eq) = self.eqs.last() {
            let number = eq.eqn;
            // SAFETY: CQ consumers were destroyed and EQ DMA/UAR are still retained.
            unsafe { self.destroy_eq_hw(number) }?;
            self.eqs.pop();
        }
        self.tx_cq_by_sq.clear();
        self.rx_cq_by_rq.clear();

        if let Some(info) = self.mkey_info.as_ref() {
            let index = info.mkey_index;
            // SAFETY: all DMA queues using the owned MKEY were destroyed first.
            unsafe { self.destroy_mkey_hw(index) }?;
            self.mkey_info = None;
        }
        if self.underlay_qpn != 0 {
            // SAFETY: the stored QP is an owned firmware grant retained on failure.
            unsafe { self.destroy_qp_hw(self.underlay_qpn) }?;
            self.underlay_qpn = 0;
        }
        if self.pd != 0 {
            // SAFETY: owned PD consumers were destroyed before this release.
            unsafe { self.dealloc_pd_hw(self.pd) }?;
            self.pd = 0;
        }
        if self.td != 0 {
            // SAFETY: owned TD consumers were destroyed before this release.
            unsafe { self.dealloc_td_hw(self.td) }?;
            self.td = 0;
        }
        // LOOP_PROOF: mode=condition; reason=The checked release consumes one recorded UAR only after a known completion, failure keeps its UID and grant.;
        while !self.allocated_uars.is_empty() {
            // SAFETY: this finalizer retains command DMA and all queues are destroyed.
            unsafe { self.release_last_uar() }?;
        }
        // SAFETY: queue teardown succeeded, command DMA and firmware page leases remain live.
        unsafe { self.teardown_hca_hw(true) }?;
        self.finish_fw_pages()?;
        // SAFETY: the firmware pages were successfully returned before HCA disable.
        unsafe { self.disable_hca_hw() }?;
        self.state = DeviceState::Uninitialized;
        self.resources_allocated = false;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_sq_hw(&mut self, sqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_destroy_sq_input(in_mbox, sqn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroySq,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    // ... added more destroy helpers as needed
    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_rq_hw(&mut self, rqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_destroy_rq_input(in_mbox, rqn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyRq,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_rmp_hw(&mut self, rmpn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_destroy_rmp_input(in_mbox, rmpn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyRmp,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_cq_hw(&mut self, cqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_destroy_cq_input(in_mbox, cqn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyCq,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_eq_hw(&mut self, eqn: u32) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_destroy_eq_input(in_mbox, eqn);
        cmd.execute(
            CmdOpcode::DestroyEq,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_tir_hw(&mut self, tirn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be32(0x04, tirn & 0x00FF_FFFF);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyTir,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_tis_hw(&mut self, tisn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be32(0x04, tisn & 0x00FF_FFFF);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyTis,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_qp_hw(&mut self, qpn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_destroy_qp_input(in_mbox, qpn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyQp,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_rqt_hw(&mut self, rqtn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_destroy_rqt_input(in_mbox, rqtn);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyRqt,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_flow_table_hw(&mut self, table_id: u32) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_destroy_flow_table_input(in_mbox, table_id);
        cmd.execute(
            CmdOpcode::DestroyFlowTable,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_flow_group_hw(&mut self, table_id: u32, group_id: u32) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_destroy_flow_group_input(in_mbox, table_id, group_id);
        cmd.execute(
            CmdOpcode::DestroyFlowGroup,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn delete_flow_table_entry_hw(
        &mut self,
        table_id: u32,
        flow_index: u32,
    ) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_delete_flow_table_entry_input(in_mbox, table_id, flow_index);
        cmd.execute(
            CmdOpcode::DeleteFlowTableEntry,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn destroy_mkey_hw(&mut self, mkey_index: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        *in_mbox = CmdMailbox::zeroed();
        in_mbox.write_be32(0x04, mkey_index & 0x00FF_FFFF);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DestroyMkey,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn dealloc_pd_hw(&mut self, pd: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_dealloc_pd_input(in_mbox, pd);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DeallocPd,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn dealloc_td_hw(&mut self, td: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_dealloc_td_input(in_mbox, td);
        self.execute_uid_sensitive_cmd(
            CmdOpcode::DeallocTransportDomain,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    /// Releases the recorded grant under its allocating UID, never by an
    /// ambient page number. Doorbell authority is removed only on completion.
    #[deny(unsafe_op_in_unsafe_fn)]
    unsafe fn release_last_uar(&mut self) -> Mlx5Result<()> {
        use crate::error::Mlx5Error;
        if !self.sqs.is_empty()
            || !self.rqs.is_empty()
            || !self.rmp_list.is_empty()
            || !self.cqs.is_empty()
            || !self.eqs.is_empty()
        {
            return Err(Mlx5Error::DeviceNotReady);
        }
        let Some(allocation) = self.allocated_uars.last() else {
            return Ok(());
        };
        let (number, uid) = (allocation.number, allocation.uid);
        let command = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        if !command.is_idle() {
            return Err(Mlx5Error::DeviceNotReady);
        }
        let previous_uid = command.uid();
        command.set_uid(uid);
        // SAFETY: this finalizer retains writable command DMA and admitted an idle slot.
        let mut command_input = CmdMailbox::zeroed();
        let input = &mut command_input;
        build_dealloc_uar_input(input, number);
        let result = command.execute(
            CmdOpcode::DeallocUar,
            input,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        );
        command.set_uid(previous_uid);
        result?;
        if self.uar.as_ref().is_some_and(|uar| uar.number() == number) {
            self.uar = None;
        }
        self.allocated_uars.pop();
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the resource is invalid, still in use, or cannot be released.
    pub unsafe fn teardown_hca_hw(&mut self, graceful: bool) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_teardown_hca_input(in_mbox, graceful);
        cmd.execute(
            CmdOpcode::TeardownHca,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub unsafe fn disable_hca_hw(&mut self) -> Mlx5Result<()> {
        let cmd = self
            .cmd
            .as_mut()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        *in_mbox = CmdMailbox::zeroed();
        cmd.execute(
            CmdOpcode::DisableHca,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn transition_sq_to_error(&mut self, sqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_modify_sq_input(
            in_mbox,
            sqn,
            crate::defs::WqState::Ready as u8,
            crate::defs::WqState::Error as u8,
        );
        self.execute_uid_sensitive_cmd(CmdOpcode::ModifySq, in_mbox, 0x110, 0x10)?;
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid, required resources are unavailable, or the device operation fails.
    pub unsafe fn transition_rq_to_error(&mut self, rqn: u32) -> Mlx5Result<()> {
        self.cmd
            .as_ref()
            .ok_or(crate::error::Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_modify_rq_input(
            in_mbox,
            rqn,
            crate::defs::WqState::Ready as u8,
            crate::defs::WqState::Error as u8,
        );
        self.execute_uid_sensitive_cmd(CmdOpcode::ModifyRq, in_mbox, 0x110, 0x10)?;
        Ok(())
    }
}
