// ============================================================================
// drivers/mlx5/src/device/res.rs - MLX5 Resource Management
// ============================================================================

extern crate alloc;
use crate::cmd::CmdMailbox;
use crate::cmd::CommandTransport; // needed to bring execute() method into scope
use crate::cmd::hca::*; // basic HCA commands (SET_DRIVER_VERSION etc)
use crate::cmd::res::*; // resource command builders/parsers
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE};
use crate::device::Mlx5Device;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::flow::{FlowGroup, FlowTable, FlowTableConfig, FlowTableEntry};
use crate::resources::{MkeyInfo, MkeyParams, TirInfo, TirParams, TisInfo, TisParams};

impl Mlx5Device {
    /// QUERY_SPECIAL_CONTEXTS から reserved lkey を取得
    pub unsafe fn query_reserved_lkey(&mut self) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_special_contexts_input(in_mbox);
        cmd.execute(
            CmdOpcode::QuerySpecialContexts,
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
            0x40,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(parse_query_special_contexts_resd_lkey(out_mbox))
    }

    /// Direct Memory Key を作成
    pub unsafe fn create_mkey(&mut self, params: &MkeyParams) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::res::build_create_mkey_input(in_mbox, params);

        cmd.execute(
            CmdOpcode::CreateMkey,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let mkey_index = crate::cmd::res::parse_create_mkey_output(out_mbox);
        let full_mkey = (mkey_index << 8) | 0x42;

        let info = MkeyInfo {
            mkey_index,
            mkey: full_mkey,
            params: params.clone(),
        };

        log::info!(target: "mlx5", "MKEY created: index={:#x} mkey={:#x}", mkey_index, full_mkey);
        self.mkey = full_mkey;
        self.mkey_info = Some(info);
        Ok(full_mkey)
    }

    /// TIS (Transport Interface Send) を作成
    pub unsafe fn create_tis(&mut self, params: &TisParams) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        log::info!(target: "mlx5", "Creating TIS: td={} pd={} port={} prio={}", params.td, params.pd, params.port, params.prio);

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::res::build_create_tis_input(in_mbox, params);

        cmd.execute(
            CmdOpcode::CreateTis,
            self.cmd_in_mbox_device,
            0xC0,
            self.cmd_out_mbox_device,
            0x10,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let tisn = crate::cmd::res::parse_create_tis_output(out_mbox);
        let info = TisInfo {
            tisn,
            port: params.port,
        };
        self.tis_list.push(info);
        log::info!(target: "mlx5", "TIS created: tisn={}", tisn);
        Ok(tisn)
    }

    /// TIR (Transport Interface Receive) を作成
    pub unsafe fn create_tir(&mut self, params: &TirParams) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let sw_vhca_id = self.sw_vhca_id;
        let cmd_in_mbox_device = self.cmd_in_mbox_device;
        let cmd_out_mbox_device = self.cmd_out_mbox_device;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf, sw_vhca_id);

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::res::build_create_tir_input(in_mbox, params);

        Self::execute_with_uid_candidates(cmd, &uids[..len], |cmd| {
            cmd.execute(
                CmdOpcode::CreateTir,
                cmd_in_mbox_device,
                0x110,
                cmd_out_mbox_device,
                0x10,
            )
        })?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let tirn = crate::cmd::res::parse_create_tir_output(out_mbox);

        let info = TirInfo {
            tirn,
            receive_type: params.receive_type,
        };
        self.tir_list.push(info);

        log::info!(target: "mlx5", "TIR created: tirn={}", tirn);
        Ok(tirn)
    }

    /// UAR (User Access Region) を割り当て
    pub unsafe fn alloc_uar(&mut self) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let sw_vhca_id = self.sw_vhca_id;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf, sw_vhca_id);

        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        for &uid in &uids[..len] {
            cmd.set_uid(uid);
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_alloc_uar_input(in_mbox);

            match cmd.execute(
                CmdOpcode::AllocUar,
                self.cmd_in_mbox_device,
                0x10,
                self.cmd_out_mbox_device,
                0x10,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    let uar_number = parse_alloc_uar_output(out_mbox);
                    self.allocated_uars.push(uar_number);
                    if self.uar_page == 0 {
                        self.uar_page = uar_number;
                        self.uar_base = self.bar0_base
                            + (uar_number as u64) * (crate::regs::uar::PAGE_SIZE as u64);
                    }
                    cmd.set_uid(prev_uid);
                    return Ok(uar_number);
                }
                Err(Mlx5Error::CommandFailed(status)) if status == 0x04 => {
                    let uar_number = 0;
                    self.allocated_uars.push(uar_number);
                    self.uar_page = uar_number;
                    self.uar_base =
                        self.bar0_base + (uar_number as u64) * (crate::regs::uar::PAGE_SIZE as u64);
                    cmd.set_uid(prev_uid);
                    return Ok(uar_number);
                }
                Err(e) => {
                    last_err = Err(e);
                    continue;
                }
            }
        }
        cmd.set_uid(prev_uid);
        last_err
    }

    /// Protection Domain を割り当て
    pub unsafe fn alloc_pd(&mut self) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let sw_vhca_id = self.sw_vhca_id;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf, sw_vhca_id);

        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        for &uid in &uids[..len] {
            cmd.set_uid(uid);
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_alloc_pd_input(in_mbox);

            match cmd.execute(
                CmdOpcode::AllocPd,
                self.cmd_in_mbox_device,
                0x10,
                self.cmd_out_mbox_device,
                0x10,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    self.pd = parse_alloc_pd_output(out_mbox);
                    cmd.set_uid(prev_uid);
                    return Ok(self.pd);
                }
                Err(Mlx5Error::CommandFailed(status)) if status == 0x04 => {
                    self.pd = 0;
                    cmd.set_uid(prev_uid);
                    return Ok(self.pd);
                }
                Err(e) => {
                    last_err = Err(e);
                    continue;
                }
            }
        }
        cmd.set_uid(prev_uid);
        last_err
    }

    /// Transport Domain を割り当て
    pub unsafe fn alloc_td(&mut self) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let sw_vhca_id = self.sw_vhca_id;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf, sw_vhca_id);

        let mut last_err: Mlx5Result<u32> = Err(Mlx5Error::NotSupported);
        for &uid in &uids[..len] {
            cmd.set_uid(uid);
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_alloc_td_input(in_mbox);

            match cmd.execute(
                CmdOpcode::AllocTransportDomain,
                self.cmd_in_mbox_device,
                0x10,
                self.cmd_out_mbox_device,
                0x10,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    self.td = parse_alloc_td_output(out_mbox);
                    cmd.set_uid(prev_uid);
                    return Ok(self.td);
                }
                Err(Mlx5Error::CommandFailed(status)) if status == 0x04 => {
                    self.td = 0;
                    cmd.set_uid(prev_uid);
                    return Ok(self.td);
                }
                Err(e) => {
                    last_err = Err(e);
                    continue;
                }
            }
        }
        cmd.set_uid(prev_uid);
        last_err
    }

    pub unsafe fn set_driver_version(&mut self) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let version = b"RanyOS mlx5 0.1.0";
        build_set_driver_version_input(in_mbox, version);
        self.execute_cmd_with_uid_candidates(
            CmdOpcode::SetDriverVersion,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    pub unsafe fn setup_rx_flow_table(&mut self, tirn: u32) -> Mlx5Result<()> {
        let ft_config = FlowTableConfig::default();
        let table_id = self.create_flow_table(&ft_config)?;
        let criteria = crate::flow::MatchCriteria::default();
        let group_id = self.create_flow_group(table_id, 0, 0, &criteria)?;
        let match_value = crate::flow::MatchValue::default();
        self.set_flow_table_entry(
            table_id,
            0,
            group_id,
            crate::flow::FlowAction::Allow,
            Some(tirn),
            &match_value,
        )?;
        Ok(())
    }

    pub unsafe fn create_flow_table(&mut self, config: &FlowTableConfig) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::flow::build_create_flow_table_input(in_mbox, config);
        cmd.execute(
            CmdOpcode::CreateFlowTable,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let table_id = crate::cmd::flow::parse_create_flow_table_output(out_mbox);
        self.flow_tables.push(FlowTable {
            table_id,
            table_type: config.table_type,
            size: 1 << config.log_size,
            level: config.level,
        });
        Ok(table_id)
    }

    pub unsafe fn create_flow_group(
        &mut self,
        table_id: u32,
        start_index: u32,
        end_index: u32,
        criteria: &crate::flow::MatchCriteria,
    ) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::flow::build_create_flow_group_input(
            in_mbox,
            table_id,
            start_index,
            end_index,
            criteria,
        );
        cmd.execute(
            CmdOpcode::CreateFlowGroup,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let group_id = crate::cmd::flow::parse_create_flow_group_output(out_mbox);
        self.flow_groups.push(FlowGroup {
            group_id,
            table_id,
            start_index,
            end_index,
            match_criteria: criteria.clone(),
        });
        Ok(group_id)
    }

    pub unsafe fn set_flow_table_entry(
        &mut self,
        table_id: u32,
        flow_index: u32,
        group_id: u32,
        action: crate::flow::FlowAction,
        destination_tirn: Option<u32>,
        match_value: &crate::flow::MatchValue,
    ) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::flow::build_set_flow_table_entry_input(
            in_mbox,
            table_id,
            flow_index,
            group_id,
            action,
            destination_tirn,
            match_value,
        );
        cmd.execute(
            CmdOpcode::SetFlowTableEntry,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        self.flow_entries.push(FlowTableEntry {
            index: flow_index,
            table_id,
            group_id,
            match_value: match_value.clone(),
            action,
            destination_tirn,
        });
        Ok(())
    }
}
