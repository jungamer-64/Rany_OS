// ============================================================================
// drivers/mlx5/src/device/queues.rs - MLX5 Queue Management
// ============================================================================

extern crate alloc;
// unused import Vec removed
use crate::cmd::CmdMailbox;
use crate::cmd::CommandTransport; // needed for execute() method
use crate::cmd::queues::*; // bring in helper builders/parsers
use crate::cq::CompletionQueue;
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, WqState};
use crate::device::Mlx5Device;
use crate::eq::EventQueue;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::flow::RqTable;
use crate::wq::{ReceiveQueue, SendQueue};

impl Mlx5Device {
    /// Event Queueを作成
    pub unsafe fn create_eq_hw(
        &mut self,
        eq_buf_virt: u64,
        eq_buf_pa: u64,
        log_eq_size: u8,
        msix_vector: u32,
        event_bitmask: u64,
    ) -> Mlx5Result<u32> {
        // VF 特有の MSI-X / EQ 数上限チェック
        if let Some(caps) = self.hca_caps.as_ref() {
            if msix_vector >= caps.max_eq {
                log::error!(target: "mlx5", "Requested MSI-X vector {} exceeds hardware max_eq {}", msix_vector, caps.max_eq);
                return Err(Mlx5Error::NoResources);
            }
            if self.eqs.len() >= caps.max_eq as usize {
                log::error!(target: "mlx5", "Maximum EQ count reached ({})", caps.max_eq);
                return Err(Mlx5Error::NoResources);
            }
        }

        let is_vf = self.is_vf();
        let sw_vhca_id = self.sw_vhca_id;
        let cmd_in_mbox_device = self.cmd_in_mbox_device;
        let cmd_out_mbox_device = self.cmd_out_mbox_device;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let eq_depth = 1u32 << log_eq_size;
        let eq_ptr = eq_buf_virt as *mut u8;
        core::ptr::write_bytes(eq_ptr, 0, (eq_depth as usize) * crate::regs::eqe::EQE_SIZE);
        for i in 0..eq_depth {
            let offset = (i as usize * crate::regs::eqe::EQE_SIZE) + crate::regs::eqe::STATUS_OWN;
            core::ptr::write_volatile(eq_ptr.add(offset), 0x01);
        }

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_create_eq_input(
            in_mbox,
            log_eq_size,
            eq_buf_pa,
            self.uar_page,
            msix_vector,
            event_bitmask,
        );

        let eq_bytes = (1usize << (log_eq_size as usize)) * crate::regs::eqe::EQE_SIZE;
        let eq_pages = (eq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let eq_in_len = (0x110 + eq_pages * 8) as u32;

        self.execute_uid_sensitive_cmd(CmdOpcode::CreateEq, eq_in_len, 0x10)?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let eqn = parse_create_eq_output(out_mbox);
        let eq = EventQueue::new(
            eqn,
            eq_buf_virt,
            eq_buf_pa,
            self.uar_base,
            log_eq_size,
            msix_vector,
        );
        self.eqs.push(eq);
        Ok(eqn)
    }

    /// Completion Queueを作成
    pub unsafe fn create_cq_hw(
        &mut self,
        cq_buf_virt: u64,
        cq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_cq_size: u8,
        eqn: u32,
    ) -> Mlx5Result<u32> {
        let cq_depth = 1u32 << log_cq_size;
        let cq_ptr = cq_buf_virt as *mut u8;
        core::ptr::write_bytes(cq_ptr, 0, (cq_depth as usize) * crate::regs::cqe::SIZE);
        for i in 0..cq_depth {
            let offset = (i as usize * crate::regs::cqe::SIZE) + crate::regs::cqe::OP_OWN;
            core::ptr::write_volatile(cq_ptr.add(offset), 0x01);
        }

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let cqe_comp = self.hca_caps.as_ref().map(|c| c.cqe_compression).unwrap_or(false);
        build_create_cq_input(
            in_mbox,
            log_cq_size,
            cq_buf_pa,
            db_pa,
            self.uar_page,
            eqn,
            cqe_comp,
        );

        let cq_bytes = (1usize << (log_cq_size as usize)) * crate::regs::cqe::SIZE;
        let cq_pages = (cq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let cq_in_len = (0x110 + cq_pages * 8) as u32;

        self.execute_uid_sensitive_cmd(CmdOpcode::CreateCq, cq_in_len, 0x10)?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let cqn = parse_create_cq_output(out_mbox);
        let cq = CompletionQueue::new(
            cqn,
            cq_buf_virt,
            cq_buf_pa,
            self.uar_base,
            db_virt,
            log_cq_size,
            eqn,
        );
        self.cqs.push(cq);
        self.cq_db_records.push((db_virt, db_pa));
        Ok(cqn)
    }

    /// CQモデレーション（割り込み抑制）を設定
    pub unsafe fn modify_cq_moderation(
        &mut self,
        cqn: u32,
        period_usec: u16,
        count: u16,
    ) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_modify_cq_moderation_input(in_mbox, cqn, period_usec, count);

        self.execute_uid_sensitive_cmd(
            CmdOpcode::ModifyCq,
            0x40, // input length
            0x10, // output length
        )?;
        Ok(())
    }

    /// Send Queueを作成
    pub unsafe fn create_sq_hw(
        &mut self,
        sq_buf_virt: u64,
        sq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_sq_size: u8,
        cqn: u32,
        tisn: u32,
    ) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_create_sq_input(
            in_mbox,
            log_sq_size,
            sq_buf_pa,
            db_pa,
            cqn,
            self.pd,
            self.uar_page,
            tisn,
        );
        let sq_bytes = (1usize << (log_sq_size as usize)) * 64usize;
        let sq_pages = (sq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let sq_in_len = (0x110 + sq_pages * 8) as u32;
        self.execute_uid_sensitive_cmd(CmdOpcode::CreateSq, sq_in_len, 0x10)?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let sqn = parse_create_sq_output(out_mbox);
        self.transition_sq_to_ready(sqn)?;
        let csum_offload = self.hca_caps.as_ref().map(|c| c.csum_cap).unwrap_or(false);
        let sq = SendQueue::new(
            sqn,
            sq_buf_virt,
            sq_buf_pa,
            db_virt,
            self.uar_base,
            log_sq_size,
            tisn,
            cqn,
            self.mkey,
            csum_offload,
        );
        let cq_index = self
            .cq_index_by_cqn(cqn)
            .ok_or(Mlx5Error::InvalidResponse)?;
        self.sqs.push(sq);
        self.tx_cq_by_sq.push(cq_index);
        Ok(sqn)
    }

    /// Receive Queueを作成
    pub unsafe fn create_rq_hw(
        &mut self,
        rq_buf_virt: u64,
        rq_buf_pa: u64,
        db_virt: u64,
        db_pa: u64,
        log_rq_size: u8,
        cqn: u32,
        _tirn: u32,
        scatter_fcs: bool,
        vlan_strip: bool,
    ) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_create_rq_input(
            in_mbox,
            log_rq_size,
            rq_buf_pa,
            db_pa,
            cqn,
            self.pd,
            self.uar_page,
            scatter_fcs,
            vlan_strip,
        );
        let rq_bytes = (1usize << (log_rq_size as usize)) * crate::defs::WQEBB_SIZE;
        let rq_pages = (rq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let rq_in_len = (0x110 + rq_pages * 8) as u32;
        self.execute_uid_sensitive_cmd(CmdOpcode::CreateRq, rq_in_len, 0x10)?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let rqn = parse_create_rq_output(out_mbox);
        self.transition_rq_to_ready(rqn)?;
        let csum_offload = self.hca_caps.as_ref().map(|c| c.csum_cap).unwrap_or(false);
        let rq = ReceiveQueue::new(
            rqn,
            rq_buf_virt,
            rq_buf_pa,
            db_virt,
            log_rq_size,
            cqn,
            self.mkey,
            csum_offload,
        );
        let cq_index = self
            .cq_index_by_cqn(cqn)
            .ok_or(Mlx5Error::InvalidResponse)?;
        self.rqs.push(rq);
        self.rx_cq_by_rq.push(cq_index);
        Ok(rqn)
    }

    /// RQTを作成
    pub unsafe fn create_rqt(&mut self, rq_numbers: &[u32], log_rqt_size: u8) -> Mlx5Result<u32> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::flow::build_create_rqt_input(in_mbox, rq_numbers, log_rqt_size);

        self.execute_uid_sensitive_cmd(
            CmdOpcode::CreateRqt,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let rqtn = crate::cmd::flow::parse_create_rqt_output(out_mbox);
        self.rq_tables.push(RqTable {
            rqtn,
            rq_list: rq_numbers.to_vec(),
            log_rqt_size,
        });
        Ok(rqtn)
    }

    unsafe fn transition_sq_to_ready(&mut self, sqn: u32) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_modify_sq_input(
            in_mbox,
            sqn,
            WqState::Reset as u8,
            WqState::Ready as u8,
            0,
            false,
        );
        self.execute_uid_sensitive_cmd(
            CmdOpcode::ModifySq,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }

    unsafe fn transition_rq_to_ready(&mut self, rqn: u32) -> Mlx5Result<()> {
        self.cmd.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_modify_rq_input(
            in_mbox,
            rqn,
            WqState::Reset as u8,
            WqState::Ready as u8,
            0,
            false,
        );
        self.execute_uid_sensitive_cmd(
            CmdOpcode::ModifyRq,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        Ok(())
    }
}
