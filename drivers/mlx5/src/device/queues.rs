// ============================================================================
// drivers/mlx5/src/device/queues.rs - MLX5 Queue Management
// ============================================================================

extern crate alloc;
// unused import Vec removed
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, WqState};
use crate::cmd::queues::*;  // bring in helper builders/parsers
use crate::cmd::CommandTransport; // needed for execute() method
use crate::error::{Mlx5Error, Mlx5Result};
use crate::device::Mlx5Device;
use crate::cmd::CmdMailbox;
use crate::eq::EventQueue;
use crate::cq::CompletionQueue;
use crate::wq::{SendQueue, ReceiveQueue};
use crate::flow::RqTable;

impl Mlx5Device {
    /// Event Queueを作成
    pub unsafe fn create_eq_hw(&mut self, eq_buf_virt: u64, eq_buf_pa: u64, log_eq_size: u8, msix_vector: u32, event_bitmask: u64) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;

        let eq_depth = 1u32 << log_eq_size;
        let eq_ptr = eq_buf_virt as *mut u8;
        core::ptr::write_bytes(eq_ptr, 0, (eq_depth as usize) * crate::regs::eqe::EQE_SIZE);
        for i in 0..eq_depth {
            let offset = (i as usize * crate::regs::eqe::EQE_SIZE) + crate::regs::eqe::STATUS_OWN;
            core::ptr::write_volatile(eq_ptr.add(offset), 0x01);
        }

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_create_eq_input(in_mbox, log_eq_size, eq_buf_pa, self.uar_page, msix_vector, event_bitmask);

        let eq_bytes = (1usize << (log_eq_size as usize)) * crate::regs::eqe::EQE_SIZE;
        let eq_pages = (eq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let eq_in_len = (0x110 + eq_pages * 8) as u32;

        let prev_uid = cmd.uid();
        let vhca_uid = self.sw_vhca_id;
        let mut uid_candidates = [0u16; 4];
        let mut uid_count = 0usize;
        let mut push_uid = |u: u16| {
            if !uid_candidates[..uid_count].contains(&u) {
                uid_candidates[uid_count] = u;
                uid_count += 1;
            }
        };
        push_uid(prev_uid);
        if is_vf {
            push_uid(0xFFFF);
            push_uid(0);
            if vhca_uid != 0 { push_uid(vhca_uid); }
        }

        let mut exec_res: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        for &uid in &uid_candidates[..uid_count] {
            cmd.set_uid(uid);
            let res = cmd.execute(CmdOpcode::CreateEq, self.cmd_in_mbox_device, eq_in_len, self.cmd_out_mbox_device, 0x10);
            if res.is_ok() {
                exec_res = Ok(());
                break;
            }
            exec_res = res;
        }

        cmd.set_uid(prev_uid);
        exec_res?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let eqn = parse_create_eq_output(out_mbox);
        let eq = EventQueue::new(eqn, eq_buf_virt, eq_buf_pa, self.uar_base, log_eq_size, msix_vector);
        self.eqs.push(eq);
        Ok(eqn)
    }

    /// Completion Queueを作成
    pub unsafe fn create_cq_hw(&mut self, cq_buf_virt: u64, cq_buf_pa: u64, db_virt: u64, db_pa: u64, log_cq_size: u8, eqn: u32) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let vhca_uid = self.sw_vhca_id;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();

        let cq_depth = 1u32 << log_cq_size;
        let cq_ptr = cq_buf_virt as *mut u8;
        core::ptr::write_bytes(cq_ptr, 0, (cq_depth as usize) * crate::regs::cqe::SIZE);
        for i in 0..cq_depth {
            let offset = (i as usize * crate::regs::cqe::SIZE) + crate::regs::cqe::OP_OWN;
            core::ptr::write_volatile(cq_ptr.add(offset), 0x01);
        }

        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_create_cq_input(in_mbox, log_cq_size, cq_buf_pa, db_pa, self.uar_page, eqn, false);

        let cq_bytes = (1usize << (log_cq_size as usize)) * crate::regs::cqe::SIZE;
        let cq_pages = (cq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let cq_in_len = (0x110 + cq_pages * 8) as u32;

        let mut uid_candidates = [0u16; 4];
        let mut uid_count = 0usize;
        let mut push_uid = |u: u16| {
            if !uid_candidates[..uid_count].contains(&u) {
                uid_candidates[uid_count] = u;
                uid_count += 1;
            }
        };
        push_uid(prev_uid);
        if is_vf {
            push_uid(0xFFFF);
            push_uid(0);
            if vhca_uid != 0 { push_uid(vhca_uid); }
        }

        let mut exec_res: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        for &uid in &uid_candidates[..uid_count] {
            cmd.set_uid(uid);
            let res = cmd.execute(CmdOpcode::CreateCq, self.cmd_in_mbox_device, cq_in_len, self.cmd_out_mbox_device, 0x10);
            if res.is_ok() {
                exec_res = Ok(());
                break;
            }
            exec_res = res;
        }

        cmd.set_uid(prev_uid);
        exec_res?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let cqn = parse_create_cq_output(out_mbox);
        let cq = CompletionQueue::new(cqn, cq_buf_virt, cq_buf_pa, self.uar_base, db_virt, log_cq_size, eqn);
        self.cqs.push(cq);
        self.cq_db_records.push((db_virt, db_pa));
        Ok(cqn)
    }

    /// Send Queueを作成
    pub unsafe fn create_sq_hw(&mut self, sq_buf_virt: u64, sq_buf_pa: u64, db_virt: u64, db_pa: u64, log_sq_size: u8, cqn: u32, tisn: u32) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_create_sq_input(in_mbox, log_sq_size, sq_buf_pa, db_pa, cqn, self.pd, self.uar_page, tisn);
        let sq_bytes = (1usize << (log_sq_size as usize)) * 64usize;
        let sq_pages = (sq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let sq_in_len = (0x110 + sq_pages * 8) as u32;
        cmd.execute(CmdOpcode::CreateSq, self.cmd_in_mbox_device, sq_in_len, self.cmd_out_mbox_device, 0x10)?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let sqn = parse_create_sq_output(out_mbox);
        self.transition_sq_to_ready(sqn)?;
        let csum_offload = self.hca_caps.as_ref().map(|c| c.csum_cap).unwrap_or(false);
        let sq = SendQueue::new(sqn, sq_buf_virt, sq_buf_pa, db_virt, self.uar_base, log_sq_size, tisn, cqn, self.mkey, csum_offload);
        self.sqs.push(sq);
        Ok(sqn)
    }

    /// Receive Queueを作成
    pub unsafe fn create_rq_hw(&mut self, rq_buf_virt: u64, rq_buf_pa: u64, db_virt: u64, db_pa: u64, log_rq_size: u8, cqn: u32, _tirn: u32, scatter_fcs: bool, vlan_strip: bool) -> Mlx5Result<u32> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_create_rq_input(in_mbox, log_rq_size, rq_buf_pa, db_pa, cqn, self.pd, self.uar_page, scatter_fcs, vlan_strip);
        let rq_bytes = (1usize << (log_rq_size as usize)) * crate::defs::WQEBB_SIZE;
        let rq_pages = (rq_bytes + crate::defs::MLX5_PAGE_SIZE - 1) / crate::defs::MLX5_PAGE_SIZE;
        let rq_in_len = (0x110 + rq_pages * 8) as u32;
        cmd.execute(CmdOpcode::CreateRq, self.cmd_in_mbox_device, rq_in_len, self.cmd_out_mbox_device, 0x10)?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let rqn = parse_create_rq_output(out_mbox);
        self.transition_rq_to_ready(rqn)?;
        let csum_offload = self.hca_caps.as_ref().map(|c| c.csum_cap).unwrap_or(false);
        let rq = ReceiveQueue::new(rqn, rq_buf_virt, rq_buf_pa, db_virt, log_rq_size, cqn, self.mkey, csum_offload);
        self.rqs.push(rq);
        Ok(rqn)
    }

    /// RQTを作成
    pub unsafe fn create_rqt(&mut self, rq_numbers: &[u32], log_rqt_size: u8) -> Mlx5Result<u32> {
        let is_vf = self.is_vf();
        let vhca_uid = self.sw_vhca_id;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let prev_uid = cmd.uid();
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        crate::cmd::flow::build_create_rqt_input(in_mbox, rq_numbers, log_rqt_size);

        let mut uid_candidates = [0u16; 4];
        let mut uid_count = 0usize;
        let mut push_uid = |u: u16| {
            if !uid_candidates[..uid_count].contains(&u) {
                uid_candidates[uid_count] = u;
                uid_count += 1;
            }
        };
        push_uid(prev_uid);
        if is_vf {
            push_uid(0xFFFF);
            push_uid(0);
            if vhca_uid != 0 { push_uid(vhca_uid); }
        }

        let mut exec_res: Mlx5Result<()> = Err(Mlx5Error::NotSupported);
        for &uid in &uid_candidates[..uid_count] {
            cmd.set_uid(uid);
            let res = cmd.execute(CmdOpcode::CreateRqt, self.cmd_in_mbox_device, MLX5_CMD_MBOX_SIZE as u32, self.cmd_out_mbox_device, MLX5_CMD_MBOX_SIZE as u32);
            if res.is_ok() {
                exec_res = Ok(());
                break;
            }
            exec_res = res;
        }

        cmd.set_uid(prev_uid);
        exec_res?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let rqtn = crate::cmd::flow::parse_create_rqt_output(out_mbox);
        self.rq_tables.push(RqTable { rqtn, rq_list: rq_numbers.to_vec(), log_rqt_size });
        Ok(rqtn)
    }

    unsafe fn transition_sq_to_ready(&mut self, sqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_modify_sq_input(in_mbox, sqn, WqState::Reset as u8, WqState::Ready as u8, 0, false);
        cmd.execute(CmdOpcode::ModifySq, self.cmd_in_mbox_device, MLX5_CMD_MBOX_SIZE as u32, self.cmd_out_mbox_device, MLX5_CMD_MBOX_SIZE as u32)?;
        Ok(())
    }

    unsafe fn transition_rq_to_ready(&mut self, rqn: u32) -> Mlx5Result<()> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_modify_rq_input(in_mbox, rqn, WqState::Reset as u8, WqState::Ready as u8, 0, false);
        cmd.execute(CmdOpcode::ModifyRq, self.cmd_in_mbox_device, MLX5_CMD_MBOX_SIZE as u32, self.cmd_out_mbox_device, MLX5_CMD_MBOX_SIZE as u32)?;
        Ok(())
    }
}
