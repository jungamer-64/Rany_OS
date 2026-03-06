// ============================================================================
// drivers/mlx5/src/device/ops.rs - MLX5 Device Operations
// ============================================================================

extern crate alloc;
use alloc::vec::Vec;
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, PortLinkState};
use crate::eq::EqEvent;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::device::{Mlx5Device, DeviceState};
use crate::cmd::CmdMailbox;
use crate::cmd::hca::*; // bring HCA command builders/parsers
use crate::cmd::CommandTransport; // for execute() method
// unused imports removed
use crate::health::HealthStatus;

impl Mlx5Device {
    /// パケットを送信
    pub unsafe fn transmit(&mut self, sq_index: usize, data_phys: u64, data_virt: u64, data_len: u32, inline_hdr: &[u8]) -> Mlx5Result<u16> {
        if self.state != DeviceState::Active { return Err(Mlx5Error::DeviceNotReady); }
        let sq = self.sqs.get_mut(sq_index).ok_or(Mlx5Error::InvalidParameter)?;
        let segments = [crate::wq::DmaSegment { device_addr: data_phys, virt_addr: data_virt, len: data_len }];
        sq.post_send(&segments, inline_hdr).ok_or(Mlx5Error::NoResources)
    }

    /// 受信バッファを投入
    pub unsafe fn post_receive(&mut self, rq_index: usize, buf_phys: u64, buf_virt: u64, buf_size: u32) -> Mlx5Result<u16> {
        if self.state != DeviceState::Active && self.state != DeviceState::QueuesReady { return Err(Mlx5Error::DeviceNotReady); }
        let rq = self.rqs.get_mut(rq_index).ok_or(Mlx5Error::InvalidParameter)?;
        rq.post_recv(buf_phys, buf_virt, buf_size).ok_or(Mlx5Error::NoResources)
    }

    pub unsafe fn handle_eq_interrupt(&mut self, eq_index: usize) -> Vec<EqEvent> {
        let mut events = Vec::new();
        if let Some(eq) = self.eqs.get_mut(eq_index) {
            loop {
                match eq.poll_eqe() {
                    Some(eqe) => {
                        events.push(crate::eq::decode_eqe(eqe));
                        eq.advance_consumer();
                    }
                    None => break,
                }
            }
            if !events.is_empty() { eq.update_doorbell(); }
        }
        events
    }

    pub unsafe fn poll_cq(&mut self, cq_index: usize, max_batch: u32) -> Vec<crate::cq::CqeInfo> {
        let batch = self.polling_state.max_batch_size().min(max_batch);
        let result = if let Some(cq) = self.cqs.get_mut(cq_index) { cq.poll_batch(batch) } else { Vec::new() };
        let need_rearm = self.polling_state.record_poll_cycle(result.len() as u32);
        if need_rearm { if let Some(cq) = self.cqs.get(cq_index) { cq.arm(); } }
        result
    }

    pub fn process_tx_completions(&mut self, sq_index: usize, wqe_counter: u16) -> Option<crate::wq::TxBufferInfo> {
        self.sqs.get_mut(sq_index).and_then(|sq| sq.complete_tx(wqe_counter))
    }

    pub fn process_rx_completion(&mut self, rq_index: usize, wqe_counter: u16) -> Option<crate::wq::RxBufferInfo> {
        self.rqs.get_mut(rq_index).and_then(|rq| rq.complete_rx(wqe_counter))
    }

    pub unsafe fn activate_vfs(&mut self, num_vfs: u16) -> Mlx5Result<()> {
        if self.is_vf() { return Err(Mlx5Error::NotSupported); }
        let caps = self.hca_caps.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        if !caps.vport_group_manager { return Err(Mlx5Error::NotSupported); }
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        for i in 0..num_vfs {
            let vhca_id = i + 1;
            {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                build_modify_vhca_state_input(in_mbox, vhca_id, 0, 1);
                cmd.execute(CmdOpcode::ModifyVhcaState, self.cmd_in_mbox_device, MLX5_CMD_MBOX_SIZE as u32, self.cmd_out_mbox_device, MLX5_CMD_MBOX_SIZE as u32)?;
            }
            {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                build_modify_vhca_state_input(in_mbox, vhca_id, 0, 2);
                cmd.execute(CmdOpcode::ModifyVhcaState, self.cmd_in_mbox_device, MLX5_CMD_MBOX_SIZE as u32, self.cmd_out_mbox_device, MLX5_CMD_MBOX_SIZE as u32)?;
            }
            {
                let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
                build_modify_nic_vport_state_input(in_mbox, vhca_id, true);
                cmd.execute(CmdOpcode::ModifyNicVportContext, self.cmd_in_mbox_device, MLX5_CMD_MBOX_SIZE as u32, self.cmd_out_mbox_device, MLX5_CMD_MBOX_SIZE as u32)?;
            }
        }
        Ok(())
    }

    pub unsafe fn query_port_state(&mut self, port_index: usize) -> Mlx5Result<PortLinkState> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_vport_state_input(in_mbox, 0);
        cmd.execute(CmdOpcode::QueryVportState, self.cmd_in_mbox_device, MLX5_CMD_MBOX_SIZE as u32, self.cmd_out_mbox_device, MLX5_CMD_MBOX_SIZE as u32)?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let (_admin, oper) = parse_query_vport_state_output(out_mbox);
        let link_state = if oper == 0x01 { PortLinkState::Up } else { PortLinkState::Down };
        if let Some(port) = self.ports.get_mut(port_index) { port.set_link_state(link_state); }
        Ok(link_state)
    }

    pub fn set_port_mtu(&mut self, port_index: usize, mtu: u32) -> Mlx5Result<()> {
        let port = self.ports.get_mut(port_index).ok_or(Mlx5Error::InvalidParameter)?;
        port.set_mtu(mtu).map_err(|_| Mlx5Error::InvalidParameter)?;
        Ok(())
    }

    pub unsafe fn health_check(&mut self) -> HealthStatus {
        self.health_monitor.check(self.bar0_base)
    }
}
