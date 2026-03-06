// ============================================================================
// drivers/mlx5/src/device/ops.rs - MLX5 Device Operations
// ============================================================================

extern crate alloc;
use alloc::vec::Vec;
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, PortLinkState, VportCounters};
use crate::eq::EqEvent;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::device::{Mlx5Device, DeviceState};
use crate::cmd::CmdMailbox;
use crate::cmd::hca::*; // bring HCA command builders/parsers
use crate::cmd::CommandTransport; // for execute() method
use crate::health::HealthStatus;
use crate::port::MacAddr;

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

    pub fn query_vport_context(&mut self, vport: u16) -> Mlx5Result<crate::cmd::VportContext> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        unsafe {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_query_vport_context_input(in_mbox, vport);

            cmd.execute(
                CmdOpcode::QueryNicVportContext,
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
            )?;

            let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
            Ok(parse_query_vport_context_output(out_mbox))
        }
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

    pub unsafe fn query_port_mac(&mut self, port_index: usize) -> Mlx5Result<MacAddr> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let query_patterns: &[(bool, Option<u8>, &str)] = &[
            (false, None, "self"),
            (false, Some(0), "self-uc-list"),
            (true, None, "other-vport"),
            (true, Some(0), "other-vport-uc-list"),
        ];

        let mut last_cmd_status = None;

        for (other_vport, allowed_list_type, label) in query_patterns {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_query_nic_vport_input_ex(in_mbox, 0, *other_vport, *allowed_list_type);
            match cmd.execute(
                CmdOpcode::QueryNicVportContext,
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
            ) {
                Ok(()) => {
                    let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
                    Self::debug_dump_mailbox_words("QUERY_NIC_VPORT_CONTEXT", out_mbox, 48);
                    let mac_bytes = parse_vport_mac(out_mbox);
                    if mac_bytes != [0; 6] {
                        let mac = MacAddr(mac_bytes);
                        if let Some(port) = self.ports.get_mut(port_index) {
                            port.set_mac_address(mac);
                        }
                        log::info!(target: "mlx5", "Port {} MAC: {}", port_index + 1, mac);
                        return Ok(mac);
                    }
                    log::debug!(
                        target: "mlx5",
                        "QUERY_NIC_VPORT_CONTEXT ({}) returned zero MAC",
                        label
                    );
                }
                Err(Mlx5Error::CommandFailed(status)) => {
                    last_cmd_status = Some(status);
                    log::debug!(
                        target: "mlx5",
                        "QUERY_NIC_VPORT_CONTEXT ({}) failed with status={:#x}",
                        label,
                        status
                    );
                }
                Err(err) => return Err(err),
            }
        }

        if let Some(status) = last_cmd_status {
            log::warn!(
                target: "mlx5",
                "Failed to query NIC vport MAC (status={:#x}); MAC remains unset",
                status
            );
        } else {
            log::warn!(target: "mlx5", "Failed to query NIC vport MAC; MAC remains unset");
        }

        Ok(MacAddr::ZERO)
    }

    pub unsafe fn update_port_stats(&mut self, port_index: usize) -> Mlx5Result<()> {
        let port_num = self
            .ports
            .get(port_index)
            .map(|p| p.port_number())
            .ok_or(Mlx5Error::InvalidParameter)?;

        let counters = self.query_vport_counters(port_num, false)?;

        if let Some(port) = self.ports.get_mut(port_index) {
            let stats = port.stats_mut();
            stats.rx_packets = counters.rx_unicast_packets
                + counters.rx_multicast_packets
                + counters.rx_broadcast_packets;
            stats.rx_bytes = counters.rx_unicast_bytes
                + counters.rx_multicast_bytes
                + counters.rx_broadcast_bytes;
            stats.tx_packets = counters.tx_unicast_packets
                + counters.tx_multicast_packets
                + counters.tx_broadcast_packets;
            stats.tx_bytes = counters.tx_unicast_bytes
                + counters.tx_multicast_bytes
                + counters.tx_broadcast_bytes;
            stats.rx_errors = counters.rx_error_packets;
            stats.tx_errors = counters.tx_error_packets;
            stats.rx_dropped = counters.rx_dropped;
            stats.tx_dropped = counters.tx_dropped;
        }

        Ok(())
    }

    pub unsafe fn set_port_mac(&mut self, port_index: usize, mac: MacAddr) -> Mlx5Result<()> {
        let vport_num = self
            .ports
            .get(port_index)
            .map(|p| p.port_number())
            .ok_or(Mlx5Error::InvalidParameter)? as u16;

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        build_modify_nic_vport_mac_input(in_mbox, vport_num, false, mac.0);
        cmd.execute(
            CmdOpcode::ModifyNicVportContext,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_mac_address(mac);
        }

        log::info!(target: "mlx5", "Port {} MAC updated to {}", vport_num, mac);
        Ok(())
    }

    pub unsafe fn query_vport_counters(
        &mut self,
        port_num: u8,
        clear_on_read: bool,
    ) -> Mlx5Result<VportCounters> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_vport_counter_input(in_mbox, port_num, clear_on_read);

        cmd.execute(
            CmdOpcode::QueryVportCounter,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let counters = parse_query_vport_counter_output(out_mbox);

        log::trace!(
            target: "mlx5",
            "VPORT counters: rx_unicast={} tx_unicast={} rx_errors={} tx_errors={}",
            counters.rx_unicast_packets,
            counters.tx_unicast_packets,
            counters.rx_error_packets,
            counters.tx_error_packets
        );

        Ok(counters)
    }

    pub fn set_port_mtu(&mut self, port_index: usize, mtu: u32) -> Mlx5Result<()> {
        let port = self.ports.get_mut(port_index).ok_or(Mlx5Error::InvalidParameter)?;
        port.set_mtu(mtu).map_err(|_| Mlx5Error::InvalidParameter)?;
        Ok(())
    }

    pub unsafe fn health_status(&mut self) -> HealthStatus {
        self.health_monitor.check(self.bar0_base)
    }

    pub unsafe fn health_check(&mut self) -> bool {
        !matches!(self.health_status(), HealthStatus::Critical)
    }
}
