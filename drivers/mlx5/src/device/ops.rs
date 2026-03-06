// ============================================================================
// drivers/mlx5/src/device/ops.rs - MLX5 Device Operations
// ============================================================================

extern crate alloc;
use crate::cmd::CmdMailbox;
use crate::cmd::CommandTransport; // for execute() method
use crate::cmd::hca::*; // bring HCA command builders/parsers
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, PortLinkState, VportCounters};
use crate::device::{DeviceState, Mlx5Device};
use crate::eq::EqEvent;
use crate::error::{Mlx5Error, Mlx5Result};
use crate::health::HealthStatus;
use crate::port::MacAddr;
use alloc::vec::Vec;

impl Mlx5Device {
    unsafe fn execute_rebuilt_with_uid_candidates<T, B, F, R>(
        cmd: &mut T,
        in_mbox: &mut CmdMailbox,
        is_vf: bool,
        sw_vhca_id: u16,
        mut build: B,
        mut execute: F,
    ) -> Mlx5Result<R>
    where
        T: CommandTransport,
        B: FnMut(&mut CmdMailbox, u16),
        F: FnMut(&mut T, &CmdMailbox) -> Mlx5Result<R>,
    {
        let prev_uid = cmd.uid();
        let (uids, len) = Self::uid_candidates(prev_uid, is_vf, sw_vhca_id);
        let mut last_err = Err(Mlx5Error::NotSupported);

        for &uid in &uids[..len] {
            cmd.set_uid(uid);
            build(in_mbox, uid);
            match execute(cmd, in_mbox) {
                Ok(value) => {
                    cmd.set_uid(prev_uid);
                    return Ok(value);
                }
                Err(err) => last_err = Err(err),
            }
        }

        cmd.set_uid(prev_uid);
        last_err
    }

    unsafe fn activate_vfs_with_transport<T: CommandTransport>(
        cmd: &mut T,
        in_mbox: &mut CmdMailbox,
        in_mbox_phys: u64,
        out_mbox: &mut CmdMailbox,
        out_mbox_phys: u64,
        is_vf: bool,
        sw_vhca_id: u16,
        num_vfs: u16,
    ) -> Mlx5Result<()> {
        for vf in 0..num_vfs {
            let function_id = vf + 1;
            let vhca_ctx = Self::execute_rebuilt_with_uid_candidates(
                cmd,
                in_mbox,
                is_vf,
                sw_vhca_id,
                |in_mbox, uid| build_query_vhca_state_input(in_mbox, uid, function_id),
                |cmd, _| {
                    cmd.execute(
                        CmdOpcode::QueryVhcaState,
                        in_mbox_phys,
                        0x10,
                        out_mbox_phys,
                        0x20,
                    )?;
                    Ok(parse_query_vhca_state_output(out_mbox))
                },
            )?;

            if !vhca_ctx.state.is_activation_ready() {
                log::warn!(
                    target: "mlx5",
                    "VF {} VHCA state {:?} is not activation-ready",
                    function_id,
                    vhca_ctx.state
                );
                return Err(Mlx5Error::InvalidResponse);
            }

            build_modify_vport_state_input(
                in_mbox,
                MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT,
                function_id,
                true,
                VPORT_ADMIN_STATE_UP,
            );
            cmd.execute(
                CmdOpcode::ModifyVportState,
                in_mbox_phys,
                0x10,
                out_mbox_phys,
                0x10,
            )?;
        }

        Ok(())
    }

    /// パケットを送信
    pub unsafe fn transmit(
        &mut self,
        sq_index: usize,
        data_phys: u64,
        data_virt: u64,
        data_len: u32,
        inline_hdr: &[u8],
    ) -> Mlx5Result<u16> {
        if self.state != DeviceState::Active {
            return Err(Mlx5Error::DeviceNotReady);
        }
        let sq = self
            .sqs
            .get_mut(sq_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let segments = [crate::wq::DmaSegment {
            device_addr: data_phys,
            virt_addr: data_virt,
            len: data_len,
        }];
        sq.post_send(&segments, inline_hdr)
            .ok_or(Mlx5Error::NoResources)
    }

    /// 受信バッファを投入
    pub unsafe fn post_receive(
        &mut self,
        rq_index: usize,
        buf_phys: u64,
        buf_virt: u64,
        buf_size: u32,
    ) -> Mlx5Result<u16> {
        if self.state != DeviceState::Active && self.state != DeviceState::QueuesReady {
            return Err(Mlx5Error::DeviceNotReady);
        }
        let rq = self
            .rqs
            .get_mut(rq_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        rq.post_recv(buf_phys, buf_virt, buf_size)
            .ok_or(Mlx5Error::NoResources)
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
            if !events.is_empty() {
                eq.update_doorbell();
            }
        }
        events
    }

    pub unsafe fn poll_cq(&mut self, cq_index: usize, max_batch: u32) -> Vec<crate::cq::CqeInfo> {
        let batch = self.polling_state.max_batch_size().min(max_batch);
        let result = if let Some(cq) = self.cqs.get_mut(cq_index) {
            cq.poll_batch(batch)
        } else {
            Vec::new()
        };
        let need_rearm = self.polling_state.record_poll_cycle(result.len() as u32);
        if need_rearm {
            if let Some(cq) = self.cqs.get(cq_index) {
                cq.arm();
            }
        }
        result
    }

    pub fn process_tx_completions(
        &mut self,
        sq_index: usize,
        wqe_counter: u16,
    ) -> Option<crate::wq::TxBufferInfo> {
        self.sqs
            .get_mut(sq_index)
            .and_then(|sq| sq.complete_tx(wqe_counter))
    }

    pub fn process_rx_completion(
        &mut self,
        rq_index: usize,
        wqe_counter: u16,
    ) -> Option<crate::wq::RxBufferInfo> {
        self.rqs
            .get_mut(rq_index)
            .and_then(|rq| rq.complete_rx(wqe_counter))
    }

    pub unsafe fn activate_vfs(&mut self, num_vfs: u16) -> Mlx5Result<()> {
        if self.is_vf() {
            return Err(Mlx5Error::NotSupported);
        }
        let caps = self.hca_caps.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        if !caps.vport_group_manager {
            return Err(Mlx5Error::NotSupported);
        }
        let is_vf = self.is_vf();
        let sw_vhca_id = self.sw_vhca_id;
        let in_mbox_phys = self.cmd_in_mbox_device;
        let out_mbox_phys = self.cmd_out_mbox_device;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let out_mbox = &mut *(self.cmd_out_mbox_virt as *mut CmdMailbox);
        Self::activate_vfs_with_transport(
            cmd,
            in_mbox,
            in_mbox_phys,
            out_mbox,
            out_mbox_phys,
            is_vf,
            sw_vhca_id,
            num_vfs,
        )
    }

    pub unsafe fn query_port_state(&mut self, port_index: usize) -> Mlx5Result<PortLinkState> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_vport_state_input(in_mbox, query_vport_state_op_mod_vnic_vport(), 0, false);
        cmd.execute(
            CmdOpcode::QueryVportState,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let (admin, oper, _max_tx_speed) = parse_query_vport_state_output(out_mbox);
        let link_state = match oper {
            0x01 => PortLinkState::Up,
            0x00 => PortLinkState::Down,
            _ => PortLinkState::Unknown,
        };
        if let Some(port) = self.ports.get_mut(port_index) {
            if admin == 0 {
                port.admin_down();
            } else {
                port.admin_up();
            }
            port.set_link_state(link_state);
        }
        Ok(link_state)
    }

    pub unsafe fn query_port_mac(&mut self, port_index: usize) -> Mlx5Result<MacAddr> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let query_patterns: &[(bool, Option<u8>, &str)] = &[
            (false, None, "self-permanent"),
            (false, Some(0), "self-uc-list"),
            (true, None, "other-vport-permanent"),
            (true, Some(0), "other-vport-uc-list"),
        ];

        let mut last_cmd_status = None;

        for (other_vport, allowed_list_type, label) in query_patterns {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_query_nic_vport_context_input(in_mbox, 0, *other_vport, *allowed_list_type);
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
                    let mac_bytes = if allowed_list_type.is_some() {
                        let list_size = parse_query_nic_vport_context_allowed_list_size(out_mbox);
                        (0..list_size)
                            .find_map(|index| {
                                parse_query_nic_vport_context_allowed_list_mac(out_mbox, index)
                            })
                            .unwrap_or([0; 6])
                    } else {
                        parse_query_nic_vport_context_mac(out_mbox)
                    };
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

    unsafe fn query_port_mtu(&mut self, port_index: usize) -> Mlx5Result<u32> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_nic_vport_context_input(in_mbox, 0, false, None);
        cmd.execute(
            CmdOpcode::QueryNicVportContext,
            self.cmd_in_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
            self.cmd_out_mbox_device,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        let mtu = parse_query_nic_vport_context_mtu(out_mbox) as u32;
        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_mtu(mtu).map_err(|_| Mlx5Error::InvalidResponse)?;
        }
        Ok(mtu)
    }

    unsafe fn query_vnic_env(
        &mut self,
        vport_number: u16,
        other_vport: bool,
    ) -> Mlx5Result<VnicEnvCounters> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        build_query_vnic_env_input(in_mbox, vport_number, other_vport);
        cmd.execute(
            CmdOpcode::QueryVnicEnv,
            self.cmd_in_mbox_device,
            0x10,
            self.cmd_out_mbox_device,
            0x40,
        )?;

        let out_mbox = &*(self.cmd_out_mbox_virt as *const CmdMailbox);
        Ok(parse_query_vnic_env_output(out_mbox))
    }

    pub unsafe fn refresh_port_runtime_state(&mut self, port_index: usize) -> Mlx5Result<()> {
        let _ = self.query_port_mac(port_index)?;
        let _ = self.query_port_state(port_index)?;
        let _ = self.query_port_mtu(port_index)?;
        let vnic_env = self.query_vnic_env(0, false)?;

        if let Some(port) = self.ports.get_mut(port_index) {
            let stats = port.stats_mut();
            stats.rx_dropped = vnic_env.receive_discard_vport_down;
            stats.tx_dropped = vnic_env.transmit_discard_vport_down;
        }

        Ok(())
    }

    pub unsafe fn update_port_stats(&mut self, port_index: usize) -> Mlx5Result<()> {
        let port_num = self
            .ports
            .get(port_index)
            .map(|p| p.port_number())
            .ok_or(Mlx5Error::InvalidParameter)?;

        let counters = self.query_vport_counters(port_num, false)?;
        let vnic_env = self.query_vnic_env(0, false)?;

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
            stats.rx_dropped = vnic_env.receive_discard_vport_down;
            stats.tx_dropped = vnic_env.transmit_discard_vport_down;
        }

        Ok(())
    }

    pub unsafe fn set_port_mac(&mut self, port_index: usize, mac: MacAddr) -> Mlx5Result<()> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);

        build_modify_nic_vport_mac_input(in_mbox, 0, false, mac.0);
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

        log::info!(target: "mlx5", "Port {} MAC updated to {}", port_index + 1, mac);
        Ok(())
    }

    pub unsafe fn query_vport_counters(
        &mut self,
        port_num: u8,
        clear_on_read: bool,
    ) -> Mlx5Result<VportCounters> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
        let include_port_num = self
            .hca_caps
            .as_ref()
            .map(|caps| caps.num_ports > 1)
            .unwrap_or(false);
        build_query_vport_counter_input(
            in_mbox,
            0,
            false,
            if include_port_num {
                Some(port_num)
            } else {
                None
            },
            clear_on_read,
        );

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
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        if !(68..=crate::defs::MLX5_MAX_MTU).contains(&mtu) {
            return Err(Mlx5Error::InvalidParameter);
        }

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        unsafe {
            let in_mbox = &mut *(self.cmd_in_mbox_virt as *mut CmdMailbox);
            build_modify_nic_vport_mtu_input(in_mbox, 0, false, mtu as u16);
            cmd.execute(
                CmdOpcode::ModifyNicVportContext,
                self.cmd_in_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
                self.cmd_out_mbox_device,
                MLX5_CMD_MBOX_SIZE as u32,
            )?;
        }

        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_mtu(mtu).map_err(|_| Mlx5Error::InvalidParameter)?;
        }
        Ok(())
    }

    pub unsafe fn health_status(&mut self) -> HealthStatus {
        self.health_monitor.check(self.bar0_base)
    }

    pub unsafe fn health_check(&mut self) -> bool {
        !matches!(self.health_status(), HealthStatus::Critical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::{get_bits_u32, set_bits_u32};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct CallSnapshot {
        opcode: CmdOpcode,
        uid: u16,
        encoded_uid: u16,
        function_id: u16,
        op_mod: u16,
        other_vport: bool,
        vport_number: u16,
        admin_state: u8,
    }

    struct FakeTransport {
        uid: u16,
        in_mbox: *const CmdMailbox,
        out_mbox: *mut CmdMailbox,
        valid_query_uid: u16,
        query_state: VhcaState,
        calls: Vec<CallSnapshot>,
    }

    impl FakeTransport {
        fn new(
            in_mbox: &CmdMailbox,
            out_mbox: &mut CmdMailbox,
            valid_query_uid: u16,
            query_state: VhcaState,
        ) -> Self {
            Self {
                uid: 0,
                in_mbox: in_mbox as *const CmdMailbox,
                out_mbox: out_mbox as *mut CmdMailbox,
                valid_query_uid,
                query_state,
                calls: Vec::new(),
            }
        }
    }

    impl CommandTransport for FakeTransport {
        unsafe fn execute(
            &mut self,
            opcode: CmdOpcode,
            _in_mbox_phys: u64,
            _in_len: u32,
            _out_mbox_phys: u64,
            _out_len: u32,
        ) -> Mlx5Result<()> {
            let in_mbox = &*self.in_mbox;
            match opcode {
                CmdOpcode::QueryVhcaState => {
                    let encoded_uid = get_bits_u32(&in_mbox.data[..], 16, 16) as u16;
                    let function_id = get_bits_u32(&in_mbox.data[..], 80, 16) as u16;
                    self.calls.push(CallSnapshot {
                        opcode,
                        uid: self.uid,
                        encoded_uid,
                        function_id,
                        op_mod: 0,
                        other_vport: false,
                        vport_number: 0,
                        admin_state: 0,
                    });

                    if self.uid != self.valid_query_uid {
                        return Err(Mlx5Error::CommandFailed(0x03));
                    }

                    let out_mbox = &mut *self.out_mbox;
                    *out_mbox = CmdMailbox::zeroed();
                    set_bits_u32(&mut out_mbox.data[..], 140, 4, self.query_state as u32);
                    Ok(())
                }
                CmdOpcode::ModifyVportState => {
                    self.calls.push(CallSnapshot {
                        opcode,
                        uid: self.uid,
                        encoded_uid: 0,
                        function_id: 0,
                        op_mod: get_bits_u32(&in_mbox.data[..], 48, 16) as u16,
                        other_vport: get_bits_u32(&in_mbox.data[..], 64, 1) != 0,
                        vport_number: get_bits_u32(&in_mbox.data[..], 80, 16) as u16,
                        admin_state: get_bits_u32(&in_mbox.data[..], 120, 4) as u8,
                    });
                    Ok(())
                }
                CmdOpcode::ModifyVhcaState => {
                    self.calls.push(CallSnapshot {
                        opcode,
                        uid: self.uid,
                        encoded_uid: get_bits_u32(&in_mbox.data[..], 16, 16) as u16,
                        function_id: get_bits_u32(&in_mbox.data[..], 80, 16) as u16,
                        op_mod: 0,
                        other_vport: false,
                        vport_number: 0,
                        admin_state: 0,
                    });
                    Ok(())
                }
                _ => Err(Mlx5Error::InvalidParameter),
            }
        }

        fn set_uid(&mut self, uid: u16) {
            self.uid = uid;
        }

        fn uid(&self) -> u16 {
            self.uid
        }
    }

    #[test]
    fn activate_vfs_rebuilds_vhca_query_mailboxes_and_only_admins_up_after_validation() {
        let mut in_mbox = CmdMailbox::zeroed();
        let mut out_mbox = CmdMailbox::zeroed();
        let mut transport = FakeTransport::new(&in_mbox, &mut out_mbox, 0xffff, VhcaState::Allocated);

        unsafe {
            Mlx5Device::activate_vfs_with_transport(
                &mut transport,
                &mut in_mbox,
                0,
                &mut out_mbox,
                0,
                true,
                0x2222,
                1,
            )
        }
        .unwrap();

        assert_eq!(transport.calls.len(), 3);
        assert_eq!(transport.calls[0].opcode, CmdOpcode::QueryVhcaState);
        assert_eq!(transport.calls[0].uid, 0);
        assert_eq!(transport.calls[0].encoded_uid, 0);
        assert_eq!(transport.calls[0].function_id, 1);
        assert_eq!(transport.calls[1].opcode, CmdOpcode::QueryVhcaState);
        assert_eq!(transport.calls[1].uid, 0xffff);
        assert_eq!(transport.calls[1].encoded_uid, 0xffff);
        assert_eq!(transport.calls[1].function_id, 1);
        assert_eq!(transport.calls[2].opcode, CmdOpcode::ModifyVportState);
        assert_eq!(transport.calls[2].op_mod, MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT);
        assert!(transport.calls[2].other_vport);
        assert_eq!(transport.calls[2].vport_number, 1);
        assert_eq!(transport.calls[2].admin_state, VPORT_ADMIN_STATE_UP);
        assert!(!transport
            .calls
            .iter()
            .any(|call| call.opcode == CmdOpcode::ModifyVhcaState));
    }

    #[test]
    fn activate_vfs_stops_before_admin_up_when_vhca_state_is_invalid() {
        let mut in_mbox = CmdMailbox::zeroed();
        let mut out_mbox = CmdMailbox::zeroed();
        let mut transport = FakeTransport::new(&in_mbox, &mut out_mbox, 0, VhcaState::Invalid);

        let err = unsafe {
            Mlx5Device::activate_vfs_with_transport(
                &mut transport,
                &mut in_mbox,
                0,
                &mut out_mbox,
                0,
                true,
                0x2222,
                1,
            )
        }
        .unwrap_err();

        assert_eq!(err, Mlx5Error::InvalidResponse);
        assert_eq!(transport.calls.len(), 1);
        assert_eq!(transport.calls[0].opcode, CmdOpcode::QueryVhcaState);
        assert!(!transport
            .calls
            .iter()
            .any(|call| call.opcode == CmdOpcode::ModifyVportState));
    }
}
