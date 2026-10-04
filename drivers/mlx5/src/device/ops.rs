// ============================================================================
// drivers/mlx5/src/device/ops.rs - MLX5 Device Operations
// ============================================================================

extern crate alloc;
use crate::cmd::hca::*; // bring HCA command builders/parsers
use crate::cmd::{CmdMailbox, CmdQueue};
use crate::defs::{CmdOpcode, MLX5_CMD_MBOX_SIZE, PortLinkState, VportCounters};
use crate::device::{DeviceState, Mlx5Device};
use crate::error::{Mlx5Error, Mlx5Result, WorkSubmissionError};
use crate::health::HealthStatus;
use crate::port::MacAddr;
use alloc::vec::Vec;

impl Mlx5Device {
    /// 単一または少数 segment の packet を送信
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept the operation.
    pub unsafe fn transmit_segments(
        &mut self,
        sq_index: usize,
        segments: &[crate::wq::DmaSegment],
        total_len: u32,
        options: crate::wq::TxOptions,
    ) -> Result<u16, WorkSubmissionError> {
        if self.state != DeviceState::Active {
            return Err(WorkSubmissionError::NotPublished(Mlx5Error::DeviceNotReady));
        }
        let sq = self
            .sqs
            .get_mut(sq_index)
            .ok_or(WorkSubmissionError::NotPublished(
                Mlx5Error::InvalidParameter,
            ))?;

        if total_len == 0 || segments.is_empty() {
            return Err(WorkSubmissionError::NotPublished(
                Mlx5Error::InvalidParameter,
            ));
        }

        sq.post_send(segments, options)
    }

    /// パケットを送信
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the device cannot accept the operation.
    pub unsafe fn transmit(
        &mut self,
        sq_index: usize,
        data_phys: u64,
        data_virt: u64,
        data_len: u32,
        options: crate::wq::TxOptions,
    ) -> Result<u16, WorkSubmissionError> {
        if data_len == 0 {
            return Err(WorkSubmissionError::NotPublished(
                Mlx5Error::InvalidParameter,
            ));
        }

        let segments = [crate::wq::DmaSegment {
            device_addr: data_phys,
            virt_addr: data_virt,
            len: data_len,
        }];
        self.transmit_segments(sq_index, &segments, data_len, options)
    }

    /// 受信バッファを投入
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn post_receive(
        &mut self,
        rq_index: usize,
        buf_phys: u64,
        buf_virt: u64,
        buf_size: u32,
    ) -> Result<crate::wq::ReceivePost, WorkSubmissionError> {
        if self.state != DeviceState::Active && self.state != DeviceState::QueuesReady {
            return Err(WorkSubmissionError::NotPublished(Mlx5Error::DeviceNotReady));
        }
        let rq = self
            .rqs
            .get_mut(rq_index)
            .ok_or(WorkSubmissionError::NotPublished(
                Mlx5Error::InvalidParameter,
            ))?;
        rq.post_recv(buf_phys, buf_virt, buf_size)
    }

    /// Ordinary service-task polling, with allocation before consuming entries.
    /// A failed read/ack retains the successfully consumed prefix in the result.
    pub(crate) fn poll_cq(
        &mut self,
        cq_index: usize,
        max_batch: u32,
    ) -> crate::cq::CompletionBatch {
        let mut entries = Vec::new();
        let batch = self.polling_state.max_batch_size().min(max_batch);
        if entries.try_reserve_exact(batch as usize).is_err() {
            return crate::cq::CompletionBatch {
                entries,
                completion: Err(Mlx5Error::OutOfMemory),
            };
        }
        let completion = (|| {
            let cq = self
                .cqs
                .get_mut(cq_index)
                .ok_or(Mlx5Error::InvalidParameter)?;
            for _ in 0..batch {
                match cq.next()? {
                    Some(entry) => entries.push(entry),
                    None => break,
                }
            }
            if !entries.is_empty() {
                cq.acknowledge()?;
            }
            if self.polling_state.record_poll_cycle(entries.len() as u32) {
                cq.arm()?;
            }
            Ok(())
        })();
        if completion.is_err() {
            self.state = DeviceState::Error;
        }
        crate::cq::CompletionBatch {
            entries,
            completion,
        }
    }

    /// Queue snapshots are observations of retained RAM, never completion proofs.
    ///
    /// # Errors
    /// An invalid queue index or inaccessible retained DMA mapping cannot
    /// produce a snapshot and leaves the outstanding work unchanged.
    pub fn debug_rx_queue_state(
        &mut self,
        index: usize,
    ) -> Mlx5Result<crate::wq::RxQueueDebugState> {
        self.rqs
            .get_mut(index)
            .ok_or(Mlx5Error::InvalidParameter)?
            .debug_state()
    }
    /// # Errors
    /// An invalid queue index or inaccessible retained DMA mapping leaves
    /// outstanding transmissions unchanged.
    pub fn debug_tx_queue_state(
        &mut self,
        index: usize,
    ) -> Mlx5Result<crate::wq::TxQueueDebugState> {
        self.sqs
            .get_mut(index)
            .ok_or(Mlx5Error::InvalidParameter)?
            .debug_state()
    }
    pub fn debug_tx_wqe_state(
        &self,
        index: usize,
        counter: u16,
    ) -> Option<crate::wq::TxWqeDebugInfo> {
        self.sqs.get(index)?.debug_wqe_state(counter)
    }
    /// # Errors
    /// An invalid queue index or inaccessible retained DMA mapping leaves
    /// completion ownership unchanged.
    pub fn debug_cq_state(&mut self, index: usize) -> Mlx5Result<crate::cq::CqDebugState> {
        self.cqs
            .get_mut(index)
            .ok_or(Mlx5Error::InvalidParameter)?
            .snapshot()
    }

    /// Only this queue's matching request CQE can retire its active counter.
    pub(crate) fn process_tx_completion(
        &mut self,
        index: usize,
        cq_index: usize,
        entry: &crate::cq::CqeInfo,
    ) -> Mlx5Result<()> {
        let cqn = self.cqs.get(cq_index).and_then(|cq| cq.number());
        let sq = self.sqs.get_mut(index).ok_or(Mlx5Error::InvalidParameter)?;
        if cqn != Some(sq.cqn)
            || sq.number() != Some(entry.qpn)
            || !matches!(
                entry.opcode,
                crate::defs::CqeOpcode::ReqOk | crate::defs::CqeOpcode::ReqErr
            )
        {
            return Err(Mlx5Error::InvalidResponse);
        }
        sq.complete_tx(entry.wqe_counter)
    }

    /// Reads a coherent hardware timestamp, or fails after a bounded rollover
    /// retry budget. An unresponsive device cannot keep the caller spinning.
    ///
    /// # Errors
    /// Register access failure or eight consecutive rollover samples leave
    /// the timestamp unavailable without changing device state.
    pub fn query_time(&self) -> Mlx5Result<u64> {
        for _ in 0..8 {
            if let Some(time) = self.registers.timer_sample()? {
                return Ok(time);
            }
        }
        Err(Mlx5Error::DeviceNotReady)
    }

    /// PTP (Precision Time Protocol) サポート状況を確認
    pub fn ptp_caps(&self) -> Option<(u8, u32)> {
        self.hca_caps
            .as_ref()
            .map(|caps| (caps.rq_ts_format, caps.device_frequency_khz))
    }

    /// Only this queue's matching response CQE can return a posted receive slot.
    pub(crate) fn process_rx_completion(
        &mut self,
        index: usize,
        cq_index: usize,
        entry: &crate::cq::CqeInfo,
    ) -> Mlx5Result<crate::wq::RxBufferInfo> {
        let cqn = self.cqs.get(cq_index).and_then(|cq| cq.number());
        let rq = self.rqs.get_mut(index).ok_or(Mlx5Error::InvalidParameter)?;
        if cqn != Some(rq.cqn)
            || rq.number() != Some(entry.qpn)
            || !matches!(
                entry.opcode,
                crate::defs::CqeOpcode::RespOk | crate::defs::CqeOpcode::RespErr
            )
        {
            return Err(Mlx5Error::InvalidResponse);
        }
        rq.complete_rx(entry.wqe_counter, entry.l3_ok, entry.l4_ok)
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn query_vhca_state(&mut self, function_id: u16) -> Mlx5Result<VhcaStateContext> {
        let is_vf = self.is_vf();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        let out_mbox = &mut *self.cmd_output;

        query_vhca_command(
            cmd.uid(),
            is_vf,
            function_id,
            in_mbox,
            out_mbox,
            &mut |opcode, uid, input, output| execute_vf_command(cmd, opcode, uid, input, output),
        )
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub unsafe fn activate_vfs(&mut self, num_vfs: u16) -> Mlx5Result<()> {
        if self.is_vf() {
            return Err(Mlx5Error::NotSupported);
        }
        let caps = self.hca_caps.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        if !caps.vport_group_manager {
            return Err(Mlx5Error::NotSupported);
        }
        let is_vf = self.is_vf();
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        let out_mbox = &mut *self.cmd_output;
        activate_vf_commands(
            cmd.uid(),
            is_vf,
            num_vfs,
            in_mbox,
            out_mbox,
            |opcode, uid, input, output| execute_vf_command(cmd, opcode, uid, input, output),
        )
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub unsafe fn deactivate_vfs(&mut self, num_vfs: u16) -> Mlx5Result<()> {
        if self.is_vf() {
            return Err(Mlx5Error::NotSupported);
        }
        let caps = self.hca_caps.as_ref().ok_or(Mlx5Error::DeviceNotReady)?;
        if !caps.vport_group_manager {
            return Err(Mlx5Error::NotSupported);
        }
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        deactivate_vf_commands(
            cmd.uid(),
            num_vfs,
            in_mbox,
            &mut self.cmd_output,
            |opcode, uid, input, output| execute_vf_command(cmd, opcode, uid, input, output),
        )
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn query_port_state(&mut self, port_index: usize) -> Mlx5Result<PortLinkState> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_query_vport_state_input(in_mbox, query_vport_state_op_mod_vnic_vport(), 0, false);
        self.execute_command(
            CmdOpcode::QueryVportState,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;
        let out_mbox = &*self.cmd_output;
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

    /// Drains at most one ring traversal per EQ on the ordinary service task.
    /// Consumed events remain owned until their action completes. A read,
    /// acknowledgement or action failure closes normal device admission;
    /// retained RAM/events require shutdown or explicit reset reconciliation.
    ///
    /// # Errors
    /// Returns allocation/admission errors before consuming entries, or the
    /// original registry/firmware error with all unperformed actions retained.
    pub fn process_events(&mut self) -> Mlx5Result<u32> {
        use crate::device::FirmwareEvent;
        if self.state == DeviceState::Error {
            return Err(Mlx5Error::DeviceNotReady);
        }
        let capacity = self
            .eqs
            .iter()
            .try_fold(0usize, |sum, eq| sum.checked_add(eq.depth() as usize))
            .ok_or(Mlx5Error::NoResources)?;
        self.pending_events
            .try_reserve(capacity)
            .map_err(|_| Mlx5Error::OutOfMemory)?;
        let result = (|| {
            let mut processed = 0;
            for eq in &mut self.eqs {
                for _ in 0..eq.depth() {
                    let Some(entry) = eq.next()? else { break };
                    processed += 1;
                    match entry.event_type() {
                        Some(crate::defs::EventType::PortStateChange) => {
                            self.pending_events.push_back(FirmwareEvent::RefreshPort(
                                (entry.port_number() as usize).saturating_sub(1),
                            ))
                        }
                        Some(crate::defs::EventType::NicVportChange) => self
                            .pending_events
                            .push_back(FirmwareEvent::RefreshPrimaryPortConfig),
                        Some(crate::defs::EventType::PageRequest) => {
                            self.pending_events.push_back(FirmwareEvent::Pages {
                                function: entry.function_id(),
                                count: entry.requested_pages(),
                            })
                        }
                        _ => {}
                    }
                }
                eq.acknowledge()?;
            }
            // LOOP_PROOF: mode=condition; reason=The preceding finite EQ scan is the only producer under exclusive device access, and each acknowledged event is removed or retains a terminal error.;
            while let Some(event) = self.pending_events.front().copied() {
                match event {
                    FirmwareEvent::RefreshPort(index) => {
                        unsafe { self.refresh_port_runtime_state(index) }?;
                    }
                    FirmwareEvent::RefreshPrimaryPortConfig => {
                        unsafe { self.query_port_mac(0) }?;
                        unsafe { self.query_port_mtu(0) }?;
                    }
                    FirmwareEvent::Pages { function, count } => {
                        self.service_fw_page_event(function, count)?
                    }
                }
                self.pending_events.pop_front();
            }
            Ok(processed)
        })();
        if result.is_err() {
            self.state = DeviceState::Error;
        }
        result
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn query_port_mac(&mut self, port_index: usize) -> Mlx5Result<MacAddr> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        let query_patterns: &[(bool, Option<u8>, &str)] = &[
            (false, None, "self-permanent"),
            (false, Some(0), "self-uc-list"),
            (true, None, "other-vport-permanent"),
            (true, Some(0), "other-vport-uc-list"),
        ];

        let mut last_cmd_status = None;

        for (other_vport, allowed_list_type, label) in query_patterns {
            let mut command_input = CmdMailbox::zeroed();
            let in_mbox = &mut command_input;
            build_query_nic_vport_context_input(in_mbox, 0, *other_vport, *allowed_list_type);
            match self.execute_command(
                CmdOpcode::QueryNicVportContext,
                in_mbox,
                MLX5_CMD_MBOX_SIZE as u32,
                MLX5_CMD_MBOX_SIZE as u32,
            ) {
                Ok(()) => {
                    let out_mbox = &*self.cmd_output;
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
                Err(crate::error::CommandFailure::Rejected(status)) => {
                    last_cmd_status = Some(status);
                    log::debug!(
                        target: "mlx5",
                        "QUERY_NIC_VPORT_CONTEXT ({}) failed with status={:#x}",
                        label,
                        status
                    );
                }
                Err(err) => return Err(err.cause()),
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

    /// VPort カウンタをクエリして統計情報を取得
    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn query_vport_stats(
        &mut self,
        port_index: usize,
    ) -> Mlx5Result<crate::defs::VportCounters> {
        let is_vf = self.is_vf();
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        let vport_num = if is_vf { 0 } else { (port_index + 1) as u16 };

        crate::cmd::hca::build_query_vport_counter_input(
            in_mbox, vport_num, false, // self
            None, false, // clear=false
        );

        self.execute_command(
            CmdOpcode::QueryVportCounter,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*self.cmd_output;
        let counters = crate::cmd::hca::parse_query_vport_counter_output(out_mbox);

        log::debug!(
            target: "mlx5::stats",
            "VPort {}: RX={}/{}B, TX={}/{}B, RX_ERR={}, TX_ERR={}",
            vport_num,
            counters.rx_unicast_packets,
            counters.rx_unicast_bytes,
            counters.tx_unicast_packets,
            counters.tx_unicast_bytes,
            counters.rx_error_packets,
            counters.tx_error_packets
        );

        Ok(counters)
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn query_nic_vport_promisc(&mut self) -> Mlx5Result<(bool, bool, bool)> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_query_nic_vport_context_input(in_mbox, 0, false, None);
        cmd.execute(
            CmdOpcode::QueryNicVportContext,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*self.cmd_output;
        Ok(parse_query_nic_vport_context_promisc(out_mbox))
    }

    pub(crate) unsafe fn query_port_mtu(&mut self, port_index: usize) -> Mlx5Result<u32> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_query_nic_vport_context_input(in_mbox, 0, false, None);
        cmd.execute(
            CmdOpcode::QueryNicVportContext,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*self.cmd_output;
        let mtu = parse_query_nic_vport_context_mtu(out_mbox) as u32;
        let min_inline_mode = parse_query_nic_vport_context_min_inline_mode(out_mbox);
        log::info!(
            target: "mlx5",
            "NIC vport context: mtu={} min_wqe_inline_mode={}",
            mtu,
            min_inline_mode
        );
        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_mtu(mtu).map_err(|_| Mlx5Error::InvalidResponse)?;
            port.set_min_wqe_inline_mode(min_inline_mode);
        }
        Ok(mtu)
    }

    unsafe fn query_vnic_env(
        &mut self,
        vport_number: u16,
        other_vport: bool,
    ) -> Mlx5Result<VnicEnvCounters> {
        if self.is_vf() {
            if !self.vnic_env_query_logged {
                log::info!(
                    target: "mlx5",
                    "Skipping QUERY_VNIC_ENV on VF; using zero vNIC environment counters"
                );
                self.vnic_env_query_logged = true;
            }
            return Ok(VnicEnvCounters {
                receive_discard_vport_down: 0,
                transmit_discard_vport_down: 0,
            });
        }

        if self.vnic_env_query_logged {
            return Err(Mlx5Error::NotSupported);
        }

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_query_vnic_env_input(in_mbox, vport_number, other_vport);
        if let Err(err) = cmd.execute(
            CmdOpcode::QueryVnicEnv,
            in_mbox,
            0x10,
            &mut self.cmd_output,
            0x40,
        ) {
            if !self.vnic_env_query_logged {
                log::warn!(
                    target: "mlx5",
                    "QUERY_VNIC_ENV unavailable on this function; suppressing further warnings: {:?}",
                    err
                );
                self.vnic_env_query_logged = true;
            }
            return Err(err.cause());
        }

        let out_mbox = &*self.cmd_output;
        Ok(parse_query_vnic_env_output(out_mbox))
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub unsafe fn refresh_port_runtime_state(&mut self, port_index: usize) -> Mlx5Result<()> {
        let _ = self.query_port_mac(port_index)?;
        let _ = self.query_port_state(port_index)?;
        let _ = self.query_port_mtu(port_index)?;
        let vnic_env = self.query_vnic_env(0, false).ok();

        if let (Some(port), Some(vnic_env)) = (self.ports.get_mut(port_index), vnic_env) {
            let stats = port.stats_mut();
            stats.rx_dropped = vnic_env.receive_discard_vport_down;
            stats.tx_dropped = vnic_env.transmit_discard_vport_down;
        }

        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub unsafe fn update_port_stats(&mut self, port_index: usize) -> Mlx5Result<()> {
        let port_num = self
            .ports
            .get(port_index)
            .map(|p| p.port_number())
            .ok_or(Mlx5Error::InvalidParameter)?;

        let counters = self.query_vport_counters(port_num, false)?;
        let vnic_env = self.query_vnic_env(0, false).ok();

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
            if let Some(vnic_env) = vnic_env {
                stats.rx_dropped = vnic_env.receive_discard_vport_down;
                stats.tx_dropped = vnic_env.transmit_discard_vport_down;
            }
        }

        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub unsafe fn set_port_mac(&mut self, port_index: usize, mac: MacAddr) -> Mlx5Result<()> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        let mut command_input = CmdMailbox::zeroed();

        let in_mbox = &mut command_input;
        build_modify_nic_vport_mac_input(in_mbox, 0, false, mac.0);

        self.execute_command(
            CmdOpcode::ModifyNicVportContext,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_mac_address(mac);
        }

        log::info!(target: "mlx5", "Port {} MAC updated to {}", port_index + 1, mac);
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the request is invalid or the required device state cannot be read.
    pub unsafe fn query_vport_counters(
        &mut self,
        port_num: u8,
        clear_on_read: bool,
    ) -> Mlx5Result<VportCounters> {
        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
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
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        let out_mbox = &*self.cmd_output;
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

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn set_port_mtu(&mut self, port_index: usize, mtu: u32) -> Mlx5Result<()> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;
        if !(68..=crate::defs::MLX5_MAX_MTU).contains(&mtu) {
            return Err(Mlx5Error::InvalidParameter);
        }

        let cmd = self.cmd.as_mut().ok_or(Mlx5Error::DeviceNotReady)?;
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_modify_nic_vport_mtu_input(in_mbox, 0, false, mtu as u16);
        cmd.execute(
            CmdOpcode::ModifyNicVportContext,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            &mut self.cmd_output,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        if let Some(port) = self.ports.get_mut(port_index) {
            port.set_mtu(mtu).map_err(|_| Mlx5Error::InvalidParameter)?;
        }
        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn set_nic_vport_promisc(
        &mut self,
        promisc_uc: bool,
        promisc_mc: bool,
        promisc_all: bool,
    ) -> Mlx5Result<()> {
        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_modify_nic_vport_promisc_input(
            in_mbox,
            0,
            false,
            promisc_uc,
            promisc_mc,
            promisc_all,
        );

        self.execute_command(
            CmdOpcode::ModifyNicVportContext,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        match unsafe { self.query_nic_vport_promisc() } {
            Ok((uc, mc, all)) => log::info!(
                target: "mlx5",
                "NIC vport promisc updated: uc={} mc={} all={}",
                uc,
                mc,
                all
            ),
            Err(err) => log::warn!(
                target: "mlx5",
                "NIC vport promisc update applied but QUERY_NIC_VPORT_CONTEXT verify failed: {:?}",
                err
            ),
        }

        Ok(())
    }

    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub fn set_port_admin_up(&mut self, port_index: usize) -> Mlx5Result<()> {
        self.ports
            .get(port_index)
            .ok_or(Mlx5Error::InvalidParameter)?;

        let mut command_input = CmdMailbox::zeroed();
        let in_mbox = &mut command_input;
        build_modify_vport_state_input(in_mbox, 0, 0, false, VPORT_ADMIN_STATE_UP);
        self.execute_command(
            CmdOpcode::ModifyVportState,
            in_mbox,
            MLX5_CMD_MBOX_SIZE as u32,
            MLX5_CMD_MBOX_SIZE as u32,
        )?;

        if let Some(port) = self.ports.get_mut(port_index) {
            port.admin_up();
        }
        Ok(())
    }

    /// Samples the retained health aperture. This does not establish reset or
    /// DMA quiescence; callers must use the explicit recovery protocol.
    ///
    /// # Errors
    /// Register access failure does not establish a new health observation
    /// or release any outstanding device resource.
    pub fn health_status(&mut self) -> Mlx5Result<HealthStatus> {
        let counter = self.registers.health_counter()?;
        let bytes = self.registers.health_buffer()?;
        let layout = crate::structs::health::HealthLayout::new(&bytes);
        Ok(self
            .health_monitor
            .observe(counter, layout.full_reset_required()))
    }

    /// # Errors
    /// Propagates an unavailable health sample without proving quiescence.
    pub fn health_check(&mut self) -> Mlx5Result<bool> {
        Ok(!matches!(self.health_status()?, HealthStatus::Critical))
    }

    /// プロミスキャスモードを設定
    /// # Errors
    ///
    /// Returns an error if the requested state transition is invalid or rejected by the device.
    pub unsafe fn set_promiscuous_mode(&mut self, enable: bool) -> Mlx5Result<()> {
        if self.flow_tables.is_empty() {
            return Err(Mlx5Error::NotSupported);
        }
        let table_id = self.flow_tables[0].table_id;
        let tirn = self
            .tir_list
            .first()
            .map(|t| t.tirn)
            .ok_or(Mlx5Error::NotSupported)?;

        let group_id = self
            .flow_groups
            .iter()
            .find(|g| g.start_index == 64)
            .map(|g| g.group_id)
            .ok_or(Mlx5Error::NotSupported)?;

        if enable {
            let match_value = crate::flow::MatchValue::default();
            self.set_flow_table_entry(
                table_id,
                64,
                group_id,
                crate::flow::FlowAction::Allow,
                Some(tirn),
                &match_value,
            )?;
        } else {
            let mut command_input = CmdMailbox::zeroed();
            let in_mbox = &mut command_input;
            crate::cmd::flow::build_delete_flow_table_entry_input(in_mbox, table_id, 64);
            self.execute_command(CmdOpcode::DeleteFlowTableEntry, in_mbox, 0x10, 0x10)?;
        }

        log::info!(target: "mlx5", "Promiscuous mode: {}", if enable { "enabled" } else { "disabled" });
        Ok(())
    }
}

/// VF orchestration sees only CPU request/response data. The adapter retains
/// the actual command resource and restores its UID even on a failed operation.
fn execute_vf_command(
    command: &mut CmdQueue,
    opcode: CmdOpcode,
    uid: u16,
    input: &CmdMailbox,
    output: &mut CmdMailbox,
) -> Result<(), crate::error::CommandFailure> {
    let previous = command.uid();
    command.set_uid(uid);
    let out_len = if opcode == CmdOpcode::QueryVhcaState {
        0x20
    } else {
        0x10
    };
    let result = command.execute(opcode, input, 0x10, output, out_len);
    command.set_uid(previous);
    result
}

fn query_vhca_command(
    initial_uid: u16,
    is_vf: bool,
    function: u16,
    input: &mut CmdMailbox,
    output: &mut CmdMailbox,
    execute: &mut impl FnMut(
        CmdOpcode,
        u16,
        &CmdMailbox,
        &mut CmdMailbox,
    ) -> Result<(), crate::error::CommandFailure>,
) -> Mlx5Result<VhcaStateContext> {
    let (uids, count) = Mlx5Device::uid_candidates(initial_uid, is_vf);
    super::try_uid_candidates(&uids[..count], |uid| {
        build_query_vhca_state_input(input, uid, function);
        execute(CmdOpcode::QueryVhcaState, uid, input, output)?;
        Ok(parse_query_vhca_state_output(output))
    })
    .map_err(crate::error::CommandFailure::cause)
}

fn activate_vf_commands(
    initial_uid: u16,
    is_vf: bool,
    count: u16,
    input: &mut CmdMailbox,
    output: &mut CmdMailbox,
    mut execute: impl FnMut(
        CmdOpcode,
        u16,
        &CmdMailbox,
        &mut CmdMailbox,
    ) -> Result<(), crate::error::CommandFailure>,
) -> Mlx5Result<()> {
    for index in 0..count {
        let function = index + 1;
        let context =
            query_vhca_command(initial_uid, is_vf, function, input, output, &mut execute)?;
        if !context.state.is_activation_ready() {
            return Err(Mlx5Error::InvalidResponse);
        }
        build_enable_hca_input(input, function);
        execute(CmdOpcode::EnableHca, initial_uid, input, output)?;
        build_modify_vport_state_input(
            input,
            MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT,
            function,
            true,
            VPORT_ADMIN_STATE_UP,
        );
        execute(CmdOpcode::ModifyVportState, initial_uid, input, output)?;
    }
    Ok(())
}

fn deactivate_vf_commands(
    uid: u16,
    count: u16,
    input: &mut CmdMailbox,
    output: &mut CmdMailbox,
    mut execute: impl FnMut(
        CmdOpcode,
        u16,
        &CmdMailbox,
        &mut CmdMailbox,
    ) -> Result<(), crate::error::CommandFailure>,
) -> Mlx5Result<()> {
    for index in 0..count {
        let function = index + 1;
        build_modify_vport_state_input(
            input,
            MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT,
            function,
            true,
            VPORT_ADMIN_STATE_DOWN,
        );
        execute(CmdOpcode::ModifyVportState, uid, input, output)?;
        build_enable_hca_input(input, function);
        execute(CmdOpcode::DisableHca, uid, input, output)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::structs::{get_bits_u32, set_bits_u32};

    #[test]
    fn vf_activation_rebuilds_each_query_and_validates_before_enable() {
        let mut input = CmdMailbox::zeroed();
        let mut output = CmdMailbox::zeroed();
        let mut calls = Vec::new();
        activate_vf_commands(
            0,
            true,
            1,
            &mut input,
            &mut output,
            |opcode, uid, input, output| {
                calls.push((opcode, uid, get_bits_u32(&input.data, 80, 16)));
                if opcode == CmdOpcode::QueryVhcaState {
                    assert_eq!(input.read_be16(2), uid);
                    if uid != 0xffff {
                        return Err(crate::error::CommandFailure::Rejected(3));
                    }
                    output.data.fill(0);
                    set_bits_u32(&mut output.data, 140, 4, VhcaState::Allocated as u32);
                } else if opcode == CmdOpcode::ModifyVportState {
                    assert_eq!(input.read_be16(6), MODIFY_VPORT_STATE_OP_MOD_ESW_VPORT);
                    assert_eq!(get_bits_u32(&input.data, 64, 1), 1);
                    assert_eq!(
                        get_bits_u32(&input.data, 120, 4),
                        u32::from(VPORT_ADMIN_STATE_UP)
                    );
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            calls,
            [
                (CmdOpcode::QueryVhcaState, 0, 1),
                (CmdOpcode::QueryVhcaState, 0xffff, 1),
                (CmdOpcode::EnableHca, 0, 1),
                (CmdOpcode::ModifyVportState, 0, 1)
            ]
        );
    }

    #[test]
    fn invalid_vhca_and_unknown_transport_outcome_stop_activation() {
        for error in [
            None,
            Some(Mlx5Error::CommandTimeout),
            Some(Mlx5Error::InvalidResponse),
        ] {
            let mut input = CmdMailbox::zeroed();
            let mut output = CmdMailbox::zeroed();
            let mut calls = 0;
            let result = activate_vf_commands(
                0,
                true,
                1,
                &mut input,
                &mut output,
                |opcode, _, _, output| {
                    calls += 1;
                    assert_eq!(opcode, CmdOpcode::QueryVhcaState);
                    if let Some(error) = error {
                        return Err(crate::error::CommandFailure::OutcomeUnknown(error));
                    }
                    output.data.fill(0);
                    set_bits_u32(&mut output.data, 140, 4, VhcaState::Invalid as u32);
                    Ok(())
                },
            );
            assert_eq!(result, Err(error.unwrap_or(Mlx5Error::InvalidResponse)));
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn vf_deactivation_orders_admin_down_before_disable() {
        let mut input = CmdMailbox::zeroed();
        let mut output = CmdMailbox::zeroed();
        let mut calls = Vec::new();
        deactivate_vf_commands(0, 2, &mut input, &mut output, |opcode, _, input, _| {
            calls.push((opcode, input.read_be16(10)));
            if opcode == CmdOpcode::ModifyVportState {
                assert_eq!(
                    get_bits_u32(&input.data, 120, 4),
                    u32::from(VPORT_ADMIN_STATE_DOWN)
                );
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(
            calls,
            [
                (CmdOpcode::ModifyVportState, 1),
                (CmdOpcode::DisableHca, 1),
                (CmdOpcode::ModifyVportState, 2),
                (CmdOpcode::DisableHca, 2)
            ]
        );
    }
}
